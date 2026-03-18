'use strict';

/**
 * imapOtp.js
 *
 * CRITICAL FIX: cleanup is now completely fire-and-forget.
 * The OTP is returned immediately after being found — the inbox
 * cleanup happens in the background on a separate IMAP connection
 * so it never delays the verify_email call.
 */

const { ImapFlow } = require('imapflow');
const logger = require('./utils/logger');

const IMAP_CONFIG = {
  host:   'imap.gmail.com',
  port:   993,
  secure: true,
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD,
  },
  logger: false,
  tls: { rejectUnauthorized: true },
};

// 'archive' | 'delete' | 'trash'
const IMAP_ACTION      = (process.env.IMAP_ACTION || 'archive').toLowerCase();
const CLEANUP_AFTER_MS = Number(process.env.IMAP_CLEANUP_AFTER_MS) || 10 * 60 * 1000;

const ARCHIVE_FOLDER = '[Gmail]/All Mail';
const TRASH_FOLDER   = '[Gmail]/Trash';

const OTP_PATTERNS = [
  /(?:verification|confirmation|one.?time|otp|code)[^\d]{0,40}(\d{6})/i,
  /(?:enter|use|your)[\s\S]{0,30}(\d{6})[\s\S]{0,30}(?:to|code|verify)/i,
  /\b(\d{6})\b/,
];

function extractOtp(text) {
  for (const pattern of OTP_PATTERNS) {
    const m = text.match(pattern);
    if (m?.[1]) return m[1];
  }
  return null;
}

// Global UID dedup
const _usedUids = new Set();

// ─────────────────────────────────────────────────────────────────────────────
//  Public
// ─────────────────────────────────────────────────────────────────────────────

async function waitForOtp(apolloEmail, afterDate, timeoutMs = 90_000, pollIntervalMs = 5_000) {
  if (!(afterDate instanceof Date)) {
    afterDate = new Date(Date.now() - 60_000);
  }

  const deadline = Date.now() + timeoutMs;
  logger.info('Waiting for OTP email', {
    apolloEmail,
    after:  afterDate.toISOString(),
    action: IMAP_ACTION,
  });

  while (Date.now() < deadline) {
    const result = await _fetchOtp(afterDate);
    if (result) {
      logger.info('OTP received successfully', { apolloEmail });

      // ── Fire-and-forget cleanup — does NOT block OTP return ──────────────
      _backgroundCleanup(result.disposeUids).catch(() => {});

      return result.otp;
    }
    await new Promise(r => setTimeout(r, pollIntervalMs));
  }

  throw new Error(`OTP timeout after ${timeoutMs}ms for ${apolloEmail}`);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Fetch OTP — returns immediately once found, collects UIDs to dispose
// ─────────────────────────────────────────────────────────────────────────────

async function _fetchOtp(afterDate) {
  const client = new ImapFlow(IMAP_CONFIG);

  try {
    await client.connect();
    await client.mailboxOpen('INBOX');

    const uids = await client.search({
      since: afterDate,
      or: [
        { from: 'apollo.io' },
        { subject: 'verification' },
        { subject: 'confirm' },
        { subject: 'sign in' },
      ],
    });

    if (!uids?.length) return null;

    const candidates = [...uids]
      .sort((a, b) => b - a)
      .filter(uid => !_usedUids.has(uid));

    if (!candidates.length) return null;

    for (const uid of candidates.slice(0, 10)) {
      try {
        const msg = await client.fetchOne(uid, { source: true });
        if (!msg) continue;

        const rawBody = msg.source?.toString('utf8') ?? '';
        const otp     = extractOtp(rawBody);
        if (!otp) continue;

        // Mark consumed immediately
        _usedUids.add(uid);
        logger.info(`OTP found (uid ${uid}) — cleanup scheduled in background`);

        // Collect other Apollo emails to clean up too (already filtered by afterDate)
        const disposeUids = candidates.filter(u => u !== uid).slice(0, 50);
        disposeUids.unshift(uid); // OTP email first

        return { otp, disposeUids };

      } catch (err) {
        logger.warn('Error reading email', { uid, err: err.message });
      }
    }

    return null;
  } catch (err) {
    logger.error('IMAP fetch error', { message: err.message });
    return null;
  } finally {
    try { await client.logout(); } catch { /* ignore */ }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
//  Background cleanup — runs on a fresh connection, never blocks the caller
// ─────────────────────────────────────────────────────────────────────────────

async function _backgroundCleanup(hotUids = []) {
  // Small delay so the verify_email request has time to complete first
  await new Promise(r => setTimeout(r, 3000));

  const client = new ImapFlow(IMAP_CONFIG);

  try {
    await client.connect();
    await client.mailboxOpen('INBOX');

    // 1. Dispose the hot UIDs (OTP email + sibling emails from the same poll)
    const freshHot = hotUids.filter(uid => !_usedUids.has(uid) || hotUids[0] === uid);
    if (freshHot.length) {
      freshHot.forEach(uid => _usedUids.add(uid));
      await _disposeUids(client, freshHot);
    }

    // 2. Clean up old Apollo emails (older than CLEANUP_AFTER_MS)
    const cutoff = new Date(Date.now() - CLEANUP_AFTER_MS);
    const oldUids = await client.search({
      before: cutoff,
      or: [
        { from: 'apollo.io' },
        { subject: 'verification' },
        { subject: 'confirm' },
        { subject: 'sign in' },
      ],
    });

    if (oldUids?.length) {
      const toClean = oldUids.filter(uid => !_usedUids.has(uid));
      if (toClean.length) {
        logger.info(`Background cleanup: disposing ${toClean.length} old email(s)`);
        toClean.forEach(uid => _usedUids.add(uid));
        // Process in batches of 200 to avoid huge IMAP commands
        for (let i = 0; i < toClean.length; i += 200) {
          await _disposeUids(client, toClean.slice(i, i + 200));
        }
      }
    }

  } catch (err) {
    logger.warn('Background cleanup error (non-fatal)', { err: err.message });
  } finally {
    try { await client.logout(); } catch { /* ignore */ }
  }
}

async function _disposeUids(client, uids) {
  if (!uids.length) return;
  const dest = (IMAP_ACTION === 'delete' || IMAP_ACTION === 'trash')
    ? TRASH_FOLDER
    : ARCHIVE_FOLDER;
  try {
    await client.messageMove(uids, dest);
    logger.info(`Moved ${uids.length} email(s) → ${dest}`);
  } catch {
    try { await client.messageFlagsAdd(uids, ['\\Seen']); } catch { /* ignore */ }
  }
}

module.exports = { waitForOtp };
