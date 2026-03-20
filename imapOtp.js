'use strict';

/**
 * imapOtp.js
 *
 * Key fix: IMAP `SINCE` only filters by DATE (not time), so emails from
 * earlier in the same day pass the filter even if they predate afterDate.
 * We now fetch the envelope and check the EXACT received time against afterDate.
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

// Global UID dedup — once consumed, never returned again
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
      // Fire-and-forget cleanup — never blocks OTP return
      _backgroundCleanup(result.disposeUids).catch(() => {});
      return result.otp;
    }
    await new Promise(r => setTimeout(r, pollIntervalMs));
  }

  throw new Error(`OTP timeout after ${timeoutMs}ms for ${apolloEmail}`);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Fetch — returns OTP immediately, collects UIDs for background disposal
// ─────────────────────────────────────────────────────────────────────────────

async function _fetchOtp(afterDate) {
  const client = new ImapFlow(IMAP_CONFIG);

  try {
    await client.connect();
    await client.mailboxOpen('INBOX');

    // IMAP SINCE only matches by date — we use start-of-day to cast a wide net
    // then filter by exact time ourselves using the envelope date
    const sinceDay = new Date(afterDate);
    sinceDay.setHours(0, 0, 0, 0);

    const uids = await client.search({
      since: sinceDay,
      or: [
        { from: 'apollo.io' },
        { subject: 'verification' },
        { subject: 'confirm' },
        { subject: 'sign in' },
      ],
    });

    if (!uids?.length) return null;

    // Newest first, skip already-consumed UIDs
    const candidates = [...uids]
      .sort((a, b) => b - a)
      .filter(uid => !_usedUids.has(uid));

    if (!candidates.length) return null;

    for (const uid of candidates.slice(0, 20)) {
      try {
        const msg = await client.fetchOne(uid, { envelope: true, source: true });
        if (!msg) continue;

        // ── EXACT TIME CHECK — this is the key fix ──────────────────────────
        // IMAP SINCE matches the whole day, so we must check the exact time
        // to reject emails that arrived before initiate_email_verification
        const emailDate = msg.envelope?.date ? new Date(msg.envelope.date) : null;
        if (emailDate && emailDate < afterDate) {
          logger.info('Skipping email — arrived before afterDate', {
            uid,
            emailDate: emailDate.toISOString(),
            afterDate: afterDate.toISOString(),
          });
          continue;
        }

        const rawBody = msg.source?.toString('utf8') ?? '';
        const otp     = extractOtp(rawBody);
        if (!otp) continue;

        // Mark consumed immediately
        _usedUids.add(uid);
        logger.info(`OTP found uid ${uid} at ${emailDate?.toISOString()} — cleanup scheduled`);

        // Collect sibling emails to dispose too
        const disposeUids = candidates
          .filter(u => u !== uid && !_usedUids.has(u))
          .slice(0, 50);
        disposeUids.unshift(uid);

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
//  Background cleanup — separate connection, never blocks caller
// ─────────────────────────────────────────────────────────────────────────────

async function _backgroundCleanup(hotUids = []) {
  // Small delay so verify_email completes before we archive
  await new Promise(r => setTimeout(r, 3000));

  const client = new ImapFlow(IMAP_CONFIG);

  try {
    await client.connect();
    await client.mailboxOpen('INBOX');

    // 1. Dispose hot UIDs (the OTP email + siblings from same poll)
    if (hotUids.length) {
      hotUids.forEach(uid => _usedUids.add(uid));
      await _disposeUids(client, hotUids);
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
