'use strict';

/**
 * imapOtp.js
 *
 * Fetches OTP codes from Gmail via IMAP.
 *
 * Email disposal (controlled by IMAP_ACTION env var):
 *   archive  (default) — move to [Gmail]/All Mail
 *   delete             — move to [Gmail]/Trash  (Gmail empties trash after 30 days)
 *   trash              — alias for delete
 *
 * In addition to disposing the OTP email we just used, we also clean up
 * any OTHER old Apollo OTP emails sitting in the inbox that are older than
 * IMAP_CLEANUP_AFTER_MS (default 10 minutes). This prevents inbox buildup
 * from staggered account logins.
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
const IMAP_ACTION         = (process.env.IMAP_ACTION || 'archive').toLowerCase();
const CLEANUP_AFTER_MS    = Number(process.env.IMAP_CLEANUP_AFTER_MS) || 10 * 60 * 1000; // 10 min

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

// Global UID dedup — once a UID is consumed it is never returned again
const _usedUids = new Set();

// ─────────────────────────────────────────────────────────────────────────────
//  Public
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Poll until a fresh OTP email arrives, then dispose it.
 * Also cleans up stale Apollo emails older than CLEANUP_AFTER_MS.
 *
 * @param {string} apolloEmail   — for logging only
 * @param {Date}   afterDate     — only accept emails received after this time
 * @param {number} timeoutMs
 * @param {number} pollIntervalMs
 */
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
    const otp = await _fetchAndDispose(afterDate);
    if (otp) {
      logger.info('OTP received successfully', { apolloEmail });
      return otp;
    }
    await new Promise(r => setTimeout(r, pollIntervalMs));
  }

  throw new Error(`OTP timeout after ${timeoutMs}ms for ${apolloEmail}`);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Internal
// ─────────────────────────────────────────────────────────────────────────────

async function _fetchAndDispose(afterDate) {
  const client = new ImapFlow(IMAP_CONFIG);

  try {
    await client.connect();
    await client.mailboxOpen('INBOX');

    // ── Find all Apollo-related emails since afterDate ──────────────────────
    const uids = await client.search({
      since: afterDate,
      or: [
        { from: 'apollo.io' },
        { subject: 'verification' },
        { subject: 'confirm' },
        { subject: 'sign in' },
      ],
    });

    if (!uids?.length) {
      // Even if nothing new arrived, clean up old stale Apollo emails
      await _cleanupOldEmails(client);
      return null;
    }

    // Newest first, skip already-consumed UIDs
    const candidates = [...uids]
      .sort((a, b) => b - a)
      .filter(uid => !_usedUids.has(uid));

    let foundOtp = null;
    const toDispose = [];

    for (const uid of candidates.slice(0, 10)) {
      try {
        const msg = await client.fetchOne(uid, { envelope: true, source: true });
        if (!msg) continue;

        const rawBody = msg.source?.toString('utf8') ?? '';

        if (!foundOtp) {
          const otp = extractOtp(rawBody);
          if (otp) {
            // Mark consumed immediately
            _usedUids.add(uid);
            foundOtp = otp;
            toDispose.push(uid);
            logger.info(`OTP email found — will ${IMAP_ACTION}`, { uid });
            // Don't break — collect other stale emails to dispose too
          }
        } else {
          // Additional Apollo emails we found — dispose them as well
          toDispose.push(uid);
        }
      } catch (err) {
        logger.warn('Error reading email', { uid, err: err.message });
      }
    }

    // Dispose all collected UIDs in one batch
    if (toDispose.length) {
      await _disposeUids(client, toDispose);
    }

    // Clean up any older stale emails while we have the connection open
    await _cleanupOldEmails(client);

    return foundOtp;

  } catch (err) {
    logger.error('IMAP error', { message: err.message });
    return null;
  } finally {
    try { await client.logout(); } catch { /* ignore */ }
  }
}

/**
 * Find Apollo emails older than CLEANUP_AFTER_MS and dispose them.
 * This handles inbox buildup from parallel account logins.
 */
async function _cleanupOldEmails(client) {
  try {
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

    if (!oldUids?.length) return;

    // Filter out already-disposed UIDs
    const toClean = oldUids.filter(uid => !_usedUids.has(uid));
    if (!toClean.length) return;

    logger.info(`Cleaning up ${toClean.length} old Apollo email(s)`, { action: IMAP_ACTION });
    toClean.forEach(uid => _usedUids.add(uid));
    await _disposeUids(client, toClean);

  } catch (err) {
    logger.warn('Cleanup error (non-fatal)', { err: err.message });
  }
}

/**
 * Move UIDs to archive or trash based on IMAP_ACTION.
 */
async function _disposeUids(client, uids) {
  if (!uids.length) return;

  const destination = (IMAP_ACTION === 'delete' || IMAP_ACTION === 'trash')
    ? TRASH_FOLDER
    : ARCHIVE_FOLDER;

  try {
    await client.messageMove(uids, destination);
    logger.info(`Moved ${uids.length} email(s) → ${destination}`, { uids });
  } catch (err) {
    // Fallback: mark as read if move fails (e.g. folder name differs)
    logger.warn(`messageMove failed — marking as read instead`, { err: err.message, destination });
    try {
      await client.messageFlagsAdd(uids, ['\\Seen']);
    } catch (e2) {
      logger.warn('messageFlagsAdd also failed', { err: e2.message });
    }
  }
}

module.exports = { waitForOtp };