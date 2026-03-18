'use strict';

/**
 * sessionManager.js
 *
 * Maintains a pool of Apollo account sessions.
 * Each account has its own dedicated static proxy (APOLLO_PROXIES) and
 * TLS-fingerprinted session (node-tls-client / bogdanfinn).
 *
 * .env format:
 *   APOLLO_EMAILS=a@x.com,b@x.com
 *   APOLLO_PASSWORDS=pass1,pass2
 *   APOLLO_PROXIES=http://u:p@1.1.1.1:8080,http://u:p@2.2.2.2:8080
 *
 * Leave a proxy slot blank to go direct for that account:
 *   APOLLO_PROXIES=http://proxy1,,http://proxy3
 */

const { loginToApollo } = require('./auth');
const logger            = require('./utils/logger');
const { sleep }         = require('./utils/httpClient');

const SESSION_TTL_MS         = Number(process.env.SESSION_TTL_MS)            || 3_600_000; // 1 h
const SESSION_REFRESH_BUFFER = Number(process.env.SESSION_REFRESH_BUFFER_MS) || 300_000;   // 5 min
const LOGIN_STAGGER_INTERVAL = Number(process.env.LOGIN_STAGGER_INTERVAL_MS) || 1_200_000; // 20 min
const HEALTH_CHECK_INTERVAL  = 60_000; // 1 min

// ── Load accounts ─────────────────────────────────────────────────────────────
function loadAccounts() {
  const emails    = (process.env.APOLLO_EMAILS    || '').split(',').map(s => s.trim()).filter(Boolean);
  const passwords = (process.env.APOLLO_PASSWORDS || '').split(',').map(s => s.trim()).filter(Boolean);
  const proxies   = (process.env.APOLLO_PROXIES   || '').split(',').map(s => s.trim()); // empty string = direct

  if (!emails.length) throw new Error('No APOLLO_EMAILS defined in .env');

  return emails.map((email, i) => ({
    email,
    password:  passwords[i] || '',
    accountId: `account_${i + 1}`,
    proxy:     proxies[i]   || null,
  }));
}

// ── State ─────────────────────────────────────────────────────────────────────
const sessions        = new Map(); // accountId → SessionData
const loginInProgress = new Map(); // accountId → Promise<SessionData>
let accounts = [];
let rrIndex  = 0;

// ─────────────────────────────────────────────────────────────────────────────
//  Public API
// ─────────────────────────────────────────────────────────────────────────────

async function init() {
  accounts = loadAccounts();

  for (const acc of accounts) {
    logger.info('Account loaded', {
      accountId: acc.accountId,
      email:     acc.email,
      proxy:     acc.proxy ? acc.proxy.replace(/\/\/[^@]*@/, '//***@') : 'direct',
    });
  }

  // Staggered logins — first immediately, rest every LOGIN_STAGGER_INTERVAL
  for (let i = 0; i < accounts.length; i++) {
    if (i === 0) {
      _loginAccount(accounts[0]).catch(err =>
        logger.error('Initial login failed', { accountId: accounts[0].accountId, err: err.message })
      );
    } else {
      const delay = i * LOGIN_STAGGER_INTERVAL;
      setTimeout(() => {
        _loginAccount(accounts[i]).catch(err =>
          logger.error('Staggered login failed', { accountId: accounts[i].accountId, err: err.message })
        );
      }, delay);
      logger.info('Login scheduled', { accountId: accounts[i].accountId, inMinutes: delay / 60_000 });
    }
  }

  setInterval(_healthCheck, HEALTH_CHECK_INTERVAL).unref();
}

/**
 * Return a valid session (round-robin). Blocks only if no sessions are ready yet.
 */
async function getValidSession() {
  // Fast-path: find a live session
  for (let i = 0; i < accounts.length; i++) {
    const acc     = accounts[rrIndex % accounts.length];
    rrIndex++;
    const session = sessions.get(acc.accountId);
    if (session && _isAlive(session)) return _toPublic(session);
  }

  // Wait for any login in progress
  const inProgress = [...loginInProgress.values()];
  if (inProgress.length) {
    logger.warn('No ready session — awaiting login in progress');
    return _toPublic(await inProgress[0]);
  }

  // Emergency re-login
  logger.warn('All sessions expired — emergency re-login');
  const acc     = accounts[rrIndex % accounts.length];
  const session = await _loginAccount(acc);
  return _toPublic(session);
}

/**
 * Invalidate a session after 401/403 and trigger async re-login.
 */
function invalidateSession(accountId) {
  logger.warn('Invalidating session', { accountId });
  sessions.delete(accountId);
  const acc = accounts.find(a => a.accountId === accountId);
  if (acc) {
    _loginAccount(acc).catch(err =>
      logger.error('Re-login after invalidation failed', { accountId, err: err.message })
    );
  }
}

/**
 * Health metrics for /health endpoint.
 */
function getMetrics() {
  const now = Date.now();
  return accounts.map(acc => {
    const s   = sessions.get(acc.accountId);
    const ttl = s ? Math.max(0, SESSION_TTL_MS - (now - s.createdAt)) : 0;
    return {
      accountId:       acc.accountId,
      proxy:           acc.proxy ? acc.proxy.replace(/\/\/[^@]*@/, '//***@') : 'direct',
      status:          s ? (_isAlive(s) ? 'alive' : 'expired') : 'none',
      ttlMs:           ttl,
      loginInProgress: loginInProgress.has(acc.accountId),
    };
  });
}

// ─────────────────────────────────────────────────────────────────────────────
//  Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

function _isAlive(s)      { return (Date.now() - s.createdAt) < SESSION_TTL_MS; }
function _isNearExpiry(s) { return (Date.now() - s.createdAt) >= (SESSION_TTL_MS - SESSION_REFRESH_BUFFER); }

/**
 * Expose only the fields apolloSearch needs.
 * tlsSession is included so search requests use the same Chrome fingerprint.
 */
function _toPublic(s) {
  return {
    cookieHeader: s.cookieHeader,
    headers:      s.headers,
    accountId:    s.accountId,
    proxy:        s.proxy,
    tlsSession:   s.tlsSession, // ← Chrome TLS fingerprint session for API calls
  };
}

async function _loginAccount(acc) {
  if (loginInProgress.has(acc.accountId)) return loginInProgress.get(acc.accountId);

  const promise = (async () => {
    const MAX_RETRIES = 3;
    let lastErr;
    for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
      try {
        const session = await loginToApollo(acc);
        sessions.set(acc.accountId, session);
        logger.info('Session stored', { accountId: acc.accountId });

        // Schedule proactive refresh
        const refreshIn = SESSION_TTL_MS - SESSION_REFRESH_BUFFER;
        setTimeout(() => _proactiveRefresh(acc), refreshIn).unref();

        return session;
      } catch (err) {
        lastErr = err;
        logger.error('Login attempt failed', { accountId: acc.accountId, attempt, err: err.message });
        if (attempt < MAX_RETRIES) await sleep(5_000 * attempt);
      }
    }
    throw lastErr;
  })();

  loginInProgress.set(acc.accountId, promise);
  promise.finally(() => loginInProgress.delete(acc.accountId));
  return promise;
}

async function _proactiveRefresh(acc) {
  const session = sessions.get(acc.accountId);
  if (!session || !_isNearExpiry(session)) return;
  logger.info('Proactive session refresh', { accountId: acc.accountId });
  _loginAccount(acc).catch(err =>
    logger.error('Proactive refresh failed', { accountId: acc.accountId, err: err.message })
  );
}

async function _healthCheck() {
  for (const acc of accounts) {
    const s = sessions.get(acc.accountId);
    if (s && _isNearExpiry(s) && !loginInProgress.has(acc.accountId)) {
      logger.info('Health check: refreshing near-expiry session', { accountId: acc.accountId });
      _loginAccount(acc).catch(err =>
        logger.error('Health-check refresh failed', { accountId: acc.accountId, err: err.message })
      );
    }
  }
}

module.exports = { init, getValidSession, invalidateSession, getMetrics };
