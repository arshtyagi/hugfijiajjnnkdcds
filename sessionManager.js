'use strict';

/**
 * sessionManager.js
 *
 * Login retry policy:
 *   - 3 attempts per login call (5s, 10s backoff between)
 *   - If all fail, wait RETRY_AFTER_FAILURE_MS (default 30 min) then try once more
 *   - After MAX_TOTAL_LOGIN_ATTEMPTS total failures, STOP — log a fatal error
 *     so the operator knows to intervene rather than hammering the account
 */

const { loginToApollo } = require('./auth');
const logger            = require('./utils/logger');
const { sleep }         = require('./utils/httpClient');

const SESSION_TTL_MS         = Number(process.env.SESSION_TTL_MS)                || 3_600_000;  // 1 h
const SESSION_REFRESH_BUFFER = Number(process.env.SESSION_REFRESH_BUFFER_MS)     || 300_000;    // 5 min
const LOGIN_STAGGER_INTERVAL = Number(process.env.LOGIN_STAGGER_INTERVAL_MS)     || 1_200_000;  // 20 min
const HEALTH_CHECK_INTERVAL  = 60_000;

// After all attempts fail, wait this long before one more try
const RETRY_AFTER_FAILURE_MS  = Number(process.env.LOGIN_RETRY_AFTER_FAILURE_MS) || 30 * 60 * 1000; // 30 min

// Hard cap — after this many total failures for one account, stop retrying
const MAX_TOTAL_LOGIN_ATTEMPTS = Number(process.env.MAX_TOTAL_LOGIN_ATTEMPTS) || 5;

function loadAccounts() {
  const emails    = (process.env.APOLLO_EMAILS    || '').split(',').map(s => s.trim()).filter(Boolean);
  const passwords = (process.env.APOLLO_PASSWORDS || '').split(',').map(s => s.trim()).filter(Boolean);
  const proxies   = (process.env.APOLLO_PROXIES   || '').split(',').map(s => s.trim());

  if (!emails.length) throw new Error('No APOLLO_EMAILS defined in .env');

  return emails.map((email, i) => ({
    email,
    password:  passwords[i] || '',
    accountId: `account_${i + 1}`,
    proxy:     proxies[i]   || null,
  }));
}

const sessions        = new Map();
const loginInProgress = new Map();
const failureCounts   = new Map(); // accountId → total failed login calls
const stoppedAccounts = new Set(); // accounts that hit MAX_TOTAL_LOGIN_ATTEMPTS

let accounts = [];
let rrIndex  = 0;

// ─────────────────────────────────────────────────────────────────────────────
//  Public
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

  for (let i = 0; i < accounts.length; i++) {
    if (i === 0) {
      _loginWithRetry(accounts[0]);
    } else {
      const delay = i * LOGIN_STAGGER_INTERVAL;
      setTimeout(() => _loginWithRetry(accounts[i]), delay);
      logger.info('Login scheduled', { accountId: accounts[i].accountId, inMinutes: delay / 60_000 });
    }
  }

  setInterval(_healthCheck, HEALTH_CHECK_INTERVAL).unref();
}

async function getValidSession() {
  for (let i = 0; i < accounts.length; i++) {
    const acc     = accounts[rrIndex % accounts.length];
    rrIndex++;
    const session = sessions.get(acc.accountId);
    if (session && _isAlive(session)) return _toPublic(session);
  }

  const inProgress = [...loginInProgress.values()];
  if (inProgress.length) {
    logger.warn('No ready session — awaiting login in progress');
    return _toPublic(await inProgress[0]);
  }

  // Find a non-stopped account to emergency re-login
  const activeAcc = accounts.find(a => !stoppedAccounts.has(a.accountId));
  if (!activeAcc) throw new Error('All accounts have exceeded max login attempts — manual intervention required');

  logger.warn('All sessions expired — emergency re-login', { accountId: activeAcc.accountId });
  const session = await _loginAccount(activeAcc);
  return _toPublic(session);
}

function invalidateSession(accountId) {
  logger.warn('Invalidating session', { accountId });
  sessions.delete(accountId);
  const acc = accounts.find(a => a.accountId === accountId);
  if (acc && !stoppedAccounts.has(accountId)) _loginWithRetry(acc);
}

function getMetrics() {
  const now = Date.now();
  return accounts.map(acc => {
    const s       = sessions.get(acc.accountId);
    const ttl     = s ? Math.max(0, SESSION_TTL_MS - (now - s.createdAt)) : 0;
    const stopped = stoppedAccounts.has(acc.accountId);
    const failures = failureCounts.get(acc.accountId) || 0;
    return {
      accountId:       acc.accountId,
      proxy:           acc.proxy ? acc.proxy.replace(/\/\/[^@]*@/, '//***@') : 'direct',
      status:          stopped ? 'stopped' : s ? (_isAlive(s) ? 'alive' : 'expired') : 'none',
      ttlMs:           ttl,
      loginInProgress: loginInProgress.has(acc.accountId),
      totalFailures:   failures,
      maxFailures:     MAX_TOTAL_LOGIN_ATTEMPTS,
    };
  });
}

// ─────────────────────────────────────────────────────────────────────────────
//  Internal
// ─────────────────────────────────────────────────────────────────────────────

function _isAlive(s)      { return (Date.now() - s.createdAt) < SESSION_TTL_MS; }
function _isNearExpiry(s) { return (Date.now() - s.createdAt) >= (SESSION_TTL_MS - SESSION_REFRESH_BUFFER); }

function _toPublic(s) {
  return {
    cookieHeader: s.cookieHeader,
    headers:      s.headers,
    accountId:    s.accountId,
    proxy:        s.proxy,
    tlsSession:   s.tlsSession,
  };
}

/**
 * Try login. If it fails, increment failure count.
 * If under MAX_TOTAL_LOGIN_ATTEMPTS, schedule one more attempt after RETRY_AFTER_FAILURE_MS.
 * If at the cap, mark account as stopped and log a fatal warning.
 */
function _loginWithRetry(acc) {
  if (stoppedAccounts.has(acc.accountId)) return;

  _loginAccount(acc).catch(err => {
    const failures = (failureCounts.get(acc.accountId) || 0) + 1;
    failureCounts.set(acc.accountId, failures);

    if (failures >= MAX_TOTAL_LOGIN_ATTEMPTS) {
      stoppedAccounts.add(acc.accountId);
      logger.error('🚨 ACCOUNT LOGIN STOPPED — max attempts reached. Manual intervention required.', {
        accountId:    acc.accountId,
        email:        acc.email,
        totalFailures: failures,
        maxFailures:   MAX_TOTAL_LOGIN_ATTEMPTS,
        lastError:     err.message,
      });
      return;
    }

    logger.warn('Login failed — will retry after delay', {
      accountId:     acc.accountId,
      failures,
      maxFailures:   MAX_TOTAL_LOGIN_ATTEMPTS,
      retryInMs:     RETRY_AFTER_FAILURE_MS,
      err:           err.message,
    });

    setTimeout(() => _loginWithRetry(acc), RETRY_AFTER_FAILURE_MS).unref();
  });
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
        // Reset failure count on success
        failureCounts.delete(acc.accountId);
        stoppedAccounts.delete(acc.accountId);
        logger.info('Session stored', { accountId: acc.accountId });

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
  // Reset failure count before proactive refresh so it gets full attempts
  failureCounts.delete(acc.accountId);
  _loginWithRetry(acc);
}

async function _healthCheck() {
  for (const acc of accounts) {
    if (stoppedAccounts.has(acc.accountId)) continue;
    const s = sessions.get(acc.accountId);

    if (s && _isNearExpiry(s) && !loginInProgress.has(acc.accountId)) {
      logger.info('Health check: refreshing near-expiry session', { accountId: acc.accountId });
      failureCounts.delete(acc.accountId);
      _loginWithRetry(acc);
    }

    if (!s && !loginInProgress.has(acc.accountId)) {
      logger.warn('Health check: no session — triggering login', { accountId: acc.accountId });
      _loginWithRetry(acc);
    }
  }
}

module.exports = { init, getValidSession, invalidateSession, getMetrics };
