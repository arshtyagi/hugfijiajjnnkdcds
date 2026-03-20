'use strict';

/**
 * auth.js — Apollo login with TLS fingerprinting + Cloudflare Turnstile solving.
 *
 * When Cloudflare returns a 403/Turnstile challenge, we pass the raw response
 * body to solveTurnstile() which extracts the site key directly from it.
 * No separate page fetch needed — the key is always in the challenge response.
 */

const { Session, ClientIdentifier, initTLS } = require('node-tls-client');
const { waitForOtp }                          = require('./imapOtp');
const { solveTurnstile, solveClearance, detectChallenge } = require('./captchaSolver');
const logger                                  = require('./utils/logger');

const APOLLO_HOST = process.env.APOLLO_HOST || 'https://app.apollo.io';

let _tlsReady = null;
function ensureTlsReady() {
  if (!_tlsReady) _tlsReady = initTLS();
  return _tlsReady;
}

// ─── TLS session factory ──────────────────────────────────────────────────────

async function createTlsSession(proxyUrl = null) {
  await ensureTlsReady();
  return new Session({
    clientIdentifier:        ClientIdentifier.chrome_120,
    randomTlsExtensionOrder: true,
    timeoutMilliseconds:     30_000,
    ...(proxyUrl ? { proxyUrl } : {}),
  });
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function getEpochTimestamp() { return Date.now().toString(); }

function defaultHeaders(cookieStr = '', turnstileToken = null) {
  const h = {
    'accept':             '*/*',
    'accept-language':    'es-ES,es;q=0.9,en;q=0.8,de;q=0.7,sr;q=0.6',
    'cache-control':      'no-cache',
    'content-type':       'application/json',
    'origin':             'https://app.apollo.io',
    'pragma':             'no-cache',
    'priority':           'u=1, i',
    'referer':            'https://app.apollo.io/',
    'sec-ch-ua':          '"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"',
    'sec-ch-ua-mobile':   '?0',
    'sec-ch-ua-platform': '"macOS"',
    'sec-fetch-dest':     'empty',
    'sec-fetch-mode':     'cors',
    'sec-fetch-site':     'same-origin',
    'user-agent':         'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
  };
  if (cookieStr)      h['cookie']               = cookieStr;
  if (turnstileToken) h['cf-turnstile-response'] = turnstileToken;
  return h;
}

/**
 * POST via TLS session.
 * On Cloudflare challenge (403 or challenge body), extracts site key from the
 * challenge response, solves Turnstile, and retries with the token.
 */
async function tlsPost(sess, url, bodyObj, cookieStr = '', proxyUrl = null, maxRetries = 5) {
  let lastErr;
  let turnstileToken  = null;
  let lastChallengeBody = null;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const resp    = await sess.post(url, {
        headers: defaultHeaders(cookieStr, turnstileToken),
        body:    JSON.stringify(bodyObj),
      });

      const rawBody = resp.body ?? '';

      // Cloudflare JS challenge detected ("Just a moment...")
      // Need cf_clearance cookie, not a Turnstile token
      if (resp.status === 403 || detectChallenge(rawBody)) {
        lastChallengeBody = rawBody;

        logger.info('Cloudflare JS challenge detected — getting cf_clearance', { attempt });

        if (!proxyUrl) {
          throw new Error('Cloudflare challenge requires a proxy — cannot solve without one');
        }

        try {
          const cfClearance = await solveClearance(proxyUrl);
          // Inject cf_clearance into the cookie string for next request
          cookieStr = cookieStr
            ? cookieStr.replace(/cf_clearance=[^;]+;?\s*/g, '') + `; cf_clearance=${cfClearance}`
            : `cf_clearance=${cfClearance}`;
          logger.info('cf_clearance obtained — retrying request');
          continue;
        } catch (clearanceErr) {
          logger.warn('AntiCloudflareTask failed — falling back to Turnstile solve', { err: clearanceErr.message });
          // Fallback: try Turnstile token approach
          if (!turnstileToken) {
            turnstileToken = await solveTurnstile(proxyUrl, lastChallengeBody).catch(() => null);
            if (turnstileToken) continue;
          }
          throw clearanceErr;
        }
      }

      return {
        status:  resp.status,
        cookies: resp.cookies ?? {},
        body:    (() => { try { return JSON.parse(rawBody); } catch { return null; } })(),
        rawBody,
      };
    } catch (err) {
      lastErr = err;
      logger.warn('TLS request error — retrying', { attempt, url, err: err.message });
      await new Promise(r => setTimeout(r, 1000 * attempt));
    }
  }
  throw lastErr ?? new Error('Max retries exceeded');
}

// ─── Cookie jar ───────────────────────────────────────────────────────────────

class CookieJar {
  constructor() { this._jar = new Map(); }

  ingestObj(obj = {}) {
    for (const [k, v] of Object.entries(obj)) {
      if (k && v !== undefined) this._jar.set(k, String(v));
    }
  }

  toString() {
    return [...this._jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
  }

  get(name) { return this._jar.get(name); }
  has(name) { return this._jar.has(name); }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function loginToApollo(account) {
  const { email, password, accountId, proxy = null } = account;

  logger.info('Starting Apollo login (TLS + Turnstile)', {
    accountId,
    email,
    proxy: proxy ? proxy.replace(/\/\/[^@]*@/, '//***@') : 'direct',
  });

  const tlsSess = await createTlsSession(proxy);
  const jar     = new CookieJar();

  // ── Step 1: Login ───────────────────────────────────────────────────────────
  const loginResp = await tlsPost(
    tlsSess,
    'https://app.apollo.io/api/v1/auth/login',
    { cacheKey: getEpochTimestamp(), email, password, timezone_offset: '-120' },
    jar.toString(),
    proxy,
  );
  jar.ingestObj(loginResp.cookies);
  logger.info('Login response', { accountId, status: loginResp.status });

  if (loginResp.status === 429) throw new Error('Rate-limited — rotate proxy / IP');
  if (!loginResp.body)          throw new Error('Failed to parse login response');

  const r0 = loginResp.body;

  if (
    r0.message === "Email and/or password don't match with any of our records." ||
    r0.message === 'Wrong email or password'
  ) {
    throw new Error('Wrong email or password | account locked');
  }

  // ── Step 2: 2FA ─────────────────────────────────────────────────────────────
  let finalResult = r0;
  let loginToken  = '';
  let cacheKey    = '';

  if (r0.ato === true) {
    logger.info('2FA required — initiating email verification', { accountId });
    loginToken = r0.login_token || '';
    cacheKey   = getEpochTimestamp();

    const otpAfterDate = new Date();

    const initResp = await tlsPost(
      tlsSess,
      'https://app.apollo.io/api/v1/auth/initiate_email_verification',
      { cacheKey, login_token: loginToken },
      jar.toString(),
      proxy,
    );
    jar.ingestObj(initResp.cookies);

    if (initResp.status !== 200) {
      throw new Error(`initiate_email_verification failed with HTTP ${initResp.status} — retrying full login`);
    }
    logger.info('Email verification initiated', { accountId, status: initResp.status });

    const otp = await waitForOtp(email, otpAfterDate);
    logger.info('OTP received — submitting', { accountId });

    const verifyResp = await tlsPost(
      tlsSess,
      'https://app.apollo.io/api/v1/auth/verify_email',
      { otp, login_token: loginToken, cacheKey },
      jar.toString(),
      proxy,
    );
    jar.ingestObj(verifyResp.cookies);

    if (!verifyResp.body) throw new Error('Failed to parse verify_email response');
    finalResult = verifyResp.body;
    logger.info('Verify email response', { accountId, is_logged_in: finalResult.is_logged_in });

    if (!finalResult.is_logged_in) throw new Error('Login failed: is_logged_in false after OTP');

  } else {
    if (!r0.is_logged_in) throw new Error('Login failed: is_logged_in false');
  }

  // ── Step 3: Retry if remember_token missing ──────────────────────────────────
  const MAX_TOKEN_RETRIES = 2;
  let tokenRetry = 0;

  while (!jar.has('remember_token_leadgenie_v2') && tokenRetry < MAX_TOKEN_RETRIES) {
    logger.warn('remember_token missing — retrying auth', { accountId, attempt: tokenRetry + 1 });

    cacheKey = getEpochTimestamp();
    const retryOtpAfterDate = new Date();

    const ir = await tlsPost(
      tlsSess,
      'https://app.apollo.io/api/v1/auth/initiate_email_verification',
      { cacheKey, login_token: loginToken },
      jar.toString(),
      proxy,
    );
    jar.ingestObj(ir.cookies);

    if (ir.status !== 200) throw new Error(`initiate_email_verification retry failed with HTTP ${ir.status}`);

    const otp2 = await waitForOtp(email, retryOtpAfterDate);
    logger.info('Retry OTP received', { accountId });

    const vr = await tlsPost(
      tlsSess,
      'https://app.apollo.io/api/v1/auth/verify_email',
      { otp: otp2, login_token: loginToken, cacheKey },
      jar.toString(),
      proxy,
    );
    jar.ingestObj(vr.cookies);

    if (!vr.body) throw new Error('Failed to parse retry verify_email response');
    finalResult = vr.body;
    logger.info('Retry verify response', { accountId, is_logged_in: finalResult.is_logged_in });

    if (!finalResult.is_logged_in) throw new Error('Login failed after retry');

    tokenRetry++;
  }

  if (!jar.has('remember_token_leadgenie_v2')) {
    throw new Error('remember_token_leadgenie_v2 not found after retries');
  }

  // ── Step 4: Metadata ────────────────────────────────────────────────────────
  const boot            = finalResult.bootstrapped_data || {};
  const userID          = boot.current_user_id          || '';
  const permSets        = boot.permission_sets          || [];
  const permissionSetID = permSets[0]?.id               || '';
  const csrfToken       = jar.get('X-CSRF-TOKEN')       || '';

  logger.info('✅ Login complete', { accountId, userID });

  return {
    accountId,
    cookieHeader:     jar.toString(),
    userID,
    permissionSetID,
    proxy,
    tlsSession:       await createTlsSession(proxy),
    headers: {
      'Content-Type':      'application/json',
      'Accept':            '*/*',
      'Origin':            APOLLO_HOST,
      'Referer':           `${APOLLO_HOST}/`,
      'User-Agent':        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
      'x-referer-host':    'app.apollo.io',
      'x-referer-path':    '/people',
      'x-accept-language': 'en',
      ...(csrfToken ? { 'x-csrf-token': csrfToken } : {}),
    },
    createdAt: Date.now(),
  };
}

module.exports = { loginToApollo, createTlsSession, ensureTlsReady };
