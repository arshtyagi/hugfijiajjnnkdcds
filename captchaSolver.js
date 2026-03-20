'use strict';

/**
 * captchaSolver.js
 *
 * Solves Cloudflare Turnstile for Apollo login.
 *
 * Site key extraction strategy (in order):
 *   1. Extract from the challenge response body itself — the Turnstile iframe
 *      URL contains the site key e.g. /turnstile/.../0x4AAAA.../
 *   2. Fall back to APOLLO_TURNSTILE_SITE_KEY env var
 *
 * This is the most reliable approach since the key is always present in
 * the very response that triggered the solve.
 */

const https  = require('https');
const logger = require('./utils/logger');

const CAPSOLVER_API_KEY  = process.env.CAPSOLVER_API_KEY;
const FALLBACK_SITE_KEY  = process.env.APOLLO_TURNSTILE_SITE_KEY || '0x4AAAAAABI5GqZtId4RpSvo';
const POLL_INTERVAL_MS   = 3_000;
const MAX_WAIT_MS        = 120_000;

// ─── Site key extraction ──────────────────────────────────────────────────────

/**
 * Extract Turnstile site key from a Cloudflare challenge response body.
 * The key appears in the Turnstile iframe src URL embedded in the HTML.
 *
 * Patterns found in real CF challenge pages:
 *   /turnstile/f/ov2/av0/rch/.../0x4AAAAAABI5GqZtId4RpSvo/...
 *   data-sitekey="0x4AAAAAABI5GqZtId4RpSvo"
 *   sitekey: "0x4AAAAAABI5GqZtId4RpSvo"
 */
function extractSiteKeyFromBody(body) {
  if (!body || typeof body !== 'string') return null;

  const patterns = [
    // Turnstile iframe URL path — most reliable
    /\/turnstile\/[^/]*\/[^/]*\/[^/]*\/[^/]*\/(0x4[A-Za-z0-9_-]{8,50})\//,
    // data-sitekey attribute
    /data-sitekey=["'](0x4[A-Za-z0-9_-]{8,50})["']/i,
    // JS object key
    /sitekey["'\s]*:["'\s]*(0x4[A-Za-z0-9_-]{8,50})/i,
    // websiteKey
    /websiteKey["'\s]*:["'\s]*(0x4[A-Za-z0-9_-]{8,50})/i,
    // Any quoted 0x4... string
    /"(0x4[A-Za-z0-9_-]{10,50})"/,
  ];

  for (const pattern of patterns) {
    const match = body.match(pattern);
    if (match?.[1]) return match[1];
  }

  return null;
}

// ─── CapSolver helpers ────────────────────────────────────────────────────────

function capsolverPost(path, body) {
  return new Promise((resolve, reject) => {
    const bodyStr = JSON.stringify(body);
    const req = https.request({
      hostname: 'api.capsolver.com',
      path,
      method:   'POST',
      headers:  {
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(bodyStr),
      },
    }, (res) => {
      let data = '';
      res.on('data', c => (data += c));
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { reject(new Error('Failed to parse CapSolver response')); }
      });
    });
    req.on('error', reject);
    req.write(bodyStr);
    req.end();
  });
}

async function createTask(task) {
  const resp = await capsolverPost('/createTask', {
    clientKey: CAPSOLVER_API_KEY,
    task,
  });
  if (resp.errorId !== 0) {
    throw new Error(`CapSolver createTask error [${resp.errorCode}]: ${resp.errorDescription}`);
  }
  logger.info('CapSolver task created', { taskId: resp.taskId });
  return resp.taskId;
}

async function pollForResult(taskId) {
  const deadline = Date.now() + MAX_WAIT_MS;
  while (Date.now() < deadline) {
    await new Promise(r => setTimeout(r, POLL_INTERVAL_MS));
    const resp = await capsolverPost('/getTaskResult', {
      clientKey: CAPSOLVER_API_KEY,
      taskId,
    });
    if (resp.errorId !== 0) {
      throw new Error(`CapSolver getTaskResult error [${resp.errorCode}]: ${resp.errorDescription}`);
    }
    if (resp.status === 'ready') {
      logger.info('CapSolver Turnstile solved');
      return resp.solution?.token ?? resp.solution;
    }
    if (resp.status === 'failed') throw new Error('CapSolver task failed');
  }
  throw new Error(`CapSolver timeout after ${MAX_WAIT_MS}ms`);
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Solve Cloudflare "Just a moment..." JS challenge to get cf_clearance cookie.
 * Uses AntiCloudflareTask which handles the full JS challenge.
 *
 * @param {string|null} proxyUrl — proxy (required for AntiCloudflareTask)
 * @returns {Promise<string>} cf_clearance cookie value
 */
async function solveClearance(proxyUrl = null) {
  if (!CAPSOLVER_API_KEY) {
    throw new Error('CAPSOLVER_API_KEY not set — cannot solve Cloudflare challenge');
  }

  if (!proxyUrl) {
    throw new Error('Proxy required for AntiCloudflareTask — cannot solve without proxy');
  }

  let proxyType, proxyAddress, proxyPort, proxyLogin, proxyPassword;
  try {
    const u   = new URL(proxyUrl);
    proxyType     = u.protocol.replace(':', '');
    proxyAddress  = u.hostname;
    proxyPort     = Number(u.port);
    proxyLogin    = u.username ? decodeURIComponent(u.username) : undefined;
    proxyPassword = u.password ? decodeURIComponent(u.password) : undefined;
  } catch (err) {
    throw new Error(`Failed to parse proxy URL: ${err.message}`);
  }

  logger.info('Solving Cloudflare JS challenge via CapSolver AntiCloudflareTask', {
    proxyAddress,
    proxyPort,
  });

  const task = {
    type:        'AntiCloudflareTask',
    websiteURL:  'https://app.apollo.io/api/v1/auth/login',
    proxyType:    proxyType,
    proxyAddress: proxyAddress,
    proxyPort:    proxyPort,
    proxyLogin:   proxyLogin    || '',
    proxyPassword: proxyPassword || '',
  };

  const taskId = await createTask(task);
  const result = await pollForResult(taskId);

  // AntiCloudflareTask returns { cf_clearance: "..." } or the token directly
  const clearance = result?.cf_clearance ?? result;
  if (!clearance) throw new Error('AntiCloudflareTask returned no cf_clearance');

  logger.info('Cloudflare cf_clearance obtained');
  return clearance;
}

/**
 * Solve Cloudflare Turnstile widget (embedded in Apollo login form).
 * Only use this when Apollo's own login form shows a Turnstile widget.
 *
 * @param {string|null} proxyUrl
 * @param {string|null} challengeBody
 * @returns {Promise<string>} cfTurnstileResponse token
 */
async function solveTurnstile(proxyUrl = null, challengeBody = null) {
  if (!CAPSOLVER_API_KEY) {
    throw new Error('CAPSOLVER_API_KEY not set — cannot solve Turnstile');
  }

  let siteKey = extractSiteKeyFromBody(challengeBody);

  if (siteKey) {
    logger.info('Turnstile site key extracted from challenge body', { siteKey });
  } else {
    if (challengeBody) {
      logger.info('Could not extract site key from body', {
        bodySnippet: String(challengeBody).slice(0, 200),
      });
    }
    siteKey = FALLBACK_SITE_KEY;
    logger.info('Using fallback Turnstile site key', { siteKey });
  }

  logger.info('Solving Cloudflare Turnstile via CapSolver', { siteKey });

  const task = {
    type:        'AntiTurnstileTaskProxyLess',
    websiteURL:  'https://app.apollo.io',
    websiteKey:  siteKey,
    metadata:    { action: 'managed' },
  };

  if (proxyUrl) {
    try {
      const u = new URL(proxyUrl);
      task.type          = 'AntiTurnstileTask';
      task.proxyType     = u.protocol.replace(':', '');
      task.proxyAddress  = u.hostname;
      task.proxyPort     = Number(u.port);
      if (u.username) task.proxyLogin    = decodeURIComponent(u.username);
      if (u.password) task.proxyPassword = decodeURIComponent(u.password);
    } catch {
      task.type = 'AntiTurnstileTaskProxyLess';
    }
  }

  const taskId = await createTask(task);
  return await pollForResult(taskId);
}

/**
 * Detect if a response body contains a Cloudflare challenge.
 */
function detectChallenge(rawBody) {
  if (!rawBody) return false;
  return /just a moment|cf-turnstile|turnstile\.cloudflare\.com|checking your browser/i.test(rawBody);
}

module.exports = { solveTurnstile, solveClearance, detectChallenge, extractSiteKeyFromBody };
