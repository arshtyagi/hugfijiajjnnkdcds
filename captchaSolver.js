'use strict';

/**
 * captchaSolver.js
 * Solves Cloudflare Turnstile challenges via CapSolver API.
 */

const https = require('https');
const logger = require('./utils/logger');

const CAPSOLVER_API_KEY   = process.env.CAPSOLVER_API_KEY;
const APOLLO_TURNSTILE_KEY = process.env.APOLLO_TURNSTILE_SITE_KEY || '0x4AAAAAAABkMYinukE8nzYS';
const POLL_INTERVAL_MS    = 3_000;
const MAX_WAIT_MS         = 120_000;

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

/**
 * Solve Cloudflare Turnstile for Apollo login page.
 * Returns the cfTurnstileResponse token.
 */
async function solveTurnstile(proxyUrl = null) {
  if (!CAPSOLVER_API_KEY) {
    throw new Error('CAPSOLVER_API_KEY not set — cannot solve Turnstile');
  }

  logger.info('Solving Cloudflare Turnstile via CapSolver', { siteKey: APOLLO_TURNSTILE_KEY });

  const task = {
    type:        'AntiTurnstileTaskProxyLess',
    websiteURL:  'https://app.apollo.io',
    websiteKey:  APOLLO_TURNSTILE_KEY,
    metadata:    { action: 'managed' },
  };

  // If proxy is provided use proxy-based task for better success rate
  if (proxyUrl) {
    try {
      const u = new URL(proxyUrl);
      task.type       = 'AntiTurnstileTask';
      task.proxyType  = u.protocol.replace(':', '');
      task.proxyAddress = u.hostname;
      task.proxyPort  = Number(u.port);
      if (u.username) task.proxyLogin    = decodeURIComponent(u.username);
      if (u.password) task.proxyPassword = decodeURIComponent(u.password);
    } catch {
      // fallback to proxyless if URL parse fails
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

module.exports = { solveTurnstile, detectChallenge };
