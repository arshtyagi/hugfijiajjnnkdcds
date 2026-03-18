'use strict';

require('dotenv').config();

const express        = require('express');
const { v4: uuidv4 } = require('uuid');
const sessionManager = require('./sessionManager');
const { getLeadCount } = require('./apolloSearch');
const logger         = require('./utils/logger');
const fs             = require('fs');

// Ensure logs directory exists
if (!fs.existsSync('logs')) fs.mkdirSync('logs');

const app  = express();
const PORT = Number(process.env.PORT) || 3000;

// CORS
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});
app.use(express.json());

// Request ID + latency logging
app.use((req, res, next) => {
  req.requestId = uuidv4();
  req.startTime = Date.now();
  res.setHeader('X-Request-Id', req.requestId);
  res.on('finish', () => {
    logger.info('Request completed', {
      method:    req.method,
      path:      req.path,
      status:    res.statusCode,
      latencyMs: Date.now() - req.startTime,
      requestId: req.requestId,
    });
  });
  next();
});

// ─────────────────────────────────────────────────────────────────────────────
//  Routes
// ─────────────────────────────────────────────────────────────────────────────

/**
 * POST /leads/count
 * Body:    { "apollo_url": "https://app.apollo.io/#/people?..." }
 * Returns: { "lead_count": 12456 }
 */
app.post('/leads/count', async (req, res) => {
  const { apollo_url } = req.body ?? {};

  if (!apollo_url || typeof apollo_url !== 'string') {
    return res.status(400).json({ error: 'apollo_url is required and must be a string' });
  }
  if (!apollo_url.includes('apollo.io')) {
    return res.status(400).json({ error: 'Invalid Apollo URL' });
  }

  try {
    const leadCount = await getLeadCount(apollo_url);
    return res.json({ lead_count: leadCount });
  } catch (err) {
    logger.error('Lead count request failed', { requestId: req.requestId, message: err.message });
    return res.status(500).json({ error: 'Failed to retrieve lead count', detail: err.message });
  }
});

/**
 * GET /health
 */
app.get('/health', (req, res) => {
  const metrics = sessionManager.getMetrics();
  const healthy = metrics.some(m => m.status === 'alive');
  res.status(healthy ? 200 : 503).json({
    status:   healthy ? 'ok' : 'degraded',
    sessions: metrics,
    uptime:   Math.floor(process.uptime()),
  });
});

/**
 * GET /sessions
 */
app.get('/sessions', (req, res) => {
  res.json({ sessions: sessionManager.getMetrics() });
});

// 404
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// Global error handler
app.use((err, req, res, _next) => {
  logger.error('Unhandled error', { requestId: req.requestId, message: err.message });
  res.status(500).json({ error: 'Internal server error' });
});

// ─────────────────────────────────────────────────────────────────────────────
//  Bootstrap
// ─────────────────────────────────────────────────────────────────────────────

async function start() {
  try {
    logger.info('Initialising session manager...');
    await sessionManager.init();
    app.listen(PORT, () => logger.info(`Apollo API listening on port ${PORT}`));
  } catch (err) {
    logger.error('Fatal startup error', { message: err.message });
    process.exit(1);
  }
}

process.on('SIGTERM', () => { logger.info('SIGTERM — shutting down'); process.exit(0); });
process.on('SIGINT',  () => { logger.info('SIGINT — shutting down');  process.exit(0); });
process.on('unhandledRejection', reason => logger.error('Unhandled rejection', { reason: String(reason) }));

start();
