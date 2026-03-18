'use strict';

const { createLogger, format, transports } = require('winston');
const { combine, timestamp, printf, colorize, errors } = format;

const REDACT_KEYS = ['password', 'cookie', 'set-cookie', 'authorization', 'otp', 'token', 'x-csrf-token'];

function redact(obj, depth = 0) {
  if (depth > 6 || obj === null || obj === undefined) return obj;
  if (typeof obj === 'string') return obj;
  if (Array.isArray(obj)) return obj.map(v => redact(v, depth + 1));
  if (typeof obj === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(obj)) {
      out[k] = REDACT_KEYS.some(r => k.toLowerCase().includes(r))
        ? '[REDACTED]'
        : redact(v, depth + 1);
    }
    return out;
  }
  return obj;
}

const logFormat = printf(({ level, message, timestamp: ts, ...meta }) => {
  const metaStr = Object.keys(meta).length ? ' ' + JSON.stringify(redact(meta)) : '';
  return `${ts} [${level}] ${message}${metaStr}`;
});

const logger = createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: combine(errors({ stack: true }), timestamp({ format: 'YYYY-MM-DD HH:mm:ss.SSS' }), logFormat),
  transports: [
    new transports.Console({
      format: combine(colorize(), timestamp({ format: 'HH:mm:ss.SSS' }), logFormat),
    }),
    new transports.File({ filename: 'logs/error.log',    level: 'error' }),
    new transports.File({ filename: 'logs/combined.log' }),
  ],
});

module.exports = logger;
