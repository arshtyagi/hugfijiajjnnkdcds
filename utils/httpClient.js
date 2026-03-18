'use strict';

/**
 * httpClient.js
 * Kept as sleep helper — sessionManager imports this.
 * All actual HTTP is done via node-tls-client in auth.js / apolloSearch.js.
 */

const sleep = ms => new Promise(r => setTimeout(r, ms));

module.exports = { sleep };
