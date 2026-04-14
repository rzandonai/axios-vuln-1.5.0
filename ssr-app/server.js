/**
 * SSR attack reproduction server
 *
 * Attack chain — JSON body route (vulnerableDeepMerge):
 *   POST /api/profile
 *   {"__proto__": {"x-inject": "dummy\r\n\r\nPUT /latest/api/token HTTP/1.1\r\n..."}}
 *   → JSON.parse keeps __proto__ as own property
 *   → for...in vulnerableDeepMerge pollutes Object.prototype
 *   → sendToInternalAPI for...in leaks into headers
 *   → net.Socket sends with CRLF (HTTP Request Splitting)
 */

const express = require('express');
const net = require('net');

const app = express();

// For vulnerable routes:
// Use express.text() to get body as raw string, then manually JSON.parse.
// JSON.parse keeps {"__proto__": {...}} as own property,
// so vulnerableDeepMerge's for...in enumerates __proto__ key and causes prototype pollution.
app.use('/api/', express.text({ type: 'application/json' }));

// For safe routes: Use express.json() (body-parser@1.20.1).
// ※ body-parser@1.20.1 itself doesn't have __proto__ filtering (not dependent on bourne).
//   This route is safe because safeDeepMerge uses Object.keys() + __proto__ skip,
//   not because of the express.json() parser's own protection.
app.use('/safe/', express.json());

const MOCK_IMDS_HOST = 'mock-imds';
const MOCK_IMDS_PORT = 80;

// ---------------------------------------------------------------
// Vulnerable deepMerge (same as lodash < 4.17.17 / jQuery < 3.4.0)
// Does not skip __proto__ key, causing prototype pollution
// ---------------------------------------------------------------
function vulnerableDeepMerge(target, source) {
  for (const key in source) {         // for...in traverses prototype chain too
    if (
      typeof source[key] === 'object' &&
      source[key] !== null &&
      !Array.isArray(source[key])
    ) {
      if (!target[key]) target[key] = {};
      vulnerableDeepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];      // __proto__ key gets processed here too
    }
  }
  return target;
}

// ---------------------------------------------------------------
// Safe deepMerge
// Explicitly skips dangerous keys using hasOwnProperty check
// ---------------------------------------------------------------
function safeDeepMerge(target, source) {
  for (const key of Object.keys(source)) {   // Object.keys() doesn't traverse prototype
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue;                               // Explicitly skip dangerous keys
    }
    if (
      typeof source[key] === 'object' &&
      source[key] !== null &&
      !Array.isArray(source[key])
    ) {
      if (!target[key]) target[key] = {};
      safeDeepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// ---------------------------------------------------------------
// Send request to internal API
// for...in collects polluted values from prototype chain into headers,
// net.Socket sends raw HTTP with CRLF, bypassing http module validation
// ---------------------------------------------------------------
function sendToInternalAPI(apiPath) {
  return new Promise((resolve) => {
    // Collect polluted values from prototype chain with for...in (vulnerable implementation)
    const defaults = {};
    const leakedHeaders = [];
    for (const key in defaults) {
      leakedHeaders.push({ key, value: String(defaults[key]) });
    }

    // Assemble HTTP request as raw string (CRLF included as-is)
    let rawRequest = `GET ${apiPath} HTTP/1.1\r\nHost: ${MOCK_IMDS_HOST}\r\n`;
    for (const { key, value } of leakedHeaders) {
      rawRequest += `${key}: ${value}\r\n`;
    }
    rawRequest += '\r\n';

    // Send directly with net.Socket (bypasses http module's CRLF validation)
    const socket = net.createConnection(MOCK_IMDS_PORT, MOCK_IMDS_HOST, () => {
      socket.write(rawRequest);
    });

    const chunks = [];
    socket.on('data', chunk => chunks.push(chunk.toString()));
    socket.on('end', () => resolve({ raw: chunks.join(''), leakedHeaders, rawRequest }));
    socket.on('error', () => resolve({ raw: '', leakedHeaders, rawRequest }));
    setTimeout(() => {
      socket.destroy();
      resolve({ raw: chunks.join(''), leakedHeaders, rawRequest });
    }, 3000);
  });
}

// ---------------------------------------------------------------
// Vulnerable endpoint: POST /api/profile
// Common implementation that merges user profile settings
// ---------------------------------------------------------------
app.post('/api/profile', async (req, res) => {
  // express.text() passes body as raw string → parse with JSON.parse
  // JSON.parse keeps __proto__ as own property (no filtering)
  let userInput = {};
  try {
    userInput = JSON.parse(req.body);
  } catch {
    return res.status(400).json({ error: 'Invalid JSON' });
  }

  console.log('\n[SSR] ⚠️  POST /api/profile received');
  console.log('[SSR] Request body:', JSON.stringify(userInput).slice(0, 200));

  // Merge user input with vulnerable deepMerge → prototype pollution occurs
  const serverConfig = {};
  vulnerableDeepMerge(serverConfig, userInput);

  const polluted = Object.prototype['x-inject'];
  if (polluted) {
    console.log(`[SSR] 🚨 Prototype pollution detected!`);
    console.log(`[SSR]    x-inject = "${String(polluted).replace(/\r/g, '\\r').replace(/\n/g, '\\n').slice(0, 80)}..."`);
  }

  // Request to internal API (polluted headers get mixed in)
  const result = await sendToInternalAPI('/api/healthcheck');

  console.log(`[SSR] Request sent to internal API:\n${result.rawRequest.replace(/\r/g, '\\r').replace(/\n/g, '\\n')}`);

  res.json({
    endpoint: 'POST /api/profile (vulnerable)',
    mergeFunction: 'vulnerableDeepMerge (uses for...in)',
    prototypePolluted: !!polluted,
    pollutedValue: polluted
      ? String(polluted).replace(/\r/g, '\\r').replace(/\n/g, '\\n').slice(0, 150) + '...'
      : null,
    leakedHeaders: result.leakedHeaders,
    rawRequestSent: result.rawRequest,
    internalAPIResponseHead: result.raw.split('\r\n').slice(0, 8).join('\n')
  });

  // Reset pollution (prevent impact on next request)
  delete Object.prototype['x-inject'];
});

// ---------------------------------------------------------------
// Safe endpoint: POST /safe/profile
// ---------------------------------------------------------------
app.post('/safe/profile', async (req, res) => {
  const userInput = req.body;

  console.log('\n[SSR] ✅ POST /safe/profile received');

  // Safe deepMerge → ignores __proto__ key
  const serverConfig = {};
  safeDeepMerge(serverConfig, userInput);

  const polluted = Object.prototype['x-inject'];
  console.log(`[SSR] Prototype pollution: ${polluted ? 'occurred' : 'none (blocked)'}`);

  const axios = require('axios');
  try {
    const response = await axios.get(`http://${MOCK_IMDS_HOST}/api/healthcheck`);
    res.json({
      endpoint: 'POST /safe/profile (safe)',
      mergeFunction: 'safeDeepMerge (Object.keys() + __proto__ skip)',
      prototypePolluted: !!polluted,
      internalAPIResponse: response.data
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.listen(4000, () => {
  console.log('[SSR] Server started: http://localhost:4000');
  console.log('[SSR] Vulnerable endpoint: POST /api/profile  (vulnerableDeepMerge)');
  console.log('[SSR] Safe endpoint: POST /safe/profile (safeDeepMerge)\n');
});
