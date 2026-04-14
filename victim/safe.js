/**
 * CVE-2026-40175 verification script
 *
 * Uses custom adapter to verify axios header validation layer only,
 * bypassing Node.js http module CRLF validation.
 *
 * - axios@1.14.0 (vulnerable): CRLF passes validation, reaches adapter
 * - axios@1.15.0 (fixed): assertValidHeaderValue detects CRLF, throws error before adapter
 *
 * Usage:
 *   # Run with v1.14.0 (vulnerable → CRLF passes)
 *   docker compose run --rm victim node safe.js
 *
 *   # Upgrade to v1.15.0 and run (fixed → error thrown)
 *   docker compose run --rm victim sh -c "npm install axios@1.15.0 && node safe.js"
 */

const axios = require('axios');
const installedVersion = require('axios/package.json').version;

console.log(`=== CVE-2026-40175 verification (axios@${installedVersion}) ===\n`);

// ============================================================
// Custom adapter
// Skips actual HTTP sending, returns axios-assembled headers.
// Completely bypasses Node.js http module CRLF validation.
// ============================================================
const captureAdapter = (config) => {
  return Promise.resolve({
    data: { capturedHeaders: config.headers },
    status: 200,
    statusText: 'OK',
    headers: {},
    config,
    request: {},
  });
};

const client = axios.create({ adapter: captureAdapter });

// ============================================================
// Step 1: Prototype pollution (same premise as exploit.js)
// ============================================================
const CRLF_PAYLOAD =
  'dummy\r\n\r\n' +
  'PUT /latest/api/token HTTP/1.1\r\n' +
  'Host: 169.254.169.254\r\n' +
  'X-aws-ec2-metadata-token-ttl-seconds: 21600\r\n' +
  '\r\n';

Object.prototype['x-inject'] = CRLF_PAYLOAD;

console.log('[1] Executed prototype pollution');
console.log('    Object.prototype["x-inject"] set with CRLF smuggling payload\n');

async function main() {
  // ============================================================
// Test ①: Does prototype pollution mix into headers alone?
// axios uses Object.keys() for header processing, ignores prototype.
// → Even v1.14.0 doesn't leak via this path.
  // ============================================================
  console.log('[2] Prototype pollution state, normal request (no explicit headers)...');
  try {
    const res = await client.get('http://169.254.169.254/latest/meta-data/');
    const headers = res.data.capturedHeaders;
    // Determine by checking if it's own property, not traversing prototype chain.
    // headers['x-inject'] returns value even via Object.prototype, causing false positive.
    const leaked = Object.prototype.hasOwnProperty.call(headers, 'x-inject');
    if (leaked) {
      console.log('    ⚠️  Prototype pollution value mixed into axios headers as own property!');
      console.log('    x-inject:', JSON.stringify(String(headers['x-inject'])).slice(0, 60) + '...');
    } else {
      console.log('    Prototype pollution value did not mix into headers');
      console.log('    (axios uses Object.keys() for header processing, does not traverse prototype)');
    }
  } catch (e) {
    console.log('    エラー:', e.message);
  }
  console.log();

  // ============================================================
  // Test ②: Pass CRLF-containing headers directly to axios
  // ★ This is the essential test for CVE-2026-40175 ★
  //
  // v1.14.0: normalizeValue only removes trailing \r\n
  //          CRLF passes through to adapter → vulnerable
  //
  // v1.15.0: assertValidHeaderValue detects \r\n and throws error immediately
  //          → doesn't reach adapter → fixed
  // ============================================================
  console.log('[3] ★ CVE verification: Directly pass CRLF-containing header to axios...');
  try {
    const res = await client.get('http://169.254.169.254/latest/meta-data/', {
      headers: { 'x-inject': CRLF_PAYLOAD },
    });

    // Reaching adapter = CRLF bypassed validation → vulnerable
    const sentValue = res.data.capturedHeaders['x-inject'];
    console.log(`\n    ⚠️  [axios@${installedVersion}] CRLF reached adapter without validation!`);
    console.log('    Header value that was about to be sent:');
    console.log('    ' + JSON.stringify(String(sentValue)));
    console.log('\n    → This version is vulnerable to CVE-2026-40175.');
    console.log('    → In actual HTTP sending, request splits on CRLF,');
    console.log('       smuggled PUT /latest/api/token reaches IMDS.');
    console.log('\n    To confirm fix:');
    console.log('    docker compose run --rm victim sh -c "npm install axios@1.15.0 && node safe.js"');
  } catch (e) {
    if (e.message && e.message.includes('Invalid character in header content')) {
      console.log(`\n    ✅ [axios@${installedVersion}] ブロックされました: ${e.message}`);
      console.log('    → assertValidHeaderValue detected CRLF and threw error before reaching adapter!');
      console.log('    → Fixed for CVE-2026-40175.');
    } else {
      console.log('    Unexpected error:', e.message);
    }
  }
}

main();
