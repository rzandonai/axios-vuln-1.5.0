/**
 * CVE-2026-40175 automated test
 *
 * Uses Node.js 20 built-in node:test.
 * Adjusts expectations based on installed axios version.
 *
 *   # Run with v1.14.0 (confirm vulnerability)
 *   npm test
 *
 *   # Run with v1.15.0 (confirm fix)
 *   npm install axios@1.15.0 && npm test
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const axios = require('axios');
const installedVersion = require('axios/package.json').version;

const [, minor] = installedVersion.split('.').map(Number);
const isVulnerable = minor < 15;

// Adapter that doesn't perform HTTP communication, just returns headers assembled by axios
const captureAdapter = (config) =>
  Promise.resolve({
    data: { capturedHeaders: config.headers },
    status: 200,
    statusText: 'OK',
    headers: {},
    config,
    request: {},
  });

const client = axios.create({ adapter: captureAdapter });

// ============================================================
describe(`axios@${installedVersion}`, () => {

  // ----------------------------------------------------------
  // Test ①: Prototype pollution propagation
  // Since axios processes headers with Object.keys()
  // Polluted values don't mix into requests without explicit header specification.
  // However, in v1.14.0, there are places that use for...in during config merging
  // And polluted values can mix in through some paths. Tests record this fact.
  // ----------------------------------------------------------
  test('Prototype pollution: Confirm no mixing into non-header-specified requests', async () => {
    Object.prototype['x-proto-test'] = 'polluted-value\r\nBAD: header';

    const res = await client.get('http://example.com');
    const headers = res.data.capturedHeaders;
    // Reference via prototype chain (headers['x-proto-test']) is
    // Returns Object.prototype value causing false positive. Determine by own property.
    const leaked = Object.prototype.hasOwnProperty.call(headers, 'x-proto-test');

    // axios uses Object.keys() for header processing, so not an own property
    assert.equal(leaked, false, 'prototype-polluted value should NOT be an own property of headers');
    console.log(`  Prototype pollution value not included as own property in headers (axios@${installedVersion})`);
    console.log(`  (headers['x-proto-test'] returns "${headers['x-proto-test']}" via prototype chain but is not own property)`);

    delete Object.prototype['x-proto-test'];
  });

  // ----------------------------------------------------------
  // Test ②: CRLF validation (core of CVE)
  // ----------------------------------------------------------
  if (isVulnerable) {
    test('CRLF passes validation and reaches adapter (vulnerable)', async () => {
      const payload = 'dummy\r\n\r\nPUT /latest/api/token HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n';

      const res = await client.get('http://example.com', {
        headers: { 'x-inject': payload },
      });

      const sentValue = String(res.data.capturedHeaders['x-inject'] ?? '');
      assert.ok(
        sentValue.includes('\r\n'),
        `axios@${installedVersion} does not validate CRLF, vulnerable`
      );
    });
  } else {
    test('CRLF-containing headers blocked by assertValidHeaderValue (fixed)', async () => {
      const payload = 'dummy\r\n\r\nPUT /latest/api/token HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n';

      await assert.rejects(
        () =>
          client.get('http://example.com', {
            headers: { 'x-inject': payload },
          }),
        (err) => {
          assert.ok(
            err.message.includes('Invalid character in header content'),
            `Expected error: "Invalid character in header content", got: "${err.message}"`
          );
          return true;
        }
      );
    });
  }

  // ----------------------------------------------------------
  // Test ③: Normal headers pass in both versions
  // ----------------------------------------------------------
  test('Normal headers without CRLF do not cause error', async () => {
    const res = await client.get('http://example.com', {
      headers: { 'x-custom': 'normal-value' },
    });

    assert.equal(res.status, 200);
  });
});
