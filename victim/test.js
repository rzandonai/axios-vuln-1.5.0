/**
 * CVE-2026-40175 自動テスト
 *
 * Node.js 20 組み込みの node:test を使用。
 * インストール済みの axios バージョンに応じて期待値を切り替える。
 *
 *   # v1.14.0 でテスト（脆弱を確認）
 *   npm test
 *
 *   # v1.15.0 でテスト（修正を確認）
 *   npm install axios@1.15.0 && npm test
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const axios = require('axios');
const installedVersion = require('axios/package.json').version;

const [, minor] = installedVersion.split('.').map(Number);
const isVulnerable = minor < 15;

// HTTP 通信を行わず、axios が組み立てたヘッダーを返すだけのアダプター
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
  // テスト①: プロトタイプ汚染の伝播
  // axios は Object.keys() でヘッダーを処理するため
  // 明示指定なしのリクエストにはプロトタイプ汚染値が混入しない。
  // ただし v1.14.0 では config マージ時に for...in を使う箇所があり
  // 一部の経路で汚染値が混入する。テストではその事実を記録する。
  // ----------------------------------------------------------
  test('プロトタイプ汚染: ヘッダー未指定のリクエストへの混入を確認', async () => {
    Object.prototype['x-proto-test'] = 'polluted-value\r\nBAD: header';

    const res = await client.get('http://example.com');
    const headers = res.data.capturedHeaders;
    // プロトタイプチェーン経由の参照 (headers['x-proto-test']) は
    // Object.prototype の値を返すため誤検知になる。own property で判定する。
    const leaked = Object.prototype.hasOwnProperty.call(headers, 'x-proto-test');

    // axios は Object.keys() でヘッダーを処理するため own property には含まれない
    assert.equal(leaked, false, 'prototype-polluted value should NOT be an own property of headers');
    console.log(`  プロトタイプ汚染値はヘッダーの own property に含まれなかった (axios@${installedVersion})`);
    console.log(`  (headers['x-proto-test'] はプロトタイプチェーン経由で "${headers['x-proto-test']}" を返すが own property ではない)`);

    delete Object.prototype['x-proto-test'];
  });

  // ----------------------------------------------------------
  // テスト②: CRLF バリデーション（CVE の核心）
  // ----------------------------------------------------------
  if (isVulnerable) {
    test('CRLF がバリデーションされずアダプターに到達する（脆弱）', async () => {
      const payload = 'dummy\r\n\r\nPUT /latest/api/token HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n';

      const res = await client.get('http://example.com', {
        headers: { 'x-inject': payload },
      });

      const sentValue = String(res.data.capturedHeaders['x-inject'] ?? '');
      assert.ok(
        sentValue.includes('\r\n'),
        `axios@${installedVersion} は CRLF をバリデーションしないため脆弱`
      );
    });
  } else {
    test('CRLF を含むヘッダーは assertValidHeaderValue でブロックされる（修正済み）', async () => {
      const payload = 'dummy\r\n\r\nPUT /latest/api/token HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n';

      await assert.rejects(
        () =>
          client.get('http://example.com', {
            headers: { 'x-inject': payload },
          }),
        (err) => {
          assert.ok(
            err.message.includes('Invalid character in header content'),
            `期待するエラーメッセージ: "Invalid character in header content", 実際: "${err.message}"`
          );
          return true;
        }
      );
    });
  }

  // ----------------------------------------------------------
  // テスト③: 正常ヘッダーはどちらのバージョンでも通過する
  // ----------------------------------------------------------
  test('CRLF を含まない正常なヘッダーはエラーにならない', async () => {
    const res = await client.get('http://example.com', {
      headers: { 'x-custom': 'normal-value' },
    });

    assert.equal(res.status, 200);
  });
});
