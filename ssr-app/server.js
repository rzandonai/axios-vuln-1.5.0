/**
 * SSR攻撃再現サーバー
 *
 * 攻撃チェーン — JSON ボディ経由（vulnerableDeepMerge）:
 *   POST /api/profile
 *   {"__proto__": {"x-inject": "dummy\r\n\r\nPUT /latest/api/token HTTP/1.1\r\n..."}}
 *   → JSON.parse が __proto__ を own property として保持
 *   → for...in の vulnerableDeepMerge が Object.prototype を汚染
 *   → sendToInternalAPI の for...in がヘッダーへ漏洩
 *   → net.Socket で CRLF ごと送信（HTTP Request Splitting）
 */

const express = require('express');
const net = require('net');

const app = express();

// 脆弱なルート用:
// express.text() でボディを生文字列として取得してから手動で JSON.parse する。
// JSON.parse は {"__proto__": {...}} を own property として保持するため、
// vulnerableDeepMerge の for...in で __proto__ キーが列挙されプロトタイプ汚染が起きる。
app.use('/api/', express.text({ type: 'application/json' }));

// 安全なルート用: express.json() (body-parser@1.20.1) を使う。
// ※ body-parser@1.20.1 自体は __proto__ フィルタを持たない（bourne 非依存）。
//   このルートが安全な理由は safeDeepMerge が Object.keys() + __proto__ スキップを
//   使っているためであり、express.json() のパーサー自体の保護ではない。
app.use('/safe/', express.json());

const MOCK_IMDS_HOST = 'mock-imds';
const MOCK_IMDS_PORT = 80;

// ---------------------------------------------------------------
// 脆弱な deepMerge（lodash < 4.17.17 / jQuery < 3.4.0 などと同様の実装）
// __proto__ キーを無視しないため、プロトタイプ汚染が発生する
// ---------------------------------------------------------------
function vulnerableDeepMerge(target, source) {
  for (const key in source) {         // for...in でプロトタイプも辿る
    if (
      typeof source[key] === 'object' &&
      source[key] !== null &&
      !Array.isArray(source[key])
    ) {
      if (!target[key]) target[key] = {};
      vulnerableDeepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];      // __proto__ キーもここで処理される
    }
  }
  return target;
}

// ---------------------------------------------------------------
// 安全な deepMerge
// hasOwnProperty チェックで __proto__ キーを無視する
// ---------------------------------------------------------------
function safeDeepMerge(target, source) {
  for (const key of Object.keys(source)) {   // Object.keys() はプロトタイプを辿らない
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue;                               // 危険なキーを明示的にスキップ
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
// 内部APIへのリクエスト送信
// for...in でプロトタイプ汚染された値をヘッダーに取り込み、
// net.Socket でCRLFバリデーションをバイパスして送信する
// ---------------------------------------------------------------
function sendToInternalAPI(apiPath) {
  return new Promise((resolve) => {
    // for...in でプロトタイプチェーンから汚染値を収集（脆弱な実装）
    const defaults = {};
    const leakedHeaders = [];
    for (const key in defaults) {
      leakedHeaders.push({ key, value: String(defaults[key]) });
    }

    // HTTPリクエストを生文字列で組み立て（CRLFがそのまま含まれる）
    let rawRequest = `GET ${apiPath} HTTP/1.1\r\nHost: ${MOCK_IMDS_HOST}\r\n`;
    for (const { key, value } of leakedHeaders) {
      rawRequest += `${key}: ${value}\r\n`;
    }
    rawRequest += '\r\n';

    // net.Socket で直接送信（httpモジュールのCRLFバリデーションをバイパス）
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
// 脆弱なエンドポイント: POST /api/profile
// ユーザーのプロフィール設定をマージする、よくある実装
// ---------------------------------------------------------------
app.post('/api/profile', async (req, res) => {
  // express.text() がボディを生文字列で渡してくる → JSON.parse で解析
  // JSON.parse は __proto__ を own property として保持する（フィルタなし）
  let userInput = {};
  try {
    userInput = JSON.parse(req.body);
  } catch {
    return res.status(400).json({ error: 'Invalid JSON' });
  }

  console.log('\n[SSR] ⚠️  POST /api/profile 受信');
  console.log('[SSR] リクエストボディ:', JSON.stringify(userInput).slice(0, 200));

  // ユーザー入力を脆弱な deepMerge でマージ → プロトタイプ汚染発生
  const serverConfig = {};
  vulnerableDeepMerge(serverConfig, userInput);

  const polluted = Object.prototype['x-inject'];
  if (polluted) {
    console.log(`[SSR] 🚨 プロトタイプ汚染を検出！`);
    console.log(`[SSR]    x-inject = "${String(polluted).replace(/\r/g, '\\r').replace(/\n/g, '\\n').slice(0, 80)}..."`);
  }

  // 内部APIへのリクエスト（プロトタイプ汚染されたヘッダーが混入する）
  const result = await sendToInternalAPI('/api/healthcheck');

  console.log(`[SSR] 内部APIへ送信したリクエスト:\n${result.rawRequest.replace(/\r/g, '\\r').replace(/\n/g, '\\n')}`);

  res.json({
    endpoint: 'POST /api/profile（脆弱）',
    mergeFunction: 'vulnerableDeepMerge（for...in を使用）',
    prototypePolluted: !!polluted,
    pollutedValue: polluted
      ? String(polluted).replace(/\r/g, '\\r').replace(/\n/g, '\\n').slice(0, 150) + '...'
      : null,
    leakedHeaders: result.leakedHeaders,
    rawRequestSent: result.rawRequest,
    internalAPIResponseHead: result.raw.split('\r\n').slice(0, 8).join('\n')
  });

  // 汚染をリセット（次のリクエストへの影響を防ぐ）
  delete Object.prototype['x-inject'];
});

// ---------------------------------------------------------------
// 安全なエンドポイント: POST /safe/profile
// ---------------------------------------------------------------
app.post('/safe/profile', async (req, res) => {
  const userInput = req.body;

  console.log('\n[SSR] ✅ POST /safe/profile 受信');

  // 安全な deepMerge → __proto__ キーを無視する
  const serverConfig = {};
  safeDeepMerge(serverConfig, userInput);

  const polluted = Object.prototype['x-inject'];
  console.log(`[SSR] プロトタイプ汚染: ${polluted ? '発生' : 'なし（ブロック済み）'}`);

  const axios = require('axios');
  try {
    const response = await axios.get(`http://${MOCK_IMDS_HOST}/api/healthcheck`);
    res.json({
      endpoint: 'POST /safe/profile（安全）',
      mergeFunction: 'safeDeepMerge（Object.keys() + __proto__ スキップ）',
      prototypePolluted: !!polluted,
      internalAPIResponse: response.data
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.listen(4000, () => {
  console.log('[SSR] サーバー起動: http://localhost:4000');
  console.log('[SSR] 脆弱エンドポイント: POST /api/profile  （vulnerableDeepMerge）');
  console.log('[SSR] 安全エンドポイント: POST /safe/profile （safeDeepMerge）\n');
});
