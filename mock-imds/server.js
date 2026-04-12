const http = require('http');

const FAKE_TOKEN = 'FAKE-IMDS-TOKEN-AAABBBCCC111222';
const FAKE_CREDENTIALS = {
  Code: 'Success',
  LastUpdated: '2026-04-11T00:00:00Z',
  Type: 'AWS-HMAC',
  AccessKeyId: 'ASIA_FAKE_ACCESS_KEY_ID',
  SecretAccessKey: 'FAKE/SECRET/ACCESS/KEY/FOR/DEMO',
  Token: 'FAKE_SESSION_TOKEN_DEMO_ONLY',
  Expiration: '2026-04-12T00:00:00Z',
};

const server = http.createServer((req, res) => {
  // ブラウザからのクロスオリジンリクエストを許可（教育目的ラボのため）
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, PUT, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');

  // OPTIONSプリフライトリクエストへの応答
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  console.log('\n========================================');
  console.log(`[IMDS] ${req.method} ${req.url}`);
  console.log('[IMDS] Headers:');
  Object.entries(req.headers).forEach(([k, v]) => {
    console.log(`  ${k}: ${v}`);
  });

  // IMDSv2: PUTリクエストでトークン発行
  if (req.method === 'PUT' && req.url === '/latest/api/token') {
    const ttl = req.headers['x-aws-ec2-metadata-token-ttl-seconds'];
    console.log(`\n[IMDS] ⚠️  IMDSv2トークン発行リクエスト検知！TTL=${ttl}`);
    console.log('[IMDS] 🔑 偽トークンを返します...');
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(FAKE_TOKEN);
    return;
  }

  // IAM認証情報の取得
  if (req.url.startsWith('/latest/meta-data/iam/security-credentials')) {
    const token = req.headers['x-aws-ec2-metadata-token'];
    if (token === FAKE_TOKEN) {
      console.log('\n[IMDS] 🚨 IAM認証情報が窃取されました！');
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(FAKE_CREDENTIALS, null, 2));
    } else {
      res.writeHead(401);
      res.end('Unauthorized');
    }
    return;
  }

  // その他のリクエスト
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('mock-imds OK');
});

server.listen(80, () => {
  console.log('[IMDS] 偽AWSメタデータサーバー起動 (port 80)');
  console.log('[IMDS] 169.254.169.254 の代役として待機中...\n');
});
