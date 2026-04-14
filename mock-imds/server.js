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
  // Allow cross-origin requests from browser (for educational lab purposes)
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, PUT, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');

  // OPTIONS preflight request response
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

  // IMDSv2: PUT request to issue token
  if (req.method === 'PUT' && req.url === '/latest/api/token') {
    const ttl = req.headers['x-aws-ec2-metadata-token-ttl-seconds'];
    console.log(`\n[IMDS] ⚠️  IMDSv2 token issuance request detected! TTL=${ttl}`);
    console.log('[IMDS] 🔑  Returning fake token...');
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(FAKE_TOKEN);
    return;
  }

  // Retrieving IAM credentials
  if (req.url.startsWith('/latest/meta-data/iam/security-credentials')) {
    const token = req.headers['x-aws-ec2-metadata-token'];
    if (token === FAKE_TOKEN) {
      console.log('\n[IMDS] 🚨 IAM credentials have been stolen!');
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(FAKE_CREDENTIALS, null, 2));
    } else {
      res.writeHead(401);
      res.end('Unauthorized');
    }
    return;
  }

  // Other requests
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('mock-imds OK');
});

server.listen(80, () => {
  console.log('[IMDS] Fake AWS metadata server started (port 80)');
  console.log('[IMDS] Acting as 169.254.169.254...\n');
});
