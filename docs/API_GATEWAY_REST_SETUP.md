# API Gateway REST API — partner JWT, token endpoint, and payment initiation

This project exposes **three Lambda handlers** (same shaded JAR, different handler classes) for a **REST API** flow:

| Handler class | Purpose |
|----------------|---------|
| `com.ryanwoolf.auth.PartnerTokenIssuerHandler` | **Public** `POST /auth/token` — validates `x-api-key` + `x-partner-id` (Argon2 in DynamoDB), returns JWT. |
| `com.ryanwoolf.auth.JwtPolicyAuthorizerHandler` | **Lambda authorizer** (`TOKEN` type) — verifies JWT, returns an IAM policy that allows `execute-api:Invoke` **only** for the incoming `methodArn` when it matches your payment route (see env vars). |
| `com.ryanwoolf.transactions.PaymentInitiationHandler` | **Protected** `POST /payments` — reads `partnerId` / `partner` **only** from `requestContext.authorizer`; requires `Idempotency-Key` header; writes a **PENDING** row to DynamoDB (`partnerId#key` composite PK). |

---

## 1. Prerequisites

1. **Partners DynamoDB table** with `partnerId` (PK), `apiKeyHash` (Argon2), `partner`, `enabled` — as in `RELEASE_REMINDER.md`.
2. **Transactions DynamoDB table** — partition key attribute name default **`idempotencyKey`** (String). Items are created by `PaymentInitiationHandler` — see `RELEASE_REMINDER.md`.
3. **Three Lambda functions** — see [§2 AWS Lambda setup](#2-aws-lambda-setup) for step-by-step creation:
   - **PartnerTokenIssuer** — handler `com.ryanwoolf.auth.PartnerTokenIssuerHandler`
   - **JwtAuthorizer** — handler `com.ryanwoolf.auth.JwtPolicyAuthorizerHandler`
   - **PaymentInitiation** — handler `com.ryanwoolf.transactions.PaymentInitiationHandler`
4. The **same** shaded JAR (`target/partner-api-key-authorizer-1.0.0.jar`) uploaded to all three; only the **Handler** string differs (§2.3).
5. **IAM**
   - **Token issuer**: `dynamodb:GetItem` on the partners table.
   - **Payment handler**: `dynamodb:PutItem` on the transactions table.
   - **JWT authorizer**: **no DynamoDB**; only needs CloudWatch Logs. **Both** token issuer and authorizer must use the **same** JWT signing configuration (see env vars).

---

## 2. AWS Lambda setup

This section walks through **building the JAR**, **IAM roles**, and **creating the three Lambda functions** in AWS. API Gateway wiring is in [§4](#4-create-the-rest-api-console-outline); environment variable reference is in [§3](#3-environment-variables).

### 2.1 Build the deployment package

From the **project root** (where `pom.xml` lives):

```bash
mvn package
```

Use Java **21** locally if your compiler targets match `pom.xml` (`maven.compiler.source` / `target`).

**Output:** `target/partner-api-key-authorizer-1.0.0.jar` — a **shaded (fat) JAR** containing your code and dependencies.

- Use this **same JAR file** for all three Lambdas.
- Only the **Handler** class name differs per function (see §2.3).

If the JAR is **too large** for a direct console upload (~50 MB zipped limit varies), upload to **S3** first, then in Lambda choose **Upload from** → **Amazon S3 location**.

### 2.2 IAM execution roles

Create **one IAM role per Lambda** (simplest to reason about least privilege), or one shared role whose policy is the **union** of all three (acceptable for small accounts).

**Trust policy (each role):** allow `lambda.amazonaws.com` to assume the role (the **Create Lambda** wizard usually creates this automatically).

**Attach the AWS managed policy:**

- `AWSLambdaBasicExecutionRole` — sends logs to **CloudWatch Logs**.

**Add permissions to DynamoDB tables** (replace `region`, `account-id`, and table names):

| Lambda | Policy intent |
|--------|----------------|
| **Partner token issuer** | `dynamodb:GetItem` on the **partners** table ARN, e.g. `arn:aws:dynamodb:<region>:<account-id>:table/<PartnersTableName>` |
| **JWT authorizer** | No DynamoDB required (JWT verify only). |
| **Payment initiation** | `dynamodb:PutItem` on the **transactions** table ARN, e.g. `arn:aws:dynamodb:<region>:<account-id>:table/<TransactionsTableName>` |

Keep ARNs **table-scoped**; avoid `Resource: *` for DynamoDB in production.

### 2.2.1 Storing JWT keys in AWS Secrets Manager

**Runtime (implemented):** set **`JWT_RSA_PRIVATE_KEY_SECRET_ID`** / **`JWT_RSA_PUBLIC_KEY_SECRET_ID`** to the Secrets Manager secret **name** or **ARN**. The code calls **`GetSecretValue`**, supports **JSON** (default keys `JWT_RSA_PRIVATE_KEY_PEM` / `JWT_RSA_PUBLIC_KEY_PEM`) or **raw PEM**, and **caches** the PEM per Lambda instance. **`AWS_REGION`** is used automatically in Lambda.

**Alternative:** set **`JWT_RSA_PRIVATE_KEY_PEM`** / **`JWT_RSA_PUBLIC_KEY_PEM`** in env only (local dev or small setups). See §3.

#### How to structure the secret

| Recommendation | Details |
|----------------|---------|
| **Two secrets (preferred)** | One secret for the **private** key (token issuer only), one for the **public** key (JWT authorizer only). Smaller blast radius than one secret holding both. |
| **Secret type** | In the console choose **Other type of secret** (or store as **Plaintext** if you only paste the PEM). |
| **Payload** | **Either** store the **entire PEM** as the secret **plaintext** string, **or** JSON with keys **`JWT_RSA_PRIVATE_KEY_PEM`** / **`JWT_RSA_PUBLIC_KEY_PEM`** (override with `JWT_RSA_*_SECRET_JSON_KEY` env vars). `JwtSecretPemLoader` turns that into the string passed to `RsaPemKeys`. |
| **Multi-line in JSON** | Escape newlines as `\n` inside JSON, or store **plaintext** secret and paste real newlines. `RsaPemKeys` also accepts `\n` as two characters in a single-line string. |
| **Encryption key** | Default **Secrets Manager** KMS key is fine. If you use a **customer managed KMS CMK**, the Lambda role also needs `kms:Decrypt` on that key (often via the CMK key policy + IAM). |

Avoid **automatic rotation** for JWT signing keys unless you have a thought-out dual-key (overlap) process; it is not like a database password rotation.

#### IAM on the Lambda execution role

Add **`secretsmanager:GetSecretValue`** (and optionally **`secretsmanager:DescribeSecret`**) on **only** the secret ARN(s) each function needs:

| Lambda | Secret | Typical ARN pattern |
|--------|--------|---------------------|
| Token issuer | Private key | `arn:aws:secretsmanager:<region>:<account-id>:secret:<name>-<randomSuffix>` |
| JWT authorizer | Public key | Same as above for the public-key secret |

Scope **`Resource`** to those ARNs (wildcard only on the deterministic suffix if your org allows `secret:name-*`).

#### Ways to get the PEM into this application

| Approach | What you do | Pros / notes |
|--------|-------------|----------------|
| **A. Deploy-time resolution (IaC)** | In **AWS SAM**, **CDK**, **Terraform**, or **CloudFormation**, use a pattern that reads the secret at deploy time and sets Lambda env vars `JWT_RSA_PRIVATE_KEY_PEM` / `JWT_RSA_PUBLIC_KEY_PEM`. | No code change; values match what the JAR expects. Env values are visible in Lambda console to anyone with view access—mitigate with tight IAM and **no logging of env**. |
| **B. CloudFormation dynamic reference** | In template: environment value like `{{resolve:secretsmanager:arn…}}` (see [AWS docs](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references-secretsmanager.html)). | Same as A; standard for SAM/CFN. |
| **C. Runtime `GetSecretValue` in Java** | **`JwtSecretPemLoader`** (used by **`JwtTokenService`**) loads secrets by id env vars; PEM is cached after the first read. | **Implemented in this repo.** PEM never appears in Lambda **environment variable values** in the console. |
| **D. Parameters and Secrets Lambda Extension** | Add the [AWS extension](https://docs.aws.amazon.com/systems-manager/latest/userguide/ps-integration-lambda-extensions.html) layer; fetch secret over HTTP from the extension with caching. | Fewer Secrets Manager API calls; good at high volume. Still needs glue code to pass PEM into **`JwtTokenService`**. |

For **production**, **C** (runtime fetch) is usually simplest with this codebase. **A/B** remains valid if you prefer inlined env PEM from IaC.

#### Optional: resource policy

Secrets Manager **does not** require a resource policy for access from your own account’s Lambda role if **IAM on the role** grants `GetSecretValue`. Cross-account access would need both IAM and a secret **resource policy**.

### 2.3 Create each Lambda function (console)

Repeat the following for **three** functions. Use the **same AWS Region** as API Gateway and DynamoDB.

1. Open **AWS Lambda** → **Create function**.
2. Choose **Author from scratch**.
3. **Function name:** for example  
   - `PartnerTokenIssuer`  
   - `JwtAuthorizer`  
   - `PaymentInitiation`
4. **Runtime:** **Java 21** (aligned with this project’s `pom.xml`; if your account only offers Java 17, align the project `pom.xml` and rebuild).
5. **Architecture:** **x86_64** is fine unless you standardize on **arm64** (Graviton).
6. **Execution role:** choose **Use an existing role**, and select the role from §2.2 with the correct DynamoDB permissions for **that** function.
7. Click **Create function**.

**After creation, configure each function:**

#### Code

1. Open the **Code** tab.
2. **Upload from** → **.zip or .jar** → select `partner-api-key-authorizer-1.0.0.jar` (or deploy from S3).
3. Open **Runtime settings** → **Edit**:
   - **Handler** must be exactly **one** of:

| Function | Handler (fully qualified class name) |
|----------|--------------------------------------|
| Partner token issuer | `com.ryanwoolf.auth.PartnerTokenIssuerHandler` |
| JWT authorizer | `com.ryanwoolf.auth.JwtPolicyAuthorizerHandler` |
| Payment initiation | `com.ryanwoolf.transactions.PaymentInitiationHandler` |

For AWS Lambda **Java** with `RequestHandler`, the handler is typically the **class name only** (no `::methodName`). If your console or deployment tool requires `Class::handleRequest`, use your tool’s documented format.

4. **Save**.

#### General configuration

Under **Configuration** → **General configuration** → **Edit**:

- **Memory:** start with **512 MB**; increase if you see slow cold starts or high duration (token path runs Argon2 in `PartnerLookupService`).
- **Timeout:** e.g. **10 s** for token + authorizer; **15–30 s** for payment (DynamoDB + future async work).

#### Environment variables

Under **Configuration** → **Environment variables** → **Edit**, set variables per [§3](#3-environment-variables). Minimum per function:

| Function | Required variables |
|----------|---------------------|
| Token issuer | **`JWT_RSA_PRIVATE_KEY_SECRET_ID`** *or* **`JWT_RSA_PRIVATE_KEY_PEM`**; **`PARTNER_TABLE_NAME`**; optional `JWT_*`, `PARTNER_TABLE_PK_ATTRIBUTE`, `JWT_RSA_PRIVATE_KEY_SECRET_JSON_KEY` |
| JWT authorizer | **`JWT_RSA_PUBLIC_KEY_SECRET_ID`** *or* **`JWT_RSA_PUBLIC_KEY_PEM`**; optional `JWT_*`, `PAYMENT_INITIATION_*`, `JWT_RSA_PUBLIC_KEY_SECRET_JSON_KEY` |
| Payment | `TRANSACTIONS_TABLE_NAME`; optional `TRANSACTIONS_TABLE_PK_ATTRIBUTE` |

**Critical:** Use a matching RSA key pair (private on issuer, public on authorizer). **`JWT_ISSUER`** and **`JWT_AUDIENCE`** must be the **same** on both Lambdas. Tokens are **RS256**.

#### Logging

With `AWSLambdaBasicExecutionRole`, each invocation writes to **CloudWatch Logs** log group `/aws/lambda/<FunctionName>`. Use this when debugging 401/403/409 responses.

### 2.4 Allow API Gateway to invoke your Lambdas

When you connect Lambda to API Gateway (integration or authorizer), the console usually prompts to **add a resource-based policy** so `apigateway.amazonaws.com` can invoke the function.

If calls fail with access denied:

1. **Lambda** → **Configuration** → **Permissions** → scroll to **Resource-based policy statements**.
2. Confirm a statement allows **Invoke** from API Gateway for your API’s **execute-api** ARN (or create the integration again and accept **Add permissions**).

Authorizer Lambdas and integration Lambdas **each** need invoke permission from API Gateway for the APIs that use them.

### 2.5 Redeploy after code or config changes

1. Run `mvn package` (add `-DskipTests` locally if you prefer).
2. Upload the new JAR to **each** of the three functions (or automate via CI/CD, SAM, CDK, Terraform).
3. If you use **aliases** or **versions** in production, publish a new **version** and move the **alias**; otherwise `$LATEST` is enough for development.

---

## 3. Environment variables

### JWT — RS256 (token issuer vs authorizer)

| Variable | Required on | Description |
|----------|-------------|-------------|
| `JWT_RSA_PRIVATE_KEY_SECRET_ID` | Token issuer | Optional. Secrets Manager secret **name** (e.g. `jwt-private-key-for-lambda-token-creator`) or **ARN**. If set, PEM is loaded at runtime (JSON key `JWT_RSA_PRIVATE_KEY_PEM` by default). |
| `JWT_RSA_PRIVATE_KEY_SECRET_JSON_KEY` | Token issuer | Optional. Default `JWT_RSA_PRIVATE_KEY_PEM`. |
| `JWT_RSA_PRIVATE_KEY_PEM` | Token issuer | Optional if `JWT_RSA_PRIVATE_KEY_SECRET_ID` is set. PKCS#8 PEM for local/dev. |
| `JWT_RSA_PUBLIC_KEY_SECRET_ID` | JWT authorizer | Optional. Secrets Manager id for the public key. |
| `JWT_RSA_PUBLIC_KEY_SECRET_JSON_KEY` | JWT authorizer | Optional. Default `JWT_RSA_PUBLIC_KEY_PEM`. |
| `JWT_RSA_PUBLIC_KEY_PEM` | JWT authorizer | Optional if `JWT_RSA_PUBLIC_KEY_SECRET_ID` is set. SPKI PEM. |
| `JWT_ISSUER` | Both | Optional. Default `partner-api`. Must match issuer and verifier. |
| `JWT_AUDIENCE` | Both | Optional. Default `partner-payments`. Must match. |
| `JWT_TTL_SECONDS` | Both | Optional. Default `3600`. |

**Generate a key pair (example with OpenSSL):**

```bash
openssl genrsa -out rsa-private.pem 2048
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in rsa-private.pem -out rsa-private-pkcs8.pem
openssl rsa -in rsa-private-pkcs8.pem -pubout -out rsa-public.pem
```

- Store **`rsa-private-pkcs8.pem`** contents in Secrets Manager (or set env `JWT_RSA_PRIVATE_KEY_PEM`).
- Store **`rsa-public.pem`** in a second secret (or set env `JWT_RSA_PUBLIC_KEY_PEM`).

For env-only PEM, newlines can be real or `\n` escapes; `RsaPemKeys` normalizes `\\n` → newline.

### Token issuer only (`PartnerTokenIssuerHandler`)

| Variable | Required | Description |
|----------|----------|-------------|
| `PARTNER_TABLE_NAME` | Yes | Partners DynamoDB table. |
| `PARTNER_TABLE_PK_ATTRIBUTE` | No | Default `partnerId`. |

### JWT authorizer only (`JwtPolicyAuthorizerHandler`)

| Variable | Required | Description |
|----------|----------|-------------|
| `PAYMENT_INITIATION_HTTP_METHOD` | No | Default `POST`. |
| `PAYMENT_INITIATION_RESOURCE_PATH` | No | Default `payments` (must match the **last** path segment in API Gateway’s `methodArn` for that integration, e.g. `.../POST/payments`). |

### Payment handler (`PaymentInitiationHandler`)

| Variable | Required | Description |
|----------|----------|-------------|
| `TRANSACTIONS_TABLE_NAME` | Yes | Transactions table name. |
| `TRANSACTIONS_TABLE_PK_ATTRIBUTE` | No | Default `idempotencyKey` (partition key stores `partnerId#<Idempotency-Key header>`). |

---

## 4. Create the REST API (console outline)

1. **API Gateway** → **REST API** → **Build** (or **Import**).
2. **Actions** → **Create Resource**
   - Resource path: `auth` (no CORS required for server-to-server; optional for browsers).
3. Under `auth`, **Create Resource** `token`.
4. Select `/auth/token` → **Create Method** → **POST**:
   - Integration type: **Lambda Function**
   - Lambda: `PartnerTokenIssuer`
   - Use **Lambda Proxy integration** (recommended).
5. **Deploy API** to a stage (e.g. `dev`).

### Payment resource

1. **Create Resource** at root: `payments` (path `{payments}` literal name `payments`).
2. **POST** → **Lambda Proxy** → `PaymentInitiation` Lambda.
3. **Method Request**:
   - **Authorization** → **Custom**
   - **Authorizer** → create new **Lambda Authorizer**:
     - **Name:** e.g. `JwtPaymentAuthorizer`
     - **Lambda function:** `JwtAuthorizer`
     - **Lambda event payload:** **TOKEN**
     - **Token source:** `Authorization` (header)
     - **TTL:** e.g. `300` seconds (adjust for your security vs. caching tradeoff).
4. Save and **grant API Gateway permission** to invoke the authorizer Lambda when prompted.

> The authorizer returns an IAM policy whose **Resource** is exactly the incoming `methodArn`. That ties **Allow** to this **POST /payments** method only. `JwtPolicyAuthorizerHandler` also **parses** `methodArn` and **denies** if the route is not `POST` + your configured resource path (fail closed if the authorizer were ever attached to the wrong method).

5. **Deploy API** again after changes.

---

## 5. Rate limiting the public token endpoint (`POST /auth/token`)

API Gateway **usage plans** throttle per **API key**; your token endpoint is “public” in the sense of **no JWT**, but you should still **throttle and abuse‑protect**:
Set to 
Rate: 100
Burst: 50 (adjust for your expected legitimate traffic volume and partner count).

It should never get anywhere near these limits under normal use, but they provide a safety net against credential leaks or abuse.


### Option A — Stage / method throttling (simple)

1. **Stage** → **Stage Editor** → **Settings** / **Default Method Throttling** (or **Method** → **Throttling** for `POST /auth/token` only).
2. Set **Burst** and **Rate** limits appropriate for legitimate partners.

### Option B — Usage plan + API keys (per partner or per integration)

1. **API Keys** → create keys (optional: one per partner).
2. **Usage Plans** → link API + stage + keys, set throttle & quota.
3. For `POST /auth/token`, require a header such as `x-api-key` **for the API Gateway usage plan key** is separate from your **partner** `x-api-key` credential — avoid naming collision:
   - e.g. use plan key in `x-gateway-key` while partner secret stays `x-api-key`, **or**
   - rely on stage throttling + WAF only.

### Option C — AWS WAF on the API

Associate an **AWS WAF** web ACL with the API stage and add a **rate-based rule** scoped to `/auth/token` (path condition). This is the strongest option for anonymous public abuse.

---

## 6. Testing — Lambda console

### Token issuer

**Test event** (REST proxy style), replace values:

```json
{
  "httpMethod": "POST",
  "path": "/auth/token",
  "headers": {
    "x-api-key": "<valid-api-key-plaintext>",
    "x-partner-id": "<partnerId>",
    "Content-Type": "application/json"
  },
  "body": null,
  "isBase64Encoded": false
}
```

Expect **200** and JSON with `access_token`, `token_type`, `expires_in`.

### JWT authorizer

Authorizer test event:

```json
{
  "type": "TOKEN",
  "authorizationToken": "Bearer <paste access_token>",
  "methodArn": "arn:aws:execute-api:<region>:<account-id>:<api-id>/<stage>/POST/payments"
}
```

Expect **policyDocument** with **Allow** and **context** containing `partnerId` / `partner` strings.

Use the **exact** `methodArn` format your stage produces (copy from a failed authorizer log if needed).

### Payment initiation

Use `src/test/resources/apigateway-rest-proxy-post-payments.json` as a template; include header **`Idempotency-Key`**, and set `requestContext.authorizer` to the same shape API Gateway injects after a successful authorizer (string map).

---

## 7. Testing — Postman

1. **Issue token**  
   `POST https://{api-id}.execute-api.{region}.amazonaws.com/{stage}/auth/token`  
   Headers:
   - `x-api-key`: partner API key plaintext  
   - `x-partner-id`: partner id  
   Body: optional empty.

2. **Initiate payment**  
   `POST https://{api-id}.execute-api.{region}.amazonaws.com/{stage}/payments`  
   Headers:
   - `Authorization`: `Bearer {access_token}`  
   - `Idempotency-Key`: unique key per logical payment (scoped in storage with authenticated `partnerId`)  
   - `Content-Type`: `application/json`  
   Body: payment JSON (amount, currency, etc.) — **do not** send `partnerId`; it comes from the JWT authorizer context.

Expect **202** and `{ "transactionId", "partnerId", "partner", "status": "PENDING", "repeat": false }` where **`transactionId`** equals the DynamoDB partition key (`partnerId#` + your `Idempotency-Key`). A duplicate **same** partner + same key returns **409** (`IDEMPOTENCY_CONFLICT`).

---

## 8. Security checklist

- [ ] RSA private key is **only** on the token issuer; public key on the authorizer. Neither is committed to git (use Secrets Manager / SSM for production).
- [ ] Token issuer uses **HTTPS** only (API Gateway default).
- [ ] Payment Lambda trusts **only** `requestContext.authorizer` for partner identity.
- [ ] Authorizer **Deny** on wrong route or bad JWT (handler returns explicit Deny policy).
- [ ] Throttling / WAF in place on `/auth/token`.
