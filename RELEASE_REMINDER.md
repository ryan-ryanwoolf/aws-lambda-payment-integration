# Release reminder — Partner API (JWT + payments)

Full **REST API** setup (Lambda functions, IAM, routes, authorizer, rate limiting, Postman): [`docs/API_GATEWAY_REST_SETUP.md`](docs/API_GATEWAY_REST_SETUP.md)

This JAR supports multiple handlers:

| Handler | Class |
|---------|--------|
| Issue JWT (public `POST /auth/token`) | `com.ryanwoolf.auth.PartnerTokenIssuerHandler` |
| REST **TOKEN** Lambda authorizer | `com.ryanwoolf.auth.JwtPolicyAuthorizerHandler` |
| Payment initiation (`POST /payments`) | `com.ryanwoolf.transactions.PaymentInitiationHandler` |

## Lambda environment variables

### Partners table (token issuance)

| Variable | Description |
|----------|-------------|
| `PARTNER_TABLE_NAME` | DynamoDB table name. |
| `PARTNER_TABLE_PK_ATTRIBUTE` | Optional. Partition key attribute name (default: `partnerId`). |

### JWT — RS256 (issuer vs authorizer)

Tokens use **RS256**. The **issuer** signs with an RSA **private** key; the **authorizer** verifies with the matching **public** key. **`JWT_ISSUER`**, **`JWT_AUDIENCE`**, and **`JWT_TTL_SECONDS`** must match on both Lambdas.

**Secrets Manager (production):** set **`JWT_RSA_PRIVATE_KEY_SECRET_ID`** on the token Lambda and **`JWT_RSA_PUBLIC_KEY_SECRET_ID`** on the authorizer (secret **name** or **ARN**). Each secret may be **JSON** (e.g. key `JWT_RSA_PRIVATE_KEY_PEM` / `JWT_RSA_PUBLIC_KEY_PEM`) or **raw PEM** only. Override JSON field names with **`JWT_RSA_PRIVATE_KEY_SECRET_JSON_KEY`** / **`JWT_RSA_PUBLIC_KEY_SECRET_JSON_KEY`** if needed. PEM is cached per runtime container after first load.

**Local / fallback:** omit the `*_SECRET_ID` variables and set PEM in env instead.

| Variable | Where | Description |
|----------|--------|-------------|
| `JWT_RSA_PRIVATE_KEY_SECRET_ID` | Token issuer | Optional. Secrets Manager id for private key (JSON or raw PEM). |
| `JWT_RSA_PRIVATE_KEY_SECRET_JSON_KEY` | Token issuer | Optional. Default `JWT_RSA_PRIVATE_KEY_PEM`. |
| `JWT_RSA_PRIVATE_KEY_PEM` | Token issuer | Optional if `JWT_RSA_PRIVATE_KEY_SECRET_ID` is set. PKCS#8 PEM. |
| `JWT_RSA_PUBLIC_KEY_SECRET_ID` | JWT authorizer | Optional. Secrets Manager id for public key. |
| `JWT_RSA_PUBLIC_KEY_SECRET_JSON_KEY` | JWT authorizer | Optional. Default `JWT_RSA_PUBLIC_KEY_PEM`. |
| `JWT_RSA_PUBLIC_KEY_PEM` | JWT authorizer | Optional if `JWT_RSA_PUBLIC_KEY_SECRET_ID` is set. SPKI PEM. |
| `JWT_ISSUER` | Both | Optional. Default `partner-api`. |
| `JWT_AUDIENCE` | Both | Optional. Default `partner-payments`. |
| `JWT_TTL_SECONDS` | Both | Optional. Default `3600`. |

Region for the Secrets Manager client uses **`AWS_REGION`** or **`AWS_DEFAULT_REGION`** (Lambda sets `AWS_REGION` automatically).

**PEM newlines:** `RsaPemKeys` normalizes `\\n` → newline in PEM text.

### JWT authorizer — payment route guard

| Variable | Description |
|----------|-------------|
| `PAYMENT_INITIATION_HTTP_METHOD` | Optional. Default `POST`. |
| `PAYMENT_INITIATION_RESOURCE_PATH` | Optional. Default `payments` (path segment in execute-api ARN). |

### Payment handler — transactions table

| Variable | Description |
|----------|-------------|
| `TRANSACTIONS_TABLE_NAME` | Required. DynamoDB table for payment initiations. |
| `TRANSACTIONS_TABLE_PK_ATTRIBUTE` | Optional. Partition key name (default: `idempotencyKey`). Stores the composite key `partnerId#<client Idempotency-Key header>`. |

## IAM (Lambda execution role)

- **Token issuer**: `dynamodb:GetItem` on the partner table; if using Secrets Manager for the private key, `secretsmanager:GetSecretValue` on that secret ARN (and `kms:Decrypt` if the secret uses a customer-managed KMS key).
- **JWT authorizer**: if using Secrets Manager for the public key, `secretsmanager:GetSecretValue` on that secret ARN (and `kms:Decrypt` if applicable).
- **Payment handler**: `dynamodb:PutItem` on the transactions table (conditional create).

If you see **`Runtime.BadFunctionCode`** on cold start, it was often a **constructor-time** Secrets Manager failure. Issuer and authorizer now load keys on **first invoke**, so CloudWatch should show the real error (for example `AccessDeniedException` or `ResourceNotFoundException`). Fix IAM, region, and `JWT_RSA_*_SECRET_ID` to match the secret.

## DynamoDB item (transactions)

| Attribute | Type |
|-----------|------|
| `idempotencyKey` | String (PK) — composite `{partnerId}#{client Idempotency-Key}`; same value returned as `transactionId` in the API. |
| `partnerId` | String |
| `status` | String — initial value `PENDING`. |
| `createdAt` | String — ISO-8601 timestamp (UTC `Instant.toString()`). |

## DynamoDB item (partners)

| Attribute | Type |
|-----------|------|
| `partnerId` | String (PK) — unique partner identifier. |
| `apiKeyHash` | String — Argon2id encoded hash of the API key. |
| `partner` | String |
| `enabled` | BOOL |
