# Ferrum

A secrets management server built from scratch in Go. No third-party security libraries. Every cryptographic primitive implemented directly against the Go standard library.

Ferrum stores secrets encrypted at rest, issues time-limited access tokens, enforces role-based access control, and writes an append-only audit trail of every request. The goal was not to replicate HashiCorp Vault. The goal was to understand exactly what a secrets manager has to get right, and then get it right.

---

## Why this exists

Most developers use security libraries without understanding what they do. That works until something breaks or an attacker finds the gap you did not know existed.

Ferrum was built as a learning exercise in adversarial thinking. Every design decision starts from the question: what does an attacker do if this fails? The answers shaped the implementation.

---

## What it does

Clients authenticate against `POST /auth` with a username and password. On success, Ferrum issues a signed JWT. Every subsequent request must carry that token in the `Authorization` header. The token encodes the caller's role. Middleware verifies the token and enforces access policy before any handler runs.

Secrets are stored encrypted on disk. A stolen filesystem reveals nothing without the encryption key. When the server restarts, it decrypts and reloads secrets from disk automatically.

Every request is logged to an append-only audit file in JSONL format: who made it, what they did, when, and what the outcome was.

---

## Technical decisions and why

**AES-256-GCM for encryption at rest.**
GCM is authenticated encryption. It does not just hide the data, it also detects tampering. If a secret file is modified on disk, decryption fails with an error before any plaintext is returned. A fresh cryptographically random nonce is generated for every encryption operation. Nonce reuse under GCM is catastrophic and is tested explicitly.

**JWT from scratch using HMAC-SHA256.**
No JWT library. The header, payload, and signature are constructed manually. The signing and verification logic sits in about 60 lines of Go. This means the implementation can be read, audited, and understood completely. The signature is verified before expiry is checked, because an unverified token's claims are attacker-controlled data and must not be trusted.

**Constant-time comparisons throughout.**
Token signature comparison uses `hmac.Equal`. Password comparison uses `crypto/subtle.ConstantTimeCompare`. Neither returns early on a mismatch. A regular string comparison leaks timing information that an attacker can use to forge signatures or enumerate valid passwords one byte at a time.

**Role-based access control with a numeric rank system.**
Two roles: `admin` and `reader`. Roles carry numeric ranks. The access policy maps each HTTP method and path to a minimum required rank. Adding a new role requires one line. Changing a permission requires one line. The entire policy is readable in one place.

**Append-only audit logging in JSONL.**
The log file is opened with `O_APPEND` at the OS level, not enforced by application logic. Each entry is a self-contained JSON object on its own line. The format is machine-readable, grep-friendly, and appendable without parsing the existing file. Unauthenticated requests are logged with subject `anonymous`, never with the caller-supplied username, which is untrusted input.

**Input validation on secret keys.**
Secret keys become filenames. Keys containing `/`, `\`, `.`, or null bytes are rejected before they reach the filesystem. Path traversal is not mitigated after the fact. It is prevented at the boundary.

**Dependency injection throughout.**
The store, the token key, and the audit logger are passed into the server constructor. Nothing is global. This makes every component independently testable with `httptest` without starting a real server or touching the real filesystem.

---

## Architecture

```
cmd/ferrum/        binary entry point
internal/
  api/             HTTP handlers, middleware, RBAC
  audit/           append-only JSONL audit logger
  crypto/          AES-GCM encrypt and decrypt
  store/           thread-safe in-memory store with encrypted disk persistence
  token/           JWT issue and verify
data/
  secrets/         encrypted secret files (one per key)
  audit.log        append-only audit trail
```

---

## API

| Method | Path | Role required | Description |
|--------|------|---------------|-------------|
| POST | `/auth` | none | Authenticate and receive a JWT |
| POST | `/secrets` | admin | Store a new secret |
| GET | `/secrets/{key}` | reader | Retrieve a secret by key |
| DELETE | `/secrets/{key}` | admin | Delete a secret |
| GET | `/secrets` | reader | List all secret keys |

Secrets are returned by key name only in the list endpoint. Values are never included in list responses.

---

## Running locally

```bash
git clone https://github.com/t-Shack/ferrum
cd ferrum
go run ./cmd/ferrum
```

The server starts on `:8080`. Authenticate first, then use the returned token on all subsequent requests.

```bash
# Authenticate
curl -X POST http://localhost:8080/auth \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"ferrum-admin-password"}'

# Store a secret
curl -X POST http://localhost:8080/secrets \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"key":"db_password","value":"supersecret"}'

# Retrieve it
curl http://localhost:8080/secrets/db_password \
  -H "Authorization: Bearer <token>"
```

---

## Test suite

```bash
go test -count=1 ./...
```

Tests cover the full stack: AES-GCM round trips, nonce uniqueness, tamper detection, JWT signing and verification, token expiry, wrong-key rejection, store concurrency, encrypted persistence across restarts, HTTP handler behaviour, RBAC enforcement, audit log integrity, and input validation edge cases. No test shares state with another.

---

## What this is not

Ferrum is not production-ready. Credentials are hardcoded. The encryption key is derived from a loop, not from a secure key management system. There is no TLS. These are known and deliberate: the project exists to demonstrate understanding of security engineering fundamentals, not to ship a product.

The implementation decisions that matter for that purpose are all present and intentional.

---

## Built with

Go 1.26 standard library only. No third-party dependencies.

`crypto/aes` `crypto/cipher` `crypto/hmac` `crypto/rand` `crypto/sha256` `crypto/subtle` `encoding/json` `net/http` `os` `sync` `testing`
