# ATECC608 Security API

A **FastAPI**-based cryptographic security service that exposes core security
primitives over HTTP for **IoT** and **blockchain** applications.

It provides ECC key generation, SHA-256 hashing, ECDSA digital signatures,
ECDH shared-secret derivation, cryptographically secure random bytes and an
API-key authentication layer.

---

## Features

| Primitive | Standard | Endpoint |
|-----------|----------|----------|
| ECC Key Generation | NIST P-256 (`secp256r1`) | `POST /api/v1/keys/generate` |
| Public Key Retrieval | PEM `SubjectPublicKeyInfo` | `GET  /api/v1/keys/{key_id}` |
| SHA-256 Hashing | FIPS 180-4 | `POST /api/v1/hash/sha256` |
| ECDSA Sign | FIPS 186-4 + SHA-256 | `POST /api/v1/ecdsa/sign` |
| ECDSA Verify | FIPS 186-4 + SHA-256 | `POST /api/v1/ecdsa/verify` |
| ECDH Shared Secret | SP 800-56A | `POST /api/v1/ecdh/derive` |
| Secure Random Bytes | OS CSPRNG | `POST /api/v1/random/generate` |
| API-Key Issuance | SHA-256 token hashing | `POST /api/v1/auth/api-key` |

**Security properties**
- Private keys are generated in-process and **never serialized or returned** —
  only the public key is exported.
- API keys are stored **only as SHA-256 hashes** (the raw key is shown once).
- All randomness comes from the OS CSPRNG (`secrets`) — no PRNG in any
  security path.
- `InvalidSignature` is absorbed at the service layer and returned as a
  boolean, so no stack traces leak to clients.

---

## Architecture

A strict three-layer design — routes never touch cryptographic objects directly:

```
API / Routes  →  Core (facades, auth, key manager)  →  Services (crypto primitives)
                         ↓                                    ↓
                  key store / API-key store          cryptography, hashlib, secrets
```

See [`ALGORITHM.md`](ALGORITHM.md) for the full algorithm specification of
every module, including complexity analysis and end-to-end workflows.

---

## Requirements

- Python 3.11+

## Installation

```bash
pip install -r requirements.txt
```

## Running the API

```bash
uvicorn app.main:app --reload
```

- Interactive docs (Swagger UI): <http://127.0.0.1:8000/docs>
- ReDoc: <http://127.0.0.1:8000/redoc>
- Dashboard: <http://127.0.0.1:8000/>

## Running the tests

```bash
python -m pytest tests -q
```

Expected: **17 passed**.

---

## Example Usage

```bash
# 1. Generate a key pair
curl -X POST http://127.0.0.1:8000/api/v1/keys/generate

# 2. Hash some data
curl -X POST http://127.0.0.1:8000/api/v1/hash/sha256 \
     -H "Content-Type: application/json" \
     -d "{\"data\": \"hello\"}"

# 3. Generate 32 secure random bytes
curl -X POST "http://127.0.0.1:8000/api/v1/random/generate?length=32"
```

---

## Project Structure

```
.
├── app/
│   ├── main.py                  # FastAPI app factory + router registration
│   ├── api/routes/              # HTTP endpoints (keys, ecdsa, ecdh, hash, random, auth)
│   ├── core/                    # KeyManager, SecurityEngine, auth, api-key store
│   ├── schemas/                 # Pydantic request models
│   ├── services/                # Cryptographic primitives
│   └── templates/dashboard.html # Web dashboard served at "/"
├── tests/                       # End-to-end TestClient suite (17 tests)
├── ALGORITHM.md                 # Full algorithm documentation
└── requirements.txt
```

---

## Notes / Roadmap

- The key store and API-key store are currently **in-memory** — suitable for
  demonstration. A database or secure-element backend (e.g. the ATECC608
  itself) is the intended next step.
- The API-key dependency (`core/auth.py::require_api_key`) is implemented but
  not yet enforced on the routes.

---

## License

Add your preferred license here.
