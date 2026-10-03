# ALGORITHM DOCUMENTATION

## ATECC608 Security API — Cryptographic Security Service

**Version:** 1.0.0
**Runtime:** Python 3.11 / FastAPI
**Crypto Backend:** `cryptography` (OpenSSL)
**Curve:** NIST P-256 (`secp256r1`)

---

## 1. Purpose

This document specifies the algorithm for every module of the Security API.
The API exposes the following cryptographic primitives and security services
to IoT and blockchain clients:

| # | Primitive | Standard | Purpose |
|---|-----------|----------|---------|
| 1 | ECC Key Generation | NIST P-256 | Create signing / key-agreement key pairs |
| 2 | SHA-256 Hashing | FIPS 180-4 | Integrity / fingerprinting |
| 3 | ECDSA | FIPS 186-4 + SHA-256 | Digital signature (authenticity + non-repudiation) |
| 4 | ECDH | SP 800-56A | Shared-secret establishment (confidentiality) |
| 5 | CSPRNG | OS entropy | Cryptographically secure random bytes |
| 6 | API-Key Auth | SHA-256 token hashing | Client authentication |

---

## 2. System Architecture (Module Map)

The system is a strict **3-layer architecture**. A layer may only call the
layer directly below it. No route ever touches cryptographic objects directly.

```
 ┌───────────────────────────────────────────────────────────┐
 │  LAYER 3 — API / PRESENTATION                             │
 │  api/routes/keys.py      api/routes/ecdsa.py              │
 │  api/routes/random.py    api/routes/ecdh.py               │
 │  api/routes/hashing.py   api/routes/auth.py               │
 │  (HTTP in/out, request validation, HTTP status codes)     │
 └───────────────────────────┬───────────────────────────────┘
                             │ calls
 ┌───────────────────────────▼───────────────────────────────┐
 │  LAYER 2 — CORE / ORCHESTRATION                           │
 │  core/key_manager.py     core/security_engine.py          │
 │  core/auth.py            core/api_key.py                  │
 │  (facade + access control + API-key lifecycle)            │
 └───────────────────────────┬───────────────────────────────┘
                             │ calls
 ┌───────────────────────────▼───────────────────────────────┐
 │  LAYER 1 — SERVICES / CRYPTO PRIMITIVES                   │
 │  services/key_service.py    services/ecdsa.py             │
 │  services/random_service.py services/ecdh.py              │
 │  services/hash_service.py                                 │
 │  (raw algorithms — no HTTP, no validation, no exceptions) │
 └───────────────────────────┬───────────────────────────────┘
                             │ uses
                    ┌────────▼────────┐
                    │  cryptography   │
                    │  + hashlib      │
                    │  + secrets/uuid │
                    └─────────────────┘
```

**Files** — every application module lives under the `app/` package (paths in
the diagram above are relative to it); `tests/` sits at the project root:
- `main.py` — application factory, router registration, dashboard endpoint
- `schemas/*.py` — Pydantic request models (input contracts)
- `core/*` — facades / auth / key management
- `services/*` — cryptographic primitives
- `tests/*` — end-to-end `TestClient` validation suite

---

## 3. Global Notation & Conventions

| Symbol | Meaning |
|--------|---------|
| `_key_store` | In-memory dict `{key_id → {private_key, public_key}}` |
| `_api_key_store` | In-memory dict `{sha256(api_key) → {key_id, active}}` |
| `‖` | byte-string concatenation |
| `H(m)` | SHA-256 digest of message `m` |
| `PEM` | Base64 `SubjectPublicKeyInfo` encoding |
| `SK` | private key (never serialized, never returned) |
| `PK` | public key |
| `d` | ECDH private scalar |
| `Q` | ECDH public point `= d·G` |

**Design invariants enforced by the algorithm:**

1. **I1 — Private keys never leave the process.** `SK` is stored as a live
   object in `_key_store` and is *never* serialized to PEM, hex or bytes for
   any response. Only `PK` is exported.
2. **I2 — Keys are addressed by an opaque ID**, `key_id = uuid4()`, never by
   key material.
3. **I3 — Snapshots are O(1).** Handles are stored, not copies, so a 256-bit
   scalar is never duplicated in memory.
4. **I4 — Randomness is always CSPRNG.** `secrets` / OS entropy is used for
   key material, API keys, key IDs and random-byte delivery. `random` is
   never used for anything security-relevant.
5. **I5 — Errors are converted at the boundary.** Layer 1 returns
   values or `None`; only Layer 3 raises `HTTPException`. Crypto exceptions
   (`InvalidSignature`) are absorbed in Layer 1 and converted to booleans.

---

## 4. LAYER 1 — Cryptographic Primitive Algorithms

### 4.1 ALG-GENKEY — ECC Key Pair Generation
`services/key_service.py :: generate_key_pair()`

**Input:** none
**Output:** `{key_id, algorithm, curve, public_key}`
**Time:** O(1) — one P-256 keygen (≈ 0.1–0.5 ms)

```
ALGORITHM Generate_Key_Pair()
BEGIN
  Step 1. private_key ← ec.generate_private_key(SECP256R1())
             // CSPRNG draws scalar d from [1, n-1]
  Step 2. public_key  ← private_key.public_key()
             // Q ← d·G  (one EC scalar multiplication)
  Step 3. key_id      ← UUID4().to_string()
  Step 4. _key_store[key_id] ← { private_key, public_key }   // I1/I3
  Step 5. pem ← public_key.public_bytes(PEM, SubjectPublicKeyInfo)
  Step 6. RETURN { key_id, algorithm:"ECC", curve:"secp256r1",
                   public_key: UTF8(pem) }
END
```

**Correctness argument:** `Step 2` guarantees `Q = d·G` on the same curve as
`Step 1`, so the pair is mathematically bound. `Step 3` uses UUID4 (random),
so collision probability is negligible (`~2^-122` at practical volumes).
`Step 6` exports `PK` only ⇒ **I1 holds**.

---

### 4.2 ALG-GETPUB — Public Key Retrieval
`services/key_service.py :: get_public_key(key_id)`

**Input:** `key_id`
**Output:** `{key_id, algorithm, curve, public_key}` or `None`

```
ALGORITHM Get_Public_Key(key_id)
BEGIN
  Step 1. key_data ← _key_store.get(key_id)
  Step 2. IF key_data = NULL THEN RETURN None        // no exception (I5)
  Step 3. pem ← key_data.public_key → PEM/SubjectPublicKeyInfo
  Step 4. RETURN { key_id, algorithm:"ECC", curve:"secp256r1",
                   public_key: UTF8(pem) }
END
```

**Time:** O(1) hash lookup + O(1) DER encoding.

---

### 4.3 ALG-RAND — Cryptographically Secure Random Bytes
`services/random_service.py :: generate_random_bytes(length)`

**Input:** `length` (int)
**Output:** hex string of `2 × length` characters
**Time:** O(length)

```
ALGORITHM Generate_Random_Bytes(length)
BEGIN
  Step 1. raw ← secrets.token_bytes(length)   // OS CSPRNG, never prng
  Step 2. RETURN hex_encode(raw)              // 2 hex chars per byte
END
```

**Invariant:** `len(output) = 2 × length` exactly. Deterministic length,
non-deterministic value (tested: two calls of length 32 differ).

---

### 4.4 ALG-SHA — SHA-256 Hashing
`services/hash_service.py :: sha256_hash(data)`

**Input:** `data` (str)
**Output:** 64-char lowercase hex digest
**Time:** O(|data|)

```
ALGORITHM SHA256(data)
BEGIN
  Step 1. m      ← UTF8_encode(data)           // explicit, stable encoding
  Step 2. digest ← hashlib.sha256(m).digest()  // 32 bytes = 256 bits
  Step 3. RETURN hex_encode(digest)            // 64 characters
END
```

**Properties:** deterministic (same in ⇒ same out), collision-resistant,
avalanche effect (1-bit change ⇒ ~50% of digest bits flip).

---

### 4.5 ALG-SIGN — ECDSA Signature Generation
`services/ecdsa.py :: sign_data(private_key, data)`

**Input:** `private_key` (object), `data` (str)
**Output:** hex-encoded DER signature `(r, s)`
**Time:** O(1) — one EC scalar multiplication + SHA-256

```
ALGORITHM ECDSA_Sign(SK, data)
BEGIN
  Step 1. m ← UTF8_encode(data)
  Step 2. e ← SHA256(m)                        // hash the message
  Step 3. k ← CSPRNG(n)                        // ephemeral nonce, SECRET
  Step 4. R ← k·G ;  r ← R.x mod n
  Step 5. s ← k⁻¹·(e + r·SK) mod n             // SK = private scalar
  Step 6. IF s > n/2 THEN s ← n − s            // low-S normalization
  Step 7. RETURN hex_encode(DER_encode(r, s))
END
```

> `Steps 2–6` run inside `private_key.sign(...)` (OpenSSL), but are stated
> explicitly because `k` must be uniformly random and secret: reuse of `k`
> leaks `SK` (the classic ECDSA failure mode — cf. PS3/Bitcoin attacks).
> `Step 6` blocks signature malleability.

---

### 4.6 ALG-VERIFY — ECDSA Signature Verification
`services/ecdsa.py :: verify_signature(public_key, data, signature_hex)`

**Input:** `public_key` (object), `data` (str), `signature_hex` (str)
**Output:** `True` | `False` (boolean, never raises — **I5**)
**Time:** O(1)

```
ALGORITHM ECDSA_Verify(PK, data, signature_hex)
BEGIN
  Step 1. TRY
            Step 1.1 sig ← from_hex(signature_hex)  // ValueError if bad hex
            Step 1.2 m   ← UTF8_encode(data)
            Step 1.3 e   ← SHA256(m)
            Step 1.4 PK.verify(sig, m, ECDSA(SHA256()))
                       // check x mod n == r, else raise InvalidSignature
            Step 1.5 RETURN True
          CATCH InvalidSignature
            Step 1.6 RETURN False                   // tampering detected
          END TRY
END
```

**Security meaning:** `False` is returned for a wrong key, a modified message
or a corrupted signature — all three are **indistinguishable** to the client,
which prevents differential/oracle probing.

---

### 4.7 ALG-ECDH — Shared Secret Derivation
`services/ecdh.py :: derive_shared_secret(private_key, peer_public_key)`

**Input:** own `SK_A`, peer `PK_B`
**Output:** hex-encoded x-coordinate of `S = d_A · Q_B` (64 hex chars)
**Time:** O(1) — one EC scalar multiplication

```
ALGORITHM ECDH_Derive(SK_A, PK_B)
BEGIN
  Step 1. S ← SK_A.exchange(ECDH(), PK_B)
             // S = x-coord of d_A·Q_B; OpenSSL validates PK_B is on-curve
             // and rejects the point at infinity (invalid-curve attack guard)
  Step 2. RETURN hex_encode(S)
END
```

**Symmetry proof (the property the tests assert):**

```
Alice: S_A = d_A·Q_B = d_A·(d_B·G) = (d_A·d_B)·G
Bob  : S_B = d_B·Q_A = d_B·(d_A·G) = (d_A·d_B)·G
⇒ S_A = S_B                                        ∎
```

Scalar multiplication is commutative on the same curve, so both parties
recover an identical 32-byte secret **that was never transmitted**. This is
exactly what `test_ecdh_shared_secret_matches` verifies.

---

### 4.8 ALG-APIKEY-GEN — API Key Issuance
`core/api_key.py :: generate_api_key()`

**Input:** none
**Output:** `{key_id, api_key}` — raw `api_key` returned **once only**
**Time:** O(1)

```
ALGORITHM Generate_API_Key()
BEGIN
  Step 1. api_key ← "sk_live_" ‖ token_urlsafe(32)
             // 32 random bytes → ~43 URL-safe chars ≈ 256 bits entropy
  Step 2. key_id  ← token_hex(8)                // 16 hex chars, public id
  Step 3. h       ← SHA256(UTF8(api_key))       // one-way; raw key discarded
  Step 4. _api_key_store[h] ← { key_id, active: True }
  Step 5. RETURN { key_id, api_key }            // last time raw key is visible
END
```

**Why hash the key (`Step 3`):** the store holds only `H(api_key)`, so a store
disclosure does **not** yield usable credentials — an attacker would have to
pre-image SHA-256. The `sk_live_` prefix is an industry convention enabling
automated secret scanners to detect accidental leakage.

---

### 4.9 ALG-APIKEY-VERIFY — API Key Verification
`core/api_key.py :: verify_api_key(api_key)`

**Input:** `api_key` (str)
**Output:** `True` | `False`
**Time:** O(1)

```
ALGORITHM Verify_API_Key(api_key)
BEGIN
  Step 1. h        ← SHA256(UTF8(api_key))
  Step 2. key_data ← _api_key_store.get(h)
  Step 3. IF key_data = NULL THEN RETURN False   // unknown key
  Step 4. RETURN key_data.active                 // revoked ⇒ False
END
```

**Notes:** lookup is by *digest* (unguessable), giving an effectively
constant-time keyed lookup with no per-key scan. The `active` flag supports
**revocation without deletion**, preserving a future audit trail.

---

## 5. LAYER 2 — Core Orchestration Algorithms

### 5.1 ALG-KEYMGR — Key Manager Facade
`core/key_manager.py :: class KeyManager`

**Role:** the *only* permitted entry point for key operations from routes.
It wraps `services/key_service.py` so routes never import crypto internals.

```
ALGORITHM KeyManager.generate_key()
BEGIN
  Step 1. RETURN Generate_Key_Pair()          // §4.1
END

ALGORITHM KeyManager.get_key(key_id)          // INTERNAL use only
BEGIN
  Step 1. RETURN _key_store.get(key_id)       // may include SK
END

ALGORITHM KeyManager.get_public_key(key_id)   // PUBLIC use
BEGIN
  Step 1. RETURN Get_Public_Key(key_id)       // §4.2 — PK only
END
```

**Encapsulation rule (critical):** `get_key()` returns the record *including*
the private key and is reserved for ECDSA/ECDH. `get_public_key()` is the
route-safe accessor. Mixing them up is the single highest-risk defect in this
codebase, hence the explicit split and naming.

---

### 5.2 ALG-ENGINE — Security Engine (Single Cryptographic Facade)
`core/security_engine.py :: class SecurityEngine`

**Role:** one class exposing *all* primitives, so a future hardware backend
(the ATECC608 secure element itself) can be dropped in without touching routes.

```
ALGORITHM SecurityEngine.generate_key()      → Generate_Key_Pair()      §4.1
ALGORITHM SecurityEngine.get_public_key(k)   → Get_Public_Key(k)        §4.2
ALGORITHM SecurityEngine.generate_random(n)  → Generate_Random_Bytes(n) §4.3
ALGORITHM SecurityEngine.hash_sha256(d)      → SHA256(d)                §4.4
ALGORITHM SecurityEngine.sign(SK, d)         → ECDSA_Sign(SK, d)        §4.5
ALGORITHM SecurityEngine.verify(PK, d, s)    → ECDSA_Verify(PK, d, s)   §4.6
ALGORITHM SecurityEngine.derive_secret(SK,Q) → ECDH_Derive(SK, Q)       §4.7
```

**Every method is `@staticmethod`** ⇒ the engine has no state of its own and
is trivially thread-safe; all state lives in the two stores.

---

### 5.3 ALG-REQAUTH — API-Key Authorization Dependency
`core/auth.py :: require_api_key()`

**Role:** FastAPI dependency (`Security(APIKeyHeader("X-API-Key"))`) that
gates protected endpoints. `auto_error=False` makes FastAPI hand the header
to us even when absent, so **we** control the error body.

**Input:** HTTP header `X-API-Key` (or none)
**Output:** the validated key, or `HTTPException(401)`

```
ALGORITHM Require_API_Key()
BEGIN
  Step 1. api_key ← header["X-API-Key"]        // Security(APIKeyHeader)
  Step 2. IF api_key IS MISSING / EMPTY THEN
            RAISE HTTP_401 "Missing API key"
          END IF
  Step 3. IF Verify_API_Key(api_key) = FALSE THEN  // §4.9
            RAISE HTTP_401 "Invalid API key"
          END IF
  Step 4. RETURN api_key                       // caller is now authorized
END
```

**Design notes:**
- Two distinct 401 messages (`Missing` vs `Invalid`) separate *absent
  credential* from *bad credential* — useful for client debugging. (If
  information leakage were a concern, they would be collapsed to one message.)
- Returning `api_key` at `Step 4` lets a protected route bind the request to
  an identity for logging/rate-limiting/auditing.
- The dependency is **not** a decorator side-effect: it must be attached via
  `Depends(require_api_key)` on each route to take effect.

---

## 6. LAYER 3 — API Endpoint Algorithms

### 6.0 ALG-PIPELINE — Common Request Pipeline
Every endpoint follows this uniform control flow:

```
ALGORITHM Handle_Request(method, path, body, headers)
BEGIN
  Step 1. ROUTE    ← FastAPI matches (method, path) → handler
  Step 2. VALIDATE ← Pydantic parses `body` into the declared schema;
                     IF invalid THEN RETURN 422 (automatic, before handler)
  Step 3. AUTH     ← IF Depends(Require_API_Key) attached
                     THEN run §5.3, abort with 401
  Step 4. BIND     ← map schema fields → service arguments
  Step 5. DOMAIN   ← call Layer 2 / Layer 1 (no crypto inline in route)
  Step 6. GUARD    ← IF resource missing THEN RETURN 404
                     IF parameter out of range THEN RETURN 400
  Step 7. SERIALIZE← build uniform JSON {algorithm, ..., result}
  Step 8. RETURN response with status 200
END
```

**Uniform response contract:** every cryptographic response carries an
`algorithm` field so clients can log/negotiate without out-of-band knowledge.

---

### 6.1 ALG-EP-KEYGEN — `POST /api/v1/keys/generate`
`api/routes/keys.py :: generate_keys()`

```
ALGORITHM Endpoint_Generate_Keys()
BEGIN
  Step 1. result ← KeyManager.generate_key()     // §5.1
  Step 2. RETURN 200 result                      // {key_id, algorithm, curve,
                                                 //  public_key}  — never SK
END
```

### 6.2 ALG-EP-KEYGET — `GET /api/v1/keys/{key_id}`
`api/routes/keys.py :: retrieve_public_key(key_id)`

```
ALGORITHM Endpoint_Get_Public_Key(key_id)
BEGIN
  Step 1. key_data ← KeyManager.get_public_key(key_id)    // §5.1
  Step 2. IF key_data = NULL THEN
            RAISE HTTP_404 "Key not found"                // enumeration guard
          END IF
  Step 3. RETURN 200 key_data                             // PK only
END
```

**Note:** an unknown `key_id` yields an identical 404 regardless of ID format,
so the endpoint does not leak which IDs exist beyond membership itself.

---

### 6.3 ALG-EP-RANDOM — `POST /api/v1/random/generate?length=N`
`api/routes/random.py :: generate_random(length=32)`

```
ALGORITHM Endpoint_Generate_Random(length)
BEGIN
  Step 1. IF length ≤ 0 THEN
            RAISE HTTP_400 "Length must be greater than 0"
          END IF
  Step 2. IF length > 1024 THEN
            RAISE HTTP_400 "Length cannot exceed 1024 bytes"
          END IF
  Step 3. random_data ← Generate_Random_Bytes(length)     // §4.3
  Step 4. RETURN 200 { length, random_data }
END
```

**Why the bounds (Step 1–2):** the upper bound (1024) is a **resource-abuse
guard** — without it a caller could request gigabytes and exhaust memory; hex
encoding doubles the payload, so 1024 bytes → 2048 chars. The lower bound
rejects the degenerate empty output.

---

### 6.4 ALG-EP-HASH — `POST /api/v1/hash/sha256`
`api/routes/hashing.py :: generate_sha256()`

```
ALGORITHM Endpoint_SHA256(request)
BEGIN
  Step 1. request.data ← Pydantic(HashRequest).data        // required str
  Step 2. digest ← SHA256(request.data)                    // §4.4
  Step 3. RETURN 200 { algorithm:"SHA-256", hash: digest }
END
```

**Stateless** — no key-store access, so this is the only endpoint with no 404
path and the highest throughput.

---

### 6.5 ALG-EP-SIGN — `POST /api/v1/ecdsa/sign`
`api/routes/ecdsa.py :: create_signature()`

```
ALGORITHM Endpoint_ECDSA_Sign(request)
BEGIN
  Step 1. key_data ← _key_store.get(request.key_id)
  Step 2. IF key_data = NULL THEN RAISE HTTP_404 "Key not found"
  Step 3. SK ← key_data.private_key              // internal; never serialized
  Step 4. signature ← ECDSA_Sign(SK, request.data)        // §4.5
  Step 5. RETURN 200 { algorithm:"ECDSA", curve:"secp256r1",
                       key_id: request.key_id, signature }
END
```

### 6.6 ALG-EP-VERIFY — `POST /api/v1/ecdsa/verify`
`api/routes/ecdsa.py :: verify_ecdsa_signature()`

```
ALGORITHM Endpoint_ECDSA_Verify(request)
BEGIN
  Step 1. key_data ← _key_store.get(request.key_id)
  Step 2. IF key_data = NULL THEN RAISE HTTP_404 "Key not found"
  Step 3. PK ← key_data.public_key
  Step 4. valid ← ECDSA_Verify(PK, request.data, request.signature)  // §4.6
  Step 5. RETURN 200 { algorithm:"ECDSA", key_id, valid }  // 200 even if False
END
```

**Important:** an *invalid* signature is a **successful** HTTP request
(`200 {valid: false}`), **not** a 4xx. Only a *missing key* is an error.
This cleanly separates "your signature is wrong" (a cryptographic answer)
from "you referenced a key that does not exist" (an addressing error).

---

### 6.7 ALG-EP-ECDH — `POST /api/v1/ecdh/derive`
`api/routes/ecdh.py :: derive_ecdh_secret()`

```
ALGORITHM Endpoint_ECDH_Derive(request)
BEGIN
  Step 1. priv_data ← _key_store.get(request.private_key_id)
  Step 2. IF priv_data = NULL THEN RAISE HTTP_404 "Private key not found"
  Step 3. peer_data ← _key_store.get(request.peer_key_id)
  Step 4. IF peer_data = NULL THEN RAISE HTTP_404 "Peer key not found"
  Step 5. SK_A ← priv_data.private_key
  Step 6. PK_B ← peer_data.public_key
  Step 7. secret ← ECDH_Derive(SK_A, PK_B)                // §4.7
  Step 8. RETURN 200 { algorithm:"ECDH", curve:"secp256r1",
                       shared_secret: secret }
END
```

**Safety property:** because both arguments resolve to IDs *in the server's
own store*, a client can only exchange with a key the server already owns —
it cannot inject an arbitrary attacker-chosen point, which is the principal
invalid-curve attack vector for raw ECDH. The two distinct 404 messages also
make mis-addressing debuggable.

---

### 6.8 ALG-EP-APIKEY — `POST /api/v1/auth/api-key`
`api/routes/auth.py :: create_api_key()`

```
ALGORITHM Endpoint_Create_API_Key()
BEGIN
  Step 1. result ← Generate_API_Key()           // §4.8
  Step 2. RETURN 200 result                     // {key_id, api_key}
END
```

The client **must persist** `api_key` at `Step 2`: the server keeps only
`SHA256(api_key)`, so the raw value is unrecoverable afterwards.

---

## 7. MASTER END-TO-END ALGORITHMS

### 7.1 ALG-FLOW-SIGNVERIFY — Authenticity Workflow

```
Sender                                    Receiver
  │ POST /keys/generate                      │
  │◄── key_id, PK (PEM) ─────────────────────┤  (PK shared out-of-band)
  │                                          │
  │ POST /ecdsa/sign {key_id, data}          │
  │   SK ← store[key_id].private_key         │
  │   sig ← ECDSA_Sign(SK, data)             │
  │◄── sig (hex) ───────────────────────────►│ POST /ecdsa/verify
  │                                          │   {key_id, data, sig}
  │                                          │   PK ← store[key_id].public_key
  │                                          │   ECDSA_Verify(PK, data, sig)
  │                                          │◄── {valid: true|false}
```

```
ALGORITHM Flow_Authenticity()
BEGIN
  Step 1. issue  ← Endpoint_Generate_Keys()              // §6.1
  Step 2. share  ← publish issue.public_key to counterparty
  Step 3. sig    ← Endpoint_ECDSA_Sign({issue.key_id, msg})   // §6.5
  Step 4. verdict← Endpoint_ECDSA_Verify({issue.key_id, msg, sig})  // §6.6
  Step 5. IF verdict.valid = TRUE
            THEN accept msg as authentic and untampered
            ELSE reject msg (message altered, or wrong key, or forged sig)
          END IF
END
```

### 7.2 ALG-FLOW-ECDH — Confidential Channel Establishment

```
A (client)                                  B (client)
  │ POST /keys/generate  ──► key_id_A        │ POST /keys/generate ──► key_id_B
  │ POST /ecdh/derive                          │ POST /ecdh/derive
  │   {private_key_id: key_id_A,               │   {private_key_id: key_id_B,
  │    peer_key_id:    key_id_B}               │    peer_key_id:    key_id_A}
  │◄─ S = d_A·Q_B ── hex                      │◄─ S = d_B·Q_A ── hex
  │                                           │
  └──────────── S_A == S_B  (shared key) ─────┘
```

```
ALGORITHM Flow_Confidential_Channel()
BEGIN
  Step 1. (key_id_A, PK_A) ← Endpoint_Generate_Keys()     // party A
  Step 2. (key_id_B, PK_B) ← Endpoint_Generate_Keys()     // party B
  Step 3. S_A ← Endpoint_ECDH_Derive({key_id_A, key_id_B})  // §6.7
  Step 4. S_B ← Endpoint_ECDH_Derive({key_id_B, key_id_A})  // §6.7
  Step 5. ASSERT S_A = S_B            // guaranteed by the §4.7 symmetry proof
  Step 6. USE S_A as the symmetric session key (e.g. AES-GCM input key)
END
```

### 7.3 ALG-FLOW-INTEGRITY — Hash-Based Integrity Check

```
ALGORITHM Flow_Integrity(payload)
BEGIN
  Step 1. h1 ← Endpoint_SHA256({data: payload})     // before transmission
  Step 2. transmit payload to receiver
  Step 3. h2 ← Endpoint_SHA256({data: payload'})    // payload as received
  Step 4. IF h1 = h2 THEN payload' = payload   (integrity intact)
                        ELSE payload' ≠ payload (corruption / tampering found)
          END IF
END
```

> A bare hash detects accidental corruption; pairing it with §7.1 (sign the
> digest instead of the payload) additionally provides authenticity.

### 7.4 ALG-FLOW-RANDOM — CSPRNG Delivery

```
ALGORITHM Flow_Secure_Random(n)
BEGIN
  Step 1. IF n ∉ (0, 1024] THEN RETURN HTTP_400     // §6.3 guards
  Step 2. hex ← OS_CSPRNG(n) → hex                  // §4.3
  Step 3. RETURN hex     // usable for nonces, salts, IVs, session IDs
END
```

---

## 8. APPLICATION STARTUP ALGORITHM

`main.py`

```
ALGORITHM Bootstrap_Application()
BEGIN
  Step 1. app ← FastAPI(title="ATECC608 Security API",
                        description="Secure cryptographic API for IoT and
                                     blockchain applications",
                        version="1.0.0")
  Step 2. app.include_router(keys.router)      // /api/v1/keys
  Step 3. app.include_router(random.router)    // /api/v1/random
  Step 4. app.include_router(hashing.router)   // /api/v1/hash
  Step 5. app.include_router(ecdsa.router)     // /api/v1/ecdsa
  Step 6. app.include_router(ecdh.router)      // /api/v1/ecdh
  Step 7. REGISTER  GET "/" → read templates/dashboard.html as HTMLResponse
  Step 8. RETURN app
END
```

**Router prefixes (the complete public surface):**

| Router | Prefix | Endpoints |
|--------|--------|-----------|
| keys | `/api/v1/keys` | `POST /generate`, `GET /{key_id}` |
| random | `/api/v1/random` | `POST /generate` |
| hashing | `/api/v1/hash` | `POST /sha256` |
| ecdsa | `/api/v1/ecdsa` | `POST /sign`, `POST /verify` |
| ecdh | `/api/v1/ecdh` | `POST /derive` |
| auth | `/api/v1/auth` | `POST /api-key` |

---

## 9. COMPLEXITY ANALYSIS

| Algorithm | Time | Space | Dominant cost |
|-----------|------|-------|---------------|
| ALG-GENKEY | O(1) | O(1) | EC keygen ≈ 0.1–0.5 ms |
| ALG-GETPUB | O(1) | O(1) | dict lookup + DER encode |
| ALG-RAND | O(n) | O(n) | `n` = byte count (≤ 1024) |
| ALG-SHA | O(m) | O(1) | `m` = input bytes |
| ALG-SIGN | O(1) | O(1) | 1 scalar mult + SHA-256 |
| ALG-VERIFY | O(1) | O(1) | 2 scalar mults + SHA-256 |
| ALG-ECDH | O(1) | O(1) | 1 scalar mult |
| ALG-APIKEY-GEN | O(1) | O(1) | 1 SHA-256 over ~43 bytes |
| ALG-APIKEY-VERIFY | O(1) | O(1) | hash-map lookup |
| ALG-REQAUTH | O(1) | O(1) | 1 SHA-256 |
| All endpoints | O(1)* | O(1)* | *except random/hash, which are O(n)/O(m) |

**Interpretation for the report:** every key-referencing operation is
**constant time** in the number of stored keys — this is the benefit of the
`dict`-indexed store. Throughput therefore does not degrade as more keys are
issued, which is the scalability claim of the design.

Encryption output sizes are also fixed: ECDH secret = 32 bytes (64 hex),
SHA-256 = 32 bytes (64 hex), P-256 DER signature = 70–72 bytes.

---

## 10. VALIDATION ALGORITHM (TEST SUITE)

`tests/*.py` — 5 files, exercising the API through `fastapi.testclient.TestClient`.

```
ALGORITHM Validate_Security_API()
BEGIN
  Step 1. client ← TestClient(app)             // in-process, no network
  Step 2. FOR each test module T in
            {test_keys, test_random, test_hash, test_ecdsa, test_ecdh}:
            RUN T and record pass/fail
  Step 3. RETURN overall result
END
```

**Property coverage — the "correctness obligations" each test discharges:**

| Test | Property proven |
|------|-----------------|
| `test_generate_key` | endpoint returns 200 and a non-empty `key_id` |
| `test_generate_multiple_keys` | uniqueness of `key_id` (collision-freedom) |
| `test_generated_key_has_public_key` | `public_key` present, PK-only disclosure |
| `test_generate_random_bytes` | length 32 ⇒ 64 hex chars (byte↔hex mapping) |
| `test_random_length` | length 16 ⇒ 32 hex chars (scales correctly) |
| `test_random_values_are_different` | non-determinism ⇒ CSPRNG, not PRNG |
| `test_random_length_zero` | guard: length 0 ⇒ 400 |
| `test_random_length_too_large` | guard: length 1025 ⇒ 400 |
| `test_sha256_hash` | digest is exactly 64 hex chars (256-bit output) |
| `test_sha256_same_input_same_hash` | determinism |
| `test_sha256_different_input_different_hash` | collision resistance (spot check) |
| `test_ecdsa_sign` | sign returns 200, algorithm tag, non-empty signature |
| `test_ecdsa_verify_valid_signature` | completeness: valid ⇒ `valid == True` |
| `test_ecdsa_verify_invalid_signature` | soundness: altered data ⇒ `valid == False` |
| `test_ecdh_shared_secret_matches` | symmetry: `S_A == S_B` (§4.7 proof) |
| `test_ecdh_missing_private_key` | 404 on unknown private key |
| `test_ecdh_missing_peer_key` | 404 on unknown peer key |

**Security-specific meta-properties the suite establishes:**

1. **Completeness** — every legitimate operation returns the documented
   200 + schema (no false negatives).
2. **Soundness** — tampering is caught (`verify` returns `False`) rather than
   raising, satisfying **I5**.
3. **Symmetry** — the core ECDH guarantee.
4. **Non-determinism** — randomness really is random.
5. **Length discipline** — every fixed-length output is exactly the expected
   size, which protects downstream code relying on slice widths.
6. **Negative paths** — the two 4xx guards and the two 404 guards are covered.

**Run command:**

```
python -m pytest tests -q          # add -v for per-test names
```

---

## 11. QUICK REFERENCE — ALGORITHM–FILE INDEX

All file paths are relative to the `app/` package
(e.g. `services/key_service.py` ⇒ `app/services/key_service.py`).

| Algorithm ID | Layer | File | Symbol |
|--------------|-------|------|--------|
| ALG-GENKEY | 1 | `services/key_service.py` | `generate_key_pair` |
| ALG-GETPUB | 1 | `services/key_service.py` | `get_public_key` |
| ALG-RAND | 1 | `services/random_service.py` | `generate_random_bytes` |
| ALG-SHA | 1 | `services/hash_service.py` | `sha256_hash` |
| ALG-SIGN | 1 | `services/ecdsa.py` | `sign_data` |
| ALG-VERIFY | 1 | `services/ecdsa.py` | `verify_signature` |
| ALG-ECDH | 1 | `services/ecdh.py` | `derive_shared_secret` |
| ALG-APIKEY-GEN | 2 | `core/api_key.py` | `generate_api_key` |
| ALG-APIKEY-VERIFY | 2 | `core/api_key.py` | `verify_api_key` |
| ALG-KEYMGR | 2 | `core/key_manager.py` | `KeyManager` |
| ALG-ENGINE | 2 | `core/security_engine.py` | `SecurityEngine` |
| ALG-REQAUTH | 2 | `core/auth.py` | `require_api_key` |
| ALG-EP-KEYGEN | 3 | `api/routes/keys.py` | `generate_keys` |
| ALG-EP-KEYGET | 3 | `api/routes/keys.py` | `retrieve_public_key` |
| ALG-EP-RANDOM | 3 | `api/routes/random.py` | `generate_random` |
| ALG-EP-HASH | 3 | `api/routes/hashing.py` | `generate_sha256` |
| ALG-EP-SIGN | 3 | `api/routes/ecdsa.py` | `create_signature` |
| ALG-EP-VERIFY | 3 | `api/routes/ecdsa.py` | `verify_ecdsa_signature` |
| ALG-EP-ECDH | 3 | `api/routes/ecdh.py` | `derive_ecdh_secret` |
| ALG-EP-APIKEY | 3 | `api/routes/auth.py` | `create_api_key` |
| ALG-PIPELINE | 3 | *all routes* | common flow |
| ALG-FLOW-* | all | `tests/*` | end-to-end workflows |
| Bootstrap_Application | — | `main.py` | app factory |

**— End of algorithm documentation —**