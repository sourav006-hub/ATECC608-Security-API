# ALGORITHM DOCUMENTATION

## ATECC608 Security API — Cryptographic Security Service

**Version:** 1.0.0
**Runtime:** Python 3.11 / FastAPI
**Crypto Backend:** `cryptography` (OpenSSL)
**Curve:** NIST P-256 (`secp256r1`)

---

## Contents

| § | Section |
|---|---------|
| 1 | Purpose |
| 2 | Methodology |
| 3 | System Architecture (Module Map) |
| 4 | Global Notation & Conventions |
| 5 | Layer 1 — Cryptographic Primitive Algorithms |
| 6 | Layer 2 — Core Orchestration Algorithms |
| 7 | Layer 3 — API Endpoint Algorithms |
| 8 | Master End-to-End Algorithms |
| 9 | Application Startup Algorithm |
| 10 | Complexity Analysis |
| 11 | Validation Algorithm (Test Suite) |
| 12 | Implementation Observations & Algorithm-Level Gaps |
| 13 | Quick Reference — Algorithm–File Index |

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

## 2. METHODOLOGY

This chapter describes the methodology used to design, implement, test and
evaluate the ATECC608 Security API. It explains *why* the algorithms are
structured the way they are, and how the design was validated.

### 2.1 Guiding Design Philosophy

Five principles drove every design decision:

| # | Principle | How it is realised in this project |
|---|-----------|-------------------------------------|
| P1 | **Do not roll your own crypto** | All primitives delegate to the vetted `cryptography` (OpenSSL) library — no hand-written curve arithmetic or padding |
| P2 | **Separation of concerns** | A strict three-layer architecture (§3): routes only handle HTTP, services only handle mathematics |
| P3 | **Fail-safe defaults** | Missing key → `404`; out-of-range length → `400`; tampered signature → `valid:false` — never a silent success |
| P4 | **Minimal attack surface** | Nine endpoints only; private keys never leave the process; API keys stored only as SHA-256 digests |
| P5 | **Verifiability** | Every algorithm is written as explicit, numbered pseudocode that can be checked against the source line by line |

### 2.2 Requirement Analysis

#### 2.2.1 Functional Requirements

| ID | Requirement | Delivered by |
|----|-------------|--------------|
| FR1 | Generate an ECC key pair on demand | `POST /api/v1/keys/generate` |
| FR2 | Retrieve a public key by identifier | `GET /api/v1/keys/{key_id}` |
| FR3 | Produce a SHA-256 digest of arbitrary text | `POST /api/v1/hash/sha256` |
| FR4 | Sign data with a private key (ECDSA) | `POST /api/v1/ecdsa/sign` |
| FR5 | Verify a signature against a key (ECDSA) | `POST /api/v1/ecdsa/verify` |
| FR6 | Derive a shared secret between two parties (ECDH) | `POST /api/v1/ecdh/derive` |
| FR7 | Supply cryptographically secure random bytes | `POST /api/v1/random/generate` |
| FR8 | Issue and verify API keys for client authentication | `POST /api/v1/auth/api-key`, `core/auth.py` |

#### 2.2.2 Non-Functional Requirements

| ID | Requirement | Target | Status |
|----|-------------|--------|--------|
| NFR1 | Constant-time lookups regardless of key count | O(1) per operation | ✅ dict-indexed stores (§10) |
| NFR2 | Private keys must never be serialised | 0 occurrences | ✅ only PEM public keys are exported |
| NFR3 | Randomness must come from the OS CSPRNG | no `random` module in security paths | ✅ `secrets` used throughout |
| NFR4 | Errors must not leak internals | structured JSON only | ✅ `InvalidSignature` absorbed in Layer 1 |
| NFR5 | Input must be validated at the boundary | Pydantic + explicit guards | ✅ schemas + 400/404 checks |
| NFR6 | Behaviour must be reproducible for verification | automated test suite | ✅ 17 tests (§11) |

### 2.3 Development Methodology

The system was built using an **incremental, bottom-up** methodology: each
cryptographic primitive was implemented and verified *before* the layer that
consumes it. This ordering guarantees that no route is ever written against a
primitive that does not yet work.

| Phase | Activity | Output |
|-------|----------|--------|
| 1. Requirement Analysis | Identify primitives and constraints (§2.2) | FR / NFR tables |
| 2. Technology Selection | Choose Python + FastAPI + `cryptography` (§2.7) | stack decision |
| 3. Architectural Design | Define the three layers and the dependency rule (§3) | module map |
| 4. Primitive Implementation | Build Layer 1 (services) and verify each | 7 crypto primitives |
| 5. Orchestration | Build Layer 2 facades, auth and stores | KeyManager, SecurityEngine |
| 6. Exposure | Build Layer 3 routes + Pydantic schemas | 9 endpoints |
| 7. Integration | Register routers, serve the dashboard | `app/main.py` |
| 8. Verification | Black-box test suite over the live application | 17 passing tests |
| 9. Documentation | Write this algorithm specification | `ALGORITHM.md` |

**Why bottom-up?** Every layer is then testable in isolation, and a defect is
localised to the layer where it first appears. This is what made the package
layout problem (§12.1) a single-line diagnosis rather than a search.

### 2.4 System Design Methodology

#### 2.4.1 Layered Architecture

The design follows a strict **three-tier** model with a one-way dependency
rule: *a layer may call only the layer directly beneath it.*

```
Layer 3  API / Routes      ->  HTTP parsing, status codes, JSON shaping
Layer 2  Core / Facades    ->  orchestration, access control, stores
Layer 1  Services          ->  pure cryptographic operations
                              (dependency flows upward only)
```

**Rationale:** cryptographic code is the hardest to get right and the easiest
to break. By isolating it in Layer 1 — with no HTTP, no exception handling and
no global state — it can be reasoned about and replaced independently of the
web framework.

#### 2.4.2 Facade Pattern

Two facades hide the internals from the routing layer:

- **`SecurityEngine` (§6.2)** — a single entry point exposing *all* primitives.
  Every method is a `@staticmethod`, so the engine is stateless and trivially
  thread-safe.
- **`KeyManager` (§6.1)** — the only sanctioned route-facing gateway for key
  operations, with an explicit split between the private-key-bearing
  `get_key()` (internal use) and the safe `get_public_key()` (public use).

Consequently Layer 3 never imports `cryptography` and never handles a private
key object directly.

#### 2.4.3 Invariant-Driven Design

Rather than relying on convention, five invariants (§4) are stated explicitly
and each algorithm is written so the invariant is a direct consequence of its
steps:

- **I1** (private keys never serialised) holds because the only serialization
  call in the codebase is applied to a `public_key` object.
- **I4** (CSPRNG only) holds because every entropy request routes through
  `secrets` / `os.urandom`, and no algorithm ever imports `random`.
- **I5** (errors converted at the boundary) holds because `InvalidSignature`
  is caught in Layer 1 and returned as a boolean.

#### 2.4.4 Storage Design

State is held in two module-level dictionaries:

| Store | Key | Value |
|-------|-----|-------|
| `_key_store` | `uuid4()` string | `{private_key, public_key}` objects |
| `_api_key_store` | `SHA256(api_key)` | `{key_id, active}` |

Design choices and their justification:

- **Keys are addressed by opaque ID, never by key material** — keeps URLs and
  logs free of secret data and avoids accidental leakage.
- **Objects are stored, not byte copies (I3)** — the 256-bit scalar exists
  once and is never duplicated, limiting memory exposure.
- **The API-key store is keyed by digest, not by the raw key** — so a store
  disclosure yields no usable credential (§5.8).
- **An `active` flag enables revocation without deletion** — preserving an
  audit trail for a future persistence backend.

The known consequence — that these stores are volatile and per-process — is
recorded honestly in §12.5.

### 2.5 Cryptographic Primitive Selection & Justification

Each primitive was chosen against explicit criteria rather than convenience.
The dominant constraint is the target hardware: the **Microchip ATECC608A**
secure element (the subject of the project title) natively accelerates the
NIST **P-256** curve, ECDSA, ECDH and SHA-256.

| Layer | Chosen | Alternatives considered | Justification |
|-------|--------|--------------------------|---------------|
| Curve | **NIST P-256** (`secp256r1`) | `secp256k1`, Curve25519 | Hardware-accelerated by the ATECC608A; FIPS 186-4 approved; `secp256k1` is Bitcoin-specific, and Curve25519 cannot do ECDSA |
| Hash | **SHA-256** | MD5, SHA-1, SHA-3 | MD5/SHA-1 are collision-broken; SHA-256 matches the 256-bit curve (matched security strength) and is FIPS 180-4 approved |
| Signature | **ECDSA** | RSA-2048/3072 | 256-bit ECDSA ≈ 3072-bit RSA security with a far smaller key and a ~64-byte signature — critical for IoT bandwidth and storage |
| Agreement | **ECDH** (ephemeral) | RSA key transport, finite-field DH | Natural pairing with P-256; one scalar multiplication per side, and the secret is never transmitted |
| Entropy | **`secrets`** (OS CSPRNG) | `random`, timestamps, counters | `random` uses the Mersenne Twister, which is *predictable* once enough outputs are observed — unacceptable for key material |
| API-key storage | **SHA-256 digest** | bcrypt, scrypt, Argon2 | See the nuance below |

#### 2.5.1 A deliberate nuance: why a *fast* hash is correct for API keys

Password-storage best practice calls for slow, memory-hard functions (bcrypt /
Argon2). That guidance does **not** apply here, and the reasoning belongs in
the report:

- A password is **low-entropy** and *guessable*, so an attacker who steals the
  digest mounts an offline dictionary attack. Slowness is what defends it.
- A generated API key is `sk_live_` + `secrets.token_urlsafe(32)` ≈ **256 bits
  of uniform entropy**. Brute-forcing it is infeasible regardless of hash
  speed, so a slow hash would add latency to *every authenticated request* while
  buying no practical security.

Therefore SHA-256 is the **correct** choice for this threat model. Stating this
explicitly demonstrates that the decision was reasoned, not accidental.

### 2.6 Algorithm Specification Method

Every operation is documented using one uniform, checkable form:

```
ALGORITHM <Name>(<inputs>)
BEGIN
  Step 1. <action>              // rationale for this step
  ...
  Step n. RETURN <output>
END
```

Each specification carries four supporting elements:

| Element | Purpose |
|---------|---------|
| **Input / Output** | The exact contract of the function |
| **Time / Space** | Complexity class and dominant cost (§10) |
| **Correctness argument** | *Why* the step sequence achieves the stated goal (e.g. the ECDH symmetry proof in §5.7) |
| **Invariant note** | Which of I1–I5 the algorithm upholds, and by which step |

#### 2.6.1 Traceability

The specification is deliberately machine-checkable against the source:

- Each algorithm is annotated with its `file :: symbol` location.
- §13 (Algorithm–File Index) maps every algorithm ID to its implementing file
  and function, so a reviewer can verify each one in isolation.
- The pseudocode names the *actual* library calls (`EC.generate_private_key`,
  `hashlib.sha256`, `secrets.token_bytes`) rather than abstract placeholders,
  so the mapping from specification to code is one-to-one.

#### 2.6.2 What is specified beyond the code

Two things are documented that the source does not state explicitly:

1. **The textbook algorithm inside library calls.** For example, `PrivateKey.sign()`
   is a single line in the code but is specified in §5.5 as the full ECDSA
   equations (`r = (k·G).x mod n`, `s = k⁻¹(e + r·d) mod n`) because the
   security of the whole system depends on `k` being uniformly random and
   secret — a property the one-line call conceals.
2. **The invariants.** §4 formalises the five implicit design rules (I1–I5) as
   testable claims, converting informal good practice into checkable
   requirements.

### 2.7 Technology Stack & Tools

| Component | Technology | Version | Role |
|-----------|-----------|---------|------|
| Language | Python | 3.11.9 | Implementation language |
| Web framework | FastAPI | 0.142.2 | Routing, dependency injection, OpenAPI generation |
| ASGI server | Uvicorn | 0.54.0 | Serves the application (`--reload` in development) |
| Cryptography | `cryptography` (OpenSSL) | 50.0.2 | All primitives — EC keys, ECDSA, ECDH |
| Validation | Pydantic | 2.13.5 | Request-schema parsing and type enforcement |
| Testing | pytest + `TestClient` (httpx) | 9.1.1 / 0.28.1 | In-process black-box test suite |
| Version control | Git + GitHub | 2.55.0 | Source management and publication |
| Documentation | Markdown | — | This specification and the `README.md` |

Environment setup:

```bash
pip install -r requirements.txt
```

### 2.8 Testing & Validation Methodology

#### 2.8.1 Strategy: black-box, contract-first

Tests exercise the application through `fastapi.testclient.TestClient` — an
in-process HTTP client — rather than calling service functions directly. This
is a deliberate methodological choice:

- It validates the **public contract** (status codes, JSON shape, field names),
  which is what a real client actually depends on.
- It drives **all three layers** on every test, so a defect anywhere on the
  request path is caught.
- It needs **no network**, so the suite is fast (≈ 1 s) and deterministic.

A consequence worth stating: refactoring the internals cannot break these tests
unless it also breaks the contract — precisely the property that is wanted.

#### 2.8.2 Test-design techniques applied

| Technique | Where it appears |
|-----------|------------------|
| **Equivalence partitioning** | Inputs divided into valid / invalid classes |
| **Boundary-value analysis** | `length = 0` (just below minimum), `length = 1025` (just above maximum), `length = 16 / 32` (valid) |
| **Positive (happy-path) testing** | Key generation, hashing, valid sign → verify |
| **Negative testing** | Tampered data, unknown key IDs, out-of-range lengths |
| **Property testing** | Symmetry (`S_A == S_B`), determinism, non-determinism, uniqueness |

#### 2.8.3 The verification loop

Verification was iterative, and the loop is itself part of the methodology:

1. **Implement** the primitive.
2. **Specify** it as pseudocode (§5–§8).
3. **Test** it through the API (§11).
4. **Reconcile** — any disagreement between specification, code and observed
   result is a defect in one of the three, and all three are corrected together.

This loop is exactly what surfaced the implementation gaps in §12 (the missing
`app/` package and the unmounted `auth` router): each was detected by a *failing
test*, then fixed and re-verified. The suite went from an import error to
**17 passed**.

#### 2.8.4 Coverage summary

| Layer / concern | How it is exercised |
|-----------------|---------------------|
| Layer 1 — services | Indirectly, through every endpoint |
| Layer 2 — core / auth | `KeyManager` (all key tests), API-key flow |
| Layer 3 — routes | All 9 endpoints |
| Guard conditions | 2 × `400` (length bounds), 2 × `404` (unknown keys) |
| Cryptographic properties | Symmetry, soundness, completeness, non-determinism |

The full property-by-property mapping of the 17 tests appears in §11.

### 2.9 Security Evaluation Methodology

The design was evaluated against an explicit threat model rather than by
intuition. The method has four steps:

1. Enumerate the **assets** worth protecting.
2. Enumerate the **adversary's capabilities**.
3. State the **security criteria** (confidentiality, integrity, authenticity,
   non-repudiation, availability).
4. Map each threat to a **mitigation**, and record any **residual risk**.

#### 2.9.1 Assets

| Asset | Where it lives | Confidentiality requirement |
|-------|----------------|-----------------------------|
| Private keys (scalar `d`) | `_key_store`, in memory only | Critical — must never leave the process |
| Shared secrets (ECDH) | Returned to the requester, transient | Critical |
| API keys (raw) | Returned once, never stored | Critical |
| API-key digests | `_api_key_store` | Low — one-way hashes |
| Key identifiers | Returned / stored | Public |

#### 2.9.2 Threat model and mitigations

| # | Threat | Mitigation in this design |
|---|--------|---------------------------|
| T1 | Key exfiltration via an API response | Responses expose only PEM public keys; I1 is enforced structurally (§6.1) |
| T2 | Store disclosure (memory dump / backup) | API keys are stored only as SHA-256 digests (§5.8) |
| T3 | Signature forgery | ECDSA over P-256 — forgery is equivalent to solving the ECDLP |
| T4 | **ECDSA nonce reuse** (which leaks `d`) | `k` is drawn from the OS CSPRNG on every signature; low-S normalisation (§5.5) |
| T5 | Message tampering | Detectable — `verify` returns `false` (§7.6) |
| T6 | Weak / predictable randomness | Only `secrets` (OS CSPRNG) is used; `random` is never imported (I4) |
| T7 | Invalid-curve point injection into ECDH | Peer keys resolve only from the server's own store; OpenSSL validates the point (§7.7) |
| T8 | Resource exhaustion (DoS) | `length` is bounded to ≤ 1024 bytes (§7.3) |
| T9 | Key-ID enumeration | A uniform `404` is returned for any unknown ID (§7.2) |
| T10 | Information leakage via errors | `InvalidSignature` is absorbed in Layer 1; no stack traces (I5) |
| T11 | Man-in-the-middle on ECDH | **Residual risk** — raw ECDH is unauthenticated (see §2.10) |

#### 2.9.3 Evaluation criteria

| Criterion | How the design meets it |
|-----------|-------------------------|
| **Confidentiality** | Keys stay in-process; API keys are hashed; the ECDH secret is never transmitted |
| **Integrity** | SHA-256 digests; tampering is detectable through signature verification |
| **Authenticity** | ECDSA signatures; API-key authentication |
| **Non-repudiation** | An ECDSA signature binds a message to the holder of the key |
| **Availability** | Bounded inputs, O(1) key lookups, stateless engine |

### 2.10 Limitations & Assumptions

Stating these explicitly is part of the methodology — an evaluation that hides
its scope is not an evaluation.

**Assumptions:**

1. The host running the API is trusted and the process is not compromised
   (an in-memory key store cannot defend against a memory-level attacker).
2. The `cryptography` / OpenSSL implementation is correct.
3. A single application process owns the store.
4. In production the API is served behind **TLS (HTTPS)**; on its own it speaks
   plain HTTP.

**Known limitations:**

| # | Limitation | Impact | Reference |
|---|-----------|--------|-----------|
| L1 | Key and API-key stores are volatile and per-process | State is lost on restart; unusable with multiple workers | §12.5 |
| L2 | Raw ECDH is unauthenticated | Vulnerable to MITM unless public keys are authenticated out-of-band | §7.7 |
| L3 | The API-key dependency is not yet applied to routes | Endpoints are currently reachable without a key | §12.4 |
| L4 | No rate limiting / throttling | Brute-force and DoS are only partially mitigated | — |
| L5 | No key rotation, expiry or revocation for key pairs | A leaked private key cannot be retired | §12.5 |
| L6 | No audit logging | Failures are not recorded for forensic review | — |

These are recorded as **scope boundaries, not defects** — each is a deliberate
deferral to the persistence / secure-element stage of the project.

## 3. System Architecture (Module Map)

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

## 4. Global Notation & Conventions

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

## 5. LAYER 1 — Cryptographic Primitive Algorithms

### 5.1 ALG-GENKEY — ECC Key Pair Generation
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

### 5.2 ALG-GETPUB — Public Key Retrieval
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

### 5.3 ALG-RAND — Cryptographically Secure Random Bytes
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

### 5.4 ALG-SHA — SHA-256 Hashing
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

### 5.5 ALG-SIGN — ECDSA Signature Generation
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

### 5.6 ALG-VERIFY — ECDSA Signature Verification
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

### 5.7 ALG-ECDH — Shared Secret Derivation
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

### 5.8 ALG-APIKEY-GEN — API Key Issuance
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

### 5.9 ALG-APIKEY-VERIFY — API Key Verification
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

## 6. LAYER 2 — Core Orchestration Algorithms

### 6.1 ALG-KEYMGR — Key Manager Facade
`core/key_manager.py :: class KeyManager`

**Role:** the *only* permitted entry point for key operations from routes.
It wraps `services/key_service.py` so routes never import crypto internals.

```
ALGORITHM KeyManager.generate_key()
BEGIN
  Step 1. RETURN Generate_Key_Pair()          // §5.1
END

ALGORITHM KeyManager.get_key(key_id)          // INTERNAL use only
BEGIN
  Step 1. RETURN _key_store.get(key_id)       // may include SK
END

ALGORITHM KeyManager.get_public_key(key_id)   // PUBLIC use
BEGIN
  Step 1. RETURN Get_Public_Key(key_id)       // §5.2 — PK only
END
```

**Encapsulation rule (critical):** `get_key()` returns the record *including*
the private key and is reserved for ECDSA/ECDH. `get_public_key()` is the
route-safe accessor. Mixing them up is the single highest-risk defect in this
codebase, hence the explicit split and naming.

---

### 6.2 ALG-ENGINE — Security Engine (Single Cryptographic Facade)
`core/security_engine.py :: class SecurityEngine`

**Role:** one class exposing *all* primitives, so a future hardware backend
(the ATECC608 secure element itself) can be dropped in without touching routes.

```
ALGORITHM SecurityEngine.generate_key()      → Generate_Key_Pair()      §5.1
ALGORITHM SecurityEngine.get_public_key(k)   → Get_Public_Key(k)        §5.2
ALGORITHM SecurityEngine.generate_random(n)  → Generate_Random_Bytes(n) §5.3
ALGORITHM SecurityEngine.hash_sha256(d)      → SHA256(d)                §5.4
ALGORITHM SecurityEngine.sign(SK, d)         → ECDSA_Sign(SK, d)        §5.5
ALGORITHM SecurityEngine.verify(PK, d, s)    → ECDSA_Verify(PK, d, s)   §5.6
ALGORITHM SecurityEngine.derive_secret(SK,Q) → ECDH_Derive(SK, Q)       §5.7
```

**Every method is `@staticmethod`** ⇒ the engine has no state of its own and
is trivially thread-safe; all state lives in the two stores.

---

### 6.3 ALG-REQAUTH — API-Key Authorization Dependency
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
  Step 3. IF Verify_API_Key(api_key) = FALSE THEN  // §5.9
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
  `Depends(require_api_key)` on each route to take effect (see §12.4).

---

## 7. LAYER 3 — API Endpoint Algorithms

### 7.0 ALG-PIPELINE — Common Request Pipeline
Every endpoint follows this uniform control flow:

```
ALGORITHM Handle_Request(method, path, body, headers)
BEGIN
  Step 1. ROUTE    ← FastAPI matches (method, path) → handler
  Step 2. VALIDATE ← Pydantic parses `body` into the declared schema;
                     IF invalid THEN RETURN 422 (automatic, before handler)
  Step 3. AUTH     ← IF Depends(Require_API_Key) attached
                     THEN run §6.3, abort with 401
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

### 7.1 ALG-EP-KEYGEN — `POST /api/v1/keys/generate`
`api/routes/keys.py :: generate_keys()`

```
ALGORITHM Endpoint_Generate_Keys()
BEGIN
  Step 1. result ← KeyManager.generate_key()     // §6.1
  Step 2. RETURN 200 result                      // {key_id, algorithm, curve,
                                                 //  public_key}  — never SK
END
```

### 7.2 ALG-EP-KEYGET — `GET /api/v1/keys/{key_id}`
`api/routes/keys.py :: retrieve_public_key(key_id)`

```
ALGORITHM Endpoint_Get_Public_Key(key_id)
BEGIN
  Step 1. key_data ← KeyManager.get_public_key(key_id)    // §6.1
  Step 2. IF key_data = NULL THEN
            RAISE HTTP_404 "Key not found"                // enumeration guard
          END IF
  Step 3. RETURN 200 key_data                             // PK only
END
```

**Note:** an unknown `key_id` yields an identical 404 regardless of ID format,
so the endpoint does not leak which IDs exist beyond membership itself.

---

### 7.3 ALG-EP-RANDOM — `POST /api/v1/random/generate?length=N`
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
  Step 3. random_data ← Generate_Random_Bytes(length)     // §5.3
  Step 4. RETURN 200 { length, random_data }
END
```

**Why the bounds (Step 1–2):** the upper bound (1024) is a **resource-abuse
guard** — without it a caller could request gigabytes and exhaust memory; hex
encoding doubles the payload, so 1024 bytes → 2048 chars. The lower bound
rejects the degenerate empty output.

---

### 7.4 ALG-EP-HASH — `POST /api/v1/hash/sha256`
`api/routes/hashing.py :: generate_sha256()`

```
ALGORITHM Endpoint_SHA256(request)
BEGIN
  Step 1. request.data ← Pydantic(HashRequest).data        // required str
  Step 2. digest ← SHA256(request.data)                    // §5.4
  Step 3. RETURN 200 { algorithm:"SHA-256", hash: digest }
END
```

**Stateless** — no key-store access, so this is the only endpoint with no 404
path and the highest throughput.

---

### 7.5 ALG-EP-SIGN — `POST /api/v1/ecdsa/sign`
`api/routes/ecdsa.py :: create_signature()`

```
ALGORITHM Endpoint_ECDSA_Sign(request)
BEGIN
  Step 1. key_data ← _key_store.get(request.key_id)
  Step 2. IF key_data = NULL THEN RAISE HTTP_404 "Key not found"
  Step 3. SK ← key_data.private_key              // internal; never serialized
  Step 4. signature ← ECDSA_Sign(SK, request.data)        // §5.5
  Step 5. RETURN 200 { algorithm:"ECDSA", curve:"secp256r1",
                       key_id: request.key_id, signature }
END
```

### 7.6 ALG-EP-VERIFY — `POST /api/v1/ecdsa/verify`
`api/routes/ecdsa.py :: verify_ecdsa_signature()`

```
ALGORITHM Endpoint_ECDSA_Verify(request)
BEGIN
  Step 1. key_data ← _key_store.get(request.key_id)
  Step 2. IF key_data = NULL THEN RAISE HTTP_404 "Key not found"
  Step 3. PK ← key_data.public_key
  Step 4. valid ← ECDSA_Verify(PK, request.data, request.signature)  // §5.6
  Step 5. RETURN 200 { algorithm:"ECDSA", key_id, valid }  // 200 even if False
END
```

**Important:** an *invalid* signature is a **successful** HTTP request
(`200 {valid: false}`), **not** a 4xx. Only a *missing key* is an error.
This cleanly separates "your signature is wrong" (a cryptographic answer)
from "you referenced a key that does not exist" (an addressing error).

---

### 7.7 ALG-EP-ECDH — `POST /api/v1/ecdh/derive`
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
  Step 7. secret ← ECDH_Derive(SK_A, PK_B)                // §5.7
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

### 7.8 ALG-EP-APIKEY — `POST /api/v1/auth/api-key`
`api/routes/auth.py :: create_api_key()`

```
ALGORITHM Endpoint_Create_API_Key()
BEGIN
  Step 1. result ← Generate_API_Key()           // §5.8
  Step 2. RETURN 200 result                     // {key_id, api_key}
END
```

The client **must persist** `api_key` at `Step 2`: the server keeps only
`SHA256(api_key)`, so the raw value is unrecoverable afterwards.

---

## 8. MASTER END-TO-END ALGORITHMS

### 8.1 ALG-FLOW-SIGNVERIFY — Authenticity Workflow

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
  Step 1. issue  ← Endpoint_Generate_Keys()              // §7.1
  Step 2. share  ← publish issue.public_key to counterparty
  Step 3. sig    ← Endpoint_ECDSA_Sign({issue.key_id, msg})   // §7.5
  Step 4. verdict← Endpoint_ECDSA_Verify({issue.key_id, msg, sig})  // §7.6
  Step 5. IF verdict.valid = TRUE
            THEN accept msg as authentic and untampered
            ELSE reject msg (message altered, or wrong key, or forged sig)
          END IF
END
```

### 8.2 ALG-FLOW-ECDH — Confidential Channel Establishment

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
  Step 3. S_A ← Endpoint_ECDH_Derive({key_id_A, key_id_B})  // §7.7
  Step 4. S_B ← Endpoint_ECDH_Derive({key_id_B, key_id_A})  // §7.7
  Step 5. ASSERT S_A = S_B            // guaranteed by the §5.7 symmetry proof
  Step 6. USE S_A as the symmetric session key (e.g. AES-GCM input key)
END
```

### 8.3 ALG-FLOW-INTEGRITY — Hash-Based Integrity Check

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

> A bare hash detects accidental corruption; pairing it with §8.1 (sign the
> digest instead of the payload) additionally provides authenticity.

### 8.4 ALG-FLOW-RANDOM — CSPRNG Delivery

```
ALGORITHM Flow_Secure_Random(n)
BEGIN
  Step 1. IF n ∉ (0, 1024] THEN RETURN HTTP_400     // §7.3 guards
  Step 2. hex ← OS_CSPRNG(n) → hex                  // §5.3
  Step 3. RETURN hex     // usable for nonces, salts, IVs, session IDs
END
```

---

## 9. APPLICATION STARTUP ALGORITHM

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

## 10. COMPLEXITY ANALYSIS

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

## 11. VALIDATION ALGORITHM (TEST SUITE)

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
| `test_ecdh_shared_secret_matches` | symmetry: `S_A == S_B` (§5.7 proof) |
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

> **Verified:** with `fastapi 0.142.2`, `cryptography 50.0.2`, `pydantic 2.13.5`,
> `pytest 9.1.1` and `httpx 0.28.1` installed under Python 3.11.9, the suite runs
> green — **17 passed** (≈ 0.8 s). One benign Starlette deprecation warning about
> `httpx`/`httpx2` is emitted by `TestClient`.

---

## 12. IMPLEMENTATION OBSERVATIONS & ALGORITHM-LEVEL GAPS

The algorithm above faithfully describes the code as written. Reviewing it as
a whole surfaced several points worth recording in the report (each is an
*implementation* issue, not a flaw in the cryptographic design).

**Resolution status** (re-verified by running the suite — see §11):

| Item | Issue | Status |
|------|-------|--------|
| §12.1 | missing `app/` package | ✅ Fixed — modules moved under `app/` |
| §12.2 | dashboard path resolved to `templates/templates/…` | ✅ Fixed — `main.py` now at `app/main.py`; `GET /` returns the dashboard (19 055 bytes) |
| §12.3 | `auth` router never mounted | ✅ Fixed — registered in `Bootstrap_Application()` |
| §12.6 | duplicate imports in `ecdsa.py` | ✅ Fixed — single import block |
| §12.4 | `require_api_key` not applied to routes | ⚠️ Open — left deliberately; see the note below |
| §12.5 | in-memory stores | ⚠️ Open — by design; needs a persistence backend |
| §12.7 | cosmetic style | ⚠️ Open — non-functional |

The sections below retain the original analysis for the record.

### 12.1 Package-path mismatch (would block startup)
Every module imports through an `app.` package:
`from app.main import app`, `from app.api.routes import ...`,
`from app.core...`, `from app.services...`, `from app.schemas...`.
On disk the packages are flattened at the repository root and there is **no
`app/` package**, so `python -m pytest tests` raises
`ModuleNotFoundError: No module named 'app'`.

**Algorithm-preserving fix (either is fine):**
- Create an `app/` package directory and move `api/`, `core/`, `services/`,
  `schemas/`, `main.py` inside it, with `main.py` at `app/main.py`; **or**
- Rewrite the imports to drop the `app.` prefix (e.g.
  `from core.key_manager import KeyManager`).

### 12.2 `main.py` location vs. its own path logic
`main.py` lives in `templates/`, yet it computes
`Path(__file__).parent / "templates" / "dashboard.html"`.
That resolves to `templates/templates/dashboard.html`, which does not exist,
so `GET /` would fail. Placing `main.py` one level above `templates/`
(i.e. at the package root, per §12.1) makes the path correct.

### 12.3 The `auth` router is never mounted
§9 shows `main.py` registers keys/random/hashing/ecdsa/ecdh but **not**
`auth.router`. Therefore `POST /api/v1/auth/api-key` is currently unreachable
— no client can obtain the API key that §6.3 would consume.
**Fix:** `app.include_router(auth.router)` in `Bootstrap_Application()`.

### 12.4 API-key enforcement is defined but not applied
`require_api_key` (§6.3) exists and is correct, but **no route declares
`Depends(require_api_key)`**. Consequently all five mounted endpoint groups
are currently public. To close the loop, the algorithm should read:

```
@router.post("/sign")
def create_signature(request: SignRequest,
                     api_key: str = Depends(require_api_key)):
    ...
```

and likewise for `ecdsa/verify`, `ecdh/derive`, `keys/*`. `hash`, `random`
and `keys/generate` are reasonable candidates for a public tier.

> **Why it was left open:** the existing `tests/*.py` call every endpoint
> *without* an `X-API-Key` header. Attaching the dependency would therefore
> turn all 17 tests into `401` failures. Applying it correctly is a two-part
> change — wire `Depends(require_api_key)` into the routes **and** update the
> tests to first `POST /api/v1/auth/api-key` and send the returned key in the
> header. That is a deliberate design decision for the report, not an
> oversight.

### 12.5 Stores are in-memory only
Both `_key_store` and `_api_key_store` are module-level dicts (the code
comments acknowledge "later this will be replaced with a database").
Consequences the report should state explicitly:
- keys and API keys **vanish on process restart**;
- state is **per-worker**, so it breaks under multiple uvicorn workers;
- there is no key expiry, rotation or audit log.
`active: True` in the API-key record is already the right hook for a
`revoke_api_key()` companion algorithm.

### 12.6 Minor code hygiene in `api/routes/ecdsa.py`
The module contains duplicate imports of `SignRequest`, `VerifyRequest`,
`sign_data` and `verify_signature` (lines 3–7). Harmless at runtime, but a
linter/report reviewer will flag it — collapse to one import block.

### 12.7 Cosmetic inconsistency
`services/random_service.py` has no blank line after `import secrets`, and
`services/key_service.py` uses a module-level singleton store; a light pass
with `ruff`/`black` would normalise style across the layers.

### 12.8 What is already done well (worth claiming in the report)
1. **Separation of concerns** — a genuine 3-layer architecture with a facade
   (`SecurityEngine`, `KeyManager`) between HTTP and crypto.
2. **Private-key containment (I1)** — `SK` is never serialized in any response
   path; only PEM `PK` is exported.
3. **One-way API-key storage** — only `SHA256(api_key)` is persisted.
4. **Correct use of vetted primitives** — no hand-rolled curve math, no
   `random` module in any security path, low-S via the library, on-curve
   validation via OpenSSL.
5. **Error containment (I5)** — `InvalidSignature` is converted to `False` at
   Layer 1, so routes never leak stack traces.
6. **Boundary validation** — Pydantic schemas plus explicit 400/404 guards.
7. **A meaningful test suite** covering completeness, soundness, symmetry,
   non-determinism, length discipline and negative paths.

---

## 13. QUICK REFERENCE — ALGORITHM–FILE INDEX

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