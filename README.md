# Fair Coin Selection Protocol

> **A Cryptographically Verifiable Multi-Party Random Selection Protocol**

The **Fair Coin Selection Protocol** selects exactly one participant from $n$ participants ($3 \le n \le 20$) with equal mathematical probability ($1/n$) under defined protocol assumptions. The system uses a commit–reveal cryptographic scheme, bitwise XOR entropy combination, and 64-bit rejection sampling, combined with independent browser-side verification that does not trust server assertions.

---

## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [Why Ordinary Random Selection Is Insufficient](#2-why-ordinary-random-selection-is-insufficient)
3. [Threat Model & Security Assumptions](#3-threat-model--security-assumptions)
4. [Protocol Overview & Lifecycle](#4-protocol-overview--lifecycle)
5. [Cryptographic Specifications](#5-cryptographic-specifications)
   - [5.1 Cryptographic Commitment Formula](#51-cryptographic-commitment-formula)
   - [5.2 Randomness Generation](#52-randomness-generation)
   - [5.3 Entropy Combination](#53-entropy-combination)
   - [5.4 Unbiased Rejection Sampling](#54-unbiased-rejection-sampling)
6. [Finite State Machine](#6-finite-state-machine)
7. [Timeout & Abort Behavior](#7-timeout--abort-behavior)
8. [Session Authentication & Reconnection Model](#8-session-authentication--reconnection-model)
9. [Independent Client Verification](#9-independent-client-verification)
10. [Interactive Security Lab](#10-interactive-security-lab)
11. [Fairness Simulation](#11-fairness-simulation)
12. [System Architecture & Technology Stack](#12-system-architecture--technology-stack)
13. [Installation & Running (Zero-npm)](#13-installation--running-zero-npm)
14. [Automated Test Suite](#14-automated-test-suite)
15. [Project Structure](#15-project-structure)
16. [Trust Assumptions & Limitations](#16-trust-assumptions--limitations)
17. [Academic & Demonstration Disclaimer](#17-academic--demonstration-disclaimer)

---

## 1. Problem Statement

In distributed environments, selecting a single winner fairly among competing participants presents significant challenges when participants do not trust each other or a centralized authority:
- A centralized coordinator can manipulate the random seed to pick a favored winner.
- Participants can attempt to choose their input after observing others' inputs.
- Unconstrained modulo reduction over random integers introduces statistical bias.

The protocol solves this by ensuring that the selection seed is mutually constructed from all participants' inputs, locked before any secret is revealed, and verifiable by all observers.

---

## 2. Why Ordinary Random Selection Is Insufficient

Ordinary approaches fail in adversarial settings:
1. **Server-Generated PRNG (`Math.random()`, `random.randint`):** The server possesses unilateral control over the seed and can selectively re-roll until a favored participant wins.
2. **Simple Majority / Hash Schemes:** If participants reveal secrets without prior binding commitments, the last revealer can compute the winner and alter their secret before disclosure.
3. **Naïve Modulo Arithmetic:** Computing $\text{winner} = V \pmod n$ over fixed-width integers (e.g. 64-bit or 256-bit) causes **modulo bias**, giving lower-indexed participants a statistically higher probability of winning when the total value space is not evenly divisible by $n$.

---

## 3. Threat Model & Security Assumptions

- **Centralized Server:** The protocol runs on an authoritative server. The server orchestrates room transitions, enforces deadlines, and broadcasts messages. While the server is centralized, **independent client verification** ensures the server cannot alter commitments, forge entropy, or misdeclare the winner without immediate mathematical detection.
- **Honest Contributor Assumption:** The cryptographic uniformity of the output requires that **at least one participant** generates a uniform, unpredictable secret using a CSPRNG and does not collude with other participants.
- **Selective Abort (The Withholding Problem):** In any standard commit–reveal protocol without financial deposits or threshold secret sharing, the last participant to reveal can compute the outcome early and choose to withhold their secret if they lose. The protocol mitigates this by enforcing an authoritative timeout, excluding non-revealers, and requiring a minimum of 2 valid reveals to proceed; otherwise, it safely aborts.
- Detailed threat modeling is available in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

---

## 4. Protocol Overview & Lifecycle

```text
       1. LOBBY PHASE (3–20 Participants join room)
                 ↓
       2. COMMIT PHASE (Secrets generated locally; SHA-256 commitments submitted)
                 ↓
       3. LOCKED PHASE (All commitments recorded; state sealed permanently)
                 ↓
       4. REVEAL PHASE (Authoritative deadline starts; secrets submitted)
                 ↓
       5. REVEAL_CLOSED (Secrets verified; non-revealers timed out; secrets disclosed)
                 ↓
       6. ENTROPY DERIVATION (Bitwise XOR: R = SHA-256(S1) ⊕ ... ⊕ SHA-256(Sk))
                 ↓
       7. REJECTION SAMPLING (Zero modulo bias rejection loop over 64-bit samples)
                 ↓
       8. COMPLETED / AUDIT (Winner announced; public audit trail independently verified)
```

---

## 5. Cryptographic Specifications

### 5.1 Cryptographic Commitment Formula
Each participant $i$ generates a random 256-bit secret $S_i$ (64 hexadecimal characters). The commitment $H_i$ is computed as:

$$H_i = \text{SHA-256}\left(\text{participantId}_i + \text{":"} + S_i\right)$$

- **Delimiter Collision Resistance:** The `:` separator strictly prevents tuple-extension ambiguities (e.g., distinguishing between `id="alice", secret="123"` and `id="alic", secret="e123"`).
- **Binding:** By the second-preimage resistance of SHA-256, it is computationally infeasible to produce a different secret $S_i' \neq S_i$ that matches $H_i$.

### 5.2 Randomness Generation
- **Browser:** `window.crypto.getRandomValues(new Uint8Array(32))` via Web Crypto CSPRNG.
- **Python Backend:** `secrets.token_hex(32)` via OS-level CSPRNG (`/dev/urandom` or `CryptGenRandom`).
- Predictable sources such as `Math.random()` or timestamp-based seeds are strictly prohibited.

### 5.3 Entropy Combination
All verified secrets from participants who successfully revealed are combined using bitwise XOR:

$$R = \text{SHA-256}(S_1) \oplus \text{SHA-256}(S_2) \oplus \dots \oplus \text{SHA-256}(S_k)$$

By the properties of XOR, if at least one secret $S_j$ is uniformly random and independent, the resulting 256-bit value $R$ is uniformly distributed across $\{0, 1\}^{256}$.

### 5.4 Unbiased Rejection Sampling
To select an index from $k$ participants without modulo bias:
1. Define the 64-bit integer space: $2^{64} = 18,446,744,073,709,551,616$.
2. Compute the unbiased rejection threshold:
   $$L = 2^{64} - \left(2^{64} \pmod k\right)$$
3. Read the first 8 bytes of $R$ as an unsigned 64-bit big-endian integer $V$.
4. **Acceptance Step:**
   - If $V < L$: accept index:
     $$\text{selectedIndex} = V \pmod k$$
   - If $V \ge L$: reject the sample, re-hash $R \leftarrow \text{SHA-256}(R)$, increment rejection counter, and re-sample until $V < L$.

---

## 6. Finite State Machine

The protocol enforces strict, non-reversible state progression:

| State | Allowed Transitions | Permitted Actions |
|---|---|---|
| `LOBBY` | $\to$ `COMMIT` | Join room, add bot, leave, start protocol (host only). |
| `COMMIT` | $\to$ `LOCKED` | Submit commitment once. Participant set remains locked. |
| `LOCKED` | $\to$ `REVEAL` | Commitments frozen. Automatically transitions to reveal phase. |
| `REVEAL` | $\to$ `REVEAL_CLOSED` | Submit reveal secret once. Deadline timer active. |
| `REVEAL_CLOSED` | $\to$ `COMPLETED` or `ABORTED` | Non-revealers marked timeout. Synchronized disclosure. |
| `COMPLETED` | Terminal | Final winner selected; audit trail permanently inspectable. |
| `ABORTED` | Terminal | Insufficient reveals ($< 2$); audit trail permanently inspectable. |

---

## 7. Timeout & Abort Behavior

- **Authoritative Server Deadline:** When the `REVEAL` phase opens, a server-enforced timer begins (default 25 seconds).
- **Non-Revealers:** Participants who fail to reveal prior to deadline expiration are marked `isTimeout = True` and excluded from the entropy pool.
- **Safe Abort Threshold:** A minimum of 2 validly verified reveals is mathematically required to combine multi-party entropy. If fewer than 2 participants reveal, the room transitions to `ABORTED`, declaring no winner and documenting the non-revealing participants in the audit trail.

---

## 8. Session Authentication & Reconnection Model

- **Session Tokens:** Upon creating or joining a room, each connection receives an unguessable 256-bit `sessionToken` private to that client.
- **Public Isolation:** Session tokens are stored strictly in server memory and are **never** included in broadcast messages, public room state, or audit trails.
- **Reconnection:** Disconnected participants can reconnect over native WebSocket using action `reconnect` with their `participantId` and `sessionToken`. Tokens are validated in constant time via `hmac.compare_digest`.

---

## 9. Independent Client Verification

The browser never relies on the server's boolean verification flags (`verified: true`, `winner: {...}`). Instead, when the game concludes, [`public/app.js`](public/app.js) executes `verifyAuditTrail()` directly in the client:
1. Re-computes SHA-256 commitments for all participants using the Web Crypto API.
2. Flags and excludes any invalid preimages.
3. Re-derives combined entropy via bitwise XOR over valid secrets.
4. Executes 64-bit BigInt rejection sampling locally.
5. Asserts that the locally computed winner matches the server's declared winner.
6. Updates the UI with a live verification status:
   - `✓ VERIFIED BY BROWSER` (all checks passed).
   - `⚠ VERIFICATION FAILED` (tampering detected with detailed error explanation).

---

## 10. Interactive Security Lab

The built-in **Security Lab** allows users and reviewers to execute simulated attacks on isolated test vectors without altering live room state:
1. **Secret Tampering:** Mutates a character in a revealed secret; confirms commitment rejection ($H(\text{pid}:\text{secret}') \neq \text{comm}$).
2. **Commitment Tampering:** Alters a registered commitment hash; confirms reveal rejection.
3. **Participant-ID Tampering:** Tests domain separation by altering the participant ID bound to a secret.
4. **Winner Tampering:** Simulates a rogue server announcing an incorrect winner; confirms immediate detection by client-side rejection sampling cross-checks.
5. **Modulo Bias vs. Rejection Sampling:** Runs an empirical simulation comparing raw modulo reduction against rejection sampling over a constrained range, displaying distribution variance and theoretical bounds.

---

## 11. Fairness Simulation

An automated simulation suite is accessible via the web interface and HTTP endpoint (`/api/simulate`):
- Executes $N$ trials ($100 \le \text{trials} \le 50,000$) across $n$ participants ($2 \le n \le 20$).
- Measures empirical win counts, percentage deviations, rejection sampling frequency, and Chi-Square goodness-of-fit ($\chi^2$).
- Rate-limited with an in-memory concurrency lock to prevent event-loop starvation.
- *Note:* Empirical simulations demonstrate statistical conformity with uniform distribution; they do not replace formal mathematical proofs.

---

## 12. System Architecture & Technology Stack

```text
[ Browser (Vanilla JS / Web Crypto) ]
                 ↕ Native WebSocket (/ws)
[ Python Server (FastAPI / Starlette / Uvicorn) ]
   ├── In-Memory RoomManager (FSM & authoritative timers)
   ├── Cryptographic Engine (hashlib, hmac, secrets)
   └── Independent Verifier (verify_audit_trail)
```

- **Backend:** Python 3.10+ using FastAPI, Starlette, and Uvicorn.
- **Frontend:** Vanilla HTML5, modern CSS3, vanilla ES2022 JavaScript.
- **Cryptography:**
  - Client: Native Web Crypto API (`window.crypto.subtle`, `getRandomValues`).
  - Server: Python Standard Library (`hashlib`, `hmac`, `secrets`).
- **Dependencies:** **Zero-npm.** No Node.js runtime, no npm packages, no React, no Tailwind, no Socket.IO.

---

## 13. Installation & Running (Zero-npm)

### Prerequisites
- Python 3.10 or higher.
- `pip install fastapi uvicorn`

### Starting the Server
```bash
python server.py
```
Open your browser and navigate to:
```text
http://localhost:3000
```

---

## 14. Automated Test Suite

The project includes 88 comprehensive automated tests covering unit primitives, multi-party WebSocket integration, protocol invariants, adversarial edge cases, fairness metrics, and deterministic vectors.

### Running the Entire Test Suite
```bash
python -m unittest test_server.py
```

### Test Coverage Highlights
- `TestProtocolCore`: Delimiter collision resistance, SHA-256 commitments, XOR symmetry, rejection sampling.
- `TestPhase2ProtocolFairness`: State boundary locking, deadline enforcement, timeout handling, safe aborts.
- `TestPhase3NativeWebSocketAndSessionRecovery`: Frame size limits, malformed JSON handling, constant-time reconnection authentication, room isolation.
- `TestPhase4IndependentClientVerification`: Full browser verification parity, secret privacy during reveal, session token non-leakage.
- `TestPhase6ProtocolInvariants`: Illegal transition guards, duplicate submission blocks, post-abort immutability.
- `TestPhase6AdversarialAndNegative`: Malicious payload rejection, fake token reconnects, cross-room containment, server room capacity limits.
- `TestPhase6FairnessAndStatisticalProperties`: Uniform distribution and Chi-Square bounds across $n \in \{3, 4, 5, 10, 20\}$.
- `TestPhase6DeterministicTestVectors`: Fixed cross-platform byte-exact test vectors.

---

## 15. Project Structure

```text
Fair-Coin-Selection-Protocol/
├── docs/
│   └── THREAT_MODEL.md          # Comprehensive threat model & security specifications
├── public/
│   ├── app.js                   # Client protocol engine & independent verifier
│   ├── index.html               # Web interface, verification display & Security Lab
│   └── style.css                # Interface styles & state badges
├── server/                      # Historical/legacy Node backend (retained for reference)
│   ├── crypto.js
│   ├── protocol.js
│   └── server.js
├── test/                        # Historical Node test runner
│   └── protocol.test.js
├── .gitignore                   # Exclusions for Python caches, OS, and editor files
├── CODE_OF_CONDUCT.md           # Community guidelines
├── CONTRIBUTING.md              # Zero-npm contributor guidelines
├── README.md                    # System documentation (this file)
├── SECURITY.md                  # Vulnerability disclosure policy
├── package.json                 # Historical Node package configuration (MIT licensed)
├── package-lock.json            # Historical Node lockfile
├── server.py                    # Active Python backend & protocol engine
└── test_server.py               # Complete automated test suite (88 tests)
```

---

## 16. Trust Assumptions & Limitations

1. **Centralized Protocol Coordinator:** The active server is centralized. Independent client-side verification guarantees that server tampering of commitments, entropy, or winner calculation is detected, but the server is trusted for transport availability.
2. **Selective Abort / Withholding:** A malicious participant who reveals last can observe others' secrets and withhold their own to force a timeout. Mitigated by exclusion and safe abort thresholds, but financial penalties (slashing/collateral) are outside the scope of this implementation.
3. **In-Memory Volatility:** Active rooms reside in server memory. Process restart terminates ongoing sessions.
4. **Historical Node Backend:** The files in `server/` and `test/` represent the legacy prototype. The active, production-ready system is `server.py` and `public/`.

---

## 17. Academic & Demonstration Disclaimer

This project is developed as an educational and research implementation of cryptographic commit-reveal protocols and fair multi-party selection. It is intended for academic evaluation, cybersecurity coursework, and protocol demonstrations.
