# Fair Coin Selection Protocol

> **A Cryptographically Secure and Verifiable Random Selection Protocol for Multiple Participants**

Selects exactly one winner from $n$ participants ($3 \le n \le 20$) with provably equal probability ($1/n$), resistant to manipulation and cheating even when $n - 1$ participants are colluding.

---

## 1. Project Purpose

In distributed systems and competitive games without a trusted third party, deciding a single winner fairly is challenging:
- A single centralized coordinator could manipulate the outcome.
- Simple pseudo-random generators can be predicted or seeded by a malicious actor.
- Modulo operations on random integers often introduce subtle biases (modulo bias).

The **Fair Coin Selection Protocol** addresses these challenges through a decentralized cryptographic commit–reveal scheme, bitwise XOR entropy combination, and zero-bias rejection sampling.

---

## 2. Technology

- **Backend**: Node.js, Express, Socket.IO
- **Frontend**: Vanilla HTML5, CSS3, JavaScript (ES2022)
- **Cryptography**:
  - Web Crypto API (`crypto.getRandomValues`, `crypto.subtle.digest`) on client
  - Node.js `node:crypto` (`crypto.randomBytes`, `crypto.createHash`, `crypto.timingSafeEqual`) on server
  - SHA-256 hash commitments
- **Package Manager**: npm
- **Testing**: Native Node.js test runner (`node:test`, `node:assert`)

---

## 3. Protocol Architecture & Lifecycle

```text
       LOBBY (3–20 Participants)
                 ↓
      1. COMMIT PHASE (Secrets held locally; SHA-256 hashes submitted)
                 ↓
      2. LOCK PHASE (Commitments frozen; modifications strictly rejected)
                 ↓
      3. REVEAL PHASE (Secrets submitted; verified against locked hashes)
                 ↓
      4. COMBINE ENTROPY (Bitwise XOR: R = R1 ⊕ R2 ⊕ ... ⊕ Rn)
                 ↓
      5. UNBIASED SELECTION (Rejection sampling eliminates modulo bias)
                 ↓
      6. WINNER ANNOUNCED (Audit trail with full verification breakdown)
```

### 3.1 Commit–Reveal Protocol
1. **Commitment**: Each participant $i$ generates a 256-bit cryptographically secure local secret $S_i$. The client computes:
   $$H_i = \text{SHA-256}(\text{participantId}_i \parallel S_i)$$
   Only $H_i$ is submitted to the server. $S_i$ remains strictly in client memory.
2. **Locking**: Once all required commitments are registered, the server locks the state. No late arrivals, replacement commitments, or alterations are permitted.
3. **Reveal**: Each participant submits their plaintext secret $S_i$. The server verifies:
   $$\text{SHA-256}(\text{participantId}_i \parallel S_i) \stackrel{?}{=} H_i$$
   - Matches are marked `✓ Verified`.
   - Any mismatch triggers `❌ Attack Detected` and is immediately rejected.

### 3.2 Randomness Combination
All valid secrets are combined using bitwise XOR:
$$R = R_1 \oplus R_2 \oplus \dots \oplus R_n$$
Because XOR is commutative, associative, and entropy-preserving, if even a single participant acts honestly with uniform randomness, the resulting combined seed $R$ is completely uniform and unpredictable.

### 3.3 Unbiased Selection via Rejection Sampling
Using naïve modulo arithmetic:
$$\text{index} = R \pmod n$$
introduces **modulo bias** because $2^{64}$ (or $2^{256}$) is generally not evenly divisible by $n$.

To guarantee strict mathematical fairness, we implement rejection sampling:
1. Read an unsigned 64-bit integer $V$ from seed $R$.
2. Compute the maximum unbiased limit:
   $$L = 2^{64} - (2^{64} \pmod n)$$
3. If $V < L$, select $\text{index} = V \pmod n$.
4. If $V \ge L$, reject the sample, re-hash $R' = \text{SHA-256}(R)$, and retry.

---

## 4. Installation & Running

### Prerequisites
- Node.js (v18+) & npm

### Installation
```bash
git clone https://github.com/Shravani-Pawar/Fair-Coin-Selection-Protocol.git
cd Fair-Coin-Selection-Protocol
npm install
```

### Starting the Server
```bash
npm start
```
Open your browser and navigate to:
```text
http://localhost:3000
```

---

## 5. Automated Tests

The test suite validates:
1. **Cryptographic Primitives**: SHA-256 commitment integrity, preimage resistance, and XOR symmetry.
2. **Cheating Detection**: Tampered secrets and altered commitments are rejected.
3. **Scalability**: Protocol execution across $n \in \{3, 4, 5, 10, 20\}$ participants.
4. **Timeout Handling**: Silent/non-revealing participants are excluded without halting protocol.
5. **Statistical Fairness**: 10,000 automated selections verifying win rates stay within statistical tolerance ($p > 0.01$, $\chi^2$ test).

Run tests with:
```bash
npm test
```

---

## 6. Cheating Detection & Attack Demonstration

The application includes an interactive **Attack Sandbox** and an in-game **Simulate Cheating Attack** button:
- A participant commits to original secret $S = 123456...$
- During the reveal phase, they attempt to reveal $S' = 999999...$
- The server verifies:
  $$\text{SHA-256}(\text{id} \parallel 999999...) \neq H_{\text{stored}}$$
- The server flags `❌ ATTACK DETECTED`, rejects the reveal, logs the attack in the audit trail, and excludes the attacker from the winner selection.

---

## 7. Limitations

1. **Non-Reveal / Withholding Problem**: In commit–reveal schemes, a malicious participant who sees other reveals could refuse to reveal their own secret if they realize they are not winning. The protocol handles this by timing out and excluding non-revealers, but in high-stakes financial scenarios, economic deposits or threshold secret sharing (e.g. Shamir's Secret Sharing) would be required.
2. **Academic Demonstration**: This application demonstrates foundational multi-party cryptographic fair selection and is intended for educational and reference purposes.
