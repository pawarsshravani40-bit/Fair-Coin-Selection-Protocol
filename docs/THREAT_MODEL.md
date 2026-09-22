# Fair Coin Selection Protocol — Threat Model

This document outlines the security architecture, asset classifications, adversary models, trust assumptions, security properties, and known limitations of the **Fair Coin Selection Protocol**.

---

## 1. System Assets

The protocol handles and protects the following assets:

| Asset | Sensitivity | Description & Protection Mechanism |
|---|---|---|
| **Participant Secrets ($S_i$)** | High (pre-reveal) / Public (post-closure) | 256-bit cryptographically secure random values generated locally on each client. Kept strictly in client memory during the `COMMIT` and `LOCKED` phases; hidden by the server until `REVEAL_CLOSED`. |
| **Commitment Hashes ($H_i$)** | Public | $\text{SHA-256}(\text{participantId}_i + \text{":"} + S_i)$. Publicly visible once submitted; immutable once registered. |
| **Session Tokens** | High (Confidential) | 256-bit unguessable tokens issued exclusively to the owning WebSocket connection for session recovery. Never included in room broadcasts or audit trails. |
| **Participant Identities** | Low | Unique participant IDs and sanitized display names. Bound to commitments via the `:` delimiter. |
| **Protocol State** | Critical | Finite State Machine (`LOBBY` $\to$ `COMMIT` $\to$ `LOCKED` $\to$ `REVEAL` $\to$ `REVEAL_CLOSED` $\to$ `COMPLETED`/`ABORTED`). Enforced authoritatively by the server. |
| **Combined Entropy ($R$)** | Public | Bitwise XOR combination of all validly revealed secrets: $R = \bigoplus_{i} \text{SHA-256}(S_i)$. |
| **Audit Trail & Result** | Public | Verifiable record containing participants, commitments, revealed secrets, rejection counts, sample value, and winner. |

---

## 2. Adversary Models

The protocol considers adversaries operating in the following roles:

### 2.1 Malicious Participant
- **Commitment Alteration:** An attacker submits a commitment $H_A$, observes the commitments or reveals of other participants, and attempts to change their secret $S_A'$ to force a desired outcome.
  - *Mitigation:* Cryptographic binding of SHA-256 and immutability enforced in `COMMIT` and `LOCKED` phases. Any reveal where $\text{SHA-256}(\text{id} + \text{":"} + S') \neq H_A$ is rejected.
- **Identity Swapping / Domain Extension:** An attacker attempts to exploit delimiter ambiguity (e.g. swapping characters between participant ID and secret).
  - *Mitigation:* Explicit `:` delimiter separation enforced in both Python and client Web Crypto verification.
- **Selective Abort / Withholding:** An attacker withholds their secret upon discovering that revealing it would cause them to lose.
  - *Mitigation:* Authoritative server reveal deadline (`reveal_deadline`). Non-revealing participants are marked as timed out and excluded from the entropy pool. If at least 2 valid reveals remain, selection proceeds over honest participants. If fewer than 2 remain, the protocol aborts safely.

### 2.2 Dishonest or Compromised Server
- **Manipulating the Winner:** The server attempts to declare a favored participant as winner regardless of the mathematical entropy.
  - *Mitigation:* **Independent Client Verification (`verifyAuditTrail`)**. The browser re-computes all commitments, recombines entropy, and executes rejection sampling locally. Any forged winner triggers `⚠ VERIFICATION FAILED`.
- **Early Secret Leakage:** The server broadcasts revealed secrets to colluding participants before the reveal phase closes.
  - *Mitigation:* The protocol enforces `revealedSecret = None` in public broadcasts until `REVEAL_CLOSED`. However, because the server is centralized, a compromised server could privately leak data to an accomplice (see Section 4).

### 2.3 Network / In-Transit Attacker
- **Eavesdropping and Replay:** An adversary attempts to capture session tokens or inject forged WebSocket frames.
  - *Mitigation:* Transport Layer Security (TLS/WSS in production). In addition, session tokens are compared using constant-time comparisons (`hmac.compare_digest`), and request correlation IDs prevent replay ambiguity.

---

## 3. Trust Assumptions

1. **At Least One Honest Participant:**  
   The randomness combination relies on the XOR property:
   $$R = S_1 \oplus S_2 \oplus \dots \oplus S_k$$
   If at least one participant $j$ generates a truly unpredictable secret using a cryptographically secure pseudorandom number generator (CSPRNG via Web Crypto or OS `/dev/urandom`), the resulting XOR $R$ is strictly uniform and unpredictable to all other $k-1$ colluding participants.
2. **Client Cryptographic Primitives:**  
   Clients must possess a conforming implementation of the Web Crypto API (`window.crypto.subtle` and `window.crypto.getRandomValues`).
3. **Server Execution Integrity for Liveness:**  
   The server is trusted for protocol *liveness* (broadcasting messages and enforcing timers). It is *not* trusted for cryptographic *validity*, as clients independently verify all mathematical assertions.
4. **Transport Security:**  
   Production deployments must terminate TLS (`https://` and `wss://`) to protect communication from eavesdropping.

---

## 4. Security Properties & Guarantees

- **Commitment Binding:** Once a participant registers $H_i$, they cannot find another secret $S_i' \neq S_i$ such that $\text{SHA-256}(\text{pid}_i : S_i') = H_i$ without breaking SHA-256 second-preimage resistance.
- **Commitment Secrecy (Hiding):** Prior to reveal, secrets cannot be extracted from commitments without breaking SHA-256 preimage resistance.
- **Unbiased Selection:** Naïve modulo ($V \pmod n$) introduces statistical skew when $2^{64}$ is not divisible by $n$. Rejection sampling bounds sampling to $L = 2^{64} - (2^{64} \pmod n)$, guaranteeing uniform selection probability ($1/n$) over all surviving participants.
- **Full Public Auditability:** Every game produces an exportable cryptographic receipt containing all data needed to independently verify the outcome without accessing private credentials.

---

## 5. Known Limitations

1. **Centralized Server Architecture:**  
   The server is a centralized Python process. While it cannot forge winners without detection by independent client verifiers, a malicious server operator could arbitrarily disconnect clients, refuse to advance rounds, or withhold broadcasts. This project is **not** a decentralized consensus protocol or blockchain.
2. **No Financial Collateral / Slashing:**  
   While non-revealers are timed out and excluded, the protocol does not penalize withholding via financial bonds or slashing. In adversarial high-stakes environments, threshold cryptography (such as distributed key generation or Shamir's secret sharing) or escrow deposits would be required.
3. **In-Memory Volatility:**  
   Room state and active sessions reside in server memory. A server restart terminates active rooms.
4. **Sybil Resistance:**  
   The protocol operates within closed rooms of size $3 \le n \le 20$. It does not provide open-membership Sybil defense; participant authorization is governed at room entry.
