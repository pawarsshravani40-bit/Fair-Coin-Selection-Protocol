# Security Policy

## 1. Scope & Purpose

The **Fair Coin Selection Protocol** is an educational and reference implementation of a multi-party commit-reveal scheme with rejection sampling. This security policy outlines vulnerability handling, scope boundaries, and responsible disclosure procedures.

---

## 2. In-Scope Security Issues

The project considers the following to be valid security vulnerabilities:

1. **Cryptographic Weaknesses:**
   - Preimage or collision vulnerabilities in commitment construction.
   - Flaws in entropy aggregation (bitwise XOR) or rejection sampling limit calculations.
   - Non-timing-safe credential comparisons.
2. **Protocol Invariant Violations:**
   - Bypassing the `LOCKED` state to submit or modify commitments.
   - Leaking revealed secrets to unauthorized parties before `REVEAL_CLOSED`.
   - Accepting multiple reveals or forged secrets for a single participant.
   - Incomplete state transitions or invalid winner calculations.
3. **Authentication & Session Flaws:**
   - Session token prediction, session hijacking, or cross-room access.
   - Exposure of session tokens in public room broadcasts or audit trails.
4. **Denial-of-Service (DoS) & Resource Exhaustion:**
   - Memory exhaustion via uncontrolled room allocation.
   - Event loop starvation via unconstrained simulation parameters.

---

## 3. Out-of-Scope

The following items are recognized protocol characteristics or explicitly outside the educational threat model:

- **Selective Abort without Collateral:** Withholding of the final secret by a losing participant is an inherent property of basic commit-reveal schemes without financial bonds or threshold secret sharing (see `docs/THREAT_MODEL.md`).
- **Server Termination:** In-memory state loss due to intentional or unintentional process termination.
- **Client Device Compromise:** Attacks requiring physical or administrative compromise of a participant's browser or operating system.

---

## 4. Reporting a Vulnerability

If you discover a security vulnerability within this project:

1. **Do not create a public GitHub issue.**
2. Open a private security advisory on the GitHub repository:
   - Navigate to **Security** $\to$ **Advisories** $\to$ **Report a vulnerability**.
3. Include the following details in your report:
   - Description of the vulnerability and attack scenario.
   - Minimal reproducible test case or script.
   - Potential security impact (e.g., integrity violation, denial of service).
   - Proposed remediation (if available).

All valid reports will be reviewed, acknowledged, and addressed in accordance with responsible disclosure practices.
