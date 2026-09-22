# Contributing to Fair Coin Selection Protocol

Thank you for contributing to the **Fair Coin Selection Protocol**. This project is maintained with strict engineering standards, reproducible zero-npm workflows, and rigorous cryptographic testing.

---

## 1. Environment & Architecture Principles

1. **Zero-npm Development Workflow:**
   - The active backend runs on Python 3.10+ (FastAPI + Uvicorn + Starlette).
   - **Do NOT run `npm`, `npm install`, or add Node.js dependencies.**
   - The frontend is implemented in vanilla HTML5, CSS3, and ES2022 JavaScript using the native Web Crypto API and browser WebSockets.
2. **No Framework Proliferation:**
   - Do not introduce React, Vue, Vite, Tailwind, Socket.IO, or other external build chains.
   - Keep the codebase lightweight, understandable, and free of heavyweight dependencies.
3. **No Generated Media:**
   - Do not commit videos, GIFs, animations, audio files, stock images, or AI-generated media.

---

## 2. Local Setup & Running

### Prerequisites
- Python 3.10 or higher.
- Modern web browser (Chrome, Firefox, Safari, Edge) with Web Crypto support.

### Running the Server
```bash
python server.py
```
Access the application locally at `http://localhost:3000`.

---

## 3. Testing Requirements

All contributions must pass 100% of the automated test suite prior to submitting a pull request:

```bash
# Run the complete test suite
python -m unittest test_server.py
```

When contributing new features or security hardening:
- Include corresponding unit tests in `test_server.py`.
- Verify that all existing protocol invariant, cryptographic, and WebSocket tests continue to pass.
- Maintain zero regressions across all phases.

---

## 4. Coding & Security Standards

- **Timing Safety:** Always use constant-time comparisons (`hmac.compare_digest`) for secrets, hashes, and session tokens.
- **Privacy Preservation:** Never expose unrevealed secrets or internal session tokens in public room broadcasts or audit trails.
- **Input Validation:** Enforce strict format checks (e.g. 64-hex regex `^[0-9a-fA-F]{64}$`, sanitized room codes, and length limits).
- **Independent Verification:** Ensure any changes to cryptographic formulas remain mirrored and verifiable between `server.py` and `public/app.js`.

---

## 5. Pull Request Guidelines

1. Ensure the working tree is clean with no temporary, build, or cache files committed.
2. Provide a clear commit message explaining the technical rationale.
3. Verify that `python -m py_compile server.py` and `python -m unittest test_server.py` succeed without errors or warnings.
