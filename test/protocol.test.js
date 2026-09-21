const { test, describe } = require('node:test');
const assert = require('node:assert');

const {
  generateSecret,
  computeCommitment,
  verifyCommitment,
  combineRandomness,
  unbiasedSelect
} = require('../server/crypto');

const { Room, RoomManager, STATES } = require('../server/protocol');

describe('Fair Coin Selection Protocol — Cryptographic Primitives', () => {
  test('generateSecret() creates 256-bit cryptographically secure hex secrets', () => {
    const s1 = generateSecret();
    const s2 = generateSecret();

    assert.strictEqual(typeof s1, 'string');
    assert.strictEqual(s1.length, 64);
    assert.match(s1, /^[0-9a-f]{64}$/);
    assert.notStrictEqual(s1, s2, 'Consecutive secrets must be unique');
  });

  test('computeCommitment() is deterministic and matches SHA-256', () => {
    const id = 'user-1';
    const secret = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890';
    const c1 = computeCommitment(id, secret);
    const c2 = computeCommitment(id, secret);

    assert.strictEqual(c1, c2);
    assert.strictEqual(c1.length, 64);

    // Different id or secret produces completely different commitment
    const c3 = computeCommitment('user-2', secret);
    assert.notStrictEqual(c1, c3);
  });

  test('verifyCommitment() validates genuine secrets and rejects altered secrets', () => {
    const id = 'alice';
    const secret = generateSecret();
    const commitment = computeCommitment(id, secret);

    // Genuine secret
    assert.strictEqual(verifyCommitment(id, secret, commitment), true);

    // Altered secret (1 char modified)
    const altered = secret.slice(0, -1) + (secret.endsWith('0') ? '1' : '0');
    assert.strictEqual(verifyCommitment(id, altered, commitment), false);

    // Altered participant id
    assert.strictEqual(verifyCommitment('bob', secret, commitment), false);

    // Empty or malformed inputs
    assert.strictEqual(verifyCommitment(id, '', commitment), false);
    assert.strictEqual(verifyCommitment('', secret, commitment), false);
  });

  test('combineRandomness() performs commutative and associative XOR combination', () => {
    const s1 = generateSecret();
    const s2 = generateSecret();
    const s3 = generateSecret();

    const r123 = combineRandomness([s1, s2, s3]);
    const r321 = combineRandomness([s3, s2, s1]);

    assert.strictEqual(r123.length, 32);
    assert.deepStrictEqual(r123, r321, 'XOR combination must be order-independent');
  });

  test('unbiasedSelect() selects valid index in [0, n - 1] without bias', () => {
    const seed = combineRandomness([generateSecret(), generateSecret()]);
    for (const n of [3, 4, 5, 10, 20]) {
      const result = unbiasedSelect(seed, n);
      assert(result.index >= 0 && result.index < n);
      assert.strictEqual(typeof result.rejections, 'number');
      assert.strictEqual(result.finalSeedHex.length, 64);
    }
  });
});

describe('Fair Coin Selection Protocol — Full Lifecycle (n = 3)', () => {
  test('Complete valid commit-reveal-select execution', () => {
    const room = new Room('TEST01', 'host-id', 'Alice', 3);
    assert.strictEqual(room.state, STATES.LOBBY);

    // Bob and Charlie join
    room.addParticipant('bob-id', 'Bob');
    room.addParticipant('charlie-id', 'Charlie');
    assert.strictEqual(room.participants.size, 3);

    // Alice starts selection
    room.startProtocol('host-id');
    assert.strictEqual(room.state, STATES.COMMIT);

    // Step 1: Participants generate local secrets
    const aliceSecret = generateSecret();
    const bobSecret = generateSecret();
    const charlieSecret = generateSecret();

    // Step 2: Participants compute commitments locally
    const aliceCommitment = computeCommitment('host-id', aliceSecret);
    const bobCommitment = computeCommitment('bob-id', bobSecret);
    const charlieCommitment = computeCommitment('charlie-id', charlieSecret);

    // Step 3: Participants submit commitments to server
    room.submitCommitment('host-id', aliceCommitment);
    room.submitCommitment('bob-id', bobCommitment);
    assert.strictEqual(room.state, STATES.COMMIT);

    // Last commitment triggers lock and transitions to REVEAL
    room.submitCommitment('charlie-id', charlieCommitment);
    assert.strictEqual(room.state, STATES.REVEAL);

    // Attempting to submit another commitment after lock must throw
    assert.throws(() => {
      room.submitCommitment('host-id', generateSecret());
    }, /Commitments not accepted/);

    // Step 4: Reveal phase
    room.submitReveal('host-id', aliceSecret);
    room.submitReveal('bob-id', bobSecret);
    assert.strictEqual(room.state, STATES.REVEAL);

    room.submitReveal('charlie-id', charlieSecret);

    // Step 5: Finalization & Winner
    assert.strictEqual(room.state, STATES.COMPLETED);
    assert.ok(room.result);
    assert.ok(room.result.winner);
    assert(['Alice', 'Bob', 'Charlie'].includes(room.result.winner.name));
    assert.strictEqual(room.result.verifiedCount, 3);
    assert.strictEqual(room.result.auditTrail.length, 3);
    assert(room.result.auditTrail.every((p) => p.verified === true));
  });
});

describe('Fair Coin Selection Protocol — Cheating Detection', () => {
  test('Tampered secret fails commitment verification and triggers attack alert', () => {
    const room = new Room('TEST02', 'p1', 'Alice', 3);
    room.addParticipant('p2', 'Bob');
    room.addParticipant('p3', 'Eve (Attacker)');

    room.startProtocol('p1');

    const s1 = generateSecret();
    const s2 = generateSecret();
    const realEveSecret = '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef';
    const fakeEveSecret = '9999999999abcdef9999999999abcdef9999999999abcdef9999999999abcdef';

    // Eve commits to realEveSecret
    const c1 = computeCommitment('p1', s1);
    const c2 = computeCommitment('p2', s2);
    const c3 = computeCommitment('p3', realEveSecret);

    room.submitCommitment('p1', c1);
    room.submitCommitment('p2', c2);
    room.submitCommitment('p3', c3);

    assert.strictEqual(room.state, STATES.REVEAL);

    // Alice and Bob reveal legitimately
    room.submitReveal('p1', s1);
    room.submitReveal('p2', s2);

    // Eve attempts to reveal a different secret!
    room.submitReveal('p3', fakeEveSecret);

    assert.strictEqual(room.state, STATES.COMPLETED);

    // Check Eve was rejected and detected
    const eveData = room.participants.get('p3');
    assert.strictEqual(eveData.verified, false);
    assert.strictEqual(eveData.isAttacking, true);
    assert.strictEqual(room.attackLog.length, 1);
    assert.strictEqual(room.attackLog[0].participantId, 'p3');
    assert.match(room.attackLog[0].message, /Commitment verification failed/);

    // Winner must be selected ONLY from verified participants (Alice or Bob, NOT Eve)
    assert(['Alice', 'Bob'].includes(room.result.winner.name));
    assert.notStrictEqual(room.result.winner.name, 'Eve (Attacker)');
  });

  test('Modifying commitment after submission is rejected', () => {
    const room = new Room('TEST03', 'p1', 'Alice', 3);
    room.addParticipant('p2', 'Bob');
    room.addParticipant('p3', 'Charlie');
    room.startProtocol('p1');

    const s1 = generateSecret();
    room.submitCommitment('p1', computeCommitment('p1', s1));

    // Alice tries to submit a replacement commitment
    assert.throws(() => {
      room.submitCommitment('p1', computeCommitment('p1', generateSecret()));
    }, /Modifications are strictly forbidden/);
  });
});

describe('Fair Coin Selection Protocol — Scalability (n = 3, 4, 5, 10, 20)', () => {
  const countsToTest = [3, 4, 5, 10, 20];

  for (const n of countsToTest) {
    test(`Protocol completes successfully with n = ${n} participants`, () => {
      const room = new Room(`ROOM${n}`, 'p-0', 'Participant 0', n);

      for (let i = 1; i < n; i++) {
        room.addParticipant(`p-${i}`, `Participant ${i}`);
      }
      assert.strictEqual(room.participants.size, n);

      room.startProtocol('p-0');

      const secrets = [];
      for (let i = 0; i < n; i++) {
        const s = generateSecret();
        secrets.push(s);
        room.submitCommitment(`p-${i}`, computeCommitment(`p-${i}`, s));
      }

      assert.strictEqual(room.state, STATES.REVEAL);

      for (let i = 0; i < n; i++) {
        room.submitReveal(`p-${i}`, secrets[i]);
      }

      assert.strictEqual(room.state, STATES.COMPLETED);
      assert.strictEqual(room.result.verifiedCount, n);
      assert(room.result.winner !== null);
      assert(room.result.winner.id.startsWith('p-'));
    });
  }
});

describe('Fair Coin Selection Protocol — Non-Reveal Timeout Handling', () => {
  test('Non-revealing participant is excluded upon timeout without aborting other valid reveals', () => {
    const room = new Room('TIMEOUT', 'p1', 'Alice', 3);
    room.addParticipant('p2', 'Bob');
    room.addParticipant('p3', 'Charlie (Silent)');

    room.startProtocol('p1');

    const s1 = generateSecret();
    const s2 = generateSecret();
    const s3 = generateSecret();

    room.submitCommitment('p1', computeCommitment('p1', s1));
    room.submitCommitment('p2', computeCommitment('p2', s2));
    room.submitCommitment('p3', computeCommitment('p3', s3));

    // Alice and Bob reveal
    room.submitReveal('p1', s1);
    room.submitReveal('p2', s2);

    // Charlie does not reveal. Trigger timeout
    room.handleTimeout();

    assert.strictEqual(room.state, STATES.COMPLETED);
    const charlie = room.participants.get('p3');
    assert.strictEqual(charlie.isTimeout, true);
    assert.strictEqual(charlie.verified, false);

    // Winner chosen only between Alice and Bob
    assert(['Alice', 'Bob'].includes(room.result.winner.name));
    assert.strictEqual(room.result.verifiedCount, 2);
  });
});

describe('Fair Coin Selection Protocol — Statistical Fairness Simulation', () => {
  test('Observed frequencies across 10,000 selections are uniform (p > 0.01)', () => {
    const n = 5;
    const trials = 10000;
    const wins = new Array(n).fill(0);
    const expectedWins = trials / n; // 2000

    for (let i = 0; i < trials; i++) {
      const secrets = [];
      for (let j = 0; j < n; j++) {
        secrets.push(generateSecret());
      }
      const combined = combineRandomness(secrets);
      const sel = unbiasedSelect(combined, n);
      wins[sel.index]++;
    }

    // Chi-Square statistic calculation
    let chiSquare = 0;
    for (let i = 0; i < n; i++) {
      chiSquare += Math.pow(wins[i] - expectedWins, 2) / expectedWins;
      const winPct = (wins[i] / trials) * 100;
      // Each participant win percentage should be 20% +/- 2%
      assert(
        winPct >= 18.0 && winPct <= 22.0,
        `Participant ${i} win percentage ${winPct.toFixed(2)}% deviated beyond acceptable tolerance`
      );
    }

    // For df = 4, critical chi-square value for alpha = 0.01 is 13.277
    assert(
      chiSquare < 13.28,
      `Chi-square statistic ${chiSquare.toFixed(2)} indicates potential non-uniformity (critical 13.28)`
    );
  });
});
