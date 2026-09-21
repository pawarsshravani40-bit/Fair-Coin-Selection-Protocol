const crypto = require('crypto');

/**
 * Fair Coin Selection Protocol — Cryptographic Utilities
 *
 * Implements:
 * 1. Cryptographically secure 256-bit secret generation
 * 2. SHA-256 commitment computation: H = SHA-256(participantId || secret)
 * 3. Timing-safe commitment verification
 * 4. Associative and commutative XOR randomness combination: R = R1 XOR R2 XOR ... XOR Rn
 * 5. Rejection sampling for provably unbiased selection (eliminates modulo bias)
 */

/**
 * Generate a 256-bit cryptographically secure random secret (64 hex characters).
 * @returns {string} Hex encoded secret
 */
function generateSecret() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Compute SHA-256 commitment: H = SHA-256(participantId || secret)
 * @param {string} participantId - Unique participant identifier
 * @param {string} secret - Revealed or secret string
 * @returns {string} Hex encoded SHA-256 hash
 */
function computeCommitment(participantId, secret) {
  if (!participantId || !secret) {
    throw new Error('participantId and secret are required for commitment calculation');
  }
  return crypto
    .createHash('sha256')
    .update(String(participantId) + String(secret))
    .digest('hex');
}

/**
 * Timing-safe commitment verification.
 * Prevents timing attacks when comparing hashes.
 * @param {string} participantId - Unique participant identifier
 * @param {string} secret - Revealed secret string
 * @param {string} commitment - Expected SHA-256 commitment hex string
 * @returns {boolean} True if matching, false otherwise
 */
function verifyCommitment(participantId, secret, commitment) {
  if (!participantId || !secret || !commitment) return false;
  try {
    const computed = computeCommitment(participantId, secret);
    const computedBuf = Buffer.from(computed, 'hex');
    const expectedBuf = Buffer.from(commitment, 'hex');

    if (computedBuf.length !== expectedBuf.length) {
      return false;
    }
    return crypto.timingSafeEqual(computedBuf, expectedBuf);
  } catch (err) {
    return false;
  }
}

/**
 * Combine valid participant secret contributions using XOR:
 * R = R1 XOR R2 XOR ... XOR Rn
 * @param {string[]} secrets - Array of verified secret hex strings (at least 32 bytes / 64 hex chars)
 * @returns {Buffer} Combined 32-byte randomness buffer
 */
function combineRandomness(secrets) {
  if (!Array.isArray(secrets) || secrets.length === 0) {
    throw new Error('At least one secret is required to combine randomness');
  }

  const result = Buffer.alloc(32, 0);

  for (const s of secrets) {
    const sBuf = crypto.createHash('sha256').update(String(s)).digest();
    for (let i = 0; i < 32; i++) {
      result[i] ^= sBuf[i];
    }
  }

  return result;
}

/**
 * Select an unbiased index from [0, n - 1] using rejection sampling.
 * Avoids modulo bias (R % n) by rejecting draws in the incomplete remainder range:
 * Range: [0, 2^64 - 1]
 * Limit L = 2^64 - (2^64 % n)
 * If drawn value V >= L, rejection occurs and seed is advanced via SHA-256.
 *
 * @param {Buffer} seedBuffer - 32-byte combined randomness buffer
 * @param {number} n - Number of participants (3 <= n <= 20)
 * @returns {{ index: number, rejections: number, finalSeedHex: string, sampleValue: string }}
 */
function unbiasedSelect(seedBuffer, n) {
  if (!Number.isInteger(n) || n < 2) {
    throw new Error('Participant count n must be an integer >= 2');
  }

  const MAX_UINT64 = 18446744073709551616n; // 2^64
  const nBig = BigInt(n);
  const limit = MAX_UINT64 - (MAX_UINT64 % nBig);

  let currentBuffer = Buffer.from(seedBuffer);
  let rejections = 0;

  while (true) {
    // Read first 8 bytes as 64-bit unsigned BigInt
    const val = currentBuffer.readBigUInt64BE(0);

    if (val < limit) {
      const selectedIndex = Number(val % nBig);
      return {
        index: selectedIndex,
        rejections,
        finalSeedHex: currentBuffer.toString('hex'),
        sampleValue: val.toString()
      };
    }

    // Rejection: re-hash seed to produce independent draw
    rejections++;
    currentBuffer = crypto.createHash('sha256').update(currentBuffer).digest();
  }
}

module.exports = {
  generateSecret,
  computeCommitment,
  verifyCommitment,
  combineRandomness,
  unbiasedSelect
};
