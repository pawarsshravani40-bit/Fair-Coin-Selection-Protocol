const {
  computeCommitment,
  verifyCommitment,
  combineRandomness,
  unbiasedSelect
} = require('./crypto');

/**
 * Protocol States
 */
const STATES = {
  LOBBY: 'LOBBY',
  COMMIT: 'COMMIT',
  LOCKED: 'LOCKED',
  REVEAL: 'REVEAL',
  COMPLETED: 'COMPLETED',
  ABORTED: 'ABORTED'
};

/**
 * Room class managing the state of a single Fair Coin Selection session.
 */
class Room {
  /**
   * @param {string} code - 6-character room code
   * @param {string} hostId - Socket/Participant ID of host
   * @param {string} hostName - Host name
   * @param {number} requiredParticipants - 3 to 20
   */
  constructor(code, hostId, hostName, requiredParticipants) {
    this.code = code;
    this.hostId = hostId;
    this.requiredParticipants = Math.max(3, Math.min(20, requiredParticipants || 3));
    this.state = STATES.LOBBY;
    this.createdAt = Date.now();

    /**
     * Map of participantId -> Participant
     * Participant structure:
     * {
     *   id: string,
     *   name: string,
     *   isHost: boolean,
     *   commitment: string | null,
     *   revealedSecret: string | null,
     *   verified: boolean | null,
     *   isRevealed: boolean,
     *   isAttacking: boolean,
     *   isTimeout: boolean
     * }
     */
    this.participants = new Map();

    // Add host as first participant
    this.participants.set(hostId, {
      id: hostId,
      name: hostName,
      isHost: true,
      commitment: null,
      revealedSecret: null,
      verified: null,
      isRevealed: false,
      isAttacking: false,
      isTimeout: false
    });

    // Final outcome
    this.result = null;
    this.attackLog = [];
  }

  /**
   * Add participant to room
   */
  addParticipant(id, name) {
    if (this.state !== STATES.LOBBY) {
      throw new Error(`Cannot join room: game is already in ${this.state} phase`);
    }
    if (this.participants.size >= this.requiredParticipants) {
      throw new Error(`Room is full (${this.requiredParticipants} participants maximum)`);
    }
    if (this.participants.has(id)) {
      throw new Error('Participant ID already in room');
    }

    this.participants.set(id, {
      id,
      name: name.trim() || `Participant ${this.participants.size + 1}`,
      isHost: false,
      commitment: null,
      revealedSecret: null,
      verified: null,
      isRevealed: false,
      isAttacking: false,
      isTimeout: false
    });

    return this.participants.get(id);
  }

  /**
   * Remove participant (e.g. on disconnect)
   */
  removeParticipant(id) {
    if (this.state === STATES.LOBBY) {
      this.participants.delete(id);
      return true;
    }
    // If during game, mark participant as disconnected/timeout
    const p = this.participants.get(id);
    if (p) {
      p.isTimeout = true;
      if (this.state === STATES.REVEAL) {
        this.checkAllRevealed();
      }
      return true;
    }
    return false;
  }

  /**
   * Start the selection protocol (Host only)
   */
  startProtocol(requesterId) {
    if (requesterId !== this.hostId) {
      throw new Error('Only the host can start the selection');
    }
    if (this.state !== STATES.LOBBY) {
      throw new Error(`Protocol already started (current state: ${this.state})`);
    }
    if (this.participants.size < 3) {
      throw new Error('At least 3 participants are required to start');
    }

    this.state = STATES.COMMIT;
    return this.getPublicState();
  }

  /**
   * Submit commitment during COMMIT phase.
   * Format: SHA-256(participantId || secret)
   */
  submitCommitment(participantId, commitmentHex) {
    if (this.state !== STATES.COMMIT) {
      throw new Error(`Commitments not accepted in state: ${this.state}`);
    }

    const participant = this.participants.get(participantId);
    if (!participant) {
      throw new Error('Participant not found');
    }

    if (participant.commitment !== null) {
      throw new Error('Commitment already submitted. Modifications are strictly forbidden.');
    }

    if (typeof commitmentHex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(commitmentHex)) {
      throw new Error('Invalid commitment format. Must be a 64-character SHA-256 hex string.');
    }

    participant.commitment = commitmentHex.toLowerCase();

    // Check if all active participants have submitted commitments
    const allCommitted = Array.from(this.participants.values()).every(
      (p) => p.commitment !== null
    );

    if (allCommitted) {
      this.lockCommitments();
    }

    return this.getPublicState();
  }

  /**
   * Transition from COMMIT to LOCKED, then immediately open REVEAL
   */
  lockCommitments() {
    if (this.state !== STATES.COMMIT) return;

    this.state = STATES.LOCKED;

    // Transition immediately to REVEAL after lock is established
    this.state = STATES.REVEAL;
  }

  /**
   * Submit secret reveal during REVEAL phase.
   */
  submitReveal(participantId, secretHex) {
    if (this.state !== STATES.REVEAL) {
      throw new Error(`Reveals are not accepted in state: ${this.state}`);
    }

    const participant = this.participants.get(participantId);
    if (!participant) {
      throw new Error('Participant not found');
    }

    if (participant.isRevealed) {
      throw new Error('Secret already revealed. Modifications are strictly forbidden.');
    }

    if (participant.commitment === null) {
      throw new Error('Cannot reveal: no commitment was provided during commit phase.');
    }

    const isValid = verifyCommitment(participant.id, secretHex, participant.commitment);

    participant.revealedSecret = secretHex;
    participant.isRevealed = true;
    participant.verified = isValid;

    if (!isValid) {
      participant.isAttacking = true;
      const expected = computeCommitment(participant.id, secretHex);
      this.attackLog.push({
        participantId: participant.id,
        participantName: participant.name,
        attemptedSecret: secretHex,
        expectedCommitment: expected,
        storedCommitment: participant.commitment,
        timestamp: new Date().toISOString(),
        message: 'Commitment verification failed. Reveal rejected.'
      });
    }

    this.checkAllRevealed();
    return this.getPublicState();
  }

  /**
   * Timeout non-revealed participants
   */
  handleTimeout() {
    if (this.state !== STATES.REVEAL) return;

    for (const p of this.participants.values()) {
      if (!p.isRevealed) {
        p.isTimeout = true;
        p.verified = false;
      }
    }

    this.finalizeSelection();
  }

  /**
   * Check if all participants have completed the reveal (or timed out)
   */
  checkAllRevealed() {
    const allDone = Array.from(this.participants.values()).every(
      (p) => p.isRevealed || p.isTimeout
    );

    if (allDone) {
      this.finalizeSelection();
    }
  }

  /**
   * Finalize selection:
   * 1. Collect all verified secrets
   * 2. Combine via XOR: R = R1 XOR R2 XOR ... XOR Rn
   * 3. Unbiased selection via rejection sampling
   */
  finalizeSelection() {
    const verifiedParticipants = Array.from(this.participants.values()).filter(
      (p) => p.verified === true && p.revealedSecret !== null
    );

    if (verifiedParticipants.length < 1) {
      this.state = STATES.ABORTED;
      this.result = {
        error: 'Protocol aborted: No valid reveals verified.',
        winner: null
      };
      return;
    }

    // Combine all valid secrets
    const validSecrets = verifiedParticipants.map((p) => p.revealedSecret);
    const combinedRandomnessBuffer = combineRandomness(validSecrets);
    const combinedRandomnessHex = combinedRandomnessBuffer.toString('hex');

    // Perform unbiased rejection sampling
    const selection = unbiasedSelect(combinedRandomnessBuffer, verifiedParticipants.length);

    const winner = verifiedParticipants[selection.index];

    this.state = STATES.COMPLETED;
    this.result = {
      combinedRandomness: combinedRandomnessHex,
      selectedIndex: selection.index,
      sampleValue: selection.sampleValue,
      rejections: selection.rejections,
      verifiedCount: verifiedParticipants.length,
      totalCount: this.participants.size,
      winner: {
        id: winner.id,
        name: winner.name
      },
      auditTrail: Array.from(this.participants.values()).map((p) => ({
        id: p.id,
        name: p.name,
        commitment: p.commitment,
        revealedSecret: p.revealedSecret,
        verified: p.verified,
        isTimeout: p.isTimeout,
        isAttacking: p.isAttacking
      }))
    };
  }

  /**
   * Public state visible to clients.
   * Strictly avoids leaking secrets before/during reveal.
   */
  getPublicState() {
    const participantsList = Array.from(this.participants.values()).map((p) => ({
      id: p.id,
      name: p.name,
      isHost: p.isHost,
      hasCommitted: p.commitment !== null,
      commitment: p.commitment,
      // Only show secret if revealed or protocol complete
      revealedSecret: p.isRevealed ? p.revealedSecret : null,
      verified: p.verified,
      isRevealed: p.isRevealed,
      isAttacking: p.isAttacking,
      isTimeout: p.isTimeout
    }));

    return {
      code: this.code,
      hostId: this.hostId,
      state: this.state,
      requiredParticipants: this.requiredParticipants,
      participantCount: this.participants.size,
      participants: participantsList,
      result: this.result,
      attackLog: this.attackLog
    };
  }
}

/**
 * In-memory room manager
 */
class RoomManager {
  constructor() {
    this.rooms = new Map();
  }

  createRoom(hostId, hostName, requiredParticipants) {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let code = '';
    do {
      code = '';
      for (let i = 0; i < 6; i++) {
        code += chars.charAt(Math.floor(Math.random() * chars.length));
      }
    } while (this.rooms.has(code));

    const room = new Room(code, hostId, hostName, requiredParticipants);
    this.rooms.set(code, room);
    return room;
  }

  getRoom(code) {
    if (!code) return null;
    return this.rooms.get(code.toUpperCase().trim()) || null;
  }

  deleteRoom(code) {
    this.rooms.delete(code);
  }
}

module.exports = {
  STATES,
  Room,
  RoomManager
};
