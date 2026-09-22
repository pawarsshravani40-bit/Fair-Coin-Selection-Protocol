/**
 * Fair Coin Selection Protocol — Client Application
 *
 * Utilizes:
 * - Web Crypto API for cryptographically secure randomness (crypto.getRandomValues)
 * - Web Crypto API for SHA-256 hash digest (crypto.subtle.digest)
 * - Native Browser WebSocket API for multi-party protocol synchronization
 */

class NativeWebSocket {
  constructor() {
    this.listeners = {};
    this.pendingRequests = {};
    this.requestCounter = 0;
    this.id = null;
    this.ws = null;
    this.reconnectTimer = null;
    this.queue = [];
    this.init();
  }

  init() {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${proto}//${location.host}/ws`;
    this.ws = new WebSocket(wsUrl);

    this.ws.onopen = () => {
      this._attemptAutoReconnectSession();
      while (this.queue.length > 0) {
        const item = this.queue.shift();
        this.ws.send(JSON.stringify(item));
      }
      this._fire('connect');
    };

    this.ws.onmessage = (evt) => {
      try {
        const msg = JSON.parse(evt.data);
        if (msg.type === 'response' || msg.type === 'ack') {
          const reqId = msg.requestId || msg.ackId;
          const cb = this.pendingRequests[reqId];
          if (cb) {
            delete this.pendingRequests[reqId];
            cb(msg.data || msg);
          }
        } else if (msg.type === 'event') {
          this._fire(msg.event, msg.data);
        } else if (msg.type === 'error') {
          showAlert(msg.error || 'Server error', 'danger');
        }
      } catch (e) {
        console.error('[WS parse error]', e);
      }
    };

    this.ws.onclose = () => {
      this._fire('disconnect');
      if (!this.reconnectTimer) {
        this.reconnectTimer = setTimeout(() => {
          this.reconnectTimer = null;
          this.init();
        }, 2000);
      }
    };

    this.ws.onerror = (err) => {
      console.warn('[WS connection error]', err);
    };
  }

  _attemptAutoReconnectSession() {
    const raw = sessionStorage.getItem('fair_coin_session');
    if (!raw) return;
    try {
      const sess = JSON.parse(raw);
      if (sess.roomCode && sess.participantId && sess.sessionToken) {
        this.emit('reconnect', {
          roomCode: sess.roomCode,
          participantId: sess.participantId,
          sessionToken: sess.sessionToken
        }, (response) => {
          if (response && response.success) {
            this.id = sess.participantId;
            state.participantId = sess.participantId;
            state.participantName = sess.participantName || '';
            state.isHost = !!sess.isHost;
            state.roomCode = sess.roomCode;
            state.sessionToken = sess.sessionToken;
            state.localSecret = sess.localSecret || null;
            state.localCommitment = sess.localCommitment || null;
            state.hasCommitted = !!sess.hasCommitted;
            state.hasRevealed = !!sess.hasRevealed;

            const badge = document.getElementById('clientIdentityBadge');
            if (badge) badge.textContent = `ID: ${state.participantId.slice(0, 8)}...`;
            if (state.localSecret) {
              const secDisp = document.getElementById('localSecretDisplay');
              if (secDisp) secDisp.textContent = state.localSecret;
            }
            if (state.localCommitment) {
              const commDisp = document.getElementById('localCommitmentDisplay');
              if (commDisp) commDisp.textContent = state.localCommitment;
            }
            if (state.hasCommitted) {
              const btn = document.getElementById('commitActionBtn');
              if (btn) btn.textContent = '✓ Commitment Submitted';
            }
            if (state.hasRevealed) {
              const btn = document.getElementById('revealActionBtn');
              if (btn) btn.textContent = '✓ Secret Verified';
            }

            if (response.room) {
              state.roomData = response.room;
              if (response.room.state === 'LOBBY') {
                updateLobbyUI(response.room);
                showGameView('lobby');
              } else {
                updateProtocolUI(response.room);
                showGameView('protocol');
              }
            }
            showAlert('Session restored 🔄', 'info', 3000);
          } else {
            sessionStorage.removeItem('fair_coin_session');
          }
        });
      }
    } catch (e) {
      sessionStorage.removeItem('fair_coin_session');
    }
  }

  on(event, callback) {
    if (!this.listeners[event]) this.listeners[event] = [];
    this.listeners[event].push(callback);
    if (event === 'connect' && this.ws && this.ws.readyState === WebSocket.OPEN) {
      setTimeout(() => callback(), 0);
    }
  }

  _fire(event, data) {
    const fns = this.listeners[event] || [];
    fns.forEach((fn) => {
      try { fn(data); } catch (e) { console.error(e); }
    });
  }

  emit(type, payload, callback) {
    let data = payload;
    let cb = callback;
    if (typeof payload === 'function') {
      cb = payload;
      data = {};
    }

    const reqId = 'req_' + (++this.requestCounter) + '_' + Math.random().toString(36).substring(2, 7);
    if (typeof cb === 'function') {
      this.pendingRequests[reqId] = cb;
    }

    const msg = {
      type: type,
      requestId: reqId,
      payload: data || {}
    };

    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(msg));
    } else {
      this.queue.push(msg);
    }
  }
}

// Initialize native WebSocket client
const socket = new NativeWebSocket();

// Local Client State
const state = {
  participantId: null,
  participantName: '',
  sessionToken: null,
  isHost: false,
  roomCode: null,
  roomData: null,
  localSecret: null,
  localCommitment: null,
  hasCommitted: false,
  hasRevealed: false
};

// Cryptographic Primitives (Web Crypto API)
function generateClientSecret() {
  const bytes = new Uint8Array(32);
  window.crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function computeClientCommitment(participantId, secret) {
  const enc = new TextEncoder();
  const data = enc.encode(String(participantId) + ':' + String(secret));
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Independently verifies the completed selection result against the public audit trail.
 * Does NOT trust any server-provided 'verified' flags or the declared winner.
 * Recomputes SHA-256 commitments, bitwise XOR entropy combination, and
 * rejection sampling from scratch using the Web Crypto API and BigInt arithmetic.
 *
 * @param {Array<Object>} auditTrail - Array of participant audit records
 * @param {Object} serverResult - The server's declared result object
 * @returns {Promise<Object>} Verification report with granular check results
 */
async function verifyAuditTrail(auditTrail, serverResult) {
  const HEX_64_REGEX = /^[0-9a-fA-F]{64}$/;

  if (!Array.isArray(auditTrail) || auditTrail.length < 2) {
    return {
      verified: false,
      checks: {},
      error: 'Invalid audit trail: minimum 2 participants required'
    };
  }
  if (!serverResult || typeof serverResult !== 'object') {
    return {
      verified: false,
      checks: {},
      error: 'Missing or invalid server result'
    };
  }

  let commitmentsPassed = 0;
  let commitmentsFailed = 0;
  let timeoutCount = 0;
  const participantVerifications = [];
  const verifiedParticipants = [];

  for (const p of auditTrail) {
    const pid = String(p.id || '');
    const comm = String(p.commitment || '');
    const sec = p.revealedSecret ? String(p.revealedSecret) : null;
    const isTimeout = Boolean(p.isTimeout);

    // 1. Commitment format validation
    if (!comm || !HEX_64_REGEX.test(comm)) {
      commitmentsFailed++;
      participantVerifications.push({
        id: pid,
        name: p.name,
        verified: false,
        reason: 'Invalid commitment format (must be 64 hex characters)'
      });
      continue;
    }

    // 2. Timeout / non-reveal handling
    if (isTimeout || !sec) {
      timeoutCount++;
      participantVerifications.push({
        id: pid,
        name: p.name,
        verified: false,
        reason: 'Participant timed out or did not reveal secret'
      });
      continue;
    }

    // 3. Secret format validation
    if (!HEX_64_REGEX.test(sec)) {
      commitmentsFailed++;
      participantVerifications.push({
        id: pid,
        name: p.name,
        verified: false,
        reason: 'Invalid revealed secret format (must be 64 hex characters)'
      });
      continue;
    }

    // 4. Cryptographic commitment verification: SHA-256(participantId + ":" + secret)
    const computedHash = await computeClientCommitment(pid, sec);
    if (computedHash.toLowerCase() === comm.toLowerCase()) {
      commitmentsPassed++;
      participantVerifications.push({
        id: pid,
        name: p.name,
        verified: true,
        computedCommitment: computedHash
      });
      verifiedParticipants.push({
        id: pid,
        name: p.name,
        secret: sec
      });
    } else {
      commitmentsFailed++;
      participantVerifications.push({
        id: pid,
        name: p.name,
        verified: false,
        reason: 'Commitment mismatch: preimage hash differs from locked commitment',
        computedCommitment: computedHash,
        storedCommitment: comm
      });
    }
  }

  const commitmentsValid = (commitmentsFailed === 0 && commitmentsPassed >= 2);

  // If fewer than 2 valid reveals, protocol must safely abort
  if (verifiedParticipants.length < 2) {
    const isAborted = (serverResult.winner === null || serverResult.winner === undefined) &&
      String(serverResult.error || '').toLowerCase().includes('aborted');
    return {
      verified: isAborted,
      isAborted: true,
      participantVerifications,
      checks: {
        commitments: {
          valid: commitmentsValid,
          passed: commitmentsPassed,
          total: auditTrail.length,
          failed: commitmentsFailed,
          timeouts: timeoutCount
        },
        reveals: {
          valid: commitmentsFailed === 0,
          validCount: verifiedParticipants.length,
          requiredCount: 2
        },
        entropy: { valid: true, computed: null, expected: null },
        selection: { valid: true, computedIndex: null, expectedIndex: null },
        winner: { valid: isAborted, computedWinner: null, expectedWinner: null }
      },
      error: isAborted ? null : 'Insufficient valid reveals (minimum 2 required) but protocol was not marked aborted'
    };
  }

  // 5. Entropy Reconstruction: SHA-256(S1) ^ SHA-256(S2) ^ ...
  const enc = new TextEncoder();
  const combined = new Uint8Array(32);

  for (const p of verifiedParticipants) {
    const sBytes = enc.encode(p.secret);
    const digest = await window.crypto.subtle.digest('SHA-256', sBytes);
    const digestArray = new Uint8Array(digest);
    for (let i = 0; i < 32; i++) {
      combined[i] ^= digestArray[i];
    }
  }

  const computedEntropyHex = Array.from(combined)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  const expectedEntropyHex = String(serverResult.combinedRandomness || '').toLowerCase();
  const entropyValid = (computedEntropyHex === expectedEntropyHex);

  // 6. Rejection Sampling using BigInt
  const MAX_UINT64 = 18446744073709551616n; // 2^64
  const n = BigInt(verifiedParticipants.length);
  const limit = MAX_UINT64 - (MAX_UINT64 % n);
  let curr = new Uint8Array(combined);
  let rejections = 0;
  let selectedIndex = -1;
  let sampleValueStr = '';

  while (true) {
    let val = 0n;
    for (let i = 0; i < 8; i++) {
      val = (val << 8n) | BigInt(curr[i]);
    }
    if (val < limit) {
      selectedIndex = Number(val % n);
      sampleValueStr = val.toString();
      break;
    }
    rejections++;
    const nextDigest = await window.crypto.subtle.digest('SHA-256', curr);
    curr = new Uint8Array(nextDigest);
  }

  const selectionValid = (
    selectedIndex === serverResult.selectedIndex &&
    sampleValueStr === String(serverResult.sampleValue) &&
    rejections === serverResult.rejections
  );

  // 7. Winner Validation
  const calculatedWinner = verifiedParticipants[selectedIndex];
  const expectedWinner = serverResult.winner;
  const winnerMatches = Boolean(
    expectedWinner &&
    calculatedWinner &&
    calculatedWinner.id === expectedWinner.id
  );

  const allPassed = commitmentsValid && entropyValid && selectionValid && winnerMatches;
  const failureReasons = [];
  if (!commitmentsValid) {
    failureReasons.push(`Commitment verification failed (${commitmentsFailed} invalid reveals)`);
  }
  if (!entropyValid) {
    failureReasons.push('Combined entropy mismatch (locally computed bitwise XOR differs from server declaration)');
  }
  if (!selectionValid) {
    failureReasons.push(`Selection calculation mismatch (computed index ${selectedIndex} with ${rejections} rejections vs server index ${serverResult.selectedIndex} with ${serverResult.rejections} rejections)`);
  }
  if (!winnerMatches) {
    failureReasons.push(`Winner identity mismatch: independently calculated winner ${calculatedWinner ? calculatedWinner.name : 'Unknown'} (${calculatedWinner ? calculatedWinner.id : ''}) differs from announced winner ${expectedWinner ? expectedWinner.name : 'None'} (${expectedWinner ? expectedWinner.id : ''})`);
  }

  return {
    verified: allPassed,
    isAborted: false,
    participantVerifications,
    checks: {
      commitments: {
        valid: commitmentsValid,
        passed: commitmentsPassed,
        total: auditTrail.length,
        failed: commitmentsFailed,
        timeouts: timeoutCount
      },
      reveals: {
        valid: commitmentsFailed === 0,
        validCount: verifiedParticipants.length,
        requiredCount: 2
      },
      entropy: {
        valid: entropyValid,
        computed: computedEntropyHex,
        expected: expectedEntropyHex
      },
      selection: {
        valid: selectionValid,
        computedIndex: selectedIndex,
        expectedIndex: serverResult.selectedIndex,
        computedSampleValue: sampleValueStr,
        expectedSampleValue: serverResult.sampleValue,
        computedRejections: rejections,
        expectedRejections: serverResult.rejections
      },
      winner: {
        valid: winnerMatches,
        computedWinner: calculatedWinner ? { id: calculatedWinner.id, name: calculatedWinner.name } : null,
        expectedWinner: expectedWinner
      }
    },
    error: allPassed ? null : failureReasons.join('; ')
  };
}

/**
 * Runs independent client verification on the finalized game result
 * and updates the verification UI elements accordingly.
 */
async function runIndependentVerification(result) {
  if (!result || !result.auditTrail) return;

  const box = document.getElementById('independentVerificationBox');
  const badge = document.getElementById('verificationStatusBadge');
  const errBox = document.getElementById('verificationErrorDetail');
  const checkComm = document.getElementById('vCheckCommitments');
  const checkRev = document.getElementById('vCheckReveals');
  const checkEnt = document.getElementById('vCheckEntropy');
  const checkSel = document.getElementById('vCheckSelection');
  const checkWin = document.getElementById('vCheckWinner');

  if (box) box.classList.remove('hidden');

  try {
    const report = await verifyAuditTrail(result.auditTrail, result);

    if (report.verified) {
      if (badge) {
        badge.className = 'status-badge verified';
        badge.textContent = '✓ VERIFIED BY BROWSER';
      }
      if (checkComm) {
        checkComm.className = 'check-item passed';
        checkComm.textContent = `✓ Commitments Verified (${report.checks.commitments.passed}/${report.checks.commitments.total} SHA-256 preimages valid)`;
      }
      if (checkRev) {
        checkRev.className = 'check-item passed';
        checkRev.textContent = `✓ Reveal Integrity Verified (All ${report.checks.reveals.validCount} reveals bound to commitments)`;
      }
      if (checkEnt) {
        checkEnt.className = 'check-item passed';
        checkEnt.textContent = '✓ Entropy Reconstruction Verified (Bitwise XOR matches)';
      }
      if (checkSel) {
        checkSel.className = 'check-item passed';
        checkSel.textContent = `✓ Rejection Sampling Verified (Zero-bias sampling index ${report.checks.selection.computedIndex}, ${report.checks.selection.computedRejections} rejections)`;
      }
      if (checkWin) {
        checkWin.className = 'check-item passed';
        checkWin.textContent = `✓ Winner Match Confirmed (${report.checks.winner.computedWinner ? report.checks.winner.computedWinner.name : 'Aborted safely'})`;
      }
      if (errBox) errBox.classList.add('hidden');
    } else {
      if (badge) {
        badge.className = 'status-badge attack';
        badge.textContent = '⚠ VERIFICATION FAILED';
      }
      if (checkComm) {
        checkComm.className = report.checks.commitments?.valid ? 'check-item passed' : 'check-item failed';
        checkComm.textContent = report.checks.commitments?.valid
          ? `✓ Commitments Verified (${report.checks.commitments.passed}/${report.checks.commitments.total})`
          : `❌ Commitment Mismatch (${report.checks.commitments?.failed || 0} failed)`;
      }
      if (checkRev) {
        checkRev.className = report.checks.reveals?.valid ? 'check-item passed' : 'check-item failed';
        checkRev.textContent = report.checks.reveals?.valid ? '✓ Reveal Integrity Verified' : '❌ Corrupted Reveal Detected';
      }
      if (checkEnt) {
        checkEnt.className = report.checks.entropy?.valid ? 'check-item passed' : 'check-item failed';
        checkEnt.textContent = report.checks.entropy?.valid ? '✓ Entropy Reconstructed' : '❌ Entropy Mismatch';
      }
      if (checkSel) {
        checkSel.className = report.checks.selection?.valid ? 'check-item passed' : 'check-item failed';
        checkSel.textContent = report.checks.selection?.valid ? '✓ Selection Verified' : '❌ Selection Calculation Discrepancy';
      }
      if (checkWin) {
        checkWin.className = report.checks.winner?.valid ? 'check-item passed' : 'check-item failed';
        checkWin.textContent = report.checks.winner?.valid ? '✓ Winner Matches' : '❌ Fraudulent Winner Declared';
      }
      if (errBox) {
        errBox.textContent = `⚠ Verification Failed: ${report.error || 'Cryptographic mismatch detected'}`;
        errBox.classList.remove('hidden');
      }
    }

    // Populate Audit Table with local verification column
    const auditTbody = document.getElementById('auditTableBody');
    if (auditTbody && report.participantVerifications) {
      auditTbody.innerHTML = '';
      report.participantVerifications.forEach((pv, idx) => {
        const item = result.auditTrail[idx] || {};
        const tr = document.createElement('tr');
        const vBadge = pv.verified
          ? '<span class="status-badge verified">✓ Verified locally</span>'
          : `<span class="status-badge attack">❌ ${escapeHtml(pv.reason || 'Failed')}</span>`;
        const sBadge = item.verified
          ? '<span class="status-badge verified">Server: Verified</span>'
          : '<span class="status-badge attack">Server: Rejected</span>';

        tr.innerHTML = `
          <td><strong>${escapeHtml(pv.name || item.name || pv.id)}</strong></td>
          <td><span class="hash-box" style="margin:0; padding:0.2rem; font-size:0.75rem;">${item.commitment || '—'}</span></td>
          <td><span class="hash-box" style="margin:0; padding:0.2rem; font-size:0.75rem;">${item.revealedSecret || '—'}</span></td>
          <td>${vBadge}</td>
          <td>${sBadge}</td>
        `;
        auditTbody.appendChild(tr);
      });
    }
  } catch (err) {
    if (badge) {
      badge.className = 'status-badge attack';
      badge.textContent = '⚠ ERROR';
    }
    if (errBox) {
      errBox.textContent = `Verification execution error: ${err.message}`;
      errBox.classList.remove('hidden');
    }
  }
}

// DOM Elements
const views = {
  home: document.getElementById('homeView'),
  create: document.getElementById('createView'),
  join: document.getElementById('joinView'),
  lobby: document.getElementById('lobbyView'),
  protocol: document.getElementById('protocolView'),
  fairness: document.getElementById('fairnessSection'),
  attack: document.getElementById('attackSection'),
  gameSection: document.getElementById('gameSection')
};

const nav = {
  game: document.getElementById('navGameBtn'),
  fairness: document.getElementById('navFairnessBtn'),
  attack: document.getElementById('navAttackBtn')
};

// UI Alerts
const alertBanner = document.getElementById('alertBanner');

function showAlert(message, type = 'info', timeoutMs = 6000) {
  alertBanner.className = `alert-banner ${type}`;
  alertBanner.textContent = message;
  alertBanner.classList.remove('hidden');

  if (timeoutMs > 0) {
    setTimeout(() => {
      alertBanner.classList.add('hidden');
    }, timeoutMs);
  }
}

// Navigation Tab Switching
function switchNav(activeNav) {
  [nav.game, nav.fairness, nav.attack].forEach((b) => b.classList.remove('active'));
  [views.gameSection, views.fairness, views.attack].forEach((v) => v.classList.add('hidden'));

  if (activeNav === 'game') {
    nav.game.classList.add('active');
    views.gameSection.classList.remove('hidden');
  } else if (activeNav === 'fairness') {
    nav.fairness.classList.add('active');
    views.fairness.classList.remove('hidden');
  } else if (activeNav === 'attack') {
    nav.attack.classList.add('active');
    views.attack.classList.remove('hidden');
    updateAttackSandboxHashes();
  }
}

nav.game.addEventListener('click', () => switchNav('game'));
nav.fairness.addEventListener('click', () => switchNav('fairness'));
nav.attack.addEventListener('click', () => switchNav('attack'));

// View Navigation within Game
function showGameView(viewKey) {
  [views.home, views.create, views.join, views.lobby, views.protocol].forEach((v) =>
    v.classList.add('hidden')
  );
  if (views[viewKey]) {
    views[viewKey].classList.remove('hidden');
  }
}

// Home Actions
document.getElementById('openCreateBtn').addEventListener('click', () => showGameView('create'));
document.getElementById('openJoinBtn').addEventListener('click', () => showGameView('join'));
document.getElementById('cancelCreateBtn').addEventListener('click', () => showGameView('home'));
document.getElementById('cancelJoinBtn').addEventListener('click', () => showGameView('home'));

// Create Game Range Slider Sync
const createRange = document.getElementById('createCountRange');
const createCountDisplay = document.getElementById('createCountDisplay');
createRange.addEventListener('input', (e) => {
  createCountDisplay.textContent = e.target.value;
});

// Create Room Submission
document.getElementById('submitCreateBtn').addEventListener('click', () => {
  const name = document.getElementById('createNameInput').value.trim() || 'Host';
  const participantsCount = parseInt(createRange.value, 10) || 3;

  socket.emit('create_room', { name, participantsCount }, (response) => {
    if (response.success) {
      state.participantId = response.participantId;
      state.participantName = name;
      state.sessionToken = response.sessionToken;
      state.isHost = true;
      state.roomCode = response.room.code;
      state.roomData = response.room;

      sessionStorage.setItem('fair_coin_session', JSON.stringify({
        roomCode: state.roomCode,
        participantId: state.participantId,
        participantName: name,
        sessionToken: state.sessionToken,
        isHost: true
      }));

      document.getElementById('clientIdentityBadge').textContent = `ID: ${state.participantId.slice(0, 8)}...`;
      updateLobbyUI(response.room);
      showGameView('lobby');
    } else {
      showAlert(response.error, 'danger');
    }
  });
});

// Join Room Submission
document.getElementById('submitJoinBtn').addEventListener('click', () => {
  const name = document.getElementById('joinNameInput').value.trim() || 'Guest';
  const code = document.getElementById('joinCodeInput').value.trim().toUpperCase();

  if (!code || code.length !== 6) {
    showAlert('Please enter a valid 6-character room code', 'danger');
    return;
  }

  socket.emit('join_room', { code, name }, (response) => {
    if (response.success) {
      state.participantId = response.participantId;
      state.participantName = name;
      state.sessionToken = response.sessionToken;
      state.isHost = false;
      state.roomCode = response.room.code;
      state.roomData = response.room;

      sessionStorage.setItem('fair_coin_session', JSON.stringify({
        roomCode: state.roomCode,
        participantId: state.participantId,
        participantName: name,
        sessionToken: state.sessionToken,
        isHost: false
      }));

      document.getElementById('clientIdentityBadge').textContent = `ID: ${state.participantId.slice(0, 8)}...`;
      updateLobbyUI(response.room);
      showGameView('lobby');
    } else {
      showAlert(response.error, 'danger');
    }
  });
});

// Copy Room Code Button
document.getElementById('copyCodeBtn').addEventListener('click', () => {
  if (state.roomCode) {
    navigator.clipboard.writeText(state.roomCode).then(() => {
      showAlert(`Room code ${state.roomCode} copied to clipboard!`, 'info', 3000);
    });
  }
});

// Host Start Selection
const startProtocolBtn = document.getElementById('startProtocolBtn');
startProtocolBtn.addEventListener('click', () => {
  socket.emit('start_protocol', (response) => {
    if (!response.success) {
      showAlert(response.error, 'danger');
    }
  });
});

// Add Bot Participant
const addBotBtn = document.getElementById('addBotBtn');
if (addBotBtn) {
  addBotBtn.addEventListener('click', () => {
    socket.emit('add_bot', (response) => {
      if (!response.success) {
        showAlert(response.error, 'danger');
      }
    });
  });
}

// Update Lobby UI
function updateLobbyUI(room) {
  document.getElementById('lobbyRoomCode').textContent = room.code;
  document.getElementById('lobbyCountDisplay').textContent = room.participantCount;
  document.getElementById('lobbyMaxDisplay').textContent = room.requiredParticipants;

  const rosterEl = document.getElementById('lobbyRoster');
  rosterEl.innerHTML = '';

  room.participants.forEach((p) => {
    const li = document.createElement('li');
    li.innerHTML = `
      <span>${escapeHtml(p.name)} ${p.id === state.participantId ? '<strong style="color:var(--accent-cyan)">(You)</strong>' : ''}</span>
      ${p.isHost ? '<span class="host-tag">HOST</span>' : ''}
    `;
    rosterEl.appendChild(li);
  });

  const waitingMsg = document.getElementById('lobbyWaitingMsg');
  if (state.isHost) {
    if (room.participantCount >= 3) {
      startProtocolBtn.classList.remove('hidden');
      waitingMsg.textContent = `Ready! ${room.participantCount} participants in lobby.`;
    } else {
      startProtocolBtn.classList.add('hidden');
      waitingMsg.textContent = `Need at least 3 participants to start (${room.participantCount} currently).`;
    }

    if (addBotBtn) {
      if (room.participantCount < room.requiredParticipants) {
        addBotBtn.classList.remove('hidden');
      } else {
        addBotBtn.classList.add('hidden');
      }
    }
  } else {
    startProtocolBtn.classList.add('hidden');
    if (addBotBtn) addBotBtn.classList.add('hidden');
    waitingMsg.textContent = `Waiting for host to start selection... (${room.participantCount}/${room.requiredParticipants} joined)`;
  }
}

// Generate & Submit Commitment
const commitActionBtn = document.getElementById('commitActionBtn');
commitActionBtn.addEventListener('click', async () => {
  commitActionBtn.disabled = true;

  // Generate 256-bit cryptographically secure secret locally
  state.localSecret = generateClientSecret();
  document.getElementById('localSecretDisplay').textContent = state.localSecret;

  // Compute SHA-256(participantId || secret) locally
  state.localCommitment = await computeClientCommitment(state.participantId, state.localSecret);
  document.getElementById('localCommitmentDisplay').textContent = state.localCommitment;

  // Submit only commitment to server
  socket.emit('submit_commitment', { commitment: state.localCommitment }, (response) => {
    if (response.success) {
      state.hasCommitted = true;
      commitActionBtn.textContent = '✓ Commitment Submitted';

      // Persist in session storage for refresh recovery
      try {
        const sess = JSON.parse(sessionStorage.getItem('fair_coin_session') || '{}');
        sess.localSecret = state.localSecret;
        sess.localCommitment = state.localCommitment;
        sess.hasCommitted = true;
        sessionStorage.setItem('fair_coin_session', JSON.stringify(sess));
      } catch (e) {}

      showAlert('Commitment submitted to server. Secret remains securely held in client memory.', 'info', 4000);
    } else {
      commitActionBtn.disabled = false;
      showAlert(response.error, 'danger');
    }
  });
});

// Submit Valid Reveal
const revealActionBtn = document.getElementById('revealActionBtn');
revealActionBtn.addEventListener('click', () => {
  if (!state.localSecret) {
    showAlert('No local secret available to reveal.', 'danger');
    return;
  }

  revealActionBtn.disabled = true;
  document.getElementById('attackDemoBtn').disabled = true;

  socket.emit('submit_reveal', { secret: state.localSecret }, (response) => {
    if (response.success) {
      state.hasRevealed = true;
      revealActionBtn.textContent = '✓ Secret Verified';

      try {
        const sess = JSON.parse(sessionStorage.getItem('fair_coin_session') || '{}');
        sess.hasRevealed = true;
        sessionStorage.setItem('fair_coin_session', JSON.stringify(sess));
      } catch (e) {}

      showAlert('Secret revealed and verified by server.', 'info', 4000);
    } else {
      revealActionBtn.disabled = false;
      document.getElementById('attackDemoBtn').disabled = false;
      showAlert(response.error, 'danger');
    }
  });
});

// Demonstrate Cheating Attack (Altered Secret)
const attackDemoBtn = document.getElementById('attackDemoBtn');
attackDemoBtn.addEventListener('click', () => {
  if (!state.localSecret) return;

  // Alter secret: change first 6 hex characters to '999999'
  const corrupted = '999999' + state.localSecret.slice(6);

  revealActionBtn.disabled = true;
  attackDemoBtn.disabled = true;

  socket.emit('simulate_attack', { corruptedSecret: corrupted }, (response) => {
    showAlert('Cheating attack submitted: server rejected altered secret.', 'danger', 6000);
  });
});

// Force Timeout Button
const forceTimeoutBtn = document.getElementById('forceTimeoutBtn');
if (forceTimeoutBtn) {
  forceTimeoutBtn.addEventListener('click', () => {
    socket.emit('force_timeout', (response) => {
      if (response && response.success) {
        showAlert('Timeout applied to non-revealing participants.', 'info');
      } else if (response && response.error) {
        showAlert(response.error, 'danger');
      }
    });
  });
}

// View Audit Details
const toggleAuditBtn = document.getElementById('toggleAuditBtn');
const auditDrawer = document.getElementById('auditDrawer');
toggleAuditBtn.addEventListener('click', () => {
  auditDrawer.classList.toggle('hidden');
  toggleAuditBtn.textContent = auditDrawer.classList.contains('hidden')
    ? 'View Cryptographic Audit Details'
    : 'Hide Cryptographic Audit Details';
});

// Play Again Button
document.getElementById('newGameBtn').addEventListener('click', () => {
  sessionStorage.removeItem('fair_coin_session');
  location.reload();
});

// Socket Event Handlers
socket.on('connect', () => {
  const badge = document.getElementById('clientIdentityBadge');
  if (badge) {
    badge.textContent = state.participantId
      ? `ID: ${state.participantId.slice(0, 8)}...`
      : 'Connected (Native WebSocket)';
  }
});

socket.on('room_updated', (room) => {
  state.roomData = room;

  if (room.state === 'LOBBY') {
    updateLobbyUI(room);
  } else {
    updateProtocolUI(room);
  }
});

socket.on('protocol_started', (room) => {
  state.roomData = room;
  showGameView('protocol');
  updateProtocolUI(room);
  showAlert('Protocol started! Commit Phase initiated.', 'info', 4000);
});

socket.on('commitments_locked', (room) => {
  state.roomData = room;
  const banner = document.getElementById('lockedBanner');
  if (banner) {
    banner.classList.remove('hidden');
    setTimeout(() => {
      banner.classList.add('hidden');
    }, 4000);
  }

  showAlert('All commitments received! Commitments locked 🔐. Entering Reveal Phase.', 'info', 5000);
  updateProtocolUI(room);
});

socket.on('attack_detected', (data) => {
  showAlert(`❌ ATTACK DETECTED: ${data.participantName} attempted an invalid reveal! Commitment verification failed. Reveal rejected.`, 'danger', 8000);
});

socket.on('winner_announced', (room) => {
  state.roomData = room;
  updateProtocolUI(room);
});

socket.on('protocol_aborted', (room) => {
  state.roomData = room;
  showAlert(room.result?.error || 'Protocol aborted: Insufficient valid reveals.', 'danger', 8000);
  updateProtocolUI(room);
});

// Update Protocol Runtime UI
function updateProtocolUI(room) {
  showGameView('protocol');

  // Update Stepper
  const steps = {
    COMMIT: document.getElementById('stepCommit'),
    LOCKED: document.getElementById('stepLock'),
    REVEAL: document.getElementById('stepReveal'),
    COMPLETED: document.getElementById('stepWinner')
  };

  Object.values(steps).forEach((s) => s.classList.remove('active', 'completed'));

  if (room.state === 'COMMIT') {
    steps.COMMIT.classList.add('active');
  } else if (room.state === 'LOCKED') {
    steps.COMMIT.classList.add('completed');
    steps.LOCKED.classList.add('active');
  } else if (room.state === 'REVEAL') {
    steps.COMMIT.classList.add('completed');
    steps.LOCKED.classList.add('completed');
    steps.REVEAL.classList.add('active');
  } else if (room.state === 'COMPLETED') {
    steps.COMMIT.classList.add('completed');
    steps.LOCKED.classList.add('completed');
    steps.REVEAL.classList.add('completed');
    steps.COMPLETED.classList.add('active');
  }

  // Update Table
  const tbody = document.getElementById('protocolTableBody');
  tbody.innerHTML = '';

  room.participants.forEach((p) => {
    const isMe = p.id === state.participantId;
    const tr = document.createElement('tr');

    let commitBadge = '<span class="status-badge waiting">⏳ Waiting</span>';
    if (p.hasCommitted) {
      commitBadge = '<span class="status-badge committed">✓ Committed</span>';
    }

    let secretBadge = '<span class="status-badge waiting">Hidden</span>';
    if (p.isRevealed) {
      secretBadge = '<span class="status-badge committed">Revealed</span>';
    } else if (p.isTimeout) {
      secretBadge = '<span class="status-badge timeout">Timed Out</span>';
    }

    let verifyBadge = '<span class="status-badge waiting">—</span>';
    if (p.verified === true) {
      verifyBadge = '<span class="status-badge verified">✓ Verified</span>';
    } else if (p.verified === false) {
      verifyBadge = '<span class="status-badge attack">❌ Invalid Reveal</span>';
    }

    tr.innerHTML = `
      <td><strong>${escapeHtml(p.name)}</strong> ${isMe ? '<span style="color:var(--accent-cyan); font-size:0.8rem;">(You)</span>' : ''}</td>
      <td>${p.isHost ? '<span class="host-tag">Host</span>' : '<span style="color:var(--text-muted)">Participant</span>'}</td>
      <td><span class="hash-box" style="margin:0; padding:0.2rem 0.4rem; font-size:0.75rem;">${p.commitment ? p.commitment.slice(0, 16) + '...' : 'Not submitted'}</span></td>
      <td>${secretBadge}</td>
      <td>${verifyBadge}</td>
    `;
    tbody.appendChild(tr);
  });

  // Local Controls visibility
  const commitControls = document.getElementById('commitControls');
  const revealControls = document.getElementById('revealControls');
  const timeoutControls = document.getElementById('timeoutControls');
  const winnerSection = document.getElementById('winnerSection');

  if (room.state === 'COMMIT') {
    commitControls.classList.remove('hidden');
    revealControls.classList.add('hidden');
    timeoutControls.classList.add('hidden');
    winnerSection.classList.add('hidden');
  } else if (room.state === 'REVEAL') {
    commitControls.classList.add('hidden');
    revealControls.classList.remove('hidden');
    timeoutControls.classList.add('hidden');
    winnerSection.classList.add('hidden');
  } else if (room.state === 'COMPLETED' || room.state === 'ABORTED') {
    commitControls.classList.add('hidden');
    revealControls.classList.add('hidden');
    timeoutControls.classList.add('hidden');

    if (room.state === 'ABORTED') {
      winnerSection.classList.remove('hidden');
      const crown = document.querySelector('.winner-crown');
      if (crown) crown.textContent = '⚠️';
      const title = document.querySelector('.winner-title');
      if (title) title.textContent = 'PROTOCOL ABORTED';
      document.getElementById('winnerNameDisplay').textContent = room.result?.error || 'Insufficient valid reveals (minimum 2 required).';
    } else if (room.result && room.result.winner) {
      winnerSection.classList.remove('hidden');
      const crown = document.querySelector('.winner-crown');
      if (crown) crown.textContent = '👑';
      const title = document.querySelector('.winner-title');
      if (title) title.textContent = '🎉 WINNER 🎉';
      document.getElementById('winnerNameDisplay').textContent = room.result.winner.name;
      document.getElementById('auditCombinedSeed').textContent = room.result.combinedRandomness;
      document.getElementById('auditSampleVal').textContent = room.result.sampleValue;
      document.getElementById('auditRejections').textContent = room.result.rejections;
      document.getElementById('auditIndex').textContent = `${room.result.selectedIndex} (${room.result.winner.name})`;
    }

    // Trigger independent client-side verification
    if (room.result) {
      runIndependentVerification(room.result);
    }
  }
}

// FAIRNESS SIMULATION LOGIC
const runSimBtn = document.getElementById('runSimBtn');
runSimBtn.addEventListener('click', async () => {
  const n = parseInt(document.getElementById('simNSelect').value, 10);
  const trials = parseInt(document.getElementById('simTrialsSelect').value, 10);

  runSimBtn.disabled = true;
  runSimBtn.textContent = 'Simulating...';

  try {
    const res = await fetch(`/api/simulate?n=${n}&trials=${trials}`);
    const data = await res.json();

    if (!res.ok) throw new Error(data.error);

    // Display Stats
    document.getElementById('simStatsRow').classList.remove('hidden');
    document.getElementById('simExpectedPct').textContent = `${data.expectedPercentage.toFixed(2)}%`;
    document.getElementById('simMaxDev').textContent = `±${data.maxDeviation.toFixed(3)}%`;
    document.getElementById('simChiSquare').textContent = data.chiSquare.toFixed(2);
    document.getElementById('simRejections').textContent = data.totalRejections;

    // Render Dynamic HTML/CSS Bar Chart
    const wrapper = document.getElementById('barsWrapper');
    wrapper.innerHTML = '';

    const maxPct = Math.max(...data.percentages, data.expectedPercentage) * 1.25;

    data.counts.forEach((count, idx) => {
      const pct = data.percentages[idx];
      const barWidth = (pct / maxPct) * 100;
      const expectedWidth = (data.expectedPercentage / maxPct) * 100;

      const row = document.createElement('div');
      row.className = 'bar-row';
      row.innerHTML = `
        <div class="bar-info">
          <span><strong>Participant ${idx + 1}</strong> (${count.toLocaleString()} wins)</span>
          <span><strong>${pct.toFixed(2)}%</strong> (Expected: ${data.expectedPercentage.toFixed(2)}%)</span>
        </div>
        <div class="bar-track">
          <div class="expected-line" style="left: ${expectedWidth}%;" title="Expected: ${data.expectedPercentage.toFixed(2)}%"></div>
          <div class="bar-fill" style="width: ${barWidth}%;"></div>
        </div>
      `;
      wrapper.appendChild(row);
    });
  } catch (err) {
    showAlert(`Simulation error: ${err.message}`, 'danger');
  } finally {
    runSimBtn.disabled = false;
    runSimBtn.textContent = 'Run Fairness Simulation';
  }
});

// ===========================================================================
// SECURITY LAB LOGIC (ISOLATED CLIENT EXPERIMENTS)
// ===========================================================================

// Security Lab Tab Switching
const labTabBtns = document.querySelectorAll('.lab-tab-btn');
const labPanes = document.querySelectorAll('.lab-pane');

labTabBtns.forEach((btn) => {
  btn.addEventListener('click', () => {
    labTabBtns.forEach((b) => b.classList.remove('active'));
    labPanes.forEach((p) => p.classList.add('hidden'));
    btn.classList.add('active');
    const targetId = btn.getAttribute('data-tab');
    const pane = document.getElementById(targetId);
    if (pane) pane.classList.remove('hidden');
    refreshSecurityLabPreviews();
  });
});

/**
 * Returns an isolated test vector for Security Lab experiments.
 * Never references or mutates state.roomData.
 */
async function getBaseLabTestVector() {
  const p1 = {
    id: 'usr_alice123',
    name: 'Alice',
    secret: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  };
  const p2 = {
    id: 'usr_bob456',
    name: 'Bob',
    secret: 'a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0'
  };
  const p3 = {
    id: 'usr_charlie789',
    name: 'Charlie',
    secret: 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210'
  };

  const comm1 = await computeClientCommitment(p1.id, p1.secret);
  const comm2 = await computeClientCommitment(p2.id, p2.secret);
  const comm3 = await computeClientCommitment(p3.id, p3.secret);

  const enc = new TextEncoder();
  const d1 = new Uint8Array(await window.crypto.subtle.digest('SHA-256', enc.encode(p1.secret)));
  const d2 = new Uint8Array(await window.crypto.subtle.digest('SHA-256', enc.encode(p2.secret)));
  const d3 = new Uint8Array(await window.crypto.subtle.digest('SHA-256', enc.encode(p3.secret)));

  const combined = new Uint8Array(32);
  for (let i = 0; i < 32; i++) combined[i] = d1[i] ^ d2[i] ^ d3[i];

  const combHex = Array.from(combined).map((b) => b.toString(16).padStart(2, '0')).join('');

  const MAX_UINT64 = 18446744073709551616n;
  const n = 3n;
  const limit = MAX_UINT64 - (MAX_UINT64 % n);
  let curr = new Uint8Array(combined);
  let rejections = 0;
  let selectedIndex = 0;
  let sampleValue = '0';

  while (true) {
    let val = 0n;
    for (let i = 0; i < 8; i++) val = (val << 8n) | BigInt(curr[i]);
    if (val < limit) {
      selectedIndex = Number(val % n);
      sampleValue = val.toString();
      break;
    }
    rejections++;
    curr = new Uint8Array(await window.crypto.subtle.digest('SHA-256', curr));
  }

  const participants = [
    { id: p1.id, name: p1.name, commitment: comm1, revealedSecret: p1.secret, verified: true, isTimeout: false, isAttacking: false },
    { id: p2.id, name: p2.name, commitment: comm2, revealedSecret: p2.secret, verified: true, isTimeout: false, isAttacking: false },
    { id: p3.id, name: p3.name, commitment: comm3, revealedSecret: p3.secret, verified: true, isTimeout: false, isAttacking: false }
  ];

  const winner = participants[selectedIndex];

  return {
    combinedRandomness: combHex,
    selectedIndex: selectedIndex,
    sampleValue: sampleValue,
    rejections: rejections,
    verifiedCount: 3,
    totalCount: 3,
    winner: { id: winner.id, name: winner.name },
    auditTrail: participants
  };
}

async function refreshSecurityLabPreviews() {
  const vector = await getBaseLabTestVector();

  // Exp A previews
  const labSecPid = document.getElementById('labSecPid');
  const labSecOriginal = document.getElementById('labSecOriginal');
  const labSecTampered = document.getElementById('labSecTampered');
  const labSecOriginalCommit = document.getElementById('labSecOriginalCommit');
  const labSecTamperedCommit = document.getElementById('labSecTamperedCommit');

  if (labSecPid && labSecOriginal && labSecOriginalCommit) {
    const origHash = await computeClientCommitment(labSecPid.value, labSecOriginal.value);
    labSecOriginalCommit.textContent = origHash;
  }
  if (labSecPid && labSecTampered && labSecTamperedCommit) {
    const tampHash = await computeClientCommitment(labSecPid.value, labSecTampered.value);
    labSecTamperedCommit.textContent = tampHash;
  }

  // Exp B previews
  const labCommPid = document.getElementById('labCommPid');
  const labCommSecret = document.getElementById('labCommSecret');
  const labCommRealHash = document.getElementById('labCommRealHash');
  if (labCommPid && labCommSecret && labCommRealHash) {
    const realHash = await computeClientCommitment(labCommPid.value, labCommSecret.value);
    labCommRealHash.textContent = realHash;
  }

  // Exp C previews
  const labIdOrigPid = document.getElementById('labIdOrigPid');
  const labIdTamperedPid = document.getElementById('labIdTamperedPid');
  const labIdSecret = document.getElementById('labIdSecret');
  const labIdOrigCommit = document.getElementById('labIdOrigCommit');
  const labIdTamperedCommit = document.getElementById('labIdTamperedCommit');
  if (labIdOrigPid && labIdSecret && labIdOrigCommit) {
    const origCommit = await computeClientCommitment(labIdOrigPid.value, labIdSecret.value);
    labIdOrigCommit.textContent = origCommit;
  }
  if (labIdTamperedPid && labIdSecret && labIdTamperedCommit) {
    const tampCommit = await computeClientCommitment(labIdTamperedPid.value, labIdSecret.value);
    labIdTamperedCommit.textContent = tampCommit;
  }

  // Exp D previews
  const legitWinnerEl = document.getElementById('labWinLegitWinner');
  const legitIndexEl = document.getElementById('labWinLegitIndex');
  if (legitWinnerEl && legitIndexEl) {
    legitWinnerEl.textContent = `${vector.winner.name} (${vector.winner.id})`;
    legitIndexEl.textContent = `${vector.selectedIndex}`;
  }
}

// Exp A: Secret Tampering Handlers
const labSecOriginalInput = document.getElementById('labSecOriginal');
const labSecTamperedInput = document.getElementById('labSecTampered');
if (labSecOriginalInput) labSecOriginalInput.addEventListener('input', refreshSecurityLabPreviews);
if (labSecTamperedInput) labSecTamperedInput.addEventListener('input', refreshSecurityLabPreviews);

const btnFlipSecretBit = document.getElementById('btnFlipSecretBit');
if (btnFlipSecretBit) {
  btnFlipSecretBit.addEventListener('click', () => {
    const inp = document.getElementById('labSecTampered');
    if (inp) {
      const cur = inp.value;
      inp.value = cur.startsWith('9') ? '8' + cur.slice(1) : '9' + cur.slice(1);
      refreshSecurityLabPreviews();
    }
  });
}

const btnVerifySecretTamper = document.getElementById('btnVerifySecretTamper');
if (btnVerifySecretTamper) {
  btnVerifySecretTamper.addEventListener('click', async () => {
    const vector = await getBaseLabTestVector();
    const pid = document.getElementById('labSecPid').value;
    const tamperedSec = document.getElementById('labSecTampered').value;

    vector.auditTrail[0].revealedSecret = tamperedSec;
    const report = await verifyAuditTrail(vector.auditTrail, vector);

    const resBox = document.getElementById('labSecResult');
    if (resBox) {
      resBox.classList.remove('hidden');
      const origCommit = await computeClientCommitment(pid, document.getElementById('labSecOriginal').value);
      const tampCommit = await computeClientCommitment(pid, tamperedSec);

      if (!report.verified) {
        resBox.innerHTML = `
          <div class="alert-box-danger">
            <h3>❌ ATTACK DETECTED / VERIFICATION FAILED</h3>
            <p><strong>Independent Verification Result:</strong> Commitment check failed.</p>
            <p>${escapeHtml(report.error || 'Preimage does not match stored hash')}</p>
            <div class="tamper-details">
              <div>Participant ID: <code>${escapeHtml(pid)}</code></div>
              <div>Expected Commitment: <code>${escapeHtml(origCommit)}</code></div>
              <div>Computed from Tampered Secret: <code>${escapeHtml(tampCommit)}</code></div>
              <div style="margin-top:0.5rem; color:var(--accent-amber);">Security Guarantee: Preimage resistance ensures an attacker cannot change their secret after commitments are locked.</div>
            </div>
          </div>
        `;
      } else {
        resBox.innerHTML = `<div class="alert-box-success"><h3>✓ Verification Passed</h3></div>`;
      }
    }
  });
}

// Exp B: Commitment Tampering Handlers
const btnCorruptCommitment = document.getElementById('btnCorruptCommitment');
if (btnCorruptCommitment) {
  btnCorruptCommitment.addEventListener('click', () => {
    const inp = document.getElementById('labCommTampered');
    if (inp) inp.value = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
  });
}

const btnVerifyCommTamper = document.getElementById('btnVerifyCommTamper');
if (btnVerifyCommTamper) {
  btnVerifyCommTamper.addEventListener('click', async () => {
    const vector = await getBaseLabTestVector();
    const tamperedComm = document.getElementById('labCommTampered').value;

    vector.auditTrail[1].commitment = tamperedComm;
    const report = await verifyAuditTrail(vector.auditTrail, vector);

    const resBox = document.getElementById('labCommResult');
    if (resBox) {
      resBox.classList.remove('hidden');
      const realHash = await computeClientCommitment(vector.auditTrail[1].id, vector.auditTrail[1].revealedSecret);

      if (!report.verified) {
        resBox.innerHTML = `
          <div class="alert-box-danger">
            <h3>❌ ATTACK DETECTED / VERIFICATION FAILED</h3>
            <p><strong>Independent Verification Result:</strong> Stored commitment mismatch.</p>
            <div class="tamper-details">
              <div>Real Preimage Hash: <code>${escapeHtml(realHash)}</code></div>
              <div>Tampered Stored Commitment: <code>${escapeHtml(tamperedComm)}</code></div>
              <div style="margin-top:0.5rem; color:var(--accent-amber);">Security Guarantee: Audit integrity ensures neither participants nor server can tamper with committed hashes without instant detection.</div>
            </div>
          </div>
        `;
      } else {
        resBox.innerHTML = `<div class="alert-box-success"><h3>✓ Verification Passed</h3></div>`;
      }
    }
  });
}

// Exp C: Participant-ID Tampering Handlers
const labIdOrigPidInput = document.getElementById('labIdOrigPid');
const labIdTamperedPidInput = document.getElementById('labIdTamperedPid');
const labIdSecretInput = document.getElementById('labIdSecret');
if (labIdOrigPidInput) labIdOrigPidInput.addEventListener('input', refreshSecurityLabPreviews);
if (labIdTamperedPidInput) labIdTamperedPidInput.addEventListener('input', refreshSecurityLabPreviews);
if (labIdSecretInput) labIdSecretInput.addEventListener('input', refreshSecurityLabPreviews);

const btnVerifyIdTamper = document.getElementById('btnVerifyIdTamper');
if (btnVerifyIdTamper) {
  btnVerifyIdTamper.addEventListener('click', async () => {
    const vector = await getBaseLabTestVector();
    const tamperedPid = document.getElementById('labIdTamperedPid').value;

    vector.auditTrail[2].id = tamperedPid;
    const report = await verifyAuditTrail(vector.auditTrail, vector);

    const resBox = document.getElementById('labIdResult');
    if (resBox) {
      resBox.classList.remove('hidden');
      const origPid = document.getElementById('labIdOrigPid').value;
      const secret = document.getElementById('labIdSecret').value;
      const origComm = await computeClientCommitment(origPid, secret);
      const tampComm = await computeClientCommitment(tamperedPid, secret);

      if (!report.verified) {
        resBox.innerHTML = `
          <div class="alert-box-danger">
            <h3>❌ ATTACK DETECTED / VERIFICATION FAILED</h3>
            <p><strong>Identity Binding Violation:</strong> Commitment verification failed for impersonated ID.</p>
            <div class="tamper-details">
              <div>Original ID Hash: <code>${escapeHtml(origComm)}</code></div>
              <div>Impersonator ID Hash: <code>${escapeHtml(tampComm)}</code></div>
              <div style="margin-top:0.5rem; color:var(--accent-amber);">Security Guarantee: SHA-256(Participant ID + ":" + Secret) binds the commitment to the sender's identity, preventing replay and impersonation attacks.</div>
            </div>
          </div>
        `;
      } else {
        resBox.innerHTML = `<div class="alert-box-success"><h3>✓ Verification Passed</h3></div>`;
      }
    }
  });
}

// Exp D: Winner Tampering Handlers
const btnVerifyWinnerTamper = document.getElementById('btnVerifyWinnerTamper');
if (btnVerifyWinnerTamper) {
  btnVerifyWinnerTamper.addEventListener('click', async () => {
    const vector = await getBaseLabTestVector();
    const fakeName = document.getElementById('labWinTamperedName').value;
    const fakeIdx = parseInt(document.getElementById('labWinTamperedIndex').value, 10);

    const originalWinner = vector.winner;
    const originalIndex = vector.selectedIndex;

    // Fraudulent announcement
    vector.winner = { id: 'usr_attacker', name: fakeName };
    vector.selectedIndex = fakeIdx;

    const report = await verifyAuditTrail(vector.auditTrail, vector);

    const resBox = document.getElementById('labWinResult');
    if (resBox) {
      resBox.classList.remove('hidden');
      if (!report.verified) {
        resBox.innerHTML = `
          <div class="alert-box-danger">
            <h3>❌ ATTACK DETECTED / VERIFICATION FAILED</h3>
            <p><strong>Fraudulent Winner Announcement Caught:</strong> Client selection recomputation disagrees with claimed result.</p>
            <div class="tamper-details">
              <div>Independently Calculated Winner: <code>${escapeHtml(originalWinner.name)} (Index ${originalIndex})</code></div>
              <div>Fraudulent Server Winner: <code>${escapeHtml(fakeName)} (Index ${fakeIdx})</code></div>
              <div style="margin-top:0.5rem; color:var(--accent-amber);">Security Guarantee: The client computes the winner independently from the verified entropy seed, rendering server-side outcome manipulation impossible.</div>
            </div>
          </div>
        `;
      } else {
        resBox.innerHTML = `<div class="alert-box-success"><h3>✓ Verification Passed</h3></div>`;
      }
    }
  });
}

// Exp E: Modulo Bias vs Rejection Sampling
const btnRunModuloCompare = document.getElementById('btnRunModuloCompare');
if (btnRunModuloCompare) {
  btnRunModuloCompare.addEventListener('click', () => {
    const domainSize = parseInt(document.getElementById('labModDomainSelect').value, 10);
    const n = 3;
    const limit = domainSize - (domainSize % n);

    // Run 1000 simulated uniform draws from [0, domainSize - 1]
    const naiveBuckets = [0, 0, 0];
    const rejectionBuckets = [0, 0, 0];
    let rejectionsTriggered = 0;

    for (let i = 0; i < 1000; i++) {
      const v = Math.floor(Math.random() * domainSize);
      naiveBuckets[v % n]++;

      if (v < limit) {
        rejectionBuckets[v % n]++;
      } else {
        rejectionsTriggered++;
        // Re-sample candidate until accepted
        let nextV = Math.floor(Math.random() * domainSize);
        while (nextV >= limit) {
          nextV = Math.floor(Math.random() * domainSize);
        }
        rejectionBuckets[nextV % n]++;
      }
    }

    const resRow = document.getElementById('labModResults');
    const logBox = document.getElementById('labModComparisonLog');
    if (resRow) resRow.classList.remove('hidden');
    if (logBox) logBox.classList.remove('hidden');

    document.getElementById('labModNaiveRejections').textContent = `0 (Unchecked)`;
    document.getElementById('labModLimit').textContent = `L = ${limit} (Discards values >= ${limit})`;
    document.getElementById('labModRejectionsTriggered').textContent = `${rejectionsTriggered} / 1000 draws`;

    if (logBox) {
      logBox.innerHTML = `
        <strong>Empirical Distribution over 1,000 Draws:</strong><br>
        • Naive Modulo (val % 3): Bucket 0: ${naiveBuckets[0]} (${(naiveBuckets[0]/10).toFixed(1)}%), Bucket 1: ${naiveBuckets[1]} (${(naiveBuckets[1]/10).toFixed(1)}%), Bucket 2: ${naiveBuckets[2]} (${(naiveBuckets[2]/10).toFixed(1)}%)<br>
        • Fair Pick Rejection Sampling: Bucket 0: ${rejectionBuckets[0]} (${(rejectionBuckets[0]/10).toFixed(1)}%), Bucket 1: ${rejectionBuckets[1]} (${(rejectionBuckets[1]/10).toFixed(1)}%), Bucket 2: ${rejectionBuckets[2]} (${(rejectionBuckets[2]/10).toFixed(1)}%)<br>
        <br>
        <em>Theoretical Note: In the naive approach, remainder values in [0, ${domainSize % n - 1}] have probability ${(Math.ceil(domainSize/n) / domainSize * 100).toFixed(2)}%, while higher buckets have ${(Math.floor(domainSize/n) / domainSize * 100).toFixed(2)}%. Rejection sampling eliminates this difference.</em>
      `;
    }
  });
}

// Initialize Security Lab previews on startup
setTimeout(refreshSecurityLabPreviews, 500);

// Utility
function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
