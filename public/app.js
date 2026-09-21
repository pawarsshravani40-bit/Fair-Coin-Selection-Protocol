/**
 * Fair Coin Selection Protocol — Client Application
 *
 * Utilizes:
 * - Web Crypto API for cryptographically secure randomness (crypto.getRandomValues)
 * - Web Crypto API for SHA-256 hash digest (crypto.subtle.digest)
 * - Socket.IO for real-time multi-party protocol synchronization
 */

// Initialize Socket.IO connection
const socket = io();

// Local Client State
const state = {
  participantId: null,
  participantName: '',
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
  const data = enc.encode(String(participantId) + String(secret));
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
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
      state.isHost = true;
      state.roomCode = response.room.code;
      state.roomData = response.room;

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
      state.isHost = false;
      state.roomCode = response.room.code;
      state.roomData = response.room;

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
  } else {
    startProtocolBtn.classList.add('hidden');
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
forceTimeoutBtn.addEventListener('click', () => {
  socket.emit('force_timeout', (response) => {
    if (response.success) {
      showAlert('Timeout applied to non-revealing participants.', 'info');
    }
  });
});

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
  location.reload();
});

// Socket Event Handlers
socket.on('connect', () => {
  state.participantId = socket.id;
  document.getElementById('clientIdentityBadge').textContent = `Socket ID: ${socket.id.slice(0, 8)}...`;
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
  banner.classList.remove('hidden');

  showAlert('All commitments received! Commitments locked 🔐. Entering Reveal Phase.', 'info', 5000);

  setTimeout(() => {
    banner.classList.add('hidden');
  }, 4000);

  updateProtocolUI(room);
});

socket.on('attack_detected', (data) => {
  showAlert(`❌ ATTACK DETECTED: ${data.participantName} attempted an invalid reveal! Commitment verification failed. Reveal rejected.`, 'danger', 8000);
});

socket.on('winner_announced', (room) => {
  state.roomData = room;
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
    timeoutControls.classList.remove('hidden');
    winnerSection.classList.add('hidden');
  } else if (room.state === 'COMPLETED') {
    commitControls.classList.add('hidden');
    revealControls.classList.add('hidden');
    timeoutControls.classList.add('hidden');
    winnerSection.classList.remove('hidden');

    // Populate Winner
    if (room.result && room.result.winner) {
      document.getElementById('winnerNameDisplay').textContent = room.result.winner.name;
      document.getElementById('auditCombinedSeed').textContent = room.result.combinedRandomness;
      document.getElementById('auditSampleVal').textContent = room.result.sampleValue;
      document.getElementById('auditRejections').textContent = room.result.rejections;
      document.getElementById('auditIndex').textContent = `${room.result.selectedIndex} (${room.result.winner.name})`;

      // Populate Audit Table
      const auditTbody = document.getElementById('auditTableBody');
      auditTbody.innerHTML = '';
      room.result.auditTrail.forEach((item) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><strong>${escapeHtml(item.name)}</strong></td>
          <td><span class="hash-box" style="margin:0; padding:0.2rem; font-size:0.75rem;">${item.commitment || '—'}</span></td>
          <td><span class="hash-box" style="margin:0; padding:0.2rem; font-size:0.75rem;">${item.revealedSecret || '—'}</span></td>
          <td>${item.verified ? '<span class="status-badge verified">✓ Verified</span>' : '<span class="status-badge attack">❌ Rejected</span>'}</td>
        `;
        auditTbody.appendChild(tr);
      });
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

// ATTACK SANDBOX LOGIC
async function updateAttackSandboxHashes() {
  const origSecret = document.getElementById('demoOriginalSecret').value;
  const tampSecret = document.getElementById('demoTamperedSecret').value;

  const origCommit = await computeClientCommitment('attacker-id', origSecret);
  const tampCommit = await computeClientCommitment('attacker-id', tampSecret);

  document.getElementById('demoOriginalCommitment').textContent = origCommit;
  document.getElementById('demoTamperedCommitment').textContent = tampCommit;
}

document.getElementById('demoOriginalSecret').addEventListener('input', updateAttackSandboxHashes);
document.getElementById('demoTamperedSecret').addEventListener('input', updateAttackSandboxHashes);

document.getElementById('testTamperBtn').addEventListener('click', async () => {
  const origSecret = document.getElementById('demoOriginalSecret').value;
  const tampSecret = document.getElementById('demoTamperedSecret').value;

  const origCommit = await computeClientCommitment('attacker-id', origSecret);
  const tampCommit = await computeClientCommitment('attacker-id', tampSecret);

  const resultBox = document.getElementById('tamperResultBox');
  document.getElementById('tamperExpected').textContent = origCommit;
  document.getElementById('tamperStored').textContent = tampCommit;
  resultBox.classList.remove('hidden');
});

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
