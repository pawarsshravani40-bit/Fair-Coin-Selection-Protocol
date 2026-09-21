const path = require('path');
const http = require('http');
const express = require('express');
const { Server } = require('socket.io');

const { RoomManager, STATES } = require('./protocol');
const { generateSecret, computeCommitment, combineRandomness, unbiasedSelect } = require('./crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*'
  }
});

const PORT = process.env.PORT || 3000;
const roomManager = new RoomManager();

// Serve static frontend files
app.use(express.static(path.join(__dirname, '..', 'public')));
app.use(express.json());

// API endpoint to run automated fairness simulations
app.get('/api/simulate', (req, res) => {
  try {
    const n = parseInt(req.query.n, 10) || 5;
    const trials = parseInt(req.query.trials, 10) || 10000;

    if (n < 2 || n > 20) {
      return res.status(400).json({ error: 'Participant count n must be between 2 and 20' });
    }
    if (trials < 100 || trials > 100000) {
      return res.status(400).json({ error: 'Trials must be between 100 and 100,000' });
    }

    const counts = new Array(n).fill(0);
    let totalRejections = 0;

    for (let t = 0; t < trials; t++) {
      // Simulate n participant contributions
      const secrets = [];
      for (let i = 0; i < n; i++) {
        secrets.push(generateSecret());
      }
      const combined = combineRandomness(secrets);
      const sel = unbiasedSelect(combined, n);
      counts[sel.index]++;
      totalRejections += sel.rejections;
    }

    const expectedCount = trials / n;
    const expectedPercentage = 100 / n;
    const percentages = counts.map((c) => (c / trials) * 100);

    // Compute Chi-Square statistic
    let chiSquare = 0;
    for (let i = 0; i < n; i++) {
      chiSquare += Math.pow(counts[i] - expectedCount, 2) / expectedCount;
    }

    const maxDeviation = Math.max(...percentages.map((p) => Math.abs(p - expectedPercentage)));

    res.json({
      n,
      trials,
      counts,
      percentages: percentages.map((p) => Number(p.toFixed(3))),
      expectedPercentage: Number(expectedPercentage.toFixed(3)),
      chiSquare: Number(chiSquare.toFixed(3)),
      maxDeviation: Number(maxDeviation.toFixed(3)),
      totalRejections
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Socket.IO real-time event handlers
io.on('connection', (socket) => {
  let currentRoomCode = null;

  // 1. Create Room
  socket.on('create_room', ({ name, participantsCount }, callback) => {
    try {
      const count = parseInt(participantsCount, 10) || 3;
      const room = roomManager.createRoom(socket.id, name || 'Host', count);
      currentRoomCode = room.code;
      socket.join(room.code);

      const state = room.getPublicState();
      if (typeof callback === 'function') {
        callback({ success: true, room: state, participantId: socket.id });
      }
      io.to(room.code).emit('room_updated', state);
    } catch (err) {
      if (typeof callback === 'function') {
        callback({ success: false, error: err.message });
      }
    }
  });

  // 2. Join Room
  socket.on('join_room', ({ code, name }, callback) => {
    try {
      const room = roomManager.getRoom(code);
      if (!room) {
        throw new Error('Room not found');
      }

      room.addParticipant(socket.id, name);
      currentRoomCode = room.code;
      socket.join(room.code);

      const state = room.getPublicState();
      if (typeof callback === 'function') {
        callback({ success: true, room: state, participantId: socket.id });
      }
      io.to(room.code).emit('room_updated', state);
    } catch (err) {
      if (typeof callback === 'function') {
        callback({ success: false, error: err.message });
      }
    }
  });

  // 3. Start Protocol (Host only)
  socket.on('start_protocol', (callback) => {
    try {
      const room = roomManager.getRoom(currentRoomCode);
      if (!room) throw new Error('Not in a room');

      const state = room.startProtocol(socket.id);
      io.to(room.code).emit('protocol_started', state);
      io.to(room.code).emit('room_updated', state);

      if (typeof callback === 'function') {
        callback({ success: true });
      }
    } catch (err) {
      if (typeof callback === 'function') {
        callback({ success: false, error: err.message });
      }
    }
  });

  // 4. Submit Commitment
  socket.on('submit_commitment', ({ commitment }, callback) => {
    try {
      const room = roomManager.getRoom(currentRoomCode);
      if (!room) throw new Error('Not in a room');

      const prevState = room.state;
      const state = room.submitCommitment(socket.id, commitment);

      if (prevState === STATES.COMMIT && room.state === STATES.REVEAL) {
        io.to(room.code).emit('commitments_locked', state);
      }

      io.to(room.code).emit('room_updated', state);
      if (typeof callback === 'function') {
        callback({ success: true });
      }
    } catch (err) {
      if (typeof callback === 'function') {
        callback({ success: false, error: err.message });
      }
    }
  });

  // 5. Submit Reveal
  socket.on('submit_reveal', ({ secret }, callback) => {
    try {
      const room = roomManager.getRoom(currentRoomCode);
      if (!room) throw new Error('Not in a room');

      const state = room.submitReveal(socket.id, secret);

      const participant = room.participants.get(socket.id);
      if (participant && !participant.verified) {
        io.to(room.code).emit('attack_detected', {
          participantId: socket.id,
          participantName: participant.name,
          message: 'Commitment verification failed! Reveal rejected.'
        });
      }

      if (room.state === STATES.COMPLETED) {
        io.to(room.code).emit('winner_announced', state);
      }

      io.to(room.code).emit('room_updated', state);
      if (typeof callback === 'function') {
        callback({ success: true, verified: participant ? participant.verified : false });
      }
    } catch (err) {
      if (typeof callback === 'function') {
        callback({ success: false, error: err.message });
      }
    }
  });

  // 6. Demonstrate Cheating / Attack
  socket.on('simulate_attack', ({ corruptedSecret }, callback) => {
    try {
      const room = roomManager.getRoom(currentRoomCode);
      if (!room) throw new Error('Not in a room');

      const state = room.submitReveal(socket.id, corruptedSecret);
      const participant = room.participants.get(socket.id);

      io.to(room.code).emit('attack_detected', {
        participantId: socket.id,
        participantName: participant.name,
        attemptedSecret: corruptedSecret,
        storedCommitment: participant.commitment,
        message: 'Commitment verification failed. Reveal rejected.'
      });

      if (room.state === STATES.COMPLETED) {
        io.to(room.code).emit('winner_announced', state);
      }

      io.to(room.code).emit('room_updated', state);
      if (typeof callback === 'function') {
        callback({ success: true, verified: false, attackDetected: true });
      }
    } catch (err) {
      if (typeof callback === 'function') {
        callback({ success: false, error: err.message });
      }
    }
  });

  // 7. Force Timeout (Non-revealing participants)
  socket.on('force_timeout', (callback) => {
    try {
      const room = roomManager.getRoom(currentRoomCode);
      if (!room) throw new Error('Not in a room');

      room.handleTimeout();
      const state = room.getPublicState();

      if (room.state === STATES.COMPLETED) {
        io.to(room.code).emit('winner_announced', state);
      }

      io.to(room.code).emit('room_updated', state);
      if (typeof callback === 'function') {
        callback({ success: true });
      }
    } catch (err) {
      if (typeof callback === 'function') {
        callback({ success: false, error: err.message });
      }
    }
  });

  // 8. Disconnect
  socket.on('disconnect', () => {
    if (currentRoomCode) {
      const room = roomManager.getRoom(currentRoomCode);
      if (room) {
        room.removeParticipant(socket.id);
        const state = room.getPublicState();
        io.to(room.code).emit('room_updated', state);
        if (room.state === STATES.COMPLETED) {
          io.to(room.code).emit('winner_announced', state);
        }
      }
    }
  });
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`Fair Coin Selection Protocol Server running at http://localhost:${PORT}`);
  });
}

module.exports = { app, server, roomManager };
