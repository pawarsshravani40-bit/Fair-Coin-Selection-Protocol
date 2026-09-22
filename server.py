"""
Fair Coin Selection Protocol — Python Backend Server

A zero-npm, zero-Node replacement for running the Fair Coin Selection Protocol.
Powered by Python standard library cryptography and FastAPI / Uvicorn.
"""

import asyncio
import os
import sys
import json
import secrets
import hashlib
import hmac
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Set

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
import uvicorn

# Protocol Constants
MAX_UINT64 = 18446744073709551616  # 2^64
HEX_64_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")
REVEAL_TIMEOUT_SECONDS = 25.0
STATES = {
    "LOBBY": "LOBBY",
    "COMMIT": "COMMIT",
    "LOCKED": "LOCKED",
    "REVEAL": "REVEAL",
    "REVEAL_CLOSED": "REVEAL_CLOSED",
    "COMPLETED": "COMPLETED",
    "ABORTED": "ABORTED",
}

# ---------------------------------------------------------------------------
# Cryptographic Core (Hardened)
# ---------------------------------------------------------------------------

def generate_secret() -> str:
    """Generate a 256-bit cryptographically secure random secret (64 hex characters)."""
    return secrets.token_hex(32)

def compute_commitment(participant_id: str, secret: str) -> str:
    """Compute SHA-256 commitment: H = SHA-256(participantId || ':' || secret)"""
    if not participant_id or not secret:
        raise ValueError("participant_id and secret are required")
    data = f"{participant_id}:{secret}".encode("utf-8")
    return hashlib.sha256(data).hexdigest()

def verify_commitment(participant_id: str, secret: str, commitment: str) -> bool:
    """Timing-safe commitment verification."""
    if not participant_id or not secret or not commitment:
        return False
    try:
        computed = compute_commitment(participant_id, secret)
        return hmac.compare_digest(computed.lower(), str(commitment).lower())
    except Exception:
        return False

def combine_randomness(secret_list: List[str]) -> bytes:
    """
    Combine secrets using bitwise XOR:
    R = SHA-256(S1) XOR SHA-256(S2) XOR ... XOR SHA-256(Sn)
    """
    if not secret_list:
        raise ValueError("At least one secret is required to combine randomness")
    result = bytearray(32)
    for s in secret_list:
        s_hash = hashlib.sha256(str(s).encode("utf-8")).digest()
        for i in range(32):
            result[i] ^= s_hash[i]
    return bytes(result)

def unbiased_select(seed_bytes: bytes, n: int) -> dict:
    """
    Rejection sampling to eliminate modulo bias.
    Range: [0, 2^64 - 1]
    Limit L = 2^64 - (2^64 % n)
    """
    if n < 2:
        raise ValueError("Participant count n must be an integer >= 2")
    limit = MAX_UINT64 - (MAX_UINT64 % n)
    curr = bytes(seed_bytes)
    rejections = 0

    while True:
        val = int.from_bytes(curr[:8], byteorder="big", signed=False)
        if val < limit:
            return {
                "index": int(val % n),
                "rejections": rejections,
                "finalSeedHex": curr.hex(),
                "sampleValue": str(val),
            }
        rejections += 1
        curr = hashlib.sha256(curr).digest()


# ---------------------------------------------------------------------------
# Room & Protocol State Manager (Identical to Node protocol.js)
# ---------------------------------------------------------------------------

class Participant:
    def __init__(self, pid: str, name: str, is_host: bool = False, is_bot: bool = False):
        self.id = pid
        self.name = name
        self.is_host = is_host
        self.is_bot = is_bot
        self.commitment: Optional[str] = None
        self.revealed_secret: Optional[str] = None
        self.verified: Optional[bool] = None
        self.is_revealed = False
        self.is_attacking = False
        self.is_timeout = False
        self.session_token: str = secrets.token_hex(32)
        self.connected: bool = True
        # Secret held locally (bots generate and keep it in memory)
        self.bot_secret: Optional[str] = None

class Room:
    def __init__(self, code: str, host_id: str, host_name: str, required_participants: int = 3, reveal_duration_seconds: float = REVEAL_TIMEOUT_SECONDS):
        self.code = code
        self.host_id = host_id
        self.required_participants = max(3, min(20, required_participants or 3))
        self.state = STATES["LOBBY"]
        self.created_at = time.time()
        self.last_active = time.time()
        self.locked_at: Optional[float] = None
        self.reveal_deadline: Optional[float] = None
        self.reveal_duration_seconds = float(reveal_duration_seconds)
        self.participants: Dict[str, Participant] = {}
        self.result: Optional[dict] = None
        self.attack_log: List[dict] = []
        self._is_finalizing: bool = False

        # Add host
        clean_name = str(host_name).strip()[:30] or "Host"
        self.participants[host_id] = Participant(host_id, clean_name, is_host=True)

    def verify_session(self, pid: str, session_token: str) -> Optional[Participant]:
        """Timing-safe session verification for secure reconnection."""
        p = self.participants.get(pid)
        if not p:
            return None
        if not hmac.compare_digest(p.session_token, str(session_token).strip()):
            return None
        p.connected = True
        self.last_active = time.time()
        return p

    def add_participant(self, pid: str, name: str, is_bot: bool = False) -> Participant:
        if self.state != STATES["LOBBY"]:
            raise ValueError(f"Cannot join room: game is in {self.state} phase")
        if len(self.participants) >= self.required_participants:
            raise ValueError(f"Room is full ({self.required_participants} maximum)")
        if pid in self.participants:
            raise ValueError("Participant ID already in room")

        clean_name = str(name).strip()[:30] or f"Participant {len(self.participants) + 1}"
        p = Participant(pid, clean_name, is_bot=is_bot)
        self.participants[pid] = p
        self.last_active = time.time()
        return p

    def remove_participant(self, pid: str) -> bool:
        self.last_active = time.time()
        if self.state == STATES["LOBBY"]:
            if pid in self.participants:
                del self.participants[pid]
                return True
            return False
        # In COMMIT, LOCKED, REVEAL, etc.: committed participant set remains fixed
        return True

    def start_protocol(self, requester_id: str) -> dict:
        if requester_id != self.host_id:
            raise ValueError("Only the host can start the selection")
        if self.state != STATES["LOBBY"]:
            raise ValueError(f"Protocol already started ({self.state})")
        if len(self.participants) < 3:
            raise ValueError("At least 3 participants are required to start")

        self.state = STATES["COMMIT"]
        self.last_active = time.time()
        return self.get_public_state()

    def submit_commitment(self, pid: str, commitment_hex: str) -> dict:
        if self.state != STATES["COMMIT"]:
            raise ValueError(f"Commitments not accepted in state: {self.state}")
        p = self.participants.get(pid)
        if not p:
            raise ValueError("Participant not found")
        if p.commitment is not None:
            raise ValueError("Commitment already submitted. Modifications forbidden.")

        comm_clean = str(commitment_hex).strip().lower()
        if not HEX_64_REGEX.match(comm_clean):
            raise ValueError("Invalid commitment format: must be 64 hex characters")

        p.commitment = comm_clean
        self.last_active = time.time()

        if all(part.commitment is not None for part in self.participants.values()):
            self.lock_commitments()

        return self.get_public_state()

    def lock_commitments(self):
        """Permanent protocol boundary: seals all commitments and prevents any modifications."""
        if self.state != STATES["COMMIT"]:
            return
        self.state = STATES["LOCKED"]
        self.locked_at = time.time()
        self.last_active = time.time()

    def open_reveal_phase(self, duration_seconds: Optional[float] = None) -> dict:
        """Opens the private reveal phase with an authoritative server deadline."""
        if self.state != STATES["LOCKED"]:
            raise ValueError(f"Cannot open reveal phase from state: {self.state}")
        self.state = STATES["REVEAL"]
        duration = float(duration_seconds) if duration_seconds is not None else self.reveal_duration_seconds
        self.reveal_deadline = time.time() + duration
        self.last_active = time.time()
        return self.get_public_state()

    def submit_reveal(self, pid: str, secret_hex: str) -> dict:
        if self.state != STATES["REVEAL"]:
            raise ValueError(f"Reveals not accepted in state: {self.state}")

        # Authoritative server deadline enforcement
        if self.reveal_deadline and time.time() > self.reveal_deadline:
            self.close_reveal_and_finalize()
            raise ValueError("Reveal deadline has expired")

        p = self.participants.get(pid)
        if not p:
            raise ValueError("Participant not found")
        if p.is_revealed:
            raise ValueError("Secret already revealed. Second reveal is strictly forbidden.")
        if p.commitment is None:
            raise ValueError("No commitment was submitted")

        secret_clean = str(secret_hex).strip().lower()
        if not HEX_64_REGEX.match(secret_clean):
            raise ValueError("Invalid secret format: must be 64 hex characters")

        is_valid = verify_commitment(p.id, secret_clean, p.commitment)
        p.revealed_secret = secret_clean
        p.is_revealed = True
        p.verified = is_valid
        self.last_active = time.time()

        if not is_valid:
            p.is_attacking = True
            expected = compute_commitment(p.id, secret_clean)
            self.attack_log.append({
                "participantId": p.id,
                "participantName": p.name,
                "attemptedSecret": secret_clean,
                "expectedCommitment": expected,
                "storedCommitment": p.commitment,
                "message": "Commitment verification failed. Reveal rejected."
            })

        # If all participants have submitted reveals, finalize immediately
        if all(part.is_revealed for part in self.participants.values()):
            self.close_reveal_and_finalize()

        return self.get_public_state()

    def close_reveal_and_finalize(self):
        """Authoritative closure: marks timeouts, determines valid reveals, and performs synchronized disclosure."""
        if self._is_finalizing or self.state in (STATES["COMPLETED"], STATES["ABORTED"]):
            return
        self._is_finalizing = True
        self.state = STATES["REVEAL_CLOSED"]
        self.last_active = time.time()

        # Handle non-revealing participants deterministically
        for p in self.participants.values():
            if not p.is_revealed:
                p.is_timeout = True
                p.verified = False

        # Gather validly verified reveals
        verified = [
            p for p in self.participants.values()
            if p.verified is True and p.revealed_secret is not None
        ]

        # Handle insufficient reveals safely without crashing
        if len(verified) < 2:
            self.state = STATES["ABORTED"]
            self.result = {
                "error": "Protocol aborted: Insufficient valid reveals (minimum 2 required).",
                "winner": None,
                "verifiedCount": len(verified),
                "totalCount": len(self.participants),
                "auditTrail": [
                    {
                        "id": p.id,
                        "name": p.name,
                        "commitment": p.commitment,
                        "revealedSecret": p.revealed_secret,
                        "verified": p.verified,
                        "isTimeout": p.is_timeout,
                        "isAttacking": p.is_attacking,
                    }
                    for p in self.participants.values()
                ],
            }
            self._is_finalizing = False
            return

        # Perform selection strictly after reveal closure
        valid_secrets = [p.revealed_secret for p in verified]
        combined_buffer = combine_randomness(valid_secrets)
        selection = unbiased_select(combined_buffer, len(verified))
        winner = verified[selection["index"]]

        self.state = STATES["COMPLETED"]
        self.result = {
            "combinedRandomness": combined_buffer.hex(),
            "selectedIndex": selection["index"],
            "sampleValue": selection["sampleValue"],
            "rejections": selection["rejections"],
            "verifiedCount": len(verified),
            "totalCount": len(self.participants),
            "winner": {
                "id": winner.id,
                "name": winner.name,
            },
            "auditTrail": [
                {
                    "id": p.id,
                    "name": p.name,
                    "commitment": p.commitment,
                    "revealedSecret": p.revealed_secret,
                    "verified": p.verified,
                    "isTimeout": p.is_timeout,
                    "isAttacking": p.is_attacking,
                }
                for p in self.participants.values()
            ],
        }
        self._is_finalizing = False

    def handle_timeout(self):
        """Authoritative timeout: only allows closure if deadline has expired."""
        if self.state != STATES["REVEAL"]:
            return
        if self.reveal_deadline and time.time() < self.reveal_deadline:
            raise ValueError("Cannot force timeout: reveal deadline has not expired")
        self.close_reveal_and_finalize()

    def get_public_state(self) -> dict:
        self.last_active = time.time()
        is_finalized = self.state in (STATES["COMPLETED"], STATES["ABORTED"])
        return {
            "code": self.code,
            "hostId": self.host_id,
            "state": self.state,
            "requiredParticipants": self.required_participants,
            "participantCount": len(self.participants),
            "revealDeadline": self.reveal_deadline,
            "participants": [
                {
                    "id": p.id,
                    "name": p.name,
                    "isHost": p.is_host,
                    "hasCommitted": p.commitment is not None,
                    "commitment": p.commitment,
                    # PRIVATE REVEAL: Do NOT leak secrets until protocol is COMPLETED / ABORTED
                    "revealedSecret": p.revealed_secret if is_finalized else None,
                    "verified": p.verified if is_finalized else None,
                    "isRevealed": p.is_revealed,
                    "isAttacking": p.is_attacking if is_finalized else False,
                    "isTimeout": p.is_timeout,
                    "connected": p.connected,
                }
                for p in self.participants.values()
            ],
            "result": self.result if is_finalized else None,
            "attackLog": self.attack_log if is_finalized else [],
        }

class RoomManager:
    def __init__(self, max_idle_seconds: int = 3600):
        self.rooms: Dict[str, Room] = {}
        self.max_idle_seconds = max_idle_seconds

    def cleanup_stale_rooms(self):
        """Remove rooms that have been inactive longer than max_idle_seconds."""
        now = time.time()
        stale_codes = [
            code for code, room in self.rooms.items()
            if (now - room.last_active) > self.max_idle_seconds
        ]
        for code in stale_codes:
            self.delete_room(code)

    def create_room(self, host_id: str, host_name: str, required_participants: int, reveal_duration_seconds: float = REVEAL_TIMEOUT_SECONDS) -> Room:
        self.cleanup_stale_rooms()
        clean_name = str(host_name).strip()[:30] or "Host"
        try:
            count = int(required_participants)
        except (ValueError, TypeError):
            count = 3
        count = max(3, min(20, count))

        chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        while True:
            code = "".join(secrets.choice(chars) for _ in range(6))
            if code not in self.rooms:
                break
        room = Room(code, host_id, clean_name, count, reveal_duration_seconds=reveal_duration_seconds)
        self.rooms[code] = room
        return room

    def get_room(self, code: Optional[str]) -> Optional[Room]:
        if not code:
            return None
        self.cleanup_stale_rooms()
        c = str(code).strip().upper()
        room = self.rooms.get(c)
        if room:
            room.last_active = time.time()
        return room

    def delete_room(self, code: str):
        c = str(code).upper().strip()
        self.rooms.pop(c, None)
        room_subscribers.pop(c, None)


# ---------------------------------------------------------------------------
# FastAPI Application & Socket.IO Mock Adapter
# ---------------------------------------------------------------------------

app = FastAPI(title="Fair Coin Selection Protocol")
room_manager = RoomManager()

# Map WebSocket -> client_id & room_code
ws_clients: Dict[WebSocket, str] = {}
client_rooms: Dict[str, str] = {}
room_subscribers: Dict[str, Set[WebSocket]] = {}
MAX_MESSAGE_SIZE = 65536  # 64 KB message size limit

async def send_response(ws: WebSocket, request_id: Optional[str], success: bool, data: Optional[dict] = None, error: Optional[str] = None):
    """Send a structured JSON response to a specific WebSocket connection."""
    resp: Dict[str, Any] = {
        "type": "response",
        "success": success
    }
    if request_id is not None:
        resp["requestId"] = request_id
        resp["ackId"] = request_id  # compatibility
    if success:
        resp["data"] = data or {}
    else:
        err_str = str(error or "Unknown error")
        resp["error"] = err_str
        resp["data"] = {"success": False, "error": err_str}
    await ws.send_text(json.dumps(resp))

@app.get("/api/simulate")
async def simulate(
    n: int = Query(5, ge=2, le=20),
    trials: int = Query(10000, ge=100, le=100000)
):
    counts = [0] * n
    total_rejections = 0

    for _ in range(trials):
        sec_list = [generate_secret() for _ in range(n)]
        comb = combine_randomness(sec_list)
        sel = unbiased_select(comb, n)
        counts[sel["index"]] += 1
        total_rejections += sel["rejections"]

    expected_count = trials / n
    expected_pct = 100.0 / n
    percentages = [(c / trials) * 100.0 for c in counts]

    chi_sq = sum(((c - expected_count) ** 2) / expected_count for c in counts)
    max_dev = max(abs(p - expected_pct) for p in percentages)

    return JSONResponse({
        "n": n,
        "trials": trials,
        "counts": counts,
        "percentages": [round(p, 3) for p in percentages],
        "expectedPercentage": round(expected_pct, 3),
        "chiSquare": round(chi_sq, 3),
        "maxDeviation": round(max_dev, 3),
        "totalRejections": total_rejections,
    })


async def broadcast_to_room(room_code: str, event: str, data: dict):
    """Send an event to all clients currently connected to the room."""
    subs = room_subscribers.get(room_code, set())
    message = json.dumps({"type": "event", "event": event, "data": data})
    dead = []
    for ws in list(subs):
        try:
            await ws.send_text(message)
        except Exception:
            dead.append(ws)
    for ws in dead:
        subs.discard(ws)

def process_bots_commit(room: Room):
    """Auto-generate commitments for bot participants."""
    for p in room.participants.values():
        if p.is_bot and p.commitment is None:
            p.bot_secret = generate_secret()
            commitment = compute_commitment(p.id, p.bot_secret)
            room.submit_commitment(p.id, commitment)

def process_bots_reveal(room: Room):
    """Auto-submit reveals for bot participants."""
    for p in room.participants.values():
        if p.is_bot and not p.is_revealed and p.bot_secret:
            room.submit_reveal(p.id, p.bot_secret)

async def schedule_reveal_timer(room_code: str, duration: float):
    """Authoritative background timer to close the reveal phase upon deadline expiry."""
    await asyncio.sleep(duration)
    room = room_manager.get_room(room_code)
    if not room:
        return
    if room.state == STATES["REVEAL"]:
        room.close_reveal_and_finalize()
        state = room.get_public_state()
        if room.state == STATES["COMPLETED"]:
            await broadcast_to_room(room.code, "winner_announced", state)
        elif room.state == STATES["ABORTED"]:
            await broadcast_to_room(room.code, "protocol_aborted", state)
        await broadcast_to_room(room.code, "room_updated", state)


VALID_ACTIONS = {
    "create_room", "join_room", "reconnect", "start_protocol",
    "add_bot", "submit_commitment", "submit_reveal",
    "simulate_attack", "force_timeout", "handshake"
}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    client_id: Optional[str] = None
    current_room_code: Optional[str] = None

    try:
        while True:
            text = await websocket.receive_text()
            if len(text) > MAX_MESSAGE_SIZE:
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "error": "Payload exceeds maximum allowed size"
                }))
                continue

            try:
                msg = json.loads(text)
            except Exception:
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "error": "Malformed JSON message"
                }))
                continue

            if not isinstance(msg, dict):
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "error": "Message must be a JSON object"
                }))
                continue

            raw_type = msg.get("type")
            if raw_type == "emit":
                action = msg.get("event")
            else:
                action = raw_type

            if not action or not isinstance(action, str):
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "error": "Missing or invalid message type"
                }))
                continue

            request_id = msg.get("requestId") or msg.get("ackId")

            if isinstance(msg.get("payload"), dict):
                payload = msg.get("payload")
            elif isinstance(msg.get("data"), dict):
                payload = msg.get("data")
            else:
                payload = {}

            if action not in VALID_ACTIONS:
                await send_response(websocket, request_id, False, error=f"Unknown message type: {action}")
                continue

            # Handshake (compatibility)
            if action == "handshake":
                client_id = payload.get("id") or msg.get("id") or f"client_{secrets.token_hex(4)}"
                ws_clients[websocket] = client_id
                await websocket.send_text(json.dumps({"type": "handshake_ack", "id": client_id}))
                continue

            # 1. CREATE ROOM
            if action == "create_room":
                raw_name = str(payload.get("name", "Host")).strip()
                name = raw_name[:30] if raw_name else "Host"
                try:
                    count = int(payload.get("participantsCount", 3))
                except (ValueError, TypeError):
                    count = 3
                count = max(3, min(20, count))

                if not client_id:
                    client_id = f"usr_{secrets.token_hex(6)}"

                room = room_manager.create_room(client_id, name, count)
                current_room_code = room.code
                client_rooms[client_id] = room.code

                if room.code not in room_subscribers:
                    room_subscribers[room.code] = set()
                room_subscribers[room.code].add(websocket)

                p = room.participants[client_id]
                state = room.get_public_state()

                await send_response(websocket, request_id, True, {
                    "room": state,
                    "participantId": client_id,
                    "sessionToken": p.session_token
                })
                await broadcast_to_room(room.code, "room_updated", state)
                continue

            # 2. JOIN ROOM
            elif action == "join_room":
                raw_code = str(payload.get("code", "")).strip().upper()
                raw_name = str(payload.get("name", "Guest")).strip()
                name = raw_name[:30] if raw_name else "Guest"

                if len(raw_code) != 6 or not raw_code.isalnum():
                    await send_response(websocket, request_id, False, error="Invalid room code format (must be 6 alphanumeric characters)")
                    continue

                room = room_manager.get_room(raw_code)
                if not room:
                    await send_response(websocket, request_id, False, error="Room not found")
                    continue

                try:
                    if not client_id or client_id in room.participants:
                        client_id = f"usr_{secrets.token_hex(6)}"

                    p = room.add_participant(client_id, name)
                    current_room_code = room.code
                    client_rooms[client_id] = room.code

                    if room.code not in room_subscribers:
                        room_subscribers[room.code] = set()
                    room_subscribers[room.code].add(websocket)

                    state = room.get_public_state()
                    await send_response(websocket, request_id, True, {
                        "room": state,
                        "participantId": client_id,
                        "sessionToken": p.session_token
                    })
                    await broadcast_to_room(room.code, "room_updated", state)
                    continue
                except Exception as e:
                    await send_response(websocket, request_id, False, error=str(e))
                    continue

            # 3. RECONNECT / SESSION RECOVERY
            elif action == "reconnect":
                raw_code = str(payload.get("roomCode", "")).strip().upper()
                req_pid = str(payload.get("participantId", "")).strip()
                req_token = str(payload.get("sessionToken", "")).strip()

                if len(raw_code) != 6 or not raw_code.isalnum():
                    await send_response(websocket, request_id, False, error="Invalid room code format")
                    continue
                if not req_pid or not req_token:
                    await send_response(websocket, request_id, False, error="participantId and sessionToken are required for reconnection")
                    continue

                room = room_manager.get_room(raw_code)
                if not room:
                    await send_response(websocket, request_id, False, error="Room not found or session expired")
                    continue

                p = room.verify_session(req_pid, req_token)
                if not p:
                    await send_response(websocket, request_id, False, error="Invalid session credential: authentication failed")
                    continue

                if current_room_code and current_room_code in room_subscribers:
                    room_subscribers[current_room_code].discard(websocket)

                client_id = p.id
                current_room_code = room.code
                ws_clients[websocket] = client_id
                client_rooms[client_id] = room.code

                if room.code not in room_subscribers:
                    room_subscribers[room.code] = set()
                room_subscribers[room.code].add(websocket)

                state = room.get_public_state()
                await send_response(websocket, request_id, True, {
                    "room": state,
                    "participantId": p.id,
                    "sessionToken": p.session_token
                })
                await broadcast_to_room(room.code, "room_updated", state)
                continue

            # Common validation for room-scoped actions
            room = room_manager.get_room(current_room_code)
            if not room:
                await send_response(websocket, request_id, False, error="Not in a room")
                continue
            if not client_id or client_id not in room.participants:
                await send_response(websocket, request_id, False, error="Unauthorized: participant not in room")
                continue

            # 4. ADD BOT
            if action == "add_bot":
                try:
                    bot_idx = len(room.participants) + 1
                    bot_id = f"bot_{secrets.token_hex(4)}"
                    bot_names = ["Bob (Bot)", "Charlie (Bot)", "Diana (Bot)", "Edward (Bot)"]
                    b_name = bot_names[(bot_idx - 2) % len(bot_names)]
                    room.add_participant(bot_id, b_name, is_bot=True)
                    state = room.get_public_state()
                    await send_response(websocket, request_id, True, {"room": state})
                    await broadcast_to_room(room.code, "room_updated", state)
                    continue
                except Exception as e:
                    await send_response(websocket, request_id, False, error=str(e))
                    continue

            # 5. START PROTOCOL
            elif action == "start_protocol":
                try:
                    state = room.start_protocol(client_id)
                    process_bots_commit(room)
                    state = room.get_public_state()
                    await send_response(websocket, request_id, True, {"room": state})
                    await broadcast_to_room(room.code, "protocol_started", state)
                    await broadcast_to_room(room.code, "room_updated", state)
                    continue
                except Exception as e:
                    await send_response(websocket, request_id, False, error=str(e))
                    continue

            # 6. SUBMIT COMMITMENT
            elif action == "submit_commitment":
                try:
                    comm = str(payload.get("commitment", "")).strip().lower()
                    if not HEX_64_REGEX.match(comm):
                        raise ValueError("Invalid commitment format: must be 64 hex characters")

                    prev_state = room.state
                    state = room.submit_commitment(client_id, comm)
                    process_bots_commit(room)
                    state = room.get_public_state()

                    await send_response(websocket, request_id, True, {"success": True})

                    if prev_state == STATES["COMMIT"] and room.state == STATES["LOCKED"]:
                        await broadcast_to_room(room.code, "commitments_locked", state)
                        room.open_reveal_phase()
                        asyncio.create_task(schedule_reveal_timer(room.code, room.reveal_duration_seconds))
                        process_bots_reveal(room)
                        state = room.get_public_state()

                        if room.state == STATES["COMPLETED"]:
                            await broadcast_to_room(room.code, "winner_announced", state)
                        elif room.state == STATES["ABORTED"]:
                            await broadcast_to_room(room.code, "protocol_aborted", state)

                    await broadcast_to_room(room.code, "room_updated", state)
                    continue
                except Exception as e:
                    await send_response(websocket, request_id, False, error=str(e))
                    continue

            # 7. SUBMIT REVEAL
            elif action == "submit_reveal":
                try:
                    sec = str(payload.get("secret", "")).strip().lower()
                    if not HEX_64_REGEX.match(sec):
                        raise ValueError("Invalid secret format: must be 64 hex characters")

                    state = room.submit_reveal(client_id, sec)
                    p = room.participants.get(client_id)

                    await send_response(websocket, request_id, True, {
                        "success": True,
                        "verified": p.verified if p else False
                    })

                    process_bots_reveal(room)
                    state = room.get_public_state()

                    if room.state == STATES["COMPLETED"]:
                        await broadcast_to_room(room.code, "winner_announced", state)
                    elif room.state == STATES["ABORTED"]:
                        await broadcast_to_room(room.code, "protocol_aborted", state)

                    await broadcast_to_room(room.code, "room_updated", state)
                    continue
                except Exception as e:
                    await send_response(websocket, request_id, False, error=str(e))
                    continue

            # 8. SIMULATE ATTACK
            elif action == "simulate_attack":
                try:
                    corrupted = str(payload.get("corruptedSecret", "")).strip().lower()
                    if not HEX_64_REGEX.match(corrupted):
                        raise ValueError("Corrupted secret must be 64 hex characters")

                    state = room.submit_reveal(client_id, corrupted)
                    p = room.participants.get(client_id)

                    await send_response(websocket, request_id, True, {
                        "success": True,
                        "verified": False,
                        "attackDetected": True
                    })

                    process_bots_reveal(room)
                    state = room.get_public_state()

                    if room.state == STATES["COMPLETED"]:
                        await broadcast_to_room(room.code, "winner_announced", state)
                    elif room.state == STATES["ABORTED"]:
                        await broadcast_to_room(room.code, "protocol_aborted", state)

                    await broadcast_to_room(room.code, "room_updated", state)
                    continue
                except Exception as e:
                    await send_response(websocket, request_id, False, error=str(e))
                    continue

            # 9. FORCE TIMEOUT
            elif action == "force_timeout":
                try:
                    room.handle_timeout()
                    state = room.get_public_state()
                    await send_response(websocket, request_id, True, {"success": True})
                    if room.state == STATES["COMPLETED"]:
                        await broadcast_to_room(room.code, "winner_announced", state)
                    elif room.state == STATES["ABORTED"]:
                        await broadcast_to_room(room.code, "protocol_aborted", state)
                    await broadcast_to_room(room.code, "room_updated", state)
                    continue
                except Exception as e:
                    await send_response(websocket, request_id, False, error=str(e))
                    continue

    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"[WS Error]: {e}", file=sys.stderr)
    finally:
        ws_clients.pop(websocket, None)
        if current_room_code and current_room_code in room_subscribers:
            room_subscribers[current_room_code].discard(websocket)
            room = room_manager.get_room(current_room_code)
            if room and client_id:
                p = room.participants.get(client_id)
                if p:
                    p.connected = False
                if room.state == STATES["LOBBY"]:
                    room.remove_participant(client_id)
                    human_count = sum(1 for part in room.participants.values() if not part.is_bot and part.connected)
                    if human_count == 0:
                        room_manager.delete_room(current_room_code)
                    else:
                        state = room.get_public_state()
                        await broadcast_to_room(room.code, "room_updated", state)
                else:
                    state = room.get_public_state()
                    await broadcast_to_room(room.code, "room_updated", state)
                    if room.state == STATES["COMPLETED"]:
                        await broadcast_to_room(room.code, "winner_announced", state)
                    elif room.state == STATES["ABORTED"]:
                        await broadcast_to_room(room.code, "protocol_aborted", state)


# ---------------------------------------------------------------------------
# Mount Static Files (public directory)
# ---------------------------------------------------------------------------

public_dir = Path(__file__).parent / "public"
if public_dir.exists():
    app.mount("/", StaticFiles(directory=str(public_dir), html=True), name="public")

# ---------------------------------------------------------------------------
# Direct Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 3000))
    print(f"\n=======================================================")
    print(f"  FAIR COIN SELECTION PROTOCOL (Python Backend)")
    print(f"  Server running at: http://localhost:{port}")
    print(f"  Press Ctrl+C to stop the server")
    print(f"=======================================================\n")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
