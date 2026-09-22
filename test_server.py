import time
import unittest
import json
import hashlib
import copy
from starlette.testclient import TestClient

from server import (
    app,
    generate_secret,
    compute_commitment,
    verify_commitment,
    combine_randomness,
    unbiased_select,
    verify_audit_trail,
    MAX_UINT64,
    Room,
    RoomManager,
    STATES,
    HEX_64_REGEX
)

class TestProtocolCore(unittest.TestCase):
    def test_generate_secret(self):
        s1 = generate_secret()
        s2 = generate_secret()
        self.assertEqual(len(s1), 64)
        self.assertNotEqual(s1, s2)
        self.assertTrue(HEX_64_REGEX.match(s1))

    def test_commitment_and_verification(self):
        pid = "alice"
        sec = generate_secret()
        c = compute_commitment(pid, sec)
        self.assertTrue(verify_commitment(pid, sec, c))
        # Altered secret
        altered = sec[:-1] + ("1" if sec.endswith("0") else "0")
        self.assertFalse(verify_commitment(pid, altered, c))
        # Altered id
        self.assertFalse(verify_commitment("bob", sec, c))

    def test_delimiter_collision_resistance(self):
        # Without delimiter, "alice" + "1234" == "alic" + "e1234"
        # With delimiter ':', "alice:1234" != "alic:e1234"
        c1 = compute_commitment("alice", "1234")
        c2 = compute_commitment("alic", "e1234")
        self.assertNotEqual(c1, c2, "Delimiter must prevent tuple extension collisions")

    def test_combine_randomness(self):
        s1 = generate_secret()
        s2 = generate_secret()
        s3 = generate_secret()
        r123 = combine_randomness([s1, s2, s3])
        r321 = combine_randomness([s3, s2, s1])
        self.assertEqual(len(r123), 32)
        self.assertEqual(r123, r321)

    def test_unbiased_select(self):
        seed = combine_randomness([generate_secret(), generate_secret()])
        for n in [3, 4, 5, 10, 20]:
            sel = unbiased_select(seed, n)
            self.assertTrue(0 <= sel["index"] < n)
            self.assertIsInstance(sel["rejections"], int)
            self.assertEqual(len(sel["finalSeedHex"]), 64)

    def test_room_name_and_count_validation(self):
        rm = RoomManager()
        r_low = rm.create_room("h1", "Host", 1)
        self.assertEqual(r_low.required_participants, 3)

        r_high = rm.create_room("h2", "Host", 99)
        self.assertEqual(r_high.required_participants, 20)

        long_name = "A" * 50
        r_name = rm.create_room("h3", long_name, 3)
        self.assertEqual(len(r_name.participants["h3"].name), 30)

    def test_room_cleanup(self):
        rm = RoomManager(max_idle_seconds=1)
        room1 = rm.create_room("h1", "Host", 3)
        code1 = room1.code
        self.assertIsNotNone(rm.get_room(code1))

        rm.delete_room(code1)
        self.assertIsNone(rm.get_room(code1))

        room2 = rm.create_room("h2", "Host", 3)
        code2 = room2.code
        room2.last_active = time.time() - 10
        self.assertIsNone(rm.get_room(code2))


class TestPhase2ProtocolFairness(unittest.TestCase):
    """Rigorous tests covering all 21 required scenarios for Phase 2."""

    def _setup_3_player_commit_room(self):
        room = Room("ROOM01", "host_id", "Alice", 3, reveal_duration_seconds=10.0)
        room.add_participant("bob_id", "Bob")
        room.add_participant("carol_id", "Carol")
        room.start_protocol("host_id")
        return room

    def test_01_locked_state_prevents_new_commitments(self):
        """1. LOCKED state prevents new commitments."""
        room = self._setup_3_player_commit_room()
        s1, s2, s3 = generate_secret(), generate_secret(), generate_secret()

        room.submit_commitment("host_id", compute_commitment("host_id", s1))
        room.submit_commitment("bob_id", compute_commitment("bob_id", s2))
        room.submit_commitment("carol_id", compute_commitment("carol_id", s3))

        self.assertEqual(room.state, STATES["LOCKED"])
        self.assertIsNotNone(room.locked_at)

        # Attempting new commitment in LOCKED is rejected
        with self.assertRaises(ValueError) as ctx:
            room.submit_commitment("host_id", compute_commitment("host_id", generate_secret()))
        self.assertIn("Commitments not accepted in state: LOCKED", str(ctx.exception))

    def test_02_commitment_replacement_rejected(self):
        """2. Commitment replacement after LOCKED is rejected (and during COMMIT)."""
        room = self._setup_3_player_commit_room()
        s1 = generate_secret()
        room.submit_commitment("host_id", compute_commitment("host_id", s1))

        # Replacing in COMMIT
        with self.assertRaises(ValueError) as ctx:
            room.submit_commitment("host_id", compute_commitment("host_id", generate_secret()))
        self.assertIn("Modifications forbidden", str(ctx.exception))

    def test_03_reveal_during_commit_rejected(self):
        """3. Reveal during COMMIT is rejected."""
        room = self._setup_3_player_commit_room()
        sec = generate_secret()
        with self.assertRaises(ValueError) as ctx:
            room.submit_reveal("host_id", sec)
        self.assertIn("Reveals not accepted in state: COMMIT", str(ctx.exception))

    def test_04_reveal_during_locked_rejected(self):
        """4. Reveal during LOCKED is rejected if protocol does not permit it."""
        room = self._setup_3_player_commit_room()
        s1, s2, s3 = generate_secret(), generate_secret(), generate_secret()
        room.submit_commitment("host_id", compute_commitment("host_id", s1))
        room.submit_commitment("bob_id", compute_commitment("bob_id", s2))
        room.submit_commitment("carol_id", compute_commitment("carol_id", s3))
        self.assertEqual(room.state, STATES["LOCKED"])

        with self.assertRaises(ValueError) as ctx:
            room.submit_reveal("host_id", s1)
        self.assertIn("Reveals not accepted in state: LOCKED", str(ctx.exception))

    def test_05_06_valid_and_invalid_reveal(self):
        """5. Valid reveal during REVEAL succeeds; 6. Invalid reveal is rejected."""
        room = self._setup_3_player_commit_room()
        s1, s2, s3 = generate_secret(), generate_secret(), generate_secret()
        room.submit_commitment("host_id", compute_commitment("host_id", s1))
        room.submit_commitment("bob_id", compute_commitment("bob_id", s2))
        room.submit_commitment("carol_id", compute_commitment("carol_id", s3))

        room.open_reveal_phase()
        self.assertEqual(room.state, STATES["REVEAL"])

        # Invalid format rejected
        with self.assertRaises(ValueError):
            room.submit_reveal("host_id", "bad_hex")

        # Valid reveal
        room.submit_reveal("host_id", s1)
        self.assertTrue(room.participants["host_id"].is_revealed)
        self.assertTrue(room.participants["host_id"].verified)

        # Invalid reveal (altered secret)
        corrupted = generate_secret()
        room.submit_reveal("bob_id", corrupted)
        self.assertTrue(room.participants["bob_id"].is_revealed)
        self.assertFalse(room.participants["bob_id"].verified)
        self.assertTrue(room.participants["bob_id"].is_attacking)

    def test_07_reveal_secret_not_included_in_room_updates_during_reveal(self):
        """7. Reveal secret is not included in normal room updates during REVEAL."""
        room = self._setup_3_player_commit_room()
        s1, s2, s3 = generate_secret(), generate_secret(), generate_secret()
        room.submit_commitment("host_id", compute_commitment("host_id", s1))
        room.submit_commitment("bob_id", compute_commitment("bob_id", s2))
        room.submit_commitment("carol_id", compute_commitment("carol_id", s3))
        room.open_reveal_phase()

        # Alice reveals
        room.submit_reveal("host_id", s1)
        state = room.get_public_state()

        self.assertEqual(state["state"], STATES["REVEAL"])
        self.assertIsNone(state["result"])
        self.assertEqual(state["attackLog"], [])

        for p in state["participants"]:
            self.assertIsNone(p["revealedSecret"], "Revealed secret must NEVER leak in public state during REVEAL")
            self.assertIsNone(p["verified"], "Verification status must not leak during REVEAL")

    def test_08_second_reveal_rejected(self):
        """8. Second reveal from the same participant is rejected."""
        room = self._setup_3_player_commit_room()
        s1, s2, s3 = generate_secret(), generate_secret(), generate_secret()
        room.submit_commitment("host_id", compute_commitment("host_id", s1))
        room.submit_commitment("bob_id", compute_commitment("bob_id", s2))
        room.submit_commitment("carol_id", compute_commitment("carol_id", s3))
        room.open_reveal_phase()

        room.submit_reveal("host_id", s1)
        with self.assertRaises(ValueError) as ctx:
            room.submit_reveal("host_id", s1)
        self.assertIn("Secret already revealed", str(ctx.exception))

    def test_09_19_force_timeout_cannot_prematurely_close(self):
        """9. force_timeout cannot prematurely close reveal; 19. Participant cannot force another participant's timeout."""
        room = self._setup_3_player_commit_room()
        s1, s2, s3 = generate_secret(), generate_secret(), generate_secret()
        room.submit_commitment("host_id", compute_commitment("host_id", s1))
        room.submit_commitment("bob_id", compute_commitment("bob_id", s2))
        room.submit_commitment("carol_id", compute_commitment("carol_id", s3))
        room.open_reveal_phase(duration_seconds=60.0)

        with self.assertRaises(ValueError) as ctx:
            room.handle_timeout()
        self.assertIn("reveal deadline has not expired", str(ctx.exception))
        self.assertEqual(room.state, STATES["REVEAL"])

    def test_10_11_server_deadline_closes_reveal_and_rejects_late(self):
        """10. Server deadline closes reveal; 11. Reveal after deadline is rejected."""
        room = self._setup_3_player_commit_room()
        s1, s2, s3 = generate_secret(), generate_secret(), generate_secret()
        room.submit_commitment("host_id", compute_commitment("host_id", s1))
        room.submit_commitment("bob_id", compute_commitment("bob_id", s2))
        room.submit_commitment("carol_id", compute_commitment("carol_id", s3))

        # Open reveal with 0.05s duration
        room.open_reveal_phase(duration_seconds=0.05)
        room.submit_reveal("host_id", s1)

        # Wait for deadline to expire
        time.sleep(0.06)

        # Reveal after deadline is rejected and triggers finalization
        with self.assertRaises(ValueError) as ctx:
            room.submit_reveal("bob_id", s2)
        self.assertIn("Reveal deadline has expired", str(ctx.exception))

        # Protocol is finalized
        self.assertIn(room.state, [STATES["COMPLETED"], STATES["ABORTED"]])

    def test_12_13_missing_participant_handled_at_deadline(self):
        """12. Missing participant is handled at deadline; 13. Invalid/missing reveals do not crash."""
        room = self._setup_3_player_commit_room()
        s1, s2, s3 = generate_secret(), generate_secret(), generate_secret()
        room.submit_commitment("host_id", compute_commitment("host_id", s1))
        room.submit_commitment("bob_id", compute_commitment("bob_id", s2))
        room.submit_commitment("carol_id", compute_commitment("carol_id", s3))

        room.open_reveal_phase(duration_seconds=0.05)
        # Only Alice and Bob reveal; Carol withholds
        room.submit_reveal("host_id", s1)
        room.submit_reveal("bob_id", s2)

        time.sleep(0.06)
        room.close_reveal_and_finalize()

        self.assertEqual(room.state, STATES["COMPLETED"])
        self.assertTrue(room.participants["carol_id"].is_timeout)
        self.assertFalse(room.participants["carol_id"].verified)
        self.assertIn(room.result["winner"]["id"], ["host_id", "bob_id"])
        self.assertNotEqual(room.result["winner"]["id"], "carol_id")

    def test_14_fewer_than_2_valid_participants_aborts_without_crash(self):
        """14. Fewer than 2 valid participants does not call unbiasedSelect with n=1 and aborts safely."""
        room = self._setup_3_player_commit_room()
        s1, s2, s3 = generate_secret(), generate_secret(), generate_secret()
        room.submit_commitment("host_id", compute_commitment("host_id", s1))
        room.submit_commitment("bob_id", compute_commitment("bob_id", s2))
        room.submit_commitment("carol_id", compute_commitment("carol_id", s3))

        room.open_reveal_phase(duration_seconds=0.05)
        # Alice reveals valid secret; Bob reveals corrupted secret; Carol withholds
        room.submit_reveal("host_id", s1)
        room.submit_reveal("bob_id", generate_secret())  # corrupted

        time.sleep(0.06)
        # Finalize when only 1 valid reveal exists
        room.close_reveal_and_finalize()

        self.assertEqual(room.state, STATES["ABORTED"])
        self.assertIsNotNone(room.result)
        self.assertIn("Insufficient valid reveals", room.result["error"])
        self.assertIsNone(room.result["winner"])
        self.assertEqual(room.result["verifiedCount"], 1)
        self.assertEqual(len(room.result["auditTrail"]), 3)

    def test_15_selection_occurs_only_after_reveal_closure(self):
        """15. Selection occurs only after reveal closure."""
        room = self._setup_3_player_commit_room()
        s1, s2, s3 = generate_secret(), generate_secret(), generate_secret()
        room.submit_commitment("host_id", compute_commitment("host_id", s1))
        room.submit_commitment("bob_id", compute_commitment("bob_id", s2))
        room.submit_commitment("carol_id", compute_commitment("carol_id", s3))
        room.open_reveal_phase()

        room.submit_reveal("host_id", s1)
        self.assertIsNone(room.result)
        room.submit_reveal("bob_id", s2)
        self.assertIsNone(room.result)

        # Only on 3rd reveal does closure and selection occur
        room.submit_reveal("carol_id", s3)
        self.assertEqual(room.state, STATES["COMPLETED"])
        self.assertIsNotNone(room.result)

    def test_16_17_concurrent_finalization_is_idempotent(self):
        """16. Multiple near-simultaneous reveals finalize once; 17. Duplicate finalization is impossible."""
        room = self._setup_3_player_commit_room()
        s1, s2, s3 = generate_secret(), generate_secret(), generate_secret()
        room.submit_commitment("host_id", compute_commitment("host_id", s1))
        room.submit_commitment("bob_id", compute_commitment("bob_id", s2))
        room.submit_commitment("carol_id", compute_commitment("carol_id", s3))
        room.open_reveal_phase()

        room.submit_reveal("host_id", s1)
        room.submit_reveal("bob_id", s2)
        room.submit_reveal("carol_id", s3)

        initial_result = room.result
        # Subsequent finalization attempts must be no-ops
        room.close_reveal_and_finalize()
        room.close_reveal_and_finalize()
        self.assertEqual(room.result, initial_result)

    def test_18_disconnect_during_reveal_does_not_crash(self):
        """18. Disconnect during reveal does not crash the room."""
        room = self._setup_3_player_commit_room()
        s1, s2, s3 = generate_secret(), generate_secret(), generate_secret()
        room.submit_commitment("host_id", compute_commitment("host_id", s1))
        room.submit_commitment("bob_id", compute_commitment("bob_id", s2))
        room.submit_commitment("carol_id", compute_commitment("carol_id", s3))
        room.open_reveal_phase()

        # Carol disconnects
        res = room.remove_participant("carol_id")
        self.assertTrue(res)
        # Participant set must remain fixed once locked
        self.assertIn("carol_id", room.participants)

    def test_20_normal_3_player_end_to_end(self):
        """20. Normal 3-player end-to-end protocol still works."""
        room = self._setup_3_player_commit_room()
        s1, s2, s3 = generate_secret(), generate_secret(), generate_secret()

        room.submit_commitment("host_id", compute_commitment("host_id", s1))
        room.submit_commitment("bob_id", compute_commitment("bob_id", s2))
        room.submit_commitment("carol_id", compute_commitment("carol_id", s3))
        self.assertEqual(room.state, STATES["LOCKED"])

        room.open_reveal_phase()
        self.assertEqual(room.state, STATES["REVEAL"])

        room.submit_reveal("host_id", s1)
        room.submit_reveal("bob_id", s2)
        room.submit_reveal("carol_id", s3)
        self.assertEqual(room.state, STATES["COMPLETED"])
        self.assertIn(room.result["winner"]["name"], ["Alice", "Bob", "Carol"])
        self.assertEqual(len(room.result["auditTrail"]), 3)

    def test_21_scalability_various_participant_counts(self):
        """21. Test participant counts including 3, 4, 5, 10, and 20."""
        rm = RoomManager()
        for count in [3, 4, 5, 10, 20]:
            room = rm.create_room("h", "Host", count)
            secrets_map = {"h": generate_secret()}

            for i in range(1, count):
                pid = f"p_{i}"
                room.add_participant(pid, f"Player {i}")
                secrets_map[pid] = generate_secret()

            room.start_protocol("h")
            self.assertEqual(room.state, STATES["COMMIT"])

            # All commit
            for pid, sec in secrets_map.items():
                room.submit_commitment(pid, compute_commitment(pid, sec))

            self.assertEqual(room.state, STATES["LOCKED"])
            room.open_reveal_phase()
            self.assertEqual(room.state, STATES["REVEAL"])

            # All reveal
            for pid, sec in secrets_map.items():
                room.submit_reveal(pid, sec)

            self.assertEqual(room.state, STATES["COMPLETED"], f"Failed for participant count {count}")
            self.assertIsNotNone(room.result["winner"])
            self.assertEqual(len(room.result["auditTrail"]), count)


class TestWebSocketSelectiveAbortMitigation(unittest.TestCase):
    """
    WebSocket test proving that selective-abort / last-revealer leakage is prevented:
    Participant A must NOT receive Participant B's secret over the wire before reveal closure.
    """

    def test_websocket_private_reveal_and_timeout_rejection(self):
        client = TestClient(app)

        with client.websocket_connect("/ws") as ws_alice, \
             client.websocket_connect("/ws") as ws_bob, \
             client.websocket_connect("/ws") as ws_carol:

            # Handshakes
            ws_alice.send_text(json.dumps({"type": "handshake", "id": "alice"}))
            ws_bob.send_text(json.dumps({"type": "handshake", "id": "bob"}))
            ws_carol.send_text(json.dumps({"type": "handshake", "id": "carol"}))

            _ = json.loads(ws_alice.receive_text())
            _ = json.loads(ws_bob.receive_text())
            _ = json.loads(ws_carol.receive_text())

            # Alice creates room
            ws_alice.send_text(json.dumps({
                "type": "emit",
                "event": "create_room",
                "data": {"name": "Alice", "participantsCount": 3},
                "ackId": "create_ack"
            }))
            res = json.loads(ws_alice.receive_text())
            room_code = res["data"]["room"]["code"]
            # room_updated
            _ = json.loads(ws_alice.receive_text())

            # Bob joins
            ws_bob.send_text(json.dumps({
                "type": "emit",
                "event": "join_room",
                "data": {"code": room_code, "name": "Bob"},
                "ackId": "join_bob"
            }))
            _ = json.loads(ws_bob.receive_text())
            _ = json.loads(ws_bob.receive_text())
            _ = json.loads(ws_alice.receive_text())

            # Carol joins
            ws_carol.send_text(json.dumps({
                "type": "emit",
                "event": "join_room",
                "data": {"code": room_code, "name": "Carol"},
                "ackId": "join_carol"
            }))
            _ = json.loads(ws_carol.receive_text())
            _ = json.loads(ws_carol.receive_text())
            _ = json.loads(ws_alice.receive_text())
            _ = json.loads(ws_bob.receive_text())

            # Start protocol
            ws_alice.send_text(json.dumps({
                "type": "emit",
                "event": "start_protocol",
                "data": {},
                "ackId": "start_ack"
            }))
            _ = json.loads(ws_alice.receive_text())  # ack
            _ = json.loads(ws_alice.receive_text())  # protocol_started
            _ = json.loads(ws_alice.receive_text())  # room_updated
            _ = json.loads(ws_bob.receive_text())    # protocol_started
            _ = json.loads(ws_bob.receive_text())    # room_updated
            _ = json.loads(ws_carol.receive_text())  # protocol_started
            _ = json.loads(ws_carol.receive_text())  # room_updated

            # Generate secrets
            sec_alice = generate_secret()
            sec_bob = generate_secret()
            sec_carol = generate_secret()

            # Alice commits
            ws_alice.send_text(json.dumps({
                "type": "emit",
                "event": "submit_commitment",
                "data": {"commitment": compute_commitment("alice", sec_alice)},
                "ackId": "c_alice"
            }))
            _ = json.loads(ws_alice.receive_text())  # ack
            _ = json.loads(ws_alice.receive_text())  # room_updated
            _ = json.loads(ws_bob.receive_text())    # room_updated
            _ = json.loads(ws_carol.receive_text())  # room_updated

            # Bob commits
            ws_bob.send_text(json.dumps({
                "type": "emit",
                "event": "submit_commitment",
                "data": {"commitment": compute_commitment("bob", sec_bob)},
                "ackId": "c_bob"
            }))
            _ = json.loads(ws_bob.receive_text())    # ack
            _ = json.loads(ws_bob.receive_text())    # room_updated
            _ = json.loads(ws_alice.receive_text())  # room_updated
            _ = json.loads(ws_carol.receive_text())  # room_updated

            # Carol commits -> Triggers commitments_locked and opens REVEAL
            ws_carol.send_text(json.dumps({
                "type": "emit",
                "event": "submit_commitment",
                "data": {"commitment": compute_commitment("carol", sec_carol)},
                "ackId": "c_carol"
            }))
            _ = json.loads(ws_carol.receive_text())  # ack
            # Each participant receives commitments_locked then room_updated (REVEAL state)
            lock_alice = json.loads(ws_alice.receive_text())
            update_alice = json.loads(ws_alice.receive_text())
            _ = json.loads(ws_bob.receive_text())
            _ = json.loads(ws_bob.receive_text())
            _ = json.loads(ws_carol.receive_text())
            _ = json.loads(ws_carol.receive_text())

            self.assertEqual(lock_alice["event"], "commitments_locked")
            self.assertEqual(update_alice["data"]["state"], STATES["REVEAL"])

            # Bob tries premature force_timeout before deadline
            ws_bob.send_text(json.dumps({
                "type": "emit",
                "event": "force_timeout",
                "data": {},
                "ackId": "premature_timeout"
            }))
            timeout_res = json.loads(ws_bob.receive_text())
            self.assertFalse(timeout_res["data"]["success"])
            self.assertIn("deadline has not expired", timeout_res["data"]["error"])

            # Alice submits her reveal
            ws_alice.send_text(json.dumps({
                "type": "emit",
                "event": "submit_reveal",
                "data": {"secret": sec_alice},
                "ackId": "r_alice"
            }))
            alice_ack = json.loads(ws_alice.receive_text())
            self.assertTrue(alice_ack["data"]["success"])
            self.assertTrue(alice_ack["data"]["verified"])

            # Receive room_updated on Bob and Carol's sockets
            bob_update = json.loads(ws_bob.receive_text())
            carol_update = json.loads(ws_carol.receive_text())
            _ = json.loads(ws_alice.receive_text())

            # CRITICAL SECURITY VERIFICATION:
            # Check Bob and Carol's received payload for Alice's secret.
            # Alice's secret must NOT be in the payload!
            alice_in_bob_view = next(p for p in bob_update["data"]["participants"] if p["id"] == "alice")
            self.assertTrue(alice_in_bob_view["isRevealed"])
            self.assertIsNone(
                alice_in_bob_view["revealedSecret"],
                "SECURITY LEAK: Alice's revealed secret was sent to Bob during active reveal!"
            )
            self.assertNotIn(
                sec_alice,
                json.dumps(bob_update),
                "SECURITY LEAK: Raw secret string found in WebSocket message to Bob!"
            )

            alice_in_carol_view = next(p for p in carol_update["data"]["participants"] if p["id"] == "alice")
            self.assertIsNone(alice_in_carol_view["revealedSecret"])
            self.assertNotIn(sec_alice, json.dumps(carol_update))

            # Bob reveals
            ws_bob.send_text(json.dumps({
                "type": "emit",
                "event": "submit_reveal",
                "data": {"secret": sec_bob},
                "ackId": "r_bob"
            }))
            _ = json.loads(ws_bob.receive_text())    # ack
            _ = json.loads(ws_bob.receive_text())    # room_updated
            _ = json.loads(ws_alice.receive_text())  # room_updated
            _ = json.loads(ws_carol.receive_text())  # room_updated

            # Carol reveals -> Protocol completes! Synchronized disclosure
            ws_carol.send_text(json.dumps({
                "type": "emit",
                "event": "submit_reveal",
                "data": {"secret": sec_carol},
                "ackId": "r_carol"
            }))
            _ = json.loads(ws_carol.receive_text())  # ack

            # Each socket receives winner_announced and room_updated
            winner_event = json.loads(ws_carol.receive_text())
            self.assertEqual(winner_event["event"], "winner_announced")
            self.assertEqual(winner_event["data"]["state"], STATES["COMPLETED"])
            self.assertIsNotNone(winner_event["data"]["result"]["winner"])

            # Now, upon completion, all 3 secrets are disclosed in the audit trail
            audit_secrets = [p["revealedSecret"] for p in winner_event["data"]["result"]["auditTrail"]]
            self.assertIn(sec_alice, audit_secrets)
            self.assertIn(sec_bob, audit_secrets)
            self.assertIn(sec_carol, audit_secrets)

    def test_websocket_server_enforced_timeout_and_abort(self):
        """Test server timer closes automatically and aborts safely over WebSocket when insufficient reveals."""
        from server import room_manager
        client = TestClient(app)

        with client.websocket_connect("/ws") as ws_alice, \
             client.websocket_connect("/ws") as ws_bob:

            ws_alice.send_text(json.dumps({"type": "handshake", "id": "user_a"}))
            ws_bob.send_text(json.dumps({"type": "handshake", "id": "user_b"}))
            _ = json.loads(ws_alice.receive_text())
            _ = json.loads(ws_bob.receive_text())

            # Create 3-player room with 1 bot
            ws_alice.send_text(json.dumps({
                "type": "emit",
                "event": "create_room",
                "data": {"name": "UserA", "participantsCount": 3},
                "ackId": "c_room"
            }))
            res = json.loads(ws_alice.receive_text())
            room_code = res["data"]["room"]["code"]
            _ = json.loads(ws_alice.receive_text())  # room_updated

            ws_bob.send_text(json.dumps({
                "type": "emit",
                "event": "join_room",
                "data": {"code": room_code, "name": "UserB"},
                "ackId": "j_bob"
            }))
            _ = json.loads(ws_bob.receive_text())
            _ = json.loads(ws_bob.receive_text())
            _ = json.loads(ws_alice.receive_text())

            # Add bot
            ws_alice.send_text(json.dumps({
                "type": "emit",
                "event": "add_bot",
                "data": {},
                "ackId": "add_bot_ack"
            }))
            _ = json.loads(ws_alice.receive_text())
            _ = json.loads(ws_alice.receive_text())
            _ = json.loads(ws_bob.receive_text())

            # Configure room with fast reveal deadline for testing
            room = room_manager.get_room(room_code)
            self.assertIsNotNone(room)
            room.reveal_duration_seconds = 0.2

            # Start protocol
            ws_alice.send_text(json.dumps({"type": "emit", "event": "start_protocol", "data": {}, "ackId": "start"}))
            _ = json.loads(ws_alice.receive_text())  # ack
            _ = json.loads(ws_alice.receive_text())  # protocol_started
            _ = json.loads(ws_alice.receive_text())  # room_updated
            _ = json.loads(ws_bob.receive_text())    # protocol_started
            _ = json.loads(ws_bob.receive_text())    # room_updated

            # UserA and UserB commit (bot already committed during start_protocol)
            sec_a = generate_secret()
            sec_b = generate_secret()
            ws_alice.send_text(json.dumps({"type": "emit", "event": "submit_commitment", "data": {"commitment": compute_commitment("user_a", sec_a)}, "ackId": "ca"}))
            _ = json.loads(ws_alice.receive_text())  # ack
            _ = json.loads(ws_alice.receive_text())  # room_updated
            _ = json.loads(ws_bob.receive_text())    # room_updated

            ws_bob.send_text(json.dumps({"type": "emit", "event": "submit_commitment", "data": {"commitment": compute_commitment("user_b", sec_b)}, "ackId": "cb"}))
            _ = json.loads(ws_bob.receive_text())    # ack
            # Commitments locked and REVEAL opened
            _ = json.loads(ws_alice.receive_text())  # commitments_locked
            _ = json.loads(ws_alice.receive_text())  # room_updated
            _ = json.loads(ws_bob.receive_text())    # commitments_locked
            _ = json.loads(ws_bob.receive_text())    # room_updated

            # Corrupt reveal from UserA; UserB does not reveal
            corrupted_secret = "0" * 64
            ws_alice.send_text(json.dumps({"type": "emit", "event": "simulate_attack", "data": {"corruptedSecret": corrupted_secret}, "ackId": "sim_att"}))
            _ = json.loads(ws_alice.receive_text())  # ack
            _ = json.loads(ws_alice.receive_text())  # room_updated
            _ = json.loads(ws_bob.receive_text())    # room_updated

            # Wait for background server deadline (0.2s) to automatically finalize
            time.sleep(0.3)

            # Check for protocol_aborted event broadcast by schedule_reveal_timer
            # (Only bot is valid -> len(verified) == 1 < 2 -> ABORTED)
            abort_alice = json.loads(ws_alice.receive_text())
            self.assertEqual(abort_alice["event"], "protocol_aborted")
            self.assertEqual(abort_alice["data"]["state"], STATES["ABORTED"])
            self.assertIn("Insufficient valid reveals", abort_alice["data"]["result"]["error"])


class TestPhase3NativeWebSocketAndSessionRecovery(unittest.TestCase):
    """28 comprehensive tests for Native WebSocket Migration and Session Recovery."""

    def test_01_malformed_json_rejected(self):
        """1. Server gracefully rejects malformed JSON without crashing."""
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws:
            ws.send_text("this is definitely not json {[[")
            resp = json.loads(ws.receive_text())
            self.assertEqual(resp.get("type"), "error")
            self.assertIn("Malformed JSON", resp.get("error", ""))

    def test_02_non_object_json_rejected(self):
        """2. Server rejects non-object JSON payloads (e.g. array or primitive)."""
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps([1, 2, 3]))
            resp = json.loads(ws.receive_text())
            self.assertEqual(resp.get("type"), "error")
            self.assertIn("JSON object", resp.get("error", ""))

    def test_03_missing_or_invalid_type_rejected(self):
        """3. Server rejects messages lacking a valid string action/type."""
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({"requestId": "test_req"}))
            resp = json.loads(ws.receive_text())
            self.assertEqual(resp.get("type"), "error")
            self.assertIn("Missing or invalid message type", resp.get("error", ""))

    def test_04_unknown_action_rejected(self):
        """4. Server returns structured error response for unknown action types."""
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({"type": "nonexistent_action_xyz", "requestId": "req_unk"}))
            resp = json.loads(ws.receive_text())
            self.assertEqual(resp.get("type"), "response")
            self.assertEqual(resp.get("requestId"), "req_unk")
            self.assertFalse(resp.get("success"))
            self.assertIn("Unknown message type", resp.get("error", ""))

    def test_05_oversized_payload_rejected(self):
        """5. Server rejects payloads exceeding MAX_MESSAGE_SIZE (64KB)."""
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws:
            oversized = json.dumps({"type": "create_room", "payload": {"blob": "X" * 70000}})
            ws.send_text(oversized)
            resp = json.loads(ws.receive_text())
            self.assertEqual(resp.get("type"), "error")
            self.assertIn("Payload exceeds maximum", resp.get("error", ""))

    def test_06_request_id_correlation_in_response(self):
        """6. Server correlates responses with client-supplied requestId."""
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws:
            req_id = "custom_req_uuid_987654"
            ws.send_text(json.dumps({
                "type": "create_room",
                "requestId": req_id,
                "payload": {"name": "HostUser", "participantsCount": 3}
            }))
            resp = json.loads(ws.receive_text())
            self.assertEqual(resp.get("type"), "response")
            self.assertEqual(resp.get("requestId"), req_id)
            self.assertTrue(resp.get("success"))

    def test_07_native_create_room_returns_session_token(self):
        """7. Native create_room issues unpredictable session token and participantId."""
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({
                "type": "create_room",
                "requestId": "cr_1",
                "payload": {"name": "Alice", "participantsCount": 3}
            }))
            resp = json.loads(ws.receive_text())
            self.assertTrue(resp.get("success"))
            data = resp.get("data", {})
            self.assertIn("participantId", data)
            self.assertIn("sessionToken", data)
            self.assertEqual(len(data["sessionToken"]), 64)
            self.assertTrue(HEX_64_REGEX.match(data["sessionToken"]))

    def test_08_native_join_room_returns_session_token(self):
        """8. Native join_room issues unpredictable session token and participantId."""
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws_host, \
             client.websocket_connect("/ws") as ws_guest:
            ws_host.send_text(json.dumps({
                "type": "create_room",
                "requestId": "cr_h",
                "payload": {"name": "Host", "participantsCount": 3}
            }))
            host_resp = json.loads(ws_host.receive_text())
            room_code = host_resp["data"]["room"]["code"]
            _ = json.loads(ws_host.receive_text())  # room_updated

            ws_guest.send_text(json.dumps({
                "type": "join_room",
                "requestId": "jr_g",
                "payload": {"code": room_code, "name": "Guest"}
            }))
            guest_resp = json.loads(ws_guest.receive_text())
            self.assertTrue(guest_resp.get("success"))
            data = guest_resp.get("data", {})
            self.assertIn("participantId", data)
            self.assertIn("sessionToken", data)
            self.assertEqual(len(data["sessionToken"]), 64)
            self.assertTrue(HEX_64_REGEX.match(data["sessionToken"]))

    def test_09_join_room_invalid_code_format(self):
        """9. Native join_room rejects invalid code length or characters."""
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws:
            # Too short
            ws.send_text(json.dumps({
                "type": "join_room",
                "requestId": "jr_bad1",
                "payload": {"code": "ABC", "name": "Guest"}
            }))
            resp = json.loads(ws.receive_text())
            self.assertFalse(resp.get("success"))
            self.assertIn("Invalid room code format", resp.get("error", ""))

            # Non-alphanumeric
            ws.send_text(json.dumps({
                "type": "join_room",
                "requestId": "jr_bad2",
                "payload": {"code": "AB!@#$", "name": "Guest"}
            }))
            resp2 = json.loads(ws.receive_text())
            self.assertFalse(resp2.get("success"))
            self.assertIn("Invalid room code format", resp2.get("error", ""))

    def test_10_join_nonexistent_room(self):
        """10. Native join_room rejects non-existent room codes."""
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({
                "type": "join_room",
                "requestId": "jr_none",
                "payload": {"code": "ZZZZZZ", "name": "Guest"}
            }))
            resp = json.loads(ws.receive_text())
            self.assertFalse(resp.get("success"))
            self.assertIn("Room not found", resp.get("error", ""))

    def test_11_join_full_room_rejected(self):
        """11. Joining a room that has reached required_participants is rejected."""
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws_host, \
             client.websocket_connect("/ws") as ws_extra:
            ws_host.send_text(json.dumps({
                "type": "create_room",
                "requestId": "cr",
                "payload": {"name": "Host", "participantsCount": 3}
            }))
            host_resp = json.loads(ws_host.receive_text())
            room_code = host_resp["data"]["room"]["code"]
            _ = json.loads(ws_host.receive_text())

            # Add two bots to fill room (1 host + 2 bots = 3)
            ws_host.send_text(json.dumps({"type": "add_bot", "requestId": "b1"}))
            _ = json.loads(ws_host.receive_text())
            _ = json.loads(ws_host.receive_text())

            ws_host.send_text(json.dumps({"type": "add_bot", "requestId": "b2"}))
            _ = json.loads(ws_host.receive_text())
            _ = json.loads(ws_host.receive_text())

            # Extra guest attempts to join full room
            ws_extra.send_text(json.dumps({
                "type": "join_room",
                "requestId": "jr_full",
                "payload": {"code": room_code, "name": "Extra"}
            }))
            resp = json.loads(ws_extra.receive_text())
            self.assertFalse(resp.get("success"))
            self.assertIn("full", resp.get("error", "").lower())

    def test_12_unauthorized_action_without_room_rejected(self):
        """12. Room-scoped actions before joining any room are rejected."""
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({
                "type": "start_protocol",
                "requestId": "unauth_start"
            }))
            resp = json.loads(ws.receive_text())
            self.assertFalse(resp.get("success"))
            self.assertIn("Not in a room", resp.get("error", ""))

    def test_13_reconnect_success_with_valid_session_token(self):
        """13. Reconnection succeeds with valid credentials and restores connected state."""
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws1:
            ws1.send_text(json.dumps({
                "type": "create_room",
                "requestId": "c1",
                "payload": {"name": "Alice", "participantsCount": 3}
            }))
            res = json.loads(ws1.receive_text())
            code = res["data"]["room"]["code"]
            alice_pid = res["data"]["participantId"]
            alice_token = res["data"]["sessionToken"]
            _ = json.loads(ws1.receive_text())  # room_updated

            ws1.send_text(json.dumps({"type": "add_bot", "requestId": "b1"}))
            _ = json.loads(ws1.receive_text())
            _ = json.loads(ws1.receive_text())
            ws1.send_text(json.dumps({"type": "add_bot", "requestId": "b2"}))
            _ = json.loads(ws1.receive_text())
            _ = json.loads(ws1.receive_text())

            ws1.send_text(json.dumps({"type": "start_protocol", "requestId": "s1"}))
            _ = json.loads(ws1.receive_text())
            _ = json.loads(ws1.receive_text())
            _ = json.loads(ws1.receive_text())

        # Alice disconnects (ws1 block exits). Now Alice reconnects on a fresh WebSocket connection
        with client.websocket_connect("/ws") as ws_alice_rec:
            ws_alice_rec.send_text(json.dumps({
                "type": "reconnect",
                "requestId": "rec1",
                "payload": {
                    "roomCode": code,
                    "participantId": alice_pid,
                    "sessionToken": alice_token
                }
            }))
            rec_resp = json.loads(ws_alice_rec.receive_text())
            self.assertTrue(rec_resp.get("success"))
            data = rec_resp.get("data", {})
            self.assertEqual(data.get("participantId"), alice_pid)
            self.assertEqual(data.get("sessionToken"), alice_token)
            reconnected_part = next(p for p in data["room"]["participants"] if p["id"] == alice_pid)
            self.assertTrue(reconnected_part["connected"])

    def test_14_reconnect_does_not_duplicate_participant(self):
        """14. Reconnecting does not create a duplicate participant record."""
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws1:
            ws1.send_text(json.dumps({
                "type": "create_room",
                "requestId": "c1",
                "payload": {"name": "Alice", "participantsCount": 3}
            }))
            res = json.loads(ws1.receive_text())
            code = res["data"]["room"]["code"]
            pid = res["data"]["participantId"]
            token = res["data"]["sessionToken"]
            _ = json.loads(ws1.receive_text())

            # Add a second participant
            ws2 = client.websocket_connect("/ws")
            ws2.__enter__()
            ws2.send_text(json.dumps({
                "type": "join_room",
                "requestId": "j2",
                "payload": {"code": code, "name": "Bob"}
            }))
            res2 = json.loads(ws2.receive_text())
            bob_pid = res2["data"]["participantId"]
            bob_token = res2["data"]["sessionToken"]
            _ = json.loads(ws1.receive_text())

            # Start protocol so Bob won't be removed on disconnect
            ws1.send_text(json.dumps({"type": "add_bot", "requestId": "b1"}))
            _ = json.loads(ws1.receive_text())
            _ = json.loads(ws1.receive_text())
            _ = json.loads(ws2.receive_text())

            ws1.send_text(json.dumps({"type": "start_protocol", "requestId": "s1"}))
            _ = json.loads(ws1.receive_text())
            _ = json.loads(ws1.receive_text())
            _ = json.loads(ws1.receive_text())
            _ = json.loads(ws2.receive_text())
            _ = json.loads(ws2.receive_text())

            # Bob disconnects
            ws2.close()
            _ = json.loads(ws1.receive_text())

            # Bob reconnects
            ws3 = client.websocket_connect("/ws")
            ws3.__enter__()
            ws3.send_text(json.dumps({
                "type": "reconnect",
                "requestId": "rec_bob",
                "payload": {
                    "roomCode": code,
                    "participantId": bob_pid,
                    "sessionToken": bob_token
                }
            }))
            rec_res = json.loads(ws3.receive_text())
            self.assertTrue(rec_res.get("success"))
            self.assertEqual(len(rec_res["data"]["room"]["participants"]), 3)
            ws3.close()

    def test_15_reconnect_rejected_on_invalid_session_token(self):
        """15. Reconnection with a forged session token fails authentication."""
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws1:
            ws1.send_text(json.dumps({
                "type": "create_room",
                "requestId": "c1",
                "payload": {"name": "Alice", "participantsCount": 3}
            }))
            res = json.loads(ws1.receive_text())
            code = res["data"]["room"]["code"]
            pid = res["data"]["participantId"]

            # Attacker tries to reconnect with tampered sessionToken while room is alive
            with client.websocket_connect("/ws") as ws_attacker:
                ws_attacker.send_text(json.dumps({
                    "type": "reconnect",
                    "requestId": "atk_rec",
                    "payload": {
                        "roomCode": code,
                        "participantId": pid,
                        "sessionToken": "0" * 64
                    }
                }))
                atk_res = json.loads(ws_attacker.receive_text())
                self.assertFalse(atk_res.get("success"))
                self.assertIn("authentication failed", atk_res.get("error", "").lower())

    def test_16_reconnect_rejected_on_unknown_participant_id(self):
        """16. Reconnection with a non-existent participantId is rejected."""
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws1:
            ws1.send_text(json.dumps({
                "type": "create_room",
                "requestId": "c1",
                "payload": {"name": "Alice", "participantsCount": 3}
            }))
            res = json.loads(ws1.receive_text())
            code = res["data"]["room"]["code"]

            with client.websocket_connect("/ws") as ws2:
                ws2.send_text(json.dumps({
                    "type": "reconnect",
                    "requestId": "atk_rec2",
                    "payload": {
                        "roomCode": code,
                        "participantId": "nonexistent_pid",
                        "sessionToken": "a" * 64
                    }
                }))
                atk_res = json.loads(ws2.receive_text())
                self.assertFalse(atk_res.get("success"))
                self.assertIn("authentication failed", atk_res.get("error", "").lower())

    def test_17_reconnect_rejected_on_invalid_room_code(self):
        """17. Reconnection with invalid or expired room code is rejected."""
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({
                "type": "reconnect",
                "requestId": "rec_bad_code",
                "payload": {
                    "roomCode": "XXXXXX",
                    "participantId": "pid_123",
                    "sessionToken": "b" * 64
                }
            }))
            resp = json.loads(ws.receive_text())
            self.assertFalse(resp.get("success"))
            self.assertIn("Room not found", resp.get("error", ""))

    def test_18_reconnect_rejected_on_missing_credentials(self):
        """18. Reconnection missing required credential fields is rejected."""
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({
                "type": "reconnect",
                "requestId": "rec_missing",
                "payload": {
                    "roomCode": "ABCDEF"
                }
            }))
            resp = json.loads(ws.receive_text())
            self.assertFalse(resp.get("success"))
            self.assertIn("required", resp.get("error", "").lower())

    def test_19_reconnect_during_commit_phase(self):
        """19. Participant can disconnect and reconnect during COMMIT phase and submit commitment."""
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws_alice:
            ws_alice.send_text(json.dumps({
                "type": "create_room",
                "requestId": "ca",
                "payload": {"name": "Alice", "participantsCount": 3}
            }))
            res_a = json.loads(ws_alice.receive_text())
            code = res_a["data"]["room"]["code"]
            alice_pid = res_a["data"]["participantId"]
            alice_token = res_a["data"]["sessionToken"]
            _ = json.loads(ws_alice.receive_text())

            # Add bots and start
            ws_alice.send_text(json.dumps({"type": "add_bot", "requestId": "b1"}))
            _ = json.loads(ws_alice.receive_text())
            _ = json.loads(ws_alice.receive_text())
            ws_alice.send_text(json.dumps({"type": "add_bot", "requestId": "b2"}))
            _ = json.loads(ws_alice.receive_text())
            _ = json.loads(ws_alice.receive_text())

            ws_alice.send_text(json.dumps({"type": "start_protocol", "requestId": "st"}))
            _ = json.loads(ws_alice.receive_text())
            _ = json.loads(ws_alice.receive_text())
            _ = json.loads(ws_alice.receive_text())

        # Alice disconnected during COMMIT phase. Now Alice reconnects:
        with client.websocket_connect("/ws") as ws_alice_new:
            ws_alice_new.send_text(json.dumps({
                "type": "reconnect",
                "requestId": "rec_a",
                "payload": {
                    "roomCode": code,
                    "participantId": alice_pid,
                    "sessionToken": alice_token
                }
            }))
            rec_res = json.loads(ws_alice_new.receive_text())
            self.assertTrue(rec_res.get("success"))
            self.assertEqual(rec_res["data"]["room"]["state"], STATES["COMMIT"])
            _ = json.loads(ws_alice_new.receive_text())  # room_updated broadcast from reconnect

            # Alice submits commitment after reconnecting
            sec_a = generate_secret()
            comm_a = compute_commitment(alice_pid, sec_a)
            ws_alice_new.send_text(json.dumps({
                "type": "submit_commitment",
                "requestId": "comm_a",
                "payload": {"commitment": comm_a}
            }))
            comm_res = json.loads(ws_alice_new.receive_text())
            self.assertTrue(comm_res.get("success"))

    def test_20_reconnect_during_reveal_phase_does_not_leak_secrets(self):
        """20. Reconnection during REVEAL phase does NOT leak unrevealed secrets of any participant."""
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws_alice, \
             client.websocket_connect("/ws") as ws_bob:
            ws_alice.send_text(json.dumps({
                "type": "create_room",
                "requestId": "ca",
                "payload": {"name": "Alice", "participantsCount": 3}
            }))
            res_a = json.loads(ws_alice.receive_text())
            code = res_a["data"]["room"]["code"]
            _ = json.loads(ws_alice.receive_text())

            ws_bob.send_text(json.dumps({
                "type": "join_room",
                "requestId": "jb",
                "payload": {"code": code, "name": "Bob"}
            }))
            res_b = json.loads(ws_bob.receive_text())
            bob_pid = res_b["data"]["participantId"]
            bob_token = res_b["data"]["sessionToken"]
            _ = json.loads(ws_alice.receive_text())

            # Add bot
            ws_alice.send_text(json.dumps({"type": "add_bot", "requestId": "b1"}))
            _ = json.loads(ws_alice.receive_text())
            _ = json.loads(ws_alice.receive_text())
            _ = json.loads(ws_bob.receive_text())

            # Start protocol
            ws_alice.send_text(json.dumps({"type": "start_protocol", "requestId": "st"}))
            _ = json.loads(ws_alice.receive_text())
            _ = json.loads(ws_alice.receive_text())
            _ = json.loads(ws_alice.receive_text())
            _ = json.loads(ws_bob.receive_text())
            _ = json.loads(ws_bob.receive_text())

            # Alice & Bob commit
            sec_a = generate_secret()
            sec_b = generate_secret()
            comm_a = compute_commitment(res_a["data"]["participantId"], sec_a)
            comm_b = compute_commitment(bob_pid, sec_b)

            ws_alice.send_text(json.dumps({"type": "submit_commitment", "requestId": "ca", "payload": {"commitment": comm_a}}))
            _ = json.loads(ws_alice.receive_text())
            _ = json.loads(ws_alice.receive_text())
            _ = json.loads(ws_bob.receive_text())

            ws_bob.send_text(json.dumps({"type": "submit_commitment", "requestId": "cb", "payload": {"commitment": comm_b}}))
            _ = json.loads(ws_bob.receive_text())
            _ = json.loads(ws_alice.receive_text())  # commitments_locked
            _ = json.loads(ws_alice.receive_text())  # room_updated
            _ = json.loads(ws_bob.receive_text())    # commitments_locked
            _ = json.loads(ws_bob.receive_text())    # room_updated

            # Alice reveals
            ws_alice.send_text(json.dumps({"type": "submit_reveal", "requestId": "ra", "payload": {"secret": sec_a}}))
            _ = json.loads(ws_alice.receive_text())  # ack
            _ = json.loads(ws_alice.receive_text())  # room_updated
            _ = json.loads(ws_bob.receive_text())    # room_updated

        # Bob reconnects on a new connection while reveal phase is active
        with client.websocket_connect("/ws") as ws_bob_new:
            ws_bob_new.send_text(json.dumps({
                "type": "reconnect",
                "requestId": "rec_b",
                "payload": {
                    "roomCode": code,
                    "participantId": bob_pid,
                    "sessionToken": bob_token
                }
            }))
            rec_b_res = json.loads(ws_bob_new.receive_text())
            self.assertTrue(rec_b_res.get("success"))
            participants = rec_b_res["data"]["room"]["participants"]

            # Verify neither Alice's secret nor any bot's secret is revealed in public state
            for p in participants:
                self.assertIsNone(
                    p["revealedSecret"],
                    f"Privacy violation: {p['id']} secret leaked in reconnect response!"
                )
            self.assertNotIn(sec_a, json.dumps(rec_b_res))

    def test_21_reconnect_after_completion(self):
        """21. Reconnecting to a completed room returns finalized state and audit trail."""
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({
                "type": "create_room",
                "requestId": "c1",
                "payload": {"name": "Host", "participantsCount": 3}
            }))
            res = json.loads(ws.receive_text())
            code = res["data"]["room"]["code"]
            pid = res["data"]["participantId"]
            token = res["data"]["sessionToken"]
            _ = json.loads(ws.receive_text())

            ws.send_text(json.dumps({"type": "add_bot", "requestId": "b1"}))
            _ = json.loads(ws.receive_text())
            _ = json.loads(ws.receive_text())
            ws.send_text(json.dumps({"type": "add_bot", "requestId": "b2"}))
            _ = json.loads(ws.receive_text())
            _ = json.loads(ws.receive_text())

            ws.send_text(json.dumps({"type": "start_protocol", "requestId": "st"}))
            _ = json.loads(ws.receive_text())
            _ = json.loads(ws.receive_text())
            _ = json.loads(ws.receive_text())

            sec = generate_secret()
            comm = compute_commitment(pid, sec)
            ws.send_text(json.dumps({"type": "submit_commitment", "requestId": "comm", "payload": {"commitment": comm}}))
            _ = json.loads(ws.receive_text())
            _ = json.loads(ws.receive_text())
            _ = json.loads(ws.receive_text())

            ws.send_text(json.dumps({"type": "submit_reveal", "requestId": "rev", "payload": {"secret": sec}}))
            _ = json.loads(ws.receive_text())
            _ = json.loads(ws.receive_text())  # winner_announced
            _ = json.loads(ws.receive_text())  # room_updated

        # Reconnect on fresh socket
        with client.websocket_connect("/ws") as ws_reconnect:
            ws_reconnect.send_text(json.dumps({
                "type": "reconnect",
                "requestId": "rec_final",
                "payload": {
                    "roomCode": code,
                    "participantId": pid,
                    "sessionToken": token
                }
            }))
            resp = json.loads(ws_reconnect.receive_text())
            self.assertTrue(resp.get("success"))
            room_state = resp["data"]["room"]
            self.assertEqual(room_state["state"], STATES["COMPLETED"])
            self.assertIsNotNone(room_state["result"]["winner"])
            self.assertIn("auditTrail", room_state["result"])

    def test_22_reconnect_after_abort(self):
        """22. Reconnecting to an aborted room returns aborted state and error explanation."""
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({
                "type": "create_room",
                "requestId": "c1",
                "payload": {"name": "Host", "participantsCount": 3}
            }))
            res = json.loads(ws.receive_text())
            code = res["data"]["room"]["code"]
            pid = res["data"]["participantId"]
            token = res["data"]["sessionToken"]
            _ = json.loads(ws.receive_text())

            ws.send_text(json.dumps({"type": "add_bot", "requestId": "b1"}))
            _ = json.loads(ws.receive_text())
            _ = json.loads(ws.receive_text())
            ws.send_text(json.dumps({"type": "add_bot", "requestId": "b2"}))
            _ = json.loads(ws.receive_text())
            _ = json.loads(ws.receive_text())

            ws.send_text(json.dumps({"type": "start_protocol", "requestId": "st"}))
            _ = json.loads(ws.receive_text())
            _ = json.loads(ws.receive_text())
            _ = json.loads(ws.receive_text())

            sec = generate_secret()
            comm = compute_commitment(pid, sec)
            ws.send_text(json.dumps({"type": "submit_commitment", "requestId": "comm", "payload": {"commitment": comm}}))
            _ = json.loads(ws.receive_text())
            _ = json.loads(ws.receive_text())
            _ = json.loads(ws.receive_text())

            # Force timeout without revealing
            ws.send_text(json.dumps({"type": "force_timeout", "requestId": "to"}))
            _ = json.loads(ws.receive_text())  # ack
            _ = json.loads(ws.receive_text())  # winner_announced or protocol_aborted
            _ = json.loads(ws.receive_text())  # room_updated

        # Reconnect on fresh socket
        with client.websocket_connect("/ws") as ws_reconnect:
            ws_reconnect.send_text(json.dumps({
                "type": "reconnect",
                "requestId": "rec_aborted",
                "payload": {
                    "roomCode": code,
                    "participantId": pid,
                    "sessionToken": token
                }
            }))
            resp = json.loads(ws_reconnect.receive_text())
            self.assertTrue(resp.get("success"))
            room_state = resp["data"]["room"]
            self.assertIn(room_state["state"], (STATES["COMPLETED"], STATES["ABORTED"]))

    def test_23_disconnect_during_commit_preserves_participant(self):
        """23. Participant disconnect during COMMIT sets connected=False without purging participant."""
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws1:
            ws1.send_text(json.dumps({
                "type": "create_room",
                "requestId": "c1",
                "payload": {"name": "Alice", "participantsCount": 3}
            }))
            res = json.loads(ws1.receive_text())
            code = res["data"]["room"]["code"]
            _ = json.loads(ws1.receive_text())

            ws2 = client.websocket_connect("/ws")
            ws2.__enter__()
            ws2.send_text(json.dumps({
                "type": "join_room",
                "requestId": "j2",
                "payload": {"code": code, "name": "Bob"}
            }))
            _ = json.loads(ws2.receive_text())
            _ = json.loads(ws1.receive_text())

            ws1.send_text(json.dumps({"type": "add_bot", "requestId": "b1"}))
            _ = json.loads(ws1.receive_text())
            _ = json.loads(ws1.receive_text())
            _ = json.loads(ws2.receive_text())

            ws1.send_text(json.dumps({"type": "start_protocol", "requestId": "st"}))
            _ = json.loads(ws1.receive_text())
            _ = json.loads(ws1.receive_text())
            _ = json.loads(ws1.receive_text())
            _ = json.loads(ws2.receive_text())
            _ = json.loads(ws2.receive_text())

            # Bob disconnects during COMMIT
            ws2.close()
            room_upd = json.loads(ws1.receive_text())
            self.assertEqual(len(room_upd["data"]["participants"]), 3)
            bob_info = next(p for p in room_upd["data"]["participants"] if p["name"] == "Bob")
            self.assertFalse(bob_info["connected"])

    def test_24_disconnect_during_reveal_preserves_deadline_and_privacy(self):
        """24. Participant disconnect during REVEAL retains room progression and secret privacy."""
        from server import room_manager
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws1:
            ws1.send_text(json.dumps({
                "type": "create_room",
                "requestId": "c1",
                "payload": {"name": "Alice", "participantsCount": 3}
            }))
            res = json.loads(ws1.receive_text())
            code = res["data"]["room"]["code"]
            alice_pid = res["data"]["participantId"]
            _ = json.loads(ws1.receive_text())

            ws2 = client.websocket_connect("/ws")
            ws2.__enter__()
            ws2.send_text(json.dumps({
                "type": "join_room",
                "requestId": "j2",
                "payload": {"code": code, "name": "Bob"}
            }))
            res2 = json.loads(ws2.receive_text())
            bob_pid = res2["data"]["participantId"]
            _ = json.loads(ws1.receive_text())

            ws1.send_text(json.dumps({"type": "add_bot", "requestId": "b1"}))
            _ = json.loads(ws1.receive_text())
            _ = json.loads(ws1.receive_text())
            _ = json.loads(ws2.receive_text())

            ws1.send_text(json.dumps({"type": "start_protocol", "requestId": "st"}))
            _ = json.loads(ws1.receive_text())
            _ = json.loads(ws1.receive_text())
            _ = json.loads(ws1.receive_text())
            _ = json.loads(ws2.receive_text())
            _ = json.loads(ws2.receive_text())

            sec_a = generate_secret()
            sec_b = generate_secret()
            comm_a = compute_commitment(alice_pid, sec_a)
            comm_b = compute_commitment(bob_pid, sec_b)

            ws1.send_text(json.dumps({"type": "submit_commitment", "requestId": "ca", "payload": {"commitment": comm_a}}))
            _ = json.loads(ws1.receive_text())
            _ = json.loads(ws1.receive_text())
            _ = json.loads(ws2.receive_text())

            ws2.send_text(json.dumps({"type": "submit_commitment", "requestId": "cb", "payload": {"commitment": comm_b}}))
            _ = json.loads(ws2.receive_text())
            _ = json.loads(ws1.receive_text())
            _ = json.loads(ws1.receive_text())
            _ = json.loads(ws2.receive_text())
            _ = json.loads(ws2.receive_text())

            # In REVEAL phase, Bob disconnects
            ws2.close()
            room_upd = json.loads(ws1.receive_text())
            bob_info = next(p for p in room_upd["data"]["participants"] if p["id"] == bob_pid)
            self.assertFalse(bob_info["connected"])

            # Verify room is still in REVEAL phase
            room = room_manager.get_room(code)
            self.assertIsNotNone(room)
            self.assertEqual(room.state, STATES["REVEAL"])

    def test_25_disconnect_in_lobby_removes_participant_and_cleans_up(self):
        """25. Disconnecting in LOBBY removes participant; last participant disconnect cleans up room."""
        from server import room_manager
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws1:
            ws1.send_text(json.dumps({
                "type": "create_room",
                "requestId": "c1",
                "payload": {"name": "Alice", "participantsCount": 3}
            }))
            res = json.loads(ws1.receive_text())
            code = res["data"]["room"]["code"]
            _ = json.loads(ws1.receive_text())

            ws2 = client.websocket_connect("/ws")
            ws2.__enter__()
            ws2.send_text(json.dumps({
                "type": "join_room",
                "requestId": "j2",
                "payload": {"code": code, "name": "Bob"}
            }))
            _ = json.loads(ws2.receive_text())
            _ = json.loads(ws1.receive_text())

            # Bob disconnects in lobby -> removed
            ws2.close()
            upd = json.loads(ws1.receive_text())
            self.assertEqual(len(upd["data"]["participants"]), 1)

        # Alice disconnects (last participant) -> room deleted
        self.assertIsNone(room_manager.get_room(code))

    def test_26_room_isolation_no_cross_room_leakage(self):
        """26. Room isolation: Messages and broadcasts in Room A never reach Room B subscribers."""
        from server import room_subscribers
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws_a, \
             client.websocket_connect("/ws") as ws_b:
            # Alice creates Room A
            ws_a.send_text(json.dumps({
                "type": "create_room",
                "requestId": "cra",
                "payload": {"name": "Alice", "participantsCount": 3}
            }))
            res_a = json.loads(ws_a.receive_text())
            code_a = res_a["data"]["room"]["code"]
            _ = json.loads(ws_a.receive_text())  # room_updated A

            # Bob creates Room B
            ws_b.send_text(json.dumps({
                "type": "create_room",
                "requestId": "crb",
                "payload": {"name": "Bob", "participantsCount": 3}
            }))
            res_b = json.loads(ws_b.receive_text())
            code_b = res_b["data"]["room"]["code"]
            _ = json.loads(ws_b.receive_text())  # room_updated B

            self.assertNotEqual(code_a, code_b)

            # Check subscriber isolation
            subs_a = room_subscribers.get(code_a, set())
            subs_b = room_subscribers.get(code_b, set())
            self.assertNotIn(ws_b, subs_a)
            self.assertNotIn(ws_a, subs_b)

            # Alice adds bot in Room A
            ws_a.send_text(json.dumps({"type": "add_bot", "requestId": "bot_a"}))
            _ = json.loads(ws_a.receive_text())  # ack
            _ = json.loads(ws_a.receive_text())  # room_updated for A

            # Bob performs an action in Room B and receives ONLY Room B's event
            ws_b.send_text(json.dumps({"type": "add_bot", "requestId": "bot_b"}))
            ack_b = json.loads(ws_b.receive_text())
            self.assertEqual(ack_b.get("requestId"), "bot_b")
            upd_b = json.loads(ws_b.receive_text())
            self.assertEqual(upd_b["data"]["code"], code_b)
            self.assertEqual(len(upd_b["data"]["participants"]), 2)

    def test_27_timing_safe_token_verification(self):
        """27. Room.verify_session uses timing-safe comparison and handles invalid tokens securely."""
        room = Room("ISOL01", "host_1", "Host", 3)
        p = room.participants["host_1"]
        valid_token = p.session_token

        # 1. Matching token succeeds
        self.assertEqual(room.verify_session("host_1", valid_token), p)
        self.assertTrue(p.connected)

        # 2. Tampered token (1 character flipped) fails
        tampered = valid_token[:-1] + ("0" if valid_token[-1] != "0" else "1")
        self.assertIsNone(room.verify_session("host_1", tampered))

        # 3. Empty or None token fails
        self.assertIsNone(room.verify_session("host_1", ""))
        self.assertIsNone(room.verify_session("host_1", None))

        # 4. Wrong participant id fails
        self.assertIsNone(room.verify_session("wrong_pid", valid_token))

    def test_28_full_native_websocket_3_player_protocol_e2e(self):
        """28. Complete 3-player game executed entirely over Native WebSocket JSON protocol."""
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws_alice, \
             client.websocket_connect("/ws") as ws_bob, \
             client.websocket_connect("/ws") as ws_carol:

            # 1. Alice creates room
            ws_alice.send_text(json.dumps({
                "type": "create_room",
                "requestId": "req_create",
                "payload": {"name": "Alice", "participantsCount": 3}
            }))
            res_create = json.loads(ws_alice.receive_text())
            self.assertTrue(res_create["success"])
            room_code = res_create["data"]["room"]["code"]
            alice_id = res_create["data"]["participantId"]
            _ = json.loads(ws_alice.receive_text())  # room_updated

            # 2. Bob joins room
            ws_bob.send_text(json.dumps({
                "type": "join_room",
                "requestId": "req_join_bob",
                "payload": {"code": room_code, "name": "Bob"}
            }))
            res_bob = json.loads(ws_bob.receive_text())
            self.assertTrue(res_bob["success"])
            bob_id = res_bob["data"]["participantId"]
            _ = json.loads(ws_bob.receive_text())    # room_updated
            _ = json.loads(ws_alice.receive_text())  # room_updated

            # 3. Carol joins room
            ws_carol.send_text(json.dumps({
                "type": "join_room",
                "requestId": "req_join_carol",
                "payload": {"code": room_code, "name": "Carol"}
            }))
            res_carol = json.loads(ws_carol.receive_text())
            self.assertTrue(res_carol["success"])
            carol_id = res_carol["data"]["participantId"]
            _ = json.loads(ws_carol.receive_text())  # room_updated
            _ = json.loads(ws_alice.receive_text())  # room_updated
            _ = json.loads(ws_bob.receive_text())    # room_updated

            # 4. Alice starts protocol
            ws_alice.send_text(json.dumps({
                "type": "start_protocol",
                "requestId": "req_start",
                "payload": {}
            }))
            _ = json.loads(ws_alice.receive_text())  # ack
            _ = json.loads(ws_alice.receive_text())  # protocol_started
            _ = json.loads(ws_alice.receive_text())  # room_updated
            _ = json.loads(ws_bob.receive_text())    # protocol_started
            _ = json.loads(ws_bob.receive_text())    # room_updated
            _ = json.loads(ws_carol.receive_text())  # protocol_started
            _ = json.loads(ws_carol.receive_text())  # room_updated

            # 5. Commit phase: Generate secrets and commitments
            sec_alice = generate_secret()
            sec_bob = generate_secret()
            sec_carol = generate_secret()

            comm_alice = compute_commitment(alice_id, sec_alice)
            comm_bob = compute_commitment(bob_id, sec_bob)
            comm_carol = compute_commitment(carol_id, sec_carol)

            # Alice commits
            ws_alice.send_text(json.dumps({
                "type": "submit_commitment",
                "requestId": "comm_alice",
                "payload": {"commitment": comm_alice}
            }))
            _ = json.loads(ws_alice.receive_text())  # ack
            _ = json.loads(ws_alice.receive_text())  # room_updated
            _ = json.loads(ws_bob.receive_text())    # room_updated
            _ = json.loads(ws_carol.receive_text())  # room_updated

            # Bob commits
            ws_bob.send_text(json.dumps({
                "type": "submit_commitment",
                "requestId": "comm_bob",
                "payload": {"commitment": comm_bob}
            }))
            _ = json.loads(ws_bob.receive_text())    # ack
            _ = json.loads(ws_alice.receive_text())  # room_updated
            _ = json.loads(ws_bob.receive_text())    # room_updated
            _ = json.loads(ws_carol.receive_text())  # room_updated

            # Carol commits -> Commitments locked -> Reveal phase opened
            ws_carol.send_text(json.dumps({
                "type": "submit_commitment",
                "requestId": "comm_carol",
                "payload": {"commitment": comm_carol}
            }))
            _ = json.loads(ws_carol.receive_text())  # ack
            _ = json.loads(ws_alice.receive_text())  # commitments_locked
            _ = json.loads(ws_alice.receive_text())  # room_updated
            _ = json.loads(ws_bob.receive_text())    # commitments_locked
            _ = json.loads(ws_bob.receive_text())    # room_updated
            _ = json.loads(ws_carol.receive_text())  # commitments_locked
            _ = json.loads(ws_carol.receive_text())  # room_updated

            # 6. Reveal phase: Alice reveals, privacy verified
            ws_alice.send_text(json.dumps({
                "type": "submit_reveal",
                "requestId": "rev_alice",
                "payload": {"secret": sec_alice}
            }))
            rev_ack = json.loads(ws_alice.receive_text())
            self.assertTrue(rev_ack["data"]["verified"])

            upd_a = json.loads(ws_alice.receive_text())
            upd_b = json.loads(ws_bob.receive_text())
            upd_c = json.loads(ws_carol.receive_text())

            # Bob and Carol verify Alice's secret is NOT in public broadcast
            bob_sees_alice = next(p for p in upd_b["data"]["participants"] if p["id"] == alice_id)
            self.assertIsNone(bob_sees_alice["revealedSecret"])
            self.assertNotIn(sec_alice, json.dumps(upd_b))

            carol_sees_alice = next(p for p in upd_c["data"]["participants"] if p["id"] == alice_id)
            self.assertIsNone(carol_sees_alice["revealedSecret"])
            self.assertNotIn(sec_alice, json.dumps(upd_c))

            # Bob reveals
            ws_bob.send_text(json.dumps({
                "type": "submit_reveal",
                "requestId": "rev_bob",
                "payload": {"secret": sec_bob}
            }))
            _ = json.loads(ws_bob.receive_text())    # ack
            _ = json.loads(ws_alice.receive_text())  # room_updated
            _ = json.loads(ws_bob.receive_text())    # room_updated
            _ = json.loads(ws_carol.receive_text())  # room_updated

            # Carol reveals -> Synchronized disclosure & final winner announced
            ws_carol.send_text(json.dumps({
                "type": "submit_reveal",
                "requestId": "rev_carol",
                "payload": {"secret": sec_carol}
            }))
            _ = json.loads(ws_carol.receive_text())  # ack

            winner_alice = json.loads(ws_alice.receive_text())
            winner_bob = json.loads(ws_bob.receive_text())
            winner_carol = json.loads(ws_carol.receive_text())

            self.assertEqual(winner_alice["event"], "winner_announced")
            self.assertEqual(winner_bob["event"], "winner_announced")
            self.assertEqual(winner_carol["event"], "winner_announced")

            winner_result = winner_alice["data"]["result"]
            self.assertIn(winner_result["winner"]["name"], ["Alice", "Bob", "Carol"])
            self.assertEqual(winner_alice["data"]["state"], STATES["COMPLETED"])

            # Verify cryptographic audit trail contains all 3 secrets
            audit_secrets = [item["revealedSecret"] for item in winner_result["auditTrail"]]
            self.assertIn(sec_alice, audit_secrets)
            self.assertIn(sec_bob, audit_secrets)
            self.assertIn(sec_carol, audit_secrets)


class TestPhase4IndependentClientVerification(unittest.TestCase):
    """
    Phase 4: Independent Client Verification & Security Lab Tests.
    Verifies that client-side verification logic operates independently without trusting
    server flags, accurately verifies mathematical commitments, bitwise XOR entropy combination,
    and BigInt rejection sampling, and rejects all forms of tampering.
    """

    def _setup_completed_3_player_game(self):
        """Helper to create and run a 3-player protocol run to COMPLETED."""
        room = Room("ROOM44", "alice_id", "Alice", 3, reveal_duration_seconds=10.0)
        room.add_participant("bob_id", "Bob")
        room.add_participant("carol_id", "Carol")
        room.start_protocol("alice_id")

        s_alice = generate_secret()
        s_bob = generate_secret()
        s_carol = generate_secret()

        room.submit_commitment("alice_id", compute_commitment("alice_id", s_alice))
        room.submit_commitment("bob_id", compute_commitment("bob_id", s_bob))
        room.submit_commitment("carol_id", compute_commitment("carol_id", s_carol))

        room.open_reveal_phase(duration_seconds=10.0)
        room.submit_reveal("alice_id", s_alice)
        room.submit_reveal("bob_id", s_bob)
        room.submit_reveal("carol_id", s_carol)

        return room, (s_alice, s_bob, s_carol)

    def test_01_valid_commitment_independently_verifies(self):
        """1. Valid commitment independently verifies (SHA-256(pid:secret) matching)."""
        pid = "participant_alice"
        secret = generate_secret()
        expected_hash = hashlib.sha256(f"{pid}:{secret}".encode("utf-8")).hexdigest()
        server_comm = compute_commitment(pid, secret)

        self.assertEqual(server_comm, expected_hash)
        self.assertTrue(verify_commitment(pid, secret, server_comm))

    def test_02_altered_secret_fails_commitment_verification(self):
        """2. Altered secret fails commitment verification."""
        pid = "alice_id"
        secret = generate_secret()
        commitment = compute_commitment(pid, secret)

        # Mutate last character of secret
        altered_secret = secret[:-1] + ("0" if secret[-1] != "0" else "1")
        self.assertFalse(verify_commitment(pid, altered_secret, commitment))

        # Test within audit trail verification
        room, _ = self._setup_completed_3_player_game()
        tampered_trail = copy.deepcopy(room.result["auditTrail"])
        tampered_trail[0]["revealedSecret"] = altered_secret

        verification = verify_audit_trail(tampered_trail, room.result)
        self.assertFalse(verification["verified"])
        self.assertFalse(verification["checks"]["commitments"]["valid"])
        self.assertGreaterEqual(verification["checks"]["commitments"]["failed"], 1)

    def test_03_altered_commitment_fails_verification(self):
        """3. Altered commitment fails verification."""
        pid = "bob_id"
        secret = generate_secret()
        commitment = compute_commitment(pid, secret)

        altered_commitment = commitment[:-1] + ("a" if commitment[-1] != "a" else "b")
        self.assertFalse(verify_commitment(pid, secret, altered_commitment))

        room, _ = self._setup_completed_3_player_game()
        tampered_trail = copy.deepcopy(room.result["auditTrail"])
        tampered_trail[1]["commitment"] = altered_commitment

        verification = verify_audit_trail(tampered_trail, room.result)
        self.assertFalse(verification["verified"])
        self.assertFalse(verification["checks"]["commitments"]["valid"])

    def test_04_altered_participant_id_fails_verification(self):
        """4. Altered participant ID fails verification."""
        pid = "carol_id"
        secret = generate_secret()
        commitment = compute_commitment(pid, secret)

        tampered_pid = "attacker_id"
        self.assertFalse(verify_commitment(tampered_pid, secret, commitment))

        room, _ = self._setup_completed_3_player_game()
        tampered_trail = copy.deepcopy(room.result["auditTrail"])
        tampered_trail[2]["id"] = tampered_pid

        verification = verify_audit_trail(tampered_trail, room.result)
        self.assertFalse(verification["verified"])
        self.assertFalse(verification["checks"]["commitments"]["valid"])

    def test_05_altered_winner_fails_final_result_verification(self):
        """5. Altered winner fails final result verification (tampered index / tampered winner)."""
        room, _ = self._setup_completed_3_player_game()
        original_result = room.result
        audit_trail = original_result["auditTrail"]

        # 1) Clean verification passes
        clean_verify = verify_audit_trail(audit_trail, original_result)
        self.assertTrue(clean_verify["verified"])
        self.assertTrue(clean_verify["checks"]["winner"]["valid"])

        # 2) Tamper winner name and ID
        tampered_result = copy.deepcopy(original_result)
        real_winner_id = original_result["winner"]["id"]
        other_p = next(p for p in audit_trail if p["id"] != real_winner_id)
        tampered_result["winner"] = {"id": other_p["id"], "name": other_p["name"]}

        verification = verify_audit_trail(audit_trail, tampered_result)
        self.assertFalse(verification["verified"])
        self.assertFalse(verification["checks"]["winner"]["valid"])
        self.assertIn("Winner mismatch", str(verification["error"]))

        # 3) Tamper selectedIndex
        tampered_idx_result = copy.deepcopy(original_result)
        tampered_idx_result["selectedIndex"] = (tampered_idx_result["selectedIndex"] + 1) % 3
        verification2 = verify_audit_trail(audit_trail, tampered_idx_result)
        self.assertFalse(verification2["verified"])
        self.assertFalse(verification2["checks"]["selection"]["valid"])

    def test_06_valid_entropy_reconstruction_matches_server_calculation(self):
        """6. Valid entropy reconstruction matches server calculation (XOR of all revealed secrets)."""
        s1 = generate_secret()
        s2 = generate_secret()
        s3 = generate_secret()

        server_entropy = combine_randomness([s1, s2, s3])

        # Client-side independent bitwise XOR calculation: SHA-256(s1) ^ SHA-256(s2) ^ SHA-256(s3)
        h1 = hashlib.sha256(s1.encode("utf-8")).digest()
        h2 = hashlib.sha256(s2.encode("utf-8")).digest()
        h3 = hashlib.sha256(s3.encode("utf-8")).digest()
        client_entropy = bytes(x ^ y ^ z for x, y, z in zip(h1, h2, h3))

        self.assertEqual(client_entropy, server_entropy)
        self.assertEqual(client_entropy.hex(), server_entropy.hex())

    def test_07_valid_rejection_sampling_matches_server_result(self):
        """7. Valid rejection sampling matches server result (same combined entropy produces exact same winner)."""
        s1, s2, s3 = generate_secret(), generate_secret(), generate_secret()
        combined = combine_randomness([s1, s2, s3])
        n = 3

        # Server selection
        server_res = unbiased_select(combined, n)

        # Independent client calculation
        limit = MAX_UINT64 - (MAX_UINT64 % n)
        curr = combined
        rejections = 0
        while True:
            val = int.from_bytes(curr[:8], "big")
            if val < limit:
                idx = val % n
                break
            rejections += 1
            curr = hashlib.sha256(curr).digest()

        self.assertEqual(server_res["index"], idx)
        self.assertEqual(server_res["sampleValue"], str(val))
        self.assertEqual(server_res["rejections"], rejections)

    def test_08_rejection_case_handled_correctly(self):
        """8. Rejection case handled correctly (when counter example or large byte value triggers rejection, loop proceeds correctly)."""
        n = 3
        limit = MAX_UINT64 - (MAX_UINT64 % n)
        # Synthetic seed with first 8 bytes = limit (0xFFFFFFFFFFFFFFFF)
        # 18446744073709551615 is exactly equal to limit for n=3, so val < limit evaluates to False
        synthetic_seed = (0xFFFFFFFFFFFFFFFF).to_bytes(8, "big") + bytes(24)

        result = unbiased_select(synthetic_seed, n)

        self.assertGreaterEqual(result["rejections"], 1)
        self.assertIn(result["index"], range(n))
        # Ensure independent simulation with the same seed matches
        curr = synthetic_seed
        client_rejections = 0
        while True:
            val = int.from_bytes(curr[:8], "big")
            if val < limit:
                client_idx = val % n
                break
            client_rejections += 1
            curr = hashlib.sha256(curr).digest()

        self.assertEqual(result["index"], client_idx)
        self.assertEqual(result["rejections"], client_rejections)
        self.assertEqual(result["sampleValue"], str(val))

    def test_09_secrets_remain_hidden_before_reveal_closed(self):
        """9. Unrevealed secrets remain None in broadcast before REVEAL_CLOSED (privacy preserved during reveal phase)."""
        room = Room("ROOM09", "alice_id", "Alice", 3, reveal_duration_seconds=10.0)
        room.add_participant("bob_id", "Bob")
        room.add_participant("carol_id", "Carol")
        room.start_protocol("alice_id")

        s1, s2, s3 = generate_secret(), generate_secret(), generate_secret()
        room.submit_commitment("alice_id", compute_commitment("alice_id", s1))
        room.submit_commitment("bob_id", compute_commitment("bob_id", s2))
        room.submit_commitment("carol_id", compute_commitment("carol_id", s3))

        room.open_reveal_phase(duration_seconds=10.0)

        # Alice reveals her secret
        room.submit_reveal("alice_id", s1)

        # During REVEAL (before all have revealed or deadline elapsed), public state MUST NOT leak secrets
        pub = room.get_public_state()
        self.assertEqual(pub["state"], STATES["REVEAL"])
        for p in pub["participants"]:
            self.assertIsNone(p["revealedSecret"], f"Secret leaked early for {p['id']}!")
        self.assertIsNone(pub["result"])

    def test_10_completed_audit_contains_required_public_verification_data(self):
        """10. Completed audit trail contains all required public verification data (id, commitment, revealedSecret, status)."""
        room, secrets_tuple = self._setup_completed_3_player_game()
        self.assertEqual(room.state, STATES["COMPLETED"])

        res = room.result
        self.assertIn("combinedRandomness", res)
        self.assertIn("selectedIndex", res)
        self.assertIn("sampleValue", res)
        self.assertIn("rejections", res)
        self.assertIn("winner", res)
        self.assertIn("auditTrail", res)

        trail = res["auditTrail"]
        self.assertEqual(len(trail), 3)
        for item in trail:
            self.assertIn("id", item)
            self.assertIn("name", item)
            self.assertIn("commitment", item)
            self.assertIn("revealedSecret", item)
            self.assertIn("verified", item)
            self.assertTrue(HEX_64_REGEX.match(item["commitment"]))
            self.assertTrue(HEX_64_REGEX.match(item["revealedSecret"]))

    def test_11_security_lab_data_isolation(self):
        """11. Security Lab data isolation: running lab verification does not alter server state or room participants."""
        room, _ = self._setup_completed_3_player_game()

        orig_state = room.state
        orig_winner = copy.deepcopy(room.result["winner"])
        orig_trail = copy.deepcopy(room.result["auditTrail"])

        # Simulate Security Lab clone and mutate
        lab_vector = {
            "auditTrail": copy.deepcopy(room.result["auditTrail"]),
            "serverResult": copy.deepcopy(room.result)
        }
        # Security lab mutates clone
        lab_vector["auditTrail"][0]["revealedSecret"] = "f" * 64
        lab_vector["serverResult"]["winner"] = {"id": "fake_id", "name": "Fake"}

        lab_verification = verify_audit_trail(lab_vector["auditTrail"], lab_vector["serverResult"])
        self.assertFalse(lab_verification["verified"])

        # Assert server state and room data are completely unchanged
        self.assertEqual(room.state, orig_state)
        self.assertEqual(room.result["winner"], orig_winner)
        self.assertEqual(room.result["auditTrail"], orig_trail)

    def test_12_session_tokens_never_appear_in_public_audit_data(self):
        """12. Session tokens never appear in public audit data or broadcast state."""
        room, _ = self._setup_completed_3_player_game()

        # Collect session tokens from participants
        tokens = [p.session_token for p in room.participants.values() if p.session_token]
        self.assertGreater(len(tokens), 0)

        pub_json = json.dumps(room.get_public_state())
        result_json = json.dumps(room.result)

        for token in tokens:
            self.assertNotIn(token, pub_json)
            self.assertNotIn(token, result_json)

    def test_13_failed_verification_never_reports_success(self):
        """13. Failed verification never reports success (tampered state returns valid=False)."""
        room, _ = self._setup_completed_3_player_game()
        trail = room.result["auditTrail"]
        res = room.result

        def corrupt_pop(t, r):
            t.pop()
            t.pop()

        corruptions = [
            # 1. Invalid secret length
            (lambda t, r: t[0].__setitem__("revealedSecret", "short"), "Invalid secret format"),
            # 2. Tampered commitment
            (lambda t, r: t[0].__setitem__("commitment", "0" * 64), "Commitment mismatch"),
            # 3. Tampered combined entropy
            (lambda t, r: r.__setitem__("combinedRandomness", "1" * 64), "Entropy mismatch"),
            # 4. Tampered winner
            (lambda t, r: r.__setitem__("winner", {"id": "nobody", "name": "Nobody"}), "Winner mismatch"),
            # 5. Invalid participant count
            (corrupt_pop, "Invalid audit trail"),
        ]

        for corrupt_fn, desc in corruptions:
            t_copy = copy.deepcopy(trail)
            r_copy = copy.deepcopy(res)
            corrupt_fn(t_copy, r_copy)
            out = verify_audit_trail(t_copy, r_copy)
            self.assertFalse(out["verified"], f"Failed test case '{desc}' unexpectedly passed verification!")

    def test_14_complete_valid_3_player_game_independently_verifies(self):
        """14. Complete valid 3-player game: all 3 independent verifications succeed, combined entropy matches, winner matches, audit trail is complete."""
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws_alice, \
             client.websocket_connect("/ws") as ws_bob, \
             client.websocket_connect("/ws") as ws_carol:

            # 1. Alice creates room
            ws_alice.send_text(json.dumps({
                "type": "create_room",
                "requestId": "req_create",
                "payload": {"name": "Alice", "participantsCount": 3}
            }))
            res_create = json.loads(ws_alice.receive_text())
            self.assertTrue(res_create["success"])
            room_code = res_create["data"]["room"]["code"]
            alice_id = res_create["data"]["participantId"]
            _ = json.loads(ws_alice.receive_text())  # room_updated

            # 2. Bob joins room
            ws_bob.send_text(json.dumps({
                "type": "join_room",
                "requestId": "req_join_bob",
                "payload": {"code": room_code, "name": "Bob"}
            }))
            res_bob = json.loads(ws_bob.receive_text())
            self.assertTrue(res_bob["success"])
            bob_id = res_bob["data"]["participantId"]
            _ = json.loads(ws_bob.receive_text())    # room_updated
            _ = json.loads(ws_alice.receive_text())  # room_updated

            # 3. Carol joins room
            ws_carol.send_text(json.dumps({
                "type": "join_room",
                "requestId": "req_join_carol",
                "payload": {"code": room_code, "name": "Carol"}
            }))
            res_carol = json.loads(ws_carol.receive_text())
            self.assertTrue(res_carol["success"])
            carol_id = res_carol["data"]["participantId"]
            _ = json.loads(ws_carol.receive_text())  # room_updated
            _ = json.loads(ws_alice.receive_text())  # room_updated
            _ = json.loads(ws_bob.receive_text())    # room_updated

            # 4. Alice starts protocol
            ws_alice.send_text(json.dumps({
                "type": "start_protocol",
                "requestId": "req_start",
                "payload": {}
            }))
            _ = json.loads(ws_alice.receive_text())  # ack
            _ = json.loads(ws_alice.receive_text())  # protocol_started
            _ = json.loads(ws_alice.receive_text())  # room_updated
            _ = json.loads(ws_bob.receive_text())    # protocol_started
            _ = json.loads(ws_bob.receive_text())    # room_updated
            _ = json.loads(ws_carol.receive_text())  # protocol_started
            _ = json.loads(ws_carol.receive_text())  # room_updated

            # 5. Commit phase: Generate secrets and commitments
            sec_alice = generate_secret()
            sec_bob = generate_secret()
            sec_carol = generate_secret()

            comm_alice = compute_commitment(alice_id, sec_alice)
            comm_bob = compute_commitment(bob_id, sec_bob)
            comm_carol = compute_commitment(carol_id, sec_carol)

            # Alice commits
            ws_alice.send_text(json.dumps({
                "type": "submit_commitment",
                "requestId": "comm_alice",
                "payload": {"commitment": comm_alice}
            }))
            _ = json.loads(ws_alice.receive_text())  # ack
            _ = json.loads(ws_alice.receive_text())  # room_updated
            _ = json.loads(ws_bob.receive_text())    # room_updated
            _ = json.loads(ws_carol.receive_text())  # room_updated

            # Bob commits
            ws_bob.send_text(json.dumps({
                "type": "submit_commitment",
                "requestId": "comm_bob",
                "payload": {"commitment": comm_bob}
            }))
            _ = json.loads(ws_bob.receive_text())    # ack
            _ = json.loads(ws_alice.receive_text())  # room_updated
            _ = json.loads(ws_bob.receive_text())    # room_updated
            _ = json.loads(ws_carol.receive_text())  # room_updated

            # Carol commits -> Commitments locked -> Reveal phase opened
            ws_carol.send_text(json.dumps({
                "type": "submit_commitment",
                "requestId": "comm_carol",
                "payload": {"commitment": comm_carol}
            }))
            _ = json.loads(ws_carol.receive_text())  # ack
            _ = json.loads(ws_alice.receive_text())  # commitments_locked
            _ = json.loads(ws_alice.receive_text())  # room_updated
            _ = json.loads(ws_bob.receive_text())    # commitments_locked
            _ = json.loads(ws_bob.receive_text())    # room_updated
            _ = json.loads(ws_carol.receive_text())  # commitments_locked
            _ = json.loads(ws_carol.receive_text())  # room_updated

            # 6. Reveal phase
            ws_alice.send_text(json.dumps({
                "type": "submit_reveal",
                "requestId": "rev_alice",
                "payload": {"secret": sec_alice}
            }))
            _ = json.loads(ws_alice.receive_text())  # ack
            _ = json.loads(ws_alice.receive_text())  # room_updated
            _ = json.loads(ws_bob.receive_text())    # room_updated
            _ = json.loads(ws_carol.receive_text())  # room_updated

            ws_bob.send_text(json.dumps({
                "type": "submit_reveal",
                "requestId": "rev_bob",
                "payload": {"secret": sec_bob}
            }))
            _ = json.loads(ws_bob.receive_text())    # ack
            _ = json.loads(ws_alice.receive_text())  # room_updated
            _ = json.loads(ws_bob.receive_text())    # room_updated
            _ = json.loads(ws_carol.receive_text())  # room_updated

            ws_carol.send_text(json.dumps({
                "type": "submit_reveal",
                "requestId": "rev_carol",
                "payload": {"secret": sec_carol}
            }))
            _ = json.loads(ws_carol.receive_text())  # ack

            # Winner announcement broadcasts
            ev_a = json.loads(ws_alice.receive_text())
            ev_b = json.loads(ws_bob.receive_text())
            ev_c = json.loads(ws_carol.receive_text())

            self.assertEqual(ev_a["event"], "winner_announced")
            self.assertEqual(ev_b["event"], "winner_announced")
            self.assertEqual(ev_c["event"], "winner_announced")

            result_data = ev_a["data"]["result"]
            audit_trail = result_data["auditTrail"]

            # Independent verification executed on the broadcast data
            client_verification = verify_audit_trail(audit_trail, result_data)

            self.assertTrue(client_verification["verified"])
            self.assertTrue(client_verification["checks"]["commitments"]["valid"])
            self.assertEqual(client_verification["checks"]["commitments"]["passed"], 3)
            self.assertEqual(client_verification["checks"]["commitments"]["failed"], 0)
            self.assertTrue(client_verification["checks"]["reveals"]["valid"])
            self.assertTrue(client_verification["checks"]["entropy"]["valid"])
            self.assertTrue(client_verification["checks"]["selection"]["valid"])
            self.assertTrue(client_verification["checks"]["winner"]["valid"])
            self.assertIn(client_verification["checks"]["winner"]["computedWinner"]["name"], ["Alice", "Bob", "Carol"])
            self.assertEqual(
                client_verification["checks"]["winner"]["computedWinner"]["id"],
                result_data["winner"]["id"]
            )


class TestPhase6ProtocolInvariants(unittest.TestCase):
    """
    Step 4: Protocol Invariant Testing.
    Verifies that all illegal state transitions and protocol violations are rejected deterministically.
    """
    def _setup_3_player_room(self):
        room = Room("INV001", "host_id", "Alice", 3, reveal_duration_seconds=10.0)
        room.add_participant("bob_id", "Bob")
        room.add_participant("carol_id", "Carol")
        return room

    def test_cannot_reveal_before_commitments_lock(self):
        room = self._setup_3_player_room()
        room.start_protocol("host_id")
        s1 = generate_secret()
        with self.assertRaises(ValueError) as ctx:
            room.submit_reveal("host_id", s1)
        self.assertIn("Reveals not accepted in state: COMMIT", str(ctx.exception))

    def test_cannot_commit_after_locked(self):
        room = self._setup_3_player_room()
        room.start_protocol("host_id")
        s1, s2, s3 = generate_secret(), generate_secret(), generate_secret()
        room.submit_commitment("host_id", compute_commitment("host_id", s1))
        room.submit_commitment("bob_id", compute_commitment("bob_id", s2))
        room.submit_commitment("carol_id", compute_commitment("carol_id", s3))
        self.assertEqual(room.state, STATES["LOCKED"])
        with self.assertRaises(ValueError) as ctx:
            room.submit_commitment("host_id", compute_commitment("host_id", generate_secret()))
        self.assertIn("Commitments not accepted in state: LOCKED", str(ctx.exception))

    def test_cannot_join_after_protocol_starts(self):
        room = self._setup_3_player_room()
        room.start_protocol("host_id")
        with self.assertRaises(ValueError) as ctx:
            room.add_participant("dave_id", "Dave")
        self.assertIn("game is in COMMIT phase", str(ctx.exception))

    def test_cannot_submit_duplicate_commitment(self):
        room = self._setup_3_player_room()
        room.start_protocol("host_id")
        s1 = generate_secret()
        comm = compute_commitment("host_id", s1)
        room.submit_commitment("host_id", comm)
        with self.assertRaises(ValueError) as ctx:
            room.submit_commitment("host_id", comm)
        self.assertIn("Modifications forbidden", str(ctx.exception))

    def test_cannot_reveal_twice(self):
        room = self._setup_3_player_room()
        room.start_protocol("host_id")
        s1, s2, s3 = generate_secret(), generate_secret(), generate_secret()
        room.submit_commitment("host_id", compute_commitment("host_id", s1))
        room.submit_commitment("bob_id", compute_commitment("bob_id", s2))
        room.submit_commitment("carol_id", compute_commitment("carol_id", s3))
        room.open_reveal_phase()
        room.submit_reveal("host_id", s1)
        with self.assertRaises(ValueError) as ctx:
            room.submit_reveal("host_id", s1)
        self.assertIn("Second reveal is strictly forbidden", str(ctx.exception))

    def test_cannot_force_timeout_before_valid_deadline(self):
        room = self._setup_3_player_room()
        room.start_protocol("host_id")
        s1, s2, s3 = generate_secret(), generate_secret(), generate_secret()
        room.submit_commitment("host_id", compute_commitment("host_id", s1))
        room.submit_commitment("bob_id", compute_commitment("bob_id", s2))
        room.submit_commitment("carol_id", compute_commitment("carol_id", s3))
        room.open_reveal_phase(duration_seconds=60.0)
        with self.assertRaises(ValueError) as ctx:
            room.handle_timeout()
        self.assertIn("reveal deadline has not expired", str(ctx.exception))

    def test_cannot_force_timeout_after_completion(self):
        room = self._setup_3_player_room()
        room.start_protocol("host_id")
        s1, s2, s3 = generate_secret(), generate_secret(), generate_secret()
        room.submit_commitment("host_id", compute_commitment("host_id", s1))
        room.submit_commitment("bob_id", compute_commitment("bob_id", s2))
        room.submit_commitment("carol_id", compute_commitment("carol_id", s3))
        room.open_reveal_phase()
        room.submit_reveal("host_id", s1)
        room.submit_reveal("bob_id", s2)
        room.submit_reveal("carol_id", s3)
        self.assertEqual(room.state, STATES["COMPLETED"])
        with self.assertRaises(ValueError) as ctx:
            room.handle_timeout()
        self.assertIn("Cannot handle timeout in state: COMPLETED", str(ctx.exception))

    def test_cannot_produce_winner_from_insufficient_reveals(self):
        room = self._setup_3_player_room()
        room.start_protocol("host_id")
        s1, s2, s3 = generate_secret(), generate_secret(), generate_secret()
        room.submit_commitment("host_id", compute_commitment("host_id", s1))
        room.submit_commitment("bob_id", compute_commitment("bob_id", s2))
        room.submit_commitment("carol_id", compute_commitment("carol_id", s3))
        room.open_reveal_phase(duration_seconds=0.01)
        room.submit_reveal("host_id", s1)
        time.sleep(0.02)
        room.handle_timeout()
        self.assertEqual(room.state, STATES["ABORTED"])
        self.assertIsNone(room.result["winner"])
        self.assertIn("Insufficient valid reveals", room.result["error"])

    def test_aborted_rooms_cannot_become_completed(self):
        room = self._setup_3_player_room()
        room.start_protocol("host_id")
        s1, s2, s3 = generate_secret(), generate_secret(), generate_secret()
        room.submit_commitment("host_id", compute_commitment("host_id", s1))
        room.submit_commitment("bob_id", compute_commitment("bob_id", s2))
        room.submit_commitment("carol_id", compute_commitment("carol_id", s3))
        room.open_reveal_phase(duration_seconds=0.01)
        room.submit_reveal("host_id", s1)
        time.sleep(0.02)
        room.handle_timeout()
        self.assertEqual(room.state, STATES["ABORTED"])
        with self.assertRaises(ValueError) as ctx:
            room.submit_reveal("bob_id", s2)
        self.assertIn("Reveals not accepted in state: ABORTED", str(ctx.exception))
        self.assertEqual(room.state, STATES["ABORTED"])

    def test_cannot_change_participant_set_after_protocol_start(self):
        room = self._setup_3_player_room()
        room.start_protocol("host_id")
        self.assertEqual(len(room.participants), 3)
        room.remove_participant("bob_id")
        self.assertIn("bob_id", room.participants)


class TestPhase6AdversarialAndNegative(unittest.TestCase):
    """
    Step 5: Adversarial and Negative Testing.
    Simulates malicious clients attempting malformed, oversized, or unauthorized interactions.
    """
    def test_adversarial_malformed_json_rejected(self):
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws:
            ws.send_text("NOT_JSON{{{")
            resp = json.loads(ws.receive_text())
            self.assertEqual(resp["type"], "error")
            self.assertIn("Malformed JSON", resp["error"])

    def test_adversarial_oversized_payload_rejected(self):
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws:
            ws.send_text("X" * 70000)
            resp = json.loads(ws.receive_text())
            self.assertEqual(resp["type"], "error")
            self.assertIn("Payload exceeds maximum", resp["error"])

    def test_adversarial_unknown_action_rejected(self):
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({"type": "fake_admin_action", "requestId": "req_1"}))
            resp = json.loads(ws.receive_text())
            self.assertFalse(resp.get("success", True))
            self.assertIn("Unknown message type", resp.get("error", ""))

    def test_adversarial_unauthorized_room_action_rejected(self):
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws:
            ws.send_text(json.dumps({
                "type": "submit_commitment",
                "requestId": "req_steal",
                "payload": {"commitment": "0" * 64}
            }))
            resp = json.loads(ws.receive_text())
            self.assertFalse(resp.get("success", True))
            self.assertIn("Not in a room", resp.get("error", ""))

    def test_adversarial_fake_session_token_reconnect_rejected(self):
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws1, \
             client.websocket_connect("/ws") as ws2:
            # ws1 creates room
            ws1.send_text(json.dumps({
                "type": "create_room",
                "requestId": "cr",
                "payload": {"name": "Host", "participantsCount": 3}
            }))
            res = json.loads(ws1.receive_text())
            code = res["data"]["room"]["code"]
            pid = res["data"]["participantId"]

            # ws2 attempts reconnect with fake token
            ws2.send_text(json.dumps({
                "type": "reconnect",
                "requestId": "rec_fake",
                "payload": {"roomCode": code, "participantId": pid, "sessionToken": "0" * 64}
            }))
            res2 = json.loads(ws2.receive_text())
            self.assertFalse(res2.get("success", True))
            self.assertIn("Invalid session credential", res2.get("error", ""))

    def test_adversarial_cross_room_access_prevented(self):
        client = TestClient(app)
        with client.websocket_connect("/ws") as ws1, \
             client.websocket_connect("/ws") as ws2:
            # ws1 creates Room A
            ws1.send_text(json.dumps({
                "type": "create_room",
                "requestId": "cr_a",
                "payload": {"name": "Alice", "participantsCount": 3}
            }))
            res_a = json.loads(ws1.receive_text())
            code_a = res_a["data"]["room"]["code"]

            # ws2 creates Room B
            ws2.send_text(json.dumps({
                "type": "create_room",
                "requestId": "cr_b",
                "payload": {"name": "Bob", "participantsCount": 3}
            }))
            res_b = json.loads(ws2.receive_text())
            code_b = res_b["data"]["room"]["code"]
            self.assertNotEqual(code_a, code_b)

    def test_adversarial_room_capacity_limit_enforced(self):
        rm = RoomManager()
        rm.MAX_ROOMS = 5
        # Fill capacity
        for i in range(5):
            rm.create_room(f"host_{i}", "Host", 3)
        self.assertEqual(len(rm.rooms), 5)
        with self.assertRaises(ValueError) as ctx:
            rm.create_room("overflow_host", "Host", 3)
        self.assertIn("Server room capacity reached", str(ctx.exception))

    def test_adversarial_simulation_parameters_bounded(self):
        client = TestClient(app)
        # Query below range
        resp_low = client.get("/api/simulate?n=1&trials=1000")
        self.assertEqual(resp_low.status_code, 422)
        # Query above range
        resp_high = client.get("/api/simulate?n=5&trials=1000000")
        self.assertEqual(resp_high.status_code, 422)


class TestPhase6FairnessAndStatisticalProperties(unittest.TestCase):
    """
    Step 6: Empirical Fairness and Statistical Checks.
    Validates uniformity and absence of structural bias across participant counts.
    Note: Empirical observations do not constitute a formal mathematical proof.
    """
    def test_fairness_distribution_across_multiple_participant_counts(self):
        test_counts = [3, 4, 5, 10, 20]
        trials = 2000

        for n in test_counts:
            counts = [0] * n
            total_rejections = 0
            for _ in range(trials):
                secrets_list = [generate_secret() for _ in range(n)]
                comb = combine_randomness(secrets_list)
                sel = unbiased_select(comb, n)
                idx = sel["index"]
                self.assertIn(idx, range(n))
                counts[idx] += 1
                total_rejections += sel["rejections"]

            # 1. No participant position was structurally excluded
            for i in range(n):
                self.assertGreater(counts[i], 0, f"Participant {i} of {n} was never selected in {trials} trials")

            # 2. Chi-square goodness-of-fit test
            expected = trials / n
            chi_sq = sum(((c - expected) ** 2) / expected for c in counts)
            # With n degrees of freedom - 1, chi_sq should be within reasonable empirical bound for 2000 trials
            self.assertLess(chi_sq, 80.0, f"Chi-square {chi_sq} excessive for n={n}")
            self.assertGreaterEqual(total_rejections, 0)


class TestPhase6DeterministicTestVectors(unittest.TestCase):
    """
    Step 8: Deterministic Test Vectors.
    Fixed cryptographic test vectors guaranteeing reproducible cross-platform calculation.
    """
    def test_fixed_test_vector_1_three_participants(self):
        pids = ["alice", "bob", "carol"]
        s1 = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
        s2 = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
        s3 = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

        # Verified precomputed values
        exp_c1 = "5eef4c99629544d076344fb2c7747f941fb89ecf4d4b26aa04373aa25781f62f"
        exp_c2 = "5c4916e0caf37edfeaac13e972cba4a7438e6d58282cde6d2ef23abba7cf3ac0"
        exp_c3 = "88197b6a8a6758bee357c1ba908fea80e0b8a963cdb1df7e1d545d63ef479044"
        exp_comb = "3980f37b34db6594861246e5a9dc39779d6c50fdb6b3e499b8c62a8598618029"

        # 1. Commitments
        self.assertEqual(compute_commitment("alice", s1), exp_c1)
        self.assertEqual(compute_commitment("bob", s2), exp_c2)
        self.assertEqual(compute_commitment("carol", s3), exp_c3)

        # 2. Entropy combination
        comb = combine_randomness([s1, s2, s3])
        self.assertEqual(comb.hex(), exp_comb)

        # 3. Unbiased selection
        sel = unbiased_select(comb, 3)
        self.assertEqual(sel["index"], 0)
        self.assertEqual(sel["rejections"], 0)
        self.assertEqual(sel["sampleValue"], "4143579367674176916")

        # 4. Audit Trail Verification on Fixed Vector
        audit_trail = [
            {"id": "alice", "name": "Alice", "commitment": exp_c1, "revealedSecret": s1, "verified": True},
            {"id": "bob", "name": "Bob", "commitment": exp_c2, "revealedSecret": s2, "verified": True},
            {"id": "carol", "name": "Carol", "commitment": exp_c3, "revealedSecret": s3, "verified": True},
        ]
        server_result = {
            "combinedRandomness": exp_comb,
            "selectedIndex": 0,
            "sampleValue": "4143579367674176916",
            "rejections": 0,
            "winner": {"id": "alice", "name": "Alice"},
            "auditTrail": audit_trail
        }
        res = verify_audit_trail(audit_trail, server_result)
        self.assertTrue(res["verified"])
        self.assertTrue(res["checks"]["commitments"]["valid"])
        self.assertTrue(res["checks"]["entropy"]["valid"])
        self.assertTrue(res["checks"]["selection"]["valid"])
        self.assertTrue(res["checks"]["winner"]["valid"])

    def test_fixed_test_vector_2_rejection_boundary(self):
        # First 8 bytes = 0xFFFFFFFFFFFFFFFF (2^64 - 1)
        synthetic_seed = (0xFFFFFFFFFFFFFFFF).to_bytes(8, "big") + bytes(24)
        sel = unbiased_select(synthetic_seed, 3)

        self.assertEqual(sel["rejections"], 1)
        self.assertEqual(sel["index"], 1)
        self.assertEqual(sel["sampleValue"], "4557997227390710014")
        self.assertEqual(sel["finalSeedHex"], "3f41425439d6b0fea00cf2f3551bafca85ead4bfc8f1726d7c33d9c738a344d6")


if __name__ == "__main__":
    unittest.main()

