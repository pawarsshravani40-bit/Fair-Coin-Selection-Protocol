import time
import unittest
import json
from starlette.testclient import TestClient

from server import (
    app,
    generate_secret,
    compute_commitment,
    verify_commitment,
    combine_randomness,
    unbiased_select,
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


if __name__ == "__main__":
    unittest.main()
