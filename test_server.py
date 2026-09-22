import unittest
from server import (
    generate_secret,
    compute_commitment,
    verify_commitment,
    combine_randomness,
    unbiased_select,
    Room,
    RoomManager,
    STATES
)

class TestProtocolCore(unittest.TestCase):
    def test_generate_secret(self):
        s1 = generate_secret()
        s2 = generate_secret()
        self.assertEqual(len(s1), 64)
        self.assertNotEqual(s1, s2)

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

    def test_room_lifecycle(self):
        rm = RoomManager()
        room = rm.create_room("host_1", "Alice", 3)
        self.assertEqual(room.state, STATES["LOBBY"])

        # Bob and Charlie join
        room.add_participant("bob_1", "Bob")
        room.add_participant("charlie_1", "Charlie")
        self.assertEqual(len(room.participants), 3)

        # Host starts selection
        room.start_protocol("host_1")
        self.assertEqual(room.state, STATES["COMMIT"])

        # Secrets & Commitments
        s_alice = generate_secret()
        s_bob = generate_secret()
        s_charlie = generate_secret()

        room.submit_commitment("host_1", compute_commitment("host_1", s_alice))
        room.submit_commitment("bob_1", compute_commitment("bob_1", s_bob))
        self.assertEqual(room.state, STATES["COMMIT"])

        # Charlie commits -> triggers lock -> transitions to REVEAL
        room.submit_commitment("charlie_1", compute_commitment("charlie_1", s_charlie))
        self.assertEqual(room.state, STATES["REVEAL"])

        # Reveals
        room.submit_reveal("host_1", s_alice)
        room.submit_reveal("bob_1", s_bob)
        self.assertEqual(room.state, STATES["REVEAL"])

        room.submit_reveal("charlie_1", s_charlie)
        self.assertEqual(room.state, STATES["COMPLETED"])
        self.assertIsNotNone(room.result)
        self.assertIn(room.result["winner"]["name"], ["Alice", "Bob", "Charlie"])
        self.assertEqual(len(room.result["auditTrail"]), 3)
        print("\nAll unit tests passed successfully!")

if __name__ == "__main__":
    unittest.main()
