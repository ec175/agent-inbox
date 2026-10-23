# SPDX-License-Identifier: MIT
# agent-inbox by Ethan Earl - https://github.com/ec175/agent-inbox
"""Offline tests: the published BIP-340 and NIP-44 v2 vectors, plus message round trips.

    python -m unittest discover -s tests
"""
import csv
import hashlib
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import agent_inbox as ai  # noqa: E402

VEC = os.path.join(HERE, "vectors")
with open(os.path.join(VEC, "nip44.vectors.json"), encoding="utf-8") as f:
    N44 = json.load(f)["v2"]


class BIP340(unittest.TestCase):
    def test_vectors(self):
        with open(os.path.join(VEC, "bip340.csv"), encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        self.assertGreater(len(rows), 10)
        for r in rows:
            msg = bytes.fromhex(r["message"])
            pub = bytes.fromhex(r["public key"])
            sig = bytes.fromhex(r["signature"])
            expect = r["verification result"] == "TRUE"
            with self.subTest(index=r["index"]):
                if r["secret key"]:
                    sk = bytes.fromhex(r["secret key"])
                    self.assertEqual(ai.pubkey_of(sk), pub)
                    self.assertEqual(ai.schnorr_sign(msg, sk, bytes.fromhex(r["aux_rand"])), sig)
                self.assertEqual(ai.schnorr_verify(msg, pub, sig), expect)


class NIP44(unittest.TestCase):
    def test_conversation_key(self):
        for v in N44["valid"]["get_conversation_key"]:
            got = ai.conversation_key(bytes.fromhex(v["sec1"]), bytes.fromhex(v["pub2"]))
            self.assertEqual(got.hex(), v["conversation_key"])

    def test_invalid_conversation_key(self):
        for v in N44["invalid"]["get_conversation_key"]:
            with self.subTest(note=v["note"]), self.assertRaises(ValueError):
                ai.conversation_key(bytes.fromhex(v["sec1"]), bytes.fromhex(v["pub2"]))

    def test_message_keys(self):
        mk = N44["valid"]["get_message_keys"]
        ck = bytes.fromhex(mk["conversation_key"])
        for v in mk["keys"]:
            k, n, h = ai.message_keys(ck, bytes.fromhex(v["nonce"]))
            self.assertEqual((k.hex(), n.hex(), h.hex()), (v["chacha_key"], v["chacha_nonce"], v["hmac_key"]))

    def test_padded_len(self):
        for n, want in N44["valid"]["calc_padded_len"]:
            self.assertEqual(ai.padded_len(n), want, n)

    def test_encrypt_decrypt(self):
        for v in N44["valid"]["encrypt_decrypt"]:
            ck = ai.conversation_key(bytes.fromhex(v["sec1"]), ai.pubkey_of(bytes.fromhex(v["sec2"])))
            self.assertEqual(ck.hex(), v["conversation_key"])
            self.assertEqual(ai.nip44_encrypt(v["plaintext"], ck, bytes.fromhex(v["nonce"])), v["payload"])
            self.assertEqual(ai.nip44_decrypt(v["payload"], ck), v["plaintext"])

    def test_long_messages(self):
        for v in N44["valid"]["encrypt_decrypt_long_msg"]:
            pt = v["pattern"] * v["repeat"]
            self.assertEqual(hashlib.sha256(pt.encode()).hexdigest(), v["plaintext_sha256"])
            ck = bytes.fromhex(v["conversation_key"])
            payload = ai.nip44_encrypt(pt, ck, bytes.fromhex(v["nonce"]))
            self.assertEqual(hashlib.sha256(payload.encode()).hexdigest(), v["payload_sha256"])

    def test_invalid_lengths(self):
        ck = os.urandom(32)
        for n in N44["invalid"]["encrypt_msg_lengths"]:
            with self.assertRaises(ValueError):
                ai.nip44_encrypt("a" * n, ck)

    def test_invalid_decrypt(self):
        for v in N44["invalid"]["decrypt"]:
            with self.subTest(note=v["note"]), self.assertRaises(ValueError):
                ai.nip44_decrypt(v["payload"], bytes.fromhex(v["conversation_key"]))


class Messages(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ[ai.HOME_ENV] = self.tmp.name
        self.a = ai.Identity(ai.new_secret(), "alice")
        self.b = ai.Identity(ai.new_secret(), "bob")

    def tearDown(self):
        os.environ.pop(ai.HOME_ENV, None)
        self.tmp.cleanup()

    def test_round_trip(self):
        wrap, rumor = ai.wrap_message(self.a, self.b.pk, "héllo, bob \n line two")
        self.assertTrue(ai.verify_event(wrap))
        self.assertNotEqual(wrap["pubkey"], self.a.pk)          # sender hidden behind a throwaway key
        got = ai.unwrap_message(self.b, wrap)
        self.assertEqual((got["from"], got["text"]), (self.a.pk, "héllo, bob \n line two"))

    def test_outsider_cannot_read(self):
        wrap, _ = ai.wrap_message(self.a, self.b.pk, "secret")
        with self.assertRaises(ValueError):
            ai.unwrap_message(ai.Identity(ai.new_secret(), "eve"), wrap)

    def test_tampered_wrap_rejected(self):
        wrap, _ = ai.wrap_message(self.a, self.b.pk, "x")
        wrap["content"] = wrap["content"][:-4] + "AAA="
        with self.assertRaises(ValueError):
            ai.unwrap_message(self.b, wrap)

    def test_spoofed_sender_rejected(self):
        # Mallory seals a rumor that claims to be from Alice: the signer check must catch it.
        mal = ai.Identity(ai.new_secret(), "mallory")
        rumor = {"pubkey": self.a.pk, "created_at": 1, "kind": 14, "tags": [["p", self.b.pk]], "content": "hi"}
        rumor["id"] = ai.event_id(rumor)
        to = bytes.fromhex(self.b.pk)
        seal = ai.make_event(mal.sk, 13, ai.nip44_encrypt(json.dumps(rumor), ai.conversation_key(mal.sk, to)))
        eph = ai.new_secret()
        wrap = ai.make_event(eph, 1059, ai.nip44_encrypt(json.dumps(seal), ai.conversation_key(eph, to)),
                             [["p", self.b.pk]])
        with self.assertRaises(ValueError):
            ai.unwrap_message(self.b, wrap)

    def test_profile_handle_is_recomputed(self):
        ev = ai.profile_event(self.a)
        handle, prof = ai.parse_profile(ev)
        self.assertEqual(handle, self.a.handle)
        self.assertTrue(handle.endswith("#" + self.a.pk[:8]))

    def test_npub(self):
        # NIP-19 example key
        pk = "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e"
        npub = "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg"
        self.assertEqual(ai.npub_encode(pk), npub)
        self.assertEqual(ai.npub_decode(npub), pk)

    def test_identity_persists(self):
        self.a.save()
        again = ai.Identity.load()
        self.assertEqual((again.pk, again.handle), (self.a.pk, self.a.handle))


if __name__ == "__main__":
    unittest.main()
