# SPDX-License-Identifier: MIT
# agent-inbox by Clancy Earl - https://github.com/ec175/agent-inbox
"""Offline tests: the published BIP-340 and NIP-44 v2 vectors, plus message round trips.

    python -m unittest discover -s tests
"""
import base64
import csv
import hashlib
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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


class Board(unittest.TestCase):
    NOW = 1_800_000_000

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ[ai.HOME_ENV] = self.tmp.name
        self.a = ai.Identity(ai.new_secret(), "alice")
        self.b = ai.Identity(ai.new_secret(), "bob")

    def tearDown(self):
        os.environ.pop(ai.HOME_ENV, None)
        self.tmp.cleanup()

    def post(self, who, text, parent_ev=None, at=None, **kw):
        parent = ai.parse_post(parent_ev) if parent_ev else None
        return ai.post_event(who, text, parent=parent, now=self.NOW if at is None else at, **kw)

    def test_post_tags(self):
        ev = self.post(self.a, "hello board", topic="Intros")
        self.assertEqual(ev["kind"], 30078)
        self.assertNotEqual(ev["kind"], 1)                       # never a social-feed note
        tags = [t[:2] for t in ev["tags"]]
        self.assertIn(["t", "agent-inbox"], tags)
        self.assertIn(["l", "intros"], tags)
        self.assertEqual(ai._tag(ev, "expiration"), str(self.NOW + ai.YEAR))
        self.assertTrue(ai._tag(ev, "d").startswith(ai.BOARD_D))
        self.assertEqual(ev["created_at"], self.NOW)             # real time, unlike DM wraps
        p = ai.parse_post(ev)
        self.assertEqual((p["topic"], p["text"], p["parent"]), ("intros", "hello board", None))

    def test_two_posts_have_distinct_addresses(self):
        a, b = self.post(self.a, "one"), self.post(self.a, "two")
        self.assertNotEqual(ai._tag(a, "d"), ai._tag(b, "d"))

    def test_reply_tags_and_topic_inherited(self):
        root = self.post(self.a, "root", topic="tools")
        r1 = self.post(self.b, "first reply", root, at=self.NOW + 5)
        r2 = self.post(self.a, "reply to the reply", r1, at=self.NOW + 9)
        p1, p2 = ai.parse_post(r1), ai.parse_post(r2)
        self.assertEqual((p1["root"], p1["parent"], p1["topic"]), (root["id"], root["id"], "tools"))
        self.assertEqual((p2["root"], p2["parent"]), (root["id"], r1["id"]))
        posts = ai.board_view([r2, root, r1], now=self.NOW + 60)
        self.assertEqual(posts[root["id"]]["replies"], [r1["id"]])
        order = [(p["id"], d) for p, d in ai.threads(posts)]
        self.assertEqual(order, [(root["id"], 0), (r1["id"], 1), (r2["id"], 2)])

    def test_limits(self):
        with self.assertRaises(SystemExit):
            self.post(self.a, "x" * (ai.MAX_TEXT + 1))
        with self.assertRaises(SystemExit):
            self.post(self.a, "   ")
        with self.assertRaises(SystemExit):
            self.post(self.a, "x", topic="no spaces")
        with self.assertRaises(SystemExit):
            self.post(self.a, "x", days=400)

    def test_rejects_malformed(self):
        ev = self.post(self.a, "real")
        bad_sig = dict(ev, content="edited by a relay")
        self.assertIsNone(ai.parse_post(bad_sig))
        self.assertIsNone(ai.parse_post(dict(ev, kind=1)))
        no_t = ai.make_event(self.a.sk, 30078, "x", [t for t in ev["tags"] if t[0] != "t"], self.NOW)
        self.assertIsNone(ai.parse_post(no_t))
        profile = ai.profile_event(self.a)                        # same kind, not a post
        self.assertIsNone(ai.parse_post(profile))

    def test_hiding(self):
        fresh = ai.parse_post(self.post(self.a, "fresh"))
        self.assertTrue(ai.visible(fresh, self.NOW + 10))
        self.assertFalse(ai.visible(fresh, self.NOW + ai.YEAR + 1))           # a year on
        short = ai.parse_post(self.post(self.a, "short", days=1))
        self.assertFalse(ai.visible(short, self.NOW + 86400 + 1))            # its own expiration
        ahead = ai.parse_post(self.post(self.a, "from the future", at=self.NOW + 3600))
        self.assertFalse(ai.visible(ahead, self.NOW))                         # pinned-to-top trick
        no_exp = ai.make_event(self.a.sk, 30078, "old client",
                               [t for t in self.post(self.a, "x")["tags"] if t[0] != "expiration"],
                               self.NOW - ai.YEAR - 5)
        self.assertFalse(ai.visible(ai.parse_post(no_exp), self.NOW))

    def test_edit_keeps_thread(self):
        root = self.post(self.a, "v1")
        reply = self.post(self.b, "answer", root, at=self.NOW + 5)
        v2 = ai.make_event(self.a.sk, 30078, "v2", root["tags"], self.NOW + 10)   # same address
        posts = ai.board_view([root, reply, v2], now=self.NOW + 60)
        self.assertNotIn(root["id"], posts)
        self.assertTrue(posts[v2["id"]]["edited"])
        self.assertEqual(posts[v2["id"]]["replies"], [reply["id"]])
        self.assertEqual(posts[reply["id"]]["parent"], v2["id"])

    def test_archive_dedupes_and_survives_torn_lines(self):
        e1, e2 = self.post(self.a, "one"), self.post(self.b, "two")
        self.assertEqual(len(ai.archive_add([e1, e2])), 2)
        self.assertEqual(ai.archive_add([e1, e2]), [])
        with open(ai._archive_path(), "a", encoding="utf-8") as f:
            f.write('{"id": "torn')
        self.assertEqual(set(ai.archive_load()), {e1["id"], e2["id"]})
        self.assertEqual(ai.archive_add([{"kind": 1, "id": "f" * 64}]), [])   # not a post: refused

    def test_find_post_by_prefix(self):
        root = self.post(self.a, "root", at=int(ai.time.time()))
        ai.archive_add([root])
        self.assertEqual(ai.find_post(root["id"][:10], online=False)["id"], root["id"])
        with self.assertRaises(SystemExit):
            ai.find_post("abc", online=False)                  # too short to mean anything

    def test_rate_limit(self):
        t = 1_000_000.0
        ai.rate_note(ai.rate_check(t), t)
        with self.assertRaises(SystemExit):
            ai.rate_check(t + ai.POST_MIN_GAP - 1)
        recent = ai.rate_check(t + ai.POST_MIN_GAP)
        for i in range(ai.POST_MAX_PER_HOUR - 1):
            recent.append(t + 1 + i)
        ai.rate_note(recent, t + 100)
        with self.assertRaises(SystemExit):
            ai.rate_check(t + 200)
        self.assertEqual(ai.rate_check(t + 4000), [])           # an hour later, all clear

    def test_parse_since(self):
        self.assertEqual(ai.parse_since("2d", now=self.NOW), self.NOW - 2 * 86400)
        self.assertEqual(ai.parse_since("2026-10-23"), 1792713600)
        with self.assertRaises(SystemExit):
            ai.parse_since("yesterday")


class Viewer(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ[ai.HOME_ENV] = self.tmp.name

    def tearDown(self):
        os.environ.pop(ai.HOME_ENV, None)
        self.tmp.cleanup()

    def test_hostile_text_is_escaped(self):
        mal = ai.Identity(ai.new_secret(), "mallory")
        evil = '<script>alert(1)</script><img src=x onerror=alert(2)>'
        ev = ai.post_event(mal, evil, now=int(ai.time.time()))
        posts = ai.board_view([ev])
        page = ai.render_board(posts, {mal.pk: '<b>mallory</b>#1234'})
        self.assertNotIn("<script>alert", page)
        self.assertNotIn("<img src=x", page)
        self.assertNotIn("<b>mallory", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertIn(ai.html.escape(ai.UNTRUSTED), page)
        dms = ai.render_dms([{"dir": "in", "from": mal.pk, "at": 1, "text": evil}], {})
        self.assertNotIn("<script>alert", dms)

    def test_deep_chain_does_not_recurse(self):
        me = ai.Identity(ai.new_secret(), "deep")
        now = int(ai.time.time()) - 5000
        evs = [ai.post_event(me, "0", now=now)]
        for i in range(1, 1500):                         # deeper than Python's recursion limit
            parent = ai.parse_post(evs[-1], verify=False)    # unsigned: the view trusts the archive
            evs.append({"id": "%064x" % i, "pubkey": me.pk, "created_at": now + i, "kind": 30078,
                        "content": str(i), "sig": "0" * 128,
                        "tags": [["d", ai.BOARD_D + "%016x" % i], ["t", ai.APP],
                                 ["e", parent["root"] or parent["id"], "", "root"],
                                 ["e", parent["id"], "", "reply"]]})
        rows = ai.threads(ai.board_view(evs))
        self.assertEqual(len(rows), 1500)
        self.assertEqual(rows[-1][1], 1499)

    def test_host_check(self):
        self.assertTrue(ai.host_ok("127.0.0.1:8803", 8803))
        self.assertTrue(ai.host_ok("localhost:8803", 8803))
        self.assertFalse(ai.host_ok("evil.example:8803", 8803))      # DNS rebinding
        self.assertFalse(ai.host_ok(None, 8803))

    def test_server_round_trip(self):
        import http.client
        import threading
        srv = ai.ThreadingHTTPServer(("127.0.0.1", 0), ai.ViewerHandler)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            me = ai.Identity(ai.new_secret(), "poster")
            ai.archive_add([ai.post_event(me, "visible in the viewer", now=int(ai.time.time()))])
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("GET", "/")
            r = c.getresponse()
            body = r.read().decode()
            self.assertEqual(r.status, 200)
            self.assertIn("visible in the viewer", body)
            self.assertIn("default-src 'none'", r.getheader("Content-Security-Policy"))
            c.request("GET", "/dm")
            self.assertEqual(c.getresponse().status, 200)
            c.request("GET", "/", headers={"Host": "attacker.example:%d" % port})
            self.assertEqual(c.getresponse().status, 403)
            c.request("POST", "/", body=b"x")
            self.assertEqual(c.getresponse().status, 501)                 # read-only
        finally:
            srv.shutdown()
            srv.server_close()


def _read(path):
    with open(path, "rb") as f:
        return f.read()


class AESGCM(unittest.TestCase):
    """FIPS-197 and the AES-256 cases of the GCM spec (McGrew & Viega, test cases 13-16)."""
    K = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
    IV = bytes.fromhex("cafebabefacedbaddecaf888")
    P = bytes.fromhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                      "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
    C = bytes.fromhex("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                      "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad")

    def test_fips197_block(self):
        self.assertEqual(ai.aes256_encrypt_block(bytes(range(32)), bytes.fromhex("00112233445566778899aabbccddeeff")).hex(),
                         "8ea2b7ca516745bfeafc49904b496089")

    def test_gcm_vectors(self):
        z, n = bytes(32), bytes(12)
        self.assertEqual(ai.aes_gcm_encrypt(z, n, b"").hex(), "530f8afbc74536b9a963b4f1c4cb738b")
        self.assertEqual(ai.aes_gcm_encrypt(z, n, bytes(16)).hex(),
                         "cea7403d4d606b6e074ec5d3baf39d18" "d0d1c8a799996bf0265b98b5d48ab919")
        self.assertEqual(ai.aes_gcm_encrypt(self.K, self.IV, self.P), self.C + bytes.fromhex("b094dac5d93471bdec1a502270e3cc6c"))
        aad = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        self.assertEqual(ai.aes_gcm_encrypt(self.K, self.IV, self.P[:60], aad),
                         self.C[:60] + bytes.fromhex("76fc6ece0f4e1768cddf8853bb2d551b"))

    def test_table_ghash_matches_bitwise(self):
        h = int.from_bytes(os.urandom(16), "big")
        tables = ai._ghash_tables(h)
        for _ in range(20):
            x = int.from_bytes(os.urandom(16), "big")
            y = 0
            for pos in range(16):
                y ^= tables[pos][(x >> (8 * (15 - pos))) & 0xFF]
            self.assertEqual(y, ai._gf_mul(x, h))

    def test_round_trip_and_tamper(self):
        key, nonce = os.urandom(32), os.urandom(12)
        for size in (0, 1, 15, 16, 17, 1000):
            data = os.urandom(size)
            blob = ai.aes_gcm_encrypt(key, nonce, data)
            self.assertEqual(ai.aes_gcm_decrypt(key, nonce, blob), data)
        bad = bytearray(ai.aes_gcm_encrypt(key, nonce, b"hello world"))
        bad[3] ^= 1
        with self.assertRaises(ValueError):
            ai.aes_gcm_decrypt(key, nonce, bytes(bad))
        with self.assertRaises(ValueError):
            ai.aes_gcm_decrypt(os.urandom(32), nonce, ai.aes_gcm_encrypt(key, nonce, b"x"))


class _Blossom(BaseHTTPRequestHandler):
    """A minimal BUD-01/02 server: checks the kind-24242 authorization, stores by sha256."""
    store = {}

    def log_message(self, *a):
        pass

    def do_PUT(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        sha = hashlib.sha256(body).hexdigest()
        try:
            auth = self.headers.get("Authorization", "")
            ev = json.loads(base64.b64decode(auth.split(" ", 1)[1]))
            tags = {t[0]: t[1] for t in ev["tags"]}
            assert auth.startswith("Nostr ") and ai.verify_event(ev) and ev["kind"] == 24242
            assert tags["t"] == "upload" and tags["x"] == sha and int(tags["expiration"]) > time.time()
        except Exception:
            self.send_response(401)
            self.end_headers()
            return
        self.store[sha] = body
        desc = json.dumps({"url": "http://127.0.0.1:%d/%s" % (self.server.server_port, sha), "sha256": sha,
                           "size": len(body), "type": "application/octet-stream", "uploaded": int(time.time())}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(desc)))
        self.end_headers()
        self.wfile.write(desc)

    def do_GET(self):
        body = self.store.get(self.path.strip("/"))
        self.send_response(200 if body is not None else 404)
        self.end_headers()
        if body is not None:
            self.wfile.write(body)


class Files(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ[ai.HOME_ENV] = self.tmp.name
        self.a = ai.Identity(ai.new_secret(), "alice")
        self.b = ai.Identity(ai.new_secret(), "bob")
        self.sent = []
        self._orig = (ai.publish_all, ai.dm_relays_of)
        ai.publish_all = lambda urls, ev, ident=None: (self.sent.append(ev), {"wss://test": (True, "")})[1]
        ai.dm_relays_of = lambda pk: []
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), _Blossom)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.server = "http://127.0.0.1:%d" % self.srv.server_port

    def tearDown(self):
        ai.publish_all, ai.dm_relays_of = self._orig
        self.srv.shutdown()
        self.srv.server_close()
        os.environ.pop(ai.HOME_ENV, None)
        self.tmp.cleanup()

    def _file(self, size, name="kit.zip"):
        p = os.path.join(self.tmp.name, name)
        with open(p, "wb") as f:
            f.write(os.urandom(size))
        return p

    def _deliver(self, path, **kw):
        res, rumor, info = ai.send_file(self.a, self.b.pk, path, **kw)
        got = ai.unwrap_message(self.b, self.sent[-1])
        return got, info

    def test_small_file_travels_inline(self):
        path = self._file(5000)
        got, info = self._deliver(path)
        self.assertEqual(got["from"], self.a.pk)
        self.assertTrue(got["file"]["url"].startswith("data:"))
        self.assertIn("[file] kit.zip", got["text"])
        out = ai.fetch_file(got["file"], os.path.join(self.tmp.name, "out"))
        self.assertEqual(_read(out), _read(path))

    def test_large_file_goes_as_a_blob(self):
        path = self._file(40000)
        got, info = self._deliver(path, servers=[self.server])
        self.assertTrue(got["file"]["url"].startswith(self.server))
        stored = _Blossom.store[got["file"]["x"]]
        self.assertNotIn(_read(path)[:64], stored)          # the server only ever sees ciphertext
        out = ai.fetch_file(got["file"], os.path.join(self.tmp.name, "out"))
        self.assertEqual(_read(out), _read(path))

    def test_kind15_tags(self):
        got, info = self._deliver(self._file(100), )
        rumor_kind = json.loads(ai.nip44_decrypt(
            json.loads(ai.nip44_decrypt(self.sent[-1]["content"], ai.conversation_key(
                self.b.sk, bytes.fromhex(self.sent[-1]["pubkey"]))))["content"],
            ai.conversation_key(self.b.sk, bytes.fromhex(self.a.pk))))
        self.assertEqual(rumor_kind["kind"], 15)
        names = [t[0] for t in rumor_kind["tags"]]
        for t in ("p", "file-type", "encryption-algorithm", "decryption-key", "decryption-nonce", "x", "ox", "size"):
            self.assertIn(t, names)

    def test_tampered_blob_refused(self):
        got, _ = self._deliver(self._file(40000), servers=[self.server])
        x = got["file"]["x"]
        _Blossom.store[x] = _Blossom.store[x][:-1] + bytes([_Blossom.store[x][-1] ^ 1])
        with self.assertRaises(SystemExit):
            ai.fetch_file(got["file"], os.path.join(self.tmp.name, "out"))

    def test_unauthorised_upload_refused_by_server(self):
        with self.assertRaises(SystemExit):   # a bad authorization: the server answers 401, no server took it
            orig = ai.blossom_auth
            ai.blossom_auth = lambda me, sha, verb="upload", ttl=600: "Nostr e30="
            try:
                ai.blossom_upload(self.a, b"x" * 100, [self.server])
            finally:
                ai.blossom_auth = orig

    def test_hostile_name_is_sanitised(self):
        got, info = self._deliver(self._file(10, name="evil.zip"))
        got["file"]["name"] = "../../../windows/system32/x.exe"
        out = ai.fetch_file(got["file"], os.path.join(self.tmp.name, "out"))
        self.assertTrue(os.path.realpath(out).startswith(os.path.realpath(os.path.join(self.tmp.name, "out"))))

    def test_malformed_file_message_rejected(self):
        rumor = {"pubkey": self.a.pk, "created_at": 1, "kind": 15, "tags": [["p", self.b.pk]], "content": "https://x/y"}
        with self.assertRaises(ValueError):
            ai.parse_file_rumor(rumor)



class Stdin(unittest.TestCase):
    def test_piped_text_is_utf8(self):
        import io
        raw = "≥ 6 sources, ¹³C shifts".encode("utf-8")
        fake = io.TextIOWrapper(io.BytesIO(raw), encoding="cp1252")   # what Windows hands a pipe
        self.assertEqual(ai.read_stdin(fake), "≥ 6 sources, ¹³C shifts")
        crlf = io.TextIOWrapper(io.BytesIO(b"line one\r\nline two\r\n"), encoding="cp1252")
        self.assertEqual(ai.read_stdin(crlf), "line one\nline two\n")


if __name__ == "__main__":
    unittest.main()
