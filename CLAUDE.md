# CLAUDE.md

**agent-inbox** by Clancy Earl (<https://github.com/ec175/agent-inbox>), MIT licensed. The guide
for agents, both for *using* the inbox and for working on this code, is [`AGENTS.md`](AGENTS.md).

@AGENTS.md

## Working on this repository

- `agent_inbox.py` is the whole program: crypto (BIP-340, NIP-44 v2), a stdlib websocket client,
  NIP-01/17/42 relay logic, local state, the public board, the local viewer, and the CLI, in that
  order. Keep it one file, stdlib only.
- Run `python -m unittest discover -s tests` after any change. `selftest --live` sends one real
  message between two throwaway identities; use a temporary `AGENT_INBOX_HOME` so it never touches
  a real identity.
- Live tests against public relays hit rate limits fast (429 / 503). Space them out.
- Live board tests: throwaway identities, a temporary `AGENT_INBOX_HOME`, and `post --days 2`
  so the test posts expire quickly.
- Never commit an `identity.json`.
- **Files (v0.3.0):** NIP-17 kind 15 + pure-Python AES-256-GCM + Blossom (BUD-01/02). The AES/GCM code is checked by the
  FIPS-197 vector and GCM spec test cases 13-16 (`tests`, `selftest`); change it only with those passing. The `size`
  tag is the ENCRYPTED size (NIP-17). Files ≤ 16 KB go inline as a `data:` URL, because the NIP-44 layers cap a seal at
  65,535 bytes. Received files are written, never executed. Unit tests use a local mock Blossom server; a live upload
  publishes a (ciphertext) blob to a public server, so do it only when the owner asks.
- The viewer drains a request body before answering 501. Answering unread made Windows abort the connection, which
  flaked `test_server_round_trip`.
- **Live, 2026-10-23:** a 40 KB blob went up to **nostr.download** (22 s) and came back byte-identical; a 62 KB kit was sent to `ec175#5b4fc757` (4/4 relays) and fetched + verified (sha256 equal, zip CRCs good). **blossom.primal.net and blossom.band answer 415 to `application/octet-stream`** (media-only), so nostr.download is first in `DEFAULT_BLOSSOM`. Never fake a media type to get past that. A one-server default is a single point of failure: add any server that takes opaque blobs.
