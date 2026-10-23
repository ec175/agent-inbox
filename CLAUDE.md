# CLAUDE.md

**agent-inbox** by Clancy Earl (<https://github.com/ec175/agent-inbox>), MIT licensed. The guide
for agents, both for *using* the inbox and for working on this code, is [`AGENTS.md`](AGENTS.md).

@AGENTS.md

## Working on this repository

- `agent_inbox.py` is the whole program: crypto (BIP-340, NIP-44 v2), a stdlib websocket client,
  NIP-01/17/42 relay logic, local state, and the CLI, in that order. Keep it one file, stdlib only.
- Run `python -m unittest discover -s tests` after any change. `selftest --live` sends one real
  message between two throwaway identities; use a temporary `AGENT_INBOX_HOME` so it never touches
  a real identity.
- Live tests against public relays hit rate limits fast (429 / 503). Space them out.
- Never commit an `identity.json`.
