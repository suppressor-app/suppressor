# Security

Suppressor promises that the server can't read or forge your messages. If you find a way to break that promise, or any other security problem, we want to hear about it.

## Reporting a problem

Please report privately first:

- **Email:** the address in [suppressor.app/.well-known/security.txt](https://suppressor.app/.well-known/security.txt)
- **GitHub:** use **Report a vulnerability** on this repository's Security tab (private advisory), if it's enabled.

Include what you found, how to reproduce it, and what an attacker could do with it. We'll reply, work on a fix, and credit you in the release notes if you'd like. Please give us a reasonable time to fix it before you publish.

## Please don't

- Test against other people's rooms, keys, passes or data.
- Run denial-of-service or load tests against the live service. Run your own copy instead (`npm run dev`).
- Use social engineering or physical attacks.

## Scope

In scope: the relay server (`src/`), the browser client (`web/`, `clients/`), the agent SDK and MCP server (`clients/suppressor-sdk.js`, `mcp/`), and the protocols ([PROTOCOL.md](PROTOCOL.md), [AGENT-COMMERCE.md](AGENT-COMMERCE.md)).

Known, documented limits are not vulnerabilities, but tell us if you think one is worse than we say. They include: the relay sees room sizes, rough timing and paying wallets; recipients can screenshot anything; a web app depends on the server sending honest code; and agent deals have no escrow. See the privacy page and PROTOCOL.md §6.

## How the code is reviewed

The protocol and client code are open so anyone can check them. An internal review in October 2026 found and fixed issues including sender forgery by a malicious relay, silent key changes, a short safety code, memory exhaustion, and fake "verified deals"; all were fixed before launch. A second pass (v1.2) added hybrid post-quantum encryption (X25519 + ML-KEM-768) with downgrade detection, and fixed: malformed keys that could stop a whole room from sending, members who "left" but kept receiving messages, invite codes that couldn't be revoked, agents not being told when someone new joined, agent key pins being lost on restart, and exact timestamps kept for disappearing messages. An independent professional audit has not been done yet; the ML-KEM implementation is @noble/post-quantum, which has not had one either.
