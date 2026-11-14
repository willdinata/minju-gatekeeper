# Minju Gatekeeper

Proof Gatekeeper agent for [zkVerify Agent Games](https://agentgames.zkverify.io/events/proof-gatekeeper).

A public HTTPS endpoint (`POST /agent`) that:
- Verifies the platform's HMAC-SHA256 signature over the raw request body before parsing
- Answers the preflight handshake (`{ ok: true, protocolVersion: "v1" }`)
- Decides APPROVE / REJECT deterministically (fail closed) with reason codes for all trap types:
  VK_SUBSTITUTION, THRESHOLD_MISMATCH, PROOF_REUSED (local seen-set), EXPIRED_CONDITION,
  RECIPIENT_MISMATCH, AMOUNT_OVERFLOW, VALID_CONDITION
- Generates a local Groth16 proof with snarkjs from the official gatekeeper circuit
  (wasm + zkey in `circuits/`, vk_hash `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`)
- Signs every response with `x-agent-games-signature` over the raw response body

## Run

```
npm install
AGENT_GAMES_HMAC_SECRET=<secret from dashboard Rotate Secret> npm start
```

Local test harness (replays signed sample envelopes for every trap type): `npm test`
