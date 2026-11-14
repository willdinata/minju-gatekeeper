# Minju Gatekeeper — Wildcard submission (zkVerify Agent Games)

**What it is.** A live, autonomous agent for the Proof Gatekeeper arena: it receives
signed transfer-approval tasks from the Agent Games platform, decides APPROVE or
REJECT deterministically, and proves each decision with a Groth16 zero-knowledge
proof generated locally — so the platform doesn't have to trust the agent, it
verifies it.

**Live demo.** `POST https://5cf01d74e83f29.app.lhr.life/agent` (HMAC-signed
protocol; answers the platform preflight handshake). Registered on the Agent
Games dashboard as "Minju Gatekeeper" and ENTERED in Proof Gatekeeper.

**Verified results (14 Nov 2026).**
- Signed preflight: **PASSED** — "Preflight OK — Healthy"
- Practice tasks: **3/3 correct decisions, 3/3 Groth16 proofs VERIFIED** by the
  platform against its own registered verification key (vk_hash
  0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0)
- Latency ~0.9–1.5 s per task (60 s limit)

**How it works.**
- Transport: Express endpoint; verifies `x-agent-games-signature`
  (HMAC-SHA256 over the *raw* body) before parsing; signs every response the
  same way. Fail closed on any error or uncertainty.
- Policy: deterministic checks for every trap family — VK_SUBSTITUTION,
  THRESHOLD_MISMATCH, PROOF_REUSED (local seen-set), EXPIRED_CONDITION,
  RECIPIENT_MISMATCH, AMOUNT_OVERFLOW — no LLM in the decision path.
- Proofs: snarkjs `groth16.fullProve` with the official gatekeeper wasm/zkey.
  The circuit's 13 public input signals are not published in the docs; they
  were recovered by probing the compiled wasm until every input was identified
  (taskId, registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
  currentBlock, recipient, conditionRecipient, amount, maxTransfer, decision,
  salt), with hashes/addresses reduced mod the bn128 field prime.

**Why it matters.** This is the Agent Games thesis in miniature: an agent whose
work product is not a claim but a proof. The same pattern — deterministic policy
+ locally generated ZK proof + independent verification — generalizes to any
setting where an autonomous agent's decision must be auditable without being
trusted.

**Repo.** https://github.com/willdinata/minju-gatekeeper (code, circuit
artifacts, local test harness replaying signed envelopes for every trap type).
