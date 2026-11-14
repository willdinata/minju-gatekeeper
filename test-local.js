// Local harness: starts the agent with a test secret, replays signed envelopes.
const { spawn } = require("child_process");
const crypto = require("crypto");
const SECRET = "test-secret-123";
const sign = (raw) => crypto.createHmac("sha256", SECRET).update(raw).digest("hex");

const base = {
  registered_vk: "0x7d3a00000000000000000000000000000000000000000000000000000000f291",
  proof_vk:      "0x7d3a00000000000000000000000000000000000000000000000000000000f291",
  minimum: "1000", public_balance: "1460",
  expiry_block: 19842201, current_block: 19832000,
  recipient: "0xDe4200000000000000000000000000000000009f01",
  condition_recipient: "0xDe4200000000000000000000000000000000009f01",
  amount: "500", max_transfer: "1000",
  proof_tx: "0xa4c1000000000000000000000000000000000000000000000000000000008ff1",
};
const cases = [
  ["VALID", {}],
  ["VK_SUBSTITUTION", { proof_vk: "0xa4c100000000000000000000000000000000000000000000000000000000b8ff" }],
  ["THRESHOLD_MISMATCH", { public_balance: "900" }],
  ["EXPIRED_CONDITION", { current_block: 19843000 }],
  ["RECIPIENT_MISMATCH", { recipient: "0x1111000000000000000000000000000000002222" }],
  ["AMOUNT_OVERFLOW", { amount: "1500" }],
];

async function post(obj) {
  const raw = JSON.stringify(obj);
  const r = await fetch("http://127.0.0.1:8791/agent", {
    method: "POST",
    headers: { "content-type": "application/json", "x-agent-games-signature": sign(raw) },
    body: raw,
  });
  const text = await r.text();
  const sigOk = sign(text) === r.headers.get("x-agent-games-signature");
  return { body: JSON.parse(text), sigOk };
}

(async () => {
  const child = spawn("node", ["src/index.js"], {
    env: { ...process.env, AGENT_GAMES_HMAC_SECRET: SECRET, PORT: "8791" },
    stdio: "inherit",
  });
  await new Promise((r) => setTimeout(r, 1200));
  try {
    const pf = await post({ type: "agent-games.preflight.v1", agent_id: "agt_test", nonce: "abc123" });
    console.log("PREFLIGHT:", JSON.stringify(pf.body), "sigOk:", pf.sigOk);
    let i = 0;
    for (const [name, patch] of cases) {
      i++;
      const env = { type: "agent-games.proof-gatekeeper.v1", task_id: "gk_test_" + i, mode: "practice", issued_at: "", deadline_at: "", input: { ...base, ...patch, proof_tx: base.proof_tx + i } };
      const out = await post(env);
      console.log(name.padEnd(20), "->", out.body.decision, "/", out.body.reason_code, "sigOk:", out.sigOk, "proof:", out.body.proof ? "yes" : "no");
    }
    // PROOF_REUSED: replay case 1's exact proof_tx
    const reuse = { type: "agent-games.proof-gatekeeper.v1", task_id: "gk_test_reuse", mode: "practice", input: { ...base, proof_tx: base.proof_tx + "1" } };
    const out = await post(reuse);
    console.log("PROOF_REUSED        ->", out.body.decision, "/", out.body.reason_code);
  } finally { child.kill(); }
})();
