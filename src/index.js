// Agent Games — Proof Gatekeeper agent
// Protocol: https://agentgames.zkverify.io/build (source of truth)
// - POST /agent receives signed envelopes (x-agent-games-signature = HMAC-SHA256 over RAW body)
// - Preflight: { type: "agent-games.preflight.v1" } -> { ok: true, protocolVersion: "v1" } (signed)
// - Gatekeeper task: decide APPROVE/REJECT + reason_code, attach Groth16 proof when possible
// - Every response is signed with the same HMAC over the raw response body.
// Fail closed: any error/uncertainty -> REJECT.
const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const PORT = process.env.PORT || 8791;
const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";
const SEEN_FILE = path.join(__dirname, "..", "seen.json");

let seen = new Set();
try { seen = new Set(JSON.parse(fs.readFileSync(SEEN_FILE, "utf8"))); } catch {}
function markSeen(tx) {
  if (!tx || seen.has(tx)) return;
  seen.add(tx);
  try { fs.writeFileSync(SEEN_FILE, JSON.stringify([...seen])); } catch {}
}

function hmacHex(data) {
  return crypto.createHmac("sha256", SECRET).update(data).digest("hex");
}
function verifyInbound(rawBody, header) {
  if (!SECRET || !header) return false;
  const expected = hmacHex(rawBody);
  const candidates = [
    expected,
    crypto.createHmac("sha256", SECRET).update(rawBody).digest("base64"),
    "sha256=" + expected,
  ];
  const given = String(header).trim();
  return candidates.some((c) => {
    try {
      const a = Buffer.from(c), b = Buffer.from(given);
      return a.length === b.length && crypto.timingSafeEqual(a, b);
    } catch { return false; }
  });
}
function signResponse(res, obj) {
  const body = JSON.stringify(obj);
  res.setHeader("x-agent-games-signature", hmacHex(body));
  res.setHeader("content-type", "application/json");
  res.status(200).send(body);
}

// ---------- Gatekeeper decision logic (deterministic, fail closed) ----------
// Trap checks in a fixed order; ~50% of tasks are valid, the rest carry exactly one trap.
function decide(input, seenSet) {
  const big = (v) => { try { return BigInt(v); } catch { return null; } };
  const eqAddr = (a, b) => String(a || "").toLowerCase() === String(b || "").toLowerCase();
  if (!input) return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH" };
  if (!eqAddr(input.proof_vk, input.registered_vk))
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION" };
  const bal = big(input.public_balance), min = big(input.minimum);
  if (bal === null || min === null || bal < min)
    return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH" };
  if (input.proof_tx && seenSet.has(input.proof_tx))
    return { decision: "REJECT", reason_code: "PROOF_REUSED" };
  const cur = Number(input.current_block), exp = Number(input.expiry_block);
  if (!Number.isFinite(cur) || !Number.isFinite(exp) || cur > exp)
    return { decision: "REJECT", reason_code: "EXPIRED_CONDITION" };
  if (!eqAddr(input.recipient, input.condition_recipient))
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH" };
  const amt = big(input.amount), cap = big(input.max_transfer);
  if (amt === null || cap === null || amt > cap)
    return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW" };
  return { decision: "APPROVE", reason_code: "VALID_CONDITION" };
}

// ---------- Groth16 proof (best effort; decision is returned regardless) ----------
// Circuit input names are not published on the build page; attempts are logged so
// practice feedback can be used to correct them. A missing proof costs -2, a wrong
// decision costs more, so never block the decision on proof generation.
let snarkjs = null;
try { snarkjs = require("snarkjs"); } catch {}
const WASM = path.join(__dirname, "..", "circuits", "gatekeeper.wasm");
const ZKEY = path.join(__dirname, "..", "circuits", "gatekeeper_final.zkey");
async function tryProof(input, decision) {
  if (!snarkjs || !fs.existsSync(WASM)) return null;
  // Circuit inputs discovered by probing the wasm (13 public signals, camelCase):
  // taskId, registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
  // currentBlock, recipient, conditionRecipient, amount, maxTransfer, decision, salt
  // Hashes/addresses are reduced mod the bn128 field prime; taskId encoding and
  // salt source are calibrated against Practice Mode feedback.
  const PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
  const field = (hex) => { try { return (BigInt(hex) % PRIME).toString(); } catch { return "0"; } };
  const taskField = (id) => {
    try { return (BigInt(id) % PRIME).toString(); } catch {}
    try { return (BigInt("0x" + id.replace(/[^0-9a-fA-F]/g, "")) % PRIME).toString(); } catch {}
    const h = crypto.createHash("sha256").update(String(id)).digest("hex");
    return (BigInt("0x" + h) % PRIME).toString();
  };
  const candidate = {
    taskId: taskField(input._taskId ?? ""),
    registeredVkHash: field(input.registered_vk),
    proofVkHash: field(input.proof_vk),
    minimum: String(input.minimum ?? "0"),
    publicBalance: String(input.public_balance ?? "0"),
    expiryBlock: String(input.expiry_block ?? "0"),
    currentBlock: String(input.current_block ?? "0"),
    recipient: field(input.recipient),
    conditionRecipient: field(input.condition_recipient),
    amount: String(input.amount ?? "0"),
    maxTransfer: String(input.max_transfer ?? "0"),
    decision: decision.decision === "APPROVE" ? "1" : "0",
    salt: String(input._salt ?? "0"),
  };
  try {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(candidate, WASM, ZKEY);
    return { proof, public_signals: publicSignals };
  } catch (e) {
    console.error("[proof] generation failed:", e.message.split("\n")[0]);
    return null;
  }
}

const app = express();
app.get("/", (req, res) => signResponse(res, { ok: true, service: "gatekeeper-agent" }));
app.get("/agent", (req, res) => signResponse(res, { ok: true, protocolVersion: "v1" }));

app.post("/agent", (req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", async () => {
    const raw = Buffer.concat(chunks);
    const sig = req.headers["x-agent-games-signature"];
    if (SECRET && !verifyInbound(raw, sig)) {
      return signResponse(res, { decision: "REJECT", reason_code: "VK_SUBSTITUTION" });
    }
    let msg;
    try { msg = JSON.parse(raw.toString("utf8")); } catch {
      return signResponse(res, { ok: false });
    }
    try {
      if (msg.type === "agent-games.preflight.v1") {
        return signResponse(res, { ok: true, protocolVersion: "v1" });
      }
      if (msg.type === "agent-games.proof-gatekeeper.v1") {
        if (msg.input) { msg.input._taskId = msg.task_id; msg.input._salt = msg.salt ?? msg.input.salt ?? msg.nonce ?? "0"; }
        const d = decide(msg.input, seen);
        const out = { decision: d.decision, reason_code: d.reason_code };
        if (msg.input?.proof_tx) out.proof_tx = msg.input.proof_tx;
        // PROOF_REUSED tasks have no proof to submit (excluded by the rules).
        if (d.reason_code !== "PROOF_REUSED") {
          const p = await Promise.race([
            tryProof(msg.input, d),
            new Promise((r) => setTimeout(() => r(null), 45000)),
          ]);
          if (p) { out.proof = p.proof; out.public_signals = p.public_signals; }
        }
        markSeen(msg.input?.proof_tx);
        console.log(`[task] ${msg.task_id} mode=${msg.mode} -> ${out.decision}/${out.reason_code} proof=${out.proof ? "yes" : "no"}`);
        return signResponse(res, out);
      }
      return signResponse(res, { ok: true, protocolVersion: "v1" });
    } catch (e) {
      console.error("[handler] error:", e.message);
      return signResponse(res, { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH" });
    }
  });
});

app.listen(PORT, () => console.log(`gatekeeper-agent listening on :${PORT} (secret ${SECRET ? "set" : "NOT SET"})`));
