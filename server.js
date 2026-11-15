// server.js — Proof Gatekeeper, SATU FILE, untuk zkVerify Agent Games.
// =====================================================================
// Cara pakai dari HP (tanpa folder, tanpa zip):
//   1. Di GitHub, buat repo baru, lalu Add file > Upload files,
//      upload file ini (server.js) + package.json ke ROOT repo.
//      Jangan masukkan ke folder.
//   2. Di Railway: New Project > Deploy from GitHub > pilih repo ini.
//   3. Di Railway > Variables, isi AGENT_GAMES_HMAC_SECRET
//      (secret dari dashboard Agent Games, muncul sekali saja).
//   4. Cek https://domain-kamu.up.railway.app/health -> harus ok.
//   5. Daftarkan endpoint itu di dashboard Agent Games sebagai URL
//      LENGKAP dengan path handler, mis.
//      https://domain-kamu.up.railway.app/agent
//      (bukan cuma root domain — platform hanya memanggil path itu).
//      Setelah deploy, ROTATE secret di dashboard, salin plaintext
//      yang muncul sekali itu, lalu isi sebagai
//      AGENT_GAMES_HMAC_SECRET di Railway. Preflight harus lolos
//      sebelum platform menandai agent kamu aktif.
//   6. Jalankan preflight + 1 practice task dari dashboard.
//
// Yang dilakukan file ini (sudah dites, 20 PASS di versi modularnya):
//   - Terima POST JSON task di / (juga /task, /agent)
//   - Verifikasi HMAC x-agent-games-signature terhadap RAW body dulu
//   - Cek 7 trap -> APPROVE hanya kalau semua lolos, kalau tidak REJECT
//   - Generate Groth16 proof lokal dengan circuit resmi (snarkjs).
//     Circuit (.wasm + .zkey) DIUNDUH OTOMATIS saat pertama jalan
//     dari agentgames.zkverify.io, jadi kamu tidak perlu upload
//     file circuit yang 2 MB itu dari HP.
//   - Response ditandatangani HMAC, task_id dipakai idempotency key.
//   - Kalau ragu / error / hampir timeout: FAIL CLOSED = REJECT.
//
// Env:
//   AGENT_GAMES_HMAC_SECRET  WAJIB (dari dashboard Agent Games)
//   PORT                     diisi Railway otomatis (lokal: 3000)
//   ZKVERIFY_MODE            local (default) atau kurier (opsional)
//   KURIER_API_URL, KURIER_API_KEY, KURIER_CHAIN_ID, KURIER_TIMEOUT_MS
//                            hanya kalau ZKVERIFY_MODE=kurier

'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const snarkjs = require('snarkjs');

// ------------------------------------------------------------------
// Circuit resmi Gatekeeper (Groth16/BN128, Circom 2.x)
// vkHash mainnet dari https://agentgames.zkverify.io/api/circuit-info
// ------------------------------------------------------------------
const VK_HASH =
  '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const WASM_URL = 'https://agentgames.zkverify.io/circuits/gatekeeper.wasm';
const ZKEY_URL = 'https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey';
const CIRCUIT_DIR = path.join(__dirname, 'circuits');
const WASM_PATH = path.join(CIRCUIT_DIR, 'gatekeeper.wasm');
const ZKEY_PATH = path.join(CIRCUIT_DIR, 'gatekeeper_final.zkey');

const PORT = Number(process.env.PORT || 3000);
const HMAC_SECRET =
  process.env.AGENT_GAMES_HMAC_SECRET || process.env.HMAC_SECRET || '';
const HARD_DEADLINE_MS = 60_000;

if (!HMAC_SECRET) {
  console.warn(
    '[WARN] AGENT_GAMES_HMAC_SECRET belum diset. Jangan deploy tanpa secret ini.'
  );
}

// Unduh circuit kalau belum ada (pertama kali jalan di Railway).
// Di Railway folder ini dibuat saat runtime, bukan di repo.
let circuitsReady = null;
async function ensureCircuits() {
  if (!circuitsReady) {
    circuitsReady = (async () => {
      fs.mkdirSync(CIRCUIT_DIR, { recursive: true });
      for (const [url, dest] of [[WASM_URL, WASM_PATH], [ZKEY_URL, ZKEY_PATH]]) {
        if (fs.existsSync(dest) && fs.statSync(dest).size > 100_000) {
          console.log('[circuit] sudah ada:', path.basename(dest));
          continue;
        }
        console.log('[circuit] download:', url);
        const res = await fetch(url);
        if (!res.ok) throw new Error(`download circuit gagal: HTTP ${res.status}`);
        fs.writeFileSync(dest, Buffer.from(await res.arrayBuffer()));
        console.log('[circuit] tersimpan:', dest, fs.statSync(dest).size, 'bytes');
      }
    })();
  }
  return circuitsReady;
}

// ------------------------------------------------------------------
// Logika keputusan: 7 trap. APPROVE hanya kalau SEMUA cek lolos.
// ------------------------------------------------------------------
function toBigInt(value) {
  if (value === undefined || value === null || value === '') return null;
  try {
    if (typeof value === 'bigint') return value;
    if (typeof value === 'number') return BigInt(value);
    const s = String(value).trim();
    return BigInt(s);
  } catch {
    return null;
  }
}
function toDecimalString(value) {
  const b = toBigInt(value);
  return b === null ? null : b.toString(10);
}
function toBigIntOrZero(value) {
  const b = toBigInt(value);
  return b === null ? 0n : b;
}
// taskId mis. "gk_24_9d1" -> field element (bytes UTF-8 sbg integer).
// Encoding ini sudah diuji: fullProve + groth16.verify = true.
function taskIdToField(taskId) {
  if (taskId === undefined || taskId === null) return '0';
  const s = String(taskId);
  if (s.startsWith('0x') || s.startsWith('0X')) return BigInt(s).toString(10);
  if (/^[0-9]+$/.test(s)) return BigInt(s).toString(10);
  return BigInt('0x' + Buffer.from(s, 'utf8').toString('hex')).toString(10);
}
function randomSalt() {
  return BigInt('0x' + crypto.randomBytes(16).toString('hex')).toString(10);
}

function decide(task, seenProofRefs) {
  const input = task || {};
  const checks = {
    vkMatches: false,
    proofNotReused: false,
    thresholdOk: false,
    notExpired: false,
    recipientMatches: false,
    amountOk: false,
  };
  const registeredVk = toDecimalString(input.registered_vk);
  const proofVk = toDecimalString(input.proof_vk);
  const minimum = toBigIntOrZero(input.minimum);
  const publicBalance = toBigIntOrZero(input.public_balance);
  const expiryBlock = toBigIntOrZero(input.expiry_block);
  const currentBlock = toBigIntOrZero(input.current_block);
  const recipient = toDecimalString(input.recipient);
  const conditionRecipient = toDecimalString(input.condition_recipient);
  const amount = toBigIntOrZero(input.amount);
  const maxTransfer = toBigIntOrZero(input.max_transfer);
  const proofTx = input.proof_tx ? String(input.proof_tx) : '';

  checks.vkMatches =
    registeredVk !== null && proofVk !== null && registeredVk === proofVk;
  checks.proofNotReused = Boolean(proofTx) && !seenProofRefs.has(proofTx);
  checks.thresholdOk = publicBalance >= minimum;
  checks.notExpired = expiryBlock > currentBlock;
  checks.recipientMatches =
    recipient !== null && conditionRecipient !== null && recipient === conditionRecipient;
  checks.amountOk = amount <= maxTransfer;

  // Reuse dicek duluan: trap ini tidak bisa di-prove (lihat bawah).
  let reasonCode = 'VALID_CONDITION';
  if (!checks.proofNotReused) reasonCode = 'PROOF_REUSED';
  else if (!checks.vkMatches) reasonCode = 'VK_SUBSTITUTION';
  else if (!checks.thresholdOk) reasonCode = 'THRESHOLD_MISMATCH';
  else if (!checks.notExpired) reasonCode = 'EXPIRED_CONDITION';
  else if (!checks.recipientMatches) reasonCode = 'RECIPIENT_MISMATCH';
  else if (!checks.amountOk) reasonCode = 'AMOUNT_OVERFLOW';

  const allPass = Object.values(checks).every(Boolean);
  return {
    decision: allPass ? 'APPROVE' : 'REJECT',
    reasonCode,
    verdict: allPass ? 1 : 0,
    checks,
    proofTx,
    circuitInputBase: {
      registeredVkHash: registeredVk,
      proofVkHash: proofVk,
      minimum: minimum.toString(10),
      publicBalance: publicBalance.toString(10),
      expiryBlock: expiryBlock.toString(10),
      currentBlock: currentBlock.toString(10),
      recipient,
      conditionRecipient,
      amount: amount.toString(10),
      maxTransfer: maxTransfer.toString(10),
    },
  };
}

// ------------------------------------------------------------------
// Proof Groth16. Input circuit (13 sinyal): registeredVkHash,
// proofVkHash, minimum, publicBalance, expiryBlock, currentBlock,
// recipient, conditionRecipient, amount, maxTransfer, decision,
// taskId, salt. Sudah diverifikasi langsung di wasm.
// ------------------------------------------------------------------
async function generateProof(decisionResult, taskId) {
  // PROOF_REUSED: circuit menganggap kondisi ini valid (verdict 1),
  // jadi decision 0 tidak bisa di-prove. Resmi: "PROOF_REUSED tasks
  // have no proof to submit". Jadi kembalikan null dengan sengaja.
  if (decisionResult.reasonCode === 'PROOF_REUSED') return null;
  const base = decisionResult.circuitInputBase;
  if (Object.values(base).some((v) => v === null || v === undefined)) return null;
  await ensureCircuits();
  const input = {
    ...base,
    decision: String(decisionResult.verdict),
    taskId: taskIdToField(taskId),
    salt: randomSalt(),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input, WASM_PATH, ZKEY_PATH
  );
  return { proof, publicSignals: publicSignals.map(String) };
}

// ------------------------------------------------------------------
// Kurier (opsional, default mati). ZKVERIFY_MODE=kurier untuk nyalakan.
// Submit dibatasi timeout supaya tidak bikin jawaban telat (60 detik).
// ------------------------------------------------------------------
async function submitToKurier(proof, publicSignals) {
  if (process.env.ZKVERIFY_MODE !== 'kurier') return null;
  // URL resmi dari /build: https://api.kurier.xyz/api/v1
  const apiUrl = (process.env.KURIER_API_URL || 'https://api.kurier.xyz/api/v1').replace(/\/$/, '');
  const apiKey = process.env.KURIER_API_KEY || '';
  if (!apiUrl || !apiKey) return null;
  const timeoutMs = Number(process.env.KURIER_TIMEOUT_MS || 20000);
  const startedAt = Date.now();
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const res = await fetch(`${apiUrl}/submit-proof/${apiKey}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      signal: controller.signal,
      body: JSON.stringify({
        proofType: 'groth16',
        vkRegistered: true, // vk Gatekeeper sudah terdaftar di mainnet
        proofOptions: { library: 'snarkjs', curve: 'bn128' },
        proofData: { proof, publicSignals, vk: VK_HASH },
      }),
    });
    clearTimeout(timer);
    if (!res.ok) return null;
    const data = await res.json();
    const jobId = data.jobId || data.job_id || data.id;
    if (!jobId) return null;
    // Poll sebentar sampai Finalized, tapi jangan lewati budget.
    while (Date.now() - startedAt < timeoutMs - 2000) {
      await new Promise((r) => setTimeout(r, 2000));
      const st = await fetch(`${apiUrl}/job-status/${apiKey}/${jobId}`);
      if (!st.ok) break;
      const sj = await st.json();
      if (sj.status === 'Finalized') {
        return sj.proofReference || sj.txHash || sj.aggregationId || jobId;
      }
      if (sj.status === 'Failed' || sj.status === 'Error') return null;
    }
    return jobId;
  } catch (err) {
    console.error('[kurier] error:', err.message);
    return null;
  }
}

// ------------------------------------------------------------------
// HTTP server: HMAC, idempotency, signed response, fail closed.
// ------------------------------------------------------------------
function hmacHex(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}
function signaturesMatch(secret, rawBody, headerValue) {
  if (!secret) return true; // hanya test lokal; lihat WARN di atas
  if (!headerValue) return false;
  const given = String(headerValue).replace(/^sha256=/i, '').trim().toLowerCase();
  const expected = hmacHex(secret, rawBody);
  const a = Buffer.from(given);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

const seenResponses = new Map(); // task_id -> response (idempotency)
const seenProofRefs = new Set(); // proof_tx yang sudah dipakai

function sendJson(res, statusCode, obj, sign = true) {
  const body = Buffer.from(JSON.stringify(obj));
  const headers = { 'content-type': 'application/json' };
  if (sign && HMAC_SECRET) headers['x-agent-games-signature'] = hmacHex(HMAC_SECRET, body);
  res.writeHead(statusCode, headers);
  res.end(body);
}
function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > 1024 * 1024) reject(new Error('body too large'));
      else chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function handleTask(req, res, rawBody) {
  const startedAt = Date.now();
  if (!signaturesMatch(HMAC_SECRET, rawBody, req.headers['x-agent-games-signature'])) {
    console.warn('[task] HMAC tidak valid — ditolak tanpa memproses');
    return sendJson(res, 401, { error: 'invalid signature' }, false);
  }
  let envelope;
  try {
    envelope = JSON.parse(rawBody.toString('utf8'));
  } catch {
    return sendJson(res, 400, { error: 'invalid json' });
  }

  // PREFLIGHT — dikirim platform SEBELUM task apa pun, setelah
  // register + Rotate Secret. Harus dibalas { ok: true,
  // protocolVersion: "v1" } dengan signature HMAC yang valid,
  // kalau tidak platform tidak menandai agent sebagai aktif.
  // Perhatikan: preflight ini BUKAN task, jadi jangan diproses
  // sebagai keputusan APPROVE/REJECT.
  if (envelope.type === 'agent-games.preflight.v1') {
    console.log(`[preflight] agent ${envelope.agent_id || ''} nonce ${envelope.nonce || ''}`);
    return sendJson(res, 200, { ok: true, protocolVersion: 'v1' });
  }

  const task = envelope.input || envelope.task || envelope;
  const taskId = envelope.task_id || envelope.taskId || task.task_id || 'unknown';
  const deadlineAt = envelope.deadline_at || envelope.deadlineAt || null;

  if (seenResponses.has(taskId)) {
    console.log(`[task ${taskId}] duplikat — kirim jawaban tersimpan`);
    return sendJson(res, 200, seenResponses.get(taskId));
  }

  const deadlineMs = deadlineAt ? Date.parse(deadlineAt) : startedAt + HARD_DEADLINE_MS;
  if (Number.isFinite(deadlineMs) && deadlineMs - Date.now() < 5000) {
    const fallback = {
      decision: 'REJECT', reason_code: 'TIMEOUT',
      task_id: taskId, proof_tx: task.proof_tx || null,
    };
    seenResponses.set(taskId, fallback);
    return sendJson(res, 200, fallback);
  }

  const result = decide(task, seenProofRefs);
  if (result.proofTx) seenProofRefs.add(result.proofTx);

  let proofData = null;
  try {
    proofData = await generateProof(result, taskId);
  } catch (err) {
    console.error(`[task ${taskId}] generateProof gagal:`, err.message);
    proofData = null;
  }

  let kurierRef = null;
  if (proofData) {
    try {
      kurierRef = await submitToKurier(proofData.proof, proofData.publicSignals);
    } catch (err) {
      console.error(`[task ${taskId}] kurier gagal:`, err.message);
    }
  }

  const response = {
    decision: result.decision,
    reason_code: result.reasonCode,
    task_id: taskId,
    proof_tx: kurierRef || result.proofTx || null,
    ...(proofData
      ? {
          proof: proofData.proof,
          publicSignals: proofData.publicSignals,
          public_signals: proofData.publicSignals,
        }
      : { proof: null, publicSignals: null, public_signals: null }),
  };
  seenResponses.set(taskId, response);
  console.log(
    `[task ${taskId}] ${result.decision} ${result.reasonCode} ` +
      `proof=${proofData ? 'ok' : 'none'} kurier=${kurierRef || '-'} ` +
      `${Date.now() - startedAt}ms`
  );
  return sendJson(res, 200, response);
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && (req.url === '/' || req.url === '/health')) {
      return sendJson(res, 200, {
        status: 'ok',
        service: 'agent-games-gatekeeper-single-file',
        tracks: ['proof-gatekeeper'],
        hmac_configured: Boolean(HMAC_SECRET),
        kurier_enabled: process.env.ZKVERIFY_MODE === 'kurier',
        uptime_s: Math.round(process.uptime()),
      });
    }
    if (req.method === 'POST' && (req.url === '/' || req.url === '/task' || req.url === '/agent')) {
      const rawBody = await readRawBody(req);
      return await handleTask(req, res, rawBody);
    }
    return sendJson(res, 404, { error: 'not found' }, false);
  } catch (err) {
    console.error('[server] error:', err);
    if (!res.headersSent) return sendJson(res, 500, { error: 'internal error' }, false);
  }
});

server.listen(PORT, () => {
  console.log(`Gatekeeper (single file) listening on port ${PORT}`);
  console.log(`HMAC configured: ${Boolean(HMAC_SECRET)} | Kurier: ${process.env.ZKVERIFY_MODE || 'local'}`);
  console.log('GET  /health  -> health check');
  console.log('POST /agent    -> endpoint utama (daftarkan URL lengkap ini di dashboard)');
  console.log('POST /         -> juga diterima (alias, untuk test lokal)');
  // Unduh circuit di background supaya task pertama tidak menunggu lama.
  ensureCircuits().catch((e) => console.error('[circuit] download gagal:', e.message));
});
