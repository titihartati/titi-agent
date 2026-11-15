// server.js — Proof Gatekeeper + Steal the VFY, SATU FILE,
// untuk zkVerify Agent Games. v1.1.1 (deploy ulang: bump versi
// supaya push baru ke GitHub memicu deployment baru di Railway).
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
// Yang dilakukan file ini:
//   GATEKEEPER — terima POST task di /agent, verifikasi HMAC,
//   cek 7 trap -> APPROVE hanya kalau semua lolos, kalau tidak
//   REJECT, generate Groth16 proof lokal dengan circuit resmi.
//   STEAL THE VFY — terima POST turn envelope di /agent yang
//   sama, kenali dari eventId "steal-the-vfy" (atau adanya
//   matchId + turn + balances), mainkan strategi deterministik,
//   hitung publicInputsHash (keccak256, urutan field persis
//   seperti /build), generate policy proof lokal dengan circuit
//   resmi vfy-policy, dan jawab dengan skema VFY:
//   { matchId, turn, action, policyProof, agentTimestamp,
//     idempotencyKey } + proof & public_signals.
//   Circuit (.wasm + .zkey) DIUNDUH OTOMATIS saat pertama jalan
//   dari agentgames.zkverify.io, jadi kamu tidak perlu upload
//   file circuit dari HP.
//   Response ditandatangani HMAC. Kalau ragu / error / hampir
//   timeout: FAIL CLOSED (Gatekeeper = REJECT, Steal = HOLD
//   tanpa proof — sama seperti yang dilakukan platform kalau
//   agent diam).
//
// Env:
//   AGENT_GAMES_HMAC_SECRET  WAJIB (dari dashboard Agent Games)
//   PORT                     diisi Railway otomatis (lokal: 3000)
//   ZKVERIFY_MODE            local (default) atau kurier (opsional)
//   KURIER_API_URL, KURIER_API_KEY, KURIER_TIMEOUT_MS
//                            hanya kalau ZKVERIFY_MODE=kurier
//   STRATEGY_SALT            opsional, salt rahasia untuk policy
//                            proof Steal (jangan di-commit; kalau
//                            tidak diisi, dipakai salt acak per
//                            match yang sama selama server hidup)

'use strict';

const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const snarkjs = require('snarkjs');
const { keccak256 } = require('js-sha3');

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

// ------------------------------------------------------------------
// Circuit resmi Steal the VFY (vfy-policy, Groth16/BN128, Circom 2.x)
// vkHash mainnet dari https://agentgames.zkverify.io/api/circuit-info
// Sinyal input (ditemukan dengan probing wasm, 17 total):
//   publik: commitment, matchId, turnNumber, selfBalance,
//   opponentBalance, action, amount, circuitVersion (+ 1 output)
//   privat: strategyParams[8], salt
// ------------------------------------------------------------------
const VFY_VK_HASH =
  '0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047';
const VFY_WASM_URL = 'https://agentgames.zkverify.io/circuits/vfy-policy.wasm';
const VFY_ZKEY_URL = 'https://agentgames.zkverify.io/circuits/vfy-policy_final.zkey';
const VFY_WASM_PATH = path.join(CIRCUIT_DIR, 'vfy-policy.wasm');
const VFY_ZKEY_PATH = path.join(CIRCUIT_DIR, 'vfy-policy_final.zkey');

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
      for (const [url, dest] of [[WASM_URL, WASM_PATH], [ZKEY_URL, ZKEY_PATH], [VFY_WASM_URL, VFY_WASM_PATH], [VFY_ZKEY_URL, VFY_ZKEY_PATH]]) {
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
// STEAL THE VFY
// Strategi (dipilih sekali, deterministik — state yang sama selalu
// menghasilkan aksi yang sama, sesuai panduan /build):
//   "Fortify when my balance is below the opponent's, otherwise
//    extract 5 when the opponent's balance is high enough, else hold."
//   - self < opponent            -> FORTIFY (biaya 2, blokir s.d. 6)
//   - self >= opponent, opp >= 5 -> EXTRACT 5
//   - selain itu                 -> HOLD
// Aturan amount (dari /build, "Common mistakes"): HOLD dan FORTIFY
// TIDAK BOLEH membawa field amount sama sekali — skema menolak
// field itu walaupun nilainya 0. Hanya EXTRACT yang membawa amount.
// ------------------------------------------------------------------
const VFY_ACTION_CODE = { HOLD: 0, FORTIFY: 1, EXTRACT: 2 };
const VFY_STRATEGY_EXTRACT_AMOUNT = 5;
const FIELD_P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function decideStealAction(selfBalance, opponentBalance) {
  const self = BigInt(selfBalance);
  const opp = BigInt(opponentBalance);
  if (self < opp) return { type: 'FORTIFY' };
  if (opp >= BigInt(VFY_STRATEGY_EXTRACT_AMOUNT)) {
    return { type: 'EXTRACT', amount: VFY_STRATEGY_EXTRACT_AMOUNT };
  }
  return { type: 'HOLD' };
}

function matchIdToBigInt(matchId) {
  const s = String(matchId || '').replace(/-/g, '');
  if (!s) return 0n;
  try {
    return BigInt('0x' + s);
  } catch {
    return 0n;
  }
}
function hexToBigInt(value) {
  if (value === undefined || value === null || value === '') return 0n;
  try {
    return BigInt(String(value).trim());
  } catch {
    return 0n;
  }
}
function to32BytesBE(value) {
  const buf = Buffer.alloc(32);
  let v = BigInt(value);
  for (let i = 31; i >= 0; i--) {
    buf[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return buf;
}
// publicInputsHash — persis seperti kode di /build:
// keccak256 dari 8 field, masing-masing dipadatkan ke 32 byte
// big-endian, dengan urutan: commitment, matchId (tanpa "-"),
// turn, selfBalance, opponentBalance, kode aksi (HOLD 0, FORTIFY 1,
// EXTRACT 2), amount (0 untuk HOLD/FORTIFY), nomor versi circuit
// ("v1" -> 1). Platform menghitung hash yang sama dari game state
// yang diketahuinya dan menolak proof kalau hash-nya berbeda.
function computePublicInputsHash(fields) {
  const versionNum =
    typeof fields.circuitVersion === 'string' && fields.circuitVersion.startsWith('v')
      ? BigInt(fields.circuitVersion.slice(1))
      : BigInt(fields.circuitVersion || 1);
  const parts = [
    to32BytesBE(hexToBigInt(fields.commitment)),
    to32BytesBE(matchIdToBigInt(fields.matchId)),
    to32BytesBE(BigInt(fields.turn)),
    to32BytesBE(BigInt(fields.selfBalance)),
    to32BytesBE(BigInt(fields.opponentBalance)),
    to32BytesBE(BigInt(VFY_ACTION_CODE[fields.actionType])),
    to32BytesBE(BigInt(fields.amount || 0)),
    to32BytesBE(versionNum),
  ];
  return '0x' + keccak256(Buffer.concat(parts));
}

// strategyParams[8] — encoding strategi di atas untuk circuit
// vfy-policy (sinyal privat; arti pastinya tidak dipublikasikan
// situs, jadi encoding ini adalah milik agent sendiri):
//   [0] jumlah EXTRACT strategi (5)
//   [1] ambang selisih saldo untuk FORTIFY (0: fortify kalau
//       self < opponent)
//   [2..7] cadangan (0)
function stealStrategyParams() {
  return [
    String(VFY_STRATEGY_EXTRACT_AMOUNT),
    '0',
    '0',
    '0',
    '0',
    '0',
    '0',
    '0',
  ];
}
// Salt per match, deterministik (match yang sama -> salt yang sama,
// jadi jawaban retry identik). STRATEGY_SALT (env) bisa dipakai
// sebagai garam rahasia tambahan; kalau tidak diisi, salt hanya
// berasal dari matchId.
function stealSalt(matchId) {
  const base = process.env.STRATEGY_SALT
    ? keccak256(String(process.env.STRATEGY_SALT) + ':' + String(matchId))
    : keccak256('vfy-salt:' + String(matchId));
  return (BigInt('0x' + base) % FIELD_P).toString(10);
}

async function generateVfyProof(fields) {
  await ensureCircuits();
  const input = {
    commitment: (hexToBigInt(fields.commitment) % FIELD_P).toString(10),
    matchId: (matchIdToBigInt(fields.matchId) % FIELD_P).toString(10),
    turnNumber: String(fields.turn),
    selfBalance: String(fields.selfBalance),
    opponentBalance: String(fields.opponentBalance),
    action: String(VFY_ACTION_CODE[fields.actionType]),
    amount: String(fields.amount || 0),
    circuitVersion: String(
      typeof fields.circuitVersion === 'string' && fields.circuitVersion.startsWith('v')
        ? fields.circuitVersion.slice(1)
        : fields.circuitVersion || 1
    ),
    strategyParams: stealStrategyParams(),
    salt: stealSalt(fields.matchId),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input, VFY_WASM_PATH, VFY_ZKEY_PATH
  );
  return { proof, publicSignals: publicSignals.map(String) };
}

// ------------------------------------------------------------------
// Kurier (opsional, default mati). ZKVERIFY_MODE=kurier untuk nyalakan.
// Submit dibatasi timeout supaya tidak bikin jawaban telat.
// vkHash default = Gatekeeper; untuk Steal kirim VFY_VK_HASH.
// ------------------------------------------------------------------
async function submitToKurier(proof, publicSignals, vkHash = VK_HASH) {
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
        proofData: { proof, publicSignals, vk: vkHash },
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

const seenStealResponses = new Map(); // `${matchId}:${turn}` -> response

function toBalance(value, fallback) {
  try {
    if (value === undefined || value === null || value === '') return BigInt(fallback);
    return BigInt(value);
  } catch {
    return BigInt(fallback);
  }
}

// Handler Steal the VFY: jawab SATU turn dengan skema VFY.
// Skema respons (dari /build): matchId, turn, action, policyProof,
// agentTimestamp, idempotencyKey — plus proof & public_signals
// (di level atas DAN di dalam policyProof, karena situs menaruhnya
// di dua tempat yang berbeda; validator Zod default mengabaikan
// field yang tidak dikenal, jadi duplikasi ini aman).
// Kalau generate proof gagal (mis. circuit menolak input), tetap
// kirim jawaban dengan skema yang benar + publicInputsHash yang
// benar, tanpa proof — platform akan memberi diagnostic berikutnya
// (HOLD/-2) dan bukan schema error.
async function handleSteal(req, res, envelope) {
  const startedAt = Date.now();
  const turn = envelope.input || envelope.task || envelope;
  const matchId = String(turn.matchId || turn.match_id || envelope.matchId || '');
  const turnNum = Number(turn.turn ?? turn.turnNumber ?? envelope.turn ?? 0);
  const turnNumber = Number.isFinite(turnNum) ? turnNum : 0;
  const balances = turn.balances || envelope.balances || {};
  const selfBalance = toBalance(balances.self ?? balances.selfBalance, 100);
  const opponentBalance = toBalance(balances.opponent ?? balances.opponentBalance, 100);
  const commitmentObj = turn.strategyCommitment || envelope.strategyCommitment || {};
  const commitment = commitmentObj.hash || commitmentObj.commitment || '0x0';
  const circuitVersion = commitmentObj.circuitVersion || 'v1';
  const deadline = turn.deadline || envelope.deadline || null;

  const key = `${matchId}:${turnNumber}`;
  if (seenStealResponses.has(key)) {
    console.log(`[steal ${key}] duplikat — kirim jawaban tersimpan`);
    return sendJson(res, 200, seenStealResponses.get(key));
  }

  const idempotencyKey =
    `match-${matchId.slice(0, 8)}-turn-${turnNumber}-` +
    keccak256(matchId + ':' + turnNumber).slice(0, 8);

  // Deadline hampir habis -> HOLD cepat tanpa proof.
  const late = deadline ? Date.parse(deadline) - Date.now() < 2000 : false;
  const action = late
    ? { type: 'HOLD' }
    : decideStealAction(selfBalance, opponentBalance);
  const amount = action.amount || 0;
  const fields = {
    commitment,
    matchId,
    turn: turnNumber,
    selfBalance: selfBalance.toString(10),
    opponentBalance: opponentBalance.toString(10),
    actionType: action.type,
    amount,
    circuitVersion,
  };
  const publicInputsHash = computePublicInputsHash(fields);

  let proofData = null;
  if (!late) {
    try {
      proofData = await generateVfyProof(fields);
    } catch (err) {
      console.error(`[steal ${key}] generateVfyProof gagal:`, err.message);
      proofData = null;
    }
  }

  let proofReference = null;
  if (proofData) {
    try {
      proofReference = await submitToKurier(
        proofData.proof, proofData.publicSignals, VFY_VK_HASH
      );
    } catch (err) {
      console.error(`[steal ${key}] kurier gagal:`, err.message);
    }
  }

  const policyProof = {
    circuitVersion,
    publicInputsHash,
    ...(proofReference ? { proofReference } : {}),
    ...(proofData
      ? { proof: proofData.proof, publicSignals: proofData.publicSignals }
      : {}),
  };
  const response = {
    matchId,
    turn: turnNumber,
    action,
    policyProof,
    agentTimestamp: new Date().toISOString(),
    idempotencyKey,
    ...(proofData
      ? {
          proof: proofData.proof,
          publicSignals: proofData.publicSignals,
          public_signals: proofData.publicSignals,
        }
      : {}),
  };
  seenStealResponses.set(key, response);
  console.log(
    `[steal ${key}] ${action.type} proof=${proofData ? 'ok' : 'none'} ` +
      `${Date.now() - startedAt}ms`
  );
  return sendJson(res, 200, response);
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

  // STEAL THE VFY — envelope turn, bukan task Gatekeeper. Dikenali
  // dari eventId "steal-the-vfy" atau dari adanya matchId + turn +
  // balances. Routing ini harus terjadi SEBELUM logika Gatekeeper,
  // kalau tidak turn Steal akan dijawab dengan format Gatekeeper
  // (decision REJECT) dan ditolak sebagai schema error.
  const _stealTask = envelope.input || envelope.task || envelope;
  const _stealEventId = envelope.eventId || _stealTask.eventId || '';
  const _isSteal =
    _stealEventId === 'steal-the-vfy' ||
    (_stealTask.matchId &&
      (_stealTask.turn !== undefined || _stealTask.turnNumber !== undefined) &&
      _stealTask.balances);
  if (_isSteal) return handleSteal(req, res, envelope);

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
        service: 'agent-games-gatekeeper-steal-single-file',
        tracks: ['proof-gatekeeper', 'steal-the-vfy'],
        hmac_configured: Boolean(HMAC_SECRET),
        kurier_enabled: process.env.ZKVERIFY_MODE === 'kurier',
        steal_strategy: 'fortify-when-behind-else-extract-5',
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
  console.log(`Gatekeeper + Steal (single file) listening on port ${PORT}`);
  console.log(`HMAC configured: ${Boolean(HMAC_SECRET)} | Kurier: ${process.env.ZKVERIFY_MODE || 'local'}`);
  console.log('GET  /health  -> health check');
  console.log('POST /agent    -> endpoint utama (Gatekeeper + Steal the VFY)');
  console.log('POST /         -> juga diterima (alias, untuk test lokal)');
  // Unduh circuit di background supaya task pertama tidak menunggu lama.
  ensureCircuits().catch((e) => console.error('[circuit] download gagal:', e.message));
});
