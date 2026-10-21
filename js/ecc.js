// ===================================================================
// ecc.js - secp256k1 arithmetic + the toy ECIES-style scheme + attacks
// Everything is done with JavaScript BigInt (no external libraries).
// ===================================================================

const P  = 2n ** 256n - 2n ** 32n - 977n;
const N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const G  = {
  x: 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n,
  y: 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n,
};
const INF = null;               // point at infinity
const D_MAX = 1 << 20;          // the toy restriction: d in [1, 2^20]

const mod = (a, m = P) => { const r = a % m; return r >= 0n ? r : r + m; };

// modular inverse with the extended Euclidean algorithm
function inv(a, m = P) {
  let [r0, r1] = [mod(a, m), m];
  let [s0, s1] = [1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  return mod(s0, m);
}

function onCurve(Pt) {
  if (Pt === INF) return true;
  return mod(Pt.y * Pt.y - Pt.x * Pt.x * Pt.x - 7n) === 0n;
}

function add(A, B) {
  if (A === INF) return B;
  if (B === INF) return A;
  if (A.x === B.x && mod(A.y + B.y) === 0n) return INF;
  let lam;
  if (A.x === B.x) lam = mod(3n * A.x * A.x * inv(2n * A.y));
  else             lam = mod((B.y - A.y) * inv(B.x - A.x));
  const x = mod(lam * lam - A.x - B.x);
  return { x, y: mod(lam * (A.x - x) - A.y) };
}

const neg = (A) => (A === INF ? INF : { x: A.x, y: mod(-A.y) });

function mul(k, A) {             // double-and-add
  let R = INF;
  while (k > 0n) {
    if (k & 1n) R = add(R, A);
    A = add(A, A);
    k >>= 1n;
  }
  return R;
}

// ---------- encodings ----------
const hex = (n, len = 64) => n.toString(16).padStart(len, "0");
const compress = (Pt) => (Pt.y & 1n ? "03" : "02") + hex(Pt.x);
const bytesToHex = (b) => [...b].map((v) => v.toString(16).padStart(2, "0")).join("");
const hexToBytes = (h) => Uint8Array.from(h.match(/../g) || [], (v) => parseInt(v, 16));
const bigToBytes = (n) => hexToBytes(hex(n));
const enc = new TextEncoder(), dec = new TextDecoder();

function randomBig(bytes) {
  const b = crypto.getRandomValues(new Uint8Array(bytes));
  return BigInt("0x" + bytesToHex(b));
}
function randomScalar() {           // uniform in [1, N-1] (rejection sampling)
  for (;;) { const k = randomBig(32); if (k >= 1n && k < N) return k; }
}
function randomToyKey() {           // uniform in [1, 2^20]
  const r = crypto.getRandomValues(new Uint32Array(1))[0];
  return BigInt((r % D_MAX) + 1);
}

// ---------- symmetric part: SHA-256 KDF, keystream, HMAC ----------
async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}
const concat = (...arrs) => {
  const out = new Uint8Array(arrs.reduce((s, a) => s + a.length, 0));
  let o = 0; for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
};
async function kdf(S) {             // shared point S -> (k_enc, k_mac)
  const xb = bigToBytes(S.x);
  return [await sha256(concat(xb, Uint8Array.of(1))), await sha256(concat(xb, Uint8Array.of(2)))];
}
async function keystream(key, n) {
  const blocks = [];
  for (let c = 0; blocks.length * 32 < n; c++) {
    const ctr = new Uint8Array(4); new DataView(ctr.buffer).setUint32(0, c);
    blocks.push(await sha256(concat(key, ctr)));
  }
  return concat(...blocks).slice(0, n);
}
async function hmac(key, data) {
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
}
const xor = (a, b) => a.map((v, i) => v ^ b[i]);

// ---------- the toy scheme ----------
function keygen(d) {
  d = d ?? randomToyKey();
  return { d, Q: mul(d, G) };
}

async function eciesEncrypt(Q, text, log = () => {}) {
  const m = enc.encode(text);
  const k = randomScalar();
  log(`1. pick a fresh ephemeral scalar k (256-bit random): k = 0x${hex(k).slice(0, 16)}…`);
  const R = mul(k, G);
  log(`2. R = k·G  (sent in clear)  → ${compress(R).slice(0, 22)}…`);
  const S = mul(k, Q);
  log(`3. shared point S = k·Q → x_S = 0x${hex(S.x).slice(0, 16)}…`);
  const [kEnc, kMac] = await kdf(S);
  log(`4. KDF: k_enc = SHA256(x_S‖01) = ${bytesToHex(kEnc).slice(0, 16)}…, k_mac = SHA256(x_S‖02)`);
  const c = xor(m, await keystream(kEnc, m.length));
  log(`5. c = m ⊕ keystream(k_enc)  (${m.length} bytes)`);
  const tag = await hmac(kMac, c);
  log(`6. tag = HMAC-SHA256(k_mac, c) = ${bytesToHex(tag).slice(0, 16)}…`);
  return { R, c, tag };
}

async function eciesDecrypt(d, { R, c, tag }, log = () => {}) {
  if (R === INF || !onCurve(R)) throw new Error("R is not a valid curve point");
  log("1. check that R is a valid point on secp256k1 ✓");
  const S = mul(d, R);
  log(`2. S = d·R  (same point as k·Q, because d·k·G = k·d·G) → x_S = 0x${hex(S.x).slice(0, 16)}…`);
  const [kEnc, kMac] = await kdf(S);
  log("3. same KDF → same k_enc, k_mac");
  const t2 = await hmac(kMac, c);
  if (bytesToHex(t2) !== bytesToHex(tag)) throw new Error("MAC check failed (wrong key or tampered ciphertext)");
  log("4. recompute HMAC and compare with tag ✓");
  const m = xor(c, await keystream(kEnc, c.length));
  log("5. m = c ⊕ keystream(k_enc)");
  return dec.decode(m);
}

// ---------- attacks on the restricted key space ----------
const key = (Pt) => (Pt === INF ? "inf" : Pt.x.toString(36) + ":" + (Pt.y & 1n));

// Baby-step giant-step: O(sqrt(2^20)) = ~2048 group operations
function bsgs(Q, limit = D_MAX) {
  const t0 = performance.now();
  const m = Math.ceil(Math.sqrt(limit)) + 1;
  const table = new Map();
  let T = INF;
  for (let j = 0; j < m; j++) { table.set(key(T), j); T = add(T, G); }
  const step = neg(mul(BigInt(m), G));
  let Y = Q, ops = m;
  for (let i = 0; i <= m; i++) {
    const j = table.get(key(Y));
    ops++;
    if (j !== undefined) return { d: BigInt(i * m + j), ops, m, ms: performance.now() - t0 };
    Y = add(Y, step);
  }
  return { d: null, ops, m, ms: performance.now() - t0 };
}

// Exhaustive search, done in chunks so the page does not freeze.
// onProgress(tried) is called after every chunk; return true from shouldStop() to abort.
async function bruteForce(Q, onProgress, shouldStop, limit = D_MAX) {
  const t0 = performance.now();
  let T = G, d = 1;
  const target = key(Q);
  while (d <= limit) {
    const end = Math.min(d + 4000, limit + 1);
    for (; d < end; d++) {
      if (key(T) === target) return { d: BigInt(d), ms: performance.now() - t0 };
      T = add(T, G);
    }
    onProgress(d - 1, performance.now() - t0);
    if (shouldStop()) return { d: null, stopped: true, tried: d - 1, ms: performance.now() - t0 };
    await new Promise((r) => setTimeout(r, 0));
  }
  return { d: null, ms: performance.now() - t0 };
}

if (typeof module !== "undefined") module.exports = { P, N, G, INF, D_MAX, add, mul, neg, onCurve, keygen, eciesEncrypt, eciesDecrypt, bsgs, bruteForce, compress, bytesToHex, hex };
