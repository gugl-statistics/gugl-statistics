// ===================================================================
// caesar.js - Caesar cipher + statistical key recovery
// Needs data.js (EN_FREQ, BIGRAM_LOG) loaded first.
// ===================================================================

const ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

// shift letters by k, keep case, leave everything else untouched
function caesar(text, k) {
  k = ((k % 26) + 26) % 26;
  let out = "";
  for (const ch of text) {
    const c = ch.charCodeAt(0);
    if (c >= 65 && c <= 90) out += String.fromCharCode(((c - 65 + k) % 26) + 65);
    else if (c >= 97 && c <= 122) out += String.fromCharCode(((c - 97 + k) % 26) + 97);
    else out += ch;
  }
  return out;
}
const caesarDecrypt = (text, k) => caesar(text, -k);
const onlyLetters = (t) => t.toUpperCase().replace(/[^A-Z]/g, "");

function letterCounts(L) {
  const c = new Array(26).fill(0);
  for (const ch of L) c[ch.charCodeAt(0) - 65]++;
  return c;
}

// --- scoring functions (on the letters-only string) ---
function chi2(L) {                       // lower = more English-like
  const n = L.length, c = letterCounts(L);
  let s = 0;
  for (let i = 0; i < 26; i++) { const e = n * EN_FREQ[i]; s += (c[i] - e) ** 2 / e; }
  return s;
}
function bigramScore(L) {                // higher = more English-like (log10 prob.)
  let s = 0;
  for (let i = 0; i + 1 < L.length; i++) s += BIGRAM_LOG[L.charCodeAt(i) - 65][L.charCodeAt(i + 1) - 65];
  return s;
}

// --- the three attacks ---
function attackMostFrequent(L) {         // "the most common letter must be E"
  const c = letterCounts(L);
  const top = c.indexOf(Math.max(...c));
  return (top - 4 + 26) % 26;
}
// exhaustive search over all 26 keys, keep the best score
function rankKeys(L, method = "chi2") {
  const rows = [];
  for (let k = 0; k < 26; k++) {
    const cand = caesarDecrypt(L, k);
    rows.push({ k, chi2: chi2(cand), bigram: bigramScore(cand) });
  }
  return method === "chi2" ? rows.sort((a, b) => a.chi2 - b.chi2) : rows.sort((a, b) => b.bigram - a.bigram);
}
const attackChi2 = (L) => rankKeys(L, "chi2")[0].k;
const attackBigram = (L) => rankKeys(L, "bigram")[0].k;

// --- experiment: success rate vs ciphertext length on the held-out text ---
function runExperiment(lengths, trials, seed = 1) {
  let s = seed >>> 0;                    // tiny deterministic PRNG (mulberry32)
  const rnd = () => { s |= 0; s = (s + 0x6d2b79f5) | 0; let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  const res = { lengths, mostfreq: [], chi2: [], bigram: [] };
  for (const n of lengths) {
    let a = 0, b = 0, c = 0;
    for (let t = 0; t < trials; t++) {
      const st = Math.floor(rnd() * (TEST_TEXT.length - n));
      const k = 1 + Math.floor(rnd() * 25);
      const ct = caesar(TEST_TEXT.slice(st, st + n), k);
      if (attackMostFrequent(ct) === k) a++;
      if (attackChi2(ct) === k) b++;
      if (attackBigram(ct) === k) c++;
    }
    res.mostfreq.push((100 * a) / trials);
    res.chi2.push((100 * b) / trials);
    res.bigram.push((100 * c) / trials);
  }
  return res;
}

if (typeof module !== "undefined") module.exports = { caesar, caesarDecrypt, onlyLetters, chi2, bigramScore, rankKeys, attackMostFrequent, attackChi2, attackBigram, runExperiment, letterCounts };
