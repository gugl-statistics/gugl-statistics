// ===================================================================
// main.js - wires the demos on the page to ecc.js and caesar.js
// ===================================================================
const $ = (id) => document.getElementById(id);
const esc = (s) => s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
const fmt = (x) => x.toLocaleString("en-US");
const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();

// ---------- tiny SVG bar chart ----------
// series: [{values, color}], labels: x labels, opts: {height, highlight, max, yfmt}
function barChart(el, labels, series, opts = {}) {
  const W = 640, H = opts.height || 200, pl = 40, pb = 22, pt = 8;
  const n = labels.length, gw = (W - pl - 6) / n, bw = (gw - 3) / series.length;
  const max = opts.max || Math.max(...series.flatMap((s) => s.values)) * 1.08 || 1;
  let svg = `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img">`;
  for (let t = 0; t <= 4; t++) {
    const v = (max * t) / 4, y = H - pb - ((H - pb - pt) * t) / 4;
    svg += `<line x1="${pl}" x2="${W}" y1="${y}" y2="${y}" stroke="rgba(255,255,255,0.08)"/>`;
    svg += `<text x="${pl - 6}" y="${y + 4}" text-anchor="end">${(opts.yfmt || ((x) => x.toFixed(2)))(v)}</text>`;
  }
  labels.forEach((lab, i) => {
    const x0 = pl + i * gw;
    if (opts.highlight === i) svg += `<rect x="${x0}" y="${pt}" width="${gw}" height="${H - pb - pt}" fill="rgba(255,138,31,0.12)"/>`;
    series.forEach((s, j) => {
      const v = s.values[i], h = ((H - pb - pt) * v) / max;
      svg += `<rect x="${x0 + 1.5 + j * bw}" y="${H - pb - h}" width="${Math.max(bw - 1, 1)}" height="${h}" fill="${s.color}" rx="1"><title>${lab}: ${v.toFixed(3)}</title></rect>`;
    });
    svg += `<text x="${x0 + gw / 2}" y="${H - 6}" text-anchor="middle">${lab}</text>`;
  });
  el.innerHTML = svg + "</svg>";
}

// line chart for the experiment (x = categories)
function lineChart(el, labels, series) {
  const W = 640, H = 260, pl = 44, pb = 34, pt = 10, pr = 10;
  const x = (i) => pl + ((W - pl - pr) * i) / (labels.length - 1);
  const y = (v) => H - pb - ((H - pb - pt) * v) / 100;
  let svg = `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img">`;
  for (let v = 0; v <= 100; v += 25) {
    svg += `<line x1="${pl}" x2="${W - pr}" y1="${y(v)}" y2="${y(v)}" stroke="rgba(255,255,255,0.08)"/>`;
    svg += `<text x="${pl - 6}" y="${y(v) + 4}" text-anchor="end">${v}%</text>`;
  }
  labels.forEach((l, i) => (svg += `<text x="${x(i)}" y="${H - 16}" text-anchor="middle">${l}</text>`));
  svg += `<text x="${(W + pl) / 2}" y="${H - 2}" text-anchor="middle">ciphertext length (letters)</text>`;
  for (const s of series) {
    if (!s.values) continue;
    svg += `<polyline fill="none" stroke="${s.color}" stroke-width="2.5" ${s.dash ? 'stroke-dasharray="5 4"' : ""} points="${s.values.map((v, i) => `${x(i)},${y(v)}`).join(" ")}"/>`;
    s.values.forEach((v, i) => (svg += `<circle cx="${x(i)}" cy="${y(v)}" r="3.5" fill="${s.color}"><title>${s.name}, ${labels[i]} letters: ${v.toFixed(1)}%</title></circle>`));
  }
  el.innerHTML = svg + "</svg>";
}

// =================================================== 1. toy ECC demo
let current = null;      // { d, Q }
let lastCt = null;       // { R, c, tag } (may be tampered by the button)
let cleanCt = null;      // the original, untampered ciphertext (used by the attack)

function setKey(d) {
  current = keygen(d);
  $("ecc-d").value = current.d.toString();
  $("ecc-Q").innerHTML = `<span class="s">${compress(current.Q)}</span>\n<span style="color:var(--muted)">x = 0x${hex(current.Q.x)}\ny = 0x${hex(current.Q.y)}</span>`;
  $("atk-Q").textContent = compress(current.Q);
  lastCt = cleanCt = null;
  $("ecc-dec").disabled = $("ecc-tamper").disabled = true;
  $("ecc-elog").textContent = $("ecc-dlog").textContent = $("ecc-ct").textContent = "";
}

$("ecc-gen").onclick = () => setKey();
$("ecc-setkey").onclick = () => {
  const v = parseInt($("ecc-d").value, 10);
  if (!(v >= 1 && v <= D_MAX)) { $("ecc-Q").innerHTML = `<span class="bad">d must be between 1 and ${fmt(D_MAX)}</span>`; return; }
  setKey(BigInt(v));
};

function showCt() {
  $("ecc-ct").innerHTML = `<span class="k">R</span>   = ${compress(lastCt.R)}\n<span class="k">c</span>   = ${bytesToHex(lastCt.c)}\n<span class="k">tag</span> = ${bytesToHex(lastCt.tag)}`;
}

$("ecc-enc").onclick = async () => {
  if (!current) setKey();
  const lines = [];
  lastCt = cleanCt = await eciesEncrypt(current.Q, $("ecc-msg").value, (l) => lines.push(l));
  $("ecc-elog").textContent = lines.join("\n");
  $("ecc-dlog").textContent = "";
  showCt();
  $("ecc-dec").disabled = $("ecc-tamper").disabled = false;
};

$("ecc-dec").onclick = async () => {
  const lines = [];
  try {
    const m = await eciesDecrypt(current.d, lastCt, (l) => lines.push(l));
    $("ecc-dlog").innerHTML = esc(lines.join("\n")) + `\n<span class="ok">→ "${esc(m)}"</span>`;
  } catch (e) {
    $("ecc-dlog").innerHTML = esc(lines.join("\n")) + `\n<span class="bad">✗ ${esc(e.message)}</span>`;
  }
};

$("ecc-tamper").onclick = () => {
  const c = lastCt.c.slice();
  const i = Math.floor(Math.random() * c.length);
  c[i] ^= 1;
  lastCt = { ...lastCt, c };
  showCt();
  $("ecc-dlog").innerHTML = `<span class="k">attacker flipped the lowest bit of byte ${i}. Now press "Decrypt".</span>`;
};

// =================================================== 2. Caesar demo
function updateCaesar() {
  const k = +$("cz-k").value;
  $("cz-kv").textContent = k;
  $("cz-plain").innerHTML = [...ALPHA].map((c) => `<div>${c}</div>`).join("");
  $("cz-cipher").innerHTML = [...ALPHA].map((c) => `<div>${caesar(c, k)}</div>`).join("");
  const ct = caesar($("cz-msg").value, k);
  $("cz-ct").textContent = ct;
  $("cz-pt").textContent = caesarDecrypt(ct, k);
}
$("cz-k").oninput = updateCaesar;
$("cz-msg").oninput = updateCaesar;

// =================================================== 3. histograms
async function runHist() {
  const k = +$("hist-k").value;
  $("hist-kv").textContent = k;
  const sample = TEST_TEXT.slice(5000, 7000);
  const cz = caesar(sample, k);
  const cnt = letterCounts(cz);
  barChart($("hist-caesar"), [...ALPHA], [
    { values: cnt.map((c) => c / cz.length), color: css("--orange") },
    { values: EN_FREQ, color: css("--sky") },
  ], { height: 190, yfmt: (v) => (100 * v).toFixed(0) + "%" });

  if (!current) setKey();
  const ct = await eciesEncrypt(current.Q, sample);
  const bins = new Array(16).fill(0);
  for (const b of ct.c) bins[b >> 4]++;
  barChart($("hist-ecies"), bins.map((_, i) => i.toString(16).toUpperCase() + "x"), [
    { values: bins.map((v) => v / ct.c.length), color: css("--orange") },
    { values: bins.map(() => 1 / 16), color: css("--sky") },
  ], { height: 190, yfmt: (v) => (100 * v).toFixed(0) + "%" });

  // index of coincidence: unchanged by Caesar, ~1/26 for random letters
  const ic = (c, n) => c.reduce((s, x) => s + x * (x - 1), 0) / (n * (n - 1));
  const icPlain = ic(letterCounts(sample), sample.length), icCz = ic(cnt, cz.length);
  $("hist-stats").innerHTML =
    `Index of coincidence: plaintext <span class="s">${icPlain.toFixed(4)}</span>, Caesar ciphertext <span class="k">${icCz.toFixed(4)}</span> (identical: Caesar only renames letters). ` +
    `Random letters would give 1/26 ≈ 0.0385.\nMost common Caesar ciphertext letter: <span class="k">${ALPHA[cnt.indexOf(Math.max(...cnt))]}</span> (= E shifted by ${k} → ${caesar("E", k)}). ` +
    `ECIES: ${ct.c.length} bytes spread over all 16 bins, nothing to count.`;
}
$("hist-k").oninput = runHist;
$("hist-run").onclick = runHist;

// =================================================== 4. statistical attack
barChart($("corpus-chart"), [...ALPHA], [{ values: EN_FREQ, color: css("--sky") }], { height: 170, yfmt: (v) => (100 * v).toFixed(0) + "%" });
$("corpus-n").textContent = fmt(CORPUS_LETTERS);

const samples = {
  short: "Fix my van",
  lipo: "Jazz fans buzz with joy at a big gig in a dim club",
  ita: "La zia Lucia va in Sicilia a luglio",
};
let lastTrueKey = null;
function loadSample(text) {
  lastTrueKey = 1 + Math.floor(Math.random() * 25);
  $("sa-ct").value = caesar(text, lastTrueKey);
  runAttack();
}
$("sa-gen").onclick = () => {
  const st = Math.floor(Math.random() * (TEST_TEXT.length - 100));
  loadSample(TEST_TEXT.slice(st, st + 100));
};
$("sa-short").onclick = () => loadSample(samples.short);
$("sa-lipo").onclick = () => loadSample(samples.lipo);
$("sa-ita").onclick = () => loadSample(samples.ita);
$("sa-ct").oninput = () => { lastTrueKey = null; };

function runAttack() {
  const raw = $("sa-ct").value, L = onlyLetters(raw);
  if (L.length === 0) { $("sa-summary").innerHTML = `<span class="bad">No letters in the ciphertext.</span>`; return; }
  const t0 = performance.now();
  const byChi = rankKeys(L, "chi2");
  const ms = performance.now() - t0;
  const kChi = byChi[0].k, kBi = attackBigram(L), kE = attackMostFrequent(L);
  const chiByKey = new Array(26); byChi.forEach((r) => (chiByKey[r.k] = r.chi2));
  barChart($("sa-chart"), [...Array(26).keys()].map(String), [{ values: chiByKey, color: css("--sky") }],
    { height: 170, highlight: kChi, yfmt: (v) => v.toFixed(0) });

  const mark = (k) => (lastTrueKey === null ? "" : k === lastTrueKey ? ' <span class="ok">✓</span>' : ' <span class="bad">✗</span>');
  $("sa-summary").innerHTML =
    `${L.length} letters analysed in ${ms.toFixed(1)} ms.\n` +
    `<span class="k">χ² attack → k = ${kChi}</span>${mark(kChi)}   bigram → k = ${kBi}${mark(kBi)}   most-frequent=E → k = ${kE}${mark(kE)}` +
    (lastTrueKey !== null ? `\n(true key: ${lastTrueKey})` : "") +
    `\nPlaintext with χ² key: <span class="s">${esc(caesarDecrypt(raw, kChi).slice(0, 300))}</span>`;

  let rows = `<tr><th class="num">rank</th><th class="num">k</th><th class="num">χ²</th><th class="num">bigram score</th><th>decryption</th></tr>`;
  byChi.slice(0, 5).forEach((r, i) => {
    const cls = [i === 0 ? "best" : "", r.k === lastTrueKey ? "correct" : ""].join(" ");
    rows += `<tr class="${cls}"><td class="num">${i + 1}</td><td class="num">${r.k}</td><td class="num">${r.chi2.toFixed(1)}</td><td class="num">${r.bigram.toFixed(1)}</td><td class="mono">${esc(caesarDecrypt(raw, r.k).slice(0, 60))}</td></tr>`;
  });
  $("sa-table").innerHTML = rows;
}
$("sa-run").onclick = runAttack;

// experiment chart + table
function showExperiment(res, live) {
  lineChart($("exp-chart"), res.lengths, [
    { name: "most frequent = E", values: res.mostfreq, color: "#8fa3cc" },
    { name: "χ²", values: res.chi2, color: css("--orange") },
    { name: "bigram", values: res.bigram, color: css("--sky") },
    { name: "quadgram", values: live ? null : res.quadgram, color: "#ffffff", dash: true },
  ]);
  let t = `<tr><th>length</th>${res.lengths.map((l) => `<th class="num">${l}</th>`).join("")}</tr>`;
  const row = (name, v) => (v ? `<tr><td>${name}</td>${v.map((x) => `<td class="num">${x.toFixed(1)}</td>`).join("")}</tr>` : "");
  t += row("most freq = E", res.mostfreq) + row("χ²", res.chi2) + row("bigram", res.bigram) + (live ? "" : row("quadgram", res.quadgram));
  $("exp-table").innerHTML = t;
}
showExperiment(PY_RESULTS, false);

$("exp-run").onclick = () => {
  const trials = Math.max(20, Math.min(3000, +$("exp-trials").value || 300));
  $("exp-run").disabled = true;
  $("exp-status").textContent = `Running ${trials} trials × ${PY_RESULTS.lengths.length} lengths…`;
  setTimeout(() => {
    const t0 = performance.now();
    const res = runExperiment(PY_RESULTS.lengths, trials, (Math.random() * 2 ** 32) >>> 0);
    showExperiment(res, true);
    $("exp-status").innerHTML = `Browser rerun: ${trials} trials per length, done in ${((performance.now() - t0) / 1000).toFixed(1)} s. ` +
      `<a href="#" id="exp-back">Show the Python results again</a>`;
    $("exp-back").onclick = (e) => { e.preventDefault(); showExperiment(PY_RESULTS, false); $("exp-status").textContent = "Showing the Python results (1,000 trials per length)."; };
    $("exp-run").disabled = false;
  }, 30);
};

// =================================================== 5. attack on toy ECC
let stopFlag = false;
async function ensureTarget() {
  if (!current) setKey();
  if (!cleanCt) {
    lastCt = cleanCt = await eciesEncrypt(current.Q, $("ecc-msg").value);
    showCt();
    $("ecc-dec").disabled = $("ecc-tamper").disabled = false;
  }
}
async function finishAttack(d, header) {
  if (d === null) { $("atk-out").innerHTML = header + `\n<span class="bad">key not found</span>`; return; }
  let msg;
  try { msg = `<span class="ok">decrypted message: "${esc(await eciesDecrypt(d, cleanCt))}"</span> (HMAC verified)`; }
  catch (e) { msg = `<span class="bad">${esc(e.message)}</span>`; }
  const check = compress(mul(d, G)) === compress(current.Q);
  $("atk-out").innerHTML = header + `\n<span class="k">recovered d = ${fmt(Number(d))}</span>  check d·G = Q: ${check ? '<span class="ok">✓</span>' : '<span class="bad">✗</span>'}\n` + msg;
}
$("atk-bsgs").onclick = async () => {
  await ensureTarget();
  $("atk-out").textContent = "running BSGS…";
  $("atk-bar").style.width = "0";
  await new Promise((r) => setTimeout(r, 20));
  const r = bsgs(current.Q);
  $("atk-bar").style.width = "100%";
  await finishAttack(r.d, `BSGS: m = ${r.m}, ${fmt(r.ops)} group operations / lookups, ${r.ms.toFixed(0)} ms`);
};
$("atk-bf").onclick = async () => {
  await ensureTarget();
  stopFlag = false;
  $("atk-bf").disabled = $("atk-bsgs").disabled = true;
  $("atk-stop").disabled = false;
  const r = await bruteForce(current.Q, (tried, ms) => {
    $("atk-bar").style.width = (100 * tried) / D_MAX + "%";
    $("atk-out").textContent = `brute force: tried ${fmt(tried)} keys (${(100 * tried / D_MAX).toFixed(1)}% of the key space), ${(ms / 1000).toFixed(1)} s`;
  }, () => stopFlag);
  $("atk-bf").disabled = $("atk-bsgs").disabled = false;
  $("atk-stop").disabled = true;
  if (r.stopped) { $("atk-out").textContent += "\nstopped."; return; }
  await finishAttack(r.d, `brute force: ${fmt(Number(r.d))} point additions, ${(r.ms / 1000).toFixed(1)} s`);
};
$("atk-stop").onclick = () => (stopFlag = true);

// key size calculator - measure the speed of point addition in this browser
let usPerAdd = 30;
(function measure() {
  let T = G; const t0 = performance.now();
  for (let i = 0; i < 300; i++) T = add(T, G);
  usPerAdd = ((performance.now() - t0) / 300) * 1000;
})();
function human(seconds) {
  if (!isFinite(seconds)) return "∞";
  const u = [["years", 3.156e7], ["days", 86400], ["hours", 3600], ["min", 60], ["s", 1], ["ms", 1e-3], ["µs", 1e-6]];
  for (const [n, s] of u) if (seconds >= s) {
    const v = seconds / s;
    return (v >= 1e6 ? v.toExponential(1).replace("e+", "·10^") : v.toFixed(v < 10 ? 1 : 0)) + " " + n;
  }
  return "< 1 µs";
}
function updateKeySize() {
  const b = +$("ks-bits").value;
  $("ks-bv").textContent = b;
  const bf = 2 ** (b - 1), bs = 2 * 2 ** (b / 2);
  const p2 = (e) => `2^${e % 1 === 0 ? e : e.toFixed(1)} ≈ ${(2 ** e).toExponential(2)}`;
  $("ks-table").innerHTML =
    `<tr><th>Attack</th><th class="num">operations</th><th class="num">your browser (${usPerAdd.toFixed(0)} µs/add)</th><th class="num">big cluster (10¹²/s)</th><th class="num">memory</th></tr>` +
    `<tr><td>Brute force (average)</td><td class="num">${p2(b - 1)}</td><td class="num">${human(bf * usPerAdd * 1e-6)}</td><td class="num">${human(bf / 1e12)}</td><td class="num">O(1)</td></tr>` +
    `<tr><td>BSGS</td><td class="num">${p2(b / 2 + 1)}</td><td class="num">${human(bs * usPerAdd * 1e-6)}</td><td class="num">${human(bs / 1e12)}</td><td class="num">${p2(b / 2)} points</td></tr>` +
    `<tr><td>Pollard rho / kangaroo</td><td class="num">≈ ${p2(b / 2 + 1)}</td><td class="num">${human(bs * usPerAdd * 1e-6)}</td><td class="num">${human(bs / 1e12)}</td><td class="num">O(1)</td></tr>`;
}
$("ks-bits").oninput = updateKeySize;

// =================================================== init
setKey();
updateCaesar();
runHist();
$("sa-gen").onclick();
updateKeySize();

// highlight the current section in the nav
const links = [...document.querySelectorAll("nav.toc a")];
const obs = new IntersectionObserver((entries) => {
  entries.forEach((e) => { if (e.isIntersecting) links.forEach((a) => a.classList.toggle("active", a.getAttribute("href") === "#" + e.target.id)); });
}, { rootMargin: "-40% 0px -55% 0px" });
document.querySelectorAll("main section").forEach((s) => obs.observe(s));
