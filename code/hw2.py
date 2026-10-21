"""
Homework 2 - reference implementation (Python 3, standard library only).
 - toy ECIES-style hybrid scheme on secp256k1 (private key d in [1, 2^20])
 - Caesar cipher
 - statistical attacks on Caesar (most-frequent-letter, chi-squared, bigram, quadgram)
 - attacks on the toy scheme (brute force + baby-step giant-step)
Run:  python3 hw2.py <folder with corpus .txt files>
"""
import hashlib, hmac, math, os, random, secrets, sys, time
from collections import Counter

# ---------------------------------------------------------------- secp256k1
P  = 2**256 - 2**32 - 977
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G  = (GX, GY)
INF = None                                  # point at infinity

def on_curve(Pt):
    if Pt is INF: return True
    x, y = Pt
    return (y*y - x*x*x - 7) % P == 0

def add(A, B):
    if A is INF: return B
    if B is INF: return A
    x1, y1 = A; x2, y2 = B
    if x1 == x2 and (y1 + y2) % P == 0: return INF
    if A == B: lam = 3*x1*x1 * pow(2*y1, -1, P) % P
    else:      lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam*lam - x1 - x2) % P
    return (x3, (lam*(x1 - x3) - y1) % P)

def neg(A): return INF if A is INF else (A[0], (-A[1]) % P)

def mul(k, A):                              # double-and-add
    R = INF
    while k:
        if k & 1: R = add(R, A)
        A = add(A, A); k >>= 1
    return R

# ---------------------------------------------------------------- toy ECIES
D_MAX = 2**20

def keygen():
    d = secrets.randbelow(D_MAX) + 1        # THE weakness: only 2^20 keys
    return d, mul(d, G)

def kdf(S):                                 # shared point -> 2 x 32-byte keys
    xb = S[0].to_bytes(32, "big")
    return hashlib.sha256(xb + b"\x01").digest(), hashlib.sha256(xb + b"\x02").digest()

def keystream(key, n):
    out = b""; c = 0
    while len(out) < n:
        out += hashlib.sha256(key + c.to_bytes(4, "big")).digest(); c += 1
    return out[:n]

def ecies_encrypt(Q, msg: bytes):
    k = secrets.randbelow(N - 1) + 1        # fresh ephemeral key, full size
    R = mul(k, G); S = mul(k, Q)
    k_enc, k_mac = kdf(S)
    c = bytes(a ^ b for a, b in zip(msg, keystream(k_enc, len(msg))))
    tag = hmac.new(k_mac, c, hashlib.sha256).digest()
    return R, c, tag

def ecies_decrypt(d, R, c, tag):
    if not on_curve(R) or R is INF: raise ValueError("invalid point R")
    S = mul(d, R)
    k_enc, k_mac = kdf(S)
    if not hmac.compare_digest(tag, hmac.new(k_mac, c, hashlib.sha256).digest()):
        raise ValueError("MAC check failed")
    return bytes(a ^ b for a, b in zip(c, keystream(k_enc, len(c))))

# ---------------------------------------------------------------- attacks on toy scheme
def brute_force(Q, limit=D_MAX):
    T = G
    for d in range(1, limit + 1):
        if T == Q: return d
        T = add(T, G)
    return None

def bsgs(Q, limit=D_MAX):
    m = math.isqrt(limit) + 1
    table, T = {}, INF                      # baby steps: jG for j = 0..m-1
    for j in range(m):
        table[T] = j; T = add(T, G)
    step = neg(mul(m, G))                   # -mG
    Y = Q
    for i in range(m + 1):                  # giant steps: Q - i*mG
        if Y in table: return i*m + table[Y]
        Y = add(Y, step)
    return None

# ---------------------------------------------------------------- Caesar
A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
def caesar(text, k):
    out = []
    for ch in text:
        if ch.isupper() and ch in A: out.append(A[(A.index(ch) + k) % 26])
        elif ch.upper() in A and ch.islower(): out.append(A[(A.index(ch.upper()) + k) % 26].lower())
        else: out.append(ch)
    return "".join(out)

def letters(t): return "".join(c for c in t.upper() if "A" <= c <= "Z")

class Model:
    def __init__(self, corpus):
        L = letters(corpus)
        cnt = Counter(L); tot = len(L)
        self.uni = [cnt[c] / tot for c in A]
        bi = Counter(L[i:i+2] for i in range(len(L) - 1))
        tb = sum(bi.values())
        self.bi = {a+b: math.log10((bi[a+b] + 0.5) / tb) for a in A for b in A}
        q = Counter(L[i:i+4] for i in range(len(L) - 3)); tq = sum(q.values())
        self.quad = {g: math.log10(v / tq) for g, v in q.items()}
        self.quad_floor = math.log10(0.01 / tq)
        self.n_letters = tot

    def chi2(self, L):
        n = len(L); cnt = Counter(L)
        return sum((cnt[c] - n*e)**2 / (n*e) for c, e in zip(A, self.uni))
    def bigram(self, L): return sum(self.bi[L[i:i+2]] for i in range(len(L) - 1))
    def quadgram(self, L): return sum(self.quad.get(L[i:i+4], self.quad_floor) for i in range(len(L) - 3))

def attack_mostfreq(L, M):
    top = Counter(L).most_common(1)[0][0]
    return (A.index(top) - 4) % 26          # assume it is 'E'

def attack_exhaustive(L, M, score, minimize):
    cands = [(score(letters(caesar(L, -k))), k) for k in range(26)]
    return (min(cands) if minimize else max(cands))[1]

def main(folder):
    train_files = ["austen-emma.txt", "austen-persuasion.txt", "austen-sense.txt",
                   "chesterton-ball.txt", "chesterton-brown.txt", "chesterton-thursday.txt",
                   "melville-moby_dick.txt", "edgeworth-parents.txt"]
    test_file = "carroll-alice.txt"         # held-out author, never used for training
    corpus = "".join(open(os.path.join(folder, f), encoding="latin-1").read() for f in train_files)
    M = Model(corpus)
    print(f"training corpus: {M.n_letters:,} letters")
    print("unigram %:", " ".join(f"{c}={100*p:.2f}" for c, p in zip(A, M.uni)))

    test = letters(open(os.path.join(folder, test_file), encoding="latin-1").read())
    rnd = random.Random(2026)
    methods = {
        "most-frequent=E": lambda L: attack_mostfreq(L, M),
        "chi-squared":     lambda L: attack_exhaustive(L, M, M.chi2, True),
        "bigram":          lambda L: attack_exhaustive(L, M, M.bigram, False),
        "quadgram":        lambda L: attack_exhaustive(L, M, M.quadgram, False),
    }
    TRIALS = 1000
    print(f"\nsuccess rate over {TRIALS} random snippets of '{test_file}' (random key 1..25)")
    print("len   " + "  ".join(f"{m:>16}" for m in methods))
    for n in [5, 10, 15, 20, 25, 30, 40, 50, 75, 100, 200, 500]:
        ok = Counter()
        for _ in range(TRIALS):
            s = rnd.randrange(len(test) - n); pt = test[s:s+n]; k = rnd.randrange(1, 26)
            ct = caesar(pt, k)
            for name, f in methods.items():
                ok[name] += (f(ct) == k)
        print(f"{n:<5} " + "  ".join(f"{100*ok[m]/TRIALS:>15.1f}%" for m in methods))

    # ---- toy ECIES round trip + attacks
    print("\n--- toy ECIES ---")
    d, Q = keygen()
    msg = b"Meet me at the library at noon"
    R, c, tag = ecies_encrypt(Q, msg)
    print("d =", d, " decrypt ->", ecies_decrypt(d, R, c, tag))
    t = time.perf_counter(); d1 = bsgs(Q); t1 = time.perf_counter() - t
    print(f"BSGS recovered d={d1} in {t1:.3f}s  -> {ecies_decrypt(d1, R, c, tag)}")
    t = time.perf_counter(); d2 = brute_force(Q); t2 = time.perf_counter() - t
    print(f"brute force recovered d={d2} in {t2:.3f}s ({d2} point additions)")

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "gutenberg")
