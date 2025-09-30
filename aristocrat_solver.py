import math
import random
import re
from collections import Counter, defaultdict

ALPH = 'abcdefghijklmnopqrstuvwxyz'

def normalize(text):
    return re.sub(r'[^a-zA-Z\s]', ' ', text).lower()

# --- Build n-gram model from a corpus text (one-time) ---
def build_ngram_model(corpus_text, n=4):
    corpus = normalize(corpus_text).replace(' ', '')
    counts = Counter(corpus[i:i+n] for i in range(len(corpus)-n+1))
    total = sum(counts.values())
    # Add small floor to avoid zero probs (Laplace smoothing)
    floor = 0.01
    logp = {gram: math.log((count + floor) / (total + floor * (26**n))) for gram, count in counts.items()}
    default_logp = math.log(floor / (total + floor * (26**n)))
    return logp, default_logp

# --- Wordlist-based scoring (optional external) ---
def load_wordlist(path):
    with open(path, 'r', encoding='utf8', errors='ignore') as f:
        return set(w.strip().lower() for w in f if w.strip())

def word_match_score(candidate_text, wordset):
    words = re.findall(r"[a-z]+", candidate_text.lower())
    if not words:
        return 0.0
    hits = sum(1 for w in words if w in wordset)
    return hits / len(words)

# ======== NEW: tiny built-in wordlist & boundary bigram bonus ========
# High-yield common words; tiny and in-code (no files needed)
MINI_WORDS = {
    "the","and","that","for","you","with","have","this","not","but",
    "his","her","was","are","from","they","said","one","all","there",
    "be","to","of","in","it","is","as","on","by","an","or","at"
}

# Simple word-boundary bigrams (space-aware)
BOUNDARY_BIS = [" th", "he ", " an", " a ", " in", "in ", " to", "to ", " of", "of "]

def boundary_bigram_score(ptxt, w=0.25):
    s = 0.0
    lower = ptxt.lower()
    for bb in BOUNDARY_BIS:
        s += lower.count(bb)
    return w * s
# =====================================================================

# --- Apply key to ciphertext ---
def decrypt_with_key(ctext, key_map):
    # key_map: dict mapping 'a'..'z' ciphertext -> plaintext
    out = []
    for ch in ctext:
        if ch.isalpha():
            lower = ch.lower()
            p = key_map[lower]
            out.append(p.upper() if ch.isupper() else p)
        else:
            out.append(ch)
    return ''.join(out)

# --- Score text using n-grams + word matches (+ new fallbacks) ---
def score_candidate(ptxt, ngram_logp, default_logp, n=4, wordset=None, w_word=2.0):
    # ngram score
    s = 0.0
    alpha = re.sub(r'[^a-z]', '', ptxt.lower())
    for i in range(len(alpha)-n+1):
        gram = alpha[i:i+n]
        s += ngram_logp.get(gram, default_logp)

    # word score: use external wordset if available, else tiny built-in set
    if wordset:
        s += w_word * word_match_score(ptxt, wordset)
    else:
        # add a small per-hit nudge using the tiny in-code list
        hits = sum(1 for w in re.findall(r"[a-z]+", ptxt.lower()) if w in MINI_WORDS)
        s += 1.0 * hits  # modest boost per recognized common word

    # boundary bigram bonus (gentle bias toward English-shaped spacing)
    s += boundary_bigram_score(ptxt, w=0.25)

    return s

# --- Random key operations ---
def random_key():
    letters = list(ALPH)
    plain = letters[:]
    random.shuffle(plain)
    return dict(zip(letters, plain))

def swap_two(key_map):
    # return a new key map with two plaintext values swapped
    k = key_map.copy()
    a, b = random.sample(ALPH, 2)
    k[a], k[b] = k[b], k[a]
    return k

# --- Hill-climbing with simulated annealing ---
def optimize(ctext, ngram_logp, default_logp, wordset=None, iterations=2000, starting_key=None):
    if starting_key is None:
        key = random_key()
    else:
        key = starting_key.copy()
    best_key, best_score = key, score_candidate(decrypt_with_key(ctext, key), ngram_logp, default_logp, wordset=wordset)
    current_key, current_score = best_key.copy(), best_score
    T0 = 1.0
    for i in range(iterations):
        T = T0 * (1 - i / iterations)  # linear cooling
        cand_key = swap_two(current_key)
        cand_text = decrypt_with_key(ctext, cand_key)
        cand_score = score_candidate(cand_text, ngram_logp, default_logp, wordset=wordset)
        delta = cand_score - current_score
        if delta > 0 or math.exp(delta / max(1e-9, T)) > random.random():
            current_key, current_score = cand_key, cand_score
            if current_score > best_score:
                best_key, best_score = current_key.copy(), current_score
    return best_key, best_score

# --- Example usage skeleton ---
if __name__ == '__main__':
    ciphertext = """YOUR CIPHERTEXT GOES HERE"""
    # Option A: build ngram model from a local corpus (provide corpus.txt)
    # with open('corpus.txt','r',encoding='utf8') as f: corpus = f.read()
    # ngram_logp, default_logp = build_ngram_model(corpus, n=4)

    # Option B: fallback approximate model
    ngram_logp, default_logp = {}, math.log(1e-9)

    # Load wordlist if available; otherwise we’ll use MINI_WORDS automatically
    try:
        wordset = load_wordlist('/usr/share/dict/words')
    except Exception:
        wordset = None

    # Run many restarts
    best_overall = None
    best_score = -1e9
    for r in range(50):
        start = None  # could seed a frequency-based key instead
        k, s = optimize(ciphertext, ngram_logp, default_logp, wordset=wordset, iterations=4000, starting_key=start)
        if s > best_score:
            best_score = s
            best_overall = k
            print(f"New best (r={r}) score={s:.2f}:")
            print(decrypt_with_key(ciphertext, best_overall))
    print("FINAL BEST:")
    print(decrypt_with_key(ciphertext, best_overall))
