#!/usr/bin/env python3
import argparse, random, string, math, re, json, sys
from collections import Counter

ETAOIN = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

COMMON_WORDS = set("""the be to of and a in that have I it for not on with he as you do at this but his by from they we say her she or an will my one all would there their what so up out if about who get which go me when make can like time no just him know take people into year your good some could them see other than then now look only come its over think also back after use two how our work first well way even new want because any these give day most us are is was were been had did does won t don re ve ll s m isn weren hasn aren""".split())
BIGRAMS = ["TH", "HE", "IN", "ER", "AN", "RE", "ON", "AT", "EN", "ND", "TI", "ES", "OR", "TE", "OF", "ED", "IS", "IT", "AL", "AR", "ST", "TO", "NT", "NG", "SE", "HA", "AS", "OU", "IO", "LE", "IS", "VE"]
TRIGRAMS = ["THE", "AND", "ING", "ENT", "ION", "HER", "FOR", "THA", "NTH", "INT", "ERE", "TIO", "TER", "EST", "ERS", "ATI", "HES", "VER", "ALL"]

word_re = re.compile(r"\b[a-zA-Z]{2,}\b")

def letters_only(s):
    return re.sub(r"[^A-Za-z]+", "", s).upper()

def freq_seed_key(ciphertext):
    text = letters_only(ciphertext)
    if not text:
        return dict(zip(ALPHABET, ALPHABET))
    freqs = Counter(text)
    cipher_order = "".join([p for p,_ in freqs.most_common()])
    for ch in ALPHABET:
        if ch not in cipher_order:
            cipher_order += ch
    mapping = {}
    for i, c in enumerate(cipher_order):
        mapping[c] = ETAOIN[i] if i < len(ETAOIN) else (set(ALPHABET) - set(ETAOIN))[i-len(ETAOIN)]
    for c in ALPHABET:
        mapping.setdefault(c, c)
    return mapping

def invert_mapping(map_cp):
    key = {c:map_cp.get(c, c) for c in ALPHABET}
    return "".join(key[c] for c in ALPHABET)

def apply_key(cipher, key):
    out = []
    for ch in cipher:
        if ch.isalpha():
            idx = ord(ch.upper()) - 65
            plain = key[idx]
            out.append(plain if ch.isupper() else plain.lower())
        else:
            out.append(ch)
    return "".join(out)

def score_text(text):
    up = text.upper()
    score = 0.0
    for bg in BIGRAMS:
        score += up.count(bg) * 1.5
    for tg in TRIGRAMS:
        score += up.count(tg) * 2.5
    words = re.findall(word_re, text.lower())
    hits = sum(1 for w in words if w in COMMON_WORDS)
    score += hits * 1.2
    score -= len(re.findall(r"Q(?!U)", up)) * 0.8
    spaces = text.count(' ')
    score += min(spaces, 50) * 0.05
    return score

def random_neighbor(key):
    if random.random() < 0.15:  # 15% chance of 3-cycle
        a, b, c = random.sample(range(26), 3)
        lst = list(key)
        lst[a], lst[b], lst[c] = lst[b], lst[c], lst[a]
        return "".join(lst)
    else:
        a, b = random.sample(range(26), 2)
        lst = list(key)
        lst[a], lst[b] = lst[b], lst[a]
        return "".join(lst)

def anneal(cipher, start_key, steps=8000, temp_start=3.0, temp_end=0.05):
    def temp(t):
        return temp_start * ((temp_end / temp_start) ** (t / max(1, steps-1)))
    current_key = start_key
    current_plain = apply_key(cipher, current_key)
    current_score = score_text(current_plain)
    best_key, best_score, best_plain = current_key, current_score, current_plain

    for t in range(steps):
        cand_key = random_neighbor(current_key)
        cand_plain = apply_key(cipher, cand_key)
        cand_score = score_text(cand_plain)
        d = cand_score - current_score
        if d >= 0 or random.random() < math.exp(d / max(1e-6, temp(t))):
            current_key, current_score, current_plain = cand_key, cand_score, cand_plain
            if current_score > best_score:
                best_key, best_score, best_plain = current_key, current_score, current_plain
    return {"best_key": best_key, "best_score": best_score, "best_plain": best_plain}

def random_key():
    lst = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    random.shuffle(lst)
    return "".join(lst)

def solve(cipher, steps=8000, restarts=25, seed=None):
    if seed is not None:
        random.seed(seed)
    results = []
    seed_map = freq_seed_key(cipher)
    seed_key = invert_mapping(seed_map)
    for r in range(restarts):
        start_key = seed_key if r == 0 else random_key()
        res = anneal(cipher, start_key, steps=steps)
        res["restart"] = r
        results.append(res)
    best = max(results, key=lambda x: x["best_score"])
    return best, results

def pretty_key(key):
    header = "CIPHER: " + " ".join("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    plain  = "PLAIN : " + " ".join(list(key))
    return header + "\\n" + plain

def main():
    p = argparse.ArgumentParser(description="Aristocrat (monoalphabetic substitution) solver")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--cipher", type=str, help="Ciphertext string")
    src.add_argument("--file", type=str, help="Path to ciphertext file")
    p.add_argument("--steps", type=int, default=8000, help="Annealing steps per restart")
    p.add_argument("--restarts", type=int, default=25, help="Number of restarts")
    p.add_argument("--seed", type=int, default=None, help="Random seed")
    args = p.parse_args()

    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            cipher = f.read()
    else:
        cipher = args.cipher

    best, allres = solve(cipher, steps=args.steps, restarts=args.restarts, seed=args.seed)

    print("="*72)
    print(" BEST SCORE:", round(best["best_score"], 2))
    print("="*72)
    print(pretty_key(best["best_key"]))
    print("-"*72)
    print("PLAINTEXT GUESS:\\n")
    print(best["best_plain"])
    print("-"*72)

if __name__ == "__main__":
    main()
