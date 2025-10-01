#!/usr/bin/env python3
import argparse, random, string, math, re, json, sys
from collections import Counter

ETAOIN = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

COMMON_WORDS = set("the be to of and a in that have I it for not on with he as you do at this but his by from they we say her she or an will my one all would there their what so up out if about who get which go me when make can like time no just him know take people into year your good some could them see other than then now look only come its over think also back after use two how our work first well way even new want because any these give day most us are is was were been had did does won t don re ve ll s m isn weren hasn aren".split())
BIGRAMS = ["TH","HE","IN","ER","AN","RE","ON","AT","EN","ND","TI","ES","OR","TE","OF","ED","IS","IT","AL","AR","ST","TO","NT","NG","SE","HA","AS","OU","IO","LE","IS","VE"]
TRIGRAMS = ["THE","AND","ING","ENT","ION","HER","FOR","THA","NTH","INT","ERE","TIO","TER","EST","ERS","ATI","HES","VER","ALL"]

# NEW: tiny function-word list (boundary-scored) and boundary bigrams
BOUNDARY_WORDS = ["the","and","to","of","in","on","is","it","we","he","be","as","at","for","with","that","this"]
START_BIGRAMS = ["th","he","in","re","an","co","de","pr","en","st"]
END_BIGRAMS   = ["ed","es","er","ly","al","an","on","nd","st","nt"]

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

def score_text(text, boundary_on=True, bw=0.4, bs=0.3, be=0.3, want_breakdown=False):
    up = text.upper()
    score = 0.0
    breakdown = {"bigrams":0.0,"trigrams":0.0,"common_words":0.0,"boundary_words":0.0,"start_bigrams":0.0,"end_bigrams":0.0,"q_penalty":0.0,"space_bonus":0.0}
    # classic ngram bonuses
    for bg in BIGRAMS:
        c = up.count(bg)
        score += c * 1.5
        breakdown["bigrams"] += c * 1.5
    for tg in TRIGRAMS:
        c = up.count(tg)
        score += c * 2.5
        breakdown["trigrams"] += c * 2.5
    # common-word hits
    words = re.findall(word_re, text.lower())
    hits = sum(1 for w in words if w in COMMON_WORDS)
    score += hits * 1.2
    breakdown["common_words"] += hits * 1.2

    # NEW: boundary function words (strict \bword\b), lightly capped
    # use provided bw (boundary words weight)
    boundary_cap   = 40
    bcount = 0
    for w in BOUNDARY_WORDS:
        bcount += len(re.findall(rf"\\b{re.escape(w)}\\b", text, flags=re.IGNORECASE))
    if boundary_on:
        boundary_words_score = min(bcount, boundary_cap) * bw
        score += boundary_words_score
        breakdown["boundary_words"] += boundary_words_score

    # NEW: boundary bigrams at word starts/ends
    # use provided bs/be (start/end boundary bigram weights)
    start_cap, end_cap = 60, 60
    start_hits = sum(len(re.findall(rf"\\b{re.escape(bg)}", text, flags=re.IGNORECASE)) for bg in START_BIGRAMS)
    end_hits   = sum(len(re.findall(rf"{re.escape(bg)}\\b", text, flags=re.IGNORECASE)) for bg in END_BIGRAMS)
    if boundary_on:
        start_score = min(start_hits, start_cap) * bs
        end_score   = min(end_hits, end_cap) * be
        score += start_score + end_score
        breakdown["start_bigrams"] += start_score
        breakdown["end_bigrams"] += end_score

    # existing extras
    qpen = len(re.findall(r"Q(?!U)", up)) * 0.8
    score -= qpen
    breakdown["q_penalty"] -= qpen
    spaces = text.count(' ')
    sbonus = min(spaces, 50) * 0.05
    score += sbonus
    breakdown["space_bonus"] += sbonus
    return (score, breakdown) if want_breakdown else score


def three_cycle(key):
    a, b, c = random.sample(range(26), 3)
    lst = list(key)
    lst[a], lst[b], lst[c] = lst[c], lst[a], lst[b]
    return "".join(lst)

def targeted_reassign(key, cipher_text, etaoin="ETAOINSHRDLCUMWFGYPBVKJXQZ"):
    """
    Bias: pick a cipher letter weighted by its frequency in the ciphertext,
    then try to map it to a desired plain letter from the head of ETAOIN.
    Implementation: swap the chosen cipher index with the index currently
    holding the desired plain letter (keeps permutation valid).
    """
    # compute cipher letter freqs from ciphertext
    letters = [ch for ch in cipher_text.upper() if 'A' <= ch <= 'Z']
    if not letters:
        return key
    freqs = {}
    for ch in letters:
        freqs[ch] = freqs.get(ch, 0) + 1
    # pick cipher letter by frequency weight
    population = list(freqs.keys())
    weights = [freqs[ch] for ch in population]
    pick = random.choices(population, weights=weights, k=1)[0]
    a = ord(pick) - 65  # cipher index

    # prefer one of the top-N ETAOIN letters as target plain
    N = 8
    desired_plain = random.choice(list(etaoin[:N]))
    # find index j such that key[j] == desired_plain
    lst = list(key)
    try:
        j = lst.index(desired_plain)
    except ValueError:
        return key  # shouldn't happen; plain letters should all be present
    if j == a:
        return key  # already assigned

    # swap a and j
    lst[a], lst[j] = lst[j], lst[a]
    return "".join(lst)

def random_neighbor_enriched(key, cipher_text, p_three=0.2, p_target=0.2):
    # Clamp probabilities
    p_three = max(0.0, min(1.0, p_three))
    p_target = max(0.0, min(1.0 - p_three, p_target))
    r = random.random()
    if r < p_three:
        return three_cycle(key)
    elif r < p_three + p_target:
        return targeted_reassign(key, cipher_text)
    else:
        # default swap
        a, b = random.sample(range(26), 2)
        lst = list(key)
        lst[a], lst[b] = lst[b], lst[a]
        return "".join(lst)
def random_neighbor(key):
    a, b = random.sample(range(26), 2)
    lst = list(key)
    lst[a], lst[b] = lst[b], lst[a]
    return "".join(lst)

def anneal(cipher, start_key, steps=8000, temp_start=3.0, temp_end=0.05, boundary_on=True, bw=0.4, bs=0.3, be=0.3, debug=False, use_enriched=False, p3=0.2, pt=0.2):
    def temp(t):
        return temp_start * ((temp_end / temp_start) ** (t / max(1, steps-1)))
    current_key = start_key
    current_plain = apply_key(cipher, current_key)
    current_score = score_text(current_plain, boundary_on, bw, bs, be)
    best_key, best_score, best_plain = current_key, current_score, current_plain
    for t in range(steps):
        cand_key = (random_neighbor_enriched(current_key, cipher, p_three=p3, p_target=pt) if use_enriched else random_neighbor(current_key))
        cand_plain = apply_key(cipher, cand_key)
        cand_score = score_text(cand_plain, boundary_on, bw, bs, be)
        d = cand_score - current_score
        if d >= 0 or random.random() < math.exp(d / max(1e-6, temp(t))):
            current_key, current_score, current_plain = cand_key, cand_score, cand_plain
            if current_score > best_score:
                best_key, best_score, best_plain = current_key, current_score, current_plain
    return {"best_key": best_key, "best_score": best_score, "best_plain": best_plain}

def random_key():
    import random
    lst = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    random.shuffle(lst)
    return "".join(lst)

def solve(cipher, steps=8000, restarts=25, seed=None, boundary_on=True, bw=0.4, bs=0.3, be=0.3, score_debug=False, use_enriched=False, p3=0.2, pt=0.2):
    if seed is not None:
        random.seed(seed)
    results = []
    seed_map = freq_seed_key(cipher)
    seed_key = invert_mapping(seed_map)
    for r in range(restarts):
        start_key = seed_key if r == 0 else random_key()
        res = anneal(cipher, start_key, steps=steps, boundary_on=boundary_on, bw=bw, bs=bs, be=be, debug=score_debug, use_enriched=use_enriched, p3=p3, pt=pt)
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
    p.add_argument("--no-boundary", action="store_true", help="Disable boundary word & boundary-bigram bonuses")
    p.add_argument("--bw", type=float, default=0.4, help="Boundary words weight")
    p.add_argument("--bs", type=float, default=0.3, help="Boundary start-bigram weight")
    p.add_argument("--be", type=float, default=0.3, help="Boundary end-bigram weight")
    p.add_argument("--score-debug", action="store_true", help="Print score breakdown for best plaintext")
    p.add_argument("--use-enriched", action="store_true", help="Use enriched move set (3-cycle + targeted reassign)")
    p.add_argument("--p3", type=float, default=0.2, help="Probability of 3-cycle move when enriched is on")
    p.add_argument("--pt", type=float, default=0.2, help="Probability of targeted reassign when enriched is on")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--cipher", type=str, help="Ciphertext string")
    src.add_argument("--file", type=str, help="Path to ciphertext file")
    p.add_argument("--steps", type=int, default=8000, help="Annealing steps per restart")
    p.add_argument("--restarts", type=int, default=25, help="Number of restarts")
    p.add_argument("--seed", type=int, default=None, help="Random seed")
    p.add_argument("--json-out", type=str, default=None, help="Write JSON with results")
    args = p.parse_args()

    if args.file:
        with open(args.file, "r", encoding="utf-8") as f:
            cipher = f.read()
    else:
        cipher = args.cipher

    boundary_on = not args.no_boundary
    print(f"Boundary active: {boundary_on} | bw={args.bw} bs={args.bs} be={args.be}")
    print(f"Boundary lists: START={len(START_BIGRAMS)} END={len(END_BIGRAMS)} WORDS={len(BOUNDARY_WORDS)}")
    best, allres = solve(cipher, steps=args.steps, restarts=args.restarts, seed=args.seed, boundary_on=boundary_on, bw=args.bw, bs=args.bs, be=args.be, score_debug=args.score_debug)

    print("="*72)
    print(" BEST SCORE:", round(best["best_score"], 2))
    print("="*72)
    print(pretty_key(best["best_key"]))
    print("-"*72)
    print("PLAINTEXT GUESS:\\n")
    print(best["best_plain"])
    print("-"*72)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as jf:
            json.dump(best, jf, indent=2)

if __name__ == "__main__":
    main()
