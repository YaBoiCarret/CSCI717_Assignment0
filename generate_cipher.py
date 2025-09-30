#!/usr/bin/env python3
import argparse, random, string

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

def random_key(seed=None):
    if seed is not None:
        random.seed(seed)
    lst = list(ALPHABET)
    random.shuffle(lst)
    return "".join(lst)

def apply_key(plain, key):
    table = {ALPHABET[i]: key[i] for i in range(26)}
    out = []
    for ch in plain:
        if ch.isalpha():
            up = ch.upper()
            c = table[up]
            out.append(c if ch.isupper() else c.lower())
        else:
            out.append(ch)
    return "".join(out)

def main():
    p = argparse.ArgumentParser(description="Generate an Aristocrat cipher from plaintext")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--in", dest="infile", type=str, help="Path to plaintext file")
    src.add_argument("--text", dest="text", type=str, help="Plaintext string")
    p.add_argument("--out", type=str, required=True, help="Output ciphertext file")
    p.add_argument("--seed", type=int, default=None, help="Random seed for key")
    args = p.parse_args()

    if args.infile:
        with open(args.infile, "r", encoding="utf-8") as f:
            plain = f.read()
    else:
        plain = args.text

    key = random_key(args.seed)
    cipher = apply_key(plain, key)

    with open(args.out, "w", encoding="utf-8") as f:
        f.write(cipher)

    print("Key (PLAIN->CIPHER):")
    print("PLAIN : " + " ".join(list(ALPHABET)))
    print("CIPHER: " + " ".join(list(key)))
    print(f"\nWrote ciphertext to: {args.out}")

if __name__ == "__main__":
    main()
