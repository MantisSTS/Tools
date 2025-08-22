#!/usr/bin/env python3
import sys
import itertools
from datetime import datetime

# Common suffixes/prefixes
numbers = ["", "1", "12", "123", "1234", "12345"]
specials = ["", "!", "@", "#", "$"]
years = ["", str(datetime.now().year), str(datetime.now().year - 1), str(datetime.now().year + 1)]

# Leet substitutions
leet_map = {
    "a": ["4", "@"],
    "e": ["3"],
    "i": ["1", "!"],
    "o": ["0"],
    "s": ["5", "$"],
    "t": ["7"],
}

def leetify(word):
    """Generate leet variations of a word"""
    options = []
    for ch in word:
        if ch.lower() in leet_map:
            subs = leet_map[ch.lower()]
            # keep both original and subs
            options.append([ch] + subs)
        else:
            options.append([ch])
    # Cartesian product of all substitutions
    for combo in itertools.product(*options):
        yield "".join(combo)

def generate_variants(word, use_leet=False):
    variants = set()
    cases = {word, word.lower(), word.upper(), word.capitalize()}

    for base in cases:
        words = [base]
        if use_leet:
            words.extend(list(leetify(base)))

        for w in words:
            variants.add(w)
            for n in numbers + years:
                for s in specials:
                    variants.add(f"{w}{n}{s}")
                    variants.add(f"{w}{s}{n}")
                    variants.add(f"{s}{w}{n}")
                    variants.add(f"{n}{w}{s}")

    return variants

if __name__ == "__main__":
    use_leet = False
    words = []

    for arg in sys.argv[1:]:
        if arg in ("--leet", "-l"):
            use_leet = True
        else:
            words.append(arg)

    if not words:
        print(f"Usage: {sys.argv[0]} <word1> <word2> ... [--leet|-l]")
        sys.exit(1)

    all_variants = set()
    for word in words:
        all_variants |= generate_variants(word, use_leet)

    for pw in sorted(all_variants):
        print(pw)
