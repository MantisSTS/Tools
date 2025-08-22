#!/usr/bin/env python3
import sys
import itertools
from datetime import datetime

# Common suffixes/prefixes to try
numbers = ["", "1", "123", "1234", "12345"]
specials = ["", "!", "@", "#", "$"]
years = ["", str(datetime.now().year), str(datetime.now().year - 1), str(datetime.now().year + 1)]

def generate_variants(word):
    variants = set()

    # Case variants
    cases = {word, word.lower(), word.upper(), word.capitalize()}

    for base in cases:
        # Add plain word
        variants.add(base)

        # Combine with numbers, specials, years
        for n in numbers + years:
            for s in specials:
                variants.add(f"{base}{n}{s}")
                variants.add(f"{base}{s}{n}")
                variants.add(f"{s}{base}{n}")
                variants.add(f"{n}{base}{s}")

    return variants

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <word1> <word2> ...")
        sys.exit(1)

    all_variants = set()
    for word in sys.argv[1:]:
        all_variants |= generate_variants(word)

    for pw in sorted(all_variants):
        print(pw)
