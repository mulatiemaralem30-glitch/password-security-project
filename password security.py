#!/usr/bin/env python3
"""
Password Strength Analyzer and Secure Password Generator
--------------------------------------------------------
Uses only the Python standard library (3.8+).

Usage:
    python password_tool.py                    # interactive menu
    python password_tool.py analyze            # prompts for a password (hidden input)
    python password_tool.py generate -l 20     # random password, 20 chars
    python password_tool.py passphrase -w 5    # 5-word passphrase
"""

import argparse
import getpass
import math
import re
import secrets
import string
from dataclasses import dataclass, field

# --------------------------------------------------------------------------
# Data
# --------------------------------------------------------------------------

# Small built-in list of very common passwords. For real use, load a larger
# list such as the top 100k from SecLists via load_wordlist().
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "12345678", "12345", "1234567",
    "qwerty", "abc123", "password1", "111111", "iloveyou", "admin",
    "welcome", "monkey", "login", "letmein", "football", "dragon",
    "baseball", "master", "sunshine", "princess", "trustno1", "passw0rd",
    "p@ssw0rd", "qwerty123", "1q2w3e4r", "zaq12wsx", "000000", "123123",
    "superman", "batman", "shadow", "michael", "freedom", "whatever",
}

KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]

LEET_MAP = str.maketrans("@4$50137!", "aassoleti")

WORDLIST = [
    "anchor", "bamboo", "candle", "dolphin", "ember", "falcon", "glacier",
    "harbor", "island", "jungle", "kettle", "lantern", "meadow", "nectar",
    "orchid", "pebble", "quartz", "river", "saddle", "thunder", "umbrella",
    "velvet", "willow", "yonder", "zephyr", "acorn", "breeze", "cobalt",
    "desert", "echo", "forest", "granite", "horizon", "ivory", "juniper",
    "koala", "lotus", "marble", "noodle", "ocean", "pepper", "quiver",
    "rocket", "summit", "tundra", "uplift", "violet", "walnut", "yarrow",
    "zigzag", "avocado", "biscuit", "canyon", "driftwood", "eclipse",
    "fountain", "garden", "hammock", "iceberg", "jasmine", "kitten",
    "lemon", "mountain", "nutmeg", "oyster", "puzzle", "rainbow", "spruce",
    "tulip", "valley", "whisper", "xylophone", "yogurt", "zucchini",
]


def load_wordlist(path):
    """Load a newline-separated wordlist file (e.g. rockyou subset)."""
    with open(path, encoding="utf-8", errors="ignore") as f:
        return {line.strip().lower() for line in f if line.strip()}


# --------------------------------------------------------------------------
# Analyzer
# --------------------------------------------------------------------------

@dataclass
class Report:
    password_length: int
    charset_size: int
    entropy_bits: float
    effective_bits: float
    score: int                      # 0-100
    rating: str
    crack_time: str
    issues: list = field(default_factory=list)
    suggestions: list = field(default_factory=list)


def charset_size(pw):
    size = 0
    if re.search(r"[a-z]", pw):
        size += 26
    if re.search(r"[A-Z]", pw):
        size += 26
    if re.search(r"\d", pw):
        size += 10
    if re.search(r"[^\w\s]", pw) or "_" in pw:
        size += 32
    if re.search(r"\s", pw):
        size += 1
    return size


def has_sequence(pw, length=4):
    """Detect ascending/descending runs (abcd, 4321) and keyboard runs (qwer)."""
    low = pw.lower()
    for i in range(len(low) - length + 1):
        chunk = low[i:i + length]
        codes = [ord(c) for c in chunk]
        diffs = {codes[j + 1] - codes[j] for j in range(length - 1)}
        if diffs == {1} or diffs == {-1}:
            return True
        for row in KEYBOARD_ROWS:
            if chunk in row or chunk in row[::-1]:
                return True
    return False


def has_repeats(pw, n=3):
    return re.search(r"(.)\1{%d,}" % (n - 1), pw) is not None


def has_repeated_block(pw):
    return re.fullmatch(r"(.{2,}?)\1+", pw) is not None


def format_time(seconds):
    if seconds < 1:
        return "instantly"
    units = [
        ("seconds", 60), ("minutes", 60), ("hours", 24), ("days", 365),
        ("years", 1000), ("thousand years", 1000), ("million years", 1000),
        ("billion years", 1000),
    ]
    value = seconds
    for name, step in units:
        if value < step:
            return f"{value:,.0f} {name}"
        value /= step
    return "trillions of years or more"


def analyze(password, common=COMMON_PASSWORDS, guesses_per_sec=1e10):
    """Analyze a password and return a Report.

    guesses_per_sec defaults to 10 billion/s, roughly an offline attack on a
    fast hash using GPUs.
    """
    issues, suggestions = [], []
    n = len(password)

    if n == 0:
        return Report(0, 0, 0.0, 0.0, 0, "Empty", "instantly",
                      ["Password is empty."], ["Enter a password."])

    cs = charset_size(password)
    entropy = n * math.log2(cs) if cs else 0.0
    penalty = 0.0

    normalized = password.lower().translate(LEET_MAP)
    if password.lower() in common or normalized in common:
        issues.append("Matches a very common password.")
        penalty += entropy  # effectively zero
    else:
        for word in common:
            if len(word) >= 5 and word in normalized:
                issues.append(f"Contains a common password ('{word}').")
                penalty += entropy * 0.6
                break

    if n < 8:
        issues.append("Shorter than 8 characters.")
        suggestions.append("Use at least 12 characters (16+ is better).")
    elif n < 12:
        suggestions.append("Longer is stronger: aim for 12+ characters.")

    if not re.search(r"[a-z]", password):
        suggestions.append("Add lowercase letters.")
    if not re.search(r"[A-Z]", password):
        suggestions.append("Add uppercase letters.")
    if not re.search(r"\d", password):
        suggestions.append("Add digits.")
    if not re.search(r"[^A-Za-z0-9]", password):
        suggestions.append("Add symbols (e.g. !@#$%).")

    if has_repeats(password):
        issues.append("Contains repeated characters (e.g. 'aaa').")
        penalty += 10
    if has_repeated_block(password):
        issues.append("Is a short pattern repeated (e.g. 'abab').")
        penalty += entropy * 0.5
    if has_sequence(password):
        issues.append("Contains a sequence or keyboard pattern (abcd, qwer, 1234).")
        penalty += 15
    if re.fullmatch(r"\d+", password):
        issues.append("Only digits.")
        penalty += 10
    if re.fullmatch(r"[A-Za-z]+", password):
        issues.append("Only letters.")
        penalty += 5
    if re.search(r"(19|20)\d{2}$", password):
        issues.append("Ends with a year, which is easy to guess.")
        penalty += 8

    effective = max(entropy - penalty, 0.0)
    seconds = (2 ** effective) / 2 / guesses_per_sec
    # Score: 0 bits -> 0, 100 bits -> 100
    score = max(0, min(100, round(effective)))

    if score < 25:
        rating = "Very Weak"
    elif score < 45:
        rating = "Weak"
    elif score < 65:
        rating = "Fair"
    elif score < 85:
        rating = "Strong"
    else:
        rating = "Very Strong"

    if not issues and not suggestions:
        suggestions.append("Looks good. Store it in a password manager.")

    return Report(n, cs, round(entropy, 1), round(effective, 1), score,
                  rating, format_time(seconds), issues, suggestions)


def print_report(r):
    bar_len = 30
    filled = round(r.score / 100 * bar_len)
    bar = "#" * filled + "-" * (bar_len - filled)
    print("\n" + "=" * 50)
    print(f" Rating : {r.rating}  (score {r.score}/100)")
    print(f" [{bar}]")
    print(f" Length : {r.password_length}   Charset size: {r.charset_size}")
    print(f" Entropy: {r.entropy_bits} bits (effective: {r.effective_bits} bits)")
    print(f" Est. offline crack time: {r.crack_time}")
    if r.issues:
        print("\n Issues:")
        for i in r.issues:
            print(f"  - {i}")
    if r.suggestions:
        print("\n Suggestions:")
        for s in r.suggestions:
            print(f"  - {s}")
    print("=" * 50 + "\n")


# --------------------------------------------------------------------------
# Generator (uses the `secrets` module, which is cryptographically secure)
# --------------------------------------------------------------------------

AMBIGUOUS = set("Il1O0o")
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"


def generate_password(length=16, lower=True, upper=True, digits=True,
                      symbols=True, avoid_ambiguous=False):
    pools = []
    if lower:
        pools.append(string.ascii_lowercase)
    if upper:
        pools.append(string.ascii_uppercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append(SYMBOLS)

    if avoid_ambiguous:
        pools = ["".join(c for c in p if c not in AMBIGUOUS) for p in pools]

    if not pools:
        raise ValueError("Select at least one character type.")
    if length < len(pools):
        raise ValueError(f"Length must be at least {len(pools)} for the chosen options.")

    # Guarantee at least one character from every selected pool
    chars = [secrets.choice(p) for p in pools]
    all_chars = "".join(pools)
    chars += [secrets.choice(all_chars) for _ in range(length - len(chars))]

    # Cryptographically secure shuffle
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def generate_passphrase(words=5, separator="-", capitalize=True, add_number=True):
    if words < 3:
        raise ValueError("Use at least 3 words.")
    picked = [secrets.choice(WORDLIST) for _ in range(words)]
    if capitalize:
        picked = [w.capitalize() for w in picked]
    phrase = separator.join(picked)
    if add_number:
        phrase += separator + str(secrets.randbelow(100))
    return phrase


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def ask_bool(prompt, default=True):
    suffix = "[Y/n]" if default else "[y/N]"
    ans = input(f"{prompt} {suffix}: ").strip().lower()
    return default if not ans else ans.startswith("y")


def interactive():
    while True:
        print("Password Tool")
        print("  1) Analyze a password")
        print("  2) Generate a random password")
        print("  3) Generate a passphrase")
        print("  4) Quit")
        choice = input("Choose: ").strip()

        if choice == "1":
            pw = getpass.getpass("Enter password (hidden): ")
            print_report(analyze(pw))
        elif choice == "2":
            try:
                length = int(input("Length [16]: ") or 16)
                pw = generate_password(
                    length,
                    lower=ask_bool("Lowercase?"),
                    upper=ask_bool("Uppercase?"),
                    digits=ask_bool("Digits?"),
                    symbols=ask_bool("Symbols?"),
                    avoid_ambiguous=ask_bool("Avoid look-alike chars (Il1O0)?", False),
                )
                print(f"\nGenerated: {pw}")
                print_report(analyze(pw))
            except ValueError as e:
                print(f"Error: {e}\n")
        elif choice == "3":
            try:
                n = int(input("Number of words [5]: ") or 5)
                phrase = generate_passphrase(n)
                print(f"\nGenerated: {phrase}")
                print_report(analyze(phrase))
            except ValueError as e:
                print(f"Error: {e}\n")
        elif choice == "4":
            break
        else:
            print("Invalid choice.\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd")

    a = sub.add_parser("analyze", help="check password strength")
    a.add_argument("password", nargs="?",
                   help="password to check (omit to be prompted securely)")

    g = sub.add_parser("generate", help="generate a random password")
    g.add_argument("-l", "--length", type=int, default=16)
    g.add_argument("--no-lower", action="store_true")
    g.add_argument("--no-upper", action="store_true")
    g.add_argument("--no-digits", action="store_true")
    g.add_argument("--no-symbols", action="store_true")
    g.add_argument("--avoid-ambiguous", action="store_true")
    g.add_argument("-n", "--count", type=int, default=1)

    p = sub.add_parser("passphrase", help="generate a word-based passphrase")
    p.add_argument("-w", "--words", type=int, default=5)
    p.add_argument("-s", "--separator", default="-")

    args = parser.parse_args()

    try:
        if args.cmd == "analyze":
            pw = args.password or getpass.getpass("Enter password (hidden): ")
            print_report(analyze(pw))
        elif args.cmd == "generate":
            for _ in range(args.count):
                pw = generate_password(
                    args.length,
                    lower=not args.no_lower, upper=not args.no_upper,
                    digits=not args.no_digits, symbols=not args.no_symbols,
                    avoid_ambiguous=args.avoid_ambiguous,
                )
                print(pw)
        elif args.cmd == "passphrase":
            print(generate_passphrase(args.words, args.separator))
        else:
            interactive()
    except ValueError as e:
        parser.error(str(e))
    except (KeyboardInterrupt, EOFError):
        print()


if __name__ == "__main__":
    main()