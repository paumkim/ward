#!/usr/bin/env python3
"""Measure the tells in a document instead of eyeballing them.

    prose-audit.py README.md docs/*.md
    prose-audit.py --max-em-dashes 0 --fail-on-tells README.md

Exit code 1 when a threshold is exceeded, so it can run in CI or a pre-commit
hook.

The tool is held to the same standard as WARD's detector: a checker with
false positives gets ignored, which makes it worse than no checker. Each rule
below is written to fire only on a genuine violation.
"""

from __future__ import annotations

import argparse
import re
import sys

#: Line patterns that are structure, not prose.
_STRIP = (
    re.compile(r"```.*?```", re.S),
    re.compile(r"^\s*\|.*\|\s*$", re.M),
    re.compile(r"^\s{4,}\S.*$", re.M),
    re.compile(r"^\s*[-=*_]{3,}\s*$", re.M),
)

#: Structural tells that can be counted line by line.
LINE_TELLS: dict[str, str] = {
        # Contractions included deliberately. "isn't just X" is the common form of
    # the most recognisable signature, and a rule matching only the expanded
    # form misses most of them.
    "false antithesis": (
        r"\b(?:not|isn't|is not|aren't|are not|wasn't|was not)"
        r"\s+(?:just|only|merely|about|for)\b"
    ),
    "meta-framing": (
        r"[Hh]ere'?s (?:the|why|what)"
        r"|the (?:honest|real|short) (?:answer|truth|question)"
        r"|the (?:reality|truth) is"
        r"|worth (?:being|noting|flagging)"
        r"|important to (?:note|understand)"
    ),
    "throat-clearing": (
        r"^(?:Great question|Absolutely|I'd be happy|Let me check"
        r"|It's important to note|It's worth mentioning)"
    ),
    "bolded list lead": r"^\s*[-*]\s+\*\*[^*]+\*\*",
    "empty intensifier": r"\b(?:very|really|extremely|incredibly|super|quite|fairly)\b",
    "unclosed punctuation": r"\b(?:in order to|due to the fact that|has the ability to)\b",
}

_HEADING = re.compile(r"^#{1,6}\s+(.+?)\s*$", re.M)
_WORD = re.compile(r"\b[A-Z][a-z]{2,}\b")

#: A leading article or preposition is correct in sentence case, so it does not
#: count towards title case.
_STOPWORDS = {
    "The", "This", "That", "How", "What", "Why", "When", "Where", "Which",
    "A", "An", "And", "Or", "But", "If", "Of", "In", "On", "For", "To",
    "With", "Using", "Your", "It", "Its", "Is", "Are", "Does", "Do", "Can",
    "Not", "No", "By", "From", "As", "At", "We", "You", "Our", "Their",
}


def prose_only(text: str) -> str:
    for pattern in _STRIP:
        text = pattern.sub("\n", text)
    return text


def split_sentences(text: str) -> list[str]:
    """Split on sentence punctuation and on line boundaries.

    Splitting on newlines matters: a heading followed by a bullet list would
    otherwise merge into one long "sentence" and the longest-sentence metric
    would report nonsense.
    """
    out: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        for piece in re.split(r"(?<=[.!?])\s+", line):
            if len(piece.split()) > 2:
                out.append(piece.strip())
    return out


def count_telegraph_colons(lines: list[str]) -> int:
    """A colon is only a tell when prose follows it.

    A colon introducing a bullet list or a code block is correct in both
    English and Markdown.
    """
    n = 0
    for i, line in enumerate(lines):
        if not re.search(r"[^:.\n]{0,55}:\s*$", line):
            continue
        for following in lines[i + 1 : i + 4]:
            stripped = following.strip()
            if not stripped:
                continue
            if stripped[0] in "-*>|#`":
                break  # introduces a list, blockquote or code
            n += 1
            break
    return n


def count_title_case_headings(raw: str) -> int:
    """Title case means two or more significant words capitalised.

    Counting any capitalised word flags "The event log is tamper-evident",
    which is correct sentence case.
    """
    n = 0
    for m in _HEADING.finditer(raw):
        words = _WORD.findall(m.group(1))
        internal = [w for w in words if w not in _STOPWORDS]
        if len(internal) >= 2:
            n += 1
    return n


def audit(path: str, verbose: bool = True) -> dict:
    with open(path, "r", errors="replace") as fh:
        raw = fh.read()
    text = prose_only(raw)
    lines = text.splitlines()
    # Structural checks run against the raw lines. Code fences are already
    # stripped from `text`, so a colon that introduces a code block would
    # otherwise look like a colon introducing the prose that follows it.
    raw_lines = raw.splitlines()
    sentences = split_sentences(text)
    words = len(re.findall(r"[A-Za-z']+", text))
    per_sentence = words / max(len(sentences), 1)

    counts = {name: sum(1 for l in raw_lines if re.search(p, l))
              for name, p in LINE_TELLS.items()}
    counts["telegraph colon"] = count_telegraph_colons(raw_lines)
    counts["title case heading"] = count_title_case_headings(raw)
    counts = {k: v for k, v in counts.items() if v}

    result = {
        "path": path,
        "words": words,
        "sentences": len(sentences),
        "words_per_sentence": round(per_sentence, 1),
        "em_dashes": raw.count("\u2014"),
        "longest_sentence": max((len(s.split()) for s in sentences), default=0),
        "counts": counts,
        "flagged": sum(counts.values()),
    }

    if verbose:
        print(f"\n=== {path} ===")
        print(f"  {words} words, {len(sentences)} sentences, "
              f"{per_sentence:.1f} words/sentence")
        print(f"  em-dashes: {result['em_dashes']}")
        print(f"  longest sentence: {result['longest_sentence']} words")
        if counts:
            for name, n in counts.items():
                print(f"  {n:>3}x  {name}")
        else:
            print("  no structural tells")
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description="Audit prose for AI tells.")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--max-em-dashes", type=int, default=2)
    ap.add_argument("--max-words-per-sentence", type=float, default=25.0)
    ap.add_argument("--max-longest-sentence", type=int, default=40)
    ap.add_argument("--fail-on-tells", action="store_true",
                    help="also fail when any structural tell is present")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    failures: list[str] = []
    for path in args.paths:
        try:
            r = audit(path, verbose=not args.quiet)
        except OSError as exc:
            print(f"cannot read {path}: {exc}", file=sys.stderr)
            failures.append(path)
            continue
        if r["em_dashes"] > args.max_em_dashes:
            failures.append(f"{path}: {r['em_dashes']} em-dash(es), "
                            f"max {args.max_em_dashes}")
        if r["words_per_sentence"] > args.max_words_per_sentence:
            failures.append(f"{path}: {r['words_per_sentence']} words/sentence, "
                            f"max {args.max_words_per_sentence}")
        if r["longest_sentence"] > args.max_longest_sentence:
            failures.append(f"{path}: longest sentence is "
                            f"{r['longest_sentence']} words, "
                            f"max {args.max_longest_sentence}")
        if args.fail_on_tells and r["flagged"]:
            failures.append(f"{path}: {r['flagged']} structural tell(s)")

    if failures:
        print("\nfailures:", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print("\nall documents within thresholds")
    return 0


if __name__ == "__main__":
    sys.exit(main())