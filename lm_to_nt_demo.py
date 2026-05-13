#!/usr/bin/env python3
"""
LM -> NT hash recovery pipeline, end to end.

Companion to the SynerComm blog article "Cracking NT Hashes via LM Halves:
A Modern GPU Pipeline." Runnable as a standalone script — no third-party
dependencies, no infrastructure required. Hashcat is the only external tool.

Usage:
    python3 lm_to_nt_demo.py /path/to/dump.pwdump [--workdir ./work]

What it does, in order:

    1. Parses the pwdump into (user, LM_hash, NT_hash) tuples and writes:
         work/lm_halves.txt  — deduplicated 16-char LM halves to crack
         work/nt_hashes.txt  — deduplicated NT hashes to crack
    2. Tells you the hashcat mode-3000 command to run against lm_halves.txt.
       After hashcat finishes, point this script at the resulting potfile
       (or paste the lines into the prompt) so it can reassemble plaintexts.
    3. Reassembles uppercase plaintexts from each user's two cracked LM
       halves. Decodes hashcat's $HEX[...] notation for non-ASCII bytes,
       then checks half-length consistency to flag ordering edge cases.
       When ordering can't be confirmed (rare — e.g. non-standard pwdump
       sources, hash collisions), both p1+p2 AND p2+p1 are emitted as
       candidate plaintexts so the NT crack covers either possibility.
    4. Writes work/case_wordlist.txt containing every case-permutation of
       every uppercase plaintext (up to 2^14 variants per password).
    5. Tells you the hashcat mode-1000 command to run against nt_hashes.txt
       with the case wordlist. After hashcat finishes, point the script at
       the resulting potfile to print the final (user, password) recovery.

Intentional design notes:
    * No HM1K dependencies. Everything is in this file.
    * Filters both the hex empty-LM marker (aad3b435...) AND the modern
      "NO PASSWORD*********************" placeholder that newer secretsdump
      versions emit. Without this you waste a brute-force pass on garbage.
    * Treats each unique LM half independently, so two users sharing the
      same first 7 password characters only contribute one half to crack.
      Partial cracks (one half recovered, the other not) are preserved on
      the user record for downstream reuse analysis — hashcat's `--show`
      against full LM hashes only emits results when both halves crack.
    * Step 3 decodes $HEX[...] sequences in recovered plaintexts. Hashcat
      writes non-renderable bytes that way (common for accented chars and
      extended ASCII); without decoding, the case-permutation step would
      generate nonsense candidates.
    * Step 3 also runs a length-consistency check on recovered halves
      (half1 should crack to 7 chars when password ≥8; half2 can be 1-7).
      When the lengths don't match standard LM construction the record is
      flagged `ordering_confirmed=False` and Step 4 emits both orderings.
    * Step 4 expands case permutations to a wordlist (rather than relying
      on hashcat's T0..TD toggle rules), so passwords containing extended
      ASCII work correctly — toggle rules only flip ASCII a-z/A-Z.
"""

from __future__ import annotations

import argparse
import itertools
import os
import re
import sys
from collections import defaultdict
from pathlib import Path


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# The LM hash of the empty string. Pwdump-format files use this in BOTH halves
# when no LM hash is stored, and in the SECOND half when the password is
# 7 characters or fewer.
EMPTY_LM_HALF = "aad3b435b51404ee"
EMPTY_LM_FULL = EMPTY_LM_HALF + EMPTY_LM_HALF

# The modern Impacket secretsdump placeholder. 32 characters, not hex, used in
# the LM column when the dump source didn't store LM. Filtering this is
# critical — a strict hex regex won't catch it and you'll end up brute-forcing
# random ASCII garbage.
NO_PASSWORD_PLACEHOLDER = "NO PASSWORD*********************"

# Maximum LM password length (the input password is uppercased then
# truncated/null-padded to 14 chars before being split into two halves).
LM_MAX_LENGTH = 14

# Hashcat writes non-renderable bytes in cracked plaintexts as $HEX[<hex>].
# Common for accented chars, extended ASCII, control codes, etc.
HEX_PATTERN = re.compile(r"\$HEX\[([0-9a-fA-F]+)\]")


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

class UserRecord:
    """One row from the pwdump. lm_half1 / lm_half2 are the two 16-char
    halves of the LM hash. nt_hash is the 32-char NT hash."""

    __slots__ = (
        "username", "rid", "lm_half1", "lm_half2", "nt_hash",
        "plain_half1", "plain_half2",
        "combined_plaintext", "ordering_confirmed",
    )

    def __init__(self, username: str, rid: str,
                 lm_half1: str, lm_half2: str, nt_hash: str) -> None:
        self.username = username
        self.rid = rid
        self.lm_half1 = lm_half1            # 16 hex chars, or "" if no LM
        self.lm_half2 = lm_half2            # 16 hex chars, or EMPTY_LM_HALF
        self.nt_hash = nt_hash              # 32 hex chars
        self.plain_half1: str | None = None
        self.plain_half2: str | None = None
        self.combined_plaintext: str | None = None
        # True when the two recovered half lengths match standard LM
        # construction. When False, Step 4 emits both p1+p2 and p2+p1
        # candidates to catch ordering edge cases.
        self.ordering_confirmed: bool = False


# ---------------------------------------------------------------------------
# $HEX[...] decoding — used during plaintext reassembly
# ---------------------------------------------------------------------------

def decode_hex_sequences(plaintext: str) -> str:
    """Decode hashcat's $HEX[<hex>] notation back to raw bytes.

    Hashcat emits non-renderable bytes in cracked passwords using this
    notation. Without decoding, the case-permutation step would treat the
    literal "$HEX[c3a4]" as 9 ASCII characters and produce nonsense.

    Examples:
        "TEST$HEX[0d0a]END" -> "TEST\\r\\nEND"
        "M$HEX[c3bc]LLER"   -> "MüLLER"  (latin-1 decode of c3bc)

    Uses latin-1 decoding so all 256 byte values round-trip cleanly. The
    case-permutation logic later compares characters via str.lower()/upper()
    which correctly handles Unicode case mapping for these bytes.
    """
    def _replace(match: re.Match) -> str:
        hex_str = match.group(1)
        try:
            return bytes.fromhex(hex_str).decode("latin-1")
        except (ValueError, UnicodeDecodeError):
            # Malformed $HEX[]; leave it alone rather than crashing
            return match.group(0)
    return HEX_PATTERN.sub(_replace, plaintext)


# ---------------------------------------------------------------------------
# Step 1 — Parse pwdump and extract halves
# ---------------------------------------------------------------------------

def parse_pwdump(path: Path) -> list[UserRecord]:
    """Read a pwdump file and return one UserRecord per user with an LM hash
    we can attack. Users with no LM (modern AD policy) are skipped — they're
    not addressable by this pipeline anyway.

    Pwdump line format:  username:rid:LM_hash:NT_hash:::
    """
    records: list[UserRecord] = []
    skipped_no_lm = 0
    skipped_malformed = 0

    with path.open("r", errors="replace") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if not line or line.startswith("#"):
                continue

            parts = line.split(":")
            if len(parts) < 4:
                skipped_malformed += 1
                continue

            username = parts[0]
            rid = parts[1]
            lm = parts[2].strip()
            nt = parts[3].strip().lower()

            # NT hash must be 32 hex chars. Without it we can't verify the
            # case of a recovered LM plaintext, so this row is useless.
            if len(nt) != 32 or not _is_hex(nt):
                skipped_malformed += 1
                continue

            # Filter every form of "no LM hash" up front.
            if (lm == EMPTY_LM_FULL
                    or lm == NO_PASSWORD_PLACEHOLDER
                    or len(lm) != 32
                    or not _is_hex(lm)):
                skipped_no_lm += 1
                continue

            lm_low = lm.lower()
            half1 = lm_low[:16]
            half2 = lm_low[16:]
            records.append(UserRecord(username, rid, half1, half2, nt))

    print(f"[1/5] Parsed {len(records)} users with LM hashes "
          f"({skipped_no_lm} no-LM rows skipped, "
          f"{skipped_malformed} malformed rows skipped).")
    return records


def _is_hex(s: str) -> bool:
    return all(c in "0123456789abcdefABCDEF" for c in s)


def write_hashcat_inputs(records: list[UserRecord], workdir: Path) -> tuple[Path, Path]:
    """Write deduplicated lm_halves.txt and nt_hashes.txt for hashcat."""
    workdir.mkdir(parents=True, exist_ok=True)
    lm_halves: set[str] = set()
    nt_hashes: set[str] = set()
    for r in records:
        lm_halves.add(r.lm_half1)
        # Only crack the second half if it's not the empty marker.
        if r.lm_half2 != EMPTY_LM_HALF:
            lm_halves.add(r.lm_half2)
        nt_hashes.add(r.nt_hash)

    lm_path = workdir / "lm_halves.txt"
    nt_path = workdir / "nt_hashes.txt"
    lm_path.write_text("\n".join(sorted(lm_halves)) + "\n")
    nt_path.write_text("\n".join(sorted(nt_hashes)) + "\n")

    print(f"[1/5] Wrote {len(lm_halves)} unique LM halves -> {lm_path}")
    print(f"[1/5] Wrote {len(nt_hashes)} unique NT hashes -> {nt_path}")
    return lm_path, nt_path


# ---------------------------------------------------------------------------
# Step 2 — Print the hashcat LM brute-force command
# ---------------------------------------------------------------------------

def print_lm_brute_command(lm_halves_path: Path, potfile_path: Path) -> None:
    """The hashcat invocation the user is expected to run themselves. Mode
    3000 with mask attack, `?u?d?s` charset, increment 1..7. Output is
    redirected into a session-specific potfile so this demo can read it
    back without colliding with the user's normal potfile."""
    print()
    print("[2/5] Run the LM brute-force step yourself:")
    print()
    print(f"    hashcat -m 3000 -a 3 \\")
    print(f"            -1 ?u?d?s \\")
    print(f"            '?1?1?1?1?1?1?1' \\")
    print(f"            -i --increment-min 1 --increment-max 7 \\")
    print(f"            -O \\")
    print(f"            --potfile-path {potfile_path} \\")
    print(f"            {lm_halves_path}")
    print()
    print("[2/5] When hashcat completes, the cracked halves will be in:")
    print(f"        {potfile_path}")
    print()


# ---------------------------------------------------------------------------
# Step 3 — Reassemble uppercase plaintexts from the cracked-halves potfile
# ---------------------------------------------------------------------------

def load_potfile(path: Path) -> dict[str, str]:
    """Return {hash: plaintext}. Skips comments and malformed lines."""
    cracked: dict[str, str] = {}
    if not path.exists():
        return cracked
    with path.open("r", errors="replace") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if not line or line.startswith("#") or ":" not in line:
                continue
            h, _, pw = line.partition(":")
            cracked[h.lower().strip()] = pw
    return cracked


def _combine_with_ordering_check(p1: str, p2: str,
                                  half2_is_empty: bool) -> tuple[str, bool]:
    """Concatenate two recovered LM-half plaintexts and report whether the
    ordering is structurally consistent.

    In standard LM construction:
      - If the password is ≤7 chars, half2's hash is aad3b435b51404ee (the
        empty marker) and only half1's plaintext is meaningful.
      - If the password is 8-13 chars, half1's plaintext is exactly 7 chars
        and half2's plaintext is 1-7 chars (the remainder).
      - If the password is exactly 14 chars, both plaintexts are 7 chars.

    Anything else (e.g. half1 cracking to <7 chars while half2 cracks to
    7) implies a non-standard pwdump source, a hash collision (very rare),
    or that the halves are in reversed byte order. The downstream wordlist
    generator emits both orderings when ordering_confirmed is False.
    """
    if half2_is_empty:
        # Password ≤7 chars: half1 IS the plaintext.
        return p1, True

    len1, len2 = len(p1), len(p2)
    if len1 == 7 and len2 < 7:
        # Standard 8-13 char password — confirmed.
        return p1 + p2, True
    if len1 == 7 and len2 == 7:
        # Exactly 14 chars — confirmed.
        return p1 + p2, True
    # Unusual structure: either reversed halves or a collision. Take p1+p2
    # as a starting point but flag it so the wordlist also tries p2+p1.
    return p1 + p2, False


def assemble_plaintexts(records: list[UserRecord],
                        lm_potfile: Path) -> list[tuple[str, bool]]:
    """Populate each record's plain_half1/plain_half2 from the LM potfile,
    decode any $HEX[...] sequences, run the ordering-confidence check, and
    return the deduplicated list of (uppercase_plaintext, confirmed) pairs
    ready for case expansion. Records with unconfirmed ordering AND two
    recovered halves contribute both p1+p2 AND p2+p1 to the candidate set.
    """
    cracked = load_potfile(lm_potfile)
    both_cracked = 0
    short_pw_cracked = 0
    one_half_only = 0
    none = 0
    unconfirmed_orderings = 0
    candidates: dict[str, bool] = {}  # plaintext -> confirmed

    for r in records:
        # Apply $HEX[] decoding to whatever hashcat reported, so the rest of
        # the pipeline operates on real characters.
        raw1 = cracked.get(r.lm_half1)
        raw2 = cracked.get(r.lm_half2) if r.lm_half2 != EMPTY_LM_HALF else None
        if raw1 is not None:
            r.plain_half1 = decode_hex_sequences(raw1)
        if raw2 is not None:
            r.plain_half2 = decode_hex_sequences(raw2)

        if r.plain_half1 is None:
            # First half didn't crack. Even if half2 did, we can't assemble
            # the full plaintext without it.
            if r.plain_half2 is not None:
                one_half_only += 1
            else:
                none += 1
            continue

        if r.lm_half2 == EMPTY_LM_HALF:
            r.combined_plaintext, r.ordering_confirmed = (
                _combine_with_ordering_check(r.plain_half1, "", True)
            )
            short_pw_cracked += 1
            candidates.setdefault(r.combined_plaintext, r.ordering_confirmed)
            continue

        if r.plain_half2 is None:
            one_half_only += 1
            continue

        r.combined_plaintext, r.ordering_confirmed = (
            _combine_with_ordering_check(r.plain_half1, r.plain_half2, False)
        )
        both_cracked += 1
        if not r.ordering_confirmed:
            unconfirmed_orderings += 1

        # Always include the standard ordering.
        candidates.setdefault(r.combined_plaintext, r.ordering_confirmed)
        # When ordering can't be confirmed, also try the reverse so the NT
        # crack covers either possibility.
        if not r.ordering_confirmed:
            reversed_plaintext = r.plain_half2 + r.plain_half1
            candidates.setdefault(reversed_plaintext, False)

    print(f"[3/5] Reassembly results:")
    print(f"        {both_cracked} users with both LM halves cracked (8-14 char passwords)")
    print(f"        {short_pw_cracked} users with ≤7 char passwords (half1 only)")
    print(f"        {one_half_only} users with only one half cracked (not recoverable)")
    print(f"        {none} users with neither half cracked (not recoverable)")
    if unconfirmed_orderings:
        print(f"        {unconfirmed_orderings} users with non-standard half-length combinations "
              f"(both orderings will be tried)")
    print(f"[3/5] Unique uppercase plaintext candidates: {len(candidates)}")
    # Stable, sorted ordering keeps the wordlist deterministic between runs.
    return sorted(candidates.items())


# ---------------------------------------------------------------------------
# Step 4 — Generate the case-permutation wordlist
# ---------------------------------------------------------------------------

def write_case_wordlist(candidates: list[tuple[str, bool]],
                         out_path: Path) -> int:
    """For each candidate plaintext, emit every case variant (2^letters).
    Returns the total line count.

    Implementation: itertools.product over (lower, upper) for each letter
    position. Non-letter characters (digits, symbols, non-letter Unicode)
    collapse to a single option so the variant count stays at 2^letter_count
    rather than 2^len for all-digit passwords. Output uses latin-1 so the
    full byte range round-trips intact.
    """
    total = 0
    written: set[str] = set()  # dedupe across all candidate plaintexts

    with out_path.open("w", encoding="latin-1", errors="replace") as f:
        for plaintext, _confirmed in candidates:
            per_char_variants = []
            for ch in plaintext:
                lower = ch.lower()
                upper = ch.upper()
                if lower == upper:
                    per_char_variants.append((ch,))
                else:
                    per_char_variants.append((lower, upper))

            for combo in itertools.product(*per_char_variants):
                variant = "".join(combo)
                if variant not in written:
                    written.add(variant)
                    f.write(variant + "\n")
                    total += 1

    print(f"[4/5] Wrote {total:,} case-permutation candidates -> {out_path}")
    return total


# ---------------------------------------------------------------------------
# Step 5 — Print the hashcat NT crack command, then read the results
# ---------------------------------------------------------------------------

def print_nt_crack_command(nt_hashes_path: Path, wordlist_path: Path,
                            potfile_path: Path) -> None:
    print()
    print("[5/5] Run the NT crack step yourself:")
    print()
    print(f"    hashcat -m 1000 -a 0 -O \\")
    print(f"            --potfile-path {potfile_path} \\")
    print(f"            {nt_hashes_path} {wordlist_path}")
    print()
    print("[5/5] When hashcat completes, the cracked NT hashes will be in:")
    print(f"        {potfile_path}")
    print()


def print_recovery_summary(records: list[UserRecord],
                            nt_potfile: Path) -> None:
    cracked = load_potfile(nt_potfile)
    recovered = 0
    print()
    print("=== Final (user, password) recovery ===")
    for r in records:
        if r.nt_hash in cracked:
            print(f"  {r.username:<32} {cracked[r.nt_hash]}")
            recovered += 1
    print(f"\nTotal recovered: {recovered}/{len(records)} users")


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="LM -> NT recovery pipeline (companion to the SynerComm blog).",
    )
    parser.add_argument("pwdump", type=Path,
                        help="Input pwdump file (user:rid:LM:NT:::)")
    parser.add_argument("--workdir", type=Path, default=Path("./lm2nt_work"),
                        help="Directory for intermediate files (default: ./lm2nt_work)")
    parser.add_argument(
        "--stage",
        choices=("prepare", "assemble", "finalize", "all"),
        default="prepare",
        help=(
            "Which stage to run. 'prepare' (default): parse pwdump and emit "
            "lm_halves.txt + nt_hashes.txt, then print the hashcat mode-3000 "
            "command. 'assemble': after you've run the mode-3000 command, "
            "reassemble plaintexts and emit case_wordlist.txt, then print the "
            "hashcat mode-1000 command. 'finalize': after you've run the "
            "mode-1000 command, print the (user, password) recovery."
        ),
    )
    args = parser.parse_args()

    if not args.pwdump.exists():
        print(f"Pwdump not found: {args.pwdump}", file=sys.stderr)
        return 2

    workdir: Path = args.workdir
    lm_halves_path = workdir / "lm_halves.txt"
    nt_hashes_path = workdir / "nt_hashes.txt"
    lm_potfile = workdir / "lm.potfile"
    nt_potfile = workdir / "nt.potfile"
    case_wordlist_path = workdir / "case_wordlist.txt"

    records = parse_pwdump(args.pwdump)
    if not records:
        print("No usable LM hashes found in input. Nothing to do.", file=sys.stderr)
        return 1

    if args.stage in ("prepare", "all"):
        write_hashcat_inputs(records, workdir)
        print_lm_brute_command(lm_halves_path, lm_potfile)
        if args.stage == "prepare":
            return 0

    if args.stage in ("assemble", "all"):
        if not lm_potfile.exists():
            print(f"LM potfile not found at {lm_potfile}. "
                  f"Run the mode-3000 command from the 'prepare' stage first.",
                  file=sys.stderr)
            return 3
        candidates = assemble_plaintexts(records, lm_potfile)
        if not candidates:
            print("No uppercase plaintexts assembled — nothing to feed into "
                  "the NT crack. Are the right LM halves in the potfile?",
                  file=sys.stderr)
            return 4
        write_case_wordlist(candidates, case_wordlist_path)
        print_nt_crack_command(nt_hashes_path, case_wordlist_path, nt_potfile)
        if args.stage == "assemble":
            return 0

    if args.stage in ("finalize", "all"):
        if not nt_potfile.exists():
            print(f"NT potfile not found at {nt_potfile}. "
                  f"Run the mode-1000 command from the 'assemble' stage first.",
                  file=sys.stderr)
            return 5
        # Re-load assembly state (plain_half1/plain_half2) so the summary
        # reflects only users whose halves we successfully recovered.
        if lm_potfile.exists():
            assemble_plaintexts(records, lm_potfile)
        print_recovery_summary(records, nt_potfile)

    return 0


if __name__ == "__main__":
    sys.exit(main())
