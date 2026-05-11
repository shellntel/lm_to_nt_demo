LM -> NT hash recovery pipeline, end to end.

Companion to the SynerComm blog article "Cracking NT Hashes via LM Halves:
A Modern GPU Pipeline." Runnable as a standalone script — no third-party dependencies, no infrastructure required. Hashcat is the only external tool.

Usage:
    python3 lm_to_nt_demo.py /path/to/dump.pwdump [--workdir ./work]

What it does, in order:

    1. Parses the pwdump into (user, LM_hash, NT_hash) tuples and writes:
         work/lm_halves.txt  — deduplicated 16-char LM halves to crack
         work/nt_hashes.txt  — deduplicated NT hashes to crack
    2. Tells you the hashcat mode-3000 command to run against lm_halves.txt.
       After hashcat finishes, point this script at the resulting potfile
       (or paste the lines into the prompt) so it can reassemble plaintexts.
    3. Reassembles uppercase plaintexts by joining each user's two cracked
       LM halves (or just half1 for ≤7-char passwords).
    4. Writes work/case_wordlist.txt containing every case-permutation of
       every uppercase plaintext (up to 2^14 variants per password).
    5. Tells you the hashcat mode-1000 command to run against nt_hashes.txt
       with the case wordlist. After hashcat finishes, point the script at
       the resulting potfile to print the final (user, password) recovery.

Intentional design notes:
- Filters both the hex empty-LM marker (aad3b435...) AND the modern "NO PASSWORD*********************" placeholder that dump tools create. Without this you waste a brute-force pass on garbage.
- Treats each unique LM half independently, so two users sharing the same first 7 password characters only contribute one half to crack.
- Step 4 expands case permutations to a wordlist (rather than relying on hashcat's T0..TD toggle rules), so passwords containing extended ASCII work correctly.
