#!/usr/bin/env python3
"""
mamkor.pro / stage1_x.exe (51148dec.exe) -- embedded stage-3 payload decryptor.

Recovered from Ghidra decompilation of the Go 1.25.4 loader
(main.gxvxxntgsoilmgbqwyldu @ 1400b2b80, call site in main.main @ ~1400d2752,
file line NUzGiZiHqRXEWXlTUx/main.go:4542). Same cipher SHAPE and same round
order as the sibling merabs-clickfix-fae70f1d case's main.eskyjlqppicw
(index-parity -> reverse -> adjacent-swap -> subtract-round -> xor-round) --
same actor/toolchain, different per-build key and blob location.

Encrypted payload location (inside stage1_x.exe):
  .rdata VA  0x140147bc0 -> file offset 0x146fc0 MINUS 6 bytes (0x146fba)
  length 0x10c496 bytes (1,098,902) -- the qword-copy loop in main.main moves
  0x21892 qwords (1,098,896 bytes) from this address; the true ciphertext
  window need only share the qword-copy's END boundary (0x253450) -- start
  offset within +/-8 bytes and 0-8 bytes of leading zero-pad all reproduce an
  IDENTICAL valid PE header (verified below), because the cipher's Round 2
  full-reverse means the decoded header depends only on the ciphertext's
  END bytes, not its start. FILE_OFF/LENGTH below is the validated pair.
Key (main.gxvxxntgsoilmgbqwyldu param_4): 0x145de

Verified: decodes to a valid PE32+ (Machine 0x8664), 4 sections
(.text/.rdata/.data/.reloc), e_lfanew=0x280, DOS stub intact, sane per-section
entropy (.text 5.66, .rdata 5.84), import directory ZEROED (anti-analysis,
same as merabs), non-Go native code, real build timestamp 2026-05-26 (unlike
stage-2's zeroed timestamp). SHA256 of decrypted stage-3:
448c2d3556557837da6de2973428063e52e90239a021ebf08a4908a5d7ece622
"""
import sys

def transform(buf, key):
    b = bytearray(buf)
    n = len(b)
    k53, k97, klo, khi = key % 53, key % 97, key & 0xff, (key >> 8) & 0xff

    # Round 1: index-parity transform
    for i in range(n):
        if i % 2 == 0:
            b[i] = (b[i] - k53 - 17 * i) & 0xff
        else:
            b[i] = ((31 * i) ^ k97 ^ b[i]) & 0xff

    # Round 2: full reverse
    b.reverse()

    # Round 3: adjacent-pair swap
    for i in range(0, n - 1, 2):
        b[i], b[i + 1] = b[i + 1], b[i]

    # Round 4: subtract high key byte + 3*i
    for i in range(n):
        b[i] = (b[i] - khi - 3 * i) & 0xff

    # Round 5: xor 5*i and low key byte
    for i in range(n):
        b[i] = ((5 * i) ^ b[i] ^ klo) & 0xff

    return bytes(b)

def main():
    exe = sys.argv[1] if len(sys.argv) > 1 else "stage1_x.exe"
    data = open(exe, "rb").read()
    FILE_OFF, LENGTH, KEY = 0x146fba, 0x10c496, 0x145de
    ct = data[FILE_OFF:FILE_OFF + LENGTH]
    pt = transform(ct, KEY)
    assert pt[:2] == b"MZ", "decrypt failed"
    open("stage3_decrypted.exe", "wb").write(pt)
    print(f"OK: wrote stage3_decrypted.exe ({len(pt)} bytes)")

if __name__ == "__main__":
    main()
