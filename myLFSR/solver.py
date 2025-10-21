#!/usr/bin/env python3
# solve_lfsr.py
# Usage: put this script next to output.txt and run: python solve_lfsr.py

from typing import List, Tuple
import math

# ---------- helpers ----------
def expand(n: int, base: int = 3) -> List[int]:
    """Expand integer n into base-`base` digits, LSB first (same as chall.expand)."""
    if n == 0:
        return [0]
    res = []
    while n:
        res.append(n % base)
        n //= base
    return res

def digits_to_bytes(digits: List[int], base: int = 3) -> bytes:
    """Convert base-`base` digits (LSB-first) back into bytes."""
    val = 0
    power = 1
    for d in digits:
        val += d * power
        power *= base
    # compute required byte length
    blen = (val.bit_length() + 7) // 8
    if blen == 0:
        return b"\x00"
    return val.to_bytes(blen, "big")

def gauss_mod3(A: List[List[int]], b: List[int]) -> List[int]:
    """
    Solve A x = b (mod 3) via Gaussian elimination.
    A: M x N (M >= N expected); b: length M
    Returns a solution x of length N (assumes unique solution).
    """
    M = len(A)
    N = len(A[0])
    # build augmented matrix
    mat = [row[:] + [bv] for row, bv in zip(A, b)]

    # row by row elimination
    row = 0
    for col in range(N):
        # find pivot in rows row..M-1 where mat[r][col] != 0
        pivot = None
        for r in range(row, M):
            if mat[r][col] % 3 != 0:
                pivot = r
                break
        if pivot is None:
            continue
        # swap pivot row into position
        mat[row], mat[pivot] = mat[pivot], mat[row]

        # normalize pivot to 1: multiply row by inv(mat[row][col]) mod 3
        inv = {1: 1, 2: 2}  # since 2*2 %3 =1
        val = mat[row][col] % 3
        factor = inv[val]
        for c in range(col, N + 1):
            mat[row][c] = (mat[row][c] * factor) % 3

        # eliminate other rows
        for r in range(M):
            if r == row:
                continue
            if mat[r][col] % 3 != 0:
                factor = mat[r][col] % 3
                # subtract factor * pivot-row
                for c in range(col, N + 1):
                    mat[r][c] = (mat[r][c] - factor * mat[row][c]) % 3
        row += 1
        if row == M:
            break

    # Now read solution: we assume unique solution; free vars not expected.
    x = [0] * N
    # find pivot columns and read corresponding value
    for r in range(M):
        # find first nonzero col in row
        first = None
        for c in range(N):
            if mat[r][c] % 3 != 0:
                first = c
                break
        if first is None:
            continue
        x[first] = mat[r][N] % 3

    return x

# ---------- main solver ----------
def main():
    # load output.txt
    with open("output.txt", "r") as f:
        lines = [line.strip() for line in f if line.strip()]
    if len(lines) < 3:
        raise SystemExit("output.txt format unexpected: need at least 3 non-empty lines")

    L = int(lines[0])  # key length
    gift_hex = lines[1].strip()
    ct_hex = lines[2].strip()

    gift_bytes = list(bytes.fromhex(gift_hex))
    ct_bytes = list(bytes.fromhex(ct_hex))

    # determine the plaintext used for the gift encryption:
    # in chall.py: gift = cipher.encrypt(b"\xff" * (len(KEY) // 3 + 3))
    gift_msg_len = (L // 3) + 3
    gift_plain_bytes = b"\xff" * gift_msg_len

    # expand the gift plaintext into base-3 digits (LSB-first)
    gift_pt_digits = expand(int.from_bytes(gift_plain_bytes, "big"), base=3)

    N = len(gift_pt_digits)
    if N != len(gift_bytes):
        # sanity: ciphertext length should match plaintext digit length
        # but if not, trim to the minimum
        N = min(N, len(gift_bytes))
        gift_pt_digits = gift_pt_digits[:N]
        gift_bytes = gift_bytes[:N]

    # recover keystream digits (stream) for the observed positions:
    # ct = pt ^ stream  => stream = pt ^ ct  (XOR)
    stream_obs = [ (gift_pt_digits[i] ^ gift_bytes[i]) for i in range(N) ]

    print(f"[+] L (KEY length) = {L}")
    print(f"[+] Observed keystream length N = {N}")

    # we need at least L equations (N - L >= L ideally) to uniquely solve mask of length L.
    # But gift plaintext was chosen so N is large (from the high-int value); proceed with whatever N is.
    if N <= L:
        raise SystemExit(f"Not enough observed keystream (N={N}) to recover mask length L={L}")

    # Build linear system: for t in 0..(N-L-1):
    # s_{t+L} = sum_{i=0..L-1} mask[i] * s_{t+i}  (mod 3)
    M_eq = N - L
    A = []
    b = []
    for t in range(M_eq):
        row = [ stream_obs[t + i] % 3 for i in range(L) ]  # coefficients * mask
        rhs = stream_obs[t + L] % 3
        A.append(row)
        b.append(rhs)

    print(f"[+] Built linear system with {M_eq} equations and {L} unknowns")

    # Solve for mask modulo 3
    mask = gauss_mod3(A, b)

    # verify mask values are in {0,1,2}
    mask = [v % 3 for v in mask]
    print(f"[+] Recovered MASK (length {len(mask)}):")
    print("    ", mask)

    # initial KEY is the first L outputs of the stream
    key = stream_obs[:L]
    print(f"[+] Recovered KEY (first {L} stream outputs):")
    print("    ", key)

    # Now simulate LFSR from initial key to reproduce the full keystream
    def simulate_lfsr(init_key: List[int], mask: List[int], steps: int) -> List[int]:
        state = init_key[:]
        out = []
        for _ in range(steps):
            b = sum(s * m for s, m in zip(state, mask)) % 3
            out.append(state[0])
            state = state[1:] + [b]
        return out

    # compute how many keystream digits were used for gift (we observed N of them)
    gift_keystream_len = N

    # compute required keystream length for flag ciphertext
    # to decrypt flag ciphertext, we need the same number of base-3 digits as ct_flag length
    ct_flag_len = len(ct_bytes)

    total_needed = gift_keystream_len + ct_flag_len
    print(f"[+] Need total keystream length = {total_needed} (gift {gift_keystream_len} + flag {ct_flag_len})")

    full_stream = simulate_lfsr(key, mask, total_needed)

    stream_for_flag = full_stream[gift_keystream_len : gift_keystream_len + ct_flag_len]
    if len(stream_for_flag) != ct_flag_len:
        raise SystemExit("Keystream generation failed (length mismatch)")

    # recover flag plaintext base-3 digits: pt_flag = ct_flag ^ stream_flag
    pt_flag_digits = [ (ct_bytes[i] ^ stream_for_flag[i]) for i in range(ct_flag_len) ]

    # convert base-3 digit stream back to bytes
    recovered_flag = digits_to_bytes(pt_flag_digits, base=3)

    print("[+] Recovered flag bytes (raw):")
    print(recovered_flag)
    try:
        print("[+] Recovered flag (utf-8):")
        print(recovered_flag.decode())
    except UnicodeDecodeError:
        print("[!] Recovered bytes are not valid UTF-8, printing hex:")
        print(recovered_flag.hex())

if __name__ == "__main__":
    main()
