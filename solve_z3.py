"""
solve_z3.py
Z3-based solver for the structural (format) gate of the
"Mini LLM Sentinel" crackme password check (sub_140004360).

This recovers the prefix, suffix, checksum, and digit-count
constraints, and returns a 16-byte candidate password that
satisfies all of them.
"""

from z3 import *


def solve_crackme():
    solver = Solver()

    # The password is 16 bytes long
    PASSWORD_LEN = 16
    chars = [BitVec(f"c_{i}", 8) for i in range(PASSWORD_LEN)]

    # 1. Every byte must be printable ASCII
    for c in chars:
        solver.add(And(c >= 32, c <= 126))

    # 2. Fixed prefix: "AI-"
    #    (recovered from sub_140004360, XOR-decoded from unk_14006C713)
    solver.add(chars[0] == ord("A"))
    solver.add(chars[1] == ord("I"))
    solver.add(chars[2] == ord("-"))

    # 3. Fixed suffix: "!"
    #    (XOR-decoded from cs:byte_140110CA0 with key 0xB6)
    solver.add(chars[15] == ord("!"))

    # 4. Checksum constraint: sum(bytes) % 256 == 0x65 (101)
    #    (sub_140004360, "sub r10d, 65h")
    char_sum = ZeroExt(24, chars[0])
    for i in range(1, PASSWORD_LEN):
        char_sum = char_sum + ZeroExt(24, chars[i])
    solver.add((char_sum & 0xFF) == 0x65)

    # 5. At least 4 of the characters must be decimal digits
    is_digit = [If(And(c >= ord("0"), c <= ord("9")), 1, 0) for c in chars]
    solver.add(Sum(is_digit) >= 4)

    print("[*] Solving constraint system...")
    if solver.check() == sat:
        model = solver.model()
        password = "".join(chr(model[c].as_long()) for c in chars)
        print(f"[+] Solved. Candidate password: {password}")
        return password

    print("[-] No solution satisfies the constraints.")
    return None


if __name__ == "__main__":
    solve_crackme()
