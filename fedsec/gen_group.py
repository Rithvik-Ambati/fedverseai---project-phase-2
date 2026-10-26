"""One-off generator for the Schnorr group used by the Pedersen commitments.

Run:  python -m fedsec.gen_group
Writes fedsec/group_params.json  (p: 1024-bit prime, q: 256-bit prime, q | p-1).
Demo-sized parameters; use >=3072-bit p for any real deployment.
"""
import json, random, os

SMALL = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]


def is_prime(n, rounds=40, rng=random):
    if n < 2:
        return False
    for s in SMALL:
        if n % s == 0:
            return n == s
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate(pbits=1024, qbits=256, seed=20240607):
    rng = random.Random(seed)
    while True:
        q = rng.getrandbits(qbits) | (1 << (qbits - 1)) | 1
        if is_prime(q, rng=rng):
            break
    while True:
        k = rng.getrandbits(pbits - qbits) | (1 << (pbits - qbits - 1))
        k &= ~1
        p = k * q + 1
        if p.bit_length() == pbits and is_prime(p, rng=rng):
            return p, q


if __name__ == "__main__":
    p, q = generate()
    path = os.path.join(os.path.dirname(__file__), "group_params.json")
    with open(path, "w") as f:
        json.dump({"p": hex(p), "q": hex(q)}, f)
    print("wrote", path, p.bit_length(), q.bit_length())
