import socket
import re
import math

HOST = "72.62.122.169"   
PORT = 8302
ROUNDS = 3               

# PARAMETER
p = 87975800266411715571738368366335380369666653297323309778888046169239182316403
a = 24706251795871763793703712664815408269526601526653607864558628275826577881713
b = 23420866761033089903868195361764762487999201284344109943038351939994211111267

m = p >> 202

# Sage 
N = 87975800266411715571738368366335380369976192431834769153921751523575374324650

g = math.gcd(N, m)
q = N // g

#  ECC 
class Point:
    __slots__ = ("x", "y", "inf")
    def __init__(self, x=None, y=None, inf=False):
        self.x = x
        self.y = y
        self.inf = inf

O = Point(inf=True)

def add(P: Point, Q: Point) -> Point:
    if P.inf:
        return Q
    if Q.inf:
        return P

    if P.x == Q.x:
        if (P.y + Q.y) % p == 0:
            return O
        # doubling
        den = (2 * P.y) % p
        if den == 0:
            return O
        lam = ((3 * P.x * P.x + a) * pow(den, -1, p)) % p
    else:
        den = (Q.x - P.x) % p
        if den == 0:
            return O
        lam = ((Q.y - P.y) * pow(den, -1, p)) % p

    xr = (lam * lam - P.x - Q.x) % p
    yr = (lam * (P.x - xr) - P.y) % p
    return Point(xr, yr)

def mul(k: int, P: Point) -> Point:
    R = O
    Q = P
    while k > 0:
        if k & 1:
            R = add(R, Q)
        Q = add(Q, Q)
        k >>= 1
    return R

# ===== NETWORK =====
def recvuntil(sock: socket.socket, token: bytes) -> bytes:
    data = b""
    while token not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

def recvline(sock: socket.socket) -> bytes:
    data = b""
    while not data.endswith(b"\n"):
        ch = sock.recv(1)
        if not ch:
            break
        data += ch
    return data

pt_re = re.compile(r"^\((\d+),\s*(\d+)\)\s*$")

def get_bits_once():
    with socket.create_connection((HOST, PORT)) as s:
        recvuntil(s, b"> ")
        s.sendall(b"1\n")

        header = recvline(s).decode(errors="ignore").strip()
        m1 = re.search(r"Printing\s+(\d+)\s+lines", header)
        if not m1:
            raise RuntimeError("Gagal parse header: " + header)
        L = int(m1.group(1))

        bits = []
        for _ in range(L):
            line = recvline(s).decode(errors="ignore").strip()
            mm = pt_re.match(line)
            if not mm:
                raise RuntimeError("Gagal parse point: " + line)
            x = int(mm.group(1))
            y = int(mm.group(2))
            P = Point(x, y)

            # membership test: q * P == O  <=>  P in mE  (bit kemungkinan 0)
            T = mul(q, P)
            bits.append(0 if T.inf else 1)

        return bits

def main():
    print("[i] m =", m)
    print("[i] N =", N)
    print("[i] gcd(N,m) =", g)
    print("[i] q =", q)
    print("[i] rounds =", ROUNDS)

    final_bits = None

    for r in range(ROUNDS):
        bits = get_bits_once()
        print(f"[i] got {len(bits)} bits from round {r+1}")

        if final_bits is None:
            final_bits = bits[:]   # copy
        else:
            # OR per-bit biar 1 yang ke-skip ketangkep di round lain
            final_bits = [fb | b for fb, b in zip(final_bits, bits)]

    # reconstruct integer (LSB-first)
    flag_int = 0
    for i, bit in enumerate(final_bits):
        if bit:
            flag_int |= (1 << i)

    blen = (len(final_bits) + 7) // 8
    flag_bytes = flag_int.to_bytes(blen, "big")
    inside = flag_bytes.decode("ascii", errors="strict")  # harusnya udah clean

    print("\nFLAG =", f"NETCOMP{{{inside}}}")

if __name__ == "__main__":
    main()
