import struct
import json
import re
import zlib
import sys
from pathlib import Path

PCAP = sys.argv[1] if len(sys.argv) > 1 else "traffics.pcapng"

def rc4_crypt(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) & 0xFF]
        out.append(b ^ k)
    return bytes(out)

def parse_pcapng(buf: bytes):
    off = 0
    endian = "<"
    interfaces = []
    packets = []

    while off + 12 <= len(buf):
        btype = struct.unpack_from(endian + "I", buf, off)[0]
        blen  = struct.unpack_from(endian + "I", buf, off + 4)[0]

        # sanity + fallback endian
        if blen < 12 or off + blen > len(buf):
            other = ">" if endian == "<" else "<"
            btype2 = struct.unpack_from(other + "I", buf, off)[0]
            blen2  = struct.unpack_from(other + "I", buf, off + 4)[0]
            if blen2 >= 12 and off + blen2 <= len(buf):
                btype, blen = btype2, blen2
                endian = other
            else:
                break

        body = buf[off + 8 : off + blen - 4]

        # Section Header Block
        if btype == 0x0A0D0D0A and len(body) >= 8:
            bom = body[:4]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"

        # Interface Description Block
        elif btype == 0x00000001 and len(body) >= 8:
            linktype = struct.unpack_from(endian + "H", body, 0)[0]
            snaplen  = struct.unpack_from(endian + "I", body, 4)[0]
            interfaces.append((linktype, snaplen))

        # Enhanced Packet Block
        elif btype == 0x00000006 and len(body) >= 20:
            iface_id, tsh, tsl, caplen, origlen = struct.unpack_from(endian + "IIIII", body, 0)
            pkt = body[20 : 20 + caplen]
            packets.append((iface_id, pkt))

        off += blen

    return interfaces, packets

def parse_ipv4(payload: bytes):
    if len(payload) < 20:
        return None
    vihl = payload[0]
    ver = vihl >> 4
    ihl = (vihl & 0x0F) * 4
    if ver != 4 or len(payload) < ihl:
        return None
    total_len = struct.unpack("!H", payload[2:4])[0]
    proto = payload[9]
    src = payload[12:16]
    dst = payload[16:20]
    l4 = payload[ihl:total_len]
    return proto, src, dst, l4

def parse_cart_from_payload(payload: bytes):
    start = payload.find(b"CART")
    if start == -1:
        return None
    blob = payload[start:]
    trac = blob.rfind(b"TRAC")
    if trac == -1:
        return None
    blob = blob[:trac + 28]  # include 28-byte footer

    # Mandatory header: 4s h Q 16s Q  (little-endian)
    if blob[:4] != b"CART":
        return None
    version = struct.unpack_from("<h", blob, 4)[0]
    reserved = struct.unpack_from("<Q", blob, 6)[0]
    key = blob[14:30]
    opt_header_len = struct.unpack_from("<Q", blob, 30)[0]

    off = 38
    opt_header_enc = blob[off:off + opt_header_len]
    off += opt_header_len

    # Mandatory footer (28 bytes): 4s Q Q Q  (di chall ini: reserved, filelen, opt_footer_len)
    footer = blob[-28:]
    if footer[:4] != b"TRAC":
        return None
    opt_footer_len = struct.unpack_from("<Q", footer, 20)[0]

    opt_footer_enc = blob[-28 - opt_footer_len:-28] if opt_footer_len else b""
    data_enc = blob[off:len(blob) - 28 - opt_footer_len]

    return key, opt_header_enc, data_enc

def extract_char_from_py(code: bytes) -> str:
    s = code.decode("utf-8", errors="ignore")
    m = re.search(r"(\w+)\s*=\s*(\w+)\s*\^\s*(\w+)", s)
    if not m:
        return "?"
    a, b = m.group(2), m.group(3)
    ma = re.search(rf"^{re.escape(a)}\s*=\s*(\d+)\s*$", s, re.M)
    mb = re.search(rf"^{re.escape(b)}\s*=\s*(\d+)\s*$", s, re.M)
    if not (ma and mb):
        return "?"
    return chr(int(ma.group(1)) ^ int(mb.group(1)))

def main():
    buf = Path(PCAP).read_bytes()
    interfaces, pkts = parse_pcapng(buf)

    # ambil UDP dst port 9890 (Ethernet linktype=1)
    extracted = {}
    for iface_id, frame in pkts:
        if len(frame) < 14:
            continue
        eth_type = struct.unpack("!H", frame[12:14])[0]
        if eth_type != 0x0800:  # IPv4
            continue

        ip = parse_ipv4(frame[14:])
        if not ip:
            continue
        proto, _src, _dst, l4 = ip
        if proto != 17 or len(l4) < 8:  # UDP
            continue

        sport, dport, ulen, _csum = struct.unpack("!HHHH", l4[:8])
        if dport != 9890:
            continue
        payload = l4[8:ulen]

        cart = parse_cart_from_payload(payload)
        if not cart:
            continue
        key, opt_header_enc, data_enc = cart

        header_plain = rc4_crypt(key, opt_header_enc)
        header_json = json.loads(header_plain.decode("utf-8", errors="ignore"))
        name = header_json.get("name", "unknown.bin")

        compressed = rc4_crypt(key, data_enc)
        raw = zlib.decompress(compressed)
        extracted[name] = raw

    # susun 000.py..083.py jadi message
    chars = []
    for i in range(84):
        fn = f"{i:03d}.py"
        chars.append(extract_char_from_py(extracted[fn]))
    msg = "".join(chars)  # sudah termasuk {...}
    print("NETCOMP" + msg)

if __name__ == "__main__":
    main()
