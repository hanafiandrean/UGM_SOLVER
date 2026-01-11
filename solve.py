import base64, hashlib, struct, zipfile

APK_PATH = "complexity.apk"

def uleb128(data, off):
    result = 0
    shift = 0
    while True:
        b = data[off]
        off += 1
        result |= (b & 0x7f) << shift
        if b & 0x80 == 0:
            break
        shift += 7
    return result, off

def sign8(x):
    x &= 0xff
    return x - 256 if x & 0x80 else x

def sign16(x):
    x &= 0xffff
    return x - 65536 if x & 0x8000 else x

def sign32(x):
    x &= 0xffffffff
    return x - 2**32 if x & 0x80000000 else x

def dalvik_int(x):
    x &= 0xffffffff
    return x - 0x100000000 if x & 0x80000000 else x

def parse_header(d):
    return {
        "string_ids_size": struct.unpack_from("<I", d, 0x38)[0],
        "string_ids_off":  struct.unpack_from("<I", d, 0x3C)[0],
        "type_ids_size":   struct.unpack_from("<I", d, 0x40)[0],
        "type_ids_off":    struct.unpack_from("<I", d, 0x44)[0],
        "proto_ids_size":  struct.unpack_from("<I", d, 0x48)[0],
        "proto_ids_off":   struct.unpack_from("<I", d, 0x4C)[0],
        "method_ids_size": struct.unpack_from("<I", d, 0x58)[0],
        "method_ids_off":  struct.unpack_from("<I", d, 0x5C)[0],
        "class_defs_size": struct.unpack_from("<I", d, 0x60)[0],
        "class_defs_off":  struct.unpack_from("<I", d, 0x64)[0],
    }

def parse_strings(d, h):
    size, off = h["string_ids_size"], h["string_ids_off"]
    str_offs = [struct.unpack_from("<I", d, off + 4*i)[0] for i in range(size)]
    out = []
    for o in str_offs:
        _, p = uleb128(d, o)
        end = d.find(b"\x00", p)
        out.append(d[p:end].decode("utf-8", "replace"))
    return out

def parse_type_ids(d, h):
    size, off = h["type_ids_size"], h["type_ids_off"]
    return [struct.unpack_from("<I", d, off + 4*i)[0] for i in range(size)]

def parse_proto_ids(d, h):
    size, off = h["proto_ids_size"], h["proto_ids_off"]
    return [struct.unpack_from("<III", d, off + i*12) for i in range(size)]

def parse_type_list(d, off):
    if off == 0:
        return []
    sz = struct.unpack_from("<I", d, off)[0]
    p = off + 4
    return [struct.unpack_from("<H", d, p + 2*i)[0] for i in range(sz)]

def parse_method_ids(d, h):
    size, off = h["method_ids_size"], h["method_ids_off"]
    return [struct.unpack_from("<HHI", d, off + i*8) for i in range(size)]

def parse_class_defs(d, h):
    size, off = h["class_defs_size"], h["class_defs_off"]
    return [struct.unpack_from("<IIIIIIII", d, off + i*32) for i in range(size)]

def parse_class_data(d, off):
    p = off
    sfs, p = uleb128(d, p)
    ifs, p = uleb128(d, p)
    dms, p = uleb128(d, p)
    vms, p = uleb128(d, p)

    last = 0
    for _ in range(sfs):
        diff, p = uleb128(d, p); _, p = uleb128(d, p); last += diff
    last = 0
    for _ in range(ifs):
        diff, p = uleb128(d, p); _, p = uleb128(d, p); last += diff

    methods = []
    last = 0
    for _ in range(dms):
        diff, p = uleb128(d, p)
        acc,  p = uleb128(d, p)
        co,   p = uleb128(d, p)
        last += diff
        methods.append((last, acc, co))

    last = 0
    for _ in range(vms):
        diff, p = uleb128(d, p)
        acc,  p = uleb128(d, p)
        co,   p = uleb128(d, p)
        last += diff
        methods.append((last, acc, co))

    return methods

def parse_code_item(d, off):
    regs, ins, outs, tries, debug_off, insns_size = struct.unpack_from("<HHHHII", d, off)
    insns_off = off + 16
    insns = list(struct.unpack_from("<%dH" % insns_size, d, insns_off))
    return regs, ins, outs, insns

class StringBuilder:
    __slots__ = ("s",)
    def __init__(self, init=""):
        self.s = init
    def append_char(self, c):
        self.s += chr(c & 0xffff)
        return self
    def toString(self):
        return self.s

def build_context(dex_bytes):
    h = parse_header(dex_bytes)
    strings = parse_strings(dex_bytes, h)
    type_ids = parse_type_ids(dex_bytes, h)
    type_desc = [strings[i] for i in type_ids]
    protos = parse_proto_ids(dex_bytes, h)
    methods = parse_method_ids(dex_bytes, h)
    class_defs = parse_class_defs(dex_bytes, h)

    def method_sig(m):
        class_idx, proto_idx, name_idx = m
        shorty_idx, ret_idx, params_off = protos[proto_idx]
        return {
            "class": type_desc[class_idx],
            "name": strings[name_idx],
            "ret": type_desc[ret_idx],
            "params": [type_desc[t] for t in parse_type_list(dex_bytes, params_off)],
        }

    minfo = [method_sig(m) for m in methods]

    check_id = None
    for idx, m in enumerate(methods):
        if strings[m[2]] == "check":
            check_id = idx
            break
    if check_id is None:
        raise RuntimeError("check() not found")

    class_data_off = class_defs[0][6]
    em = parse_class_data(dex_bytes, class_data_off)

    code_off = None
    for midx, acc, co in em:
        if midx == check_id:
            code_off = co
            break
    if code_off is None:
        raise RuntimeError("check() code not found")

    regsN, insN, outsN, insns = parse_code_item(dex_bytes, code_off)
    return strings, type_desc, minfo, regsN, insN, insns

def run_check_get_expected_char(dex_bytes, dummy_input="A"):
    strings, type_desc, minfo, regsN, insN, insns = build_context(dex_bytes)

    regs = [0] * regsN
    regs[regsN - insN] = dummy_input  # p0

    pc = 0
    last = None
    expected = None
    steps = 0

    while True:
        steps += 1
        if steps > 50000:
            raise RuntimeError("step limit (infinite loop?)")

        w0 = insns[pc]
        op = w0 & 0xff

        if op == 0x00:  # nop / (kalau nyasar ke payload, anggap nop)
            pc += 1

        elif op == 0x12:  # const/4
            A = (w0 >> 8) & 0x0f
            lit = (w0 >> 12) & 0x0f
            if lit & 0x8:
                lit -= 16
            regs[A] = lit
            pc += 1

        elif op == 0x13:  # const/16
            AA = (w0 >> 8) & 0xff
            regs[AA] = sign16(insns[pc + 1])
            pc += 2

        elif op == 0x14:  # const
            AA = (w0 >> 8) & 0xff
            lit = insns[pc + 1] | (insns[pc + 2] << 16)
            regs[AA] = sign32(lit)
            pc += 3

        elif op == 0x15:  # const/high16
            AA = (w0 >> 8) & 0xff
            regs[AA] = dalvik_int(sign16(insns[pc + 1]) << 16)
            pc += 2

        elif op in (0x01, 0x07):  # move / move-object
            A = (w0 >> 8) & 0x0f
            B = (w0 >> 12) & 0x0f
            regs[A] = regs[B]
            pc += 1

        elif op in (0x02, 0x05, 0x08):  # move/from16
            AA = (w0 >> 8) & 0xff
            BBBB = insns[pc + 1]
            regs[AA] = regs[BBBB]
            pc += 2

        elif op in (0x03, 0x06, 0x09):  # move/16
            AAAA = insns[pc + 1]
            BBBB = insns[pc + 2]
            regs[AAAA] = regs[BBBB]
            pc += 3

        elif op in (0x0a, 0x0c):  # move-result / move-result-object
            AA = (w0 >> 8) & 0xff
            regs[AA] = last
            pc += 1

        elif op in (0x0f, 0x11):  # return / return-object
            return expected

        elif op == 0x1a:  # const-string
            AA = (w0 >> 8) & 0xff
            regs[AA] = strings[insns[pc + 1]]
            pc += 2

        elif op == 0x22:  # new-instance
            AA = (w0 >> 8) & 0xff
            t = type_desc[insns[pc + 1]]
            regs[AA] = StringBuilder() if t == "Ljava/lang/StringBuilder;" else object()
            pc += 2

        elif op == 0x23:  # new-array
            A = (w0 >> 8) & 0x0f
            B = (w0 >> 12) & 0x0f
            t = type_desc[insns[pc + 1]]
            n = int(regs[B])
            regs[A] = [0] * n if t == "[I" else [None] * n
            pc += 2

        elif op == 0x24:  # filled-new-array (35c)
            Acount = (w0 >> 12) & 0x0f
            G = (w0 >> 8) & 0x0f
            w2 = insns[pc + 2]
            C = w2 & 0x0f
            D = (w2 >> 4) & 0x0f
            E = (w2 >> 8) & 0x0f
            F = (w2 >> 12) & 0x0f
            regs_list = [C, D, E, F, G][:Acount]
            last = [regs[r] for r in regs_list]   # hasil array masuk ke "result"
            pc += 3

        elif op == 0x25:  # filled-new-array/range
            AA = (w0 >> 8) & 0xff
            # type idx = insns[pc+1] (nggak perlu)
            CCCC = insns[pc + 2]
            last = [regs[CCCC + i] for i in range(AA)]
            pc += 3

        elif op == 0x26:  # fill-array-data
            AA = (w0 >> 8) & 0xff
            off = sign32(insns[pc + 1] | (insns[pc + 2] << 16))
            payload_pc = pc + off

            if insns[payload_pc] != 0x0300:
                raise RuntimeError("bad array-data payload")

            elem_width = insns[payload_pc + 1]
            size = insns[payload_pc + 2] | (insns[payload_pc + 3] << 16)
            data_start = payload_pc + 4

            arr = []
            if elem_width == 4:
                for i in range(size):
                    lo = insns[data_start + 2*i]
                    hi = insns[data_start + 2*i + 1]
                    arr.append(sign32(lo | (hi << 16)))
            elif elem_width == 2:
                for i in range(size):
                    arr.append(sign16(insns[data_start + i]))
            elif elem_width == 1:
                for i in range(size):
                    word = insns[data_start + i//2]
                    b = (word & 0xff) if i % 2 == 0 else ((word >> 8) & 0xff)
                    arr.append(sign8(b))
            else:
                raise RuntimeError("unsupported elem width")

            target = regs[AA]
            for i, v in enumerate(arr):
                target[i] = v

            pc += 3

        elif op == 0x28:  # goto
            pc += sign8((w0 >> 8) & 0xff)

        elif op == 0x29:  # goto/16
            pc += sign16(insns[pc + 1])

        elif op == 0x2a:  # goto/32
            pc += sign32(insns[pc + 1] | (insns[pc + 2] << 16))

        elif op == 0x2b:  # packed-switch
            AA = (w0 >> 8) & 0xff
            off = sign32(insns[pc + 1] | (insns[pc + 2] << 16))
            payload_pc = pc + off

            if insns[payload_pc] != 0x0100:
                raise RuntimeError("bad packed-switch payload")

            size = insns[payload_pc + 1]
            first_key = sign32(insns[payload_pc + 2] | (insns[payload_pc + 3] << 16))

            targets = []
            base = payload_pc + 4
            for i in range(size):
                t = sign32(insns[base + 2*i] | (insns[base + 2*i + 1] << 16))
                targets.append(t)

            key = regs[AA]
            idx = key - first_key
            if 0 <= idx < size:
                pc = pc + targets[idx]
            else:
                pc += 3

        elif 0x32 <= op <= 0x37:  # if-*
            A = (w0 >> 8) & 0x0f
            B = (w0 >> 12) & 0x0f
            off = sign16(insns[pc + 1])
            a, b = regs[A], regs[B]

            cond = False
            if op == 0x32: cond = (a == b)
            elif op == 0x33: cond = (a != b)
            elif op == 0x34: cond = (a < b)
            elif op == 0x35: cond = (a >= b)
            elif op == 0x36: cond = (a > b)
            elif op == 0x37: cond = (a <= b)

            pc = (pc + off) if cond else (pc + 2)

        elif 0x38 <= op <= 0x3d:  # if-*z
            AA = (w0 >> 8) & 0xff
            off = sign16(insns[pc + 1])
            a = regs[AA]

            cond = False
            if op == 0x38: cond = (a == 0)
            elif op == 0x39: cond = (a != 0)
            elif op == 0x3a: cond = (a < 0)
            elif op == 0x3b: cond = (a >= 0)
            elif op == 0x3c: cond = (a > 0)
            elif op == 0x3d: cond = (a <= 0)

            pc = (pc + off) if cond else (pc + 2)

        elif op == 0x44:  # aget
            AA = (w0 >> 8) & 0xff
            BB = insns[pc + 1] & 0xff
            CC = (insns[pc + 1] >> 8) & 0xff
            regs[AA] = regs[BB][regs[CC]]
            pc += 2

        elif op == 0x4b:  # aput
            AA = (w0 >> 8) & 0xff
            BB = insns[pc + 1] & 0xff
            CC = (insns[pc + 1] >> 8) & 0xff
            regs[BB][regs[CC]] = regs[AA]
            pc += 2

        elif 0x90 <= op <= 0xaf:  # binop
            AA = (w0 >> 8) & 0xff
            BB = insns[pc + 1] & 0xff
            CC = (insns[pc + 1] >> 8) & 0xff
            x, y = regs[BB], regs[CC]

            if op == 0x90: regs[AA] = dalvik_int(x + y)
            elif op == 0x91: regs[AA] = dalvik_int(x - y)
            elif op == 0x92: regs[AA] = dalvik_int(x * y)
            elif op == 0x95: regs[AA] = dalvik_int(x & y)
            elif op == 0x96: regs[AA] = dalvik_int(x | y)
            elif op == 0x97: regs[AA] = dalvik_int(x ^ y)
            elif op == 0x98: regs[AA] = dalvik_int(x << (y & 0x1f))
            elif op == 0x99: regs[AA] = dalvik_int(x >> (y & 0x1f))
            elif op == 0x9a: regs[AA] = dalvik_int((x & 0xffffffff) >> (y & 0x1f))
            else:
                raise RuntimeError(f"unhandled binop {hex(op)}")
            pc += 2

        elif 0xb0 <= op <= 0xba:  # binop/2addr
            A = (w0 >> 8) & 0x0f
            B = (w0 >> 12) & 0x0f
            x, y = regs[A], regs[B]

            if op == 0xb0: regs[A] = dalvik_int(x + y)
            elif op == 0xb1: regs[A] = dalvik_int(x - y)
            elif op == 0xb2: regs[A] = dalvik_int(x * y)
            elif op == 0xb5: regs[A] = dalvik_int(x & y)
            elif op == 0xb6: regs[A] = dalvik_int(x | y)
            elif op == 0xb7: regs[A] = dalvik_int(x ^ y)
            elif op == 0xb8: regs[A] = dalvik_int(x << (y & 0x1f))
            elif op == 0xb9: regs[A] = dalvik_int(x >> (y & 0x1f))
            elif op == 0xba: regs[A] = dalvik_int((x & 0xffffffff) >> (y & 0x1f))
            else:
                raise RuntimeError(f"unhandled 2addr {hex(op)}")
            pc += 1

        elif 0xd0 <= op <= 0xd7:  # binop/lit16
            A = (w0 >> 8) & 0x0f
            B = (w0 >> 12) & 0x0f
            lit = sign16(insns[pc + 1])
            x = regs[B]

            if op == 0xd0: regs[A] = dalvik_int(x + lit)
            elif op == 0xd1: regs[A] = dalvik_int(x - lit)
            elif op == 0xd2: regs[A] = dalvik_int(x * lit)
            elif op == 0xd5: regs[A] = dalvik_int(x & lit)
            elif op == 0xd6: regs[A] = dalvik_int(x | lit)
            elif op == 0xd7: regs[A] = dalvik_int(x ^ lit)
            else:
                raise RuntimeError(f"unhandled lit16 {hex(op)}")
            pc += 2

        elif 0xd8 <= op <= 0xe2:  # binop/lit8
            AA = (w0 >> 8) & 0xff
            BB = insns[pc + 1] & 0xff
            CC = (insns[pc + 1] >> 8) & 0xff
            lit = sign8(CC)
            x = regs[BB]

            if op == 0xd8: regs[AA] = dalvik_int(x + lit)
            elif op == 0xd9: regs[AA] = dalvik_int(x - lit)
            elif op == 0xda: regs[AA] = dalvik_int(x * lit)
            elif op == 0xdd: regs[AA] = dalvik_int(x & lit)
            elif op == 0xde: regs[AA] = dalvik_int(x | lit)
            elif op == 0xdf: regs[AA] = dalvik_int(x ^ lit)
            elif op == 0xe0: regs[AA] = dalvik_int(x << (lit & 0x1f))
            elif op == 0xe1: regs[AA] = dalvik_int(x >> (lit & 0x1f))
            elif op == 0xe2: regs[AA] = dalvik_int((x & 0xffffffff) >> (lit & 0x1f))
            else:
                raise RuntimeError(f"unhandled lit8 {hex(op)}")
            pc += 2

        elif op == 0x8e: 
            A = (w0 >> 8) & 0x0f
            B = (w0 >> 12) & 0x0f
            regs[A] = regs[B] & 0xffff
            pc += 1

        elif op in (0x6e, 0x70):  # invoke-virtual / invoke-direct 
            Acount = (w0 >> 12) & 0x0f
            G = (w0 >> 8) & 0x0f
            meth_idx = insns[pc + 1]
            w2 = insns[pc + 2]
            C = w2 & 0x0f
            D = (w2 >> 4) & 0x0f
            E = (w2 >> 8) & 0x0f
            F = (w2 >> 12) & 0x0f
            regs_list = [C, D, E, F, G][:Acount]
            argv = [regs[r] for r in regs_list]
            mi = minfo[meth_idx]

            if mi["class"] == "Ljava/lang/StringBuilder;" and mi["name"] == "<init>":
                sb = argv[0]
                init = argv[1] if len(argv) > 1 else ""
                sb.s = init
                last = None

            elif mi["class"] == "Ljava/lang/StringBuilder;" and mi["name"] == "append":
                sb, ch = argv
                last = sb.append_char(ch)

            elif mi["class"] == "Ljava/lang/StringBuilder;" and mi["name"] == "toString":
                sb = argv[0]
                last = sb.toString()

            elif mi["class"] == "Ljava/lang/String;" and mi["name"] == "equals":
                s, other = argv
                # expected char adalah string yang BUKAN dummy_input
                if isinstance(s, str) and isinstance(other, str):
                    expected = s if other == dummy_input else other
                last = 1 if s == other else 0

            else:
                raise RuntimeError(f"unhandled invoke {mi}")

            pc += 3

        else:
            raise RuntimeError(f"Unhandled opcode {hex(op)} at pc={pc}")

def md5i(i: int) -> str:
    return hashlib.md5(str(i).encode()).hexdigest()

def main():
    with zipfile.ZipFile(APK_PATH, "r") as z:
        b64 = []
        for i in range(280):
            dex_path = f"assets/NETCOMP_{md5i(i)}.dex"
            dex_bytes = z.read(dex_path)
            ch = run_check_get_expected_char(dex_bytes, dummy_input="A")
            if ch is None or len(ch) != 1:
                raise SystemExit(f"failed at i={i}, got={ch!r}")
            b64.append(ch)

        b64s = "".join(b64)
        flag = base64.b64decode(b64s).decode("utf-8")
        print(flag)

if __name__ == "__main__":
    main()
