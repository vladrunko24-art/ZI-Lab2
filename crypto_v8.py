import struct

SUB_KEY = b"SEC8KEY!"


def encrypt_substitution(data: bytes) -> bytes:
    key_len = len(SUB_KEY)
    return bytes(b ^ SUB_KEY[i % key_len] for i, b in enumerate(data))


def decrypt_substitution(data: bytes) -> bytes:
    return encrypt_substitution(data)


def _rol(val: int, bits: int) -> int:
    return ((val << bits) | (val >> (32 - bits))) & 0xFFFFFFFF


def compute_sha_round2(data: bytes) -> int:
    a = 0x67452301
    b = 0xEFCDAB89
    c = 0x98BADCFE
    d = 0x10325476
    e = 0xC3D2E1F0
    k2 = 0x6ED9EBA1

    padded = data + b"\x00" * ((4 - len(data) % 4) % 4)
    for i in range(0, len(padded), 4):
        (w,) = struct.unpack(">I", padded[i : i + 4])
        f = b ^ c ^ d
        temp = (_rol(a, 5) + f + e + k2 + w) & 0xFFFFFFFF
        e = d
        d = c
        c = _rol(b, 30)
        b = a
        a = temp

    return (a ^ b ^ c ^ d ^ e) & 0xFFFFFFFF


def pack_message(text: str) -> bytes:
    raw = text.encode("utf-8")
    encrypted = encrypt_substitution(raw)
    checksum = compute_sha_round2(encrypted)
    return struct.pack("!II", len(encrypted), checksum) + encrypted


def try_unpack_message(packet: bytes) -> str | None:
    try:
        if len(packet) < 8:
            return None
        payload_len, received_hash = struct.unpack("!II", packet[:8])
        encrypted = packet[8 : 8 + payload_len]

        if len(encrypted) != payload_len:
            return None

        if compute_sha_round2(encrypted) != received_hash:
            return None

        raw = decrypt_substitution(encrypted)
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return None