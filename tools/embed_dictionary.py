#!/usr/bin/env python3
"""Embed the RFC 7932 static dictionary into generated C++ source.

The decoder in ``src/brotli.cpp`` must be self-contained: it may not read data
files at run time.  This script turns the canonical dictionary blob and the
tables that RFC 7932 prints in its appendices into plain C++ arrays:

  * ``_br/dictionary.bin`` -- the 122784 bytes of Appendix A (words of length
    4..24 laid out back to back by length),
  * ``Lut0``/``Lut1``/``Lut2`` -- the literal context lookup tables of
    section 7.1, and
  * the 121 transforms of Appendix B.

Everything the RFC pins down is checked here, so a corrupted or partial input
fails loudly instead of silently generating a wrong decoder.

Usage (from the repository root):

    python tools/embed_dictionary.py
"""

import re
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DICTIONARY = ROOT / "_br" / "dictionary.bin"
RFC = ROOT / "_br" / "rfc7932.txt"
OUT_CPP = ROOT / "src" / "brotli_dictionary.cpp"

DICTIONARY_SIZE = 122784
DICTIONARY_CRC = 0x5136CB04
LUT_CRCS = (0x8E91EFB7, 0xD01A32F4, 0x0DD7A0D6)
TRANSFORM_BLOB_CRC = 0x3D965F81
TRANSFORM_COUNT = 121

# RFC 7932 section 8: log2 of the number of words of each length.  The table is
# forced by the DICTSIZE the RFC states (122784), which is re-derived below.
NDBITS = {
    4: 10, 5: 10, 6: 11, 7: 11, 8: 10, 9: 10, 10: 10, 11: 10, 12: 10,
    13: 9, 14: 9, 15: 8, 16: 7, 17: 7, 18: 8, 19: 7, 20: 7, 21: 6,
    22: 6, 23: 5, 24: 5,
}

# Appendix B transform names, in the order the elementary transforms are
# numbered in section 8 / Appendix B.
TRANSFORM_TYPES = {
    "Identity": 0,
    "FermentFirst": 1,
    "FermentAll": 2,
    "OmitFirst1": 3, "OmitFirst2": 4, "OmitFirst3": 5, "OmitFirst4": 6,
    "OmitFirst5": 7, "OmitFirst6": 8, "OmitFirst7": 9, "OmitFirst8": 10,
    "OmitFirst9": 11,
    "OmitLast1": 12, "OmitLast2": 13, "OmitLast3": 14, "OmitLast4": 15,
    "OmitLast5": 16, "OmitLast6": 17, "OmitLast7": 18, "OmitLast8": 19,
    "OmitLast9": 20,
}


def fail(message):
    sys.stderr.write("embed_dictionary: %s\n" % message)
    raise SystemExit(1)


def decode_c_string(text, where):
    """Turns an Appendix B "..." literal into raw bytes."""
    if len(text) < 2 or text[0] != '"' or text[-1] != '"':
        fail("malformed C string %r in %s" % (text, where))
    out = bytearray()
    i = 1
    end = len(text) - 1
    while i < end:
        c = text[i]
        if c != "\\":
            code = ord(c)
            if code > 0x7F:
                fail("non-ASCII character in %s" % where)
            out.append(code)
            i += 1
            continue
        i += 1
        if i >= end:
            fail("dangling backslash in %s" % where)
        e = text[i]
        if e == "x":
            digits = text[i + 1:i + 3]
            if len(digits) != 2 or not re.fullmatch(r"[0-9A-Fa-f]{2}", digits):
                fail("bad \\x escape in %s" % where)
            out.append(int(digits, 16))
            i += 3
        elif e == "n":
            out.append(0x0A)
            i += 1
        elif e == "t":
            out.append(0x09)
            i += 1
        elif e == "r":
            out.append(0x0D)
            i += 1
        elif e == '"':
            out.append(0x22)
            i += 1
        elif e == "\\":
            out.append(0x5C)
            i += 1
        else:
            fail("unknown escape \\%s in %s" % (e, where))
    return bytes(out)


def load_rfc():
    if not RFC.is_file():
        fail("missing %s" % RFC)
    return RFC.read_text(encoding="utf-8", errors="strict").splitlines()


def parse_lut(lines, name, expect_crc):
    start = None
    for i, line in enumerate(lines):
        if line.strip().startswith(name):
            start = i + 1
            break
    if start is None:
        fail("could not find %s in the RFC text" % name)
    values = []
    for line in lines[start:start + 16]:
        values.extend(int(v) for v in re.findall(r"\d+", line))
    if len(values) != 256:
        fail("%s: parsed %d values, expected 256" % (name, len(values)))
    if any(v > 255 for v in values):
        fail("%s: value out of range" % name)
    data = bytes(values)
    crc = zlib.crc32(data) & 0xFFFFFFFF
    if crc != expect_crc:
        fail("%s: CRC-32 0x%08x, expected 0x%08x" % (name, crc, expect_crc))
    return data


def parse_transforms(lines):
    start = None
    for i, line in enumerate(lines):
        if line.startswith("Appendix B."):
            start = i
            break
    if start is None:
        fail("could not find Appendix B in the RFC text")
    row = re.compile(
        r'^\s*(\d+)\s+("(?:[^"\\]|\\.)*")\s+(\w+)\s+("(?:[^"\\]|\\.)*")\s*$')
    transforms = []
    for line in lines[start:]:
        if line.startswith("Appendix C."):
            break
        m = row.match(line)
        if not m:
            continue
        index = int(m.group(1))
        prefix = decode_c_string(m.group(2), "Appendix B transform %d" % index)
        kind = m.group(3)
        suffix = decode_c_string(m.group(4), "Appendix B transform %d" % index)
        if kind not in TRANSFORM_TYPES:
            fail("transform %d: unknown elementary transform %r" % (index, kind))
        if index != len(transforms):
            fail("transform %d out of order (expected %d)" % (index, len(transforms)))
        if len(prefix) + len(suffix) > 13:
            fail("transform %d: prefix+suffix longer than the 13 bytes the RFC allows"
                 % index)
        transforms.append((prefix, TRANSFORM_TYPES[kind], suffix))
    if len(transforms) != TRANSFORM_COUNT:
        fail("parsed %d transforms, expected %d" % (len(transforms), TRANSFORM_COUNT))
    return transforms


def transform_blob(transforms):
    """The byte sequence the RFC uses to state the Appendix B CRC."""
    blob = bytearray()
    for prefix, kind, suffix in transforms:
        blob += prefix + b"\x00" + bytes([kind]) + suffix + b"\x00"
    return bytes(blob)


def c_string(data):
    out = []
    for b in data:
        if b == 0x22:
            out.append('\\"')
        elif b == 0x5C:
            out.append("\\\\")
        elif 0x20 <= b <= 0x7E:
            out.append(chr(b))
        else:
            out.append("\\%03o" % b)
    return '"' + "".join(out) + '"'


def derive_offsets():
    offsets = [0] * 32
    total = 0
    for length in range(4, 25):
        offsets[length] = total
        total += length * (1 << NDBITS[length])
    if total != DICTIONARY_SIZE:
        fail("the word-count table reaches %d bytes, expected %d"
             % (total, DICTIONARY_SIZE))
    return offsets, total


def emit_bytes(f, name, data, per_line=16):
    f.write("const unsigned char %s[%d] = {\n" % (name, len(data)))
    for i in range(0, len(data), per_line):
        chunk = data[i:i + per_line]
        f.write("    " + ", ".join(str(b) for b in chunk) + ",\n")
    f.write("};\n\n")


def main():
    dictionary = DICTIONARY.read_bytes()
    if len(dictionary) != DICTIONARY_SIZE:
        fail("dictionary.bin is %d bytes, expected %d" % (len(dictionary), DICTIONARY_SIZE))
    crc = zlib.crc32(dictionary) & 0xFFFFFFFF
    if crc != DICTIONARY_CRC:
        fail("dictionary.bin CRC-32 0x%08x, expected 0x%08x" % (crc, DICTIONARY_CRC))

    offsets, total = derive_offsets()
    sizes_bits = [0] * 32
    for length, bits in NDBITS.items():
        sizes_bits[length] = bits

    lines = load_rfc()
    lut = b"".join(parse_lut(lines, "Lut%d" % i, LUT_CRCS[i]) for i in range(3))

    transforms = parse_transforms(lines)
    blob = transform_blob(transforms)
    blob_crc = zlib.crc32(blob) & 0xFFFFFFFF
    if blob_crc != TRANSFORM_BLOB_CRC:
        fail("Appendix B blob CRC-32 0x%08x, expected 0x%08x"
             % (blob_crc, TRANSFORM_BLOB_CRC))

    with OUT_CPP.open("w", encoding="utf-8", newline="\n") as f:
        f.write("// Generated by tools/embed_dictionary.py -- do not edit by hand.\n")
        f.write("//\n")
        f.write("// Source: RFC 7932 Appendix A (%d bytes, CRC-32 0x%08X), the\n"
                % (DICTIONARY_SIZE, DICTIONARY_CRC))
        f.write("// section 7.1 context lookup tables (CRC-32 %s) and the %d\n"
                % (", ".join("0x%08X" % c for c in LUT_CRCS), TRANSFORM_COUNT))
        f.write("// transforms of Appendix B (CRC-32 0x%08X).\n\n"
                % TRANSFORM_BLOB_CRC)
        f.write('#include "netcap/brotli_dictionary.hpp"\n\n')
        f.write("namespace netcap {\n\n")

        emit_bytes(f, "kBrotliDictionary", dictionary)

        f.write("const std::size_t kBrotliDictionaryOffsets[32] = {\n")
        f.write("    " + ", ".join(str(v) for v in offsets) + ",\n};\n\n")

        f.write("const unsigned char kBrotliDictionarySizeBits[32] = {\n")
        f.write("    " + ", ".join(str(v) for v in sizes_bits) + ",\n};\n\n")

        emit_bytes(f, "kBrotliContextLookup", lut)

        f.write("const BrotliTransform kBrotliTransforms[%d] = {\n" % TRANSFORM_COUNT)
        for prefix, kind, suffix in transforms:
            f.write("    {%s, %d, %d, %s, %d},\n"
                    % (c_string(prefix), len(prefix), kind, c_string(suffix), len(suffix)))
        f.write("};\n\n")

        f.write("const u8* brotli_dictionary_data() { return kBrotliDictionary; }\n")
        f.write("std::size_t brotli_dictionary_size() { return %d; }\n" % total)
        f.write("const std::size_t* brotli_dictionary_offsets() { return kBrotliDictionaryOffsets; }\n")
        f.write("const u8* brotli_dictionary_size_bits() { return kBrotliDictionarySizeBits; }\n")
        f.write("const BrotliTransform* brotli_transforms() { return kBrotliTransforms; }\n")
        f.write("std::size_t brotli_transform_count() { return %d; }\n" % TRANSFORM_COUNT)
        f.write("const u8* brotli_context_lookup() { return kBrotliContextLookup; }\n")

        f.write("\n}  // namespace netcap\n")

    sys.stdout.write(
        "wrote %s (%d dictionary bytes, %d transforms, %d lookup bytes)\n"
        % (OUT_CPP.relative_to(ROOT).as_posix(), len(dictionary), len(transforms), len(lut)))


if __name__ == "__main__":
    main()
