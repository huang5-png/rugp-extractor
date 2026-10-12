# -*- coding: utf-8 -*-
"""
rUGP Engine Unpack & Script Extraction Toolkit (rUGP 6.x)
Author: huang5-png & Pair AI Assistant
License: MIT
"""
import os
import sys
import struct
import re
import json
import array
import argparse
from typing import List, Dict, Tuple, Optional

class StreamEx:
    """Helper memory stream reader."""
    def __init__(self, data: bytes, pos: int = 0):
        self.data = data
        self.pos = pos

    def read(self, n: int) -> bytes:
        d = self.data[self.pos:self.pos + n]
        self.pos += n
        return d

    def u16(self) -> int:
        return struct.unpack('<H', self.read(2))[0]

    def u32(self) -> int:
        return struct.unpack('<I', self.read(4))[0]


class RugpExtractor:
    """
    Core extractor for age's rUGP 6.x engine (.rio / .ici container).
    Bypasses deep MFC C++ serialization tree issues by directly decrypting
    the underlying ReadEncrypted streams and scanning bytecode dialogue tokens.
    """
    DEFAULT_RIO_KEY = 0x7E6B8CE2
    DEFAULT_ICI_KEY = 0xB29D5A0C

    def __init__(self, rio_path: str, key: int = DEFAULT_RIO_KEY):
        self.rio_path = rio_path
        self.rio_key = key
        self.file_size = os.path.getsize(rio_path)

    @staticmethod
    def read_encrypted(st: StreamEx, key: int) -> Optional[bytes]:
        """
        Decrypt rUGP ReadEncrypted stream block (32-byte chunks with PRNG rotation).
        """
        if st.pos + 8 > len(st.data):
            return None
        size1 = st.u32() ^ 0xC92E568B
        size2 = st.u32() ^ 0xC92E568F
        size2 >>= 3
        size1 = (~size1) & 0xFFFFFFFF
        if size1 != size2:
            return None

        ici = bytearray(size1)
        dst = 0
        while dst < len(ici):
            checksum = 0
            portion = min(0x20, len(ici) - dst)
            if st.pos + portion > len(st.data):
                return None
            chunk = st.read(portion)
            for i in range(portion, 0, -1):
                b = chunk[portion - i] ^ (key & 0xFF)
                ici[dst] = b
                dst += 1
                checksum = (checksum + b * i) & 0xFFFF
                bit = (key >> 15) & 1
                key = (~(bit + key * 2 + 0xA3B376C9)) & 0xFFFFFFFF
            if portion < 0x20:
                break
            if st.pos + 2 > len(st.data):
                return None
            chunk_sum = st.u16()
            if chunk_sum != checksum:
                return None
        return bytes(ici)

    @staticmethod
    def encrypt_block(plain_bytes: bytes, key: int = DEFAULT_RIO_KEY) -> bytes:
        """
        Encrypt plain bytes back into rUGP ReadEncrypted stream block format.
        Useful for rebuilding patched scenario scripts into .rio archives.
        """
        size = len(plain_bytes)
        s1 = (~size ^ 0xC92E568B) & 0xFFFFFFFF
        s2 = ((size << 3) ^ 0xC92E568F) & 0xFFFFFFFF

        out = bytearray(struct.pack('<2I', s1, s2))
        src = 0
        while src < size:
            portion = min(0x20, size - src)
            chunk = plain_bytes[src:src + portion]
            enc_chunk = bytearray(portion)
            checksum = 0
            for i in range(portion, 0, -1):
                orig_b = chunk[portion - i]
                b = orig_b ^ (key & 0xFF)
                enc_chunk[portion - i] = b
                checksum = (checksum + orig_b * i) & 0xFFFF
                bit = (key >> 15) & 1
                key = (~(bit + key * 2 + 0xA3B376C9)) & 0xFFFFFFFF
            out.extend(enc_chunk)
            src += portion
            if portion == 0x20:
                out.extend(struct.pack('<H', checksum))
        return bytes(out)

    def scan_scenario_blocks(self, chunk_mb: int = 64) -> List[Tuple[int, bytes]]:
        """
        Scan the archive across all 4-byte alignments to discover all decrypted scenario blocks.
        """
        chunk_size = chunk_mb * 1024 * 1024
        found_blocks = []

        print(f"[*] Scanning {self.rio_path} ({self.file_size / (1024*1024):.1f} MB) in {chunk_mb}MB chunks...")

        with open(self.rio_path, 'rb') as f:
            offset = 0
            while offset < self.file_size:
                f.seek(offset)
                buf = f.read(chunk_size + 16)
                if not buf:
                    break

                for align in range(4):
                    sub = buf[align:]
                    words = array.array('I')
                    aligned_len = (len(sub) // 4) * 4
                    words.frombytes(sub[:aligned_len])

                    for i in range(len(words) - 1):
                        w1 = words[i]
                        w2 = words[i + 1]
                        s1 = (~(w1 ^ 0xC92E568B)) & 0xFFFFFFFF
                        s2 = ((w2 ^ 0xC92E568F) >> 3) & 0xFFFFFFFF
                        if s1 == s2 and 500 < s1 < 0x200000:
                            abs_pos = offset + align + i * 4
                            st = StreamEx(buf, align + i * 4)
                            dec = self.read_encrypted(st, self.rio_key)
                            if dec:
                                # Count Japanese dialogue quotation marks
                                k = dec.count(b'\x81\x75')
                                c = dec.count(b'\x81\x79')
                                if k > 0 or c > 0:
                                    found_blocks.append((abs_pos, dec))
                                    print(f"  [+] Found Scenario Block @ 0x{abs_pos:08X} (Size: {len(dec)} B, Quotes: {k})")

                offset += chunk_size

        print(f"[*] Total scenario blocks identified: {len(found_blocks)}")
        return found_blocks

    @staticmethod
    def extract_dialogues_from_bytecode(dec: bytes) -> List[Dict[str, Optional[str]]]:
        """
        Extract dialogue lines (with speaker names) and narrations from decrypted rUGP bytecode.
        Opcodes: (0x60 | 0x1F | 0x20) followed by 1-byte length prefix.
        Control byte: 0x03 is converted to newline.
        """
        records = []
        seen = set()

        # Matches VM string instructions
        for m in re.finditer(b'(\x60|\x1f|\x20)(.)\x00(.)', dec):
            pos = m.start()
            ln = m.group(3)[0]
            if 1 <= ln <= 255 and pos + 4 + ln <= len(dec):
                seg = dec[pos + 4 : pos + 4 + ln]
                try:
                    raw_txt = seg.replace(b'\x03', b'\n').replace(b'\x01', b'').decode('cp932').strip()
                    # Filter for valid Japanese text (hiragana, katakana, or kanji)
                    if any(0x3040 <= ord(c) <= 0x30ff or 0x4e00 <= ord(c) <= 0x9fff for c in raw_txt):
                        # Filter resource file names
                        if raw_txt.endswith(('.png', '.wav', '.ogg', '.uuc', '.rpo')):
                            continue
                        if raw_txt in seen:
                            continue
                        seen.add(raw_txt)

                        # Separate speaker name from dialogue
                        cm = re.match(r'^(?:【(.*?)】)?(.*)$', raw_txt, re.DOTALL)
                        name = cm.group(1).strip() if cm and cm.group(1) else None
                        msg = cm.group(2).strip() if cm else raw_txt

                        records.append({
                            "name": name,
                            "message": msg
                        })
                except Exception:
                    pass

        return records

    def dump_all(self, out_dir: str, save_decrypted_binaries: bool = True):
        """
        Scan entire .rio, decrypt all scenario blocks, and dump into GalTransl JSON.
        """
        os.makedirs(out_dir, exist_ok=True)
        raw_dir = os.path.join(out_dir, "raw_dec")
        if save_decrypted_binaries:
            os.makedirs(raw_dir, exist_ok=True)

        blocks = self.scan_scenario_blocks()
        total_dialogues = 0
        manifest = []

        for idx, (pos, dec) in enumerate(blocks):
            if save_decrypted_binaries:
                bin_name = f"script_{idx:02d}_{pos:08X}.dec"
                with open(os.path.join(raw_dir, bin_name), 'wb') as bf:
                    bf.write(dec)

            records = self.extract_dialogues_from_bytecode(dec)
            if records:
                json_name = f"script_{idx:02d}_{pos:08X}.json"
                out_path = os.path.join(out_dir, json_name)
                with open(out_path, 'w', encoding='utf-8') as jf:
                    json.dump(records, jf, ensure_ascii=False, indent=2)

                total_dialogues += len(records)
                manifest.append({
                    "file": json_name,
                    "offset": hex(pos),
                    "lines": len(records)
                })
                print(f"  [✓] Exported {json_name} ({len(records)} lines)")

        print("=" * 60)
        print(f"Extraction Completed!")
        print(f"Total script files: {len(manifest)}")
        print(f"Total lines extracted: {total_dialogues}")
        print(f"Output directory: {out_dir}")


def main():
    parser = argparse.ArgumentParser(description="rUGP 6.x Engine Dialogue Extractor (.rio)")
    parser.add_argument("rio_file", help="Path to target .rio archive (e.g. game.rio)")
    parser.add_argument("-o", "--output", default="extracted_scripts", help="Output directory for GalTransl JSONs")
    parser.add_argument("-k", "--key", type=lambda x: int(x, 0), default=0x7E6B8CE2, help="RioKey hex value (default: 0x7E6B8CE2)")
    parser.add_argument("--no-raw", action="store_true", help="Do not save decrypted .dec raw bytecode binaries")

    args = parser.parse_args()

    if not os.path.exists(args.rio_file):
        print(f"Error: file {args.rio_file} does not exist.")
        sys.exit(1)

    extractor = RugpExtractor(args.rio_file, key=args.key)
    extractor.dump_all(args.output, save_decrypted_binaries=not args.no_raw)

if __name__ == "__main__":
    main()
