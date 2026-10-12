# rUGP 6.x Engine Unpack & Script Extraction Toolkit

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A fast, standalone Python toolkit for extracting dialogue scripts from **âge's rUGP 6.x engine** (`.rio` archives) directly into standard **GalTransl JSON** format.

Works on visual novels powered by rUGP 6.x (such as *Haruko Maniax*, *Muv-Luv* series, *Photonflowers*, *Photonmelodies*, etc.).

---

## 💡 Why was rUGP historically difficult to unpack?

1. **Not a flat archive, but a C++ object tree**: `.rio` archives serialize complex MFC C++ class trees (`CrelicUnitedGameProject`, `CBoxOcean`, `COceanNode`, etc.). Existing tools like GARbro often break during deep `CBoxOcean` recursive deserialization due to engine version/schema discrepancies.
2. **Hidden deep scenario nodes**: The root TOC table often only exposes system scripts (~100 lines), while 90%+ of the game's core dialogue blocks reside deep in non-indexed `ReadEncrypted` blocks.
3. **VM Bytecode Format & Mojibake Pitfalls**: Scenario text is mixed with complex VM stack opcodes (`0x60`, parameters, and jump offsets). Naive pattern matching often triggers false positives (such as parameter bytes `0x20 0x00` being misread as length prefixes), causing severe byte shifts and Shift-JIS mojibake (e.g. `ﾂ F €Lｮ\`).
4. **Nested Instruction Enclosures**: Certain event scenarios wrap text instructions inside parent macro blocks (`0x60 0x01 0x00 ...`), requiring strict boundary checks to prevent trailing nulls or machine opcode headers (`B \`4`, `K \`.`) from leaking into dialogue.

This tool solves all of these problems:
- Bypasses unstable C++ object graph deserialization entirely via a **fast 4-phase alignment scan** directly on the `ReadEncrypted` stream cipher layer (`RioKey = 0x7E6B8CE2`).
- Employs **strict VM opcode parsing** (`0x60 [sub_op] 0x00 [len]`) with CP932 character space validation and control-code stripping, achieving **100% zero-mojibake dialogue extraction** in seconds.

---

## ✨ Features

- **Zero External Dependencies**: Written in pure Python standard library (`array`, `struct`, `re`, `json`).
- **High Performance**: Vectorized 4-phase alignment chunk streaming scan (processes ~700MB in ~30 seconds).
- **100% Zero-Mojibake Clean Extraction**: Eliminates byte-shifted Shift-JIS mojibake, binary instruction offsets, and unprintable control characters.
- **GalTransl Native**: Dumps dialogues into standardized UTF-8 JSON format with speaker names and narrations cleanly separated.
- **Multi-Speaker Line Splitting**: Automatically normalizes lines containing multiple speakers (e.g. `【太一】「...」\n【晴子】「...」`) into clean, independent JSON entries.
- **Bi-directional Stream Cipher**: Includes both `read_encrypted` (decrypt) and `encrypt_block` (encrypt) functions with 100% roundtrip byte fidelity.

---

## 🚀 Quick Start

### 1. Requirements
- Python 3.8 or higher. No `pip install` required.

### 2. Usage
```bash
# Basic extraction
python rugp_extractor.py "path/to/game.rio" -o extracted_scripts

# Specify a custom RioKey (defaults to 0x7E6B8CE2)
python rugp_extractor.py "path/to/game.rio" -o extracted_scripts -k 0x7E6B8CE2

# Skip dumping raw decrypted bytecode (.dec files)
python rugp_extractor.py "path/to/game.rio" -o extracted_scripts --no-raw
```

### 3. Output Format
Extracted `.json` files strictly follow the GalTransl convention:
```json
[
  {
    "name": "太一",
    "message": "「……嫌だ」"
  },
  {
    "name": "晴子",
    "message": "「……」"
  },
  {
    "name": null,
    "message": "放してと言われて素直に放すんなら、\n最初からこんなことはしてない。"
  }
]
```

---

## 📜 License
MIT License.
