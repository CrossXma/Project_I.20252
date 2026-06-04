import os
import re
import json
from collections import Counter

import pefile
from capstone import *


# ============================================================
# CONFIG
# ============================================================

SUSPICIOUS_STRINGS = {
    "powershell",
    "cmd.exe",
    "http://",
    "https://",
    "runonce",
    "regedit",
    "taskkill",
    "vssadmin",
    "bitcoin",
    "wallet"
}

COMMON_PORTS = {
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    443,
    445,
    8080
}


# ============================================================
# PE SECTION HELPERS
# ============================================================

def get_text_section(pe):
    """
    Locate .text section.
    """

    for section in pe.sections:

        name = section.Name.decode(
            errors="ignore"
        ).strip("\x00")

        if name == ".text":
            return section

    return None


# ============================================================
# DISASSEMBLY
# ============================================================

def extract_opcodes(filepath):
    """
    Extract opcode mnemonics from .text section.
    """

    try:
        pe = pefile.PE(filepath)

        text_section = get_text_section(pe)

        if text_section is None:
            return []

        code = text_section.get_data()

        address = (
            pe.OPTIONAL_HEADER.ImageBase
            + text_section.VirtualAddress
        )

        md = Cs(CS_ARCH_X86, CS_MODE_32)

        opcodes = []

        for ins in md.disasm(code, address):
            opcodes.append(ins.mnemonic)

        return opcodes

    except Exception:
        return []


def opcode_frequency(opcodes):
    return dict(Counter(opcodes))


def top_n_opcodes(opcodes, n=30):
    return dict(
        Counter(opcodes).most_common(n)
    )


# ============================================================
# OPCODE NGRAMS
# ============================================================

def opcode_ngrams(opcodes, n=3):

    grams = []

    for i in range(len(opcodes) - n + 1):

        grams.append(
            tuple(opcodes[i:i+n])
        )

    return grams


# ============================================================
# STRING EXTRACTION
# ============================================================

def extract_strings(filepath, min_length=4):

    try:
        with open(filepath, "rb") as f:
            data = f.read()

        pattern = rb"[\x20-\x7E]{%d,}" % min_length

        matches = re.findall(
            pattern,
            data
        )

        return [
            s.decode(errors="ignore")
            for s in matches
        ]

    except Exception:
        return []


def suspicious_strings(strings):

    results = []

    for s in strings:

        lower = s.lower()

        for keyword in SUSPICIOUS_STRINGS:

            if keyword in lower:
                results.append(s)
                break

    return results


# ============================================================
# CONSTANT EXTRACTION
# ============================================================

def extract_constants(filepath):

    try:
        with open(filepath, "rb") as f:
            data = f.read()

        matches = re.findall(
            rb"\d{2,10}",
            data
        )

        constants = []

        for m in matches:

            try:
                constants.append(
                    int(m)
                )

            except ValueError:
                pass

        return constants

    except Exception:
        return []


def detect_ports(constants):

    return list(
        set(constants)
        &
        COMMON_PORTS
    )


# ============================================================
# SAVE ASM FILE
# ============================================================

def save_disassembly(
        filepath,
        output_path):

    pe = pefile.PE(filepath)

    text_section = get_text_section(pe)

    if text_section is None:
        return

    code = text_section.get_data()

    address = (
        pe.OPTIONAL_HEADER.ImageBase
        + text_section.VirtualAddress
    )

    md = Cs(
        CS_ARCH_X86,
        CS_MODE_32
    )

    with open(
        output_path,
        "w",
        encoding="utf-8"
    ) as f:

        for ins in md.disasm(
                code,
                address):

            f.write(
                f"{hex(ins.address)}: "
                f"{ins.mnemonic} "
                f"{ins.op_str}\n"
            )


# ============================================================
# MAIN FEATURE EXTRACTION
# ============================================================

def extract_asm_features(filepath):

    opcodes = extract_opcodes(filepath)

    strings = extract_strings(filepath)

    constants = extract_constants(filepath)

    return {

        "opcode_count":
            len(opcodes),

        "top_opcodes":
            top_n_opcodes(
                opcodes,
                n=30
            ),

        "opcode_ngrams":
            [
                list(x)
                for x in opcode_ngrams(
                    opcodes,
                    n=3
                )[:500]
            ],

        "string_count":
            len(strings),

        "suspicious_strings":
            suspicious_strings(strings),

        "detected_ports":
            detect_ports(constants)
    }


# ============================================================
# SAVE FEATURES
# ============================================================

def save_feature_json(
        filepath,
        output_json):

    features = extract_asm_features(
        filepath
    )

    with open(
        output_json,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            features,
            f,
            indent=4
        )

# ============================================================
# PROCESS ENTIRE DATASET
# ============================================================

def process_dataset(dataset_root,
                    feature_root,
                    asm_root=None):

    for root, dirs, files in os.walk(dataset_root):

        for filename in files:

            filepath = os.path.join(
                root,
                filename
            )

            try:

                relative_path = os.path.relpath(
                    root,
                    dataset_root
                )

                feature_dir = os.path.join(
                    feature_root,
                    relative_path
                )

                os.makedirs(
                    feature_dir,
                    exist_ok=True
                )

                features = extract_asm_features(
                    filepath
                )

                json_path = os.path.join(
                    feature_dir,
                    f"{filename}.json"
                )

                with open(
                    json_path,
                    "w",
                    encoding="utf-8"
                ) as f:

                    json.dump(
                        features,
                        f,
                        indent=4
                    )

                if asm_root:

                    asm_dir = os.path.join(
                        asm_root,
                        relative_path
                    )

                    os.makedirs(
                        asm_dir,
                        exist_ok=True
                    )

                    asm_path = os.path.join(
                        asm_dir,
                        f"{filename}.asm"
                    )

                    save_disassembly(
                        filepath,
                        asm_path
                    )

                print(
                    f"[+] {filename}"
                )

            except Exception as e:

                print(
                    f"[-] {filename}: {e}"
                )

# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    # process_dataset(
    #     dataset_root="../dataset/malware",
    #     feature_root="../dataset/features/malware",
    #     asm_root="../dataset/asm/malware"
    # )

    # process_dataset(
    #     dataset_root="../dataset/benign",
    #     feature_root="../dataset/features/benign",
    #     asm_root="../dataset/asm/benign"
    # )

    # ============================================================
    # TEST
    # ============================================================

    sample = r"sample.exe"

    features = extract_asm_features(
        sample
    )

    print(
        json.dumps(
            features,
            indent=4
        )
    )