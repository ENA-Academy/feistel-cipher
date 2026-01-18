#!/usr/bin/env python3

import re
import sys

# Input / Output files
INPUT_FILE = "input.txt"
OUTPUT_FILE = "output.txt"

hex_output = []

try:
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            # Remove Windows EOF character if exists
            line = line.replace("\x1a", "").strip()

            # Preserve empty lines
            if not line:
                hex_output.append("")
                continue

            # Extract decimal numbers only
            numbers = re.findall(r"\d+", line)

            hex_line = "".join(f"0x{int(n):02x}," for n in numbers)
            hex_output.append(hex_line)

except FileNotFoundError:
    print(f"Error: '{INPUT_FILE}' not found.")
    sys.exit(1)

# Write output to file
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    for line in hex_output:
        f.write(line + "\n")

print("Conversion completed successfully.")
print(f"Input file : {INPUT_FILE}")
print(f"Output file: {OUTPUT_FILE}")
