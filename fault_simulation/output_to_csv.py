# SPDX-License-Identifier: MIT
# Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
import sys
import mmap

def extract_and_write(input_file: str, output_file: str):
    start_mark = b"###PRINTING CSV###"
    end_mark   = b"###END PRINTING CSV###"

    # Open and memory‐map the whole file read‐only.
    with open(input_file, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

        # Find the markers
        start = mm.find(start_mark)
        if start < 0:
            sys.exit(f"Error: start marker not found in {input_file}")
        # skip past the marker line (up to the next newline)
        start = mm.find(b"\n", start) + 1

        end = mm.find(end_mark, start)
        if end < 0:
            sys.exit(f"Error: end marker not found in {input_file}")

        # Slice out the CSV block
        csv_block = mm[start:end]
        mm.close()

    # Write it in one shot
    with open(output_file, "wb") as out:
        out.write(csv_block)

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 output_to_csv.py <input_file> <output_csv_file>")
        sys.exit(1)

    inp, out = sys.argv[1], sys.argv[2]
    print(f"Extracting CSV section from {inp} to {out}")
    extract_and_write(inp, out)
    print("CSV extraction complete.")

if __name__ == "__main__":
    main()
