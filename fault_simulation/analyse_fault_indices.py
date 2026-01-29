# SPDX-License-Identifier: MIT
# Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck
import sys
import pandas as pd

def analyze_faults(d: str, e: str, s: int):
    idx_cols = [f"fault_index_{i}" for i in range(s)]
    usecols  = idx_cols + ["fault_result"]
    dtypes   = {c:"int32" for c in idx_cols}
    dtypes["fault_result"] = "int8"

    df = pd.read_csv(f"csv/fault_trace_d{d}_e{e}_s{s}.csv",
                     usecols=usecols, dtype=dtypes)

    # Direct multi‐column groupby
    summary = (
        df
        .groupby(idx_cols + ["fault_result"], sort=False)
        .size()
        .reset_index(name="count")
    )
    
    # Compute overall totals by fault_result
    totals = summary.groupby("fault_result")["count"].sum().to_dict()
    detected    = totals.get(0, 0)
    effective   = totals.get(1, 0)
    ineffective = totals.get(2, 0)
    undetected  = effective + ineffective
    total_runs  = detected + undetected

    pct = lambda x: (x / total_runs * 100) if total_runs else 0.0

    print(f"\nOverall Fault Summary for d={d}, e={e}, s={s}:")
    print(f"  Detected:                 {detected} ({pct(detected):.1f}%)")
    print(f"  Undetected:               {undetected}")
    print(f"    Ineffective (undetected): {ineffective} ({pct(ineffective):.1f}%)")
    print(f"    Effective (undetected):   {effective} ({pct(effective):.1f}%)")
    print(f"  Total Number of Runs:     {total_runs}\n")

def main():
    if len(sys.argv) != 4:
        print("Usage: python3 analyze_faults_pandas.py <d> <e> <s>")
        sys.exit(1)

    d, e, s_str = sys.argv[1], sys.argv[2], sys.argv[3]
    try:
        s = int(s_str)
    except ValueError:
        print("Error: <s> must be an integer", file=sys.stderr)
        sys.exit(1)

    analyze_faults(d, e, s)

if __name__ == "__main__":
    main()
