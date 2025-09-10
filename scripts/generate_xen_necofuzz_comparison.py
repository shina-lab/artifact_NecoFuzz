#!/usr/bin/env python3

import os
import csv
import re
import sys

def read_baseline_count():
    """Read the baseline instrumented line count for Xen/XTF"""
    baseline_file = "./out/xen_xtf/instrumented_line"
    try:
        with open(baseline_file, 'r') as f:
            lines = [l.strip() for l in f if l.strip()]
            baseline_count = len(lines)
        return baseline_count
    except FileNotFoundError:
        print(f"Error: {baseline_file} not found")
        sys.exit(1)


def extract_line_numbers(file_path):
    """Extract line numbers from coverage file (supports plain numbers or :<num>)"""
    line_numbers = set()
    if not os.path.exists(file_path):
        print(f"Warning: {file_path} not found")
        return line_numbers

    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # Case 1: plain integer line (e.g. "24")
            if line.isdigit():
                line_numbers.add(int(line))
                continue

            # Case 2: colon-delimited (e.g. "...:24")
            match = re.search(r':(\d+)$', line)
            if match:
                line_numbers.add(int(match.group(1)))

    return line_numbers


def generate_xen_coverage_comparison():
    baseline_count = read_baseline_count()
    print(f"Baseline instrumented lines: {baseline_count}")

    coverage_files = {
        'NecoFuzz': './out/xen_necofuzz/coverage_outputs/final_nested_coverage',
        'XTF': './out/xen_xtf/final_nested_coverage',
    }

    coverage_sets = {name: extract_line_numbers(path) for name, path in coverage_files.items()}

    results = []
    results.append(['Total', '100.0%', baseline_count])

    for tool_name, lines in coverage_sets.items():
        count = len(lines)
        pct = (count / baseline_count * 100) if baseline_count > 0 else 0
        results.append([tool_name, f'{pct:.1f}%', count])

    # intersection / differences
    inter = coverage_sets['NecoFuzz'] & coverage_sets['XTF']
    inter_count = len(inter)
    inter_pct = (inter_count / baseline_count * 100) if baseline_count > 0 else 0
    results.append(['NecoFuzz⋀XTF', f'{inter_pct:.1f}%', inter_count])

    neco_only = coverage_sets['NecoFuzz'] - coverage_sets['XTF']
    xtf_only = coverage_sets['XTF'] - coverage_sets['NecoFuzz']
    results.append(['NecoFuzz-XTF', f'{len(neco_only)/baseline_count*100:.1f}%', len(neco_only)])
    results.append(['XTF-NecoFuzz', f'{len(xtf_only)/baseline_count*100:.1f}%', len(xtf_only)])

    # output
    output_dir = "artifact"
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, "table4.csv")
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Category', 'Coverage %', 'Line Count'])
        writer.writerows(results)

    print(f"\nCoverage comparison saved to: {output_file}")
    for row in results:
        print(f"{row[0]:<20}: {row[1]:>7} ({row[2]} lines)")

if __name__ == "__main__":
    generate_xen_coverage_comparison()
