#!/usr/bin/env python3

import os
import csv
import re
import subprocess
import sys
from pathlib import Path

def read_baseline_count():
    """Read the baseline instrumented line count"""
    # Get kernel version using uname -r
    try:
        kernel_version = subprocess.check_output(['uname', '-r'], text=True).strip()
    except subprocess.CalledProcessError:
        print("Error: Could not get kernel version with uname -r")
        sys.exit(1)

    baseline_file = f"./kvm_baseline/{kernel_version}/kvm_arch_nested_count"
    try:
        with open(baseline_file, 'r') as f:
            baseline_count = int(f.read().strip())
        return baseline_count
    except FileNotFoundError:
        print(f"Error: {baseline_file} not found")
        print("Please run: ./tools/scripts/kvm_baseline_coverage.sh")
        sys.exit(1)

def extract_line_numbers(file_path):
    """Extract line numbers from coverage file"""
    line_numbers = set()

    if not os.path.exists(file_path):
        print(f"Warning: {file_path} not found")
        return line_numbers

    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    # Extract line number from the end of the line (after the last colon)
                    match = re.search(r':(\d+)$', line)
                    if match:
                        line_numbers.add(int(match.group(1)))

        print(f"Loaded {len(line_numbers)} lines from {file_path}")
        return line_numbers

    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return line_numbers

def generate_coverage_comparison():
    """Generate coverage comparison CSV"""

    # Read baseline count
    baseline_count = read_baseline_count()
    print(f"Baseline instrumented lines: {baseline_count}")

    # Define file paths
    coverage_files = {
        'NecoFuzz': './out/kvm_necofuzz/coverage_outpus/out/final_nested_coverage',
        'Syzkaller': './out/syzkaller/coverage/out/final_nested_coverage',
        'Selftests': './out/kvm_selftests/final_nested_coverage',
        'KVM-unit-tests': './out/kvm_unit-tests/final_nested_coverage'
    }

    # Load coverage data for each tool
    coverage_sets = {}
    for tool_name, file_path in coverage_files.items():
        coverage_sets[tool_name] = extract_line_numbers(file_path)

    # Calculate set operations and prepare results
    results = []

    # Add Total row (100% baseline)
    results.append(['Total', '100.0%', baseline_count])

    # Individual tool coverage
    necofuzz_count = len(coverage_sets['NecoFuzz'])
    necofuzz_pct = (necofuzz_count / baseline_count * 100) if baseline_count > 0 else 0
    results.append(['NecoFuzz', f'{necofuzz_pct:.1f}%', necofuzz_count])

    syzkaller_count = len(coverage_sets['Syzkaller'])
    syzkaller_pct = (syzkaller_count / baseline_count * 100) if baseline_count > 0 else 0
    results.append(['Syzkaller', f'{syzkaller_pct:.1f}%', syzkaller_count])

    # NecoFuzz vs Syzkaller comparisons
    necofuzz_syzkaller_intersection = coverage_sets['NecoFuzz'] & coverage_sets['Syzkaller']
    necofuzz_minus_syzkaller = coverage_sets['NecoFuzz'] - coverage_sets['Syzkaller']
    syzkaller_minus_necofuzz = coverage_sets['Syzkaller'] - coverage_sets['NecoFuzz']

    intersection_count = len(necofuzz_syzkaller_intersection)
    intersection_pct = (intersection_count / baseline_count * 100) if baseline_count > 0 else 0
    results.append(['NecoFuzz⋀Syzkaller', f'{intersection_pct:.1f}%', intersection_count])

    necofuzz_minus_syzkaller_count = len(necofuzz_minus_syzkaller)
    necofuzz_minus_syzkaller_pct = (necofuzz_minus_syzkaller_count / baseline_count * 100) if baseline_count > 0 else 0
    results.append(['NecoFuzz-Syzkaller', f'{necofuzz_minus_syzkaller_pct:.1f}%', necofuzz_minus_syzkaller_count])

    syzkaller_minus_necofuzz_count = len(syzkaller_minus_necofuzz)
    syzkaller_minus_necofuzz_pct = (syzkaller_minus_necofuzz_count / baseline_count * 100) if baseline_count > 0 else 0
    results.append(['Syzkaller-NecoFuzz', f'{syzkaller_minus_necofuzz_pct:.1f}%', syzkaller_minus_necofuzz_count])

    # Selftests comparisons
    selftests_count = len(coverage_sets['Selftests'])
    selftests_pct = (selftests_count / baseline_count * 100) if baseline_count > 0 else 0
    results.append(['Selftests', f'{selftests_pct:.1f}%', selftests_count])

    necofuzz_selftests_intersection = coverage_sets['NecoFuzz'] & coverage_sets['Selftests']
    necofuzz_minus_selftests = coverage_sets['NecoFuzz'] - coverage_sets['Selftests']
    selftests_minus_necofuzz = coverage_sets['Selftests'] - coverage_sets['NecoFuzz']

    necofuzz_selftests_intersection_count = len(necofuzz_selftests_intersection)
    necofuzz_selftests_intersection_pct = (necofuzz_selftests_intersection_count / baseline_count * 100) if baseline_count > 0 else 0
    results.append(['NecoFuzz⋀Selftests', f'{necofuzz_selftests_intersection_pct:.1f}%', necofuzz_selftests_intersection_count])

    necofuzz_minus_selftests_count = len(necofuzz_minus_selftests)
    necofuzz_minus_selftests_pct = (necofuzz_minus_selftests_count / baseline_count * 100) if baseline_count > 0 else 0
    results.append(['NecoFuzz-Selftests', f'{necofuzz_minus_selftests_pct:.1f}%', necofuzz_minus_selftests_count])

    selftests_minus_necofuzz_count = len(selftests_minus_necofuzz)
    selftests_minus_necofuzz_pct = (selftests_minus_necofuzz_count / baseline_count * 100) if baseline_count > 0 else 0
    results.append(['Selftests-NecoFuzz', f'{selftests_minus_necofuzz_pct:.1f}%', selftests_minus_necofuzz_count])

    # KVM-unit-tests comparisons
    kvmunit_count = len(coverage_sets['KVM-unit-tests'])
    kvmunit_pct = (kvmunit_count / baseline_count * 100) if baseline_count > 0 else 0
    results.append(['KVM-unit-tests', f'{kvmunit_pct:.1f}%', kvmunit_count])

    necofuzz_kvmunit_intersection = coverage_sets['NecoFuzz'] & coverage_sets['KVM-unit-tests']
    necofuzz_minus_kvmunit = coverage_sets['NecoFuzz'] - coverage_sets['KVM-unit-tests']
    kvmunit_minus_necofuzz = coverage_sets['KVM-unit-tests'] - coverage_sets['NecoFuzz']

    necofuzz_kvmunit_intersection_count = len(necofuzz_kvmunit_intersection)
    necofuzz_kvmunit_intersection_pct = (necofuzz_kvmunit_intersection_count / baseline_count * 100) if baseline_count > 0 else 0
    results.append(['NecoFuzz⋀KVM-unit-tests', f'{necofuzz_kvmunit_intersection_pct:.1f}%', necofuzz_kvmunit_intersection_count])

    necofuzz_minus_kvmunit_count = len(necofuzz_minus_kvmunit)
    necofuzz_minus_kvmunit_pct = (necofuzz_minus_kvmunit_count / baseline_count * 100) if baseline_count > 0 else 0
    results.append(['NecoFuzz-KVM-unit-tests', f'{necofuzz_minus_kvmunit_pct:.1f}%', necofuzz_minus_kvmunit_count])

    kvmunit_minus_necofuzz_count = len(kvmunit_minus_necofuzz)
    kvmunit_minus_necofuzz_pct = (kvmunit_minus_necofuzz_count / baseline_count * 100) if baseline_count > 0 else 0
    results.append(['KVM-unit-tests-NecoFuzz', f'{kvmunit_minus_necofuzz_pct:.1f}%', kvmunit_minus_necofuzz_count])

    # Create output directory if it doesn't exist
    output_dir = "artifact"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"Created directory: {output_dir}")

    # Write results to CSV
    output_file = os.path.join(output_dir, "table2.csv")
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Category', 'Coverage %', 'Line Count'])  # Header
        writer.writerows(results)

    print(f"\nCoverage comparison saved to: {output_file}")

    # Print summary to console
    print("\n=== Coverage Comparison Summary ===")
    for category, percentage, count in results:
        print(f"{category:<25}: {percentage:>7} ({count:>4} lines)")

    # Print additional analysis
    print("\n=== Analysis ===")
    if necofuzz_count > 0 and syzkaller_count > 0:
        intersection_ratio = len(necofuzz_syzkaller_intersection) / min(necofuzz_count, syzkaller_count) * 100
        print(f"NecoFuzz vs Syzkaller intersection ratio: {intersection_ratio:.1f}%")

    if necofuzz_count > 0:
        selftests_overlap_ratio = len(necofuzz_selftests_intersection) / necofuzz_count * 100
        kvmunit_overlap_ratio = len(necofuzz_kvmunit_intersection) / necofuzz_count * 100
        print(f"NecoFuzz overlap with Selftests: {selftests_overlap_ratio:.1f}%")
        print(f"NecoFuzz overlap with KVM-unit-tests: {kvmunit_overlap_ratio:.1f}%")

if __name__ == "__main__":
    generate_coverage_comparison()