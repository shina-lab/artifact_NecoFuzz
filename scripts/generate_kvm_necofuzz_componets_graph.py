#!/usr/bin/env python3

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import os

def read_baseline_count():
    """Read the baseline instrumented line count"""
    import subprocess
    import sys

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

def process_coverage_data(csv_file, baseline_count, hours=24):
    """Process coverage data and extend to specified hours"""
    df = pd.read_csv(csv_file)
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    start_time = df['timestamp'].iloc[0]
    df['elapsed_hours'] = (df['timestamp'] - start_time).dt.total_seconds() / 3600
    df['coverage_percent'] = (df['nested_count'] / baseline_count) * 100

    hourly_timeline = np.arange(0, hours + 0.1, 0.1)
    coverage_timeline = np.zeros(len(hourly_timeline))

    for i, hour in enumerate(hourly_timeline):
        valid_data = df[df['elapsed_hours'] <= hour]
        if len(valid_data) > 0:
            coverage_timeline[i] = valid_data['coverage_percent'].iloc[-1]
        elif i > 0:
            coverage_timeline[i] = coverage_timeline[i-1]

    return hourly_timeline, coverage_timeline

def create_coverage_graph():
    baseline_count = read_baseline_count()
    print(f"Using baseline count: {baseline_count}")

    # 対象ディレクトリとラベル
    configs = [
        ("./out/kvm_necofuzz/coverage_outputs/coverage_timeline.csv", "with ALL"),
        ("./out/kvm_necofuzz_wo_vcpu_config/coverage_outputs/coverage_timeline.csv", "w/o vCPU configurator"),
        ("./out/kvm_necofuzz_wo_harness/coverage_outputs/coverage_timeline.csv", "w/o VM execution harness"),
        ("./out/kvm_necofuzz_wo_vmstate_validator/coverage_outputs/coverage_timeline.csv", "w/o VM state validator"),
        ("./out/kvm_necofuzz_wo_all/coverage_outputs/coverage_timeline.csv", "w/o ALL"),
    ]

    fig, ax = plt.subplots(1, 1, figsize=(12, 8))

    results = []  # collect final values for CSV/summary
    for csv_file, label in configs:
        hours, coverage = process_coverage_data(csv_file, baseline_count, hours=24)
        ax.plot(hours, coverage, linewidth=2, label=label)
        final_pct = float(coverage[-1])
        final_lines = int(round(final_pct / 100.0 * baseline_count))
        results.append((label, final_pct, final_lines))
        print(f"{label} final coverage: {final_pct:.2f}% ({final_lines} lines)")

    ax.set_xlabel('Time [h]', fontsize=20)
    ax.set_ylabel('Line Coverage [%]', fontsize=20)
    ax.tick_params(axis='y', which='both', labelsize=18)
    ax.tick_params(axis='x', which='both', labelsize=18)
    ax.grid(linestyle='dotted', linewidth=2)

    x_ticks = [0, 6, 12, 18, 24]
    ax.set_xticks(x_ticks)
    ax.set_xticklabels(x_ticks, fontsize=18)

    y_ticks = [0, 20, 40, 60, 80, 100]
    ax.set_yticks(y_ticks)
    ax.set_yticklabels(y_ticks, fontsize=18)

    ax.set_xlim(0, 24)
    ax.set_ylim(0, 100)
    ax.legend(fontsize=14, loc='lower right')
    plt.tight_layout()

    output_dir = "artifact"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"Created directory: {output_dir}")

    output_path = os.path.join(output_dir, "fig4.png")
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"Graph saved to: {output_path}")

    # === Output table3 CSV (24h point) ===
    table_rows = [("Total", 100.0, baseline_count)] + results
    df_out = pd.DataFrame(
        {
            "Category": [r[0] for r in table_rows],
            "Coverage %": [f"{r[1]:.1f}%" for r in table_rows],
            "Line Count": [r[2] for r in table_rows],
        }
    )
    table_path = os.path.join(output_dir, "table3.csv")
    df_out.to_csv(table_path, index=False)
    print(f"Saved CSV to: {table_path}")

    # === Print formatted summary ===
    print("=== Coverage Comparison Summary ===")
    label_width = max(len(name) for name, _, _ in table_rows)
    for name, pct, lines in table_rows:
        print(f"{name.ljust(label_width)} : {pct:6.1f}% ({lines} lines)")

if __name__ == "__main__":
    create_coverage_graph()
