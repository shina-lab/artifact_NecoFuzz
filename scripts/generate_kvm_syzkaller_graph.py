#!/usr/bin/env python3

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime, timedelta
import os

def read_baseline_count():
    """Read the baseline instrumented line count"""
    import subprocess
    import sys

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

def process_coverage_data(csv_file, baseline_count, hours=48):
    """Process coverage data and extend to specified hours"""
    # Read CSV file
    df = pd.read_csv(csv_file)

    # Convert timestamp to datetime
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    # Calculate elapsed time in hours from the first timestamp
    start_time = df['timestamp'].iloc[0]
    df['elapsed_hours'] = (df['timestamp'] - start_time).dt.total_seconds() / 3600

    # Convert nested_count to coverage percentage
    df['coverage_percent'] = (df['nested_count'] / baseline_count) * 100

    # Create hourly timeline up to specified hours
    hourly_timeline = np.arange(0, hours + 0.1, 0.1)  # Every 6 minutes (0.1 hour)
    coverage_timeline = np.zeros(len(hourly_timeline))

    # Fill coverage data
    for i, hour in enumerate(hourly_timeline):
        # Find the latest coverage value up to this hour
        valid_data = df[df['elapsed_hours'] <= hour]
        if len(valid_data) > 0:
            coverage_timeline[i] = valid_data['coverage_percent'].iloc[-1]
        elif i > 0:
            # Use previous value if no data available
            coverage_timeline[i] = coverage_timeline[i-1]

    return hourly_timeline, coverage_timeline

def create_coverage_graph():
    """Create the coverage analysis graph"""
    # Read baseline count
    baseline_count = read_baseline_count()
    print(f"Using baseline count: {baseline_count}")

    # Process data for both tools
    necofuzz_hours, necofuzz_coverage = process_coverage_data(
        "./out/kvm_necofuzz/coverage_timeline.csv", baseline_count
    )
    syzkaller_hours, syzkaller_coverage = process_coverage_data(
        "./out/syzkaller/coverage_timeline.csv", baseline_count
    )

    # Create the plot
    fig, ax = plt.subplots(1, 1, figsize=(12, 8))

    # Plot the data
    ax.plot(necofuzz_hours, necofuzz_coverage, linewidth=2, label="NecoFuzz")
    ax.plot(syzkaller_hours, syzkaller_coverage, linewidth=2,
            linestyle="dashdot", label="Syzkaller")

    # Set labels and formatting
    ax.set_xlabel('Time [h]', fontsize=20)
    ax.set_ylabel('Line Coverage [%]', fontsize=20)

    # Set tick parameters
    ax.tick_params(axis='y', which='both', labelsize=18)
    ax.tick_params(axis='x', which='both', labelsize=18)

    # Add grid
    ax.grid(linestyle='dotted', linewidth=2)

    # Set ticks
    x_ticks = [0, 12, 24, 36, 48]
    ax.set_xticks(x_ticks)
    ax.set_xticklabels(x_ticks, fontsize=18)

    y_ticks = [0, 20, 40, 60, 80, 100]
    ax.set_yticks(y_ticks)
    ax.set_yticklabels(y_ticks, fontsize=18)

    # Set axis limits
    ax.set_xlim(0, 48)
    ax.set_ylim(0, 100)

    # Add legend
    ax.legend(fontsize=16, loc='lower right')

    # Adjust layout
    plt.tight_layout()

    # Create output directory if it doesn't exist
    output_dir = "artifact"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"Created directory: {output_dir}")

    # Save the figure
    output_path = os.path.join(output_dir, "fig3.png")
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"Graph saved to: {output_path}")

    # Show some statistics
    print(f"\nNecoFuzz final coverage: {necofuzz_coverage[-1]:.2f}%")
    print(f"Syzkaller final coverage: {syzkaller_coverage[-1]:.2f}%")

if __name__ == "__main__":
    create_coverage_graph()