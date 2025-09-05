#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
source "$SCRIPT_DIR/utilities.sh"
CURRENT_DIR="$(pwd)"

# Verify configuration
check_file "$CONFIG_PATH"

COVERAGE_DIR=$(python3 -c 'import yaml,sys;print(yaml.safe_load(sys.stdin)["directories"]["coverage_outputs"])' < $CONFIG_PATH)
COVERAGE_DIR=$(realpath "$COVERAGE_DIR")
# Create output directories
mkdir -p "$COVERAGE_DIR"/{cov,out}

# Function to process coverage file
process_coverage_file() {
    local file="$1"
    local output_dir="$2"
    local filename=$(basename "$file")  # ファイル名のみ取得

    if [[ -e "$output_dir/$filename" ]]; then
        nested_count=$(grep -c "nested.c" "$output_dir/$filename" 2>/dev/null || echo "0")
        echo "Found $nested_count nested.c references in $output_dir/$filename"
        return 0  # Already processed
    fi

    echo "Processing $file..."

    # Process coverage with error handling
    if "$SCRIPT_DIR/cov2nested.sh" "$file" "$output_dir/$filename" >/dev/null 2>&1; then
        # Count nested.c occurrences
        local nested_count
        nested_count=$(grep -c "nested.c" "$output_dir/$filename" 2>/dev/null || echo "0")
        echo "Found $nested_count nested.c references in $output_dir/$filename"

        local my_timestamp
        my_timestamp=$(date '+%Y-%m-%d %H:%M:%S')
        # Create CSV file with header if it doesn't exist
        local csv_file="$COVERAGE_DIR/coverage_timeline.csv"
        if [[ ! -f "$csv_file" ]]; then
            echo "timestamp,nested_count" > "$csv_file"
        fi
        # Append current data to CSV
        echo "$my_timestamp,$nested_count" >> "$csv_file"

        # Move coverage data and update latest
        if [[ -f "COVERAGE_DIR/cov_$filename" ]]; then
            mv "COVERAGE_DIR/cov_$filename" "$COVERAGE_DIR/cov/"
        fi
        cp "$output_dir/$filename" "$COVERAGE_DIR/out/final_coverage"
        grep nested.c "$COVERAGE_DIR/out/final_coverage" > "$COVERAGE_DIR/out/final_nested_coverage"
    else
        echo "ERROR: cov2nested.sh failed with exit code $?" >&2
    fi
}

# Process existing files
echo "Processing existing coverage files..."
for file in "$COVERAGE_DIR"/kvm_arch*; do
    if [[ -f "$file" ]]; then
        process_coverage_file "$file" "$COVERAGE_DIR/out"
    fi
done

# Check if inotifywait is available
if ! command -v inotifywait >/dev/null 2>&1; then
    echo "Warning: inotifywait not found. Install inotify-tools for real-time monitoring." >&2
    echo "Processed existing files. Exiting." >&2
    exit 0
fi

# Monitor for new files
echo "Monitoring for new coverage files... (Press Ctrl+C to stop)"
inotifywait -m "$COVERAGE_DIR" -e create -e moved_to --format '%w%f %e' 2>/dev/null |
    while read filepath event; do
        filename=$(basename "$filepath")

        # Check if file matches pattern and exists
        if [[ "$filename" =~ ^kvm_arch && -f "$filepath" ]]; then
            echo "Detected new file: $filename ($event)"

            # Small delay to ensure file is completely written
            sleep 0.5

            process_coverage_file "$filepath" "$COVERAGE_DIR/out"
        fi
    done