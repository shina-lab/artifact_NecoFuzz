#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
source "$SCRIPT_DIR/utilities.sh"
CURRENT_DIR="$(pwd)"

# Verify configuration
check_file "$CONFIG_PATH"

# Create output directories
mkdir -p "$CURRENT_DIR"/{cov,out}

# Function to process coverage file
process_coverage_file() {
    local file="$1"
    local output_dir="$2"

    if [[ -e "$output_dir/$file" ]]; then
        return 0  # Already processed
    fi

    echo "Processing $file..."

    # Process coverage with error handling
    if "$SCRIPT_DIR/cov2nested.sh" "$file" "$output_dir/$file" >/dev/null 2>&1; then
        # Count nested.c occurrences
        local nested_count
        nested_count=$(grep -c "nested.c" "$output_dir/$file" 2>/dev/null || echo "0")
        echo "Found $nested_count nested.c references in $file"

        local my_timestamp
        my_timestamp=$(date '+%Y-%m-%d %H:%M:%S')
        # Create CSV file with header if it doesn't exist
        local csv_file="$CURRENT_DIR/coverage_timeline.csv"
        if [[ ! -f "$csv_file" ]]; then
            echo "timestamp,nested_count" > "$csv_file"
        fi
        # Append current data to CSV
        echo "$my_timestamp,$nested_count" >> "$csv_file"

        # Move coverage data and update latest
        if [[ -f "cov_$file" ]]; then
            mv "cov_$file" "$CURRENT_DIR/cov/"
        fi
        cp "$output_dir/$file" "$CURRENT_DIR/out/final_coverage"
        grep nested.c "$CURRENT_DIR/out/final_coverage" > "$CURRENT_DIR/out/final_nested_coverage"
    else
        echo "Warning: Failed to process $file" >&2
    fi
}

# Process existing files
echo "Processing existing coverage files..."
for file in kvm_arch*; do
    if [[ -f "$file" ]]; then
        process_coverage_file "$file" "$CURRENT_DIR/out"
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
inotifywait -m "$CURRENT_DIR" -e create -e moved_to --format '%w%f %e' 2>/dev/null |
    while read filepath event; do
        filename=$(basename "$filepath")

        # Check if file matches pattern and exists
        if [[ "$filename" =~ ^kvm_arch && -f "$filepath" ]]; then
            echo "Detected new file: $filename ($event)"

            # Small delay to ensure file is completely written
            sleep 0.5

            process_coverage_file "$filename" "$CURRENT_DIR/out"
        fi
    done