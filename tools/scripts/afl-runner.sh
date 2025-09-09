#!/bin/bash
set -euo pipefail  # Strict error handling: exit on error, undefined vars, pipe failures

# AFL environment variables for optimal fuzzing performance
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1  # Skip crash directory warnings
export AFL_SKIP_CPUFREQ=1                       # Skip CPU frequency checks
export AFL_DISABLE_TRIM=1                       # Disable input trimming for speed
export AFL_INST_RATIO=0                         # Use all instrumentation
export AFL_AUTORESUME=1                         # Auto-resume interrupted sessions
export AFL_FAST_CAL=1                           # Fast calibration mode

# Default configuration values
CONFIG_PATH="./config.yaml"
MODE=""

# Display usage information
show_usage() {
    cat << EOF
Usage: sudo $0 [-c config_path] [-m mode] [-h help]

Arguments:
  -c config_path  : Path to config.yaml (default: ./config.yaml)
  -m mode         : Operation mode: 'c' (continuous input from stdin)
  -h              : Display this help message

Examples:
  $0                    # Run with default config.yaml
  $0 -c myconf.yaml     # Run with custom config.yaml
  $0 -m c               # Continuous mode (input from stdin)
EOF
}

# Check if file exists, exit with error if not found
check_file() {
    local file="$1"
    if [[ ! -f "$file" ]]; then
        echo "Error: File '$file' does not exist." >&2
        exit 1
    fi
}

# Read configuration value from YAML file using Python
read_config() {
    local key="$1"
    python3 -c "import yaml,sys; print(yaml.safe_load(sys.stdin)$key)" < "$CONFIG_PATH"
}

# Cleanup function called on script exit
cleanup() {
    echo "Cleaning up..." >&2
}
trap cleanup EXIT

# Parse command line arguments
while getopts ":c:m:h" opt; do
    case ${opt} in
        c ) CONFIG_PATH="$OPTARG" ;;
        m ) MODE="$OPTARG" ;;
        h ) show_usage; exit 0 ;;
        \? ) echo "Invalid option: -$OPTARG" >&2; show_usage; exit 1 ;;
        : ) echo "Option -$OPTARG requires an argument" >&2; show_usage; exit 1 ;;
    esac
done

# Validate config file
check_file "$CONFIG_PATH"

# Automatically read OUT from config.yaml
OUT=$(python3 -c 'import yaml,sys; print(yaml.safe_load(sys.stdin)["directories"]["coverage_outputs"])' < "$CONFIG_PATH")
mkdir -p "$OUT"
OUT=$(realpath "$OUT")
OUT=$(dirname "$OUT")

# Validate mode if specified
if [[ -n "$MODE" && "$MODE" != "c" ]]; then
    echo "Error: Invalid mode '$MODE'. Use 'c' for continuous mode." >&2
    exit 1
fi

# Validate configuration file exists
check_file "$CONFIG_PATH"

# Prepare output directory and backup config
cp "$CONFIG_PATH" "$OUT/config.yaml"

echo "Reading configuration from: $CONFIG_PATH"

# Read configuration values from YAML
AFL_DIR=$(read_config '["directories"]["afl_dir"]')
AFL_DIR=$(realpath "$AFL_DIR")
WORK_DIR=$(read_config '["directories"]["work_dir"]')
WORK_DIR=$(realpath "$WORK_DIR")
TARGET_HYPERVISOR=$(read_config '["fuzzing"]["target"]')
COVERAGE_GUIDE=$(read_config '["fuzzing"]["coverage_guided"]')
SEED_DIR=$(read_config '["fuzzing"]["seed_dir"]')
SEED_DIR=$(realpath "$SEED_DIR")

# Verify AFL installation
check_file "$AFL_DIR/afl-gcc"
check_file "$AFL_DIR/afl-fuzz"

# Build target program with AFL instrumentation
echo "Building target program..."
rm -f "$WORK_DIR/tools/bin/fuzz_runner"
make -C "$WORK_DIR/tools" fuzz_runner CC="$AFL_DIR/afl-gcc"

TARGET_PROGRAM="$WORK_DIR/tools/bin/fuzz_runner"
check_file "$TARGET_PROGRAM"

# Configure coverage guidance based on settings
COVERAGE_OPT=""
case "$COVERAGE_GUIDE" in
    "0")
        echo "Coverage guide disabled"
        gcc -O3 --shared -Wall -fPIE -I "$AFL_DIR/include" -o "$WORK_DIR/random_mutator.so" "$WORK_DIR/random_mutator.c"
        export AFL_CUSTOM_MUTATOR_LIBRARY="$WORK_DIR/random_mutator.so"
        export AFL_CUSTOM_MUTATOR_ONLY=1
        COVERAGE_OPT="-n"
        ;;
    "1")
        echo "Coverage guide enabled"
        gcc -O3 --shared -Wall -fPIE -I "$AFL_DIR/include" -o "$WORK_DIR/random_mutator.so" "$WORK_DIR/random_mutator.c"
        export AFL_CUSTOM_MUTATOR_LIBRARY="$WORK_DIR/random_mutator.so"
        export AFL_CUSTOM_MUTATOR_ONLY=1
        COVERAGE_OPT=""
        ;;
    *)
        echo "Error: Invalid coverage_guided value: $COVERAGE_GUIDE" >&2
        exit 1
        ;;
esac

# Execute AFL with specified parameters
run_afl() {
    local input_opt="$1"
    local mode_opt="$2"

    # Build AFL command array
    local afl_cmd=(
        "$AFL_DIR/afl-fuzz"
        $COVERAGE_OPT
        $input_opt
        -o "$OUT"
        $mode_opt
        -g 2048 -G 2048     # Memory limits
        -f afl_input        # Input file name
        -t 30000           # Timeout in ms
        -s 7               # Skip deterministic steps
        "$TARGET_PROGRAM"
    )

    echo "Running: ${afl_cmd[*]}"

    # Use sudo for KVM/VBox targets that require elevated privileges
    if [[ "$TARGET_HYPERVISOR" == "kvm" || "$TARGET_HYPERVISOR" == "vbox" ]]; then
        sudo -E "${afl_cmd[@]}"
    else
        sudo -E "${afl_cmd[@]}"
        # "${afl_cmd[@]}"
    fi
}

# Execute AFL based on specified mode
case "$MODE" in
    "c")
        echo "Running in continuous mode"
        run_afl "-i-" ""
        ;;
    ""|*)
        if [[ -z "$MODE" ]]; then
            echo "Running in single fuzzer mode"
            run_afl "-i $SEED_DIR" ""
        else
            echo "Error: Invalid mode '$MODE'. Use 'c' for continuous mode." >&2
            exit 1
        fi
        ;;
esac

echo "AFL fuzzing completed."