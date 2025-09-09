#!/bin/bash
CONFIG_PATH="./config.yaml"  # default path

XEN_COV_FILE="/tmp/tmp.gcov"
COVERAGE_FILE="/tmp/coverage.dat"
JSON_COVERAGE_FILE="/tmp/coverage.json"
KVM_COV_FILE="/dev/shm/kvm_coverage"
KVM_ARCH_COV_FILE="/dev/shm/kvm_arch_coverage"

cpu_vendor=$(grep -m1 vendor_id /proc/cpuinfo | awk -F ":" '{print $2}' | tr -d ' ')

if [ "$cpu_vendor" = "GenuineIntel" ]; then
    arch="intel"
    TARGET_FILES=("arch/x86/hvm/vmx/vvmx.c")
    GCDA_FILES=("arch/x86/hvm/vmx/.vvmx.o.gcda")
elif [ "$cpu_vendor" = "AuthenticAMD" ]; then
    arch="amd"
    TARGET_FILES=("arch/x86/hvm/svm/nestedsvm.c")
    GCDA_FILES=("arch/x86/hvm/svm/nestedsvm.gcda")
else
    echo "Unknown CPU vendor"
    exit 1
fi

monitor_fuzzing() {
    local log_file=$1
    local fuzz_started_flag="/tmp/fuzz_started.flag"
    local pid=$!
    rm -f $fuzz_started_flag

    tail -n 0 -f "$log_file" | while IFS= read -r line; do
        echo "$line"
        if [[ "$line" == *'!'* ]]; then
            touch $fuzz_started_flag
        fi
    done &
    local tail_pid=$!
    while [ ! -f $fuzz_started_flag ]; do
        sleep 1
    done
    sleep 1
    kill $tail_pid
    rm -f $fuzz_started_flag
}

log() {
    printf '\r\033[K[COV] %s\n' "$1"
    printf '\r\033[K'
}

# stty -g > /tmp/stty_settings

if [ "$1" = "kvm" ]; then
    if [ "$2" = "unload" ]; then
        cpu_vendor=$(grep -m1 vendor_id /proc/cpuinfo | awk -F ":" '{print $2}' | tr -d ' ')
        if [ "$cpu_vendor" = "GenuineIntel" ]; then
            arch="intel"
        elif [ "$cpu_vendor" = "AuthenticAMD" ]; then
            arch="amd"
        fi
        sudo pkill qemu
        echo "sudo modprobe kvm_$arch -r"
        sudo modprobe kvm_$arch -r
    elif [ "$2" = "covsave_kvm" ]; then
        COVERAGE_DIR=$(python3 -c 'import yaml,sys;print(yaml.safe_load(sys.stdin)["directories"]["coverage_outputs"])' < $CONFIG_PATH)
        file_name=$(date '+%Y_%m_%d_%H_%M_%S_%3N')
        cp $KVM_COV_FILE $COVERAGE_DIR/kvm_$file_name
        echo "New coverage found $COVERAGE_DIR/kvm_$file_name"
    elif [ "$2" = "covsave_kvm_arch" ]; then
        COVERAGE_DIR=$(python3 -c 'import yaml,sys;print(yaml.safe_load(sys.stdin)["directories"]["coverage_outputs"])' < $CONFIG_PATH)
        file_name=$(date '+%Y_%m_%d_%H_%M_%S_%3N')
        cp $KVM_ARCH_COV_FILE $COVERAGE_DIR/kvm_arch_$file_name
        echo "New coverage found $COVERAGE_DIR/kvm_arch_$file_name"
    elif [ "$2" = "start" ]; then
        log_file="/tmp/kvm-necofuzz.log"
        log_param_file="/tmp/kvm-param.log"
        cpu_vendor=$(grep -m1 vendor_id /proc/cpuinfo | awk -F ":" '{print $2}' | tr -d ' ')
        if [ "$cpu_vendor" = "GenuineIntel" ]; then
            arch="intel"
        elif [ "$cpu_vendor" = "AuthenticAMD" ]; then
            arch="amd"
        fi
        vendor_name=$3
        kvm_param=$4
        cpu_flags=$5
        qemu_path=$(python3 -c 'import yaml,sys;print(yaml.safe_load(sys.stdin)["program"]["qemu"])' < $CONFIG_PATH)
        if lsmod | grep "kvm_${arch}"; then
            while lsmod | grep "kvm_${arch}"; do
                sudo modprobe kvm_$arch -r
                sleep 0.1
            done
        fi
        sudo modprobe kvm_${arch} $kvm_param > $log_param_file 2>&1
        echo "$kvm_param" >> $log_param_file

        sudo rm $log_file -f
        sudo touch $log_file
        # chmod 666 $log_file
        sudo pkill qemu
        # exec {stdout}>&1
        sudo $qemu_path -nodefaults -enable-kvm -machine accel=kvm -cpu $cpu_flags -m 256 -smp 2 -hda json:"{\"fat-type\":0,\"dir\":\"kvm-necofuzz\",\"driver\":\"vvfat\",\"floppy\":false,\"rw\":true}" -nographic -serial file:${log_file} -no-reboot -bios /usr/share/qemu/OVMF.fd &
        # sudo $qemu_path -nodefaults -enable-kvm -machine accel=kvm -cpu $cpu_flags -m 256 -smp 2 -hda json:"{\"fat-type\":0,\"dir\":\"kvm-necofuzz\",\"driver\":\"vvfat\",\"floppy\":false,\"rw\":true}" -nographic -serial file:${log_file} -no-reboot -bios /usr/share/qemu/OVMF.fd & </dev/null 2> >(tee /dev/stderr) > /dev/fd/$stdout
        # exec {stdout}>&-
        qemu_pid=$!
        monitor_fuzzing $log_file

        sudo kill -9 $qemu_pid
        sleep 0.1
    fi
elif [ "$1" = "xen" ]; then
    if [ "$2" = "covsave" ]; then
        COVERAGE_DIR=$(python3 -c 'import yaml,sys;print(yaml.safe_load(sys.stdin)["directories"]["coverage_outputs"])' < $CONFIG_PATH)
        file_name=$(date '+%Y_%m_%d_%H_%M_%S_%3N')
        cp $JSON_COVERAGE_FILE $COVERAGE_DIR/cov_$file_name.json
    elif [ "$2" = "start" ]; then
        COVERAGE_DIR=$(python3 -c 'import yaml,sys;print(yaml.safe_load(sys.stdin)["directories"]["coverage_outputs"])' < $CONFIG_PATH)
        COVERAGE_DIR="$(realpath "$COVERAGE_DIR")"
        log_file="/tmp/xen-necofuzz.log"
        rm $log_file -f
        sudo xencov reset
        make xen-necofuzz/xen_image.img XEN=1
        sudo xl create xen-necofuzz/xen-necofuzz.cfg -c > $log_file 2>&1 &

        monitor_fuzzing $log_file

        sudo xl destroy necofuzz

        XEN_DIR=$(python3 -c 'import yaml,sys;print(yaml.safe_load(sys.stdin)["directories"]["xen_dir"])' < $CONFIG_PATH)
        XEN_DIR="$(realpath "$XEN_DIR")"

        sudo xencov read > $COVERAGE_FILE

        cd /
        xencov_split $COVERAGE_FILE > /dev/null

        rm $JSON_COVERAGE_FILE -f
        touch $JSON_COVERAGE_FILE
        cd $XEN_DIR/xen

        for gcda_file in "${GCDA_FILES[@]}"; do
            if [ -f "$gcda_file" ]; then
                # Output JSON to stdout (avoid writing .gcov.json.gz files)
                gcov-11 --json-format --stdout "$gcda_file" >> "$JSON_COVERAGE_FILE"
            else
                echo "Warning: $gcda_file not found" >&2
            fi
        done

        for target_file in "${TARGET_FILES[@]}"; do
            echo -n "$(basename "$target_file"): "

            # instrumented_line: all line numbers instrumented in this file
            # final_nested_coverage: line numbers with count > 0 (executed lines)
            # Multiple gcda files may overlap, so use uniq/sort
            mapfile -t all_lines < <(
                jq -r -s --arg f "$target_file" '
                map(.files[]?)                         # Flatten files from all JSON objects
                | map(select(.file == $f))             # Only keep the matching file
                | .[] | .lines[]?                      # Iterate over line entries
                | .line_number                         # Extract line numbers
                ' "$JSON_COVERAGE_FILE" | sort -n -u
            )

            mapfile -t covered_lines < <(
                jq -r -s --arg f "$target_file" '
                map(.files[]?)
                | map(select(.file == $f))
                | .[] | .lines[]?
                | select(.count > 0)                   # Executed lines only
                | .line_number
                ' "$JSON_COVERAGE_FILE" | sort -n -u
            )

            mapfile -t covered_line_count < <(
            jq -r -s --arg f "$target_file" '
                .[]? | .files[]? | select(.file == $f) | .lines[]? | select(.count > 0)
                | "\(.line_number):\(.count)"
            ' "$JSON_COVERAGE_FILE" | sort -t: -k1,1n
            )

            # Write output files (overwrite each time)
            printf "%s\n" "${all_lines[@]}"     >  "$COVERAGE_DIR/instrumented_line"
            printf "%s\n" "${covered_line_count[@]}"     >  "/tmp/xen_current_line_count"

            if [[ -f "$COVERAGE_DIR/final_nested_coverage" ]]; then
                prev_nested_count=$(wc -l < "$COVERAGE_DIR/final_nested_coverage")
            else
                prev_nested_count=0
            fi

            printf "%s\n" "${covered_lines[@]}" >> "$COVERAGE_DIR/final_nested_coverage"
            sort -n -u -o "$COVERAGE_DIR/final_nested_coverage" "$COVERAGE_DIR/final_nested_coverage"

            if [[ -f "$COVERAGE_DIR/final_nested_coverage" ]]; then
                nested_count=$(wc -l < "$COVERAGE_DIR/final_nested_coverage")
            else
                nested_count=0
            fi

            my_timestamp=$(date +%Y%m%d_%H%M%S)
            if (( nested_count > prev_nested_count )); then
                cp "$COVERAGE_DIR/final_nested_coverage" "$COVERAGE_DIR/cover_$my_timestamp.txt"
                log "Found $nested_count in cover_$my_timestamp.txt"
                csv_timestamp=$(date '+%Y-%m-%d %H:%M:%S')
                csv_file="$COVERAGE_DIR/coverage_timeline.csv"
                if [[ ! -f "$csv_file" ]]; then
                    echo "timestamp,nested_count" > "$csv_file"
                fi
                echo "$csv_timestamp,$nested_count" >> "$csv_file"
            fi

        done
    fi
elif [ "$1" = "vmware" ]; then
    if [ "$2" = "start" ]; then
        log_file="vmware-necofuzz/vmware-necofuzz.log"
        rm -f $log_file
        touch $log_file
        make vmware-necofuzz/vmware-necofuzz.vmdk
        vmrun start vmware-necofuzz/vmware-necofuzz.vmx nogui &
        monitor_fuzzing $log_file
        vmrun stop vmware-necofuzz/vmware-necofuzz.vmx || true
    fi
elif [ "$1" = "vbox" ]; then
    if [ "$2" = "start" ]; then
        log_file="vbox-necofuzz/vbox-necofuzz.log"
        rm -f $log_file
        make vbox-necofuzz/vbox-necofuzz.vbox vbox-necofuzz/vbox_image.vdi
        VBoxManage startvm vbox-necofuzz --type headless
        monitor_fuzzing $log_file
        VBoxManage controlvm vbox-necofuzz poweroff
    fi
fi

# stty `cat /tmp/stty_settings`
