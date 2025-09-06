#!/bin/bash
CONFIG_PATH="./config.yaml"  # default path

XEN_COV_FILE="/tmp/tmp.gcov"
KVM_COV_FILE="/dev/shm/kvm_coverage"
KVM_ARCH_COV_FILE="/dev/shm/kvm_arch_coverage"

cpu_vendor=$(grep -m1 vendor_id /proc/cpuinfo | awk -F ":" '{print $2}' | tr -d ' ')

if [ "$cpu_vendor" = "GenuineIntel" ]; then
    arch="intel"
    TARGET_FILES=("arch/x86/hvm/vmx/vvmx.c")
elif [ "$cpu_vendor" = "AuthenticAMD" ]; then
    arch="amd"
    TARGET_FILES=("arch/x86/hvm/svm/nestedsvm.c")
else
    echo "Unknown CPU vendor"
    exit 1
fi

GCDA_FILES=(
    "arch/x86/hvm/vmx/vvmx.gcda"
    "arch/x86/hvm/vmx/vmx.gcda"
    "arch/x86/hvm/svm/svm.gcda"
    "arch/x86/hvm/svm/nestedsvm.gcda"
)

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
        cp $XEN_COV_FILE $COVERAGE_DIR/gcov_$file_name
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
        $XEN_DIR="$(realpath "$XEN_DIR")"
        OUTPUT_DIR=$(python3 -c 'import yaml,sys;print(yaml.safe_load(sys.stdin)["directories"]["coverage_outputs"])' < $CONFIG_PATH)
        $OUTPUT_DIR="$(realpath "$OUTPUT_DIR")"
        sudo xencov read > /dev/null
        xencov_split /tmp/xencov > /dev/null
        rm $XEN_COV_FILE -f
        touch $XEN_COV_FILE
        cd $XEN_DIR/xen
        find . -name "*.gcda" -type f | while read -r gcda_file; do
            if [ -f "$gcda_file" ]; then
                gcov-11 -t "$gcda_file" >> "$XEN_COV_FILE"
            else
                echo "Warning: $gcda_file not found" >&2
            fi
        done

        for i in "${!TARGET_FILES[@]}"; do
            target_file="${TARGET_FILES[$i]}"
            echo -n "$(basename "$target_file"): "

            extracted=$(awk -v file="$target_file" '
            BEGIN { print_data=0 }
            $0 ~ "  -:    0:Source:" && print_data { exit }
            $0 ~ "Source:"file { print_data=1 }
            print_data { print }
            ' "$XEN_COV_FILE" | grep -v "\-:" | cut -d ":" -f 2-)

            echo "$extracted"  > "$OUTPUT_DIR/instrumented_line"

            extracted=$(awk -v file="$target_file" '
            BEGIN { print_data=0 }
            $0 ~ "  -:    0:Source:" && print_data { exit }
            $0 ~ "Source:"file { print_data=1 }
            print_data { print }
            ' "$XEN_COV_FILE" | grep -v "\-:" | grep -v "#####" | cut -d ":" -f 2-)

            echo "$extracted"  > "$OUTPUT_DIR/final_nested_coverage"

            if [[ -f "$OUTPUT_DIR/final_nested_coverage" ]]; then
                nested_count=$(wc -l < "$OUTPUT_DIR/final_nested_coverage")
            else
                nested_count=0
            fi
            local my_timestamp
            my_timestamp=$(date '+%Y-%m-%d %H:%M:%S')
            local csv_file="$OUTPUT_DIR/coverage_timeline.csv"
            if [[ ! -f "$csv_file" ]]; then
                echo "timestamp,nested_count" > "$csv_file"
            fi
            echo "$my_timestamp,$nested_count" >> "$csv_file"

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
