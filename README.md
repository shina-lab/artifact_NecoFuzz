# NecoFuzz: Effective Fuzzing of Nested Virtualization via Fuzz-Harness Virtual Machines

NecoFuzz is a gray-box fuzzer specifically designed for testing nested virtualization functionality in hypervisors. This artifact enables reproduction of the experimental results presented in our paper.

## Hardware Requirements

- **CPU**: Intel processor with VT-x support OR AMD processor with AMD-V support
- **Platform**: Bare metal machine (nested virtualization in VMs is not supported)
- **BIOS/UEFI**: Virtualization features must be enabled in firmware settings

## Software Dependencies
- Install build essentials for Linux kernel, AFL++, Xen, and QEMU
```bash
sudo apt update
sudo apt install -y gcc-11 g++-11 gcov-11 build-essential git debootstrap pkg-config automake bison flex python3 python3-pip qemu-system-x86 qemu-kvm


# Check installed versions
gcc-11 --version
g++-11 --version
gcov-11 --version

# If gcc is not using version 11, switch using update-alternatives
if ! gcc --version | grep -q "11."; then
    sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-11 110
    sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-11 110
    sudo update-alternatives --config gcc
    sudo update-alternatives --config g++
fi
```

## Setup Instructions

### 1. Initial Setup
```bash
git clone https://github.com/shina-lab/artifact_NecoFuzz
cd artifact_NecoFuzz
git submodule update --init --depth 1 --jobs 4 --progress
```

### 2. KVM Setup
```bash
./scripts/build_linux
# Configure GRUB to boot the newly built Linux kernel
sudo grub-reboot <kernel-entry>
sudo reboot
# Verify the kernel version after reboot
uname -r
```

### 3. AFL++ Setup
```bash
cd external/AFLplusplus
make
cd ../..
```

### 4. QEMU Setup
```bash
cd external/qemu
patch -p1 < ../../patches/necofuzz_qemu.patch

# Follow standard QEMU build process
mkdir build
cd build/
../configure --target-list=x86_64-softmmu --extra-ldflags=-lelf
make -j $(nproc)
cd ../../../
```

## Major Claims
### **C1. Main Effectiveness:**
NecoFuzz achieves significantly higher nested virtualization code coverage compared to existing testing approaches (selftests, kvm-unit-tests, syzkaller). Proven by experiments E1-E5 (Figure 3, Table 2).

### **C2. Architecture Validity:**
Each component of NecoFuzz's VM generator makes meaningful contributions to coverage improvement, with the VM state validator having the largest impact. Validates our system design and is proven by experiment E6 (Figure 4, Table 3).

### **C3. Generalizability:**
NecoFuzz successfully operates on multiple hypervisors (KVM and Xen) and outperforms existing testing approaches on both platforms. Demonstrates broad applicability across different virtualization platforms, proven by experiments E7 (Xen, Table 4).


## Running Experiments

These experiments are designed to evaluate the effectiveness of NecoFuzz, a novel fuzzer for hypervisor nested virtualization. We measure its code coverage on KVM and Xen and compare it against state-of-the-art fuzzers and developer-written tests to demonstrate its superiority.

### E1. NecoFuzz KVM Coverage [30 human-minutes + 48 compute-hours]
**Objective:** Measure the code coverage achieved by NecoFuzz when fuzzing KVM nested virtualization over an extended period.

**Preparation:**
1. Prepare your environment:
```bash
cp config/kvm_default.yaml
make prepare
make -C tools
```

**Execution:**
Run NecoFuzz with coverage monitoring for 48 hours.
```bash
# Terminal 1: Run the fuzzer
./tools/scripts/afl-runner.sh -o out/kvm_necofuzz
# Terminal 2: Monitor coverage
./tools/scripts/monitor_record.sh
```
**Note:** The fuzzer runs indefinitely. Manually stop the process in Terminal 1 with `Ctrl-C` after 48 hours.

**Expected Results:** Coverage data and a timeline showing NecoFuzz's progression. Coverage is expected to increase rapidly and then plateau around the 12-24 hour mark, while still achieving a higher final coverage than the baselines.

---

### E2. Syzkaller Baseline [45 human-minutes + 48 compute-hours]
**Objective:** Establish a performance baseline by measuring the coverage achieved by Syzkaller, a state-of-the-art, general-purpose kernel fuzzer.

**Preparation:**
```bash
./scripts/build_syzkaller_linux.sh
./scripts/setup_syzkaller.sh
./scripts/test_syzkaller.sh
```

**Execution:**
Run Syzkaller for 48 hours to ensure a fair comparison with NecoFuzz.
```bash
./scripts/run_syzkaller.sh out/syzkaller
# Coverage timeline will be generated in out/syzkaller/coverage_timeline.csv
```
**Note:** This script is configured for a long-duration run. Manually stop it with `Ctrl-C` after 48 hours.

**Expected Results:** A coverage timeline for Syzkaller, which is expected to show slower progression and a lower final coverage compared to NecoFuzz.

---

### E3. KVM Selftests Baseline [15 human-minutes + 30 compute-minutes]
**Objective:** Measure the coverage of the official KVM developer test suite (selftests) to serve as a baseline.

**Execution:**
```bash
patch -p1 -d external/linux < patches/linux_selftests.patch
./scripts/run_kvm_selftests.sh out/kvm_selftests run
# Results will be in out/kvm_selftests/final_nested_coverage
```

**Expected Results:** Coverage data for Table 2. These developer-written tests are expected to show limited coverage of complex nested virtualization code paths.

---

### E4. KVM Unit Tests Baseline [10 human-minutes + 20 compute-minutes]
**Objective:** Measure coverage achieved by kvm-unit-tests, another developer-centric test suite, for a comprehensive baseline comparison.

**Execution:**
```bash
./scripts/run_kvm-unit-tests.sh out/kvm_unit-tests
# Results will be in out/kvm_unit-tests/final_nested_coverage
```

**Expected Results:** Coverage data for Table 2, which is expected to demonstrate the limited scope of existing unit tests for nested virtualization.

---

### E5. Results Analysis [15 human-minutes]
**Objective:** Consolidate the results from E1-E4 to generate the final comparison figures and tables.

**Execution:**
```bash
./scripts/generate_kvm_coverage_analysis.sh
# Results will be generated in artifact/fig3.png and artifact/table2.csv
```

**Expected Results:**
- **Figure 3:** A coverage-over-time graph comparing NecoFuzz and Syzkaller, visually demonstrating that NecoFuzz achieves higher coverage faster.
- **Table 2:** A table with the final coverage numbers, quantitatively showing NecoFuzz's 1.4-2x improvement over all baseline methods.

---

### E6. Component Contribution Analysis (Ablation Study) [45 human-minutes + 120 compute-hours]
**Objective:** Perform an ablation study to measure the individual contribution of each core NecoFuzz component by selectively disabling them.

**Preparation:**
For each run, copy the corresponding configuration file to `config.yaml`. The variants are: with all components (from E1), without the VM execution harness, without the VM state validator, without the vCPU configurator, and without any components (baseline fuzzer).

**Execution:**
Run each of the four configurations below for 24 hours.

1. **Without ALL components (baseline):**
```bash
# Terminal 1: Run the fuzzer
cp config/wo_all.yaml config.yaml
./tools/scripts/afl-runner.sh -o out/kvm_necofuzz_wo_all

# Terminal 2: Monitor coverage
./tools/scripts/monitor_record.sh
```

2. **Without VM execution harness:**
```bash
# Terminal 1: Run the fuzzer
cp config/wo_harness.yaml config.yaml
./tools/scripts/afl-runner.sh -o out/kvm_necofuzz_wo_harness

# Terminal 2: Monitor coverage
./tools/scripts/monitor_record.sh
```

3. **Without vCPU configurator:**
```bash
# Terminal 1: Run the fuzzer
cp config/wo_vcpu_config.yaml config.yaml
./tools/scripts/afl-runner.sh -o out/kvm_necofuzz_wo_vcpu_config
# Terminal 2: Monitor coverage
./tools/scripts/monitor_record.sh
```

4. **Without VM state validator:**
```bash
# Terminal 1: Run the fuzzer
cp config/wo_vmstate_validator.yaml config.yaml
./tools/scripts/afl-runner.sh -o out/kvm_necofuzz_wo_vmstate_validator
# Terminal 2: Monitor coverage
./tools/scripts/monitor_record.sh
```
**Note:** Each `afl-runner.sh` command runs indefinitely. Monitor the time and manually stop each process with `Ctrl-C` after 24 hours. A coverage monitor can be run in a separate terminal for each experiment.

5. **Generate Analysis:**
```bash
./scripts/generate_kvm_coverage_analysis.sh
# Results will be generated in artifact/fig4.png and artifact/table3.csv
```

**Expected Results:**
- **Figure 4:** A set of coverage-over-time graphs showing that the full version of NecoFuzz outperforms all variants, with the VM state validator having the largest positive impact on coverage.
- **Table 3:** A table of final coverage numbers demonstrating that all components contribute meaningfully.

---

### E7. Xen Coverage [30 human-minutes + 24 compute-hours]
**Objective:** Demonstrate the generalizability of the NecoFuzz approach by applying it to the Xen hypervisor.

**Preparation - Xen Setup:**
```bash
./scripts/build_xen
sudo update-grub
# Configure GRUB to boot the Xen entry (e.g., 'Ubuntu, with Xen hypervisor')
sudo grub-reboot <xen-entry-name>
sudo reboot
# After reboot, enable Xen services
sudo update-rc.d xencommons defaults 19 18
sudo update-rc.d xendomains defaults 21 20
echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/xen.conf
sudo ldconfig
# Verify the Xen version to confirm setup
sudo xl info
```

**Execution:**

1. **NecoFuzz on Xen (24 hours):**
```bash
# Modify config.yaml to target Xen
./tools/scripts/afl-runner.sh -o out/xen_necofuzz
```
**Note:** For this NecoFuzz experiment, monitor the runtime and stop the process with `Ctrl-C` after exactly 24 hours.

2. **XTF Baseline (Xen Test Framework):**
```bash
./scripts/run_xtf.sh out/xen_xtf
# This typically completes in under 1 hour
```

3. **Generate Analysis:**
```bash
./scripts/generate_xen_coverage_analysis.sh
# Results will be in artifact/table4.csv
```

**Expected Results:**
- **Table 4:** A final coverage comparison showing NecoFuzz is also highly effective on Xen's nested virtualization code, outperforming the native XTF baseline. This demonstrates the cross-hypervisor applicability of the NecoFuzz approach.