#include "kvm_flags.h"
#include <string.h>
#include <sys/stat.h>
char* kvm_intel_paramater[] = {
    "allow_smaller_maxphyaddr",
    "emulate_invalid_guest_state",
    "enable_apicv",
    "enable_ipiv",
    "enable_shadow_vmcs",
    "enlightened_vmcs",
    "ept",
    "eptad",
    "error_on_inconsistent_vmcs_config",
    // "nested",
    "nested_early_check",
    "unrestricted_guest",
    "fasteoi",
    "flexpriority",
    "vnmi",
    "vpid",
    "dump_invalid_vmcs",
    "sgx",
    "pml",
    "preemption_timer",
};
char* low_probability_flags[] = {
    "enlightened_vmcs",
    "nested_early_check"
};
char* kvm_amd_paramater[] = {
    "force_avic",
    "sev_es",
    "vls",
    "tsc_scaling",
    "nrips",
    "npt",
    "sev",
    "vgif",
    "lbrv",
    // "nested",
    "dump_invalid_vmcb",
    "intercept_smi",
    "avic",
};

char* qemu_intel_cpu_flags[] = {
    "hv-passthrough",
    // "hv-vapic=on,hv-evmcs=on,hv-emsr-bitmap=on,hv-enforce-cpuid=on,hv-passthrough=on,hypervisor=off,+x2apic,vmx=on,umip=off,hv_relaxed=on,hv_vpindex=on,hv_time=on"
    // ,"hv-vpindex,hv-synic,hv-tlbflush,hv-ipi,hv-stimer-direct,hv-time,hv-stimer"
    // ,"hv-vapic=on"
    // ,"hv-evmcs=on"
    // ,"hv-emsr-bitmap=on"
    // ,"hv-reset","hv-frequencies,hv-reenlightenment"
    // ,"hv-runtime","hv-crash"
    // ,"hv-avic","hv-relaxed"
    // ,"vmx-vmfunc"
    // ,"hv-passthrough"
    // ,"hv-enforce-cpuid"
    "3dnow", "3dnowext", "3dnowprefetch", "abm", "ace2", "ace2-en", "acpi",
    "adx", "aes", "amd-no-ssb", "amd-ssbd", "amd-stibp", "amx-bf16", "amx-int8",
    "amx-tile", "apic", "arat", "arch-capabilities", "arch-lbr", "avic", "avx",
    "avx-vnni", "avx2", "avx512-4fmaps", "avx512-4vnniw", "avx512-bf16",
    "avx512-fp16", "avx512-vp2intersect", "avx512-vpopcntdq", "avx512bitalg",
    "avx512bw", "avx512cd", "avx512dq", "avx512er", "avx512f", "avx512ifma",
    "avx512pf", "avx512vbmi", "avx512vbmi2", "avx512vl", "avx512vnni", "bmi1",
    "bmi2", "bus-lock-detect", "cid", "cldemote", "clflush", "clflushopt",
    "clwb", "clzero", "cmov", "cmp-legacy", "core-capability", "cr8legacy",
    "cx16", "cx8", "dca", "de", "decodeassists", "ds", "ds-cpl", "dtes64",
    "erms", "est", "extapic", "f16c", "flushbyasid", "fma", "fma4", "fpu",
    "fsgsbase", "fsrm", "full-width-write", "fxsr", "fxsr-opt", "gfni", "hle",
    "ht", "hypervisor", "ia64", "ibpb", "ibrs", "ibrs-all", "ibs", "intel-pt",
    "intel-pt-lip", "invpcid", "invtsc", "kvm-asyncpf", "kvm-asyncpf-int",
    "kvm-hint-dedicated", "kvm-mmu", "kvm-msi-ext-dest-id", "kvm-nopiodelay",
    "kvm-poll-control", "kvm-pv-eoi", "kvm-pv-ipi", "kvm-pv-sched-yield",
    "kvm-pv-tlb-flush", "kvm-pv-unhalt", "kvm-steal-time", "kvmclock",
    "kvmclock", "kvmclock-stable-bit", "la57", "lahf-lm",
    "lbrv"
    // ,"lm"
    ,
    "lwp", "mca", "mce", "md-clear", "mds-no", "misalignsse", "mmx", "mmxext",
    "monitor", "movbe", "movdir64b", "movdiri", "mpx", "msr", "mtrr",
    "nodeid-msr", "npt", "nrip-save", "nx",
    "osvw"
    // ,"pae"
    ,
    "pat", "pause-filter", "pbe", "pcid", "pclmulqdq", "pcommit", "pdcm",
    "pdpe1gb", "perfctr-core", "perfctr-nb", "pfthreshold", "pge", "phe",
    "phe-en", "pks", "pku", "pmm", "pmm-en", "pn", "pni", "popcnt",
    "pschange-mc-no", "pse", "pse36", "rdctl-no", "rdpid", "rdrand", "rdseed",
    "rdtscp", "rsba", "rtm", "sep", "serialize", "sgx", "sgx-debug",
    "sgx-exinfo", "sgx-kss", "sgx-mode64", "sgx-provisionkey", "sgx-tokenkey",
    "sgx1", "sgx2", "sgxlc", "sha-ni", "skinit", "skip-l1dfl-vmentry", "smap",
    "smep", "smx", "spec-ctrl", "split-lock-detect", "ss", "ssb-no", "ssbd",
    "sse", "sse2", "sse4.1", "sse4.2", "sse4a", "ssse3", "stibp", "svm",
    "svm-lock", "svme-addr-chk", "syscall", "taa-no", "tbm", "tce", "tm", "tm2",
    "topoext", "tsc", "tsc-adjust", "tsc-deadline", "tsc-scale", "tsx-ctrl",
    "tsx-ldtrk", "umip", "v-vmsave-vmload", "vaes", "vgif", "virt-ssbd",
    "vmcb-clean"
    // ,"vme"
    ,
    "vmx-activity-hlt", "vmx-activity-shutdown", "vmx-activity-wait-sipi",
    "vmx-apicv-register"
    // ,"vmx-apicv-vid"
    ,
    "vmx-apicv-x2apic", "vmx-apicv-xapic", "vmx-cr3-load-noexit",
    "vmx-cr3-store-noexit", "vmx-cr8-load-exit", "vmx-cr8-store-exit",
    "vmx-desc-exit",
    "vmx-encls-exit"
    // ,"vmx-entry-ia32e-mode=off,vmx-eptad"
    ,
    "vmx-entry-load-bndcfgs", "vmx-entry-load-efer", "vmx-entry-load-pat",
    "vmx-entry-load-perf-global-ctrl", "vmx-entry-load-pkrs",
    "vmx-entry-load-rtit-ctl",
    "vmx-entry-noload-debugctl"
    // ,"vmx-ept"
    ,
    "vmx-ept-1gb", "vmx-ept-2mb", "vmx-ept-advanced-exitinfo",
    "vmx-ept-execonly"
    // ,"vmx-eptad=off,vmx-entry-ia32e-mode"
    ,
    "vmx-eptp-switching"
    // ,"vmx-exit-ack-intr"
    ,
    "vmx-exit-clear-bndcfgs", "vmx-exit-clear-rtit-ctl", "vmx-exit-load-efer",
    "vmx-exit-load-pat", "vmx-exit-load-perf-global-ctrl", "vmx-exit-load-pkrs",
    "vmx-exit-nosave-debugctl", "vmx-exit-save-efer", "vmx-exit-save-pat",
    "vmx-exit-save-preemption-timer", "vmx-flexpriority", "vmx-hlt-exit",
    "vmx-ins-outs"
    // ,"vmx-intr-exit"
    // ,"vmx-invept"
    ,
    "vmx-invept-all-context", "vmx-invept-single-context",
    "vmx-invept-single-context", "vmx-invept-single-context-noglobals",
    "vmx-invlpg-exit",
    "vmx-invpcid-exit"
    // ,"vmx-invvpid"
    ,
    "vmx-invvpid-all-context", "vmx-invvpid-single-addr", "vmx-io-bitmap",
    "vmx-io-exit", "vmx-monitor-exit", "vmx-movdr-exit", "vmx-msr-bitmap",
    "vmx-mtf", "vmx-mwait-exit",
    "vmx-nmi-exit"
    // ,"vmx-page-walk-4"
    ,
    "vmx-page-walk-5", "vmx-pause-exit", "vmx-ple", "vmx-pml",
    "vmx-posted-intr"
    // ,"vmx-preemption-timer"
    ,
    "vmx-rdpmc-exit", "vmx-rdrand-exit", "vmx-rdseed-exit", "vmx-rdtsc-exit",
    "vmx-rdtscp-exit"
    // ,"vmx-secondary-ctls"
    ,
    "vmx-shadow-vmcs", "vmx-store-lma", "vmx-true-ctls", "vmx-tsc-offset",
    "vmx-tsc-scaling", "vmx-unrestricted-guest", "vmx-vintr-pending",
    "vmx-vmwrite-vmexit-fields", "vmx-vnmi",
    "vmx-vnmi-pending"
    // ,"vmx-vpid"
    ,
    "vmx-wbinvd-exit", "vmx-xsaves", "vmx-zero-len-inject", "vpclmulqdq",
    "waitpkg", "wbnoinvd", "wdt", "xcrypt", "xcrypt-en", "xfd", "xgetbv1",
    "xop", "xsave", "xsavec", "xsaveerptr", "xsaveopt", "xsaves", "xstore",
    "xstore-en", "xtpr", "vmx-vmfunc", "x2apic"};

char* qemu_amd_cpu_flags[] = {
    "hv-passthrough",
    // "hv-vapic=on,hv-evmcs=on,hv-emsr-bitmap=on,hv-enforce-cpuid=on,hv-passthrough=on,hypervisor=off,+x2apic,vmx=on,umip=off,hv_relaxed=on,hv_vpindex=on,hv_time=on"
    // ,"hv-vpindex,hv-synic,hv-tlbflush,hv-ipi,hv-stimer-direct,hv-time,hv-stimer"
    // ,"hv-vapic=on"
    // ,"hv-evmcs=on"
    // ,"hv-emsr-bitmap=on"
    // ,"hv-reset","hv-frequencies,hv-reenlightenment"
    // ,"hv-runtime","hv-crash"
    // ,"hv-avic","hv-relaxed"
    // ,"vmx-vmfunc"
    // ,"hv-passthrough"
    // ,"hv-enforce-cpuid"
    "3dnow", "3dnowext", "3dnowprefetch", "abm", "ace2", "ace2-en", "acpi",
    "adx", "aes", "amd-no-ssb", "amd-ssbd", "amd-stibp", "amx-bf16", "amx-int8",
    "amx-tile", "apic", "arat", "arch-capabilities", "arch-lbr", "avic", "avx",
    "avx-vnni", "avx2", "avx512-4fmaps", "avx512-4vnniw", "avx512-bf16",
    "avx512-fp16", "avx512-vp2intersect", "avx512-vpopcntdq", "avx512bitalg",
    "avx512bw", "avx512cd", "avx512dq", "avx512er", "avx512f", "avx512ifma",
    "avx512pf", "avx512vbmi", "avx512vbmi2", "avx512vl", "avx512vnni", "bmi1",
    "bmi2", "bus-lock-detect", "cid", "cldemote", "clflush", "clflushopt",
    "clwb", "clzero", "cmov", "cmp-legacy", "core-capability", "cr8legacy",
    "cx16", "cx8", "dca", "de", "decodeassists", "ds", "ds-cpl", "dtes64",
    "erms", "est", "extapic", "f16c", "flushbyasid", "fma", "fma4", "fpu",
    "fsgsbase", "fsrm", "full-width-write", "fxsr", "fxsr-opt", "gfni", "hle",
    "ht", "hypervisor", "ia64", "ibpb", "ibrs", "ibrs-all", "ibs", "intel-pt",
    "intel-pt-lip", "invpcid", "invtsc", "kvm-asyncpf", "kvm-asyncpf-int",
    "kvm-hint-dedicated", "kvm-mmu", "kvm-msi-ext-dest-id", "kvm-nopiodelay",
    "kvm-poll-control", "kvm-pv-eoi", "kvm-pv-ipi", "kvm-pv-sched-yield",
    "kvm-pv-tlb-flush", "kvm-pv-unhalt", "kvm-steal-time", "kvmclock",
    "kvmclock", "kvmclock-stable-bit", "la57", "lahf-lm", "lbrv",
    // "lm",
    "lwp", "mca", "mce", "md-clear", "mds-no", "misalignsse", "mmx", "mmxext",
    "monitor", "movbe", "movdir64b", "movdiri", "mpx", "msr", "mtrr",
    "nodeid-msr", "npt", "nrip-save", "nx", "osvw", "pae", "pat",
    "pause-filter", "pbe", "pcid", "pclmulqdq", "pcommit", "pdcm", "pdpe1gb",
    "perfctr-core", "perfctr-nb", "pfthreshold", "pge", "phe", "phe-en", "pks",
    "pku", "pmm", "pmm-en", "pn", "pni", "popcnt", "pschange-mc-no", "pse",
    "pse36", "rdctl-no", "rdpid", "rdrand", "rdseed", "rdtscp", "rsba", "rtm",
    "sep", "serialize", "sgx", "sgx-debug", "sgx-exinfo", "sgx-kss",
    "sgx-mode64", "sgx-provisionkey", "sgx-tokenkey", "sgx1", "sgx2", "sgxlc",
    "sha-ni", "skinit", "skip-l1dfl-vmentry", "smap", "smep", "smx",
    "spec-ctrl", "split-lock-detect", "ss", "ssb-no", "ssbd", "sse", "sse2",
    "sse4.1", "sse4.2", "sse4a", "ssse3", "stibp", "svm", "svm-lock",
    "svme-addr-chk", "syscall", "taa-no", "tbm", "tce", "tm", "tm2", "topoext",
    "tsc", "tsc-adjust", "tsc-deadline", "tsc-scale", "tsx-ctrl", "tsx-ldtrk",
    "umip", "v-vmsave-vmload", "vaes", "vgif", "virt-ssbd", "vmcb-clean", "vme",
    "vpclmulqdq", "waitpkg", "wbnoinvd", "wdt", "x2apic", "xcrypt", "xcrypt-en",
    "xfd", "xgetbv1", "xop", "xsave", "xsavec", "xsaveerptr", "xsaveopt",
    "xsaves", "xstore", "xstore-en", "xtpr"};

void setup_qemu_cpu_flags(char* cpu_flags, int size) {
#ifdef VCPU_CONFIG
  char** param_flags;
  int flags_size;
  char tmp[512];
  if (vendor_id == INTEL) {
    param_flags = qemu_intel_cpu_flags;
    flags_size = sizeof(qemu_intel_cpu_flags) / sizeof(qemu_intel_cpu_flags[0]);
  } else if (vendor_id == AMD) {
    param_flags = qemu_amd_cpu_flags;
    flags_size = sizeof(qemu_amd_cpu_flags) / sizeof(qemu_amd_cpu_flags[0]);
  }
  if (yaml_config->vcpu_config) {
    for (int i = 0; i < 20; i += 1) {
      char* flag_value = (input_buf[(INPUT_SIZE - 1) - i] % 2) ? "=on" : "=off";
      snprintf(tmp, size, "%s,%s%s", cpu_flags,
               param_flags[input_buf[(INPUT_SIZE - 1) - i - 1] % flags_size],
               flag_value);
      strncpy(cpu_flags, tmp, size - 1);
      cpu_flags[size - 1] = '\0';
    }
  }
#endif
}

void setup_kvm_paramater(char* kvm_param, int size) {
#ifdef VCPU_CONFIG
  char** param_flags;
  int flags_size;
  char tmp[512];
  const char* flag_value;
  if (vendor_id == INTEL) {
    param_flags = kvm_intel_paramater;
    flags_size = sizeof(kvm_intel_paramater) / sizeof(kvm_intel_paramater[0]);
  } else if (vendor_id == AMD) {
    param_flags = kvm_amd_paramater;
    flags_size = sizeof(kvm_amd_paramater) / sizeof(kvm_amd_paramater[0]);
  }
  if (yaml_config->vcpu_config) {
    for (int i = 0; i < flags_size; i++) {
      int is_low_prob_flag = 0;
      for (int j = 0; j < sizeof(low_probability_flags) / sizeof(low_probability_flags[0]); j++) {
        if (strcmp(param_flags[i], low_probability_flags[j]) == 0) {
          is_low_prob_flag = 1;
          break;
        }
      }
      if (is_low_prob_flag) {
        // 1/100
        flag_value = (input_buf[(INPUT_SIZE - 1) - i] % 100 == 0) ? "=1" : "=0";
      } else {
        // 1/2
        flag_value = (input_buf[(INPUT_SIZE - 1) - i] % 2) ? "=1" : "=0";
      }

      snprintf(tmp, size, "%s %s%s", kvm_param, param_flags[i], flag_value);
      strncpy(kvm_param, tmp, size - 1);
      kvm_param[size - 1] = '\0';
    }
  }
#endif
}