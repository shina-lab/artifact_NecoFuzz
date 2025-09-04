#include "fuzz.h"

// extern char vmxon_region[4096] __attribute__((aligned(4096)));

FuncTableEntry fuzz_l1_table[] = {
    {fuzz_cpuid, L"fuzz_cpuid"},
    {fuzz_hlt, L"fuzz_hlt"},
    {fuzz_invd, L"fuzz_invd"},
    {fuzz_invlpg, L"fuzz_invlpg"},
    {fuzz_rdpmc, L"fuzz_rdpmc"},
    {fuzz_rdtsc, L"fuzz_rdtsc"},
    {fuzz_rsm, L"fuzz_rsm"},
    {fuzz_vmclear, L"fuzz_vmclear"},
    {fuzz_vmlaunch, L"fuzz_vmlaunch"},
    {fuzz_vmptrld, L"fuzz_vmptrld"},
    {fuzz_l1_vmptrst, L"fuzz_l1_vmptrst"},
    {fuzz_l1_vmread, L"fuzz_l1_vmread"},
    {fuzz_vmresue, L"fuzz_vmresue"},
    {fuzz_vmxoff, L"fuzz_vmxoff"},
    {fuzz_vmxon, L"fuzz_vmxon"},
    {fuzz_cr, L"fuzz_cr"},
    {fuzz_dr, L"fuzz_dr"},
    {fuzz_io, L"fuzz_io"},
    {fuzz_rdmsr, L"fuzz_rdmsr"},
    {fuzz_wrmsr, L"fuzz_wrmsr"},
    {fuzz_mwait, L"fuzz_mwait"},
    {fuzz_monitor, L"fuzz_monitor"},
    {fuzz_pause, L"fuzz_pause"},
    {fuzz_invept, L"fuzz_invept"},
    {fuzz_rdtscp, L"fuzz_rdtscp"},
    {fuzz_invvpid, L"fuzz_invvpid"},
    {fuzz_wb, L"fuzz_wb"},
    {fuzz_xset, L"fuzz_xset"},
    {fuzz_rdrand, L"fuzz_rdrand"},
    {fuzz_invpcid, L"fuzz_invpcid"},
    {fuzz_vmfunc, L"fuzz_vmfunc"},
    {fuzz_encls, L"fuzz_encls"},
    {fuzz_rdseed, L"fuzz_rdseed"},
    {fuzz_pconfig, L"fuzz_pconfig"},
    {fuzz_l2_vmptrst, L"fuzz_l2_vmptrst"},
    {fuzz_l2_vmread, L"fuzz_l2_vmread"},
    {fuzz_l1_vmwrite, L"fuzz_l1_vmwrite"},
    {fuzz_l2_vmwrite, L"fuzz_l2_vmwrite"},
    {fuzz_page_table, L"fuzz_page_table"},
    {fuzz_msr_save_load, L"fuzz_msr_save_load"},
    {fuzz_apic, L"fuzz_apic"},
    {fuzz_dtr_tr, L"fuzz_dtr_tr"},
    {fuzz_gdt_idt, L"fuzz_gdt_idt"},
    {fuzz_evmcsptr, L"fuzz_evmcsptr"},
    {fuzz_nmi_exit, L"fuzz_nmi_exit"},
    {fuzz_msr_bitmap, L"fuzz_msr_bitmap"},
    {fuzz_tpr_shadow, L"fuzz_tpr_shadow"},
};

FuncTableEntry fuzz_l2_table[] = {
    {fuzz_cpuid, L"fuzz_cpuid"},
    {fuzz_hlt, L"fuzz_hlt"},
    {fuzz_invd, L"fuzz_invd"},
    {fuzz_invlpg, L"fuzz_invlpg"},
    {fuzz_rdpmc, L"fuzz_rdpmc"},
    {fuzz_rdtsc, L"fuzz_rdtsc"},
    {fuzz_rsm, L"fuzz_rsm"},
    {fuzz_vmclear, L"fuzz_vmclear"},
    {fuzz_vmlaunch, L"fuzz_vmlaunch"},
    {fuzz_vmptrld, L"fuzz_vmptrld"},
    {fuzz_l1_vmptrst, L"fuzz_l1_vmptrst"},
    {fuzz_l1_vmread, L"fuzz_l1_vmread"},
    {fuzz_vmresue, L"fuzz_vmresue"},
    {fuzz_vmxoff, L"fuzz_vmxoff"},
    {fuzz_vmxon, L"fuzz_vmxon"},
    {fuzz_cr, L"fuzz_cr"},
    {fuzz_dr, L"fuzz_dr"},
    {fuzz_io, L"fuzz_io"},
    {fuzz_rdmsr, L"fuzz_rdmsr"},
    {fuzz_wrmsr, L"fuzz_wrmsr"},
    {fuzz_mwait, L"fuzz_mwait"},
    {fuzz_monitor, L"fuzz_monitor"},
    {fuzz_pause, L"fuzz_pause"},
    {fuzz_invept, L"fuzz_invept"},
    {fuzz_rdtscp, L"fuzz_rdtscp"},
    {fuzz_invvpid, L"fuzz_invvpid"},
    {fuzz_wb, L"fuzz_wb"},
    {fuzz_xset, L"fuzz_xset"},
    {fuzz_rdrand, L"fuzz_rdrand"},
    {fuzz_invpcid, L"fuzz_invpcid"},
    {fuzz_vmfunc, L"fuzz_vmfunc"},
    {fuzz_encls, L"fuzz_encls"},
    {fuzz_rdseed, L"fuzz_rdseed"},
    {fuzz_pconfig, L"fuzz_pconfig"},
    {fuzz_l2_vmptrst, L"fuzz_l2_vmptrst"},
    {fuzz_l2_vmread, L"fuzz_l2_vmread"},
    {fuzz_l2_vmwrite, L"fuzz_l2_vmwrite"},
    {fuzz_page_table, L"fuzz_page_table"},
    {fuzz_msr_save_load, L"fuzz_msr_save_load"},
    {fuzz_apic, L"fuzz_apic"},
    {fuzz_dtr_tr, L"fuzz_dtr_tr"},
    {fuzz_gdt_idt, L"fuzz_gdt_idt"},
    {fuzz_nmi_exit, L"fuzz_nmi_exit"},
    {fuzz_vapic_access, L"fuzz_vapic_access"},
};

const size_t L1_TABLE_SIZE = sizeof(fuzz_l1_table) / sizeof(FuncTableEntry);
const size_t L2_TABLE_SIZE = sizeof(fuzz_l2_table) / sizeof(FuncTableEntry);
extern int vmcs_num;
extern uint16_t vmcs_index[];
void fuzz_cpuid() {
  if (get8b(index_selector_count++) % 3 == 0) {
    asm volatile("cpuid" ::"a"(get8b(index_selector_count++) % 0x21),
                 "c"(get8b(index_selector_count++) % 0x21)
                 : "ebx", "edx");
  }
  if (get8b(index_selector_count++) % 3 == 1) {
    asm volatile("cpuid" ::"a"(0x80000000 | get8b(index_selector_count++) % 0x9)
                 : "ebx", "edx");
  } else {
    asm volatile("cpuid" ::"a"(0x4fffffff & (get32b(index_selector_count++)))
                 : "ebx", "edx");
    index_selector_count += 4;
  }
}

void fuzz_hlt() {
  asm volatile("hlt");
}

void fuzz_invd() {
  asm volatile("invd");  // 13
}

void fuzz_invlpg() {
  uint64_t p;
  p = get64b(index_selector_count);
  index_selector_count += 8;
  asm volatile("invlpg %0" : : "m"(p));  // 14 vmexit o
}
void fuzz_rdpmc() {
  uint64_t p;
  p = get64b(index_selector_count);
  index_selector_count += 8;
  asm volatile("rdpmc" : "+c"(p) : : "%rax");  // 15 vmexit o sometimes hang
}
void fuzz_rdtsc() {
  asm volatile("rdtsc");  // 16
}
void fuzz_rsm() {
  asm volatile("rsm");  // 16
}
void fuzz_vmclear() {
  uintptr_t value;

  if (get8b(index_selector_count++) % 2) {
    int selector = get8b(index_selector_count++) % 3;
    switch (selector) {
      case 0:
        if (get8b(index_selector_count++) % 2) {
          value = (uintptr_t)current_evmcs -
                  ((get8b(index_selector_count++) % 3) - 1);
        } else {
          value =
              (uintptr_t)vp_assist - ((get8b(index_selector_count++) % 3) - 1);
        }
        break;
      case 1:
        value =
            (uintptr_t)vmxon_region - ((get8b(index_selector_count++) % 3) - 1);
        break;
      case 2:
        value = (uintptr_t)vmcs - ((get8b(index_selector_count++) % 3) - 1);
        break;
      default:
        break;
    }
  } else {
    value = (uintptr_t)get64b(index_selector_count);
    index_selector_count += 8;
  }
  asm volatile("vmclear %0" ::"m"(value));
}
void fuzz_vmlaunch() {
  asm volatile("vmlaunch\n\t");
}
void fuzz_l1_vmptrst() {
  uint64_t value;
  vmptrst(&value);
}
void fuzz_l2_vmptrst() {
  uint64_t value;
  asm volatile("vmptrst %0" : : "m"(value) : "cc");
}

void fuzz_vmptrld() {
  uint64_t value;

  if (get8b(index_selector_count++) % 2) {
    int selector = get8b(index_selector_count++) % 3;
    switch (selector) {
      case 0:
        value = (uintptr_t)current_evmcs -
                ((get8b(index_selector_count++) % 3) - 1);
        break;
      case 1:
        value =
            (uintptr_t)vmxon_region - ((get8b(index_selector_count++) % 3) - 1);
        break;
      case 2:
        value = (uintptr_t)vmcs - ((get8b(index_selector_count++) % 3) - 1);
        break;
      default:
        break;
    }
  } else {
    value = (uintptr_t)get64b(index_selector_count);
    index_selector_count += 8;
  }
  asm volatile("vmptrld %0" : : "m"(value) : "cc");
}

void fuzz_l1_vmread() {
  vmread(vmcs_index[get16b(index_selector_count) % vmcs_num]);
  index_selector_count += 2;
}
void fuzz_l1_vmwrite() {
  uint64_t value = get64b(index_selector_count);
  index_selector_count += 8;
  vmwrite(vmcs_index[get16b(index_selector_count) % vmcs_num], value);
  index_selector_count += 2;
}
void fuzz_l2_vmread() {
  if (get8b(index_selector_count++) % 2) {
    uint64_t* v = (uint64_t*)get64b(index_selector_count);
    index_selector_count += 8;
    asm volatile(
        "vmread %1, %0"
        : "=m"(v)
        : "a"((uint64_t)(vmcs_index[get16b(index_selector_count) % vmcs_num]))
        : "cc");
    index_selector_count += 2;
  } else {
    uint64_t value;
    asm volatile("vmread %%rax, %%rdx"
                 : "=d"(value)
                 : "a"(vmcs_index[get16b(index_selector_count) % vmcs_num])
                 : "cc");
    index_selector_count += 2;
  }
}
void fuzz_l2_vmwrite() {
  uint64_t value = get64b(index_selector_count);
  index_selector_count += 8;
  if (get8b(index_selector_count++) % 2) {
    uint64_t* v = (uint64_t*)value;
    asm volatile(
        "vmwrite %1, %0"
        :
        : "a"((uint64_t)(vmcs_index[get16b(index_selector_count) % vmcs_num])),
          "m"(v)
        : "cc");
    index_selector_count += 2;
  } else {
    asm volatile("vmwrite %%rdx, %%rax"
                 :
                 : "a"(vmcs_index[get16b(index_selector_count) % vmcs_num]),
                   "d"(value)
                 : "cc", "memory");
    index_selector_count += 2;
  }
}
void fuzz_vmxoff() {
  asm volatile("vmxoff");
}

void fuzz_vmxon() {
  uintptr_t value;

  if (get8b(index_selector_count++) % 2) {
    int selector = get8b(index_selector_count++) % 3;
    switch (selector) {
      case 0:
        value = (uintptr_t)current_evmcs -
                ((get8b(index_selector_count++) % 3) - 1);
        break;
      case 1:
        value =
            (uintptr_t)vmxon_region - ((get8b(index_selector_count++) % 3) - 1);
        break;
      case 2:
        value = (uintptr_t)vmcs - ((get8b(index_selector_count++) % 3) - 1);
        break;
      default:
        break;
    }
  } else {
    value = (uintptr_t)get64b(index_selector_count);
    index_selector_count += 8;
  }
  asm volatile("vmxon %0" ::"m"(value));
}
void fuzz_vmresue() {
  asm volatile("vmresume\n\t");
}

void fuzz_cr() {
  uint64_t value, zero;
  switch (get8b(index_selector_count++) % 4) {
    case 0:
      value = get64b(index_selector_count);
      index_selector_count += 8;
      switch (get8b(index_selector_count++) % 4) {
        case 0:
          asm volatile("movq %0, %%cr0" : : "c"(value) : "%rax");
        case 1:
          asm volatile("movq %0, %%cr3" : : "c"(value) : "%rax");
        case 2:
          asm volatile("movq %0, %%cr4" : : "c"(value) : "%rax");
        case 3:
          asm volatile("movq %0, %%cr8" : : "c"(value) : "%rax");
      }
      break;
    case 1:
      switch (get8b(index_selector_count++) % 4) {
        case 0:
          asm volatile("movq %%cr0, %0" : "=c"(zero) : : "%rbx");
        case 1:
          asm volatile("movq %%cr3, %0" : "=c"(zero) : : "%rbx");
        case 2:
          asm volatile("movq %%cr4, %0" : "=c"(zero) : : "%rbx");
        case 3:
          asm volatile("movq %%cr8, %0" : "=c"(zero) : : "%rbx");
      }
      break;
    case 2:
      asm volatile("clts");
      break;
    case 3:
      value = get16b(index_selector_count);
      index_selector_count += 2;
      asm volatile("lmsw %0" : : "m"(value));
      break;
  }
}

void fuzz_dr() {
  uint64_t zero;
  asm volatile("movq %%dr0, %0" : "=c"(zero) : : "%rbx");
  asm volatile("movq %%dr1, %0" : "=c"(zero) : : "%rbx");
  asm volatile("movq %%dr2, %0" : "=c"(zero) : : "%rbx");
  asm volatile("movq %%dr3, %0" : "=c"(zero) : : "%rbx");
  asm volatile("movq %%dr4, %0" : "=c"(zero) : : "%rbx");
  asm volatile("movq %%dr5, %0" : "=c"(zero) : : "%rbx");
  asm volatile("movq %%dr6, %0" : "=c"(zero) : : "%rbx");
  asm volatile("movq %%dr7, %0" : "=c"(zero) : : "%rbx");
  asm volatile("movq %0, %%dr0"
               : "+c"(get64b(index_selector_count))
               :
               : "%rax");
  index_selector_count += 8;
  asm volatile("movq %0, %%dr1"
               : "+c"(get64b(index_selector_count))
               :
               : "%rax");
  index_selector_count += 8;
  asm volatile("movq %0, %%dr2"
               : "+c"(get64b(index_selector_count))
               :
               : "%rax");
  index_selector_count += 8;
  asm volatile("movq %0, %%dr3"
               : "+c"(get64b(index_selector_count))
               :
               : "%rax");
  index_selector_count += 8;
  asm volatile("movq %0, %%dr4"
               : "+c"(get64b(index_selector_count))
               :
               : "%rax");
  index_selector_count += 8;
  asm volatile("movq %0, %%dr5"
               : "+c"(get64b(index_selector_count))
               :
               : "%rax");
  index_selector_count += 8;
  asm volatile("movq %0, %%dr6"
               : "+c"(get64b(index_selector_count))
               :
               : "%rax");
  index_selector_count += 8;
  asm volatile("movq %0, %%dr7"
               : "+c"(get64b(index_selector_count))
               :
               : "%rax");
  index_selector_count += 8;
}

void fuzz_io() {
  if (get8b(index_selector_count++) % 2) {
    asm volatile("mov %0, %%dx" ::"r"(get16b(index_selector_count)));
    index_selector_count += 2;
    asm volatile("mov %0, %%eax" ::"r"(get32b(index_selector_count)));
    asm volatile("out %eax, %dx");
    index_selector_count += 4;
  } else {
    asm volatile("mov %0, %%dx" ::"r"(get16b(index_selector_count)));
    index_selector_count += 2;
    asm volatile("in %dx, %eax");
  }
}

void fuzz_rdmsr() {
  uint32_t index = msr_table[get16b(index_selector_count) % MSR_TABLE_SIZE];
  index_selector_count += 2;
  if (get8b(index_selector_count++) % 2) {
    asm volatile("rdmsr" ::"c"(index));
  } else {
    index = get32b(index_selector_count);
    index_selector_count += 4;
    asm volatile("rdmsr" ::"c"(index));
  }
}
void fuzz_wrmsr() {
  uint32_t index = msr_table[get16b(index_selector_count) % MSR_TABLE_SIZE];
  index_selector_count += 2;
  uint64_t value = get64b(index_selector_count);
  index_selector_count += 8;

  if (get8b(index_selector_count++) % 2) {
    asm volatile("wrmsr" ::"c"(index), "a"(value & 0xFFFFFFFF),
                 "d"(value >> 32));
  } else {
    index = get32b(index_selector_count);
    index_selector_count += 4;
    asm volatile("wrmsr" ::"c"(index), "a"(value & 0xFFFFFFFF),
                 "d"(value >> 32));
    // asm volatile("wrmsr" ::"c"(0xC0000000 | (index & 0x1FFF)), "a"(value
    // & 0xFFFFFFFF), "d"(value >> 32));
  }
}
void fuzz_mwait() {
  asm volatile("mwait");  // 36
}
void fuzz_monitor() {
  asm volatile("monitor");  // 39
}
void fuzz_pause() {
  asm volatile("pause");  // 40
}
void fuzz_rdtscp() {
  asm volatile("rdtscp");  // 51 vmexit sometimes hang
}
void fuzz_invept() {
  int type = get8b(index_selector_count++) % 4;
  invept_t inv;
  inv.rsvd = 0;
  if (get8b(index_selector_count++) % 2) {
    inv.ptr = get64b(index_selector_count);
    index_selector_count += 8;
  } else {
    inv.ptr = eptp_list[get8b(index_selector_count++) % 5];
  }
  invept((uint64_t)type, &inv);
}
void fuzz_invvpid() {
  invvpid_t inv;
  inv.rsvd = 0;
  inv.gva = get64b(index_selector_count);
  index_selector_count += 8;
  inv.vpid = get16b(index_selector_count);
  index_selector_count += 2;
  int type = get8b(index_selector_count++) % 4;
  invvpid((uint64_t)type, &inv);
}

void fuzz_wb() {
  if (get8b(index_selector_count++) % 2) {
    asm volatile("wbnoinvd" :::);  // 54
  } else {
    asm volatile("wbinvd" :::);  // 54
  }
}

void fuzz_xset() {
  asm volatile("xsetbv" :::);  // 55 sometimes hang
}

void fuzz_rdrand() {
  uint64_t zero = 0;
  asm volatile("rdrand %0" : "+c"(zero) : : "%rax");  // 57
}
void fuzz_invpcid() {
  uint64_t pcid, addr, type;
  pcid = get64b(index_selector_count);
  index_selector_count += 8;
  addr = get64b(index_selector_count);
  index_selector_count += 8;
  type = get64b(index_selector_count);
  index_selector_count += 8;
  __invpcid(pcid, addr, type);  // 58 vmexit sometimes hang
}

void fuzz_vmfunc() {
  uint64_t value = get16b(index_selector_count) % 512;
  index_selector_count += 2;
  asm volatile("mov %0, %%rcx" ::"d"(value) :);
  asm volatile("mov 0, %eax");
  asm volatile("vmfunc" :::);
}

void fuzz_encls() {
  asm volatile("encls" :::);  // 60 vmexit sometimes hang
}

void fuzz_rdseed() {
  uint64_t zero = 0;
  asm volatile("rdseed %0" : "+c"(zero) : : "%rax");  // 61
}

void fuzz_pconfig() {
  asm volatile("pconfig");  // 65 vmexit sometimes hang
}
extern uint64_t msr_load[1024] __attribute__((aligned(4096)));
extern uint64_t msr_store[1024] __attribute__((aligned(4096)));
extern uint64_t vmentry_msr_load[1024] __attribute__((aligned(4096)));
void fuzz_msr_save_load() {
  int i = get16b(index_selector_count) % 512;
  index_selector_count += 2;
  int selector = get8b(index_selector_count++) % 3;
  uint32_t index = msr_table[get16b(index_selector_count) % MSR_TABLE_SIZE];
  index_selector_count += 2;
  uint64_t value = get64b(index_selector_count);
  index_selector_count += 8;
  switch (selector) {
    case 0:
      msr_store[i * 2] = index;
      msr_store[i * 2 + 1] = value;
      break;
    case 1:
      msr_load[i * 2] = index;
      msr_load[i * 2 + 1] = value;
      break;
    case 2:
      vmentry_msr_load[i * 2] = index;
      vmentry_msr_load[i * 2 + 1] = value;
      break;
    default:
      break;
  }
}

extern uint8_t msr_bitmap[4096] __attribute__((aligned(4096)));
void fuzz_msr_bitmap() {
  int i = get16b(index_selector_count) % 4096;
  index_selector_count += 2;
  uint64_t value = get8b(index_selector_count++);
  msr_bitmap[i] = value;
}

extern const uint64_t kPageSize4K;
extern const uint64_t kPageSize2M;
extern const uint64_t kPageSize1G;

extern uint64_t pml4_table[512] __attribute__((aligned(4096)));
extern uint64_t pdp_table[512] __attribute__((aligned(4096)));
extern uint64_t page_directory[512][512] __attribute__((aligned(4096)));
extern uint64_t pml4_table_2[512] __attribute__((aligned(4096)));
void fuzz_page_table() {
  uint8_t ept_xwr = get8b(index_selector_count++) & 0x7;
  uint16_t ept_mode = get16b(index_selector_count) & 0xff8;
  index_selector_count += 2;
  pml4_table[0] = (uint64_t)&pdp_table[0] | ept_mode | ept_xwr;
  pml4_table_2[0] = (uint64_t)&pdp_table[0] | ept_mode | ept_xwr;

  uint32_t i_pdpt = get16b(index_selector_count) % 512;
  index_selector_count += 2;
  uint32_t i_pd = get16b(index_selector_count) % 512;
  index_selector_count += 2;

  pdp_table[i_pdpt] = (uint64_t)&page_directory[i_pdpt] | ept_mode | ept_xwr;

  page_directory[i_pdpt][i_pd] =
      (i_pdpt * kPageSize1G + i_pd * kPageSize2M) | ept_mode | ept_xwr;
  // for (int i_pdpt = 0; i_pdpt < 512; ++i_pdpt)
  // {
  //     pdp_table[i_pdpt] = (uint64_t)&page_directory[i_pdpt] | ept_mode |
  //     ept_xwr; for (int i_pd = 0; i_pd < 512; ++i_pd)
  //     {
  //         page_directory[i_pdpt][i_pd] = (i_pdpt * kPageSize1G + i_pd *
  //         kPageSize2M) | ept_mode | 0;
  //     }
  // }
  // wprintf(L" ept 0x%x\n", ept_mode|ept_xwr);
}

uint32_t read_local_apic_id() {
  volatile uint32_t* local_apic_id = (uint32_t*)(apic_base + APIC_ID);
  uint32_t value = *local_apic_id;
  return value;
}

uint32_t read_local_apic_version() {
  volatile uint32_t* local_apic_version = (uint32_t*)(apic_base + APIC_VERSION);
  uint32_t value = *local_apic_version;
  return value;
}

void write_eoi() {
  volatile uint32_t* eoi_register = (uint32_t*)(apic_base + APIC_EOI);
  *eoi_register = 0;
}

void write_icr() {
  uint64_t value = get64b(index_selector_count);
  index_selector_count += 8;
  volatile uint32_t* icr_low = (uint32_t*)(apic_base + APIC_ICR_LOW);
  volatile uint32_t* icr_high = (uint32_t*)(apic_base + APIC_ICR_HIGH);
  *icr_high = value >> 32;
  *icr_low = value & 0xFFFFFFFF;
}

void read_icr() {
  volatile uint32_t* icr_low = (uint32_t*)(apic_base + APIC_ICR_LOW);
  volatile uint32_t* icr_high = (uint32_t*)(apic_base + APIC_ICR_HIGH);
  uint64_t value = ((uint64_t)(*icr_high) << 32) | *icr_low;
}

void fuzz_apic() {
  uint8_t command = get8b(index_selector_count++);

  switch (command % 5) {
    case 0:
      read_local_apic_id();
      break;
    case 1:
      read_local_apic_version();
      break;
    case 2:
      write_eoi();
      break;
    case 3:
      write_icr();
      break;
    case 4:
      read_icr();
      break;
  }
}

struct descriptor_table {
  uint16_t limit;
  uint64_t base;
} __attribute__((packed));

void fuzz_gdt_idt() {
  int selector = get8b(index_selector_count++) % 4;
  struct descriptor_table dtr;
  switch (selector) {
    case 0:
      asm volatile("sgdt %0" : "=m"(dtr) : : "memory");
      break;
    case 1:
      asm volatile("sidt %0" : "=m"(dtr) : : "memory");
      break;
    case 2:
      dtr.limit = get16b(index_selector_count);
      index_selector_count += 2;
      dtr.base = get64b(index_selector_count);
      index_selector_count += 8;
      asm volatile("lgdt %0" : : "m"(dtr));
      break;
    case 3:
      dtr.limit = get16b(index_selector_count);
      index_selector_count += 2;
      dtr.base = get64b(index_selector_count);
      index_selector_count += 8;
      asm volatile("lidt %0" : : "m"(dtr));
      break;
    default:
      break;
  }
}

void fuzz_dtr_tr() {
  int selector = get8b(index_selector_count++) % 4;
  uint16_t tr;
  switch (selector) {
    case 0:
      asm volatile("sldt %0" : "=m"(tr) : : "memory");
      break;
    case 1:
      asm volatile("str %0" : "=m"(tr) : : "memory");
      break;
    case 2:
      tr = get16b(index_selector_count);
      index_selector_count += 2;
      asm volatile("lldt %0" : : "m"(tr));
      break;
    case 3:
      tr = get16b(index_selector_count);
      index_selector_count += 2;
      asm volatile("ltr %0" : : "m"(tr));
      break;
    default:
      break;
  }
}

void fuzz_evmcsptr() {
  if (current_evmcs) {
    uint64_t value = get64b(index_selector_count);
    index_selector_count += 8;
    current_vp_assist->current_nested_vmcs = value;
  }
}

void fuzz_nmi_exit() {
  int selector = get8b(index_selector_count++) % 3;
  switch (selector) {
    case 0:
      asm volatile("int $1");
      break;
    case 1:
      asm volatile("int3");
      break;
    case 2:
      asm volatile("ud2");
      break;
    default:
      break;
  }
}

void fuzz_tpr_shadow() {
  uint32_t* vtpr = (uint32_t*)vmread(0x2012) + 0x80;
  uint16_t tpr_shadow = get8b(index_selector_count++);
  vtpr[0] = 0xffffff0f | (tpr_shadow << 4);
}

void fuzz_vapic_access() {
  uint16_t index = get16b(index_selector_count);
  index_selector_count += 2;
  uint8_t value = get8b(index_selector_count++);
  virtual_apic[index] = value;
}
