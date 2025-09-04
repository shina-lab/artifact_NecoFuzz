#include "fuzz.h"

FuncTableEntry exec_l1_table[] = {{exec_cpuid, L"exec_cpuid"},
                                  {exec_hlt, L"exec_hlt"},
                                  {exec_invd, L"exec_invd"},
                                  {exec_invlpg, L"exec_invlpg"},
                                  {exec_rdpmc, L"exec_rdpmc"},
                                  {exec_rdtsc, L"exec_rdtsc"},
                                  {exec_rsm, L"exec_rsm"},
                                  {exec_cr, L"exec_cr"},
                                  {exec_dr, L"exec_dr"},
                                  {exec_io, L"exec_io"},
                                  {exec_rdmsr, L"exec_rdmsr"},
                                  {exec_wrmsr, L"exec_wrmsr"},
                                  {exec_mwait, L"exec_mwait"},
                                  {exec_monitor, L"exec_monitor"},
                                  {exec_pause, L"exec_pause"},
                                  {exec_rdtscp, L"exec_rdtscp"},
                                  {exec_wb, L"exec_wb"},
                                  {exec_xset, L"exec_xset"},
                                  {exec_rdrand, L"exec_rdrand"},
                                  {exec_invpcid, L"exec_invpcid"},
                                  {exec_rdseed, L"exec_rdseed"},
                                  {exec_pconfig, L"exec_pconfig"},
                                  {exec_pushf, L"exec_pushf"},
                                  {exec_popf, L"exec_popf"},
                                  {exec_idtr_read, L"exec_idtr_read"},
                                  {exec_gdtr_read, L"exec_gdtr_read"},
                                  {exec_ldtr_read, L"exec_ldtr_read"},
                                  {exec_tr_read, L"exec_tr_read"},
                                  {exec_idtr_write, L"exec_idtr_write"},
                                  {exec_gdtr_write, L"exec_gdtr_write"},
                                  {exec_ldtr_write, L"exec_ldtr_write"},
                                  {exec_tr_write, L"exec_tr_write"},
                                  {exec_iret, L"exec_iret"},
                                  {exec_swint, L"exec_swint"},
                                  {exec_invlpga, L"exec_invlpga"},
                                  {exec_task_switch, L"exec_task_switch"},
                                  {exec_vmrun, L"exec_vmrun"},
                                  {exec_vmmcall, L"exec_vmmcall"},
                                  {exec_vmload, L"exec_vmload"},
                                  {exec_vmsave, L"exec_vmsave"},
                                  {exec_stgi, L"exec_stgi"},
                                  {exec_clgi, L"exec_clgi"},
                                  {exec_skinit, L"exec_skinit"},
                                  {exec_monitorx, L"exec_monitorx"},
                                  {exec_rdpru, L"exec_rdpru"},
                                  {exec_invlpgb, L"exec_invlpgb"},
                                  {exec_mcommit, L"exec_mcommit"},
                                  {exec_tlbsync, L"exec_tlbsync"},
                                  {exec_vmexit_vmgexit, L"exec_vmexit_vmgexit"},
                                  {exec_apic, L"exec_apic"}};

FuncTableEntry exec_l2_table[] = {{exec_cpuid, L"exec_cpuid"},
                                  {exec_hlt, L"exec_hlt"},
                                  {exec_invd, L"exec_invd"},
                                  {exec_invlpg, L"exec_invlpg"},
                                  {exec_rdpmc, L"exec_rdpmc"},
                                  {exec_rdtsc, L"exec_rdtsc"},
                                  {exec_rsm, L"exec_rsm"},
                                  {exec_cr, L"exec_cr"},
                                  {exec_dr, L"exec_dr"},
                                  {exec_io, L"exec_io"},
                                  {exec_rdmsr, L"exec_rdmsr"},
                                  {exec_wrmsr, L"exec_wrmsr"},
                                  {exec_mwait, L"exec_mwait"},
                                  {exec_monitor, L"exec_monitor"},
                                  {exec_pause, L"exec_pause"},
                                  {exec_rdtscp, L"exec_rdtscp"},
                                  {exec_wb, L"exec_wb"},
                                  {exec_xset, L"exec_xset"},
                                  {exec_rdrand, L"exec_rdrand"},
                                  {exec_invpcid, L"exec_invpcid"},
                                  {exec_rdseed, L"exec_rdseed"},
                                  {exec_pconfig, L"exec_pconfig"},
                                  {exec_pushf, L"exec_pushf"},
                                  {exec_popf, L"exec_popf"},
                                  {exec_idtr_read, L"exec_idtr_read"},
                                  {exec_gdtr_read, L"exec_gdtr_read"},
                                  {exec_ldtr_read, L"exec_ldtr_read"},
                                  {exec_tr_read, L"exec_tr_read"},
                                  {exec_idtr_write, L"exec_idtr_write"},
                                  {exec_gdtr_write, L"exec_gdtr_write"},
                                  {exec_ldtr_write, L"exec_ldtr_write"},
                                  {exec_tr_write, L"exec_tr_write"},
                                  {exec_iret, L"exec_iret"},
                                  {exec_swint, L"exec_swint"},
                                  {exec_invlpga, L"exec_invlpga"},
                                  {exec_task_switch, L"exec_task_switch"},
                                  {exec_vmrun, L"exec_vmrun"},
                                  {exec_vmmcall, L"exec_vmmcall"},
                                  {exec_vmload, L"exec_vmload"},
                                  {exec_vmsave, L"exec_vmsave"},
                                  {exec_stgi, L"exec_stgi"},
                                  {exec_clgi, L"exec_clgi"},
                                  {exec_skinit, L"exec_skinit"},
                                  {exec_monitorx, L"exec_monitorx"},
                                  {exec_rdpru, L"exec_rdpru"},
                                  {exec_invlpgb, L"exec_invlpgb"},
                                  {exec_mcommit, L"exec_mcommit"},
                                  {exec_tlbsync, L"exec_tlbsync"},
                                  {exec_vmexit_vmgexit, L"exec_vmexit_vmgexit"},
                                  {exec_apic, L"exec_apic"}};

const size_t L1_TABLE_SIZE = sizeof(exec_l1_table) / sizeof(FuncTableEntry);
const size_t L2_TABLE_SIZE = sizeof(exec_l2_table) / sizeof(FuncTableEntry);

void exec_cpuid() {
  if (input_buf[index_selector_count++] % 3 == 0) {
    asm volatile("cpuid" ::"a"(input_buf[index_selector_count++] % 0x21),
                 "c"(input_buf[index_selector_count++] % 0x21)
                 : "ebx", "edx");
  }
  if (input_buf[index_selector_count++] % 3 == 1) {
    asm volatile(
        "cpuid" ::"a"(0x80000000 | input_buf[index_selector_count++] % 0x9)
        : "ebx", "edx");
  } else {
    asm volatile(
        "cpuid" ::"a"(0x4fffffff & (input_buf[index_selector_count++] << 16 |
                                    input_buf[index_selector_count++]))
        : "ebx", "edx");
  }
}

void exec_hlt() {
  asm volatile("hlt");
}

void exec_invd() {
  asm volatile("invd");  // 13
}

void exec_invlpg() {
  uint64_t p;
  p = get64b(index_selector_count);
  index_selector_count += 8;
  asm volatile("invlpg %0" : : "m"(p));  // 14 vmexit o
}
void exec_rdpmc() {
  uint64_t p;
  p = get64b(index_selector_count);
  index_selector_count += 8;
  asm volatile("rdpmc" : "+c"(p) : : "%rax");  // 15 vmexit o sometimes hang
}
void exec_rdtsc() {
  asm volatile("rdtsc");  // 16
}
void exec_rsm() {
  asm volatile("rsm");  // 16
}

void exec_cr() {
  uint64_t value;
  int cr_register;

  switch (get8b(index_selector_count++) % 4) {
    case 0:
      value = get64b(index_selector_count);
      index_selector_count += 8;
      cr_register = get8b(index_selector_count++) % 4;
      switch (cr_register) {
        case 0:
          asm volatile("movq %0, %%cr0" ::"r"(value));
          break;
        case 1:
          asm volatile("movq %0, %%cr3" ::"r"(value));
          break;
        case 2:
          asm volatile("movq %0, %%cr4" ::"r"(value));
          break;
        case 3:
          asm volatile("movq %0, %%cr8" ::"r"(value));
          break;
      }
      break;
    case 1:
      cr_register = get8b(index_selector_count++) % 4;
      switch (cr_register) {
        case 0:
          asm volatile("movq %%cr0, %0" : "=r"(value));
          break;
        case 1:
          asm volatile("movq %%cr3, %0" : "=r"(value));
          break;
        case 2:
          asm volatile("movq %%cr4, %0" : "=r"(value));
          break;
        case 3:
          asm volatile("movq %%cr8, %0" : "=r"(value));
          break;
      }
      break;
    case 2:
      asm volatile("clts");
      break;
    case 3:
      value = get16b(index_selector_count);
      index_selector_count += 4;
      asm volatile("lmsw %0" ::"m"(value));
      break;
  }
}

void exec_dr() {
  uint64_t value;
  int dr;

  if (get8b(index_selector_count++) % 2) {
    // Read debug registers
    dr = get8b(index_selector_count++) % 8;
    switch (dr) {
      case 0:
        asm volatile("movq %%dr0, %0" : "=r"(value));
        break;
      case 1:
        asm volatile("movq %%dr1, %0" : "=r"(value));
        break;
      case 2:
        asm volatile("movq %%dr2, %0" : "=r"(value));
        break;
      case 3:
        asm volatile("movq %%dr3, %0" : "=r"(value));
        break;
      case 4:
        asm volatile("movq %%dr4, %0" : "=r"(value));
        break;
      case 5:
        asm volatile("movq %%dr5, %0" : "=r"(value));
        break;
      case 6:
        asm volatile("movq %%dr6, %0" : "=r"(value));
        break;
      case 7:
        asm volatile("movq %%dr7, %0" : "=r"(value));
        break;
    }
  } else {
    // Write debug registers
    dr = get8b(index_selector_count++) % 8;
    value = get64b(index_selector_count);
    index_selector_count += 8;
    switch (dr) {
      case 0:
        asm volatile("movq %0, %%dr0" ::"r"(value));
        break;
      case 1:
        asm volatile("movq %0, %%dr1" ::"r"(value));
        break;
      case 2:
        asm volatile("movq %0, %%dr2" ::"r"(value));
        break;
      case 3:
        asm volatile("movq %0, %%dr3" ::"r"(value));
        break;
      case 4:
        asm volatile("movq %0, %%dr4" ::"r"(value));
        break;
      case 5:
        asm volatile("movq %0, %%dr5" ::"r"(value));
        break;
      case 6:
        asm volatile("movq %0, %%dr6" ::"r"(value));
        break;
      case 7:
        asm volatile("movq %0, %%dr7" ::"r"(value));
        break;
    }
  }
}

void exec_io() {
  uint16_t port;
  uint32_t value;

  port = get16b(index_selector_count);
  index_selector_count += 2;

  if (get8b(index_selector_count++) % 2) {
    value = get32b(index_selector_count);
    index_selector_count += 4;
    asm volatile("out %0, %1" ::"a"(value), "d"(port));
  } else {
    asm volatile("in %1, %0" : "=a"(value) : "d"(port));
  }
}

void exec_rdmsr() {
  uint32_t index = msr_table[get32b(index_selector_count) % MSR_TABLE_SIZE];
  index_selector_count += 4;
  if (input_buf[index_selector_count++] % 2) {
    asm volatile("rdmsr" ::"c"(index));
  } else {
    index = get32b(index_selector_count);
    index_selector_count += 4;
    asm volatile("rdmsr" ::"c"(index));
  }
}
void exec_wrmsr() {
  uint32_t index = msr_table[get32b(index_selector_count) % MSR_TABLE_SIZE];
  index_selector_count += 4;
  uint64_t value = get64b(index_selector_count);
  index_selector_count += 8;

  if (input_buf[index_selector_count++] % 2) {
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

void exec_mwait() {
  asm volatile("mwait");  // 36
}
void exec_monitor() {
  asm volatile("monitor");  // 39
}
void exec_pause() {
  asm volatile("pause");  // 40
}
void exec_rdtscp() {
  asm volatile("rdtscp");  // 51 vmexit sometimes hang
}

void exec_wb() {
  if (input_buf[index_selector_count++] % 2) {
    asm volatile("wbnoinvd" :::);  // 54
  } else {
    asm volatile("wbinvd" :::);  // 54
  }
}

void exec_xset() {
  asm volatile("xsetbv" :::);  // 55 sometimes hang
}

void exec_rdrand() {
  uint64_t zero = 0;
  asm volatile("rdrand %0" : "+c"(zero) : : "%rax");  // 57
}
void exec_invpcid() {
  __invpcid(0, 0, 0);  // 58 vmexit sometimes hang
}

void exec_rdseed() {
  uint64_t zero = 0;
  asm volatile("rdseed %0" : "+c"(zero) : : "%rax");  // 61
}

void exec_pconfig() {
  asm volatile("pconfig");  // 65 vmexit sometimes hang
}

void exec_pushf() {
  asm volatile("pushf");
}

void exec_popf() {
  asm volatile("popf");
}

void exec_idtr_read() {
  struct desc_ptr idtr;
  asm volatile("sidt %0" : "=m"(idtr));
}

void exec_gdtr_read() {
  struct desc_ptr gdtr;
  asm volatile("sgdt %0" : "=m"(gdtr));
}

void exec_ldtr_read() {
  struct desc_ptr ldtr;
  asm volatile("sldt %0" : "=m"(ldtr));
}

void exec_tr_read() {
  struct desc_ptr tr;
  asm volatile("str %0" : "=m"(tr));
}

void exec_idtr_write() {
  uint16_t idtr_size = get16b(index_selector_count);
  uint64_t idtr_address = get64b(index_selector_count + 2);
  index_selector_count += 10;

  struct desc_ptr idtr;

  idtr.size = idtr_size;
  idtr.address = idtr_address;

  asm volatile("lidt %0" : : "m"(idtr));
}

void exec_gdtr_write() {
  uint16_t gdtr_size = get16b(index_selector_count);
  uint64_t gdtr_address = get64b(index_selector_count + 2);
  index_selector_count += 10;

  struct desc_ptr gdtr;

  gdtr.size = gdtr_size;
  gdtr.address = gdtr_address;

  asm volatile("lgdt %0" : : "m"(gdtr));
}

void exec_ldtr_write() {
  uint16_t ldtr_val = get16b(index_selector_count);
  index_selector_count += 2;
  asm volatile("lldt %0" ::"m"(ldtr_val));
}

void exec_tr_write() {
  uint16_t tr_val = get16b(index_selector_count);
  index_selector_count += 2;
  asm volatile("ltr %0" ::"m"(tr_val));
}

void exec_iret() {
  asm volatile("iretq");
}

void exec_swint() {
  asm volatile("int $0x3");
}

void exec_invlpga() {
  uint64_t address = get64b(index_selector_count);
  uint32_t asid = get32b(index_selector_count + 8);
  index_selector_count += 12;
  asm volatile("invlpga %0, %1" ::"a"(address), "c"(asid));
}

void exec_task_switch() {
  uint32_t target_address = (uint32_t)(uintptr_t)exec_invlpga;
  uint16_t tr_val = get16b(index_selector_count);
  index_selector_count += 2;
  int a = 0;
  // asm volatile("ltr %0" ::"m"(tr_val));
  asm volatile("ljmp *%0"
               :
               : "m"((struct {
                 uint32_t offset;
                 uint16_t segment;
               }){target_address, a}));
}

void exec_vmrun() {
  asm volatile("vmrun");
}

void exec_vmmcall() {
  asm volatile("vmmcall");
}

void exec_vmload() {
  asm volatile("vmload");
}

void exec_vmsave() {
  asm volatile("vmsave");
}

void exec_stgi() {
  asm volatile("stgi");
}

void exec_clgi() {
  asm volatile("clgi");
}

void exec_skinit() {
  asm volatile("skinit");
}

// void exec_icebp() {
//     asm volatile("icebp");
// }

void exec_monitorx() {
  asm volatile("monitorx");
}

void exec_rdpru() {
  asm volatile("rdpru");
}

void exec_invlpgb() {
  asm volatile("invlpgb");
}

void exec_mcommit() {
  asm volatile("mcommit");
}

void exec_tlbsync() {
  asm volatile("tlbsync");
}

void exec_vmexit_vmgexit() {
  asm volatile("vmgexit");
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
  *icr_low = value & 0xFFFFFFFF;
  *icr_high = value >> 32;
}

void read_icr() {
  volatile uint32_t* icr_low = (uint32_t*)(apic_base + APIC_ICR_LOW);
  volatile uint32_t* icr_high = (uint32_t*)(apic_base + APIC_ICR_HIGH);
  uint64_t value = ((uint64_t)(*icr_high) << 32) | *icr_low;
}

void exec_apic() {
  uint8_t command = input_buf[index_selector_count++];

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