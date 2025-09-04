#pragma once
#include <stdint.h>
#include "../common/cpu.h"
#include "../common/msr.h"
#include "vmx.h"

typedef void (*FuncPtr)(void);

typedef struct {
  FuncPtr func;
  const unsigned short* name;
} FuncTableEntry;

#define get64b(x) ((uint64_t*)(input_buf + x))[0]
#define get32b(x) ((uint32_t*)(input_buf + x))[0]
#define get16b(x) ((uint16_t*)(input_buf + x))[0]
#define get8b(x) ((uint8_t*)(input_buf + x))[0]
#define get_vmcs_value64(x) ((uint64_t*)(input_buf + i))[0]

#define write64b(x, v) ((uint64_t*)(input_buf + x))[0] = (uint64_t)v
#define write32b(x, v) ((uint32_t*)(input_buf + x))[0] = (uint32_t)v
#define write16b(x, v) ((uint16_t*)(input_buf + x))[0] = (uint16_t)v
#define write8b(x, v) ((uint8_t*)(input_buf + x))[0] = (uint8_t)v

extern uint8_t* input_buf;
extern uint64_t index_selector_count;
extern FuncTableEntry fuzz_l1_table[];
extern FuncTableEntry fuzz_l2_table[];
extern const size_t L1_TABLE_SIZE;
extern const size_t L2_TABLE_SIZE;
extern uint8_t virtual_apic[4096] __attribute__((aligned(4096)));

void fuzz_cpuid();
void fuzz_hlt();
void fuzz_invd();
void fuzz_invlpg();
void fuzz_rdpmc();
void fuzz_rdtsc();
void fuzz_rsm();
void fuzz_vmclear();
void fuzz_vmlaunch();
void fuzz_l1_vmptrst();
void fuzz_l2_vmptrst();
void fuzz_vmptrld();

void fuzz_l1_vmread();
void fuzz_l1_vmwrite();
void fuzz_l2_vmread();
void fuzz_l2_vmwrite();
void fuzz_vmxoff();
void fuzz_vmxon();
void fuzz_vmresue();

void fuzz_cr();
void fuzz_dr();
void fuzz_io();

void fuzz_rdmsr();
void fuzz_wrmsr();
void fuzz_mwait();
void fuzz_monitor();
void fuzz_pause();
void fuzz_rdtscp();
void fuzz_invept();
void fuzz_invvpid();
void fuzz_wb();
void fuzz_xset();
void fuzz_rdrand();
void fuzz_invpcid();
void fuzz_vmfunc();
void fuzz_encls();
void fuzz_rdseed();

void fuzz_pconfig();
void fuzz_msr_save_load();
void fuzz_page_table();

uint32_t read_local_apic_id();
uint32_t read_local_apic_version();
void write_eoi();
void write_icr();
void read_icr();
void fuzz_apic();
void __invpcid(unsigned long pcid, unsigned long addr, unsigned long type);

void fuzz_gdt_idt();
void fuzz_dtr_tr();
void fuzz_evmcsptr();

void fuzz_nmi_exit();
void fuzz_msr_bitmap();
void fuzz_tpr_shadow();
void fuzz_vapic_access();
void fuzz_vapic_access();