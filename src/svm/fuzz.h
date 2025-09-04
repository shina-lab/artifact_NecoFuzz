#pragma once
#include <stdint.h>
#include "../common/cpu.h"
#include "../common/msr.h"
#include "svm.h"

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

extern uint8_t* input_buf;
extern uint64_t index_selector_count;
extern FuncTableEntry exec_l1_table[];
extern FuncTableEntry exec_l2_table[];
extern const size_t L1_TABLE_SIZE;
extern const size_t L2_TABLE_SIZE;

void exec_cpuid();
void exec_hlt();
void exec_invd();
void exec_invlpg();
void exec_rdpmc();
void exec_rdtsc();
void exec_rsm();
void exec_cr();
void exec_dr();
void exec_io();
void exec_rdmsr();
void exec_wrmsr();
void exec_mwait();
void exec_monitor();
void exec_pause();
void exec_rdtscp();
void exec_wb();
void exec_xset();
void exec_rdrand();
void exec_invpcid();
void exec_rdseed();
void exec_pconfig();
void exec_pushf();
void exec_popf();
void exec_idtr_read();
void exec_gdtr_read();
void exec_ldtr_read();
void exec_tr_read();
void exec_idtr_write();
void exec_gdtr_write();
void exec_ldtr_write();
void exec_tr_write();
void exec_iret();
void exec_swint();
void exec_invlpga();
void exec_task_switch();
void exec_vmrun();
void exec_vmmcall();
void exec_vmload();
void exec_vmsave();
void exec_stgi();
void exec_clgi();
void exec_skinit();
// void exec_icebp();
void exec_monitorx();
void exec_rdpru();
void exec_invlpgb();
void exec_mcommit();
void exec_tlbsync();
void exec_vmexit_vmgexit();
uint32_t read_local_apic_id();
uint32_t read_local_apic_version();
void write_eoi();
void write_icr();
void read_icr();
void exec_apic();