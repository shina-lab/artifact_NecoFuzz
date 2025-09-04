#pragma once
#include <stdint.h>
#include "cpu.h"
#include "uefi.h"

#define APIC_ID 0x20
#define APIC_VERSION 0x30
#define APIC_TPR 0x80
#define APIC_EOI 0xB0
#define APIC_SVR 0xF0
#define APIC_ICR_LOW 0x300
#define APIC_ICR_HIGH 0x310

#define APIC_ENABLE 0x100
#define APIC_FOCUS_DISABLE (1 << 9)

#define MSR_IA32_APICBASE 0x0000001b
#define MSR_IA32_APICBASE_BSP (1 << 8)
#define MSR_IA32_APICBASE_ENABLE (1 << 11)
#define MSR_IA32_APICBASE_BASE (0xfffff << 12)

#define BX_CR0_PE_MASK (1 << 0)
#define BX_CR0_MP_MASK (1 << 1)
#define BX_CR0_EM_MASK (1 << 2)
#define BX_CR0_TS_MASK (1 << 3)
#define BX_CR0_ET_MASK (1 << 4)
#define BX_CR0_NE_MASK (1 << 5)
#define BX_CR0_WP_MASK (1 << 16)
#define BX_CR0_AM_MASK (1 << 18)
#define BX_CR0_NW_MASK (1 << 29)
#define BX_CR0_CD_MASK (1 << 30)
#define BX_CR0_PG_MASK (1 << 31)

#define BX_CR4_VME_MASK (1 << 0)
#define BX_CR4_PVI_MASK (1 << 1)
#define BX_CR4_TSD_MASK (1 << 2)
#define BX_CR4_DE_MASK (1 << 3)
#define BX_CR4_PSE_MASK (1 << 4)
#define BX_CR4_PAE_MASK (1 << 5)
#define BX_CR4_MCE_MASK (1 << 6)
#define BX_CR4_PGE_MASK (1 << 7)
#define BX_CR4_PCE_MASK (1 << 8)
#define BX_CR4_OSFXSR_MASK (1 << 9)
#define BX_CR4_OSXMMEXCPT_MASK (1 << 10)
#define BX_CR4_UMIP_MASK (1 << 11)
#define BX_CR4_LA57_MASK (1 << 12)
#define BX_CR4_VMXE_MASK (1 << 13)
#define BX_CR4_SMXE_MASK (1 << 14)
#define BX_CR4_FSGSBASE_MASK (1 << 16)
#define BX_CR4_PCIDE_MASK (1 << 17)
#define BX_CR4_OSXSAVE_MASK (1 << 18)
#define BX_CR4_KEYLOCKER_MASK (1 << 19)
#define BX_CR4_SMEP_MASK (1 << 20)
#define BX_CR4_SMAP_MASK (1 << 21)
#define BX_CR4_PKE_MASK (1 << 22)
#define BX_CR4_CET_MASK (1 << 23)
#define BX_CR4_PKS_MASK (1 << 24)
#define BX_CR4_UINTR_MASK (1 << 25)

#define BX_EFER_SCE_MASK (1 << 0)
#define BX_EFER_LME_MASK (1 << 8)
#define BX_EFER_LMA_MASK (1 << 10)
#define BX_EFER_NXE_MASK (1 << 11)
#define BX_EFER_SVME_MASK (1 << 12)
#define BX_EFER_LMSLE_MASK (1 << 13)
#define BX_EFER_FFXSR_MASK (1 << 14)
#define BX_EFER_TCE_MASK (1 << 15)

extern uint64_t* apic_base;

struct registers {
  uint16_t cs, ds, es, fs, gs, ss, tr, ldt;
  uint32_t rflags;
  uint64_t cr0, cr3, cr4;
  uint64_t ia32_efer, ia32_feature_control;
  struct {
    uint16_t limit;
    uint64_t base;
  } __attribute__((packed)) gdt, idt;
  // attribute "packed" requires -mno-ms-bitfields
};

struct __attribute__((__packed__, aligned(64))) xsave_header {
  uint64_t xstate_bv;
  uint64_t reserved[2];
};

struct fpu_state_buffer {
  struct xsave_header header;
  char buffer[];
};
struct xsave {
  uint8_t legacy_area[512];
  union {
    struct {
      uint64_t xstate_bv;
      uint64_t xcomp_bv;
    };
    uint8_t header_area[64];
  };
  uint8_t extended_area[];
};

static inline uint64_t rdmsr(uint32_t index) {
  uint32_t eax, edx;
  asm volatile("rdmsr" : "=a"(eax), "=d"(edx) : "c"(index));
  return ((uint64_t)edx << 32) | eax;
}

static inline void wrmsr(uint32_t index, uint64_t value) {
  uint32_t eax, edx;
  eax = value & 0xffffffff;
  edx = value >> 32;
  asm volatile("wrmsr" : : "c"(index), "a"(eax), "d"(edx));
}

static inline void __invpcid(unsigned long pcid, unsigned long addr, unsigned long type) {
  struct {
    uint64_t d[2];
  } desc = {{pcid, addr}};
  /*
   * The memory clobber is because the whole point is to invalidate
   * stale TLB entries and, especially if we're flushing global
   * mappings, we don't want the compiler to reorder any subsequent
   * memory accesses before the TLB flush.
   *
   * The hex opcode is invpcid (%ecx), %eax in 32-bit mode and
   * invpcid (%rcx), %rax in long mode.
   */
  asm volatile(".byte 0x66, 0x0f, 0x38, 0x82, 0x01"
               :
               : "m"(desc), "a"(type), "c"(&desc)
               : "memory");
}

uint32_t get_seg_limit(uint32_t selector);
int32_t get_seg_access_rights(uint32_t selector);
uint64_t get_seg_base(uint32_t selector);
void save_registers(struct registers* regs);

void print_registers(struct registers* regs);

uint64_t get_apic_base();

void initialize_apic();
void* memset(void* dest, int val, int len);

extern const uint64_t kPageSize4K;
extern const uint64_t kPageSize2M;
extern const uint64_t kPageSize1G;

extern uint64_t pml4_table[512] __attribute__((aligned(4096)));
extern uint64_t pdp_table[512] __attribute__((aligned(4096)));
extern uint64_t page_directory[512][512] __attribute__((aligned(4096)));
extern uint64_t pml4_table_2[512] __attribute__((aligned(4096)));
uint64_t* SetupIdentityPageTable();