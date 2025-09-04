#pragma once
/* SPDX-License-Identifier: GPL-2.0 */
/*
 *
 */

#include <stdbool.h>
#include <stdint.h>

#include "../common/cpu.h"
#include "../common/msr.h"

#define u64 uint64_t
#define u32 uint32_t
#define u16 uint16_t
#define u8 uint8_t

// #define BX_ERROR(format, ...) wprintf(L(format), ##__VA_ARGS__)
// #define BX_ERROR(format, ...) wprintf(L##format, ##__VA_ARGS__)
// #define BX_ERROR(...) wprintf(L"%s\n", L"" #__VA_ARGS__)
#define BX_ERROR(...) \
  {}

#define BX_SUPPORT_X86_64 1
#define BX_CPU_LEVEL 6

#if BX_SUPPORT_X86_64
#define BX_LIN_ADDRESS_WIDTH 48
#else
#define BX_LIN_ADDRESS_WIDTH 32
#endif

#if BX_CPU_LEVEL == 5
#define BX_PHY_ADDRESS_WIDTH 36
#else
#define BX_PHY_ADDRESS_WIDTH 40
#endif

#if BX_PHY_ADDRESS_WIDTH > 40
#define PAGING_PDE4M_RESERVED_BITS \
  0  // there are no reserved bits in PDE4M when physical address is wider
     // than 40 bit
#else
#define PAGING_PDE4M_RESERVED_BITS \
  ((1 << (41 - BX_PHY_ADDRESS_WIDTH)) - 1) << (13 + BX_PHY_ADDRESS_WIDTH - 32)
#endif

#define BX_PHY_ADDRESS_MASK ((((uint64_t)(1)) << BX_PHY_ADDRESS_WIDTH) - 1)

#define BX_PHY_ADDRESS_RESERVED_BITS (~BX_PHY_ADDRESS_MASK)

#define BX_SUPPORT_SVM_EXTENSION(feature_mask) \
  (svm_extensions_bitmask & (feature_mask))

/* CPU model specific register (MSR) numbers. */
/* x86-64 specific MSRs */
#define MSR_EFER 0xc0000080           /* extended feature register */
#define MSR_STAR 0xc0000081           /* legacy mode SYSCALL target */
#define MSR_LSTAR 0xc0000082          /* long mode SYSCALL target */
#define MSR_CSTAR 0xc0000083          /* compat mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084   /* EFLAGS mask for syscall */
#define MSR_FS_BASE 0xc0000100        /* 64bit FS base */
#define MSR_GS_BASE 0xc0000101        /* 64bit GS base */
#define MSR_KERNEL_GS_BASE 0xc0000102 /* SwapGS GS shadow */
#define MSR_TSC_AUX 0xc0000103        /* Auxiliary TSC */

#define APIC_ID 0x20
#define APIC_VERSION 0x30
#define APIC_TPR 0x80
#define APIC_EOI 0xB0
#define APIC_SVR 0xF0
#define APIC_ICR_LOW 0x300
#define APIC_ICR_HIGH 0x310

#define APIC_ENABLE 0x100
#define APIC_FOCUS_DISABLE (1 << 9)

#define TLB_CONTROL_DO_NOTHING 0
#define TLB_CONTROL_FLUSH_ALL_ASID 1
#define TLB_CONTROL_FLUSH_ASID 3
#define TLB_CONTROL_FLUSH_ASID_LOCAL 7

#define V_TPR_MASK 0x0f

#define V_IRQ_SHIFT 8
#define V_IRQ_MASK (1 << V_IRQ_SHIFT)

#define V_GIF_SHIFT 9
#define V_GIF_MASK (1 << V_GIF_SHIFT)

#define V_INTR_PRIO_SHIFT 16
#define V_INTR_PRIO_MASK (0x0f << V_INTR_PRIO_SHIFT)

#define V_IGN_TPR_SHIFT 20
#define V_IGN_TPR_MASK (1 << V_IGN_TPR_SHIFT)

#define V_INTR_MASKING_SHIFT 24
#define V_INTR_MASKING_MASK (1 << V_INTR_MASKING_SHIFT)

#define V_GIF_ENABLE_SHIFT 25
#define V_GIF_ENABLE_MASK (1 << V_GIF_ENABLE_SHIFT)

#define AVIC_ENABLE_SHIFT 31
#define AVIC_ENABLE_MASK (1 << AVIC_ENABLE_SHIFT)

#define LBR_CTL_ENABLE_MASK BIT_ULL(0)
#define VIRTUAL_VMLOAD_VMSAVE_ENABLE_MASK BIT_ULL(1)

#define SVM_INTERRUPT_SHADOW_MASK 1

#define SVM_IOIO_STR_SHIFT 2
#define SVM_IOIO_REP_SHIFT 3
#define SVM_IOIO_SIZE_SHIFT 4
#define SVM_IOIO_ASIZE_SHIFT 7

#define SVM_IOIO_TYPE_MASK 1
#define SVM_IOIO_STR_MASK (1 << SVM_IOIO_STR_SHIFT)
#define SVM_IOIO_REP_MASK (1 << SVM_IOIO_REP_SHIFT)
#define SVM_IOIO_SIZE_MASK (7 << SVM_IOIO_SIZE_SHIFT)
#define SVM_IOIO_ASIZE_MASK (7 << SVM_IOIO_ASIZE_SHIFT)

#define SVM_VM_CR_VALID_MASK 0x001fULL
#define SVM_VM_CR_SVM_LOCK_MASK 0x0008ULL
#define SVM_VM_CR_SVM_DIS_MASK 0x0010ULL

#define SVM_NESTED_CTL_NP_ENABLE BIT(0)
#define SVM_NESTED_CTL_SEV_ENABLE BIT(1)

#define SVM_VM_CR_SVM_DISABLE 4

#define SVM_SELECTOR_S_SHIFT 4
#define SVM_SELECTOR_DPL_SHIFT 5
#define SVM_SELECTOR_P_SHIFT 7
#define SVM_SELECTOR_AVL_SHIFT 8
#define SVM_SELECTOR_L_SHIFT 9
#define SVM_SELECTOR_DB_SHIFT 10
#define SVM_SELECTOR_G_SHIFT 11

#define SVM_SELECTOR_TYPE_MASK (0xf)
#define SVM_SELECTOR_S_MASK (1 << SVM_SELECTOR_S_SHIFT)
#define SVM_SELECTOR_DPL_MASK (3 << SVM_SELECTOR_DPL_SHIFT)
#define SVM_SELECTOR_P_MASK (1 << SVM_SELECTOR_P_SHIFT)
#define SVM_SELECTOR_AVL_MASK (1 << SVM_SELECTOR_AVL_SHIFT)
#define SVM_SELECTOR_L_MASK (1 << SVM_SELECTOR_L_SHIFT)
#define SVM_SELECTOR_DB_MASK (1 << SVM_SELECTOR_DB_SHIFT)
#define SVM_SELECTOR_G_MASK (1 << SVM_SELECTOR_G_SHIFT)

#define SVM_SELECTOR_WRITE_MASK (1 << 1)
#define SVM_SELECTOR_READ_MASK SVM_SELECTOR_WRITE_MASK
#define SVM_SELECTOR_CODE_MASK (1 << 3)

#define INTERCEPT_CR0_READ 0
#define INTERCEPT_CR3_READ 3
#define INTERCEPT_CR4_READ 4
#define INTERCEPT_CR8_READ 8
#define INTERCEPT_CR0_WRITE (16 + 0)
#define INTERCEPT_CR3_WRITE (16 + 3)
#define INTERCEPT_CR4_WRITE (16 + 4)
#define INTERCEPT_CR8_WRITE (16 + 8)

#define INTERCEPT_DR0_READ 0
#define INTERCEPT_DR1_READ 1
#define INTERCEPT_DR2_READ 2
#define INTERCEPT_DR3_READ 3
#define INTERCEPT_DR4_READ 4
#define INTERCEPT_DR5_READ 5
#define INTERCEPT_DR6_READ 6
#define INTERCEPT_DR7_READ 7
#define INTERCEPT_DR0_WRITE (16 + 0)
#define INTERCEPT_DR1_WRITE (16 + 1)
#define INTERCEPT_DR2_WRITE (16 + 2)
#define INTERCEPT_DR3_WRITE (16 + 3)
#define INTERCEPT_DR4_WRITE (16 + 4)
#define INTERCEPT_DR5_WRITE (16 + 5)
#define INTERCEPT_DR6_WRITE (16 + 6)
#define INTERCEPT_DR7_WRITE (16 + 7)

#define SVM_EVTINJ_VEC_MASK 0xff

#define SVM_EVTINJ_TYPE_SHIFT 8
#define SVM_EVTINJ_TYPE_MASK (7 << SVM_EVTINJ_TYPE_SHIFT)

#define SVM_EVTINJ_TYPE_INTR (0 << SVM_EVTINJ_TYPE_SHIFT)
#define SVM_EVTINJ_TYPE_NMI (2 << SVM_EVTINJ_TYPE_SHIFT)
#define SVM_EVTINJ_TYPE_EXEPT (3 << SVM_EVTINJ_TYPE_SHIFT)
#define SVM_EVTINJ_TYPE_SOFT (4 << SVM_EVTINJ_TYPE_SHIFT)

#define SVM_EVTINJ_VALID (1 << 31)
#define SVM_EVTINJ_VALID_ERR (1 << 11)

#define SVM_EXITINTINFO_VEC_MASK SVM_EVTINJ_VEC_MASK
#define SVM_EXITINTINFO_TYPE_MASK SVM_EVTINJ_TYPE_MASK

#define SVM_EXITINTINFO_TYPE_INTR SVM_EVTINJ_TYPE_INTR
#define SVM_EXITINTINFO_TYPE_NMI SVM_EVTINJ_TYPE_NMI
#define SVM_EXITINTINFO_TYPE_EXEPT SVM_EVTINJ_TYPE_EXEPT
#define SVM_EXITINTINFO_TYPE_SOFT SVM_EVTINJ_TYPE_SOFT

#define SVM_EXITINTINFO_VALID SVM_EVTINJ_VALID
#define SVM_EXITINTINFO_VALID_ERR SVM_EVTINJ_VALID_ERR

#define SVM_EXITINFOSHIFT_TS_REASON_IRET 36
#define SVM_EXITINFOSHIFT_TS_REASON_JMP 38
#define SVM_EXITINFOSHIFT_TS_HAS_ERROR_CODE 44

#define SVM_EXITINFO_REG_MASK 0x0F

#define SVM_CR0_SELECTIVE_MASK (X86_CR0_TS | X86_CR0_MP)

// CPUID defines - SVM features CPUID[0x8000000A].EDX
// ----------------------------

// [0:0]   NP - Nested paging support
// [1:1]   LBR virtualization
// [2:2]   SVM Lock
// [3:3]   NRIPS - Next RIP save on VMEXIT
// [4:4]   TscRate - MSR based TSC ratio control
// [5:5]   VMCB Clean bits support
// [6:6]   Flush by ASID support
// [7:7]   Decode assists support
// [8:8]   Reserved
// [9:9]   Reserved
// [10:10] Pause filter support
// [11:11] Reserved
// [12:12] Pause filter threshold support
// [13:13] Advanced Virtual Interrupt Controller
// [14:14] Reserved
// [15:15] Nested Virtualization (virtualized VMLOAD and VMSAVE) Support
// [16:16] Virtual GIF
// [17:17] Guest Mode Execute Trap (CMET)

#define BX_CPUID_SVM_NESTED_PAGING (1 << 0)
#define BX_CPUID_SVM_LBR_VIRTUALIZATION (1 << 1)
#define BX_CPUID_SVM_SVM_LOCK (1 << 2)
#define BX_CPUID_SVM_NRIP_SAVE (1 << 3)
#define BX_CPUID_SVM_TSCRATE (1 << 4)
#define BX_CPUID_SVM_VMCB_CLEAN_BITS (1 << 5)
#define BX_CPUID_SVM_FLUSH_BY_ASID (1 << 6)
#define BX_CPUID_SVM_DECODE_ASSIST (1 << 7)
#define BX_CPUID_SVM_RESERVED8 (1 << 8)
#define BX_CPUID_SVM_RESERVED9 (1 << 9)
#define BX_CPUID_SVM_PAUSE_FILTER (1 << 10)
#define BX_CPUID_SVM_RESERVED11 (1 << 11)
#define BX_CPUID_SVM_PAUSE_FILTER_THRESHOLD (1 << 12)
#define BX_CPUID_SVM_AVIC (1 << 13)
#define BX_CPUID_SVM_RESERVED14 (1 << 14)
#define BX_CPUID_SVM_NESTED_VIRTUALIZATION (1 << 15)
#define BX_CPUID_SVM_VIRTUAL_GIF (1 << 16)
#define BX_CPUID_SVM_CMET (1 << 17)

#define EFER_RESERVED (0xFFFFA2FE)
#define CR4_RESERVED (0xFFC8F000)

#define SVM_INTERCEPT(intercept_bitnum) \
  (ctrls->intercept & ((uint64_t)1 << (intercept_bitnum & 63)))

#define SVM_EXCEPTION_INTERCEPTED(vector) \
  (BX_CPU_THIS_PTR vmcb.ctrls.exceptions_intercept & (1 << (vector)))

#define SVM_CR_READ_INTERCEPTED(reg_num) \
  (BX_CPU_THIS_PTR vmcb.ctrls.cr_rd_ctrl & (1 << (reg_num)))

#define SVM_CR_WRITE_INTERCEPTED(reg_num) \
  (BX_CPU_THIS_PTR vmcb.ctrls.cr_wr_ctrl & (1 << (reg_num)))

#define SVM_DR_READ_INTERCEPTED(reg_num) \
  (BX_CPU_THIS_PTR vmcb.ctrls.dr_rd_ctrl & (1 << (reg_num)))

#define SVM_DR_WRITE_INTERCEPTED(reg_num) \
  (BX_CPU_THIS_PTR vmcb.ctrls.dr_wr_ctrl & (1 << (reg_num)))

/*
 * Hyper-V uses the software reserved clean bit in VMCB
 */
#define HV_VMCB_NESTED_ENLIGHTENMENTS (1U << 31)

/* Synthetic VM-Exit */
#define HV_SVM_EXITCODE_ENL 0xf0000000
#define HV_SVM_ENL_EXITCODE_TRAP_AFTER_FLUSH (1)

/* MSR used to identify the guest OS. */
#define HV_X64_MSR_GUEST_OS_ID 0x40000000

/* MSR used to setup pages used to communicate with the hypervisor. */
#define HV_X64_MSR_HYPERCALL 0x40000001

/* Define the virtual APIC registers */
#define HV_X64_MSR_VP_ASSIST_PAGE 0x40000073

#define HV_X64_MSR_VP_ASSIST_PAGE_ENABLE 0x00000001

/* Proper HV_X64_MSR_GUEST_OS_ID value */
#define HYPERV_LINUX_OS_ID ((u64)0x8100 << 48)

/* Declare the various hypercall operations. */
#define HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE 0x0002
#define HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST 0x0003
#define HVCALL_NOTIFY_LONG_SPIN_WAIT 0x0008
#define HVCALL_SEND_IPI 0x000b
#define HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE_EX 0x0013
#define HVCALL_FLUSH_VIRTUAL_ADDRESS_LIST_EX 0x0014
#define HVCALL_SEND_IPI_EX 0x0015
#define HVCALL_GET_PARTITION_ID 0x0046
#define HVCALL_DEPOSIT_MEMORY 0x0048
#define HVCALL_CREATE_VP 0x004e
#define HVCALL_GET_VP_REGISTERS 0x0050
#define HVCALL_SET_VP_REGISTERS 0x0051
#define HVCALL_POST_MESSAGE 0x005c
#define HVCALL_SIGNAL_EVENT 0x005d
#define HVCALL_POST_DEBUG_DATA 0x0069
#define HVCALL_RETRIEVE_DEBUG_DATA 0x006a
#define HVCALL_RESET_DEBUG_SESSION 0x006b
#define HVCALL_ADD_LOGICAL_PROCESSOR 0x0076
#define HVCALL_MAP_DEVICE_INTERRUPT 0x007c
#define HVCALL_UNMAP_DEVICE_INTERRUPT 0x007d
#define HVCALL_RETARGET_INTERRUPT 0x007e
#define HVCALL_FLUSH_GUEST_PHYSICAL_ADDRESS_SPACE 0x00af
#define HVCALL_FLUSH_GUEST_PHYSICAL_ADDRESS_LIST 0x00b0
#define HVCALL_MODIFY_SPARSE_GPA_PAGE_HOST_VISIBILITY 0x00db

/* Extended hypercalls */
#define HV_EXT_CALL_QUERY_CAPABILITIES 0x8001
#define HV_EXT_CALL_MEMORY_HEAT_HINT 0x8003
#define BIT(x) (1 << (x))

#define HV_FLUSH_ALL_PROCESSORS BIT(0)
#define HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES BIT(1)
#define HV_FLUSH_NON_GLOBAL_MAPPINGS_ONLY BIT(2)
#define HV_FLUSH_USE_EXTENDED_RANGE_FORMAT BIT(3)
#define HV_HYPERCALL_FAST_BIT BIT(16)

#define __stringify(x) #x
#define KVM_EXCEPTION_MAGIC 0xabacadabaULL

#define KVM_ASM_SAFE(insn)        \
  "mov $0xabacadabaULL, %%r9\n\t" \
  "lea 1f(%%rip), %%r10\n\t"      \
  "lea 2f(%%rip), %%r11\n\t"      \
  "1: " insn                      \
  "\n\t"                          \
  "xor %%r9, %%r9\n\t"            \
  "2:\n\t"                        \
  "mov  %%r9b, %[vector]\n\t"     \
  "mov  %%r10, %[error_code]\n\t"

#define KVM_ASM_SAFE_OUTPUTS(v, ec) [vector] "=qm"(v), [error_code] "=rm"(ec)
#define KVM_ASM_SAFE_CLOBBERS "r9", "r10", "r11"

struct gpr64_regs {
  u64 rax;
  u64 rcx;
  u64 rdx;
  u64 rbx;
  u64 rsp;
  u64 rbp;
  u64 rsi;
  u64 rdi;
  u64 r8;
  u64 r9;
  u64 r10;
  u64 r11;
  u64 r12;
  u64 r13;
  u64 r14;
  u64 r15;
};

struct svm_test_data {
  /* VMCB */
  struct vmcb* vmcb; /* gva */
  void* vmcb_hva;
  uint64_t vmcb_gpa;

  /* host state-save area */
  struct vmcb_save_area* save_area; /* gva */
  void* save_area_hva;
  uint64_t save_area_gpa;

  /* MSR-Bitmap */
  void* msr; /* gva */
  void* msr_hva;
  uint64_t msr_gpa;
};

struct hv_vmcb_enlightenments {
  struct hv_enlightenments_control {
    u32 nested_flush_hypercall : 1;
    u32 msr_bitmap : 1;
    u32 enlightened_npt_tlb : 1;
    u32 reserved : 29;
  } __attribute__((__packed__)) hv_enlightenments_control;
  u32 hv_vp_id;
  u64 hv_vm_id;
  u64 partition_assist_page;
  u64 reserved;
} __attribute__((__packed__));

struct __attribute__((__packed__)) vmcb_control_area {
  u32 intercept_cr;
  u32 intercept_dr;
  u32 intercept_exceptions;
  u64 intercept;
  u8 reserved_1[40];
  u16 pause_filter_thresh;
  u16 pause_filter_count;
  u64 iopm_base_pa;
  u64 msrpm_base_pa;
  u64 tsc_offset;
  u32 asid;
  u8 tlb_ctl;
  u8 reserved_2[3];
  u32 int_ctl;
  u32 int_vector;
  u32 int_state;
  u8 reserved_3[4];
  u32 exit_code;
  u32 exit_code_hi;
  u64 exit_info_1;
  u64 exit_info_2;
  u32 exit_int_info;
  u32 exit_int_info_err;
  u64 nested_ctl;
  u64 avic_vapic_bar;
  u8 reserved_4[8];
  u32 event_inj;
  u32 event_inj_err;
  u64 nested_cr3;
  u64 virt_ext;
  u32 clean;
  u32 reserved_5;
  u64 next_rip;
  u8 insn_len;
  u8 insn_bytes[15];
  u64 avic_backing_page; /* Offset 0xe0 */
  u8 reserved_6[8];      /* Offset 0xe8 */
  u64 avic_logical_id;   /* Offset 0xf0 */
  u64 avic_physical_id;  /* Offset 0xf8 */
  u8 reserved_7[8];
  u64 vmsa_pa; /* Used for an SEV-ES guest */
  u8 reserved_8[720];
  /*
   * Offset 0x3e0, 32 bytes reserved
   * for use by hypervisor/software.
   */
  union {
    struct hv_vmcb_enlightenments hv_enlightenments;
    u8 reserved_sw[32];
  };
};

struct __attribute__((__packed__)) vmcb_seg {
  u16 selector;
  u16 attrib;
  u32 limit;
  u64 base;
};

struct __attribute__((__packed__)) vmcb_save_area {
  struct vmcb_seg es;
  struct vmcb_seg cs;
  struct vmcb_seg ss;
  struct vmcb_seg ds;
  struct vmcb_seg fs;
  struct vmcb_seg gs;
  struct vmcb_seg gdtr;
  struct vmcb_seg ldtr;
  struct vmcb_seg idtr;
  struct vmcb_seg tr;
  u8 reserved_1[43];
  u8 cpl;
  u8 reserved_2[4];
  u64 efer;
  u8 reserved_3[112];
  u64 cr4;
  u64 cr3;
  u64 cr0;
  u64 dr7;
  u64 dr6;
  u64 rflags;
  u64 rip;
  u8 reserved_4[88];
  u64 rsp;
  u8 reserved_5[24];
  u64 rax;
  u64 star;
  u64 lstar;
  u64 cstar;
  u64 sfmask;
  u64 kernel_gs_base;
  u64 sysenter_cs;
  u64 sysenter_esp;
  u64 sysenter_eip;
  u64 cr2;
  u8 reserved_6[32];
  u64 g_pat;
  u64 dbgctl;
  u64 br_from;
  u64 br_to;
  u64 last_excp_from;
  u64 last_excp_to;
};

struct __attribute__((__packed__)) vmcb {
  struct vmcb_control_area control;
  struct vmcb_save_area save;
};

struct desc_ptr {
  uint16_t size;
  uint64_t address;
} __attribute__((packed));

typedef struct {
  uint16_t offset_low;
  uint16_t selector;
  uint8_t ist;
  uint8_t flags;
  uint16_t offset_mid;
  uint32_t offset_high;
  uint32_t zero;
} __attribute__((packed)) idt_entry_t;

struct hyperv_test_pages {
  /* VP assist page */
  void* vp_assist_hva;
  uint64_t vp_assist_gpa;
  void* vp_assist;

  /* Partition assist page */
  void* partition_assist_hva;
  uint64_t partition_assist_gpa;
  void* partition_assist;

  /* Enlightened VMCS */
  void* enlightened_vmcs_hva;
  uint64_t enlightened_vmcs_gpa;
  void* enlightened_vmcs;
};

struct hv_nested_enlightenments_control {
  struct {
    uint32_t directhypercall : 1;
    uint32_t reserved : 31;
  } features;
  struct {
    uint32_t inter_partition_comm : 1;
    uint32_t reserved : 31;
  } hypercallControls;
} __attribute__((packed));

/* Define virtual processor assist page structure. */
struct hv_vp_assist_page {
  uint32_t apic_assist;
  uint32_t reserved1;
  uint32_t vtl_entry_reason;
  uint32_t vtl_reserved;
  uint64_t vtl_ret_x64rax;
  uint64_t vtl_ret_x64rcx;
  struct hv_nested_enlightenments_control nested_control;
  uint8_t enlighten_vmentry;
  uint8_t reserved2[7];
  uint64_t current_nested_vmcs;
  uint8_t synthetic_time_unhalted_timer_expired;
  uint8_t reserved3[7];
  uint8_t virtualization_fault_information[40];
  uint8_t reserved4[8];
  uint8_t intercept_message[256];
  uint8_t vtl_ret_actions[256];
} __attribute__((packed));

enum {
  INTERCEPT_INTR,
  INTERCEPT_NMI,
  INTERCEPT_SMI,
  INTERCEPT_INIT,
  INTERCEPT_VINTR,
  INTERCEPT_SELECTIVE_CR0,
  INTERCEPT_STORE_IDTR,
  INTERCEPT_STORE_GDTR,
  INTERCEPT_STORE_LDTR,
  INTERCEPT_STORE_TR,
  INTERCEPT_LOAD_IDTR,
  INTERCEPT_LOAD_GDTR,
  INTERCEPT_LOAD_LDTR,
  INTERCEPT_LOAD_TR,
  INTERCEPT_RDTSC,
  INTERCEPT_RDPMC,
  INTERCEPT_PUSHF,
  INTERCEPT_POPF,
  INTERCEPT_CPUID,
  INTERCEPT_RSM,
  INTERCEPT_IRET,
  INTERCEPT_INTn,
  INTERCEPT_INVD,
  INTERCEPT_PAUSE,
  INTERCEPT_HLT,
  INTERCEPT_INVLPG,
  INTERCEPT_INVLPGA,
  INTERCEPT_IOIO_PROT,
  INTERCEPT_MSR_PROT,
  INTERCEPT_TASK_SWITCH,
  INTERCEPT_FERR_FREEZE,
  INTERCEPT_SHUTDOWN,
  INTERCEPT_VMRUN,
  INTERCEPT_VMMCALL,
  INTERCEPT_VMLOAD,
  INTERCEPT_VMSAVE,
  INTERCEPT_STGI,
  INTERCEPT_CLGI,
  INTERCEPT_SKINIT,
  INTERCEPT_RDTSCP,
  INTERCEPT_ICEBP,
  INTERCEPT_WBINVD,
  INTERCEPT_MONITOR,
  INTERCEPT_MWAIT,
  INTERCEPT_MWAIT_COND,
  INTERCEPT_XSETBV,
  INTERCEPT_RDPRU,
};

enum {
  BX_MEMTYPE_UC = 0,
  BX_MEMTYPE_WC = 1,
  BX_MEMTYPE_RESERVED2 = 2,
  BX_MEMTYPE_RESERVED3 = 3,
  BX_MEMTYPE_WT = 4,
  BX_MEMTYPE_WP = 5,
  BX_MEMTYPE_WB = 6,
  BX_MEMTYPE_UC_WEAK = 7,  // PAT only
  BX_MEMTYPE_INVALID = 8
};

void generic_svm_setup(struct svm_test_data* svm,
                       void* guest_rip,
                       void* guest_rsp);
int run_guest(struct vmcb* vmcb, uint64_t vmcb_gpa);
int SvmEnterLoadCheckControls(struct svm_test_data* svm);
int SvmEnterLoadCheckGuestState(struct svm_test_data* svm);

static inline uint16_t get_es(void) {
  uint16_t es;

  __asm__ __volatile__("mov %%es, %[es]" : /* output */[es] "=rm"(es));
  return es;
}

static inline uint16_t get_cs(void) {
  uint16_t cs;

  __asm__ __volatile__("mov %%cs, %[cs]" : /* output */[cs] "=rm"(cs));
  return cs;
}

static inline uint16_t get_ss(void) {
  uint16_t ss;

  __asm__ __volatile__("mov %%ss, %[ss]" : /* output */[ss] "=rm"(ss));
  return ss;
}

static inline uint16_t get_ds(void) {
  uint16_t ds;

  __asm__ __volatile__("mov %%ds, %[ds]" : /* output */[ds] "=rm"(ds));
  return ds;
}

static inline uint16_t get_fs(void) {
  uint16_t fs;

  __asm__ __volatile__("mov %%fs, %[fs]" : /* output */[fs] "=rm"(fs));
  return fs;
}

static inline uint16_t get_gs(void) {
  uint16_t gs;

  __asm__ __volatile__("mov %%gs, %[gs]" : /* output */[gs] "=rm"(gs));
  return gs;
}

static inline uint16_t get_tr(void) {
  uint16_t tr;

  __asm__ __volatile__("str %[tr]" : /* output */[tr] "=rm"(tr));
  return tr;
}

static inline uint64_t get_cr0(void) {
  uint64_t cr0;

  __asm__ __volatile__("mov %%cr0, %[cr0]" : /* output */[cr0] "=r"(cr0));
  return cr0;
}

static inline uint64_t get_cr3(void) {
  uint64_t cr3;

  __asm__ __volatile__("mov %%cr3, %[cr3]" : /* output */[cr3] "=r"(cr3));
  return cr3;
}

static inline uint64_t get_cr4(void) {
  uint64_t cr4;

  __asm__ __volatile__("mov %%cr4, %[cr4]" : /* output */[cr4] "=r"(cr4));
  return cr4;
}

static inline void set_cr4(uint64_t val) {
  __asm__ __volatile__("mov %0, %%cr4" : : "r"(val) : "memory");
}

static inline void get_gdt(struct desc_ptr* gdt) {
  __asm__ __volatile__("sgdt %[gdt]" : /* output */[gdt] "=m"(*gdt));
}

static inline void get_idt(struct desc_ptr* idt) {
  __asm__ __volatile__("sidt %[idt]" : /* output */[idt] "=m"(*idt));
}

static inline bool isMemTypeValidMTRR(unsigned memtype) {
  switch (memtype) {
    case BX_MEMTYPE_UC:
    case BX_MEMTYPE_WC:
    case BX_MEMTYPE_WT:
    case BX_MEMTYPE_WP:
    case BX_MEMTYPE_WB:
      return true;
    default:
      return false;
  }
}

static inline bool IsValidPhyAddr(uint64_t addr) {
  return ((addr & BX_PHY_ADDRESS_RESERVED_BITS) == 0);
}

static inline bool isMemTypeValidPAT(unsigned memtype) {
  return (memtype == 0x07) /* UC- */ || isMemTypeValidMTRR(memtype);
}

static inline bool isValidMSR_PAT(uint64_t pat_val) {
  // use packed register as 64-bit value with convinient accessors
  uint64_t pat_msr = pat_val;
  for (unsigned i = 0; i < 8; i++)
    if (!isMemTypeValidPAT((pat_msr >> 8 * i) & 0xFF))
      return false;

  return true;
}

static inline bool long_mode(void) {
#if BX_SUPPORT_X86_64
  uint64_t efer = rdmsr(MSR_EFER);
  return efer & EFER_LMA;
#else
  return 0;
#endif
}

/*
 * Issue a Hyper-V hypercall. Returns exception vector raised or 0, 'hv_status'
 * is set to the hypercall status (if no exception occurred).
 */
static inline uint8_t __hyperv_hypercall(uint64_t control,
                                         uint64_t input_address,
                                         uint64_t output_address,
                                         uint64_t* hv_status) {
  uint64_t error_code;
  uint8_t vector;

  /* Note both the hypercall and the "asm safe" clobber r9-r11. */
  asm volatile("mov %[output_address], %%r8\n\t" KVM_ASM_SAFE("vmcall")
               : "=a"(*hv_status), "+c"(control), "+d"(input_address),
                 KVM_ASM_SAFE_OUTPUTS(vector, error_code)
               : [output_address] "r"(output_address), "a"(-1)
               : "cc", "memory", "r8", KVM_ASM_SAFE_CLOBBERS);
  return vector;
}

void print_vmcb_control(struct svm_test_data *svm);
void print_vmcb_save(struct svm_test_data *svm);