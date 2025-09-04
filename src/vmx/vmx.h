/////////////////////////////////////////////////////////////////////////
// $Id: vmx.h 14086 2021-01-30 08:35:35Z sshwarts $
/////////////////////////////////////////////////////////////////////////
//
//   Copyright (c) 2009-2019 Stanislav Shwartsman
//          Written by Stanislav Shwartsman [sshwarts at sourceforge net]
//
//  This library is free software; you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public
//  License as published by the Free Software Foundation; either
//  version 2 of the License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA B 02110-1301 USA
//
/////////////////////////////////////////////////////////////////////////
#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "../common/cpu.h"
#include "../common/uefi.h"

extern struct hv_enlightened_vmcs* current_evmcs;
extern struct hv_vp_assist_page* current_vp_assist;
extern uint64_t vmxonptr;

extern uint64_t restore_vmcs[200];
extern uint8_t vmcs[4096] __attribute__((aligned(4096)));
extern uint8_t shadow_vmcs[4096] __attribute__((aligned(4096)));
extern uint8_t vmxon_region[4096] __attribute__((aligned(4096)));
extern uint64_t msr_load[1024] __attribute__((aligned(4096)));
extern uint64_t msr_store[1024] __attribute__((aligned(4096)));
extern uint64_t vmentry_msr_load[1024] __attribute__((aligned(4096)));

extern uint8_t host_stack[4096] __attribute__((aligned(4096)));
extern uint8_t guest_stack[4096] __attribute__((aligned(4096)));
extern uint8_t vp_assist[4096] __attribute__((aligned(4096)));
extern uint8_t tss[4096] __attribute__((aligned(4096)));
extern uint8_t io_bitmap_a[4096] __attribute__((aligned(4096)));
extern uint8_t io_bitmap_b[4096] __attribute__((aligned(4096)));
extern uint8_t msr_bitmap[4096] __attribute__((aligned(4096)));
extern uint8_t vmread_bitmap[4096] __attribute__((aligned(4096)));
extern uint8_t vmwrite_bitmap[4096] __attribute__((aligned(4096)));
extern uint8_t apic_access[4096] __attribute__((aligned(4096)));
extern uint8_t virtual_apic[4096] __attribute__((aligned(4096)));
extern uint64_t eptp_list[512] __attribute__((aligned(4096)));

static inline int evmcs_vmwrite(uint64_t encoding, uint64_t value);
static inline int evmcs_vmread(uint64_t encoding, uint64_t* value);

extern const unsigned short* VMX_vmexit_reason_name[];

typedef struct {
  uint64_t ptr;
  uint64_t rsvd;
} invept_t;
typedef struct {
  uint64_t vpid : 16;
  uint64_t rsvd : 48;
  uint64_t gva;
} invvpid_t;

static inline uint64_t vmread(uint32_t index) {
  uint64_t value;
  if (current_evmcs) {
    evmcs_vmread(index, &value);
  } else {
    asm volatile("vmread %%rax, %%rdx" : "=d"(value) : "a"(index) : "cc");
  }
  return value;
}

static inline void vmwrite(uint32_t index, uint64_t value) {
  if (current_evmcs) {
    evmcs_vmwrite(index, value);
  } else {
    asm volatile("vmwrite %%rdx, %%rax"
                 :
                 : "a"(index), "d"(value)
                 : "cc", "memory");
  }
}

static inline uint64_t rdtsc(void) {
  uint32_t eax, edx;
  asm volatile("rdtsc" : "=a"(eax), "=d"(edx));
  return (uint64_t)edx << 32 | (uint64_t)eax;
}

static inline uint64_t vmcall(uint64_t arg) {
  uint64_t ret;
  asm volatile("vmcall"
               : "=a"(ret)
               : "c"(arg)
               : "memory", "rdx", "r8", "r9", "r10", "r11");
  return ret;
}
static inline void vmclear(uint64_t* arg) {
  asm volatile("vmclear %0" : : "m"(arg) : "cc");
}
static inline void vmptrld(uint64_t* arg) {
  asm volatile("vmptrld %0" : : "m"(arg) : "cc");
}
static inline void vmptrst(uint64_t* arg) {
  if (current_evmcs) {
    *arg = (uint64_t)current_evmcs & ~((uint64_t)1);
  } else {
    asm volatile("vmptrst %0" : : "m"(*arg) : "cc");
  }
}
static inline void invept(uint64_t type, const invept_t* i) {
  asm volatile(".byte 0x66, 0x0f, 0x38, 0x80, 0x0A"
               :
               : "c"(type), "d"(i)
               : "cc", "memory");
}
static inline void invvpid(uint64_t type, const invvpid_t* i) {
  asm volatile(".byte 0x66, 0x0f, 0x38, 0x81, 0x0A"
               :
               : "c"(type), "d"(i)
               : "cc", "memory");
}

#define BX_SUPPORT_VMX 2
#define BX_SUPPORT_X86_64 1
#define BX_SUPPORT_CET 0
#define BX_SUPPORT_PKEYS 0
#define BX_CPU_LEVEL 6

#if BX_SUPPORT_X86_64
typedef uint64_t bx_address;
#define BX_LIN_ADDRESS_WIDTH 48
#else
typedef uint32_t bx_address;
#define BX_LIN_ADDRESS_WIDTH 32
#endif

#if BX_PHY_ADDRESS_LONG
typedef uint64_t bx_phy_address;
#if BX_CPU_LEVEL == 5
#define BX_PHY_ADDRESS_WIDTH 36
#else
#define BX_PHY_ADDRESS_WIDTH 40
#endif
#else
typedef uint32_t bx_phy_address;
#define BX_PHY_ADDRESS_WIDTH 32
#endif

#define BX_CPU_HANDLED_EXCEPTIONS 32
#define BX_PHY_ADDRESS_MASK ((((uint64_t)(1)) << BX_PHY_ADDRESS_WIDTH) - 1)
#define BX_PHY_ADDRESS_RESERVED_BITS (~BX_PHY_ADDRESS_MASK)

// VMCS pointer is always 64-bit variable
#define BX_INVALID_VMCSPTR 0xFFFFFFFFFFFFFFFF

struct BxExceptionInfo {
  unsigned exception_type;
  unsigned exception_class;
  bool push_error;
};

enum {
  BX_ET_BENIGN = 0,
  BX_ET_CONTRIBUTORY = 1,
  BX_ET_PAGE_FAULT = 2,
  BX_ET_DOUBLE_FAULT = 10
};

enum {
  BX_EXCEPTION_CLASS_TRAP = 0,
  BX_EXCEPTION_CLASS_FAULT = 1,
  BX_EXCEPTION_CLASS_ABORT = 2
};

// VMX error codes
enum VMX_error_code {
  VMXERR_NO_ERROR = 0,
  VMXERR_VMCALL_IN_VMX_ROOT_OPERATION = 1,
  VMXERR_VMCLEAR_WITH_INVALID_ADDR = 2,
  VMXERR_VMCLEAR_WITH_VMXON_VMCS_PTR = 3,
  VMXERR_VMLAUNCH_NON_CLEAR_VMCS = 4,
  VMXERR_VMRESUME_NON_LAUNCHED_VMCS = 5,
  VMXERR_VMRESUME_VMCS_CORRUPTED = 6,
  VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD = 7,
  VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD = 8,
  VMXERR_VMPTRLD_INVALID_PHYSICAL_ADDRESS = 9,
  VMXERR_VMPTRLD_WITH_VMXON_PTR = 10,
  VMXERR_VMPTRLD_INCORRECT_VMCS_REVISION_ID = 11,
  VMXERR_UNSUPPORTED_VMCS_COMPONENT_ACCESS = 12,
  VMXERR_VMWRITE_READ_ONLY_VMCS_COMPONENT = 13,
  VMXERR_RESERVED14 = 14,
  VMXERR_VMXON_IN_VMX_ROOT_OPERATION = 15,
  VMXERR_VMENTRY_INVALID_EXECUTIVE_VMCS = 16,
  VMXERR_VMENTRY_NON_LAUNCHED_EXECUTIVE_VMCS = 17,
  VMXERR_VMENTRY_NOT_VMXON_EXECUTIVE_VMCS = 18,
  VMXERR_VMCALL_NON_CLEAR_VMCS = 19,
  VMXERR_VMCALL_INVALID_VMEXIT_FIELD = 20,
  VMXERR_RESERVED21 = 21,
  VMXERR_VMCALL_INVALID_MSEG_REVISION_ID = 22,
  VMXERR_VMXOFF_WITH_CONFIGURED_SMM_MONITOR = 23,
  VMXERR_VMCALL_WITH_INVALID_SMM_MONITOR_FEATURES = 24,
  VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD_IN_EXECUTIVE_VMCS = 25,
  VMXERR_VMENTRY_MOV_SS_BLOCKING = 26,
  VMXERR_RESERVED27 = 27,
  VMXERR_INVALID_INVEPT_INVVPID = 28
};

enum VMX_vmexit_reason {
  VMX_VMEXIT_EXCEPTION_NMI = 0,
  VMX_VMEXIT_EXTERNAL_INTERRUPT = 1,
  VMX_VMEXIT_TRIPLE_FAULT = 2,
  VMX_VMEXIT_INIT = 3,
  VMX_VMEXIT_SIPI = 4,
  VMX_VMEXIT_IO_SMI = 5,
  VMX_VMEXIT_SMI = 6,
  VMX_VMEXIT_INTERRUPT_WINDOW = 7,
  VMX_VMEXIT_NMI_WINDOW = 8,
  VMX_VMEXIT_TASK_SWITCH = 9,
  VMX_VMEXIT_CPUID = 10,
  VMX_VMEXIT_GETSEC = 11,
  VMX_VMEXIT_HLT = 12,
  VMX_VMEXIT_INVD = 13,
  VMX_VMEXIT_INVLPG = 14,
  VMX_VMEXIT_RDPMC = 15,
  VMX_VMEXIT_RDTSC = 16,
  VMX_VMEXIT_RSM = 17,
  VMX_VMEXIT_VMCALL = 18,
  VMX_VMEXIT_VMCLEAR = 19,
  VMX_VMEXIT_VMLAUNCH = 20,
  VMX_VMEXIT_VMPTRLD = 21,
  VMX_VMEXIT_VMPTRST = 22,
  VMX_VMEXIT_VMREAD = 23,
  VMX_VMEXIT_VMRESUME = 24,
  VMX_VMEXIT_VMWRITE = 25,
  VMX_VMEXIT_VMXOFF = 26,
  VMX_VMEXIT_VMXON = 27,
  VMX_VMEXIT_CR_ACCESS = 28,
  VMX_VMEXIT_DR_ACCESS = 29,
  VMX_VMEXIT_IO_INSTRUCTION = 30,
  VMX_VMEXIT_RDMSR = 31,
  VMX_VMEXIT_WRMSR = 32,
  VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE = 33,
  VMX_VMEXIT_VMENTRY_FAILURE_MSR = 34,
  VMX_VMEXIT_RESERVED35 = 35,
  VMX_VMEXIT_MWAIT = 36,
  VMX_VMEXIT_MONITOR_TRAP_FLAG = 37,
  VMX_VMEXIT_RESERVED38 = 38,
  VMX_VMEXIT_MONITOR = 39,
  VMX_VMEXIT_PAUSE = 40,
  VMX_VMEXIT_VMENTRY_FAILURE_MCA = 41,
  VMX_VMEXIT_RESERVED42 = 42,
  VMX_VMEXIT_TPR_THRESHOLD = 43,
  VMX_VMEXIT_APIC_ACCESS = 44,
  VMX_VMEXIT_VIRTUALIZED_EOI = 45,
  VMX_VMEXIT_GDTR_IDTR_ACCESS = 46,
  VMX_VMEXIT_LDTR_TR_ACCESS = 47,
  VMX_VMEXIT_EPT_VIOLATION = 48,
  VMX_VMEXIT_EPT_MISCONFIGURATION = 49,
  VMX_VMEXIT_INVEPT = 50,
  VMX_VMEXIT_RDTSCP = 51,
  VMX_VMEXIT_VMX_PREEMPTION_TIMER_EXPIRED = 52,
  VMX_VMEXIT_INVVPID = 53,
  VMX_VMEXIT_WBINVD = 54,
  VMX_VMEXIT_XSETBV = 55,
  VMX_VMEXIT_APIC_WRITE = 56,
  VMX_VMEXIT_RDRAND = 57,
  VMX_VMEXIT_INVPCID = 58,
  VMX_VMEXIT_VMFUNC = 59,
  VMX_VMEXIT_ENCLS = 60,
  VMX_VMEXIT_RDSEED = 61,
  VMX_VMEXIT_PML_LOGFULL = 62,
  VMX_VMEXIT_XSAVES = 63,
  VMX_VMEXIT_XRSTORS = 64,
  VMX_VMEXIT_RESERVED65 = 65,
  VMX_VMEXIT_SPP = 66,
  VMX_VMEXIT_UMWAIT = 67,
  VMX_VMEXIT_TPAUSE = 68,
  VMX_VMEXIT_RESERVED69 = 69,
  VMX_VMEXIT_RESERVED70 = 70,
  VMX_VMEXIT_RESERVED71 = 71,
  VMX_VMEXIT_ENQCMD_PASID = 72,
  VMX_VMEXIT_ENQCMDS_PASID = 73,
  VMX_VMEXIT_LAST_REASON
};

// exception types for interrupt method
enum {
  BX_EXTERNAL_INTERRUPT = 0,
  BX_NMI = 2,
  BX_HARDWARE_EXCEPTION = 3,  // all exceptions except #BP and #OF
  BX_SOFTWARE_INTERRUPT = 4,
  BX_PRIVILEGED_SOFTWARE_INTERRUPT = 5,
  BX_SOFTWARE_EXCEPTION = 6
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

enum BX_Exception {
  BX_DE_EXCEPTION = 0,  // Divide Error (fault)
  BX_DB_EXCEPTION = 1,  // Debug (fault/trap)
  BX_BP_EXCEPTION = 3,  // Breakpoint (trap)
  BX_OF_EXCEPTION = 4,  // Overflow (trap)
  BX_BR_EXCEPTION = 5,  // BOUND (fault)
  BX_UD_EXCEPTION = 6,
  BX_NM_EXCEPTION = 7,
  BX_DF_EXCEPTION = 8,
  BX_TS_EXCEPTION = 10,
  BX_NP_EXCEPTION = 11,
  BX_SS_EXCEPTION = 12,
  BX_GP_EXCEPTION = 13,
  BX_PF_EXCEPTION = 14,
  BX_MF_EXCEPTION = 16,
  BX_AC_EXCEPTION = 17,
  BX_MC_EXCEPTION = 18,
  BX_XM_EXCEPTION = 19,
  BX_VE_EXCEPTION = 20,
  BX_CP_EXCEPTION = 21  // Control Protection (fault)
};

// segment register encoding
enum BxSegregs {
  BX_SEG_REG_ES = 0,
  BX_SEG_REG_CS = 1,
  BX_SEG_REG_SS = 2,
  BX_SEG_REG_DS = 3,
  BX_SEG_REG_FS = 4,
  BX_SEG_REG_GS = 5,
  // NULL now has to fit in 3 bits.
  BX_SEG_REG_NULL = 7
};

#define GET32L(val64) ((uint32_t)(((uint64_t)(val64)) & 0xFFFFFFFF))
#define GET32H(val64) ((uint32_t)(((uint64_t)(val64)) >> 32))

// VMENTRY error on loading guest state qualification
enum VMX_vmentry_error {
  VMENTER_ERR_NO_ERROR = 0,
  VMENTER_ERR_GUEST_STATE_PDPTR_LOADING = 2,
  VMENTER_ERR_GUEST_STATE_INJECT_NMI_BLOCKING_EVENTS = 3,
  VMENTER_ERR_GUEST_STATE_LINK_POINTER = 4
};

// VM Functions List
enum VMFunctions { VMX_VMFUNC_EPTP_SWITCHING = 0 };

#define VMX_VMFUNC_EPTP_SWITCHING_MASK (1 << VMX_VMFUNC_EPTP_SWITCHING)

// =============
//  VMCS fields
// =============

/* VMCS 16-bit control fields */
/* binary 0000_00xx_xxxx_xxx0 */
#define VMCS_16BIT_CONTROL_VPID 0x00000000 /* VPID */
#define VMCS_16BIT_CONTROL_POSTED_INTERRUPT_VECTOR \
  0x00000002 /* Posted Interrupts - not implememted yet */
#define VMCS_16BIT_CONTROL_EPTP_INDEX 0x00000004 /* #VE Exception */

/* VMCS 16-bit guest-state fields */
/* binary 0000_10xx_xxxx_xxx0 */
#define VMCS_16BIT_GUEST_ES_SELECTOR 0x00000800
#define VMCS_16BIT_GUEST_CS_SELECTOR 0x00000802
#define VMCS_16BIT_GUEST_SS_SELECTOR 0x00000804
#define VMCS_16BIT_GUEST_DS_SELECTOR 0x00000806
#define VMCS_16BIT_GUEST_FS_SELECTOR 0x00000808
#define VMCS_16BIT_GUEST_GS_SELECTOR 0x0000080A
#define VMCS_16BIT_GUEST_LDTR_SELECTOR 0x0000080C
#define VMCS_16BIT_GUEST_TR_SELECTOR 0x0000080E
#define VMCS_16BIT_GUEST_INTERRUPT_STATUS \
  0x00000810                                  /* Virtual Interrupt Delivery */
#define VMCS_16BIT_GUEST_PML_INDEX 0x00000812 /* Page Modification Logging */

/* VMCS 16-bit host-state fields */
/* binary 0000_11xx_xxxx_xxx0 */
#define VMCS_16BIT_HOST_ES_SELECTOR 0x00000C00
#define VMCS_16BIT_HOST_CS_SELECTOR 0x00000C02
#define VMCS_16BIT_HOST_SS_SELECTOR 0x00000C04
#define VMCS_16BIT_HOST_DS_SELECTOR 0x00000C06
#define VMCS_16BIT_HOST_FS_SELECTOR 0x00000C08
#define VMCS_16BIT_HOST_GS_SELECTOR 0x00000C0A
#define VMCS_16BIT_HOST_TR_SELECTOR 0x00000C0C

/* VMCS 64-bit control fields */
/* binary 0010_00xx_xxxx_xxx0 */
#define VMCS_64BIT_CONTROL_IO_BITMAP_A 0x00002000
#define VMCS_64BIT_CONTROL_IO_BITMAP_A_HI 0x00002001
#define VMCS_64BIT_CONTROL_IO_BITMAP_B 0x00002002
#define VMCS_64BIT_CONTROL_IO_BITMAP_B_HI 0x00002003
#define VMCS_64BIT_CONTROL_MSR_BITMAPS 0x00002004
#define VMCS_64BIT_CONTROL_MSR_BITMAPS_HI 0x00002005
#define VMCS_64BIT_CONTROL_VMEXIT_MSR_STORE_ADDR 0x00002006
#define VMCS_64BIT_CONTROL_VMEXIT_MSR_STORE_ADDR_HI 0x00002007
#define VMCS_64BIT_CONTROL_VMEXIT_MSR_LOAD_ADDR 0x00002008
#define VMCS_64BIT_CONTROL_VMEXIT_MSR_LOAD_ADDR_HI 0x00002009
#define VMCS_64BIT_CONTROL_VMENTRY_MSR_LOAD_ADDR 0x0000200A
#define VMCS_64BIT_CONTROL_VMENTRY_MSR_LOAD_ADDR_HI 0x0000200B
#define VMCS_64BIT_CONTROL_EXECUTIVE_VMCS_PTR 0x0000200C
#define VMCS_64BIT_CONTROL_EXECUTIVE_VMCS_PTR_HI 0x0000200D
#define VMCS_64BIT_CONTROL_PML_ADDRESS \
  0x0000200E /* Page Modification Logging */
#define VMCS_64BIT_CONTROL_PML_ADDRESS_HI 0x0000200F
#define VMCS_64BIT_CONTROL_TSC_OFFSET 0x00002010
#define VMCS_64BIT_CONTROL_TSC_OFFSET_HI 0x00002011
#define VMCS_64BIT_CONTROL_VIRTUAL_APIC_PAGE_ADDR 0x00002012 /* TPR shadow */
#define VMCS_64BIT_CONTROL_VIRTUAL_APIC_PAGE_ADDR_HI 0x00002013
#define VMCS_64BIT_CONTROL_APIC_ACCESS_ADDR \
  0x00002014 /* APIC virtualization         \
              */
#define VMCS_64BIT_CONTROL_APIC_ACCESS_ADDR_HI 0x00002015
#define VMCS_64BIT_CONTROL_POSTED_INTERRUPT_DESC_ADDR \
  0x00002016 /* Posted Interrupts - not implemented yet */
#define VMCS_64BIT_CONTROL_POSTED_INTERRUPT_DESC_ADDR_HI 0x00002017
#define VMCS_64BIT_CONTROL_VMFUNC_CTRLS 0x00002018 /* VM Functions */
#define VMCS_64BIT_CONTROL_VMFUNC_CTRLS_HI 0x00002019
#define VMCS_64BIT_CONTROL_EPTPTR 0x0000201A /* EPT */
#define VMCS_64BIT_CONTROL_EPTPTR_HI 0x0000201B
#define VMCS_64BIT_CONTROL_EOI_EXIT_BITMAP0 \
  0x0000201C /* Virtual Interrupt Delivery */
#define VMCS_64BIT_CONTROL_EOI_EXIT_BITMAP0_HI 0x0000201D
#define VMCS_64BIT_CONTROL_EOI_EXIT_BITMAP1 0x0000201E
#define VMCS_64BIT_CONTROL_EOI_EXIT_BITMAP1_HI 0x0000201F
#define VMCS_64BIT_CONTROL_EOI_EXIT_BITMAP2 0x00002020
#define VMCS_64BIT_CONTROL_EOI_EXIT_BITMAP2_HI 0x00002021
#define VMCS_64BIT_CONTROL_EOI_EXIT_BITMAP3 0x00002022
#define VMCS_64BIT_CONTROL_EOI_EXIT_BITMAP3_HI 0x00002023
#define VMCS_64BIT_CONTROL_EPTP_LIST_ADDRESS \
  0x00002024 /* VM Functions - EPTP switching */
#define VMCS_64BIT_CONTROL_EPTP_LIST_ADDRESS_HI 0x00002025
#define VMCS_64BIT_CONTROL_VMREAD_BITMAP_ADDR 0x00002026 /* VMCS Shadowing */
#define VMCS_64BIT_CONTROL_VMREAD_BITMAP_ADDR_HI 0x00002027
#define VMCS_64BIT_CONTROL_VMWRITE_BITMAP_ADDR 0x00002028 /* VMCS Shadowing */
#define VMCS_64BIT_CONTROL_VMWRITE_BITMAP_ADDR_HI 0x00002029
#define VMCS_64BIT_CONTROL_VE_EXCEPTION_INFO_ADDR \
  0x0000202A /* #VE Exception                     \
              */
#define VMCS_64BIT_CONTROL_VE_EXCEPTION_INFO_ADDR_HI 0x0000202B
#define VMCS_64BIT_CONTROL_XSS_EXITING_BITMAP 0x0000202C /* XSAVES */
#define VMCS_64BIT_CONTROL_XSS_EXITING_BITMAP_HI 0x0000202D
#define VMCS_64BIT_CONTROL_ENCLS_EXITING_BITMAP 0x0000202E /* ENCLS/SGX */
#define VMCS_64BIT_CONTROL_ENCLS_EXITING_BITMAP_HI 0x0000202F
#define VMCS_64BIT_CONTROL_SPPTP 0x00002030 /* Sup-Page Write Protection */
#define VMCS_64BIT_CONTROL_SPPTP_HI 0x00002031
#define VMCS_64BIT_CONTROL_TSC_MULTIPLIER 0x00002032 /* TSC Scaling */
#define VMCS_64BIT_CONTROL_TSC_MULTIPLIER_HI 0x00002033

/* VMCS 64-bit read only data fields */
/* binary 0010_01xx_xxxx_xxx0 */
#define VMCS_64BIT_GUEST_PHYSICAL_ADDR 0x00002400 /* EPT */
#define VMCS_64BIT_GUEST_PHYSICAL_ADDR_HI 0x00002401

/* VMCS 64-bit guest state fields */
/* binary 0010_10xx_xxxx_xxx0 */
#define VMCS_64BIT_GUEST_LINK_POINTER 0x00002800
#define VMCS_64BIT_GUEST_LINK_POINTER_HI 0x00002801
#define VMCS_64BIT_GUEST_IA32_DEBUGCTL 0x00002802
#define VMCS_64BIT_GUEST_IA32_DEBUGCTL_HI 0x00002803
#define VMCS_64BIT_GUEST_IA32_PAT 0x00002804 /* PAT */
#define VMCS_64BIT_GUEST_IA32_PAT_HI 0x00002805
#define VMCS_64BIT_GUEST_IA32_EFER 0x00002806 /* EFER */
#define VMCS_64BIT_GUEST_IA32_EFER_HI 0x00002807
#define VMCS_64BIT_GUEST_IA32_PERF_GLOBAL_CTRL \
  0x00002808 /* Perf Global Ctrl               \
              */
#define VMCS_64BIT_GUEST_IA32_PERF_GLOBAL_CTRL_HI 0x00002809
#define VMCS_64BIT_GUEST_IA32_PDPTE0 0x0000280A /* EPT */
#define VMCS_64BIT_GUEST_IA32_PDPTE0_HI 0x0000280B
#define VMCS_64BIT_GUEST_IA32_PDPTE1 0x0000280C
#define VMCS_64BIT_GUEST_IA32_PDPTE1_HI 0x0000280D
#define VMCS_64BIT_GUEST_IA32_PDPTE2 0x0000280E
#define VMCS_64BIT_GUEST_IA32_PDPTE2_HI 0x0000280F
#define VMCS_64BIT_GUEST_IA32_PDPTE3 0x00002810
#define VMCS_64BIT_GUEST_IA32_PDPTE3_HI 0x00002811
#define VMCS_64BIT_GUEST_IA32_BNDCFGS 0x00002812 /* MPX (not implemented) */
#define VMCS_64BIT_GUEST_IA32_BNDCFGS_HI 0x00002813
#define VMCS_64BIT_GUEST_IA32_RTIT_CTL \
  0x00002814 /* Processor Trace (not implemented) */
#define VMCS_64BIT_GUEST_IA32_RTIT_CTL_HI 0x00002815
#define VMCS_64BIT_GUEST_IA32_PKRS \
  0x00002818 /* Supervisor-Mode Protection Keys */
#define VMCS_64BIT_GUEST_IA32_PKRS_HI 0x00002819

/* VMCS 64-bit host state fields */
/* binary 0010_11xx_xxxx_xxx0 */
#define VMCS_64BIT_HOST_IA32_PAT 0x00002C00 /* PAT */
#define VMCS_64BIT_HOST_IA32_PAT_HI 0x00002C01
#define VMCS_64BIT_HOST_IA32_EFER 0x00002C02 /* EFER */
#define VMCS_64BIT_HOST_IA32_EFER_HI 0x00002C03
#define VMCS_64BIT_HOST_IA32_PERF_GLOBAL_CTRL \
  0x00002C04 /* Perf Global Ctrl              \
              */
#define VMCS_64BIT_HOST_IA32_PERF_GLOBAL_CTRL_HI 0x00002C05
#define VMCS_64BIT_HOST_IA32_PKRS \
  0x00002C06 /* Supervisor-Mode Protection Keys */
#define VMCS_64BIT_HOST_IA32_PKRS_HI 0x00002C07

/* VMCS 32_bit control fields */
/* binary 0100_00xx_xxxx_xxx0 */
#define VMCS_32BIT_CONTROL_PIN_BASED_EXEC_CONTROLS 0x00004000
#define VMCS_32BIT_CONTROL_PROCESSOR_BASED_VMEXEC_CONTROLS 0x00004002
#define VMCS_32BIT_CONTROL_EXECUTION_BITMAP 0x00004004
#define VMCS_32BIT_CONTROL_PAGE_FAULT_ERR_CODE_MASK 0x00004006
#define VMCS_32BIT_CONTROL_PAGE_FAULT_ERR_CODE_MATCH 0x00004008
#define VMCS_32BIT_CONTROL_CR3_TARGET_COUNT 0x0000400A
#define VMCS_32BIT_CONTROL_VMEXIT_CONTROLS 0x0000400C
#define VMCS_32BIT_CONTROL_VMEXIT_MSR_STORE_COUNT 0x0000400E
#define VMCS_32BIT_CONTROL_VMEXIT_MSR_LOAD_COUNT 0x00004010
#define VMCS_32BIT_CONTROL_VMENTRY_CONTROLS 0x00004012
#define VMCS_32BIT_CONTROL_VMENTRY_MSR_LOAD_COUNT 0x00004014
#define VMCS_32BIT_CONTROL_VMENTRY_INTERRUPTION_INFO 0x00004016
#define VMCS_32BIT_CONTROL_VMENTRY_EXCEPTION_ERR_CODE 0x00004018
#define VMCS_32BIT_CONTROL_VMENTRY_INSTRUCTION_LENGTH 0x0000401A
#define VMCS_32BIT_CONTROL_TPR_THRESHOLD 0x0000401C /* TPR shadow */
#define VMCS_32BIT_CONTROL_SECONDARY_VMEXEC_CONTROLS 0x0000401E
#define VMCS_32BIT_CONTROL_PAUSE_LOOP_EXITING_GAP \
  0x00004020 /* PAUSE loop exiting */
#define VMCS_32BIT_CONTROL_PAUSE_LOOP_EXITING_WINDOW \
  0x00004022 /* PAUSE loop exiting */

/* VMCS 32-bit read only data fields */
/* binary 0100_01xx_xxxx_xxx0 */
#define VMCS_32BIT_INSTRUCTION_ERROR 0x00004400
#define VMCS_32BIT_VMEXIT_REASON 0x00004402
#define VMCS_32BIT_VMEXIT_INTERRUPTION_INFO 0x00004404
#define VMCS_32BIT_VMEXIT_INTERRUPTION_ERR_CODE 0x00004406
#define VMCS_32BIT_IDT_VECTORING_INFO 0x00004408
#define VMCS_32BIT_IDT_VECTORING_ERR_CODE 0x0000440A
#define VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH 0x0000440C
#define VMCS_32BIT_VMEXIT_INSTRUCTION_INFO 0x0000440E

/* VMCS 32-bit guest-state fields */
/* binary 0100_10xx_xxxx_xxx0 */
#define VMCS_32BIT_GUEST_ES_LIMIT 0x00004800
#define VMCS_32BIT_GUEST_CS_LIMIT 0x00004802
#define VMCS_32BIT_GUEST_SS_LIMIT 0x00004804
#define VMCS_32BIT_GUEST_DS_LIMIT 0x00004806
#define VMCS_32BIT_GUEST_FS_LIMIT 0x00004808
#define VMCS_32BIT_GUEST_GS_LIMIT 0x0000480A
#define VMCS_32BIT_GUEST_LDTR_LIMIT 0x0000480C
#define VMCS_32BIT_GUEST_TR_LIMIT 0x0000480E
#define VMCS_32BIT_GUEST_GDTR_LIMIT 0x00004810
#define VMCS_32BIT_GUEST_IDTR_LIMIT 0x00004812
#define VMCS_32BIT_GUEST_ES_ACCESS_RIGHTS 0x00004814
#define VMCS_32BIT_GUEST_CS_ACCESS_RIGHTS 0x00004816
#define VMCS_32BIT_GUEST_SS_ACCESS_RIGHTS 0x00004818
#define VMCS_32BIT_GUEST_DS_ACCESS_RIGHTS 0x0000481A
#define VMCS_32BIT_GUEST_FS_ACCESS_RIGHTS 0x0000481C
#define VMCS_32BIT_GUEST_GS_ACCESS_RIGHTS 0x0000481E
#define VMCS_32BIT_GUEST_LDTR_ACCESS_RIGHTS 0x00004820
#define VMCS_32BIT_GUEST_TR_ACCESS_RIGHTS 0x00004822
#define VMCS_32BIT_GUEST_INTERRUPTIBILITY_STATE 0x00004824
#define VMCS_32BIT_GUEST_ACTIVITY_STATE 0x00004826
#define VMCS_32BIT_GUEST_SMBASE 0x00004828
#define VMCS_32BIT_GUEST_IA32_SYSENTER_CS_MSR 0x0000482A
#define VMCS_32BIT_GUEST_PREEMPTION_TIMER_VALUE \
  0x0000482E /* VMX preemption timer */

/* VMCS 32-bit host-state fields */
/* binary 0100_11xx_xxxx_xxx0 */
#define VMCS_32BIT_HOST_IA32_SYSENTER_CS_MSR 0x00004C00

/* VMCS natural width control fields */
/* binary 0110_00xx_xxxx_xxx0 */
#define VMCS_CONTROL_CR0_GUEST_HOST_MASK 0x00006000
#define VMCS_CONTROL_CR4_GUEST_HOST_MASK 0x00006002
#define VMCS_CONTROL_CR0_READ_SHADOW 0x00006004
#define VMCS_CONTROL_CR4_READ_SHADOW 0x00006006
#define VMCS_CR3_TARGET0 0x00006008
#define VMCS_CR3_TARGET1 0x0000600A
#define VMCS_CR3_TARGET2 0x0000600C
#define VMCS_CR3_TARGET3 0x0000600E

/* VMCS natural width read only data fields */
/* binary 0110_01xx_xxxx_xxx0 */
#define VMCS_VMEXIT_QUALIFICATION 0x00006400
#define VMCS_IO_RCX 0x00006402
#define VMCS_IO_RSI 0x00006404
#define VMCS_IO_RDI 0x00006406
#define VMCS_IO_RIP 0x00006408
#define VMCS_GUEST_LINEAR_ADDR 0x0000640A

/* VMCS natural width guest state fields */
/* binary 0110_10xx_xxxx_xxx0 */
#define VMCS_GUEST_CR0 0x00006800
#define VMCS_GUEST_CR3 0x00006802
#define VMCS_GUEST_CR4 0x00006804
#define VMCS_GUEST_ES_BASE 0x00006806
#define VMCS_GUEST_CS_BASE 0x00006808
#define VMCS_GUEST_SS_BASE 0x0000680A
#define VMCS_GUEST_DS_BASE 0x0000680C
#define VMCS_GUEST_FS_BASE 0x0000680E
#define VMCS_GUEST_GS_BASE 0x00006810
#define VMCS_GUEST_LDTR_BASE 0x00006812
#define VMCS_GUEST_TR_BASE 0x00006814
#define VMCS_GUEST_GDTR_BASE 0x00006816
#define VMCS_GUEST_IDTR_BASE 0x00006818
#define VMCS_GUEST_DR7 0x0000681A
#define VMCS_GUEST_RSP 0x0000681C
#define VMCS_GUEST_RIP 0x0000681E
#define VMCS_GUEST_RFLAGS 0x00006820
#define VMCS_GUEST_PENDING_DBG_EXCEPTIONS 0x00006822
#define VMCS_GUEST_IA32_SYSENTER_ESP_MSR 0x00006824
#define VMCS_GUEST_IA32_SYSENTER_EIP_MSR 0x00006826
#define VMCS_GUEST_IA32_S_CET 0x00006828
#define VMCS_GUEST_SSP 0x0000682A
#define VMCS_GUEST_INTERRUPT_SSP_TABLE_ADDR 0x0000682C

/* VMCS natural width host state fields */
/* binary 0110_11xx_xxxx_xxx0 */
#define VMCS_HOST_CR0 0x00006C00
#define VMCS_HOST_CR3 0x00006C02
#define VMCS_HOST_CR4 0x00006C04
#define VMCS_HOST_FS_BASE 0x00006C06
#define VMCS_HOST_GS_BASE 0x00006C08
#define VMCS_HOST_TR_BASE 0x00006C0A
#define VMCS_HOST_GDTR_BASE 0x00006C0C
#define VMCS_HOST_IDTR_BASE 0x00006C0E
#define VMCS_HOST_IA32_SYSENTER_ESP_MSR 0x00006C10
#define VMCS_HOST_IA32_SYSENTER_EIP_MSR 0x00006C12
#define VMCS_HOST_RSP 0x00006C14
#define VMCS_HOST_RIP 0x00006C16
#define VMCS_HOST_IA32_S_CET 0x00006C18
#define VMCS_HOST_SSP 0x00006C1A
#define VMCS_HOST_INTERRUPT_SSP_TABLE_ADDR 0x00006C1C

#define VMX_HIGHEST_VMCS_ENCODING (0x34)

// ===============================
//  VMCS fields encoding/decoding
// ===============================

// extract VMCS field using its encoding
#define VMCS_FIELD(encoding) ((encoding)&0x3ff)

// check if the VMCS field encoding corresponding to HI part of 64-bit value
#define IS_VMCS_FIELD_HI(encoding) ((encoding)&1)

// bits 11:10 of VMCS field encoding indicate field's type
#define VMCS_FIELD_TYPE(encoding) (((encoding) >> 10) & 3)

enum {
  VMCS_FIELD_TYPE_CONTROL = 0x0,
  VMCS_FIELD_TYPE_READ_ONLY = 0x1,
  VMCS_FIELD_TYPE_GUEST_STATE = 0x2,
  VMCS_FIELD_TYPE_HOST_STATE = 0x3
};

// bits 14:13 of VMCS field encoding indicate field's width
#define VMCS_FIELD_WIDTH(encoding) (((encoding) >> 13) & 3)

enum {
  VMCS_FIELD_WIDTH_16BIT = 0x0,
  VMCS_FIELD_WIDTH_64BIT = 0x1,
  VMCS_FIELD_WIDTH_32BIT = 0x2,
  VMCS_FIELD_WIDTH_NATURAL_WIDTH = 0x3
};

#define VMCS_FIELD_INDEX(encoding) \
  ((VMCS_FIELD_WIDTH(encoding) << 2) + VMCS_FIELD_TYPE(encoding))

// const uint32_t VMCS_ENCODING_RESERVED_BITS = 0xffff9000;
#define VMCS_ENCODING_RESERVED_BITS 0xffff9000;
enum CPU_Activity_State {
  BX_ACTIVITY_STATE_ACTIVE = 0,
  BX_ACTIVITY_STATE_HLT,
  BX_ACTIVITY_STATE_SHUTDOWN,
  BX_ACTIVITY_STATE_WAIT_FOR_SIPI,
  BX_ACTIVITY_STATE_MWAIT,
  BX_ACTIVITY_STATE_MWAIT_IF
};

#define BX_VMX_LAST_ACTIVITY_STATE (BX_ACTIVITY_STATE_WAIT_FOR_SIPI)
// =============
//  VMCS layout
// =============

#define BX_VMX_VMCS_REVISION_ID \
  0x2B /* better to be unique bochs VMCS revision id */

enum VMCS_Access_Rights_Format {
  VMCS_AR_ROTATE,
  VMCS_AR_PACK  // Intel Skylake packs AR into 16 bit form
};

#define VMCS_LAUNCH_STATE_FIELD_ENCODING (0xfffffffe)
#define VMCS_VMX_ABORT_FIELD_ENCODING (0xfffffffc)
#define VMCS_REVISION_ID_FIELD_ENCODING (0xfffffffa)

#define VMCS_DATA_OFFSET (0x0010)

// =============
//  VMCS state
// =============

enum VMX_state { VMCS_STATE_CLEAR = 0, VMCS_STATE_LAUNCHED };

// ================
//  VMCS structure
// ================
typedef struct {  /* bx_selector_t */
  uint16_t value; /* the 16bit value of the selector */
  /* the following fields are extracted from the value field in protected
     mode only.  They're used for sake of efficiency */
  uint16_t index; /* 13bit index extracted from value in protected mode */
  uint8_t ti;     /* table indicator bit extracted from value */
  uint8_t rpl;    /* RPL extracted from value */
} bx_selector_t;

typedef struct {
#define SegValidCache (0x01)
#define SegAccessROK (0x02)
#define SegAccessWOK (0x04)
#define SegAccessROK4G (0x08)
#define SegAccessWOK4G (0x10)
  unsigned valid;  // Holds above values, Or'd together. Used to
                   // hold only 0 or 1 once.

  bool p;       /* present */
  uint8_t dpl;  /* descriptor privilege level 0..3 */
  bool segment; /* 0 = system/gate, 1 = data/code segment */
  uint8_t type; /* For system & gate descriptors:
                 *  0 = invalid descriptor (reserved)
                 *  1 = 286 available Task State Segment (TSS)
                 *  2 = LDT descriptor
                 *  3 = 286 busy Task State Segment (TSS)
                 *  4 = 286 call gate
                 *  5 = task gate
                 *  6 = 286 interrupt gate
                 *  7 = 286 trap gate
                 *  8 = (reserved)
                 *  9 = 386 available TSS
                 * 10 = (reserved)
                 * 11 = 386 busy TSS
                 * 12 = 386 call gate
                 * 13 = (reserved)
                 * 14 = 386 interrupt gate
                 * 15 = 386 trap gate */

  // For system & gate descriptors:

#define BX_GATE_TYPE_NONE (0x0)
#define BX_SYS_SEGMENT_AVAIL_286_TSS (0x1)
#define BX_SYS_SEGMENT_LDT (0x2)
#define BX_SYS_SEGMENT_BUSY_286_TSS (0x3)
#define BX_286_CALL_GATE (0x4)
#define BX_TASK_GATE (0x5)
#define BX_286_INTERRUPT_GATE (0x6)
#define BX_286_TRAP_GATE (0x7)
  /* 0x8 reserved */
#define BX_SYS_SEGMENT_AVAIL_386_TSS (0x9)
  /* 0xa reserved */
#define BX_SYS_SEGMENT_BUSY_386_TSS (0xb)
#define BX_386_CALL_GATE (0xc)
  /* 0xd reserved */
#define BX_386_INTERRUPT_GATE (0xe)
#define BX_386_TRAP_GATE (0xf)

  // For data/code descriptors:

#define BX_DATA_READ_ONLY (0x0)
#define BX_DATA_READ_ONLY_ACCESSED (0x1)
#define BX_DATA_READ_WRITE (0x2)
#define BX_DATA_READ_WRITE_ACCESSED (0x3)
#define BX_DATA_READ_ONLY_EXPAND_DOWN (0x4)
#define BX_DATA_READ_ONLY_EXPAND_DOWN_ACCESSED (0x5)
#define BX_DATA_READ_WRITE_EXPAND_DOWN (0x6)
#define BX_DATA_READ_WRITE_EXPAND_DOWN_ACCESSED (0x7)
#define BX_CODE_EXEC_ONLY (0x8)
#define BX_CODE_EXEC_ONLY_ACCESSED (0x9)
#define BX_CODE_EXEC_READ (0xa)
#define BX_CODE_EXEC_READ_ACCESSED (0xb)
#define BX_CODE_EXEC_ONLY_CONFORMING (0xc)
#define BX_CODE_EXEC_ONLY_CONFORMING_ACCESSED (0xd)
#define BX_CODE_EXEC_READ_CONFORMING (0xe)
#define BX_CODE_EXEC_READ_CONFORMING_ACCESSED (0xf)

  union {
    struct {
      bx_address base;       /* base address: 286=24bits, 386=32bits, long=64 */
      uint32_t limit_scaled; /* for efficiency, this contrived field is set to
                              * limit for byte granular, and
                              * (limit << 12) | 0xfff for page granular seg's
                              */
      bool g;                /* granularity: 0=byte, 1=4K (page) */
      bool d_b;              /* default size: 0=16bit, 1=32bit */
#if BX_SUPPORT_X86_64
      bool l; /* long mode: 0=compat, 1=64 bit */
#endif
      bool avl; /* available for use by system */
    } segment;
    struct {
      uint8_t param_count; /* 5bits (0..31) #words/dword to copy from caller's
                            * stack to called procedure's stack. */
      uint16_t dest_selector;
      uint32_t dest_offset;
    } gate;
    struct {                 /* type 5: Task Gate Descriptor */
      uint16_t tss_selector; /* TSS segment selector */
    } taskgate;
  } u;

} bx_descriptor_t;

typedef struct {
  bx_selector_t selector;
  bx_descriptor_t cache;
} bx_segment_reg_t;

typedef struct {
  bx_address base; /* base address: 24bits=286,32bits=386,64bits=x86-64 */
  uint16_t limit;  /* limit, 16bits */
} bx_global_segment_reg_t;

typedef struct bx_VMCS_GUEST_STATE {
  bx_address cr0;
  bx_address cr3;
  bx_address cr4;
  bx_address dr7;

  bx_address rip;
  bx_address rsp;
  bx_address rflags;

  bx_segment_reg_t sregs[6];

  bx_global_segment_reg_t gdtr;
  bx_global_segment_reg_t idtr;
  bx_segment_reg_t ldtr;
  bx_segment_reg_t tr;

  uint64_t ia32_debugctl_msr;
  bx_address sysenter_esp_msr;
  bx_address sysenter_eip_msr;
  uint32_t sysenter_cs_msr;

  uint32_t smbase;
  uint32_t activity_state;
  uint32_t interruptibility_state;
  uint32_t tmpDR6;

#if BX_SUPPORT_VMX >= 2
#if BX_SUPPORT_X86_64
  uint64_t efer_msr;
#endif
  uint64_t pat_msr;
  uint64_t pdptr[4];
#endif

#if BX_SUPPORT_CET
  uint64_t msr_ia32_s_cet;
  bx_address ssp;
  bx_address interrupt_ssp_table_address;
#endif

#if BX_SUPPORT_PKEYS
  uint32_t pkrs;
#endif
} VMCS_GUEST_STATE;

typedef struct bx_VMCS_HOST_STATE {
  bx_address cr0;
  bx_address cr3;
  bx_address cr4;

  uint16_t segreg_selector[6];

  bx_address fs_base;
  bx_address gs_base;

  bx_address gdtr_base;
  bx_address idtr_base;

  uint32_t tr_selector;
  bx_address tr_base;

  bx_address rsp;
  bx_address rip;

  bx_address sysenter_esp_msr;
  bx_address sysenter_eip_msr;
  uint32_t sysenter_cs_msr;

#if BX_SUPPORT_VMX >= 2
#if BX_SUPPORT_X86_64
  uint64_t efer_msr;
#endif
  uint64_t pat_msr;
#endif

#if BX_SUPPORT_CET
  uint64_t msr_ia32_s_cet;
  bx_address ssp;
  bx_address interrupt_ssp_table_address;
#endif

#if BX_SUPPORT_PKEYS
  uint32_t pkrs;
#endif
} VMCS_HOST_STATE;

typedef struct bx_VMX_Cap {
  //
  // VMX Capabilities
  //

  uint32_t vmx_pin_vmexec_ctrl_supported_bits;
  uint32_t vmx_proc_vmexec_ctrl_supported_bits;
  uint32_t vmx_vmexec_ctrl2_supported_bits;
  uint32_t vmx_vmexit_ctrl_supported_bits;
  uint32_t vmx_vmentry_ctrl_supported_bits;
#if BX_SUPPORT_VMX >= 2
  uint64_t vmx_ept_vpid_cap_supported_bits;
  uint64_t vmx_vmfunc_supported_bits;
#endif
} VMX_CAP;

#if BX_SUPPORT_VMX >= 2

// used for pause loop exiting
struct VMX_PLE {
  uint32_t pause_loop_exiting_gap;
  uint32_t pause_loop_exiting_window;
  uint64_t last_pause_time;
  uint64_t first_pause_time;
};

#endif

typedef struct bx_VMCS {
  //
  // VM-Execution Control Fields
  //

#define VMX_VM_EXEC_CTRL1_EXTERNAL_INTERRUPT_VMEXIT (1 << 0)
#define VMX_VM_EXEC_CTRL1_NMI_EXITING (1 << 3)
#define VMX_VM_EXEC_CTRL1_VIRTUAL_NMI (1 << 5) /* Virtual NMI */
#define VMX_VM_EXEC_CTRL1_VMX_PREEMPTION_TIMER_VMEXIT \
  (1 << 6) /* VMX preemption timer */
#define VMX_VM_EXEC_CTRL1_PROCESS_POSTED_INTERRUPTS \
  (1 << 7) /* Posted Interrupts (not implemented) */

#define VMX_VM_EXEC_CTRL1_SUPPORTED_BITS \
  (BX_CPU_THIS_PTR vmx_cap.vmx_pin_vmexec_ctrl_supported_bits)

  uint32_t vmexec_ctrls1;

#define VMX_VM_EXEC_CTRL2_INTERRUPT_WINDOW_VMEXIT (1 << 2)
#define VMX_VM_EXEC_CTRL2_TSC_OFFSET (1 << 3)
#define VMX_VM_EXEC_CTRL2_HLT_VMEXIT (1 << 7)
#define VMX_VM_EXEC_CTRL2_INVLPG_VMEXIT (1 << 9)
#define VMX_VM_EXEC_CTRL2_MWAIT_VMEXIT (1 << 10)
#define VMX_VM_EXEC_CTRL2_RDPMC_VMEXIT (1 << 11)
#define VMX_VM_EXEC_CTRL2_RDTSC_VMEXIT (1 << 12)
#define VMX_VM_EXEC_CTRL2_CR3_WRITE_VMEXIT (1 << 15)   /* legacy must be '1 */
#define VMX_VM_EXEC_CTRL2_CR3_READ_VMEXIT (1 << 16)    /* legacy must be '1 */
#define VMX_VM_EXEC_CTRL2_CR8_WRITE_VMEXIT (1 << 19)   /* TPR shadow */
#define VMX_VM_EXEC_CTRL2_CR8_READ_VMEXIT (1 << 20)    /* TPR shadow */
#define VMX_VM_EXEC_CTRL2_TPR_SHADOW (1 << 21)         /* TPR shadow */
#define VMX_VM_EXEC_CTRL2_NMI_WINDOW_EXITING (1 << 22) /* Virtual NMI */
#define VMX_VM_EXEC_CTRL2_DRx_ACCESS_VMEXIT (1 << 23)
#define VMX_VM_EXEC_CTRL2_IO_VMEXIT (1 << 24)
#define VMX_VM_EXEC_CTRL2_IO_BITMAPS (1 << 25)
#define VMX_VM_EXEC_CTRL2_MONITOR_TRAP_FLAG (1 << 27) /* Monitor Trap Flag */
#define VMX_VM_EXEC_CTRL2_MSR_BITMAPS (1 << 28)
#define VMX_VM_EXEC_CTRL2_MONITOR_VMEXIT (1 << 29)
#define VMX_VM_EXEC_CTRL2_PAUSE_VMEXIT (1 << 30)
#define VMX_VM_EXEC_CTRL2_SECONDARY_CONTROLS (1 << 31)

#define VMX_VM_EXEC_CTRL2_SUPPORTED_BITS \
  (BX_CPU_THIS_PTR vmx_cap.vmx_proc_vmexec_ctrl_supported_bits)

  uint32_t vmexec_ctrls2;

#define VMX_VM_EXEC_CTRL3_VIRTUALIZE_APIC_ACCESSES \
  (1 << 0)                                    /* APIC virtualization */
#define VMX_VM_EXEC_CTRL3_EPT_ENABLE (1 << 1) /* EPT */
#define VMX_VM_EXEC_CTRL3_DESCRIPTOR_TABLE_VMEXIT \
  (1 << 2) /* Descriptor Table VMEXIT */
#define VMX_VM_EXEC_CTRL3_RDTSCP (1 << 3)
#define VMX_VM_EXEC_CTRL3_VIRTUALIZE_X2APIC_MODE \
  (1 << 4)                                            /* Virtualize X2APIC */
#define VMX_VM_EXEC_CTRL3_VPID_ENABLE (1 << 5)        /* VPID */
#define VMX_VM_EXEC_CTRL3_WBINVD_VMEXIT (1 << 6)      /* WBINVD VMEXIT */
#define VMX_VM_EXEC_CTRL3_UNRESTRICTED_GUEST (1 << 7) /* Unrestricted Guest */
#define VMX_VM_EXEC_CTRL3_VIRTUALIZE_APIC_REGISTERS (1 << 8)
#define VMX_VM_EXEC_CTRL3_VIRTUAL_INT_DELIVERY (1 << 9)
#define VMX_VM_EXEC_CTRL3_PAUSE_LOOP_VMEXIT (1 << 10) /* PAUSE loop exiting */
#define VMX_VM_EXEC_CTRL3_RDRAND_VMEXIT (1 << 11)
#define VMX_VM_EXEC_CTRL3_INVPCID (1 << 12)
#define VMX_VM_EXEC_CTRL3_VMFUNC_ENABLE (1 << 13)    /* VM Functions */
#define VMX_VM_EXEC_CTRL3_VMCS_SHADOWING (1 << 14)   /* VMCS Shadowing */
#define VMX_VM_EXEC_CTRL3_SGX_ENCLS_VMEXIT (1 << 15) /* ENCLS/SGX */
#define VMX_VM_EXEC_CTRL3_RDSEED_VMEXIT (1 << 16)
#define VMX_VM_EXEC_CTRL3_PML_ENABLE (1 << 17) /* Page Modification Logging */
#define VMX_VM_EXEC_CTRL3_EPT_VIOLATION_EXCEPTION \
  (1 << 18) /* #VE Exception                      \
             */
#define VMX_VM_EXEC_CTRL3_SUPPRESS_GUEST_VMX_TRACE \
  (1 << 19) /* Processor Trace (not implemented) */
#define VMX_VM_EXEC_CTRL3_XSAVES_XRSTORS (1 << 20) /* XSAVES */
#define VMX_VM_EXEC_CTRL3_MBE_CTRL \
  (1 << 22) /* Mode Based Execution Control (not implemented yet) */
#define VMX_VM_EXEC_CTRL3_SUBPAGE_WR_PROTECT_CTRL \
  (1 << 23) /* Sub-Page Write Protection Control */
#define VMX_VM_EXEC_CTRL3_TSC_SCALING (1 << 25) /* TSC Scaling */

#define VMX_VM_EXEC_CTRL3_SUPPORTED_BITS \
  (BX_CPU_THIS_PTR vmx_cap.vmx_vmexec_ctrl2_supported_bits)

  uint32_t vmexec_ctrls3;

  uint64_t vmcs_linkptr;

  uint64_t tsc_multiplier;

  uint32_t vm_exceptions_bitmap;
  uint32_t vm_pf_mask;
  uint32_t vm_pf_match;
  uint64_t io_bitmap_addr[2];
  bx_phy_address msr_bitmap_addr;

  bx_address vm_cr0_mask;
  bx_address vm_cr0_read_shadow;
  bx_address vm_cr4_mask;
  bx_address vm_cr4_read_shadow;

#define VMX_CR3_TARGET_MAX_CNT 256

  uint32_t vm_cr3_target_cnt;
  bx_address vm_cr3_target_value[VMX_CR3_TARGET_MAX_CNT];

#if BX_SUPPORT_X86_64
  bx_phy_address virtual_apic_page_addr;
  uint32_t vm_tpr_threshold;
  bx_phy_address apic_access_page;
  unsigned apic_access;
#endif

#if BX_SUPPORT_VMX >= 2
  uint64_t eptptr;
  uint16_t vpid;
  uint64_t pml_address;
  uint16_t pml_index;
  uint64_t spptp;
#endif

#if BX_SUPPORT_VMX >= 2
  struct VMX_PLE ple;
#endif

#if BX_SUPPORT_VMX >= 2
  uint8_t svi; /* Servicing Virtual Interrupt */
  uint8_t rvi; /* Requesting Virtual Interrupt */
  uint8_t vppr;

  uint32_t eoi_exit_bitmap[8];
#endif

#if BX_SUPPORT_VMX >= 2
  bx_phy_address vmread_bitmap_addr, vmwrite_bitmap_addr;
#endif

#if BX_SUPPORT_VMX >= 2
  bx_phy_address ve_info_addr;
  uint16_t eptp_index;
#endif

#if BX_SUPPORT_VMX >= 2
  uint64_t xss_exiting_bitmap;
#endif

  //
  // VM-Exit Control Fields
  //

#define VMX_VMEXIT_CTRL1_SAVE_DBG_CTRLS (1 << 2) /* legacy must be '1 */
#define VMX_VMEXIT_CTRL1_HOST_ADDR_SPACE_SIZE (1 << 9)
#define VMX_VMEXIT_CTRL1_LOAD_PERF_GLOBAL_CTRL_MSR \
  (1 << 12) /* Perf Global Control */
#define VMX_VMEXIT_CTRL1_INTA_ON_VMEXIT (1 << 15)
#define VMX_VMEXIT_CTRL1_STORE_PAT_MSR (1 << 18)  /* PAT */
#define VMX_VMEXIT_CTRL1_LOAD_PAT_MSR (1 << 19)   /* PAT */
#define VMX_VMEXIT_CTRL1_STORE_EFER_MSR (1 << 20) /* EFER */
#define VMX_VMEXIT_CTRL1_LOAD_EFER_MSR (1 << 21)  /* EFER */
#define VMX_VMEXIT_CTRL1_STORE_VMX_PREEMPTION_TIMER \
  (1 << 22)                                      /* VMX preemption timer */
#define VMX_VMEXIT_CTRL1_CLEAR_BNDCFGS (1 << 23) /* MPX (not implemented) */
#define VMX_VMEXIT_CTRL1_SUPPRESS_HOST_VMX_TRACE \
  (1 << 24) /* Processor Trace (not implemented) */
#define VMX_VMEXIT_CTRL1_LOAD_HOST_CET_STATE (1 << 28) /* CET */
#define VMX_VMEXIT_CTRL1_LOAD_HOST_PKRS \
  (1 << 29) /* Supervisor-Mode Protection Keys */

#define VMX_VMEXIT_CTRL1_SUPPORTED_BITS \
  (BX_CPU_THIS_PTR vmx_cap.vmx_vmexit_ctrl_supported_bits)

  uint32_t vmexit_ctrls;

  uint32_t vmexit_msr_store_cnt;
  bx_phy_address vmexit_msr_store_addr;
  uint32_t vmexit_msr_load_cnt;
  bx_phy_address vmexit_msr_load_addr;

  //
  // VM-Entry Control Fields
  //

#define VMX_VMENTRY_CTRL1_LOAD_DBG_CTRLS (1 << 2) /* legacy must be '1 */
#define VMX_VMENTRY_CTRL1_X86_64_GUEST (1 << 9)
#define VMX_VMENTRY_CTRL1_SMM_ENTER (1 << 10)
#define VMX_VMENTRY_CTRL1_DEACTIVATE_DUAL_MONITOR_TREATMENT (1 << 11)
#define VMX_VMENTRY_CTRL1_LOAD_PERF_GLOBAL_CTRL_MSR \
  (1 << 13)                                       /* Perf Global Ctrl */
#define VMX_VMENTRY_CTRL1_LOAD_PAT_MSR (1 << 14)  /* PAT */
#define VMX_VMENTRY_CTRL1_LOAD_EFER_MSR (1 << 15) /* EFER */
#define VMX_VMENTRY_CTRL1_LOAD_BNDCFGS (1 << 16)  /* MPX (not implemented) */
#define VMX_VMENTRY_CTRL1_SUPPRESS_VMX_PACKETS \
  (1 << 17) /* Processor Trace (not implemented) */
#define VMX_VMENTRY_CTRL1_LOAD_GUEST_CET_STATE (1 << 20) /* CET */
#define VMX_VMENTRY_CTRL1_LOAD_GUEST_PKRS \
  (1 << 22) /* Supervisor-Mode Protection Keys */

#define VMX_VMENTRY_CTRL1_SUPPORTED_BITS \
  (BX_CPU_THIS_PTR vmx_cap.vmx_vmentry_ctrl_supported_bits)

  uint32_t vmentry_ctrls;

  uint32_t vmentry_msr_load_cnt;
  bx_phy_address vmentry_msr_load_addr;

  uint32_t vmentry_interr_info;
  uint32_t vmentry_excep_err_code;
  uint32_t vmentry_instr_length;

  //
  // VM Functions
  //

#if BX_SUPPORT_VMX >= 2

#define VMX_VMFUNC_CTRL1_SUPPORTED_BITS (rdmsr(0x491))

  uint64_t vmfunc_ctrls;

  uint64_t eptp_list_address;

#endif

  //
  // VMCS Hidden and Read-Only Fields
  //
  uint32_t idt_vector_info;
  uint32_t idt_vector_error_code;

  //
  // VMCS Host State
  //

  VMCS_HOST_STATE host_state;

} VMCS_CACHE;

#define PIN_VMEXIT(ctrl) (vm.vmexec_ctrls1 & (ctrl))
#define VMEXIT(ctrl) (vm.vmexec_ctrls2 & (ctrl))

#define SECONDARY_VMEXEC_CONTROL(ctrl) (vm.vmexec_ctrls3 & (ctrl))

#define BX_VMX_INTERRUPTS_BLOCKED_BY_STI (1 << 0)
#define BX_VMX_INTERRUPTS_BLOCKED_BY_MOV_SS (1 << 1)
#define BX_VMX_INTERRUPTS_BLOCKED_SMI_BLOCKED (1 << 2)
#define BX_VMX_INTERRUPTS_BLOCKED_NMI_BLOCKED (1 << 3)

#define BX_VMX_INTERRUPTIBILITY_STATE_MASK                                  \
  (BX_VMX_INTERRUPTS_BLOCKED_BY_STI | BX_VMX_INTERRUPTS_BLOCKED_BY_MOV_SS | \
   BX_VMX_INTERRUPTS_BLOCKED_SMI_BLOCKED |                                  \
   BX_VMX_INTERRUPTS_BLOCKED_NMI_BLOCKED)

//
// IA32_VMX_BASIC MSR (0x480)
// --------------

#define BX_VMCS_SHADOW_BIT_MASK 0x80000000

//
// 30:00 VMCS revision id
// 31:31 shadow VMCS indicator
// -----------------------------
// 32:47 VMCS region size, 0 <= size <= 4096
// 48:48 use 32-bit physical address, set when x86_64 disabled
// 49:49 support of dual-monitor treatment of SMI and SMM
// 53:50 memory type used for VMCS access
// 54:54 logical processor reports information in the VM-exit
//       instruction-information field on VM exits due to
//       execution of INS/OUTS
// 55:55 set if any VMX controls that default to `1 may be
//       cleared to `0, also indicates that IA32_VMX_TRUE_PINBASED_CTLS,
//       IA32_VMX_TRUE_PROCBASED_CTLS, IA32_VMX_TRUE_EXIT_CTLS and
//       IA32_VMX_TRUE_ENTRY_CTLS MSRs are supported.
// 56:56 if set software can use VM entry to deliver a hardware exception
//       with or without an error code, regardless of vector
// 57:63 reserved, must be zero
//

#define VMX_MSR_VMX_BASIC (rdmsr(0x480))
#define VMX_MSR_VMX_BASIC_LO (VMX_MSR_VMX_BASIC & 0xffffffff)
#define VMX_MSR_VMX_BASIC_HI (VMX_MSR_VMX_BASIC >> 32)

// ------------------------------------------------------------------------
//              reserved bit (must be '1) settings for VMX MSRs
// ------------------------------------------------------------------------

// -----------------------------------------
//  3322|2222|2222|1111|1111|11  |    |
//  1098|7654|3210|9876|5432|1098|7654|3210
// -----------------------------------------
//  ----.----.----.----.----.----.---1.-11-  MSR (0x481)
//  IA32_MSR_VMX_PINBASED_CTRLS
//  ----.-1--.----.---1.111-.---1.-111.--1-  MSR (0x482)
//  IA32_MSR_VMX_PROCBASED_CTRLS
//  ----.----.----.--11.-11-.11-1.1111.1111  MSR (0x483)
//  IA32_MSR_VMX_VMEXIT_CTRLS
//  ----.----.----.----.---1.---1.1111.1111  MSR (0x484)
//  IA32_MSR_VMX_VMENTRY_CTRLS
//

// IA32_MSR_VMX_PINBASED_CTRLS MSR (0x481)
// ---------------------------
// Bits 1, 2 and 4 must be '1

#define VMX_MSR_VMX_PINBASED_CTRLS (rdmsr(0x481))
// Allowed 0-settings: VMentry fail if a bit is '0 in pin-based vmexec controls
// but set to '1 in this MSR
#define VMX_MSR_VMX_PINBASED_CTRLS_LO (VMX_MSR_VMX_PINBASED_CTRLS & 0xffffffff)
// Allowed 1-settings: VMentry fail if a bit is '1 in pin-based vmexec controls
// but set to '0 in this MSR.
#define VMX_MSR_VMX_PINBASED_CTRLS_HI (VMX_MSR_VMX_PINBASED_CTRLS >> 32)

// IA32_MSR_VMX_TRUE_PINBASED_CTRLS MSR (0x48d)
// --------------------------------
#define VMX_MSR_VMX_TRUE_PINBASED_CTRLS (rdmsr(0x48d))
#define VMX_MSR_VMX_TRUE_PINBASED_CTRLS_LO \
  (VMX_MSR_VMX_TRUE_PINBASED_CTRLS & 0xffffffff)
#define VMX_MSR_VMX_TRUE_PINBASED_CTRLS_HI \
  (VMX_MSR_VMX_TRUE_PINBASED_CTRLS >> 32)

// IA32_MSR_VMX_PROCBASED_CTRLS MSR (0x482)
// ----------------------------
// Bits 1, 4-6, 8, 13-16, 26 must be '1
// Bits 0, 17, 18 must be '0
// Bits 19-21 also must be '0 when x86-64 is not supported
#define VMX_MSR_VMX_PROCBASED_CTRLS (rdmsr(0x482))
// Allowed 0-settings (must be '1 bits)
#define VMX_MSR_VMX_PROCBASED_CTRLS_LO \
  (VMX_MSR_VMX_PROCBASED_CTRLS & 0xffffffff)
// Allowed 1-settings
#define VMX_MSR_VMX_PROCBASED_CTRLS_HI (VMX_MSR_VMX_PROCBASED_CTRLS >> 32)

// IA32_MSR_VMX_TRUE_PROCBASED_CTRLS MSR (0x48e)
// ---------------------------------
// Bits 15 and 16 no longer must be '1

#define VMX_MSR_VMX_TRUE_PROCBASED_CTRLS (rdmsr(0x48e))
#define VMX_MSR_VMX_TRUE_PROCBASED_CTRLS_LO \
  (VMX_MSR_VMX_TRUE_PROCBASED_CTRLS & 0xffffffff)
#define VMX_MSR_VMX_TRUE_PROCBASED_CTRLS_HI \
  (VMX_MSR_VMX_TRUE_PROCBASED_CTRLS >> 32)

// IA32_MSR_VMX_VMEXIT_CTRLS MSR (0x483)
// -------------------------
// Bits 0-8, 10, 11, 13, 14, 16, 17 must be '1
#define VMX_MSR_VMX_VMEXIT_CTRLS (rdmsr(0x483))
// Allowed 0-settings (must be '1 bits)
#define VMX_MSR_VMX_VMEXIT_CTRLS_LO (VMX_MSR_VMX_VMEXIT_CTRLS & 0xffffffff)
// Allowed 1-settings
#define VMX_MSR_VMX_VMEXIT_CTRLS_HI (VMX_MSR_VMX_VMEXIT_CTRLS >> 32)

// IA32_MSR_VMX_TRUE_VMEXIT_CTRLS MSR (0x48f)
// ------------------------------

// Bit 2 no longer must be '1
#define VMX_MSR_VMX_TRUE_VMEXIT_CTRLS (rdmsr(0x48f))
#define VMX_MSR_VMX_TRUE_VMEXIT_CTRLS_LO \
  (VMX_MSR_VMX_TRUE_VMEXIT_CTRLS & 0xffffffff)
#define VMX_MSR_VMX_TRUE_VMEXIT_CTRLS_HI (VMX_MSR_VMX_TRUE_VMEXIT_CTRLS >> 32)

// IA32_MSR_VMX_VMENTRY_CTRLS MSR (0x484)
// --------------------------
// Bits 0-8, 12 must be '1
#define VMX_MSR_VMX_VMENTRY_CTRLS (rdmsr(0x484))
// Allowed 0-settings (must be '1 bits)
#define VMX_MSR_VMX_VMENTRY_CTRLS_LO (VMX_MSR_VMX_VMENTRY_CTRLS & 0xffffffff)
// Allowed 1-settings
#define VMX_MSR_VMX_VMENTRY_CTRLS_HI (VMX_MSR_VMX_VMENTRY_CTRLS >> 32)

// IA32_MSR_VMX_TRUE_VMENTRY_CTRLS MSR (0x490)
// -------------------------------
// Bit 2 is longer must be '1

#define VMX_MSR_VMX_TRUE_VMENTRY_CTRLS (rdmsr(0x490))
#define VMX_MSR_VMX_TRUE_VMENTRY_CTRLS_LO \
  (VMX_MSR_VMX_TRUE_VMENTRY_CTRLS & 0xffffffff)
#define VMX_MSR_VMX_TRUE_VMENTRY_CTRLS_HI (VMX_MSR_VMX_TRUE_VMENTRY_CTRLS >> 32)

// IA32_MSR_VMX_MISC MSR (0x485)
// -----------------

//   [4:0] - TSC:VMX_PREEMPTION_TIMER ratio
//     [5] - VMEXITs store the value of EFER.LMA into the �x86-64 guest"
//           VMENTRY control (must set to '1 if 'unrestricted guest' is
//           supported)
//     [6] - support VMENTER to HLT state
//     [7] - support VMENTER to SHUTDOWN state
//     [8] - support VMENTER to WAIT_FOR_SIPI state
//    [14] - Intel Processor Trace (Intel PT) can be used in VMX operation
//    [15] - RDMSR can be used in SMM to read the SMBASE MSR
// [24:16] - number of CR3 target values supported
// [27:25] - (N+1)*512 - recommended maximum MSRs in MSR store list
//    [28] - MSR_IA32_SMM_MONITOR_CTL[2] enable
//    [29] - Allow VMWRITE to R/O VMCS fields (to be used with VMCS Shadowing)
//    [30] - Allow injection of a software interrupt, software exception, or
//    privileged
//           software exception with an instruction length of 0
//    [31] - Reserved
// --------------------------------------------
// [63:32] - MSEG revision ID used by processor

#define VMX_MSR_MISC (rdmsr(0x485))

//
// IA32_VMX_CR0_FIXED0 MSR (0x486)   IA32_VMX_CR0_FIXED1 MSR (0x487)
// -------------------               -------------------

// allowed 0-setting in CR0 in VMX mode
// bits PE(0), NE(5) and PG(31) required to be set in CR0 to enter VMX mode
#define VMX_MSR_CR0_FIXED0 (rdmsr(0x486))

// allowed 1-setting in CR0 in VMX mode
#define VMX_MSR_CR0_FIXED1 (rdmsr(0x487))

//
// IA32_VMX_CR4_FIXED0 MSR (0x488)   IA32_VMX_CR4_FIXED1 MSR (0x489)
// -------------------               -------------------

// allowed 0-setting in CR0 in VMX mode
// bit VMXE(13) required to be set in CR4 to enter VMX mode
#define VMX_MSR_CR4_FIXED0 (rdmsr(0x488))

// allowed 1-setting in CR0 in VMX mode
#define VMX_MSR_CR4_FIXED1 (rdmsr(0x489))

//
// IA32_VMX_VMCS_ENUM MSR (0x48a)
// ------------------

//
// 09:01 highest index value used for any VMCS encoding
// 63:10 reserved, must be zero
//
/*
#define VMX_MSR_VMCS_ENUM_LO (VMX_HIGHEST_VMCS_ENCODING)
#define VMX_MSR_VMCS_ENUM_HI (0x00000000)

#define VMX_MSR_VMCS_ENUM \
   ((((uint64_t) VMX_MSR_VMCS_ENUM_HI) << 32) | VMX_MSR_VMCS_ENUM_LO)
*/

// IA32_VMX_MSR_PROCBASED_CTRLS2 MSR (0x48b)
// -----------------------------
#define VMX_MSR_VMX_PROCBASED_CTRLS2 (rdmsr(0x48b))

// Allowed 0-settings (must be '1 bits)
#define VMX_MSR_VMX_PROCBASED_CTRLS2_LO \
  (VMX_MSR_VMX_PROCBASED_CTRLS2 & 0xffffffff)
// Allowed 1-settings
#define VMX_MSR_VMX_PROCBASED_CTRLS2_HI (VMX_MSR_VMX_PROCBASED_CTRLS2 >> 32)

#if BX_SUPPORT_VMX >= 2

// IA32_VMX_EPT_VPID_CAP MSR (0x48c)
// ---------------------

enum VMX_INVEPT_INVVPID_type {
  BX_INVEPT_INVVPID_INDIVIDUAL_ADDRESS_INVALIDATION = 0,
  BX_INVEPT_INVVPID_SINGLE_CONTEXT_INVALIDATION,
  BX_INVEPT_INVVPID_ALL_CONTEXT_INVALIDATION,
  BX_INVEPT_INVVPID_SINGLE_CONTEXT_NON_GLOBAL_INVALIDATION
};

#define VMX_MSR_VMX_EPT_VPID_CAP (rdmsr(0x48c))

#endif

// IA32_MSR_EFER MSR (0x485)
// -----------------
#define MSR_EFER (rdmsr(0xc0000080))

enum VMX_error_code VMenterLoadCheckVmControls(void);
enum VMX_error_code VMenterLoadCheckHostState(void);
uint32_t VMenterLoadCheckGuestState(uint64_t* qualification);
bool isMemTypeValidMTRR(unsigned memtype);
bool isMemTypeValidPAT(unsigned memtype);
bool isValidMSR_PAT(uint64_t pat_val);
bool is_invalid_cet_control(bx_address val);
bool CheckPDPTR(uint64_t* pdptr);
bool CheckPDPTR_CR3(bx_phy_address cr3_val);
uint32_t VMX_Read_Virtual_APIC_VTPR(void);
uint32_t VMXReadRevisionID(bx_phy_address pAddr);
void VMXWriteRevisionID(bx_phy_address pAddr, uint32_t value);

/* VMCS Encodings */
enum vmcs_field {
  VIRTUAL_PROCESSOR_ID = 0x00000000,
  POSTED_INTR_NV = 0x00000002,
  LAST_PID_POINTER_INDEX = 0x00000008,
  GUEST_ES_SELECTOR = 0x00000800,
  GUEST_CS_SELECTOR = 0x00000802,
  GUEST_SS_SELECTOR = 0x00000804,
  GUEST_DS_SELECTOR = 0x00000806,
  GUEST_FS_SELECTOR = 0x00000808,
  GUEST_GS_SELECTOR = 0x0000080a,
  GUEST_LDTR_SELECTOR = 0x0000080c,
  GUEST_TR_SELECTOR = 0x0000080e,
  GUEST_INTR_STATUS = 0x00000810,
  GUEST_PML_INDEX = 0x00000812,
  HOST_ES_SELECTOR = 0x00000c00,
  HOST_CS_SELECTOR = 0x00000c02,
  HOST_SS_SELECTOR = 0x00000c04,
  HOST_DS_SELECTOR = 0x00000c06,
  HOST_FS_SELECTOR = 0x00000c08,
  HOST_GS_SELECTOR = 0x00000c0a,
  HOST_TR_SELECTOR = 0x00000c0c,
  IO_BITMAP_A = 0x00002000,
  IO_BITMAP_A_HIGH = 0x00002001,
  IO_BITMAP_B = 0x00002002,
  IO_BITMAP_B_HIGH = 0x00002003,
  MSR_BITMAP = 0x00002004,
  MSR_BITMAP_HIGH = 0x00002005,
  VM_EXIT_MSR_STORE_ADDR = 0x00002006,
  VM_EXIT_MSR_STORE_ADDR_HIGH = 0x00002007,
  VM_EXIT_MSR_LOAD_ADDR = 0x00002008,
  VM_EXIT_MSR_LOAD_ADDR_HIGH = 0x00002009,
  VM_ENTRY_MSR_LOAD_ADDR = 0x0000200a,
  VM_ENTRY_MSR_LOAD_ADDR_HIGH = 0x0000200b,
  PML_ADDRESS = 0x0000200e,
  PML_ADDRESS_HIGH = 0x0000200f,
  TSC_OFFSET = 0x00002010,
  TSC_OFFSET_HIGH = 0x00002011,
  VIRTUAL_APIC_PAGE_ADDR = 0x00002012,
  VIRTUAL_APIC_PAGE_ADDR_HIGH = 0x00002013,
  APIC_ACCESS_ADDR = 0x00002014,
  APIC_ACCESS_ADDR_HIGH = 0x00002015,
  POSTED_INTR_DESC_ADDR = 0x00002016,
  POSTED_INTR_DESC_ADDR_HIGH = 0x00002017,
  VM_FUNCTION_CONTROL = 0x00002018,
  VM_FUNCTION_CONTROL_HIGH = 0x00002019,
  EPT_POINTER = 0x0000201a,
  EPT_POINTER_HIGH = 0x0000201b,
  EOI_EXIT_BITMAP0 = 0x0000201c,
  EOI_EXIT_BITMAP0_HIGH = 0x0000201d,
  EOI_EXIT_BITMAP1 = 0x0000201e,
  EOI_EXIT_BITMAP1_HIGH = 0x0000201f,
  EOI_EXIT_BITMAP2 = 0x00002020,
  EOI_EXIT_BITMAP2_HIGH = 0x00002021,
  EOI_EXIT_BITMAP3 = 0x00002022,
  EOI_EXIT_BITMAP3_HIGH = 0x00002023,
  EPTP_LIST_ADDRESS = 0x00002024,
  EPTP_LIST_ADDRESS_HIGH = 0x00002025,
  VMREAD_BITMAP = 0x00002026,
  VMREAD_BITMAP_HIGH = 0x00002027,
  VMWRITE_BITMAP = 0x00002028,
  VMWRITE_BITMAP_HIGH = 0x00002029,
  XSS_EXIT_BITMAP = 0x0000202C,
  XSS_EXIT_BITMAP_HIGH = 0x0000202D,
  ENCLS_EXITING_BITMAP = 0x0000202E,
  ENCLS_EXITING_BITMAP_HIGH = 0x0000202F,
  TSC_MULTIPLIER = 0x00002032,
  TSC_MULTIPLIER_HIGH = 0x00002033,
  TERTIARY_VM_EXEC_CONTROL = 0x00002034,
  TERTIARY_VM_EXEC_CONTROL_HIGH = 0x00002035,
  PID_POINTER_TABLE = 0x00002042,
  PID_POINTER_TABLE_HIGH = 0x00002043,
  GUEST_PHYSICAL_ADDRESS = 0x00002400,
  GUEST_PHYSICAL_ADDRESS_HIGH = 0x00002401,
  VMCS_LINK_POINTER = 0x00002800,
  VMCS_LINK_POINTER_HIGH = 0x00002801,
  GUEST_IA32_DEBUGCTL = 0x00002802,
  GUEST_IA32_DEBUGCTL_HIGH = 0x00002803,
  GUEST_IA32_PAT = 0x00002804,
  GUEST_IA32_PAT_HIGH = 0x00002805,
  GUEST_IA32_EFER = 0x00002806,
  GUEST_IA32_EFER_HIGH = 0x00002807,
  GUEST_IA32_PERF_GLOBAL_CTRL = 0x00002808,
  GUEST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x00002809,
  GUEST_PDPTR0 = 0x0000280a,
  GUEST_PDPTR0_HIGH = 0x0000280b,
  GUEST_PDPTR1 = 0x0000280c,
  GUEST_PDPTR1_HIGH = 0x0000280d,
  GUEST_PDPTR2 = 0x0000280e,
  GUEST_PDPTR2_HIGH = 0x0000280f,
  GUEST_PDPTR3 = 0x00002810,
  GUEST_PDPTR3_HIGH = 0x00002811,
  GUEST_BNDCFGS = 0x00002812,
  GUEST_BNDCFGS_HIGH = 0x00002813,
  GUEST_IA32_RTIT_CTL = 0x00002814,
  GUEST_IA32_RTIT_CTL_HIGH = 0x00002815,
  HOST_IA32_PAT = 0x00002c00,
  HOST_IA32_PAT_HIGH = 0x00002c01,
  HOST_IA32_EFER = 0x00002c02,
  HOST_IA32_EFER_HIGH = 0x00002c03,
  HOST_IA32_PERF_GLOBAL_CTRL = 0x00002c04,
  HOST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x00002c05,
  PIN_BASED_VM_EXEC_CONTROL = 0x00004000,
  CPU_BASED_VM_EXEC_CONTROL = 0x00004002,
  EXCEPTION_BITMAP = 0x00004004,
  PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,
  PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,
  CR3_TARGET_COUNT = 0x0000400a,
  VM_EXIT_CONTROLS = 0x0000400c,
  VM_EXIT_MSR_STORE_COUNT = 0x0000400e,
  VM_EXIT_MSR_LOAD_COUNT = 0x00004010,
  VM_ENTRY_CONTROLS = 0x00004012,
  VM_ENTRY_MSR_LOAD_COUNT = 0x00004014,
  VM_ENTRY_INTR_INFO_FIELD = 0x00004016,
  VM_ENTRY_EXCEPTION_ERROR_CODE = 0x00004018,
  VM_ENTRY_INSTRUCTION_LEN = 0x0000401a,
  TPR_THRESHOLD = 0x0000401c,
  SECONDARY_VM_EXEC_CONTROL = 0x0000401e,
  PLE_GAP = 0x00004020,
  PLE_WINDOW = 0x00004022,
  NOTIFY_WINDOW = 0x00004024,
  VM_INSTRUCTION_ERROR = 0x00004400,
  VM_EXIT_REASON = 0x00004402,
  VM_EXIT_INTR_INFO = 0x00004404,
  VM_EXIT_INTR_ERROR_CODE = 0x00004406,
  IDT_VECTORING_INFO_FIELD = 0x00004408,
  IDT_VECTORING_ERROR_CODE = 0x0000440a,
  VM_EXIT_INSTRUCTION_LEN = 0x0000440c,
  VMX_INSTRUCTION_INFO = 0x0000440e,
  GUEST_ES_LIMIT = 0x00004800,
  GUEST_CS_LIMIT = 0x00004802,
  GUEST_SS_LIMIT = 0x00004804,
  GUEST_DS_LIMIT = 0x00004806,
  GUEST_FS_LIMIT = 0x00004808,
  GUEST_GS_LIMIT = 0x0000480a,
  GUEST_LDTR_LIMIT = 0x0000480c,
  GUEST_TR_LIMIT = 0x0000480e,
  GUEST_GDTR_LIMIT = 0x00004810,
  GUEST_IDTR_LIMIT = 0x00004812,
  GUEST_ES_AR_BYTES = 0x00004814,
  GUEST_CS_AR_BYTES = 0x00004816,
  GUEST_SS_AR_BYTES = 0x00004818,
  GUEST_DS_AR_BYTES = 0x0000481a,
  GUEST_FS_AR_BYTES = 0x0000481c,
  GUEST_GS_AR_BYTES = 0x0000481e,
  GUEST_LDTR_AR_BYTES = 0x00004820,
  GUEST_TR_AR_BYTES = 0x00004822,
  GUEST_INTERRUPTIBILITY_INFO = 0x00004824,
  GUEST_ACTIVITY_STATE = 0x00004826,
  GUEST_SYSENTER_CS = 0x0000482A,
  VMX_PREEMPTION_TIMER_VALUE = 0x0000482E,
  HOST_IA32_SYSENTER_CS = 0x00004c00,
  CR0_GUEST_HOST_MASK = 0x00006000,
  CR4_GUEST_HOST_MASK = 0x00006002,
  CR0_READ_SHADOW = 0x00006004,
  CR4_READ_SHADOW = 0x00006006,
  CR3_TARGET_VALUE0 = 0x00006008,
  CR3_TARGET_VALUE1 = 0x0000600a,
  CR3_TARGET_VALUE2 = 0x0000600c,
  CR3_TARGET_VALUE3 = 0x0000600e,
  EXIT_QUALIFICATION = 0x00006400,
  GUEST_LINEAR_ADDRESS = 0x0000640a,
  GUEST_CR0 = 0x00006800,
  GUEST_CR3 = 0x00006802,
  GUEST_CR4 = 0x00006804,
  GUEST_ES_BASE = 0x00006806,
  GUEST_CS_BASE = 0x00006808,
  GUEST_SS_BASE = 0x0000680a,
  GUEST_DS_BASE = 0x0000680c,
  GUEST_FS_BASE = 0x0000680e,
  GUEST_GS_BASE = 0x00006810,
  GUEST_LDTR_BASE = 0x00006812,
  GUEST_TR_BASE = 0x00006814,
  GUEST_GDTR_BASE = 0x00006816,
  GUEST_IDTR_BASE = 0x00006818,
  GUEST_DR7 = 0x0000681a,
  GUEST_RSP = 0x0000681c,
  GUEST_RIP = 0x0000681e,
  GUEST_RFLAGS = 0x00006820,
  GUEST_PENDING_DBG_EXCEPTIONS = 0x00006822,
  GUEST_SYSENTER_ESP = 0x00006824,
  GUEST_SYSENTER_EIP = 0x00006826,
  HOST_CR0 = 0x00006c00,
  HOST_CR3 = 0x00006c02,
  HOST_CR4 = 0x00006c04,
  HOST_FS_BASE = 0x00006c06,
  HOST_GS_BASE = 0x00006c08,
  HOST_TR_BASE = 0x00006c0a,
  HOST_GDTR_BASE = 0x00006c0c,
  HOST_IDTR_BASE = 0x00006c0e,
  HOST_IA32_SYSENTER_ESP = 0x00006c10,
  HOST_IA32_SYSENTER_EIP = 0x00006c12,
  HOST_RSP = 0x00006c14,
  HOST_RIP = 0x00006c16,
};
#define BIT(x) (1 << (x))
#define u8 uint8_t
#define u16 uint16_t
#define u32 uint32_t
#define u64 uint64_t
struct hv_enlightened_vmcs {
  u32 revision_id;
  u32 abort;

  u16 host_es_selector;
  u16 host_cs_selector;
  u16 host_ss_selector;
  u16 host_ds_selector;
  u16 host_fs_selector;
  u16 host_gs_selector;
  u16 host_tr_selector;

  u16 padding16_1;

  u64 host_ia32_pat;
  u64 host_ia32_efer;

  u64 host_cr0;
  u64 host_cr3;
  u64 host_cr4;

  u64 host_ia32_sysenter_esp;
  u64 host_ia32_sysenter_eip;
  u64 host_rip;
  u32 host_ia32_sysenter_cs;

  u32 pin_based_vm_exec_control;
  u32 vm_exit_controls;
  u32 secondary_vm_exec_control;

  u64 io_bitmap_a;
  u64 io_bitmap_b;
  u64 msr_bitmap;

  u16 guest_es_selector;
  u16 guest_cs_selector;
  u16 guest_ss_selector;
  u16 guest_ds_selector;
  u16 guest_fs_selector;
  u16 guest_gs_selector;
  u16 guest_ldtr_selector;
  u16 guest_tr_selector;

  u32 guest_es_limit;
  u32 guest_cs_limit;
  u32 guest_ss_limit;
  u32 guest_ds_limit;
  u32 guest_fs_limit;
  u32 guest_gs_limit;
  u32 guest_ldtr_limit;
  u32 guest_tr_limit;
  u32 guest_gdtr_limit;
  u32 guest_idtr_limit;

  u32 guest_es_ar_bytes;
  u32 guest_cs_ar_bytes;
  u32 guest_ss_ar_bytes;
  u32 guest_ds_ar_bytes;
  u32 guest_fs_ar_bytes;
  u32 guest_gs_ar_bytes;
  u32 guest_ldtr_ar_bytes;
  u32 guest_tr_ar_bytes;

  u64 guest_es_base;
  u64 guest_cs_base;
  u64 guest_ss_base;
  u64 guest_ds_base;
  u64 guest_fs_base;
  u64 guest_gs_base;
  u64 guest_ldtr_base;
  u64 guest_tr_base;
  u64 guest_gdtr_base;
  u64 guest_idtr_base;

  u64 padding64_1[3];

  u64 vm_exit_msr_store_addr;
  u64 vm_exit_msr_load_addr;
  u64 vm_entry_msr_load_addr;

  u64 cr3_target_value0;
  u64 cr3_target_value1;
  u64 cr3_target_value2;
  u64 cr3_target_value3;

  u32 page_fault_error_code_mask;
  u32 page_fault_error_code_match;

  u32 cr3_target_count;
  u32 vm_exit_msr_store_count;
  u32 vm_exit_msr_load_count;
  u32 vm_entry_msr_load_count;

  u64 tsc_offset;
  u64 virtual_apic_page_addr;
  u64 vmcs_link_pointer;

  u64 guest_ia32_debugctl;
  u64 guest_ia32_pat;
  u64 guest_ia32_efer;

  u64 guest_pdptr0;
  u64 guest_pdptr1;
  u64 guest_pdptr2;
  u64 guest_pdptr3;

  u64 guest_pending_dbg_exceptions;
  u64 guest_sysenter_esp;
  u64 guest_sysenter_eip;

  u32 guest_activity_state;
  u32 guest_sysenter_cs;

  u64 cr0_guest_host_mask;
  u64 cr4_guest_host_mask;
  u64 cr0_read_shadow;
  u64 cr4_read_shadow;
  u64 guest_cr0;
  u64 guest_cr3;
  u64 guest_cr4;
  u64 guest_dr7;

  u64 host_fs_base;
  u64 host_gs_base;
  u64 host_tr_base;
  u64 host_gdtr_base;
  u64 host_idtr_base;
  u64 host_rsp;

  u64 ept_pointer;

  u16 virtual_processor_id;
  u16 padding16_2[3];

  u64 padding64_2[5];
  u64 guest_physical_address;

  u32 vm_instruction_error;
  u32 vm_exit_reason;
  u32 vm_exit_intr_info;
  u32 vm_exit_intr_error_code;
  u32 idt_vectoring_info_field;
  u32 idt_vectoring_error_code;
  u32 vm_exit_instruction_len;
  u32 vmx_instruction_info;

  u64 exit_qualification;
  u64 exit_io_instruction_ecx;
  u64 exit_io_instruction_esi;
  u64 exit_io_instruction_edi;
  u64 exit_io_instruction_eip;

  u64 guest_linear_address;
  u64 guest_rsp;
  u64 guest_rflags;

  u32 guest_interruptibility_info;
  u32 cpu_based_vm_exec_control;
  u32 exception_bitmap;
  u32 vm_entry_controls;
  u32 vm_entry_intr_info_field;
  u32 vm_entry_exception_error_code;
  u32 vm_entry_instruction_len;
  u32 tpr_threshold;

  u64 guest_rip;

  u32 hv_clean_fields;
  u32 padding32_1;
  u32 hv_synthetic_controls;
  struct {
    u32 nested_flush_hypercall : 1;
    u32 msr_bitmap : 1;
    u32 reserved : 30;
  } __attribute__((__packed__)) hv_enlightenments_control;
  u32 hv_vp_id;
  u32 padding32_2;
  u64 hv_vm_id;
  u64 partition_assist_page;
  u64 padding64_4[4];
  u64 guest_bndcfgs;
  u64 guest_ia32_perf_global_ctrl;
  u64 guest_ia32_s_cet;
  u64 guest_ssp;
  u64 guest_ia32_int_ssp_table_addr;
  u64 guest_ia32_lbr_ctl;
  u64 padding64_5[2];
  u64 xss_exit_bitmap;
  u64 encls_exiting_bitmap;
  u64 host_ia32_perf_global_ctrl;
  u64 tsc_multiplier;
  u64 host_ia32_s_cet;
  u64 host_ssp;
  u64 host_ia32_int_ssp_table_addr;
  u64 padding64_6;
} __attribute__((__packed__));

#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE 0
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_IO_BITMAP BIT(0)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_MSR_BITMAP BIT(1)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP2 BIT(2)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP1 BIT(3)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_PROC BIT(4)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_EVENT BIT(5)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_ENTRY BIT(6)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_EXCPN BIT(7)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR BIT(8)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_XLAT BIT(9)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_BASIC BIT(10)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1 BIT(11)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2 BIT(12)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER BIT(13)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1 BIT(14)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_ENLIGHTENMENTSCONTROL BIT(15)
#define HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL 0xFFFF

static inline int evmcs_vmread(uint64_t encoding, uint64_t* value) {
  switch (encoding) {
    case GUEST_RIP:
      *value = current_evmcs->guest_rip;
      break;
    case GUEST_RSP:
      *value = current_evmcs->guest_rsp;
      break;
    case GUEST_RFLAGS:
      *value = current_evmcs->guest_rflags;
      break;
    case HOST_IA32_PAT:
      *value = current_evmcs->host_ia32_pat;
      break;
    case HOST_IA32_EFER:
      *value = current_evmcs->host_ia32_efer;
      break;
    case HOST_CR0:
      *value = current_evmcs->host_cr0;
      break;
    case HOST_CR3:
      *value = current_evmcs->host_cr3;
      break;
    case HOST_CR4:
      *value = current_evmcs->host_cr4;
      break;
    case HOST_IA32_SYSENTER_ESP:
      *value = current_evmcs->host_ia32_sysenter_esp;
      break;
    case HOST_IA32_SYSENTER_EIP:
      *value = current_evmcs->host_ia32_sysenter_eip;
      break;
    case HOST_RIP:
      *value = current_evmcs->host_rip;
      break;
    case IO_BITMAP_A:
      *value = current_evmcs->io_bitmap_a;
      break;
    case IO_BITMAP_B:
      *value = current_evmcs->io_bitmap_b;
      break;
    case MSR_BITMAP:
      *value = current_evmcs->msr_bitmap;
      break;
    case GUEST_ES_BASE:
      *value = current_evmcs->guest_es_base;
      break;
    case GUEST_CS_BASE:
      *value = current_evmcs->guest_cs_base;
      break;
    case GUEST_SS_BASE:
      *value = current_evmcs->guest_ss_base;
      break;
    case GUEST_DS_BASE:
      *value = current_evmcs->guest_ds_base;
      break;
    case GUEST_FS_BASE:
      *value = current_evmcs->guest_fs_base;
      break;
    case GUEST_GS_BASE:
      *value = current_evmcs->guest_gs_base;
      break;
    case GUEST_LDTR_BASE:
      *value = current_evmcs->guest_ldtr_base;
      break;
    case GUEST_TR_BASE:
      *value = current_evmcs->guest_tr_base;
      break;
    case GUEST_GDTR_BASE:
      *value = current_evmcs->guest_gdtr_base;
      break;
    case GUEST_IDTR_BASE:
      *value = current_evmcs->guest_idtr_base;
      break;
    case TSC_OFFSET:
      *value = current_evmcs->tsc_offset;
      break;
    case VIRTUAL_APIC_PAGE_ADDR:
      *value = current_evmcs->virtual_apic_page_addr;
      break;
    case VMCS_LINK_POINTER:
      *value = current_evmcs->vmcs_link_pointer;
      break;
    case GUEST_IA32_DEBUGCTL:
      *value = current_evmcs->guest_ia32_debugctl;
      break;
    case GUEST_IA32_PAT:
      *value = current_evmcs->guest_ia32_pat;
      break;
    case GUEST_IA32_EFER:
      *value = current_evmcs->guest_ia32_efer;
      break;
    case GUEST_PDPTR0:
      *value = current_evmcs->guest_pdptr0;
      break;
    case GUEST_PDPTR1:
      *value = current_evmcs->guest_pdptr1;
      break;
    case GUEST_PDPTR2:
      *value = current_evmcs->guest_pdptr2;
      break;
    case GUEST_PDPTR3:
      *value = current_evmcs->guest_pdptr3;
      break;
    case GUEST_PENDING_DBG_EXCEPTIONS:
      *value = current_evmcs->guest_pending_dbg_exceptions;
      break;
    case GUEST_SYSENTER_ESP:
      *value = current_evmcs->guest_sysenter_esp;
      break;
    case GUEST_SYSENTER_EIP:
      *value = current_evmcs->guest_sysenter_eip;
      break;
    case CR0_GUEST_HOST_MASK:
      *value = current_evmcs->cr0_guest_host_mask;
      break;
    case CR4_GUEST_HOST_MASK:
      *value = current_evmcs->cr4_guest_host_mask;
      break;
    case CR0_READ_SHADOW:
      *value = current_evmcs->cr0_read_shadow;
      break;
    case CR4_READ_SHADOW:
      *value = current_evmcs->cr4_read_shadow;
      break;
    case GUEST_CR0:
      *value = current_evmcs->guest_cr0;
      break;
    case GUEST_CR3:
      *value = current_evmcs->guest_cr3;
      break;
    case GUEST_CR4:
      *value = current_evmcs->guest_cr4;
      break;
    case GUEST_DR7:
      *value = current_evmcs->guest_dr7;
      break;
    case HOST_FS_BASE:
      *value = current_evmcs->host_fs_base;
      break;
    case HOST_GS_BASE:
      *value = current_evmcs->host_gs_base;
      break;
    case HOST_TR_BASE:
      *value = current_evmcs->host_tr_base;
      break;
    case HOST_GDTR_BASE:
      *value = current_evmcs->host_gdtr_base;
      break;
    case HOST_IDTR_BASE:
      *value = current_evmcs->host_idtr_base;
      break;
    case HOST_RSP:
      *value = current_evmcs->host_rsp;
      break;
    case EPT_POINTER:
      *value = current_evmcs->ept_pointer;
      break;
    case GUEST_BNDCFGS:
      *value = current_evmcs->guest_bndcfgs;
      break;
    case XSS_EXIT_BITMAP:
      *value = current_evmcs->xss_exit_bitmap;
      break;
    case GUEST_PHYSICAL_ADDRESS:
      *value = current_evmcs->guest_physical_address;
      break;
    case EXIT_QUALIFICATION:
      *value = current_evmcs->exit_qualification;
      break;
    case GUEST_LINEAR_ADDRESS:
      *value = current_evmcs->guest_linear_address;
      break;
    case VM_EXIT_MSR_STORE_ADDR:
      *value = current_evmcs->vm_exit_msr_store_addr;
      break;
    case VM_EXIT_MSR_LOAD_ADDR:
      *value = current_evmcs->vm_exit_msr_load_addr;
      break;
    case VM_ENTRY_MSR_LOAD_ADDR:
      *value = current_evmcs->vm_entry_msr_load_addr;
      break;
    case CR3_TARGET_VALUE0:
      *value = current_evmcs->cr3_target_value0;
      break;
    case CR3_TARGET_VALUE1:
      *value = current_evmcs->cr3_target_value1;
      break;
    case CR3_TARGET_VALUE2:
      *value = current_evmcs->cr3_target_value2;
      break;
    case CR3_TARGET_VALUE3:
      *value = current_evmcs->cr3_target_value3;
      break;
    case TPR_THRESHOLD:
      *value = current_evmcs->tpr_threshold;
      break;
    case GUEST_INTERRUPTIBILITY_INFO:
      *value = current_evmcs->guest_interruptibility_info;
      break;
    case CPU_BASED_VM_EXEC_CONTROL:
      *value = current_evmcs->cpu_based_vm_exec_control;
      break;
    case EXCEPTION_BITMAP:
      *value = current_evmcs->exception_bitmap;
      break;
    case VM_ENTRY_CONTROLS:
      *value = current_evmcs->vm_entry_controls;
      break;
    case VM_ENTRY_INTR_INFO_FIELD:
      *value = current_evmcs->vm_entry_intr_info_field;
      break;
    case VM_ENTRY_EXCEPTION_ERROR_CODE:
      *value = current_evmcs->vm_entry_exception_error_code;
      break;
    case VM_ENTRY_INSTRUCTION_LEN:
      *value = current_evmcs->vm_entry_instruction_len;
      break;
    case HOST_IA32_SYSENTER_CS:
      *value = current_evmcs->host_ia32_sysenter_cs;
      break;
    case PIN_BASED_VM_EXEC_CONTROL:
      *value = current_evmcs->pin_based_vm_exec_control;
      break;
    case VM_EXIT_CONTROLS:
      *value = current_evmcs->vm_exit_controls;
      break;
    case SECONDARY_VM_EXEC_CONTROL:
      *value = current_evmcs->secondary_vm_exec_control;
      break;
    case GUEST_ES_LIMIT:
      *value = current_evmcs->guest_es_limit;
      break;
    case GUEST_CS_LIMIT:
      *value = current_evmcs->guest_cs_limit;
      break;
    case GUEST_SS_LIMIT:
      *value = current_evmcs->guest_ss_limit;
      break;
    case GUEST_DS_LIMIT:
      *value = current_evmcs->guest_ds_limit;
      break;
    case GUEST_FS_LIMIT:
      *value = current_evmcs->guest_fs_limit;
      break;
    case GUEST_GS_LIMIT:
      *value = current_evmcs->guest_gs_limit;
      break;
    case GUEST_LDTR_LIMIT:
      *value = current_evmcs->guest_ldtr_limit;
      break;
    case GUEST_TR_LIMIT:
      *value = current_evmcs->guest_tr_limit;
      break;
    case GUEST_GDTR_LIMIT:
      *value = current_evmcs->guest_gdtr_limit;
      break;
    case GUEST_IDTR_LIMIT:
      *value = current_evmcs->guest_idtr_limit;
      break;
    case GUEST_ES_AR_BYTES:
      *value = current_evmcs->guest_es_ar_bytes;
      break;
    case GUEST_CS_AR_BYTES:
      *value = current_evmcs->guest_cs_ar_bytes;
      break;
    case GUEST_SS_AR_BYTES:
      *value = current_evmcs->guest_ss_ar_bytes;
      break;
    case GUEST_DS_AR_BYTES:
      *value = current_evmcs->guest_ds_ar_bytes;
      break;
    case GUEST_FS_AR_BYTES:
      *value = current_evmcs->guest_fs_ar_bytes;
      break;
    case GUEST_GS_AR_BYTES:
      *value = current_evmcs->guest_gs_ar_bytes;
      break;
    case GUEST_LDTR_AR_BYTES:
      *value = current_evmcs->guest_ldtr_ar_bytes;
      break;
    case GUEST_TR_AR_BYTES:
      *value = current_evmcs->guest_tr_ar_bytes;
      break;
    case GUEST_ACTIVITY_STATE:
      *value = current_evmcs->guest_activity_state;
      break;
    case GUEST_SYSENTER_CS:
      *value = current_evmcs->guest_sysenter_cs;
      break;
    case VM_INSTRUCTION_ERROR:
      *value = current_evmcs->vm_instruction_error;
      break;
    case VM_EXIT_REASON:
      *value = current_evmcs->vm_exit_reason;
      break;
    case VM_EXIT_INTR_INFO:
      *value = current_evmcs->vm_exit_intr_info;
      break;
    case VM_EXIT_INTR_ERROR_CODE:
      *value = current_evmcs->vm_exit_intr_error_code;
      break;
    case IDT_VECTORING_INFO_FIELD:
      *value = current_evmcs->idt_vectoring_info_field;
      break;
    case IDT_VECTORING_ERROR_CODE:
      *value = current_evmcs->idt_vectoring_error_code;
      break;
    case VM_EXIT_INSTRUCTION_LEN:
      *value = current_evmcs->vm_exit_instruction_len;
      break;
    case VMX_INSTRUCTION_INFO:
      *value = current_evmcs->vmx_instruction_info;
      break;
    case PAGE_FAULT_ERROR_CODE_MASK:
      *value = current_evmcs->page_fault_error_code_mask;
      break;
    case PAGE_FAULT_ERROR_CODE_MATCH:
      *value = current_evmcs->page_fault_error_code_match;
      break;
    case CR3_TARGET_COUNT:
      *value = current_evmcs->cr3_target_count;
      break;
    case VM_EXIT_MSR_STORE_COUNT:
      *value = current_evmcs->vm_exit_msr_store_count;
      break;
    case VM_EXIT_MSR_LOAD_COUNT:
      *value = current_evmcs->vm_exit_msr_load_count;
      break;
    case VM_ENTRY_MSR_LOAD_COUNT:
      *value = current_evmcs->vm_entry_msr_load_count;
      break;
    case HOST_ES_SELECTOR:
      *value = current_evmcs->host_es_selector;
      break;
    case HOST_CS_SELECTOR:
      *value = current_evmcs->host_cs_selector;
      break;
    case HOST_SS_SELECTOR:
      *value = current_evmcs->host_ss_selector;
      break;
    case HOST_DS_SELECTOR:
      *value = current_evmcs->host_ds_selector;
      break;
    case HOST_FS_SELECTOR:
      *value = current_evmcs->host_fs_selector;
      break;
    case HOST_GS_SELECTOR:
      *value = current_evmcs->host_gs_selector;
      break;
    case HOST_TR_SELECTOR:
      *value = current_evmcs->host_tr_selector;
      break;
    case GUEST_ES_SELECTOR:
      *value = current_evmcs->guest_es_selector;
      break;
    case GUEST_CS_SELECTOR:
      *value = current_evmcs->guest_cs_selector;
      break;
    case GUEST_SS_SELECTOR:
      *value = current_evmcs->guest_ss_selector;
      break;
    case GUEST_DS_SELECTOR:
      *value = current_evmcs->guest_ds_selector;
      break;
    case GUEST_FS_SELECTOR:
      *value = current_evmcs->guest_fs_selector;
      break;
    case GUEST_GS_SELECTOR:
      *value = current_evmcs->guest_gs_selector;
      break;
    case GUEST_LDTR_SELECTOR:
      *value = current_evmcs->guest_ldtr_selector;
      break;
    case GUEST_TR_SELECTOR:
      *value = current_evmcs->guest_tr_selector;
      break;
    case VIRTUAL_PROCESSOR_ID:
      *value = current_evmcs->virtual_processor_id;
      break;
    case HOST_IA32_PERF_GLOBAL_CTRL:
      *value = current_evmcs->host_ia32_perf_global_ctrl;
      break;
    case GUEST_IA32_PERF_GLOBAL_CTRL:
      *value = current_evmcs->guest_ia32_perf_global_ctrl;
      break;
    case ENCLS_EXITING_BITMAP:
      *value = current_evmcs->encls_exiting_bitmap;
      break;
    case TSC_MULTIPLIER:
      *value = current_evmcs->tsc_multiplier;
      break;
    default:
      return 1;
  }

  return 0;
}

static inline int evmcs_vmwrite(uint64_t encoding, uint64_t value) {
  switch (encoding) {
    case GUEST_RIP:
      current_evmcs->guest_rip = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE;
      break;
    case GUEST_RSP:
      current_evmcs->guest_rsp = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_BASIC;
      break;
    case GUEST_RFLAGS:
      current_evmcs->guest_rflags = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_BASIC;
      break;
    case HOST_IA32_PAT:
      current_evmcs->host_ia32_pat = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1;
      break;
    case HOST_IA32_EFER:
      current_evmcs->host_ia32_efer = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1;
      break;
    case HOST_CR0:
      current_evmcs->host_cr0 = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1;
      break;
    case HOST_CR3:
      current_evmcs->host_cr3 = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1;
      break;
    case HOST_CR4:
      current_evmcs->host_cr4 = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1;
      break;
    case HOST_IA32_SYSENTER_ESP:
      current_evmcs->host_ia32_sysenter_esp = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1;
      break;
    case HOST_IA32_SYSENTER_EIP:
      current_evmcs->host_ia32_sysenter_eip = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1;
      break;
    case HOST_RIP:
      current_evmcs->host_rip = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1;
      break;
    case IO_BITMAP_A:
      current_evmcs->io_bitmap_a = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_IO_BITMAP;
      break;
    case IO_BITMAP_B:
      current_evmcs->io_bitmap_b = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_IO_BITMAP;
      break;
    case MSR_BITMAP:
      current_evmcs->msr_bitmap = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_MSR_BITMAP;
      break;
    case GUEST_ES_BASE:
      current_evmcs->guest_es_base = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_CS_BASE:
      current_evmcs->guest_cs_base = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_SS_BASE:
      current_evmcs->guest_ss_base = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_DS_BASE:
      current_evmcs->guest_ds_base = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_FS_BASE:
      current_evmcs->guest_fs_base = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_GS_BASE:
      current_evmcs->guest_gs_base = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_LDTR_BASE:
      current_evmcs->guest_ldtr_base = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_TR_BASE:
      current_evmcs->guest_tr_base = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_GDTR_BASE:
      current_evmcs->guest_gdtr_base = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_IDTR_BASE:
      current_evmcs->guest_idtr_base = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case TSC_OFFSET:
      current_evmcs->tsc_offset = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP2;
      break;
    case VIRTUAL_APIC_PAGE_ADDR:
      current_evmcs->virtual_apic_page_addr = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP2;
      break;
    case VMCS_LINK_POINTER:
      current_evmcs->vmcs_link_pointer = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1;
      break;
    case GUEST_IA32_DEBUGCTL:
      current_evmcs->guest_ia32_debugctl = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1;
      break;
    case GUEST_IA32_PAT:
      current_evmcs->guest_ia32_pat = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1;
      break;
    case GUEST_IA32_EFER:
      current_evmcs->guest_ia32_efer = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1;
      break;
    case GUEST_PDPTR0:
      current_evmcs->guest_pdptr0 = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1;
      break;
    case GUEST_PDPTR1:
      current_evmcs->guest_pdptr1 = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1;
      break;
    case GUEST_PDPTR2:
      current_evmcs->guest_pdptr2 = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1;
      break;
    case GUEST_PDPTR3:
      current_evmcs->guest_pdptr3 = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1;
      break;
    case GUEST_PENDING_DBG_EXCEPTIONS:
      current_evmcs->guest_pending_dbg_exceptions = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1;
      break;
    case GUEST_SYSENTER_ESP:
      current_evmcs->guest_sysenter_esp = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1;
      break;
    case GUEST_SYSENTER_EIP:
      current_evmcs->guest_sysenter_eip = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1;
      break;
    case CR0_GUEST_HOST_MASK:
      current_evmcs->cr0_guest_host_mask = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR;
      break;
    case CR4_GUEST_HOST_MASK:
      current_evmcs->cr4_guest_host_mask = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR;
      break;
    case CR0_READ_SHADOW:
      current_evmcs->cr0_read_shadow = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR;
      break;
    case CR4_READ_SHADOW:
      current_evmcs->cr4_read_shadow = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR;
      break;
    case GUEST_CR0:
      current_evmcs->guest_cr0 = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR;
      break;
    case GUEST_CR3:
      current_evmcs->guest_cr3 = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR;
      break;
    case GUEST_CR4:
      current_evmcs->guest_cr4 = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR;
      break;
    case GUEST_DR7:
      current_evmcs->guest_dr7 = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR;
      break;
    case HOST_FS_BASE:
      current_evmcs->host_fs_base = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER;
      break;
    case HOST_GS_BASE:
      current_evmcs->host_gs_base = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER;
      break;
    case HOST_TR_BASE:
      current_evmcs->host_tr_base = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER;
      break;
    case HOST_GDTR_BASE:
      current_evmcs->host_gdtr_base = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER;
      break;
    case HOST_IDTR_BASE:
      current_evmcs->host_idtr_base = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER;
      break;
    case HOST_RSP:
      current_evmcs->host_rsp = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER;
      break;
    case EPT_POINTER:
      current_evmcs->ept_pointer = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_XLAT;
      break;
    case GUEST_BNDCFGS:
      current_evmcs->guest_bndcfgs = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1;
      break;
    case XSS_EXIT_BITMAP:
      current_evmcs->xss_exit_bitmap = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP2;
      break;
    case GUEST_PHYSICAL_ADDRESS:
      current_evmcs->guest_physical_address = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE;
      break;
    case EXIT_QUALIFICATION:
      current_evmcs->exit_qualification = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE;
      break;
    case GUEST_LINEAR_ADDRESS:
      current_evmcs->guest_linear_address = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE;
      break;
    case VM_EXIT_MSR_STORE_ADDR:
      current_evmcs->vm_exit_msr_store_addr = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL;
      break;
    case VM_EXIT_MSR_LOAD_ADDR:
      current_evmcs->vm_exit_msr_load_addr = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL;
      break;
    case VM_ENTRY_MSR_LOAD_ADDR:
      current_evmcs->vm_entry_msr_load_addr = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL;
      break;
    case CR3_TARGET_VALUE0:
      current_evmcs->cr3_target_value0 = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL;
      break;
    case CR3_TARGET_VALUE1:
      current_evmcs->cr3_target_value1 = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL;
      break;
    case CR3_TARGET_VALUE2:
      current_evmcs->cr3_target_value2 = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL;
      break;
    case CR3_TARGET_VALUE3:
      current_evmcs->cr3_target_value3 = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL;
      break;
    case TPR_THRESHOLD:
      current_evmcs->tpr_threshold = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE;
      break;
    case GUEST_INTERRUPTIBILITY_INFO:
      current_evmcs->guest_interruptibility_info = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_BASIC;
      break;
    case CPU_BASED_VM_EXEC_CONTROL:
      current_evmcs->cpu_based_vm_exec_control = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_PROC;
      break;
    case EXCEPTION_BITMAP:
      current_evmcs->exception_bitmap = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_EXCPN;
      break;
    case VM_ENTRY_CONTROLS:
      current_evmcs->vm_entry_controls = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_ENTRY;
      break;
    case VM_ENTRY_INTR_INFO_FIELD:
      current_evmcs->vm_entry_intr_info_field = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_EVENT;
      break;
    case VM_ENTRY_EXCEPTION_ERROR_CODE:
      current_evmcs->vm_entry_exception_error_code = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_EVENT;
      break;
    case VM_ENTRY_INSTRUCTION_LEN:
      current_evmcs->vm_entry_instruction_len = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_EVENT;
      break;
    case HOST_IA32_SYSENTER_CS:
      current_evmcs->host_ia32_sysenter_cs = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1;
      break;
    case PIN_BASED_VM_EXEC_CONTROL:
      current_evmcs->pin_based_vm_exec_control = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP1;
      break;
    case VM_EXIT_CONTROLS:
      current_evmcs->vm_exit_controls = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP1;
      break;
    case SECONDARY_VM_EXEC_CONTROL:
      current_evmcs->secondary_vm_exec_control = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP1;
      break;
    case GUEST_ES_LIMIT:
      current_evmcs->guest_es_limit = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_CS_LIMIT:
      current_evmcs->guest_cs_limit = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_SS_LIMIT:
      current_evmcs->guest_ss_limit = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_DS_LIMIT:
      current_evmcs->guest_ds_limit = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_FS_LIMIT:
      current_evmcs->guest_fs_limit = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_GS_LIMIT:
      current_evmcs->guest_gs_limit = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_LDTR_LIMIT:
      current_evmcs->guest_ldtr_limit = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_TR_LIMIT:
      current_evmcs->guest_tr_limit = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_GDTR_LIMIT:
      current_evmcs->guest_gdtr_limit = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_IDTR_LIMIT:
      current_evmcs->guest_idtr_limit = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_ES_AR_BYTES:
      current_evmcs->guest_es_ar_bytes = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_CS_AR_BYTES:
      current_evmcs->guest_cs_ar_bytes = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_SS_AR_BYTES:
      current_evmcs->guest_ss_ar_bytes = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_DS_AR_BYTES:
      current_evmcs->guest_ds_ar_bytes = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_FS_AR_BYTES:
      current_evmcs->guest_fs_ar_bytes = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_GS_AR_BYTES:
      current_evmcs->guest_gs_ar_bytes = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_LDTR_AR_BYTES:
      current_evmcs->guest_ldtr_ar_bytes = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_TR_AR_BYTES:
      current_evmcs->guest_tr_ar_bytes = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_ACTIVITY_STATE:
      current_evmcs->guest_activity_state = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1;
      break;
    case GUEST_SYSENTER_CS:
      current_evmcs->guest_sysenter_cs = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1;
      break;
    case VM_INSTRUCTION_ERROR:
      current_evmcs->vm_instruction_error = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE;
      break;
    case VM_EXIT_REASON:
      current_evmcs->vm_exit_reason = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE;
      break;
    case VM_EXIT_INTR_INFO:
      current_evmcs->vm_exit_intr_info = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE;
      break;
    case VM_EXIT_INTR_ERROR_CODE:
      current_evmcs->vm_exit_intr_error_code = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE;
      break;
    case IDT_VECTORING_INFO_FIELD:
      current_evmcs->idt_vectoring_info_field = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE;
      break;
    case IDT_VECTORING_ERROR_CODE:
      current_evmcs->idt_vectoring_error_code = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE;
      break;
    case VM_EXIT_INSTRUCTION_LEN:
      current_evmcs->vm_exit_instruction_len = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE;
      break;
    case VMX_INSTRUCTION_INFO:
      current_evmcs->vmx_instruction_info = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE;
      break;
    case PAGE_FAULT_ERROR_CODE_MASK:
      current_evmcs->page_fault_error_code_mask = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL;
      break;
    case PAGE_FAULT_ERROR_CODE_MATCH:
      current_evmcs->page_fault_error_code_match = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL;
      break;
    case CR3_TARGET_COUNT:
      current_evmcs->cr3_target_count = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL;
      break;
    case VM_EXIT_MSR_STORE_COUNT:
      current_evmcs->vm_exit_msr_store_count = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL;
      break;
    case VM_EXIT_MSR_LOAD_COUNT:
      current_evmcs->vm_exit_msr_load_count = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL;
      break;
    case VM_ENTRY_MSR_LOAD_COUNT:
      current_evmcs->vm_entry_msr_load_count = value;
      current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL;
      break;
    case HOST_ES_SELECTOR:
      current_evmcs->host_es_selector = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1;
      break;
    case HOST_CS_SELECTOR:
      current_evmcs->host_cs_selector = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1;
      break;
    case HOST_SS_SELECTOR:
      current_evmcs->host_ss_selector = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1;
      break;
    case HOST_DS_SELECTOR:
      current_evmcs->host_ds_selector = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1;
      break;
    case HOST_FS_SELECTOR:
      current_evmcs->host_fs_selector = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1;
      break;
    case HOST_GS_SELECTOR:
      current_evmcs->host_gs_selector = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1;
      break;
    case HOST_TR_SELECTOR:
      current_evmcs->host_tr_selector = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1;
      break;
    case GUEST_ES_SELECTOR:
      current_evmcs->guest_es_selector = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_CS_SELECTOR:
      current_evmcs->guest_cs_selector = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_SS_SELECTOR:
      current_evmcs->guest_ss_selector = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_DS_SELECTOR:
      current_evmcs->guest_ds_selector = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_FS_SELECTOR:
      current_evmcs->guest_fs_selector = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_GS_SELECTOR:
      current_evmcs->guest_gs_selector = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_LDTR_SELECTOR:
      current_evmcs->guest_ldtr_selector = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case GUEST_TR_SELECTOR:
      current_evmcs->guest_tr_selector = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2;
      break;
    case VIRTUAL_PROCESSOR_ID:
      current_evmcs->virtual_processor_id = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_XLAT;
      break;
    case HOST_IA32_PERF_GLOBAL_CTRL:
      current_evmcs->host_ia32_perf_global_ctrl = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1;
      break;
    case GUEST_IA32_PERF_GLOBAL_CTRL:
      current_evmcs->guest_ia32_perf_global_ctrl = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1;
      break;
    case ENCLS_EXITING_BITMAP:
      current_evmcs->encls_exiting_bitmap = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP2;
      break;
    case TSC_MULTIPLIER:
      current_evmcs->tsc_multiplier = value;
      current_evmcs->hv_clean_fields &=
          ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP2;
      break;
    default:
      return 1;
  }

  return 0;
}
struct hv_nested_enlightenments_control {
  struct {
    uint32_t directhypercall : 1;
    uint32_t reserved : 31;
  } features;
  struct {
    uint32_t reserved;
  } hypercallControls;
} __attribute__((__packed__));

/* Define virtual processor assist page structure. */
struct hv_vp_assist_page {
  uint32_t apic_assist;
  uint32_t reserved1;
  uint64_t vtl_control[3];
  struct hv_nested_enlightenments_control nested_control;
  uint8_t enlighten_vmentry;
  uint8_t reserved2[7];
  uint64_t current_nested_vmcs;
} __attribute__((__packed__));

int InitializeVMCS(uint64_t host_entry, uint64_t guest_entry);