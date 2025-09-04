/////////////////////////////////////////////////////////////////////////
// $Id: vmx.cc 14319 2021-07-23 10:13:48Z sshwarts $
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

#include "vmx.h"

#ifdef DEBUG
#define DEBUG_PRINT(...) wprintf(__VA_ARGS__)
#else
#define DEBUG_PRINT(...)
#endif

bool in_smm = 0;
uint64_t vmxonptr;

uint64_t restore_vmcs[200];
uint8_t vmcs[4096] __attribute__((aligned(4096)));
uint8_t shadow_vmcs[4096] __attribute__((aligned(4096)));
uint8_t vmxon_region[4096] __attribute__((aligned(4096)));

uint64_t msr_load[1024] __attribute__((aligned(4096)));
uint64_t msr_store[1024] __attribute__((aligned(4096)));
uint64_t vmentry_msr_load[1024] __attribute__((aligned(4096)));

uint8_t host_stack[4096] __attribute__((aligned(4096)));
uint8_t guest_stack[4096] __attribute__((aligned(4096)));
uint8_t vp_assist[4096] __attribute__((aligned(4096)));
uint8_t tss[4096] __attribute__((aligned(4096)));
uint8_t io_bitmap_a[4096] __attribute__((aligned(4096)));
uint8_t io_bitmap_b[4096] __attribute__((aligned(4096)));
uint8_t msr_bitmap[4096] __attribute__((aligned(4096)));
uint8_t vmread_bitmap[4096] __attribute__((aligned(4096)));
uint8_t vmwrite_bitmap[4096] __attribute__((aligned(4096)));
uint8_t apic_access[4096] __attribute__((aligned(4096)));
uint8_t virtual_apic[4096] __attribute__((aligned(4096)));

uint64_t posted_int_desc[8] __attribute__((aligned(4096)));
uint64_t pml[512] __attribute__((aligned(4096)));
uint64_t eptp_list[512] __attribute__((aligned(4096)));
uint32_t excep_info_area[6] __attribute__((aligned(4096)));

bool isMemTypeValidMTRR(unsigned memtype) {
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

bool isMemTypeValidPAT(unsigned memtype) {
  return (memtype == 0x07) /* UC- */ || isMemTypeValidMTRR(memtype);
}

bool isValidMSR_PAT(uint64_t pat_val) {
  // use packed register as 64-bit value with convinient accessors
  //   BxPackedRegister pat_msr = pat_val;
  for (unsigned i = 0; i < 8; i++)
    if (!isMemTypeValidPAT((pat_val >> i * 8) & 0xff))
      return false;

  return true;
}
uint64_t makeValidMSR_PAT(uint64_t pat_val) {
  // use packed register as 64-bit value with convinient accessors
  //   BxPackedRegister pat_msr = pat_val; 0,1,4,5,6,7
  uint64_t pat_msr = 0;
  uint8_t pat8 = 0;
  for (unsigned i = 0; i < 8; i++) {
    pat8 = (pat_val >> i * 8) & 0xff;
    if (!isMemTypeValidPAT(pat8)) {
      if (pat8 & 1 << 2) {
        pat_msr = (pat_msr << i * 8) | (pat8 & 0x07);
      } else {
        pat_msr = (pat_msr << i * 8) | (pat8 & 0x01);
      }
    } else {
      pat_msr = (pat_msr << i * 8) | (pat8);
    }
  }

  return pat_msr;
}

const uint64_t BX_CET_SHADOW_STACK_ENABLED = (1 << 0);
const uint64_t BX_CET_SHADOW_STACK_WRITE_ENABLED = (1 << 1);
const uint64_t BX_CET_ENDBRANCH_ENABLED = (1 << 2);
const uint64_t BX_CET_LEGACY_INDIRECT_BRANCH_TREATMENT = (1 << 3);
const uint64_t BX_CET_ENABLE_NO_TRACK_INDIRECT_BRANCH_PREFIX = (1 << 4);
const uint64_t BX_CET_SUPPRESS_DIS = (1 << 5);
const uint64_t BX_CET_SUPPRESS_INDIRECT_BRANCH_TRACKING = (1 << 10);
const uint64_t BX_CET_WAIT_FOR_ENBRANCH = (1 << 11);

bool is_invalid_cet_control(bx_address val) {
  if ((val &
       (BX_CET_SUPPRESS_INDIRECT_BRANCH_TRACKING | BX_CET_WAIT_FOR_ENBRANCH)) ==
      (BX_CET_SUPPRESS_INDIRECT_BRANCH_TRACKING | BX_CET_WAIT_FOR_ENBRANCH))
    return true;

  if (val & 0x3c0)
    return true;  // reserved bits check
  return false;
}

const unsigned short* segname[] = {L"es", L"cs", L"ss", L"ds", L"fs", L"gs"};
struct BxExceptionInfo exceptions_info[] = {
    /* DE */ {BX_ET_CONTRIBUTORY, BX_EXCEPTION_CLASS_FAULT, 0},
    /* DB */ {BX_ET_BENIGN, BX_EXCEPTION_CLASS_FAULT, 0},
    /* 02 */ {BX_ET_BENIGN, BX_EXCEPTION_CLASS_FAULT, 0},  // NMI
    /* BP */ {BX_ET_BENIGN, BX_EXCEPTION_CLASS_TRAP, 0},
    /* OF */ {BX_ET_BENIGN, BX_EXCEPTION_CLASS_TRAP, 0},
    /* BR */ {BX_ET_BENIGN, BX_EXCEPTION_CLASS_FAULT, 0},
    /* UD */ {BX_ET_BENIGN, BX_EXCEPTION_CLASS_FAULT, 0},
    /* NM */ {BX_ET_BENIGN, BX_EXCEPTION_CLASS_FAULT, 0},
    /* DF */ {BX_ET_DOUBLE_FAULT, BX_EXCEPTION_CLASS_FAULT, 1},
    // coprocessor segment overrun (286,386 only)
    /* 09 */ {BX_ET_BENIGN, BX_EXCEPTION_CLASS_FAULT, 0},
    /* TS */ {BX_ET_CONTRIBUTORY, BX_EXCEPTION_CLASS_FAULT, 1},
    /* NP */ {BX_ET_CONTRIBUTORY, BX_EXCEPTION_CLASS_FAULT, 1},
    /* SS */ {BX_ET_CONTRIBUTORY, BX_EXCEPTION_CLASS_FAULT, 1},
    /* GP */ {BX_ET_CONTRIBUTORY, BX_EXCEPTION_CLASS_FAULT, 1},
    /* PF */ {BX_ET_PAGE_FAULT, BX_EXCEPTION_CLASS_FAULT, 1},
    /* 15 */ {BX_ET_BENIGN, BX_EXCEPTION_CLASS_FAULT, 0},  // reserved
    /* MF */ {BX_ET_BENIGN, BX_EXCEPTION_CLASS_FAULT, 0},
    /* AC */ {BX_ET_BENIGN, BX_EXCEPTION_CLASS_FAULT, 1},
    /* MC */ {BX_ET_BENIGN, BX_EXCEPTION_CLASS_ABORT, 0},
    /* XM */ {BX_ET_BENIGN, BX_EXCEPTION_CLASS_FAULT, 0},
    /* VE */ {BX_ET_PAGE_FAULT, BX_EXCEPTION_CLASS_FAULT, 0},
    /* CP */ {BX_ET_CONTRIBUTORY, BX_EXCEPTION_CLASS_FAULT, 1},
    /* 22 */ {BX_ET_BENIGN, BX_EXCEPTION_CLASS_FAULT, 0},
    /* 23 */ {BX_ET_BENIGN, BX_EXCEPTION_CLASS_FAULT, 0},
    /* 24 */ {BX_ET_BENIGN, BX_EXCEPTION_CLASS_FAULT, 0},
    /* 25 */ {BX_ET_BENIGN, BX_EXCEPTION_CLASS_FAULT, 0},
    /* 26 */ {BX_ET_BENIGN, BX_EXCEPTION_CLASS_FAULT, 0},
    /* 27 */ {BX_ET_BENIGN, BX_EXCEPTION_CLASS_FAULT, 0},
    /* 28 */ {BX_ET_BENIGN, BX_EXCEPTION_CLASS_FAULT, 0},
    /* 29 */ {BX_ET_BENIGN, BX_EXCEPTION_CLASS_FAULT, 0},
    /* 30 */ {BX_ET_BENIGN, BX_EXCEPTION_CLASS_FAULT, 0},  // FIXME: SVM #SF
    /* 31 */ {BX_ET_BENIGN, BX_EXCEPTION_CLASS_FAULT, 0}};

////////////////////////////////////////////////////////////
// VMEXIT reasons
////////////////////////////////////////////////////////////

const unsigned short* VMX_vmexit_reason_name[] = {
    /*  0 */ L"Exception or NMI",
    /*  1 */ L"External Interrupt",
    /*  2 */ L"Triple Fault",
    /*  3 */ L"INIT",
    /*  4 */ L"SIPI",
    /*  5 */ L"I/O SMI (SMM Vmexit)",
    /*  6 */ L"SMI (SMM Vmexit)",
    /*  7 */ L"Interrupt Window Exiting",
    /*  8 */ L"NMI Window Exiting",
    /*  9 */ L"Task Switch",
    /* 10 */ L"CPUID",
    /* 11 */ L"GETSEC",
    /* 12 */ L"HLT",
    /* 13 */ L"INVD",
    /* 14 */ L"INVLPG",
    /* 15 */ L"RDPMC",
    /* 16 */ L"RDTSC",
    /* 17 */ L"RSM",
    /* 18 */ L"VMCALL",
    /* 19 */ L"VMCLEAR",
    /* 20 */ L"VMLAUNCH",
    /* 21 */ L"VMPTRLD",
    /* 22 */ L"VMPTRST",
    /* 23 */ L"VMREAD",
    /* 24 */ L"VMRESUME",
    /* 25 */ L"VMWRITE",
    /* 26 */ L"VMXOFF",
    /* 27 */ L"VMXON",
    /* 28 */ L"CR Access",
    /* 29 */ L"DR Access",
    /* 30 */ L"I/O Instruction",
    /* 31 */ L"RDMSR",
    /* 32 */ L"WRMSR",
    /* 33 */ L"VMEntry failure due to invalid guest state",
    /* 34 */ L"VMEntry failure due to MSR loading",
    /* 35 */ L"Reserved35",
    /* 36 */ L"MWAIT",
    /* 37 */ L"MTF (Monitor Trap Flag)",
    /* 38 */ L"Reserved38",
    /* 39 */ L"MONITOR",
    /* 40 */ L"PAUSE",
    /* 41 */ L"VMEntry failure due to machine check",
    /* 42 */ L"Reserved42",
    /* 43 */ L"TPR Below Threshold",
    /* 44 */ L"APIC Access",
    /* 45 */ L"Virtualized EOI",
    /* 46 */ L"GDTR/IDTR Access",
    /* 47 */ L"LDTR/TR Access",
    /* 48 */ L"EPT Violation",
    /* 49 */ L"EPT Misconfiguration",
    /* 50 */ L"INVEPT",
    /* 51 */ L"RDTSCP",
    /* 52 */ L"VMX preemption timer expired",
    /* 53 */ L"INVVPID",
    /* 54 */ L"WBINVD",
    /* 55 */ L"XSETBV",
    /* 56 */ L"APIC Write Trap",
    /* 57 */ L"RDRAND",
    /* 58 */ L"INVPCID",
    /* 59 */ L"VMFUNC",
    /* 60 */ L"ENCLS",
    /* 61 */ L"RDSEED",
    /* 62 */ L"PML Log Full",
    /* 63 */ L"XSAVES",
    /* 64 */ L"XRSTORS",
    /* 65 */ L"Reserved65",
    /* 66 */ L"Sub-Page Protection",
    /* 67 */ L"UMWAIT",
    /* 68 */ L"TPAUSE",
    /* 69 */ L"Reserved69",
    /* 70 */ L"Reserved70",
    /* 71 */ L"Reserved71",
    /* 72 */ L"ENQCMD PASID Translation",
    /* 73 */ L"ENQCMDS PASID Translation",
};

#define VMENTRY_INJECTING_EVENT(vmentry_interr_info) \
  (vmentry_interr_info & 0x80000000)

#define VMX_CHECKS_USE_MSR_VMX_PINBASED_CTRLS_LO              \
  ((BX_SUPPORT_VMX >= 2) ? VMX_MSR_VMX_TRUE_PINBASED_CTRLS_LO \
                         : VMX_MSR_VMX_PINBASED_CTRLS_LO)
#define VMX_CHECKS_USE_MSR_VMX_PINBASED_CTRLS_HI              \
  ((BX_SUPPORT_VMX >= 2) ? VMX_MSR_VMX_TRUE_PINBASED_CTRLS_HI \
                         : VMX_MSR_VMX_PINBASED_CTRLS_HI)

#define VMX_CHECKS_USE_MSR_VMX_PROCBASED_CTRLS_LO              \
  ((BX_SUPPORT_VMX >= 2) ? VMX_MSR_VMX_TRUE_PROCBASED_CTRLS_LO \
                         : VMX_MSR_VMX_PROCBASED_CTRLS_LO)
#define VMX_CHECKS_USE_MSR_VMX_PROCBASED_CTRLS_HI              \
  ((BX_SUPPORT_VMX >= 2) ? VMX_MSR_VMX_TRUE_PROCBASED_CTRLS_HI \
                         : VMX_MSR_VMX_PROCBASED_CTRLS_HI)

#define VMX_CHECKS_USE_MSR_VMX_VMEXIT_CTRLS_LO              \
  ((BX_SUPPORT_VMX >= 2) ? VMX_MSR_VMX_TRUE_VMEXIT_CTRLS_LO \
                         : VMX_MSR_VMX_VMEXIT_CTRLS_LO)
#define VMX_CHECKS_USE_MSR_VMX_VMEXIT_CTRLS_HI              \
  ((BX_SUPPORT_VMX >= 2) ? VMX_MSR_VMX_TRUE_VMEXIT_CTRLS_HI \
                         : VMX_MSR_VMX_VMEXIT_CTRLS_HI)

#define VMX_CHECKS_USE_MSR_VMX_VMENTRY_CTRLS_LO              \
  ((BX_SUPPORT_VMX >= 2) ? VMX_MSR_VMX_TRUE_VMENTRY_CTRLS_LO \
                         : VMX_MSR_VMX_VMENTRY_CTRLS_LO)
#define VMX_CHECKS_USE_MSR_VMX_VMENTRY_CTRLS_HI              \
  ((BX_SUPPORT_VMX >= 2) ? VMX_MSR_VMX_TRUE_VMENTRY_CTRLS_HI \
                         : VMX_MSR_VMX_VMENTRY_CTRLS_HI)

#if BX_SUPPORT_X86_64
static inline bool IsCanonical(bx_address offset) {
  return ((uint64_t)((((int64_t)(offset)) >> (BX_LIN_ADDRESS_WIDTH - 1)) + 1) <
          2);
}
static inline bx_address MakeCanonical(bx_address offset) {
  int64_t sign_extended = ((int64_t)offset) << (64 - BX_LIN_ADDRESS_WIDTH);
  return (bx_address)(sign_extended >> (64 - BX_LIN_ADDRESS_WIDTH));
}
#endif

static inline bool IsValidPhyAddr(bx_phy_address addr) {
  return ((addr & BX_PHY_ADDRESS_RESERVED_BITS) == 0);
}

static inline bool IsValidPageAlignedPhyAddr(bx_phy_address addr) {
  return ((addr & (BX_PHY_ADDRESS_RESERVED_BITS | 0xfff)) == 0);
}

#if BX_SUPPORT_VMX >= 2
bool is_eptptr_valid(uint64_t eptptr) {
  // [2:0] EPT paging-structure memory type
  //       0 = Uncacheable (UC)
  //       6 = Write-back (WB)
  uint32_t memtype = eptptr & 7;
  if (memtype != BX_MEMTYPE_UC && memtype != BX_MEMTYPE_WB)
    return 0;

  // [5:3] This value is 1 less than the EPT page-walk length
  uint32_t walk_length = (eptptr >> 3) & 7;
  if (walk_length != 3)
    return 0;

  // [6]   EPT A/D Enable
  //   if (! BX_SUPPORT_VMX_EXTENSION(BX_VMX_EPT_ACCESS_DIRTY)) {
  if (!(VMX_MSR_VMX_EPT_VPID_CAP & 1 << 21)) {
    if (eptptr & 0x40) {
      // // DEBUG_PRINT(L"is_eptptr_valid: EPTPTR A/D enabled when not supported
      // by CPU\r\n");
      return 0;
    }
  }

  // [7]   CET: Enable supervisor shadow stack control
#if BX_SUPPORT_CET
  //   if (! BX_CPUID_SUPPORT_ISA_EXTENSION(BX_ISA_CET)) {
  if (!(VMX_MSR_VMX_BASIC & (uint64_t)1 << 56)) {
    if (eptptr & 0x80) {
      // // DEBUG_PRINT(L"is_eptptr_valid: EPTPTR CET supervisor shadow stack
      // control bit enabled when not supported by CPU\r\n");
      return 0;
    }
  }
#endif

#define BX_EPTPTR_RESERVED_BITS 0xf00 /* bits 11:8 are reserved */
  if (eptptr & BX_EPTPTR_RESERVED_BITS) {
    // // DEBUG_PRINT(L"is_eptptr_valid: EPTPTR reserved bits set\r\n");
    return 0;
  }

  if (!IsValidPhyAddr(eptptr))
    return 0;
  return 1;
}
#endif
VMCS_CACHE vm;
enum VMX_error_code VMenterLoadCheckVmControls(void) {
  //
  // Load VM-execution control fields to VMCS Cache
  //
  vm.vmexec_ctrls1 = vmread(VMCS_32BIT_CONTROL_PIN_BASED_EXEC_CONTROLS);
  vm.vmexec_ctrls2 = vmread(VMCS_32BIT_CONTROL_PROCESSOR_BASED_VMEXEC_CONTROLS);
  if (VMEXIT(VMX_VM_EXEC_CTRL2_SECONDARY_CONTROLS))
    vm.vmexec_ctrls3 = vmread(VMCS_32BIT_CONTROL_SECONDARY_VMEXEC_CONTROLS);
  else {
    vm.vmexec_ctrls3 = 0;
    vmwrite(VMCS_32BIT_CONTROL_SECONDARY_VMEXEC_CONTROLS, 0);
  }
  vm.vm_exceptions_bitmap = vmread(VMCS_32BIT_CONTROL_EXECUTION_BITMAP);
  vm.vm_pf_mask = vmread(VMCS_32BIT_CONTROL_PAGE_FAULT_ERR_CODE_MASK);
  vm.vm_pf_match = vmread(VMCS_32BIT_CONTROL_PAGE_FAULT_ERR_CODE_MATCH);
  vm.vm_cr0_mask = vmread(VMCS_CONTROL_CR0_GUEST_HOST_MASK);
  vm.vm_cr4_mask = vmread(VMCS_CONTROL_CR4_GUEST_HOST_MASK);
  vm.vm_cr0_read_shadow = vmread(VMCS_CONTROL_CR0_READ_SHADOW);
  vm.vm_cr4_read_shadow = vmread(VMCS_CONTROL_CR4_READ_SHADOW);

  vm.vm_cr3_target_cnt = vmread(VMCS_32BIT_CONTROL_CR3_TARGET_COUNT);
  for (int n = 0; n < VMX_CR3_TARGET_MAX_CNT; n++)
    vm.vm_cr3_target_value[n] = vmread(VMCS_CR3_TARGET0 + 2 * n);

  //
  // Check VM-execution control fields
  //

  if (~vm.vmexec_ctrls1 & VMX_CHECKS_USE_MSR_VMX_PINBASED_CTRLS_LO) {
    DEBUG_PRINT(
        L"VMFAIL: VMCS EXEC CTRL: VMX pin-based controls allowed "
        L"0-settings\r\n");
    vm.vmexec_ctrls1 |= VMX_CHECKS_USE_MSR_VMX_PINBASED_CTRLS_LO;
    vmwrite(VMCS_32BIT_CONTROL_PIN_BASED_EXEC_CONTROLS, vm.vmexec_ctrls1);
  }
  if (vm.vmexec_ctrls1 & ~VMX_CHECKS_USE_MSR_VMX_PINBASED_CTRLS_HI) {
    DEBUG_PRINT(
        L"VMFAIL: VMCS EXEC CTRL: VMX pin-based controls allowed "
        L"1-settings\r\n");
    vm.vmexec_ctrls1 &= VMX_CHECKS_USE_MSR_VMX_PINBASED_CTRLS_HI;
    vmwrite(VMCS_32BIT_CONTROL_PIN_BASED_EXEC_CONTROLS, vm.vmexec_ctrls1);
  }

  if (~vm.vmexec_ctrls2 & VMX_CHECKS_USE_MSR_VMX_PROCBASED_CTRLS_LO) {
    DEBUG_PRINT(
        L"VMFAIL: VMCS EXEC CTRL: VMX proc-based controls allowed "
        L"0-settings\r\n");
    vm.vmexec_ctrls2 |= VMX_CHECKS_USE_MSR_VMX_PROCBASED_CTRLS_LO;
    vmwrite(VMCS_32BIT_CONTROL_PROCESSOR_BASED_VMEXEC_CONTROLS,
            vm.vmexec_ctrls2);
  }
  if (vm.vmexec_ctrls2 & ~VMX_CHECKS_USE_MSR_VMX_PROCBASED_CTRLS_HI) {
    DEBUG_PRINT(
        L"VMFAIL: VMCS EXEC CTRL: VMX proc-based controls allowed "
        L"1-settings\r\n");
    vm.vmexec_ctrls2 &= VMX_CHECKS_USE_MSR_VMX_PROCBASED_CTRLS_HI;
    vmwrite(VMCS_32BIT_CONTROL_PROCESSOR_BASED_VMEXEC_CONTROLS,
            vm.vmexec_ctrls2);
  }

  if (~vm.vmexec_ctrls3 & VMX_MSR_VMX_PROCBASED_CTRLS2_LO) {
    DEBUG_PRINT(
        L"VMFAIL: VMCS EXEC CTRL: VMX secondary proc-based controls allowed "
        L"0-settings\r\n");
    vm.vmexec_ctrls3 |= VMX_MSR_VMX_PROCBASED_CTRLS2_LO;
    vmwrite(VMCS_32BIT_CONTROL_SECONDARY_VMEXEC_CONTROLS, vm.vmexec_ctrls3);
  }
  if (vm.vmexec_ctrls3 & ~VMX_MSR_VMX_PROCBASED_CTRLS2_HI) {
    DEBUG_PRINT(
        L"VMFAIL: VMCS EXEC CTRL: VMX secondary controls allowed "
        L"1-settings\r\n");
    vm.vmexec_ctrls3 &= VMX_MSR_VMX_PROCBASED_CTRLS2_HI;
    vmwrite(VMCS_32BIT_CONTROL_SECONDARY_VMEXEC_CONTROLS, vm.vmexec_ctrls3);
  }

  if (vm.vm_cr3_target_cnt >
      ((VMX_MSR_MISC >> 16) & 0xf)) {  // VMX_CR3_TARGET_MAX_CNT
    DEBUG_PRINT(L"VMFAIL: VMCS EXEC CTRL: too may CR3 targets %d\r\n",
                vm.vm_cr3_target_cnt);
    vm.vm_cr3_target_cnt = (VMX_MSR_MISC >> 16) & 0xf;
    vmwrite(VMCS_32BIT_CONTROL_CR3_TARGET_COUNT, vm.vm_cr3_target_cnt);
  }

  if (vm.vmexec_ctrls2 & VMX_VM_EXEC_CTRL2_IO_BITMAPS) {
    vm.io_bitmap_addr[0] = vmread(VMCS_64BIT_CONTROL_IO_BITMAP_A);
    vm.io_bitmap_addr[1] = vmread(VMCS_64BIT_CONTROL_IO_BITMAP_B);
    // I/O bitmaps control enabled
    for (int bitmap = 0; bitmap < 2; bitmap++) {
      if (!IsValidPageAlignedPhyAddr(vm.io_bitmap_addr[bitmap])) {
        DEBUG_PRINT(
            L"VMFAIL: VMCS EXEC CTRL: I/O bitmap %c phy addr malformed\r\n",
            'A' + bitmap);
        return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
      }
    }
  }

  if (vm.vmexec_ctrls2 & VMX_VM_EXEC_CTRL2_MSR_BITMAPS) {
    vm.msr_bitmap_addr = (bx_phy_address)vmread(VMCS_64BIT_CONTROL_MSR_BITMAPS);
    if (!IsValidPageAlignedPhyAddr(vm.msr_bitmap_addr)) {
      DEBUG_PRINT(
          L"VMFAIL: VMCS EXEC CTRL: MSR bitmap phy addr malformed 0x%x\r\n",
          vm.msr_bitmap_addr);
      return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
    }
  }

  if (!(vm.vmexec_ctrls1 & VMX_VM_EXEC_CTRL1_NMI_EXITING)) {
    if (vm.vmexec_ctrls1 & VMX_VM_EXEC_CTRL1_VIRTUAL_NMI) {
      DEBUG_PRINT(
          L"VMFAIL: VMCS EXEC CTRL: misconfigured virtual NMI control\r\n");
      vm.vmexec_ctrls1 &= ~(VMX_VM_EXEC_CTRL1_VIRTUAL_NMI);
      vmwrite(VMCS_32BIT_CONTROL_PIN_BASED_EXEC_CONTROLS, vm.vmexec_ctrls1);
    }
  }

  if (!(vm.vmexec_ctrls1 & VMX_VM_EXEC_CTRL1_VIRTUAL_NMI)) {
    if (vm.vmexec_ctrls2 & VMX_VM_EXEC_CTRL2_NMI_WINDOW_EXITING) {
      DEBUG_PRINT(
          L"VMFAIL: VMCS EXEC CTRL: misconfigured NMI window exiting\r\n");
      vm.vmexec_ctrls2 &= ~(VMX_VM_EXEC_CTRL2_NMI_WINDOW_EXITING);
      vmwrite(VMCS_32BIT_CONTROL_PROCESSOR_BASED_VMEXEC_CONTROLS,
              vm.vmexec_ctrls2);
    }
  }

  if (vm.vmexec_ctrls1 & VMX_VM_EXEC_CTRL1_PROCESS_POSTED_INTERRUPTS) {
    if (VMEXIT(VMX_VM_EXEC_CTRL2_SECONDARY_CONTROLS)) {
      vm.vmexec_ctrls3 |= VMX_VM_EXEC_CTRL3_VIRTUAL_INT_DELIVERY;
      vmwrite(VMCS_32BIT_CONTROL_SECONDARY_VMEXEC_CONTROLS, vm.vmexec_ctrls3);
      vmwrite(VMCS_16BIT_CONTROL_POSTED_INTERRUPT_VECTOR,
              vmread(VMCS_16BIT_CONTROL_POSTED_INTERRUPT_VECTOR) & 0xff);
    } else {
      vm.vmexec_ctrls1 &= ~(VMX_VM_EXEC_CTRL1_PROCESS_POSTED_INTERRUPTS);
      DEBUG_PRINT(L"disable VMX_VM_EXEC_CTRL1_PROCESS_POSTED_INTERRUPTS\r\n");
      vmwrite(VMCS_32BIT_CONTROL_PIN_BASED_EXEC_CONTROLS, vm.vmexec_ctrls1);
    }
  }
#if BX_SUPPORT_VMX >= 2
  if (vm.vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_VMCS_SHADOWING) {
    vm.vmread_bitmap_addr =
        (bx_phy_address)vmread(VMCS_64BIT_CONTROL_VMREAD_BITMAP_ADDR);
    if (!IsValidPageAlignedPhyAddr(vm.vmread_bitmap_addr)) {
      DEBUG_PRINT(
          L"VMFAIL: VMCS EXEC CTRL: VMREAD bitmap phy addr malformed\r\n");
      return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
    }
    vm.vmwrite_bitmap_addr =
        (bx_phy_address)vmread(VMCS_64BIT_CONTROL_VMWRITE_BITMAP_ADDR);
    if (!IsValidPageAlignedPhyAddr(vm.vmwrite_bitmap_addr)) {
      DEBUG_PRINT(
          L"VMFAIL: VMCS EXEC CTRL: VMWRITE bitmap phy addr malformed\r\n");
      return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
    }
  }

  if (vm.vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_EPT_VIOLATION_EXCEPTION) {
    vm.ve_info_addr =
        (bx_phy_address)vmread(VMCS_64BIT_CONTROL_VE_EXCEPTION_INFO_ADDR);
    if (!IsValidPageAlignedPhyAddr(vm.ve_info_addr)) {
      DEBUG_PRINT(
          L"VMFAIL: VMCS EXEC CTRL: broken #VE information address\r\n");
      vm.vmexec_ctrls3 &= ~VMX_VM_EXEC_CTRL3_EPT_VIOLATION_EXCEPTION;
      vmwrite(VMCS_32BIT_CONTROL_SECONDARY_VMEXEC_CONTROLS, vm.vmexec_ctrls3);
    }
  }
#endif

#if BX_SUPPORT_X86_64
  if (vm.vmexec_ctrls2 & VMX_VM_EXEC_CTRL2_TPR_SHADOW) {
    vm.virtual_apic_page_addr =
        (bx_phy_address)vmread(VMCS_64BIT_CONTROL_VIRTUAL_APIC_PAGE_ADDR);
    if (!IsValidPageAlignedPhyAddr(vm.virtual_apic_page_addr)) {
      DEBUG_PRINT(
          L"VMFAIL: VMCS EXEC CTRL: virtual apic phy addr malformed\r\n");
      return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
    }

#if BX_SUPPORT_VMX >= 2
    if (vm.vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_VIRTUAL_INT_DELIVERY) {
      if (!(vm.vmexec_ctrls1 & VMX_VM_EXEC_CTRL1_EXTERNAL_INTERRUPT_VMEXIT)) {
        DEBUG_PRINT(
            L"VMFAIL: VMCS EXEC CTRL: virtual interrupt delivery must be set "
            L"together with external interrupt exiting\r\n");
        vm.vmexec_ctrls1 |= VMX_VM_EXEC_CTRL1_EXTERNAL_INTERRUPT_VMEXIT;
        vmwrite(VMCS_32BIT_CONTROL_PIN_BASED_EXEC_CONTROLS, vm.vmexec_ctrls1);
      }

      for (int reg = 0; reg < 8; reg++) {
        vm.eoi_exit_bitmap[reg] =
            vmread(VMCS_64BIT_CONTROL_EOI_EXIT_BITMAP0 + reg);
      }

      uint16_t guest_interrupt_status =
          vmread(VMCS_16BIT_GUEST_INTERRUPT_STATUS);
      vm.rvi = guest_interrupt_status & 0xff;
      vm.svi = guest_interrupt_status >> 8;
    } else
#endif
    {
      vm.vm_tpr_threshold = vmread(VMCS_32BIT_CONTROL_TPR_THRESHOLD);

      if (vm.vm_tpr_threshold & 0xfffffff0) {
        DEBUG_PRINT(L"VMFAIL: VMCS EXEC CTRL: TPR threshold too big\r\n");
        vm.vm_tpr_threshold &= 0xf;
        vmwrite(VMCS_32BIT_CONTROL_TPR_THRESHOLD, vm.vm_tpr_threshold);
      }

      if (!(vm.vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_VIRTUALIZE_APIC_ACCESSES)) {
        uint8_t tpr_shadow = (VMX_Read_Virtual_APIC_VTPR() >> 4) & 0xf;
        DEBUG_PRINT(L"vtpr 0x%x\r\n", VMX_Read_Virtual_APIC_VTPR());
        if (vm.vm_tpr_threshold > tpr_shadow) {
          DEBUG_PRINT(
              L"VMFAIL: VMCS EXEC CTRL: TPR threshold > TPR shadow\r\n");
        }
      }
    }
  }
#if BX_SUPPORT_VMX >= 2
  else {  // TPR shadow is disabled
    if (vm.vmexec_ctrls3 & (VMX_VM_EXEC_CTRL3_VIRTUALIZE_X2APIC_MODE |
                            VMX_VM_EXEC_CTRL3_VIRTUALIZE_APIC_REGISTERS |
                            VMX_VM_EXEC_CTRL3_VIRTUAL_INT_DELIVERY)) {
      vm.vmexec_ctrls3 &= ~(VMX_VM_EXEC_CTRL3_VIRTUALIZE_X2APIC_MODE |
                            VMX_VM_EXEC_CTRL3_VIRTUALIZE_APIC_REGISTERS |
                            VMX_VM_EXEC_CTRL3_VIRTUAL_INT_DELIVERY);
      vmwrite(VMCS_32BIT_CONTROL_SECONDARY_VMEXEC_CONTROLS, vm.vmexec_ctrls3);
      vm.vmexec_ctrls1 &= ~(VMX_VM_EXEC_CTRL1_PROCESS_POSTED_INTERRUPTS);
      vmwrite(VMCS_32BIT_CONTROL_PIN_BASED_EXEC_CONTROLS, vm.vmexec_ctrls1);
      DEBUG_PRINT(
          L"VMFAIL: VMCS EXEC CTRL: apic virtualization is enabled without TPR "
          L"shadow\r\n");
    }
  }
#endif  // BX_SUPPORT_VMX >= 2

  if (vm.vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_VIRTUALIZE_APIC_ACCESSES) {
    vm.apic_access_page =
        (bx_phy_address)vmread(VMCS_64BIT_CONTROL_APIC_ACCESS_ADDR);
    if (!IsValidPageAlignedPhyAddr(vm.apic_access_page)) {
      DEBUG_PRINT(
          L"VMFAIL: VMCS EXEC CTRL: apic access page phy addr malformed\r\n");
      return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
    }

#if BX_SUPPORT_VMX >= 2
    if (vm.vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_VIRTUALIZE_X2APIC_MODE) {
      DEBUG_PRINT(
          L"VMFAIL: VMCS EXEC CTRL: virtualize X2APIC mode enabled together "
          L"with APIC access virtualization\r\n");
      vm.vmexec_ctrls3 &= ~(VMX_VM_EXEC_CTRL3_VIRTUALIZE_X2APIC_MODE);
      vmwrite(VMCS_32BIT_CONTROL_SECONDARY_VMEXEC_CONTROLS, vm.vmexec_ctrls3);
    }
#endif
  }

#if BX_SUPPORT_VMX >= 2
  if (vm.vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_EPT_ENABLE) {
    vm.eptptr = (bx_phy_address)vmread(VMCS_64BIT_CONTROL_EPTPTR);
    if (!is_eptptr_valid(vm.eptptr)) {
      DEBUG_PRINT(L"VMFAIL: VMCS EXEC CTRL: invalid EPTPTR value\r\n");
      vm.vmexec_ctrls3 &= ~VMX_VM_EXEC_CTRL3_EPT_ENABLE;
      vmwrite(VMCS_32BIT_CONTROL_SECONDARY_VMEXEC_CONTROLS, vm.vmexec_ctrls3);
    }
  }
  if (!(vm.vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_EPT_ENABLE)) {
    if (vm.vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_UNRESTRICTED_GUEST) {
      DEBUG_PRINT(
          L"VMFAIL: VMCS EXEC CTRL: unrestricted guest without EPT\r\n");
      vm.vmexec_ctrls3 &= ~(VMX_VM_EXEC_CTRL3_UNRESTRICTED_GUEST);
      vmwrite(VMCS_32BIT_CONTROL_SECONDARY_VMEXEC_CONTROLS, vm.vmexec_ctrls3);
    }
  }

  if (vm.vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_VPID_ENABLE) {
    vm.vpid = vmread(VMCS_16BIT_CONTROL_VPID);
    if (vm.vpid == 0) {
      DEBUG_PRINT(L"VMFAIL: VMCS EXEC CTRL: guest VPID == 0\r\n");
      // return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
      // vmwrite non zero to VMCS_16BIT_CONTROL_VPID
      // vmwrite(VMCS_16BIT_CONTROL_VPID, (0x1));
    }
  }

  if (vm.vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_PAUSE_LOOP_VMEXIT) {
    vm.ple.pause_loop_exiting_gap =
        vmread(VMCS_32BIT_CONTROL_PAUSE_LOOP_EXITING_GAP);
    vm.ple.pause_loop_exiting_window =
        vmread(VMCS_32BIT_CONTROL_PAUSE_LOOP_EXITING_WINDOW);
  }

  if (vm.vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_VMFUNC_ENABLE)
    vm.vmfunc_ctrls = vmread(VMCS_64BIT_CONTROL_VMFUNC_CTRLS);
  else {
    vm.vmfunc_ctrls = 0;
    vmwrite(VMCS_64BIT_CONTROL_VMFUNC_CTRLS, vm.vmfunc_ctrls);
  }
#ifndef XEN
  if (vm.vmfunc_ctrls & ~VMX_VMFUNC_CTRL1_SUPPORTED_BITS) {
    DEBUG_PRINT(L"VMFAIL: VMCS VM Functions control reserved bits set\r\n");
    vm.vmfunc_ctrls &= VMX_VMFUNC_CTRL1_SUPPORTED_BITS;
    vmwrite(VMCS_64BIT_CONTROL_VMFUNC_CTRLS, vm.vmfunc_ctrls);
  }
#endif
  if (vm.vmfunc_ctrls & VMX_VMFUNC_EPTP_SWITCHING_MASK) {
    if ((vm.vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_EPT_ENABLE) == 0) {
      DEBUG_PRINT(L"VMFAIL: VMFUNC EPTP-SWITCHING: EPT disabled\r\n");
      vm.vmfunc_ctrls &= ~VMX_VMFUNC_EPTP_SWITCHING_MASK;
      vmwrite(VMCS_64BIT_CONTROL_VMFUNC_CTRLS, vm.vmfunc_ctrls);
    }
  }
  if (vm.vmfunc_ctrls & VMX_VMFUNC_EPTP_SWITCHING_MASK) {
    vm.eptp_list_address = vmread(VMCS_64BIT_CONTROL_EPTP_LIST_ADDRESS);
    if (!IsValidPageAlignedPhyAddr(vm.eptp_list_address)) {
      DEBUG_PRINT(
          L"VMFAIL: VMFUNC EPTP-SWITCHING: eptp list phy addr malformed\r\n");
      return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
    }
  }

  if (vm.vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_PML_ENABLE) {
    if ((vm.vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_EPT_ENABLE) == 0) {
      DEBUG_PRINT(L"VMFAIL: VMCS EXEC CTRL: PML is enabled without EPT\r\n");
      vm.vmexec_ctrls3 &= ~VMX_VM_EXEC_CTRL3_PML_ENABLE;
      vmwrite(VMCS_32BIT_CONTROL_SECONDARY_VMEXEC_CONTROLS, vm.vmexec_ctrls3);
    }
  }

  if (vm.vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_PML_ENABLE) {
    vm.pml_address = (bx_phy_address)vmread(VMCS_64BIT_CONTROL_PML_ADDRESS);
    if (!IsValidPageAlignedPhyAddr(vm.pml_address)) {
      DEBUG_PRINT(L"VMFAIL: VMCS EXEC CTRL: PML base phy addr malformed\r\n");
      vm.vmexec_ctrls3 &= ~VMX_VM_EXEC_CTRL3_PML_ENABLE;
      vmwrite(VMCS_32BIT_CONTROL_SECONDARY_VMEXEC_CONTROLS, vm.vmexec_ctrls3);
    }
    vm.pml_index = vmread(VMCS_16BIT_GUEST_PML_INDEX);
  }

  if (vm.vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_SUBPAGE_WR_PROTECT_CTRL) {
    if ((vm.vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_EPT_ENABLE) == 0) {
      DEBUG_PRINT(L"VMFAIL: VMCS EXEC CTRL: SPP is enabled without EPT\r\n");
      vm.vmexec_ctrls3 &= ~VMX_VM_EXEC_CTRL3_SUBPAGE_WR_PROTECT_CTRL;
      vmwrite(VMCS_32BIT_CONTROL_SECONDARY_VMEXEC_CONTROLS, vm.vmexec_ctrls3);
    }
  }

  if (vm.vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_SUBPAGE_WR_PROTECT_CTRL) {
    vm.spptp = (bx_phy_address)vmread(VMCS_64BIT_CONTROL_SPPTP);
    if (!IsValidPageAlignedPhyAddr(vm.spptp)) {
      DEBUG_PRINT(L"VMFAIL: VMCS EXEC CTRL: SPP base phy addr malformed\r\n");
      return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
    }
  }

  if (vm.vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_XSAVES_XRSTORS)
    vm.xss_exiting_bitmap = vmread(VMCS_64BIT_CONTROL_XSS_EXITING_BITMAP);
  else
    vm.xss_exiting_bitmap = 0;
#endif

#endif  // BX_SUPPORT_X86_64

  if (vm.vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_TSC_SCALING) {
    if ((vm.tsc_multiplier = vmread(VMCS_64BIT_CONTROL_TSC_MULTIPLIER)) == 0) {
      DEBUG_PRINT(
          L"VMFAIL: VMCS EXEC CTRL: TSC multiplier should be non zero\r\n");
      return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
    }
  }

  //
  // Load VM-exit control fields to VMCS Cache
  //

  vm.vmexit_ctrls = vmread(VMCS_32BIT_CONTROL_VMEXIT_CONTROLS);
  vm.vmexit_msr_store_cnt = vmread(VMCS_32BIT_CONTROL_VMEXIT_MSR_STORE_COUNT);
  vm.vmexit_msr_load_cnt = vmread(VMCS_32BIT_CONTROL_VMEXIT_MSR_LOAD_COUNT);

  //
  // Check VM-exit control fields
  //

  if (~vm.vmexit_ctrls & VMX_CHECKS_USE_MSR_VMX_VMEXIT_CTRLS_LO) {
    DEBUG_PRINT(
        L"VMFAIL: VMCS EXEC CTRL: VMX vmexit controls allowed 0-settings\r\n");
    vm.vmexit_ctrls |= VMX_CHECKS_USE_MSR_VMX_VMEXIT_CTRLS_LO;
    vmwrite(VMCS_32BIT_CONTROL_VMEXIT_CONTROLS, vm.vmexit_ctrls);
  }
  if (vm.vmexit_ctrls & ~VMX_CHECKS_USE_MSR_VMX_VMEXIT_CTRLS_HI) {
    DEBUG_PRINT(
        L"VMFAIL: VMCS EXEC CTRL: VMX vmexit controls allowed 1-settings \r\n");
    vm.vmexit_ctrls &= VMX_CHECKS_USE_MSR_VMX_VMEXIT_CTRLS_HI;
    vmwrite(VMCS_32BIT_CONTROL_VMEXIT_CONTROLS, vm.vmexit_ctrls);
  }
  if (vm.vmexec_ctrls1 & VMX_VM_EXEC_CTRL1_PROCESS_POSTED_INTERRUPTS) {
    vm.vmexit_ctrls |= VMX_VMEXIT_CTRL1_INTA_ON_VMEXIT;
    vmwrite(VMCS_32BIT_CONTROL_VMEXIT_CONTROLS, vm.vmexit_ctrls);
  }

#if BX_SUPPORT_VMX >= 2
  if ((~vm.vmexec_ctrls1 & VMX_VM_EXEC_CTRL1_VMX_PREEMPTION_TIMER_VMEXIT) &&
      (vm.vmexit_ctrls & VMX_VMEXIT_CTRL1_STORE_VMX_PREEMPTION_TIMER)) {
    DEBUG_PRINT(
        L"VMFAIL: save_VMX_preemption_timer VMEXIT control is set but "
        L"VMX_preemption_timer VMEXEC control is clear\r\n");
    vm.vmexec_ctrls1 |= VMX_VM_EXEC_CTRL1_VMX_PREEMPTION_TIMER_VMEXIT;
    vmwrite(VMCS_32BIT_CONTROL_PIN_BASED_EXEC_CONTROLS, vm.vmexec_ctrls1);
  }
#endif

  if (vm.vmexit_msr_store_cnt > 0) {
    vm.vmexit_msr_store_addr = vmread(VMCS_64BIT_CONTROL_VMEXIT_MSR_STORE_ADDR);
    if ((vm.vmexit_msr_store_addr & 0xf) != 0 ||
        !IsValidPhyAddr(vm.vmexit_msr_store_addr)) {
      DEBUG_PRINT(L"VMFAIL: VMCS VMEXIT CTRL: msr store addr malformed\r\n");
    }

    uint64_t last_byte =
        vm.vmexit_msr_store_addr + (vm.vmexit_msr_store_cnt * 16) - 1;
    if (!IsValidPhyAddr(last_byte)) {
      DEBUG_PRINT(L"VMFAIL: VMCS VMEXIT CTRL: msr store addr too high\r\n");
    }
  }

  if (vm.vmexit_msr_load_cnt > 0) {
    vm.vmexit_msr_load_addr = vmread(VMCS_64BIT_CONTROL_VMEXIT_MSR_LOAD_ADDR);
    if ((vm.vmexit_msr_load_addr & 0xf) != 0 ||
        !IsValidPhyAddr(vm.vmexit_msr_load_addr)) {
      DEBUG_PRINT(L"VMFAIL: VMCS VMEXIT CTRL: msr load addr malformed\r\n");
    }

    uint64_t last_byte =
        (uint64_t)vm.vmexit_msr_load_addr + (vm.vmexit_msr_load_cnt * 16) - 1;
    if (!IsValidPhyAddr(last_byte)) {
      DEBUG_PRINT(L"VMFAIL: VMCS VMEXIT CTRL: msr load addr too high\r\n");
    }
  }

  //
  // Load VM-entry control fields to VMCS Cache
  //

  vm.vmentry_ctrls = vmread(VMCS_32BIT_CONTROL_VMENTRY_CONTROLS);
  vm.vmentry_msr_load_cnt = vmread(VMCS_32BIT_CONTROL_VMENTRY_MSR_LOAD_COUNT);

  //
  // Check VM-entry control fields
  //

  if (~vm.vmentry_ctrls & VMX_CHECKS_USE_MSR_VMX_VMENTRY_CTRLS_LO) {
    DEBUG_PRINT(
        L"VMFAIL: VMCS EXEC CTRL: VMX vmentry controls allowed 0-settings\r\n");
    vm.vmentry_ctrls |= VMX_CHECKS_USE_MSR_VMX_VMENTRY_CTRLS_LO;
    vmwrite(VMCS_32BIT_CONTROL_VMENTRY_CONTROLS, vm.vmentry_ctrls);
  }
  if (vm.vmentry_ctrls & ~VMX_CHECKS_USE_MSR_VMX_VMENTRY_CTRLS_HI) {
    DEBUG_PRINT(
        L"VMFAIL: VMCS EXEC CTRL: VMX vmentry controls allowed 1-settings\r\n");
    vm.vmentry_ctrls &= VMX_CHECKS_USE_MSR_VMX_VMENTRY_CTRLS_HI;
    vmwrite(VMCS_32BIT_CONTROL_VMENTRY_CONTROLS, vm.vmentry_ctrls);
  }
  if (vm.vmentry_ctrls & VMX_VMENTRY_CTRL1_LOAD_PERF_GLOBAL_CTRL_MSR) {
    uint64_t guest_ia32_perf_global_ctrl =
        vmread(VMCS_64BIT_GUEST_IA32_PERF_GLOBAL_CTRL);
    if (guest_ia32_perf_global_ctrl & 0xfffffff8fffffff8) {
      guest_ia32_perf_global_ctrl &= ~0xfffffff8fffffff8;
      vmwrite(VMCS_64BIT_GUEST_IA32_PERF_GLOBAL_CTRL,
              guest_ia32_perf_global_ctrl);
    }
  }
  if (vm.vmentry_ctrls & VMX_VMENTRY_CTRL1_DEACTIVATE_DUAL_MONITOR_TREATMENT) {
    if (!in_smm) {
      DEBUG_PRINT(
          L"VMFAIL: VMENTRY from outside SMM with dual-monitor treatment "
          L"enabled\r\n");
      vm.vmentry_ctrls &=
          ~(VMX_VMENTRY_CTRL1_DEACTIVATE_DUAL_MONITOR_TREATMENT);
      vmwrite(VMCS_32BIT_CONTROL_VMENTRY_CONTROLS, vm.vmentry_ctrls);
    }
  }

  if (vm.vmentry_msr_load_cnt > 0) {
    vm.vmentry_msr_load_addr = vmread(VMCS_64BIT_CONTROL_VMENTRY_MSR_LOAD_ADDR);
    if ((vm.vmentry_msr_load_addr & 0xf) != 0 ||
        !IsValidPhyAddr(vm.vmentry_msr_load_addr)) {
      DEBUG_PRINT(L"VMFAIL: VMCS VMENTRY CTRL: msr load addr malformed\r\n");
      return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
    }

    uint64_t last_byte =
        vm.vmentry_msr_load_addr + (vm.vmentry_msr_load_cnt * 16) - 1;
    if (!IsValidPhyAddr(last_byte)) {
      DEBUG_PRINT(L"VMFAIL: VMCS VMENTRY CTRL: msr load addr too high\r\n");
      return VMXERR_VMENTRY_INVALID_VM_CONTROL_FIELD;
    }
  }

  //
  // Check VM-entry event injection info
  //

  vm.vmentry_interr_info = vmread(VMCS_32BIT_CONTROL_VMENTRY_INTERRUPTION_INFO);
  vm.vmentry_excep_err_code =
      vmread(VMCS_32BIT_CONTROL_VMENTRY_EXCEPTION_ERR_CODE);
  vm.vmentry_instr_length =
      vmread(VMCS_32BIT_CONTROL_VMENTRY_INSTRUCTION_LENGTH);

  if (VMENTRY_INJECTING_EVENT(vm.vmentry_interr_info)) {
    /* the VMENTRY injecting event to the guest */
    unsigned vector = vm.vmentry_interr_info & 0xff;
    unsigned event_type = (vm.vmentry_interr_info >> 8) & 7;
    unsigned push_error = (vm.vmentry_interr_info >> 11) & 1;
    unsigned error_code = push_error ? vm.vmentry_excep_err_code : 0;

    unsigned push_error_reference = 0;
    if (event_type == BX_HARDWARE_EXCEPTION &&
        vector < BX_CPU_HANDLED_EXCEPTIONS)
      push_error_reference = exceptions_info[vector].push_error;
#if BX_SUPPORT_CET
    //  if (! BX_CPUID_SUPPORT_ISA_EXTENSION(BX_ISA_CET)) {
    if (!(VMX_MSR_VMX_BASIC & (uint64_t)1 << 56)) {
      if (vector == BX_CP_EXCEPTION)
        push_error_reference = false;
    }
#endif

    if (vm.vmentry_interr_info & 0x7ffff000) {
      DEBUG_PRINT(L"VMFAIL: VMENTRY broken interruption info field\r\n");
      vm.vmentry_interr_info &= 0x80000fff;
      vmwrite(VMCS_32BIT_CONTROL_VMENTRY_INTERRUPTION_INFO,
              vm.vmentry_interr_info);
    }

    switch (event_type) {
      case BX_EXTERNAL_INTERRUPT:
        break;

      case BX_NMI:
        if (vector != 2) {
          DEBUG_PRINT(L"VMFAIL: VMENTRY bad injected event vector %d\r\n",
                      vector);
          vector = 2;
          vm.vmentry_interr_info &= ~(0xff);
          vm.vmentry_interr_info |= 2;
          vmwrite(VMCS_32BIT_CONTROL_VMENTRY_INTERRUPTION_INFO,
                  vm.vmentry_interr_info);
        }
        //  injecting NMI
        if (vm.vmexec_ctrls1 & VMX_VM_EXEC_CTRL1_VIRTUAL_NMI) {
          uint32_t interruptibility_state;
          interruptibility_state =
              vmread(VMCS_32BIT_GUEST_INTERRUPTIBILITY_STATE);
          if (interruptibility_state & BX_VMX_INTERRUPTS_BLOCKED_NMI_BLOCKED) {
            interruptibility_state &= ~BX_VMX_INTERRUPTS_BLOCKED_NMI_BLOCKED;
            vmwrite(VMCS_32BIT_GUEST_INTERRUPTIBILITY_STATE,
                    interruptibility_state);
            DEBUG_PRINT(
                L"VMFAIL: VMENTRY injected NMI vector when blocked by NMI in "
                L"interruptibility state\r\n",
                vector);
          }
        }

        break;

      case BX_HARDWARE_EXCEPTION:
        if (vector > 31) {
          DEBUG_PRINT(L"VMFAIL: VMENTRY bad injected event vector %d\r\n",
                      vector);
          vector &= 0x1f;
          vm.vmentry_interr_info &= 0xffffff1f;
          vmwrite(VMCS_32BIT_CONTROL_VMENTRY_INTERRUPTION_INFO,
                  vm.vmentry_interr_info);
        }
        break;

      case BX_SOFTWARE_INTERRUPT:
      case BX_PRIVILEGED_SOFTWARE_INTERRUPT:
      case BX_SOFTWARE_EXCEPTION:
        vm.vmentry_interr_info &= ~(0xff);
        vmwrite(VMCS_32BIT_CONTROL_VMENTRY_INTERRUPTION_INFO,
                vm.vmentry_interr_info);

        if ((vm.vmentry_instr_length == 0 && !(VMX_MSR_MISC & 1 << 30))) {
          DEBUG_PRINT(L"VMFAIL: VMENTRY bad injected event instr length\r\n");
          vm.vmentry_instr_length &= 0xf;
          vm.vmentry_instr_length |= 0x1;
          vmwrite(VMCS_32BIT_CONTROL_VMENTRY_INSTRUCTION_LENGTH,
                  vm.vmentry_instr_length);
        }
        if (vm.vmentry_instr_length > 15) {
          DEBUG_PRINT(L"VMFAIL: VMENTRY bad injected event instr length\r\n");
          vm.vmentry_instr_length &= 0xf;
          vm.vmentry_instr_length |= 0x1;
          vmwrite(VMCS_32BIT_CONTROL_VMENTRY_INSTRUCTION_LENGTH,
                  vm.vmentry_instr_length);
        }
        break;

      case 7: /* MTF */
        if (vector != 0) {
          DEBUG_PRINT(L"VMFAIL: VMENTRY bad MTF injection with vector=%d\r\n",
                      vector);
          vector = 0;
          vm.vmentry_interr_info &= ~(0xff);
          vmwrite(VMCS_32BIT_CONTROL_VMENTRY_INTERRUPTION_INFO,
                  vm.vmentry_interr_info);
        }
        break;

      default:
        DEBUG_PRINT(L"VMFAIL: VMENTRY bad injected event type %d\r\n",
                    event_type);
        event_type = 3;
        vm.vmentry_interr_info &= ~((0x7) << 8);
        vm.vmentry_interr_info |= ((0x3) << 8);
        vector &= 0x1f;
        vm.vmentry_interr_info &= 0xffffff1f;
        vmwrite(VMCS_32BIT_CONTROL_VMENTRY_INTERRUPTION_INFO,
                vm.vmentry_interr_info);
    }

    if (~(vmread(VMCS_GUEST_CR0)) & VMX_MSR_CR0_FIXED0) {
      DEBUG_PRINT(L"VMENTER FAIL: VMCS guest invalid CR0\r\n");
      vmwrite(VMCS_GUEST_CR0, vmread(VMCS_GUEST_CR0) | VMX_MSR_CR0_FIXED0);
    }
#if BX_SUPPORT_VMX >= 2
    if (vm.vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_UNRESTRICTED_GUEST) {
      unsigned protected_mode_guest =
          (uint32_t)vmread(VMCS_GUEST_CR0) & BX_CR0_PE_MASK;
      if (!protected_mode_guest)
        push_error_reference = 0;
    }
#endif

    if (!(VMX_MSR_VMX_BASIC & (uint64_t)1 << 56)) {
      // CET added new #CP exception with error code but legacy software assumed
      // that this vector have no error code. Therefore CET enabled processors
      // do not check the error code anymore and able to deliver a hardware
      // exception with or without an error code, regardless of vector as
      // indicated in VMX_MSR_VMX_BASIC[56]
      if (push_error != push_error_reference) {
        DEBUG_PRINT(
            L"VMFAIL: VMENTRY injected event vector %d broken error code\r\n",
            vector);
        push_error = push_error_reference;
        vm.vmentry_interr_info &= ~(1 << 11);
        vm.vmentry_interr_info |= (push_error_reference << 11);
        vmwrite(VMCS_32BIT_CONTROL_VMENTRY_INTERRUPTION_INFO,
                vm.vmentry_interr_info);
      }
    }
    if (event_type == BX_HARDWARE_EXCEPTION) {
      if (!(VMX_MSR_VMX_BASIC & (uint64_t)1 << 56)) {
        if ((uint32_t)vmread(VMCS_GUEST_CR0) & BX_CR0_PE_MASK) {
          if (vector == 8 || vector == 10 || vector == 11 || vector == 12 ||
              vector == 13 || vector == 14 || vector == 17) {
            push_error = 1;
            error_code = push_error ? vm.vmentry_excep_err_code : 0;
            vm.vmentry_interr_info |= (1 << 11);
            vmwrite(VMCS_32BIT_CONTROL_VMENTRY_INTERRUPTION_INFO,
                    vm.vmentry_interr_info);
          }
        }
      }
    }
    if (!(event_type == BX_HARDWARE_EXCEPTION) ||
        !(uint32_t)vmread(VMCS_GUEST_CR0) & BX_CR0_PE_MASK ||
        (!(VMX_MSR_VMX_BASIC & (uint64_t)1 << 56) &&
         !(vector == 8 || vector == 10 || vector == 11 || vector == 12 ||
           vector == 13 || vector == 14 || vector == 17))) {
      push_error = 0;
      error_code = push_error ? vm.vmentry_excep_err_code : 0;
      vm.vmentry_interr_info &= ~(1 << 11);
      vmwrite(VMCS_32BIT_CONTROL_VMENTRY_INTERRUPTION_INFO,
              vm.vmentry_interr_info);
    }

    if (push_error) {
      if (error_code & 0xffff0000) {
        DEBUG_PRINT(
            L"VMFAIL: VMENTRY bad error code 0x%08x for injected event %d\r\n",
            error_code, vector);
        vmwrite(VMCS_32BIT_CONTROL_VMENTRY_EXCEPTION_ERR_CODE,
                error_code & 0x0000ffff);
      }
    }
  }

  return VMXERR_NO_ERROR;
}

enum VMX_error_code VMenterLoadCheckHostState(void) {
  VMCS_HOST_STATE* host_state = &vm.host_state;
  bool x86_64_host = false, x86_64_guest = false;

  //
  // VM Host State Checks Related to Address-Space Size
  //

  uint32_t vmexit_ctrls = vm.vmexit_ctrls;
  if (vmexit_ctrls & VMX_VMEXIT_CTRL1_HOST_ADDR_SPACE_SIZE) {
    x86_64_host = true;
  }
  uint32_t vmentry_ctrls = vm.vmentry_ctrls;
  if (vmentry_ctrls & VMX_VMENTRY_CTRL1_X86_64_GUEST) {
    x86_64_guest = true;
  }

#if BX_SUPPORT_X86_64
  if (MSR_EFER & 1 << 10) {
    if (!x86_64_host) {
      DEBUG_PRINT(L"VMFAIL: VMCS x86-64 host control invalid on VMENTRY\r\n");
      vm.vmexit_ctrls |= VMX_VMEXIT_CTRL1_HOST_ADDR_SPACE_SIZE;
      vmwrite(VMCS_32BIT_CONTROL_VMEXIT_CONTROLS, vm.vmexit_ctrls);
      x86_64_host = true;
    }
  } else
#endif
  {
    if (x86_64_host || x86_64_guest) {
      DEBUG_PRINT(
          L"VMFAIL: VMCS x86-64 guest(%d)/host(%d) controls invalid on "
          L"VMENTRY\r\n",
          x86_64_guest, x86_64_host);
      return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
    }
  }

  //
  // Load and Check VM Host State to VMCS Cache
  //

  host_state->cr0 = (bx_address)vmread(VMCS_HOST_CR0);
  if (~host_state->cr0 & VMX_MSR_CR0_FIXED0) {
    DEBUG_PRINT(L"VMFAIL: VMCS host state invalid CR0 0x%08x\r\n",
                (uint32_t)host_state->cr0);
    return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }

  if (host_state->cr0 & ~VMX_MSR_CR0_FIXED1) {
    DEBUG_PRINT(L"VMFAIL: VMCS host state invalid CR0 0x%08x\r\n",
                (uint32_t)host_state->cr0);
    return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }

  host_state->cr3 = (bx_address)vmread(VMCS_HOST_CR3);
#if BX_SUPPORT_X86_64
  if (!IsValidPhyAddr(host_state->cr3)) {
    DEBUG_PRINT(L"VMFAIL: VMCS host state invalid CR3\r\n");
    return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }
#endif

  host_state->cr4 = (bx_address)vmread(VMCS_HOST_CR4);
  if (~host_state->cr4 & VMX_MSR_CR4_FIXED0) {
    DEBUG_PRINT(L"VMFAIL: VMCS host state invalid CR4 0x%x", host_state->cr4);
    return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }
  if (host_state->cr4 & ~VMX_MSR_CR4_FIXED1) {
    DEBUG_PRINT(L"VMFAIL: VMCS host state invalid CR4 0x%x", host_state->cr4);
    return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }

  for (int n = 0; n < 6; n++) {
    host_state->segreg_selector[n] =
        vmread(VMCS_16BIT_HOST_ES_SELECTOR + 2 * n);
    if (host_state->segreg_selector[n] & 7) {
      DEBUG_PRINT(L"VMFAIL: VMCS host segreg %d TI/RPL != 0\r\n", n);
      return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
    }
  }

  if (host_state->segreg_selector[BX_SEG_REG_CS] == 0) {
    DEBUG_PRINT(L"VMFAIL: VMCS host CS selector 0\r\n");
    return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }

  if (!x86_64_host && host_state->segreg_selector[BX_SEG_REG_SS] == 0) {
    DEBUG_PRINT(L"VMFAIL: VMCS host SS selector 0\r\n");
    return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }

  host_state->tr_selector = vmread(VMCS_16BIT_HOST_TR_SELECTOR);
  if (!host_state->tr_selector || (host_state->tr_selector & 7) != 0) {
    DEBUG_PRINT(L"VMFAIL: VMCS invalid host TR selector\r\n");
    return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }

  host_state->tr_base = (bx_address)vmread(VMCS_HOST_TR_BASE);
#if BX_SUPPORT_X86_64
  if (!IsCanonical(host_state->tr_base)) {
    DEBUG_PRINT(L"VMFAIL: VMCS host TR BASE non canonical\r\n");
    return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }
#endif

  host_state->fs_base = (bx_address)vmread(VMCS_HOST_FS_BASE);
  host_state->gs_base = (bx_address)vmread(VMCS_HOST_GS_BASE);
#if BX_SUPPORT_X86_64
  if (!IsCanonical(host_state->fs_base)) {
    DEBUG_PRINT(L"VMFAIL: VMCS host FS BASE non canonical\r\n");
    return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }
  if (!IsCanonical(host_state->gs_base)) {
    DEBUG_PRINT(L"VMFAIL: VMCS host GS BASE non canonical\r\n");
    return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }
#endif

  host_state->gdtr_base = (bx_address)vmread(VMCS_HOST_GDTR_BASE);
  host_state->idtr_base = (bx_address)vmread(VMCS_HOST_IDTR_BASE);
#if BX_SUPPORT_X86_64
  if (!IsCanonical(host_state->gdtr_base)) {
    DEBUG_PRINT(L"VMFAIL: VMCS host GDTR BASE non canonical\r\n");
    return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }
  if (!IsCanonical(host_state->idtr_base)) {
    DEBUG_PRINT(L"VMFAIL: VMCS host IDTR BASE non canonical\r\n");
    return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }
#endif

  host_state->sysenter_esp_msr =
      (bx_address)vmread(VMCS_HOST_IA32_SYSENTER_ESP_MSR);
  host_state->sysenter_eip_msr =
      (bx_address)vmread(VMCS_HOST_IA32_SYSENTER_EIP_MSR);
  host_state->sysenter_cs_msr =
      (uint16_t)vmread(VMCS_32BIT_HOST_IA32_SYSENTER_CS_MSR);

#if BX_SUPPORT_X86_64
  if (!IsCanonical(host_state->sysenter_esp_msr)) {
    DEBUG_PRINT(L"VMFAIL: VMCS host SYSENTER_ESP_MSR non canonical\r\n");
    return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }

  if (!IsCanonical(host_state->sysenter_eip_msr)) {
    DEBUG_PRINT(L"VMFAIL: VMCS host SYSENTER_EIP_MSR non canonical\r\n");
    return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
  }
#endif

#if BX_SUPPORT_VMX >= 2
  if (vmexit_ctrls & VMX_VMEXIT_CTRL1_LOAD_PAT_MSR) {
    host_state->pat_msr = vmread(VMCS_64BIT_HOST_IA32_PAT);
    if (!isValidMSR_PAT(host_state->pat_msr)) {
      DEBUG_PRINT(L"VMFAIL: invalid Memory Type in host MSR_PAT\r\n");
      host_state->pat_msr = makeValidMSR_PAT(host_state->pat_msr);
      vmwrite(VMCS_64BIT_HOST_IA32_PAT, host_state->pat_msr);
    }
  }
#endif

  host_state->rsp = (bx_address)vmread(VMCS_HOST_RSP);
  host_state->rip = (bx_address)vmread(VMCS_HOST_RIP);

// not supported
#if BX_SUPPORT_CET
  if (vmexit_ctrls & VMX_VMEXIT_CTRL1_LOAD_HOST_CET_STATE) {
    host_state->msr_ia32_s_cet = vmread(VMCS_HOST_IA32_S_CET);
    if (!IsCanonical(host_state->msr_ia32_s_cet) ||
        (!x86_64_host && GET32H(host_state->msr_ia32_s_cet))) {
      // DEBUG_PRINT(L"VMFAIL: VMCS host IA32_S_CET/EB_LEG_BITMAP_BASE non
      // canonical or invalid\r\n");
      return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
    }

    if (is_invalid_cet_control(host_state->msr_ia32_s_cet)) {
      // DEBUG_PRINT(L"VMFAIL: VMCS host IA32_S_CET invalid\r\n");
      return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
    }

    host_state->ssp = vmread(VMCS_HOST_SSP);
    if (!IsCanonical(host_state->ssp) ||
        (!x86_64_host && GET32H(host_state->ssp))) {
      // DEBUG_PRINT(L"VMFAIL: VMCS host SSP non canonical or invalid\r\n");
      return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
    }
    if ((host_state->ssp & 0x3) != 0) {
      // DEBUG_PRINT(L"VMFAIL: VMCS host SSP[1:0] not zero\r\n");
      return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
    }

    host_state->interrupt_ssp_table_address =
        vmread(VMCS_HOST_INTERRUPT_SSP_TABLE_ADDR);
    if (!IsCanonical(host_state->interrupt_ssp_table_address)) {
      // DEBUG_PRINT(L"VMFAIL: VMCS host INTERRUPT_SSP_TABLE_ADDR non canonical
      // or invalid\r\n");
      return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
    }

    if ((host_state->cr4 & BX_CR4_CET_MASK) &&
        (host_state->cr0 & BX_CR0_WP_MASK) == 0) {
      // DEBUG_PRINT(L"FAIL: VMCS host CR4.CET=1 when CR0.WP=0\r\n");
      return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
    }
  }
#endif

#define GET32H(val64) ((uint32_t)(((uint64_t)(val64)) >> 32))

// not supported
#if BX_SUPPORT_PKEYS
  if (vmexit_ctrls & VMX_VMEXIT_CTRL1_LOAD_HOST_PKRS) {
    host_state->pkrs = vmread(VMCS_64BIT_HOST_IA32_PKRS);
    if (GET32H(host_state->pkrs) != 0) {
      // DEBUG_PRINT(L"VMFAIL: invalid host IA32_PKRS value\r\n");
      return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
    }
  }
#endif

#if BX_SUPPORT_X86_64

#if BX_SUPPORT_VMX >= 2
  if (vmexit_ctrls & VMX_VMEXIT_CTRL1_LOAD_EFER_MSR) {
    host_state->efer_msr = vmread(VMCS_64BIT_HOST_IA32_EFER);
    if (host_state->efer_msr & ~(MSR_EFER)) {
      DEBUG_PRINT(L"VMFAIL: VMCS host EFER reserved bits set !\r\n");
      host_state->efer_msr &= MSR_EFER;
      vmwrite(VMCS_64BIT_HOST_IA32_EFER, host_state->efer_msr);
    }
    bool lme = (host_state->efer_msr >> 8) & 0x1;
    bool lma = (host_state->efer_msr >> 10) & 0x1;
    if (lma != lme || lma != x86_64_host) {
      DEBUG_PRINT(L"VMFAIL: VMCS host EFER (0x%08x) inconsistent value !\r\n",
                  (uint32_t)host_state->efer_msr);
      if (x86_64_host) {
        host_state->efer_msr |= 1 << 10 | 1 << 8;
      } else {
        host_state->efer_msr &= ~(1 << 10 | 1 << 8);
      }
      vmwrite(VMCS_64BIT_HOST_IA32_EFER, host_state->efer_msr);
    }
  }
#endif

  if (x86_64_host) {
    if ((host_state->cr4 & BX_CR4_PAE_MASK) == 0) {
      DEBUG_PRINT(L"VMFAIL: VMCS host CR4.PAE=0 with x86-64 host\r\n");
      return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
    }
    if (!IsCanonical(host_state->rip)) {
      DEBUG_PRINT(L"VMFAIL: VMCS host RIP non-canonical\r\n");
      return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
    }
  } else {
    if (GET32H(host_state->rip) != 0) {
      DEBUG_PRINT(L"VMFAIL: VMCS host RIP > 32 bit\r\n");
      return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
    }
    if (host_state->cr4 & BX_CR4_PCIDE_MASK) {
      DEBUG_PRINT(L"VMFAIL: VMCS host CR4.PCIDE set\r\n");
      return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
    }
  }
#endif

  return VMXERR_NO_ERROR;
}

bool IsLimitAccessRightsConsistent(uint32_t limit, uint32_t ar) {
  bool g = (ar >> 15) & 1;

  // access rights reserved bits set
  if (ar & 0xfffe0f00)
    return 0;

  if (g) {
    // if any of the bits in limit[11:00] are '0 <=> G must be '0
    if ((limit & 0xfff) != 0xfff)
      return 0;
  } else {
    // if any of the bits in limit[31:20] are '1 <=> G must be '1
    if ((limit & 0xfff00000) != 0)
      return 0;
  }

  return 1;
}
uint32_t MakeValidAccessRights(uint32_t limit, uint32_t ar)  // in progress
{
  bool g = (ar >> 15) & 1;

  // access rights reserved bits set
  ar &= ~(0xfffe0f00);
  return ar;

  if (g) {
    // if any of the bits in limit[11:00] are '0 <=> G must be '0
    if ((limit & 0xfff) != 0xfff)
      return 0;
  } else {
    // if any of the bits in limit[31:20] are '1 <=> G must be '1
    if ((limit & 0xfff00000) != 0)
      return 0;
  }
  return ar;
}

void parse_selector(uint16_t raw_selector, bx_selector_t* selector) {
  selector->value = raw_selector;
  selector->index = raw_selector >> 3;
  selector->ti = (raw_selector >> 2) & 0x01;
  selector->rpl = raw_selector & 0x03;
}
bool set_segment_ar_data(bx_segment_reg_t* seg,
                         bool valid,
                         uint16_t raw_selector,
                         bx_address base,
                         uint32_t limit_scaled,
                         uint16_t ar_data) {
  parse_selector(raw_selector, &seg->selector);

  bx_descriptor_t* d = &seg->cache;

  d->p = (ar_data >> 7) & 0x1;
  d->dpl = (ar_data >> 5) & 0x3;
  d->segment = (ar_data >> 4) & 0x1;
  d->type = (ar_data & 0x0f);

  d->valid = valid;

  if (d->segment || !valid) { /* data/code segment descriptors */
    d->u.segment.g = (ar_data >> 15) & 0x1;
    d->u.segment.d_b = (ar_data >> 14) & 0x1;
#if BX_SUPPORT_X86_64
    d->u.segment.l = (ar_data >> 13) & 0x1;
#endif
    d->u.segment.avl = (ar_data >> 12) & 0x1;

    d->u.segment.base = base;
    d->u.segment.limit_scaled = limit_scaled;
  } else {
    switch (d->type) {
      case BX_SYS_SEGMENT_LDT:
      case BX_SYS_SEGMENT_AVAIL_286_TSS:
      case BX_SYS_SEGMENT_BUSY_286_TSS:
      case BX_SYS_SEGMENT_AVAIL_386_TSS:
      case BX_SYS_SEGMENT_BUSY_386_TSS:
        d->u.segment.avl = (ar_data >> 12) & 0x1;
        d->u.segment.d_b = (ar_data >> 14) & 0x1;
        d->u.segment.g = (ar_data >> 15) & 0x1;
        d->u.segment.base = base;
        d->u.segment.limit_scaled = limit_scaled;
        break;

      default:
        break;
        DEBUG_PRINT(L"set_segment_ar_data(): case %d unsupported, valid=%d\r\n",
                    (unsigned)d->type, d->valid);
    }
  }

  return d->valid;
}

const uint32_t EFlagsCFMask = (1 << 0);
const uint32_t EFlagsPFMask = (1 << 2);
const uint32_t EFlagsAFMask = (1 << 4);
const uint32_t EFlagsZFMask = (1 << 6);
const uint32_t EFlagsSFMask = (1 << 7);
const uint32_t EFlagsTFMask = (1 << 8);
const uint32_t EFlagsIFMask = (1 << 9);
const uint32_t EFlagsDFMask = (1 << 10);
const uint32_t EFlagsOFMask = (1 << 11);
const uint32_t EFlagsIOPLMask = (3 << 12);
const uint32_t EFlagsNTMask = (1 << 14);
const uint32_t EFlagsRFMask = (1 << 16);
const uint32_t EFlagsVMMask = (1 << 17);
const uint32_t EFlagsACMask = (1 << 18);
const uint32_t EFlagsVIFMask = (1 << 19);
const uint32_t EFlagsVIPMask = (1 << 20);
const uint32_t EFlagsIDMask = (1 << 21);

uint32_t VMenterLoadCheckGuestState(uint64_t* qualification) {
  int n;
  VMCS_GUEST_STATE guest;

  *qualification = VMENTER_ERR_NO_ERROR;

  //
  // Load and Check Guest State from VMCS
  //
  guest.rflags = vmread(VMCS_GUEST_RFLAGS);
  // RFLAGS reserved bits [63:22], bit 15, bit 5, bit 3 must be zero
  if (guest.rflags & 0xFFFFFFFFFFC08028) {
    DEBUG_PRINT(L"VMENTER FAIL: RFLAGS reserved bits are set\r\n");
    guest.rflags &= ~0xFFFFFFFFFFC08028;
    vmwrite(VMCS_GUEST_RFLAGS, guest.rflags);
  }
  // RFLAGS[1] must be always set
  if ((guest.rflags & 0x2) == 0) {
    DEBUG_PRINT(L"VMENTER FAIL: RFLAGS[1] cleared\r\n");
    guest.rflags |= 0x2;
    vmwrite(VMCS_GUEST_RFLAGS, guest.rflags);
  }

  bool v8086_guest = false;
  if (guest.rflags & EFlagsVMMask)
    v8086_guest = true;

  bool x86_64_guest =
      false;  // can't be 1 if X86_64 is not supported (checked before)
  uint32_t vmentry_ctrls = vm.vmentry_ctrls;
#if BX_SUPPORT_X86_64
  if (vmentry_ctrls & VMX_VMENTRY_CTRL1_X86_64_GUEST) {
    DEBUG_PRINT(L"VMENTER to x86-64 guest\r\n");
    x86_64_guest = true;
  }
#endif

  if (x86_64_guest && v8086_guest) {
    DEBUG_PRINT(L"VMENTER FAIL: Enter to x86-64 guest with RFLAGS.VM\r\n");
    v8086_guest = false;
    guest.rflags &= ~EFlagsVMMask;
    vmwrite(VMCS_GUEST_RFLAGS, guest.rflags);
  }

  guest.cr0 = vmread(VMCS_GUEST_CR0);
#if BX_SUPPORT_VMX >= 2
  if (vm.vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_UNRESTRICTED_GUEST) {
    //  if (~guest.cr0 & (VMX_MSR_CR0_FIXED0 & ~(BX_CR0_PE_MASK |
    //  BX_CR0_PG_MASK))) {
    //    vm.vmexec_ctrls3 &= ~(VMX_VM_EXEC_CTRL3_UNRESTRICTED_GUEST);
    //    vmwrite(VMCS_32BIT_CONTROL_SECONDARY_VMEXEC_CONTROLS,vm.vmexec_ctrls3);
    //     // DEBUG_PRINT(L"VMENTER FAIL: VMCS guest invalid CR0\r\n");
    //     // return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
    //  }
    if (~guest.cr0 & (VMX_MSR_CR0_FIXED0)) {
      guest.cr0 |= VMX_MSR_CR0_FIXED0;
      vmwrite(VMCS_GUEST_CR0, guest.cr0);
      DEBUG_PRINT(L"VMENTER FAIL: VMCS guest invalid CR0\r\n");
    }
    bool pe = (guest.cr0 & BX_CR0_PE_MASK) != 0;
    bool pg = (guest.cr0 & BX_CR0_PG_MASK) != 0;
    DEBUG_PRINT(L"guest cr0 0x%x\nif1 0x%x\nif2 0x%x\r\n", guest.cr0,
                (~guest.cr0 &
                 (VMX_MSR_CR0_FIXED0 & ~(BX_CR0_PE_MASK | BX_CR0_PG_MASK))),
                (pg && !pe));
    if (pg && !pe) {
      DEBUG_PRINT(
          L"VMENTER FAIL: VMCS unrestricted guest CR0.PG without CR0.PE\r\n");
      vm.vmexec_ctrls3 &= ~(VMX_VM_EXEC_CTRL3_UNRESTRICTED_GUEST);
      vmwrite(VMCS_32BIT_CONTROL_SECONDARY_VMEXEC_CONTROLS, vm.vmexec_ctrls3);
    }
  }
  if (!(vm.vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_UNRESTRICTED_GUEST))
#endif
  {
    if (~guest.cr0 & VMX_MSR_CR0_FIXED0) {
      DEBUG_PRINT(L"VMENTER FAIL: VMCS guest invalid CR0\r\n");
      guest.cr0 |= VMX_MSR_CR0_FIXED0;
      vmwrite(VMCS_GUEST_CR0, guest.cr0);
    }
  }

  if (guest.cr0 & ~VMX_MSR_CR0_FIXED1) {
    DEBUG_PRINT(L"VMENTER FAIL: VMCS guest invalid CR0\r\n");
    guest.cr0 &= VMX_MSR_CR0_FIXED1;
    vmwrite(VMCS_GUEST_CR0, guest.cr0);
  }

  // #if BX_SUPPORT_VMX >= 2
  //   bool real_mode_guest = false;
  //   if (! (guest.cr0 & BX_CR0_PE_MASK))
  //      real_mode_guest = true;
  // #endif

  guest.cr3 = vmread(VMCS_GUEST_CR3);
#if BX_SUPPORT_X86_64
  if (!IsValidPhyAddr(guest.cr3)) {
    DEBUG_PRINT(L"VMENTER FAIL: VMCS guest invalid CR3\r\n");
    return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
  }
#endif

  guest.cr4 = vmread(VMCS_GUEST_CR4);
  if (~guest.cr4 & VMX_MSR_CR4_FIXED0) {
    DEBUG_PRINT(L"VMENTER FAIL: VMCS guest invalid CR4\r\n");
    guest.cr4 |= VMX_MSR_CR4_FIXED0;
    vmwrite(VMCS_GUEST_CR4, guest.cr4);
  }

  if (guest.cr4 & ~VMX_MSR_CR4_FIXED1) {
    DEBUG_PRINT(L"VMENTER FAIL: VMCS guest invalid CR4\r\n");
    guest.cr4 &= VMX_MSR_CR4_FIXED1;
    vmwrite(VMCS_GUEST_CR4, guest.cr4);
  }

#if BX_SUPPORT_X86_64
  if (x86_64_guest) {
    if ((guest.cr4 & BX_CR4_PAE_MASK) == 0) {
      DEBUG_PRINT(L"VMENTER FAIL: VMCS guest CR4.PAE=0 in x86-64 mode\r\n");
      guest.cr4 |= BX_CR4_PAE_MASK;
      vmwrite(VMCS_GUEST_CR4, guest.cr4);
    }
  } else {
    if (guest.cr4 & BX_CR4_PCIDE_MASK) {
      DEBUG_PRINT(L"VMENTER FAIL: VMCS CR4.PCIDE set in 32-bit guest\r\n");
      guest.cr4 &= ~(BX_CR4_PCIDE_MASK);
      vmwrite(VMCS_GUEST_CR4, guest.cr4);
    }
  }

  if (vmentry_ctrls & VMX_VMENTRY_CTRL1_LOAD_DBG_CTRLS) {
    guest.ia32_debugctl_msr = vmread(VMCS_64BIT_GUEST_IA32_DEBUGCTL);
    if (guest.ia32_debugctl_msr & 0xFFFFFFFFFFFF203C) {
      guest.ia32_debugctl_msr &= ~0xFFFFFFFFFFFF203C;
      vmwrite(VMCS_64BIT_GUEST_IA32_DEBUGCTL, guest.ia32_debugctl_msr);
    }
    guest.dr7 = vmread(VMCS_GUEST_DR7);
    if (GET32H(guest.dr7)) {
      DEBUG_PRINT(L"VMENTER FAIL: VMCS guest invalid DR7\r\n");
      guest.dr7 &= 0x00000000ffffffff;
      vmwrite(VMCS_GUEST_DR7, guest.dr7);
    }
  }
#endif

#if BX_SUPPORT_CET
  if ((guest.cr4 & BX_CR4_CET_MASK) && (guest.cr0 & BX_CR0_WP_MASK) == 0) {
    // // DEBUG_PRINT(L"VMENTER FAIL: VMCS guest CR4.CET=1 when CR0.WP=0\r\n");
    return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
  }

  if (vmentry_ctrls & VMX_VMENTRY_CTRL1_LOAD_GUEST_CET_STATE) {
    guest.msr_ia32_s_cet = vmread(VMCS_GUEST_IA32_S_CET);
    if (!IsCanonical(guest.msr_ia32_s_cet) ||
        (!x86_64_guest && GET32H(guest.msr_ia32_s_cet))) {
      // DEBUG_PRINT(L"VMFAIL: VMCS guest IA32_S_CET/EB_LEG_BITMAP_BASE non
      // canonical or invalid\r\n");
      return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
    }

    if (is_invalid_cet_control(guest.msr_ia32_s_cet)) {
      // DEBUG_PRINT(L"VMFAIL: VMCS guest IA32_S_CET invalid\r\n");
      return VMXERR_VMENTRY_INVALID_VM_HOST_STATE_FIELD;
    }

    guest.ssp = vmread(VMCS_GUEST_SSP);
    if (!IsCanonical(guest.ssp) || (!x86_64_guest && GET32H(guest.ssp))) {
      // DEBUG_PRINT(L"VMFAIL: VMCS guest SSP non canonical or invalid\r\n");
      return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
    }
    if ((guest.ssp & 0x3) != 0) {
      // DEBUG_PRINT(L"VMFAIL: VMCS guest SSP[1:0] not zero\r\n");
      return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
    }

    guest.interrupt_ssp_table_address =
        vmread(VMCS_GUEST_INTERRUPT_SSP_TABLE_ADDR);
    if (!IsCanonical(guest.interrupt_ssp_table_address)) {
      // DEBUG_PRINT(L"VMFAIL: VMCS guest INTERRUPT_SSP_TABLE_ADDR non canonical
      // or invalid\r\n");
      return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
    }
  }
#endif

#if BX_SUPPORT_PKEYS
  if (vmentry_ctrls & VMX_VMENTRY_CTRL1_LOAD_GUEST_PKRS) {
    guest.pkrs = vmread(VMCS_64BIT_GUEST_IA32_PKRS);
    if (GET32H(guest.pkrs) != 0) {
      // DEBUG_PRINT(L"VMFAIL: invalid guest IA32_PKRS value\r\n");
      return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
    }
  }
#endif

  //
  // Load and Check Guest State from VMCS - Segment Registers
  //

  for (n = 0; n < 6; n++) {
    uint16_t selector = vmread(VMCS_16BIT_GUEST_ES_SELECTOR + 2 * n);
    bx_address base = (bx_address)vmread(VMCS_GUEST_ES_BASE + 2 * n);
    uint32_t limit = vmread(VMCS_32BIT_GUEST_ES_LIMIT + 2 * n);
    uint32_t ar = vmread(VMCS_32BIT_GUEST_ES_ACCESS_RIGHTS + 2 * n);

    bool invalid = (ar >> 16) & 1;

    set_segment_ar_data(&guest.sregs[n], !invalid, (uint16_t)selector, base,
                        limit, (uint16_t)ar);
  }
  for (n = 0; n < 6; n++) {
    uint16_t selector = vmread(VMCS_16BIT_GUEST_ES_SELECTOR + 2 * n);
    bx_address base = (bx_address)vmread(VMCS_GUEST_ES_BASE + 2 * n);
    uint32_t limit = vmread(VMCS_32BIT_GUEST_ES_LIMIT + 2 * n);
    uint32_t ar = vmread(VMCS_32BIT_GUEST_ES_ACCESS_RIGHTS + 2 * n);

    bool invalid = (ar >> 16) & 1;

    set_segment_ar_data(&guest.sregs[n], !invalid, (uint16_t)selector, base,
                        limit, (uint16_t)ar);

    if (v8086_guest) {
      // guest in V8086 mode
      if (base != ((bx_address)(selector << 4))) {
        base = ((bx_address)(selector << 4));
        vmwrite(VMCS_GUEST_ES_BASE + 2 * n, base);
        DEBUG_PRINT(L"VMENTER FAIL: VMCS v8086 guest bad %s.BASE\r\n",
                    segname[n]);
      }
      if (limit != 0xffff) {
        DEBUG_PRINT(L"VMENTER FAIL: VMCS v8086 guest %s.LIMIT != 0xFFFF\r\n",
                    segname[n]);
        return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
      }
      // present, expand-up read/write accessed, segment, DPL=3
      if (ar != 0xF3) {
        DEBUG_PRINT(L"VMENTER FAIL: VMCS v8086 guest %s.AR != 0xF3\r\n",
                    segname[n]);
        return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
      }

      continue;  // go to next segment register
    }

#if BX_SUPPORT_X86_64
    if (n >= BX_SEG_REG_FS) {
      if (!IsCanonical(base)) {
        base = MakeCanonical(base);
        vmwrite(VMCS_GUEST_ES_BASE + 2 * n, base);
        DEBUG_PRINT(L"VMENTER FAIL: VMCS guest %s.BASE non canonical\r\n",
                    segname[n]);
      }
    }
#endif

    if (n != BX_SEG_REG_CS && invalid)
      continue;
#define BX_SELECTOR_RPL_MASK (0xfffc)
#if BX_SUPPORT_X86_64
    //  if (n == BX_SEG_REG_SS && (selector & BX_SELECTOR_RPL_MASK) == 0) {
    //     // SS is allowed to be NULL selector if going to 64-bit guest
    //     if (x86_64_guest && guest.sregs[BX_SEG_REG_CS].cache.u.segment.l)
    //        continue;
    //  }

    if (n < BX_SEG_REG_FS) {
      if (GET32H(base) != 0) {
        base &= 0xFFFFFFFF;
        vmwrite(VMCS_GUEST_ES_BASE + 2 * n, base);
        DEBUG_PRINT(L"VMENTER FAIL: VMCS guest %s.BASE > 32 bit\r\n",
                    segname[n]);
      }
    }
#endif

    if (!guest.sregs[n].cache.segment) {
      DEBUG_PRINT(L"VMENTER FAIL: VMCS guest %s not segment\r\n", segname[n]);
      guest.sregs[n].cache.segment = 1;
      ar |= 1 << 4;  // ar segment
      vmwrite(VMCS_32BIT_GUEST_ES_ACCESS_RIGHTS + 2 * n, ar);
    }

    if (!guest.sregs[n].cache.p) {
      DEBUG_PRINT(L"VMENTER FAIL: VMCS guest %s not present\r\n", segname[n]);
      guest.sregs[n].cache.p = 1;
      ar |= 1 << 7;  // ar p
      vmwrite(VMCS_32BIT_GUEST_ES_ACCESS_RIGHTS + 2 * n, ar);
    }

    if (!IsLimitAccessRightsConsistent(limit, ar)) {
      DEBUG_PRINT(L"VMENTER FAIL: VMCS guest %s.AR/LIMIT malformed\r\n",
                  segname[n]);

      ar &= ~(0xfffe0f00);
      if ((ar >> 15) & 1) {
        if ((limit & 0xfff) != 0xfff) {
          ar &= ~(1 << 15);
        }
      } else {
        if ((limit & 0xfff00000) != 0) {
          ar |= 1 << 15;
        }
      }
      vmwrite(VMCS_32BIT_GUEST_ES_ACCESS_RIGHTS + 2 * n, ar);
    }

    if (n == BX_SEG_REG_CS) {
      // CS checks
      switch (guest.sregs[BX_SEG_REG_CS].cache.type) {
        case BX_CODE_EXEC_ONLY_ACCESSED:
        case BX_CODE_EXEC_READ_ACCESSED:
          // non-conforming segment
          if (guest.sregs[BX_SEG_REG_CS].cache.dpl !=
              guest.sregs[BX_SEG_REG_SS].cache.dpl) {
            DEBUG_PRINT(
                L"VMENTER FAIL: VMCS guest non-conforming CS.DPL <> "
                L"SS.DPL\r\n");
            guest.sregs[BX_SEG_REG_CS].cache.dpl =
                guest.sregs[BX_SEG_REG_SS].cache.dpl;
            ar &= ~(1 << 5 | 1 << 6);
            ar |= guest.sregs[BX_SEG_REG_CS].cache.dpl << 5;
            vmwrite(VMCS_32BIT_GUEST_ES_ACCESS_RIGHTS + 2 * BX_SEG_REG_CS, ar);
          }
          break;
        case BX_CODE_EXEC_ONLY_CONFORMING_ACCESSED:
        case BX_CODE_EXEC_READ_CONFORMING_ACCESSED:
          // conforming segment
          if (guest.sregs[BX_SEG_REG_SS].cache.dpl <
              guest.sregs[BX_SEG_REG_CS].cache.dpl) {
            DEBUG_PRINT(
                L"VMENTER FAIL: VMCS guest non-conforming SS.DPL < CS.DPL\r\n");
            guest.sregs[BX_SEG_REG_CS].cache.dpl =
                guest.sregs[BX_SEG_REG_SS].cache.dpl;
            ar &= ~(1 << 5 | 1 << 6);
            ar |= guest.sregs[BX_SEG_REG_CS].cache.dpl << 5;
            vmwrite(VMCS_32BIT_GUEST_ES_ACCESS_RIGHTS + 2 * BX_SEG_REG_CS, ar);
          }
          break;
#if BX_SUPPORT_VMX >= 2
        case BX_DATA_READ_WRITE_ACCESSED:
          if (!(vm.vmexec_ctrls3 & (VMX_VM_EXEC_CTRL3_UNRESTRICTED_GUEST))) {
            guest.sregs[BX_SEG_REG_CS].cache.type = BX_CODE_EXEC_ONLY_ACCESSED;
            ar &= 0xfffffff0;
            ar |= guest.sregs[BX_SEG_REG_CS].cache.type;
            vmwrite(VMCS_32BIT_GUEST_ES_ACCESS_RIGHTS + 2 * BX_SEG_REG_CS, ar);
            if (guest.sregs[BX_SEG_REG_CS].cache.dpl !=
                guest.sregs[BX_SEG_REG_SS].cache.dpl) {
              DEBUG_PRINT(
                  L"VMENTER FAIL: VMCS guest non-conforming CS.DPL <> "
                  L"SS.DPL\r\n");
              guest.sregs[BX_SEG_REG_CS].cache.dpl =
                  guest.sregs[BX_SEG_REG_SS].cache.dpl;
              ar &= ~(1 << 5 | 1 << 6);
              ar |= guest.sregs[BX_SEG_REG_CS].cache.dpl << 5;
              vmwrite(VMCS_32BIT_GUEST_ES_ACCESS_RIGHTS + 2 * BX_SEG_REG_CS,
                      ar);
            }
          } else {
            guest.sregs[BX_SEG_REG_CS].cache.dpl = 0;
            ar &= ~(1 << 5 | 1 << 6);
            ar |= guest.sregs[BX_SEG_REG_CS].cache.dpl << 5;
            vmwrite(VMCS_32BIT_GUEST_ES_ACCESS_RIGHTS + 2 * BX_SEG_REG_CS, ar);
          }
          break;
#endif
        default:
          break;
          DEBUG_PRINT(L"VMENTER FAIL: VMCS guest CS.TYPE\r\n");
      }

#if BX_SUPPORT_X86_64
      if (x86_64_guest) {
        if (guest.sregs[BX_SEG_REG_CS].cache.u.segment.d_b &&
            guest.sregs[BX_SEG_REG_CS].cache.u.segment.l) {
          DEBUG_PRINT(L"VMENTER FAIL: VMCS x86_64 guest wrong CS.D_B/L\r\n");
          guest.sregs[BX_SEG_REG_CS].cache.u.segment.d_b = 0;
          ar &= ~(1 << 14);
          vmwrite(VMCS_32BIT_GUEST_ES_ACCESS_RIGHTS + 2 * BX_SEG_REG_CS, ar);
        }
      }
#endif
    } else if (n == BX_SEG_REG_SS) {
      // SS checks
      switch (guest.sregs[BX_SEG_REG_SS].cache.type) {
        case BX_DATA_READ_WRITE_ACCESSED:
        case BX_DATA_READ_WRITE_EXPAND_DOWN_ACCESSED:
          break;
        default:
          DEBUG_PRINT(L"VMENTER FAIL: VMCS guest SS.TYPE\r\n");
          ar &= 0xfffffff0;
          if (guest.sregs[BX_SEG_REG_SS].cache.type & 0x1) {
            guest.sregs[BX_SEG_REG_SS].cache.type = BX_DATA_READ_WRITE_ACCESSED;
            ar |= BX_DATA_READ_WRITE_ACCESSED;
          } else {
            guest.sregs[BX_SEG_REG_SS].cache.type =
                BX_DATA_READ_WRITE_EXPAND_DOWN_ACCESSED;
            ar |= BX_DATA_READ_WRITE_EXPAND_DOWN_ACCESSED;
          }
          vmwrite(VMCS_32BIT_GUEST_ES_ACCESS_RIGHTS + 2 * n, ar);
      }
    } else {
      // DS, ES, FS, GS
      if ((guest.sregs[n].cache.type & 0x1) == 0) {
        DEBUG_PRINT(L"VMENTER FAIL: VMCS guest %s not ACCESSED\r\n",
                    segname[n]);
        guest.sregs[n].cache.type |= 1 << 0;
        ar |= 1 << 0;
        vmwrite(VMCS_32BIT_GUEST_ES_ACCESS_RIGHTS + 2 * n, ar);
      }

      if (guest.sregs[n].cache.type & 0x8) {
        if ((guest.sregs[n].cache.type & 0x2) == 0) {
          DEBUG_PRINT(
              L"VMENTER FAIL: VMCS guest CODE segment %s not READABLE\r\n",
              segname[n]);
          guest.sregs[n].cache.type |= 1 << 1;
          ar |= 1 << 1;
          vmwrite(VMCS_32BIT_GUEST_ES_ACCESS_RIGHTS + 2 * n, ar);
        }
      }

      if (!(vm.vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_UNRESTRICTED_GUEST)) {
        if (guest.sregs[n].cache.type <= 11) {
          // data segment or non-conforming code segment
          if (guest.sregs[n].selector.rpl > guest.sregs[n].cache.dpl) {
            DEBUG_PRINT(
                L"VMENTER FAIL: VMCS guest non-conforming %s.RPL < %s.DPL\r\n",
                segname[n], segname[n]);
            guest.sregs[n].selector.value &= guest.sregs[n].cache.dpl;
            guest.sregs[n].selector.rpl = guest.sregs[n].selector.value & 0x3;
            vmwrite(VMCS_16BIT_GUEST_ES_SELECTOR + 2 * n,
                    guest.sregs[n].selector.value);
          }
        }
      }
    }
  }

  if (!v8086_guest) {
    if (!(vm.vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_UNRESTRICTED_GUEST)) {
      if (guest.sregs[BX_SEG_REG_SS].selector.rpl !=
          guest.sregs[BX_SEG_REG_SS].cache.dpl) {
        DEBUG_PRINT(L"VMENTER FAIL: VMCS guest SS.RPL <> SS.DPL\r\n");
        guest.sregs[BX_SEG_REG_SS].selector.rpl =
            guest.sregs[BX_SEG_REG_SS].cache.dpl;
        guest.sregs[BX_SEG_REG_SS].selector.value &= 0xfffc;
        guest.sregs[BX_SEG_REG_SS].selector.value |=
            guest.sregs[BX_SEG_REG_SS].selector.rpl;
        vmwrite(VMCS_16BIT_GUEST_ES_SELECTOR + 2 * BX_SEG_REG_SS,
                guest.sregs[BX_SEG_REG_SS].selector.value);
      }
      if (guest.sregs[BX_SEG_REG_SS].selector.rpl !=
          guest.sregs[BX_SEG_REG_CS].selector.rpl) {
        DEBUG_PRINT(L"VMENTER FAIL: VMCS guest CS.RPL != SS.RPL\r\n");
        guest.sregs[BX_SEG_REG_CS].selector.rpl =
            guest.sregs[BX_SEG_REG_SS].selector.rpl;
        guest.sregs[BX_SEG_REG_CS].selector.value &= 0xfffc;
        guest.sregs[BX_SEG_REG_CS].selector.value |=
            guest.sregs[BX_SEG_REG_CS].selector.rpl;
        vmwrite(VMCS_16BIT_GUEST_ES_SELECTOR + 2 * BX_SEG_REG_CS,
                guest.sregs[BX_SEG_REG_CS].selector.value);
      }
    }
    // #if BX_SUPPORT_VMX >= 2
    //      else { // unrestricted guest
    //         if (real_mode_guest || guest.sregs[BX_SEG_REG_CS].cache.type ==
    //         BX_DATA_READ_WRITE_ACCESSED) {
    //            if (guest.sregs[BX_SEG_REG_CS].cache.dpl != 0) {
    //              // DEBUG_PRINT(L"VMENTER FAIL: VMCS unrestricted guest
    //              SS.DPL != 0\r\n"); return
    //              VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
    //            }
    //         }
    //      }
    // #endif
  }

  /*
       if (n == BX_SEG_REG_CS) {
          // CS checks
          switch (guest.sregs[BX_SEG_REG_CS].cache.type) {
            case BX_CODE_EXEC_ONLY_ACCESSED:
            case BX_CODE_EXEC_READ_ACCESSED:
               // non-conforming segment
               if (guest.sregs[BX_SEG_REG_CS].cache.dpl !=
    guest.sregs[BX_SEG_REG_SS].cache.dpl) {
                 // DEBUG_PRINT(L"VMENTER FAIL: VMCS guest non-conforming CS.DPL
    <> SS.DPL\r\n");
                 // return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
                 guest.sregs[BX_SEG_REG_CS].cache.dpl =
    guest.sregs[BX_SEG_REG_SS].cache.dpl; ar &= ~(1<<5|1<<6); ar |=
    guest.sregs[BX_SEG_REG_CS].cache.dpl;
                 vmwrite(VMCS_32BIT_GUEST_ES_ACCESS_RIGHTS + 2*BX_SEG_REG_CS,
    ar);
               }
               break;
            case BX_CODE_EXEC_ONLY_CONFORMING_ACCESSED:
            case BX_CODE_EXEC_READ_CONFORMING_ACCESSED:
               // conforming segment
               if (guest.sregs[BX_SEG_REG_SS].cache.dpl <
    guest.sregs[BX_SEG_REG_CS].cache.dpl) {
                 // DEBUG_PRINT(L"VMENTER FAIL: VMCS guest non-conforming SS.DPL
    < CS.DPL\r\n");
                 // return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
                 guest.sregs[BX_SEG_REG_CS].cache.dpl =
    guest.sregs[BX_SEG_REG_SS].cache.dpl; ar &= ~(1<<5|1<<6); ar |=
    guest.sregs[BX_SEG_REG_CS].cache.dpl;
                 vmwrite(VMCS_32BIT_GUEST_ES_ACCESS_RIGHTS + 2*BX_SEG_REG_CS,
    ar);
               }
               break;

    if (! v8086_guest) {
       if (! (vm.vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_UNRESTRICTED_GUEST)) {
          if (guest.sregs[BX_SEG_REG_SS].selector.rpl !=
    guest.sregs[BX_SEG_REG_SS].cache.dpl) {
             // DEBUG_PRINT(L"VMENTER FAIL: VMCS guest SS.RPL <> SS.DPL\r\n");
           //   return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
             guest.sregs[BX_SEG_REG_SS].selector.rpl =
    guest.sregs[BX_SEG_REG_SS].cache.dpl;
             guest.sregs[BX_SEG_REG_SS].selector.value &= 0xfffc;
             guest.sregs[BX_SEG_REG_SS].selector.value |=
    guest.sregs[BX_SEG_REG_SS].selector.rpl;
             vmwrite(VMCS_16BIT_GUEST_ES_SELECTOR + 2*BX_SEG_REG_SS,
    guest.sregs[BX_SEG_REG_SS].selector.value);
          }
          if (guest.sregs[BX_SEG_REG_SS].selector.rpl !=
    guest.sregs[BX_SEG_REG_CS].selector.rpl) {
             // DEBUG_PRINT(L"VMENTER FAIL: VMCS guest CS.RPL != SS.RPL\r\n");
           //   return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
                 guest.sregs[BX_SEG_REG_CS].selector.rpl =
    guest.sregs[BX_SEG_REG_SS].selector.rpl;
                 guest.sregs[BX_SEG_REG_CS].selector.value &= 0xfffc;
                 guest.sregs[BX_SEG_REG_CS].selector.value |=
    guest.sregs[BX_SEG_REG_CS].selector.rpl;
                 vmwrite(VMCS_16BIT_GUEST_ES_SELECTOR + 2*BX_SEG_REG_CS,
    guest.sregs[BX_SEG_REG_CS].selector.value);
          }
       }
  */

  //
  // Load and Check Guest State from VMCS - GDTR/IDTR
  //

  uint64_t gdtr_base = vmread(VMCS_GUEST_GDTR_BASE);
  uint32_t gdtr_limit = vmread(VMCS_32BIT_GUEST_GDTR_LIMIT);
  uint64_t idtr_base = vmread(VMCS_GUEST_IDTR_BASE);
  uint32_t idtr_limit = vmread(VMCS_32BIT_GUEST_IDTR_LIMIT);

#if BX_SUPPORT_X86_64
  if (!IsCanonical(gdtr_base)) {
    gdtr_base = MakeCanonical(gdtr_base);
    vmwrite(VMCS_GUEST_GDTR_BASE, gdtr_base);
  }
  if (!IsCanonical(idtr_base)) {
    idtr_base = MakeCanonical(idtr_base);
    vmwrite(VMCS_GUEST_GDTR_BASE, idtr_base);
    DEBUG_PRINT(L"VMENTER FAIL: VMCS guest IDTR/IDTR.BASE non canonical\r\n");
  }
#endif
  if (gdtr_limit > 0xffff || idtr_limit > 0xffff) {
    DEBUG_PRINT(L"VMENTER FAIL: VMCS guest GDTR/IDTR limit > 0xFFFF\r\n");
    vmwrite(VMCS_32BIT_GUEST_GDTR_LIMIT, gdtr_limit & 0xffff);
    vmwrite(VMCS_32BIT_GUEST_IDTR_LIMIT, idtr_limit & 0xffff);
  }

  //
  // Load and Check Guest State from VMCS - LDTR
  //

  uint16_t ldtr_selector = vmread(VMCS_16BIT_GUEST_LDTR_SELECTOR);
  uint64_t ldtr_base = vmread(VMCS_GUEST_LDTR_BASE);
  uint32_t ldtr_limit = vmread(VMCS_32BIT_GUEST_LDTR_LIMIT);
  uint32_t ldtr_ar = vmread(VMCS_32BIT_GUEST_LDTR_ACCESS_RIGHTS);
  ldtr_ar &= 0xFF;
  vmwrite(VMCS_32BIT_GUEST_LDTR_ACCESS_RIGHTS, ldtr_ar);
  bool ldtr_invalid = (ldtr_ar >> 16) & 1;
  if (set_segment_ar_data(&guest.ldtr, !ldtr_invalid, (uint16_t)ldtr_selector,
                          ldtr_base, ldtr_limit, (uint16_t)(ldtr_ar))) {
    // ldtr is valid
    if (guest.ldtr.selector.ti) {
      DEBUG_PRINT(L"VMENTER FAIL: VMCS guest LDTR.TI set\r\n");
      guest.ldtr.selector.ti = 0;
      guest.ldtr.selector.value &= ~(1 << 2);
      vmwrite(VMCS_16BIT_GUEST_LDTR_SELECTOR, guest.ldtr.selector.value);
    }
    if (guest.ldtr.cache.type != BX_SYS_SEGMENT_LDT) {
      DEBUG_PRINT(L"VMENTER FAIL: VMCS guest incorrect LDTR type (%d)\r\n",
                  guest.ldtr.cache.type);
      guest.ldtr.cache.type = BX_SYS_SEGMENT_LDT;
      ldtr_ar &= ~(0xf);
      ldtr_ar |= 0x2;
      vmwrite(VMCS_32BIT_GUEST_LDTR_ACCESS_RIGHTS, ldtr_ar);
    }
    if (guest.ldtr.cache.segment) {
      DEBUG_PRINT(L"VMENTER FAIL: VMCS guest LDTR is not system segment\r\n");
      guest.ldtr.cache.segment = 0;
      ldtr_ar &= ~(1 << 4);
      vmwrite(VMCS_32BIT_GUEST_LDTR_ACCESS_RIGHTS, ldtr_ar);
    }
    if (!guest.ldtr.cache.p) {
      DEBUG_PRINT(L"VMENTER FAIL: VMCS guest LDTR not present\r\n");
      guest.ldtr.cache.p = 1;
      ldtr_ar |= 1 << 7;
      vmwrite(VMCS_32BIT_GUEST_LDTR_ACCESS_RIGHTS, ldtr_ar);
    }
    if (!IsLimitAccessRightsConsistent(ldtr_limit, ldtr_ar)) {
      DEBUG_PRINT(L"VMENTER FAIL: VMCS guest LDTR.AR/LIMIT malformed\r\n");
      ldtr_ar &= ~(0xfffe0f00);
      if ((ldtr_ar >> 15) & 1) {
        if ((ldtr_limit & 0xfff) != 0xfff) {
          ldtr_ar &= ~(1 << 15);
        }
      } else {
        if ((ldtr_limit & 0xfff00000) != 0) {
          ldtr_ar |= 1 << 15;
        }
      }
      vmwrite(VMCS_32BIT_GUEST_LDTR_ACCESS_RIGHTS, ldtr_ar);
    }
#if BX_SUPPORT_X86_64
    if (!IsCanonical(ldtr_base)) {
      ldtr_base = MakeCanonical(ldtr_base);
      vmwrite(VMCS_GUEST_LDTR_BASE, ldtr_base);
      DEBUG_PRINT(L"VMENTER FAIL: VMCS guest LDTR.BASE non canonical\r\n");
    }
#endif
  }

  //
  // Load and Check Guest State from VMCS - TR
  //

  uint16_t tr_selector = vmread(VMCS_16BIT_GUEST_TR_SELECTOR);
  uint64_t tr_base = vmread(VMCS_GUEST_TR_BASE);
  uint32_t tr_limit = vmread(VMCS_32BIT_GUEST_TR_LIMIT);
  uint32_t tr_ar = vmread(VMCS_32BIT_GUEST_TR_ACCESS_RIGHTS);
  tr_ar &= 0xFF;
  vmwrite(VMCS_32BIT_GUEST_TR_ACCESS_RIGHTS, tr_ar);
  bool tr_invalid = (tr_ar >> 16) & 1;

#if BX_SUPPORT_X86_64
  if (!IsCanonical(tr_base)) {
    tr_base = MakeCanonical(tr_base);
    vmwrite(VMCS_GUEST_LDTR_BASE, tr_base);
    DEBUG_PRINT(L"VMENTER FAIL: VMCS guest TR.BASE non canonical\r\n");
  }
#endif

  if (tr_invalid) {
    DEBUG_PRINT(L"VMENTER FAIL: VMCS guest TR invalid\r\n");
    tr_invalid = 0;
    tr_ar &= ~(1 << 16);
    vmwrite(VMCS_32BIT_GUEST_TR_ACCESS_RIGHTS, tr_ar);
  }
  set_segment_ar_data(&guest.tr, !tr_invalid, (uint16_t)tr_selector, tr_base,
                      tr_limit, (uint16_t)(tr_ar));
  if (guest.tr.selector.ti) {
    DEBUG_PRINT(L"VMENTER FAIL: VMCS guest TR.TI set\r\n");
    guest.tr.selector.ti = 0;
    guest.tr.selector.value &= ~(1 << 2);
    vmwrite(VMCS_16BIT_GUEST_TR_SELECTOR, guest.tr.selector.value);
  }
  if (guest.tr.cache.segment) {
    DEBUG_PRINT(L"VMENTER FAIL: VMCS guest TR is not system segment\r\n");
    guest.tr.cache.segment = 0;
    tr_ar &= ~(1 << 4);
    vmwrite(VMCS_32BIT_GUEST_TR_ACCESS_RIGHTS, tr_ar);
  }
  if (!guest.tr.cache.p) {
    DEBUG_PRINT(L"VMENTER FAIL: VMCS guest TR not present\r\n");
    guest.tr.cache.p = 1;
    tr_ar |= 1 << 7;
    vmwrite(VMCS_32BIT_GUEST_TR_ACCESS_RIGHTS, tr_ar);
  }
  if (!IsLimitAccessRightsConsistent(tr_limit, tr_ar)) {
    DEBUG_PRINT(L"VMENTER FAIL: VMCS guest TR.AR/LIMIT malformed\r\n");
    tr_ar &= ~(0xfffe0f00);
    if ((tr_ar >> 15) & 1) {
      if ((tr_limit & 0xfff) != 0xfff) {
        tr_ar &= ~(1 << 15);
      }
    } else {
      if ((tr_limit & 0xfff00000) != 0) {
        ldtr_ar |= 1 << 15;
      }
    }
    vmwrite(VMCS_32BIT_GUEST_LDTR_ACCESS_RIGHTS, tr_ar);
  }

  switch (guest.tr.cache.type) {
    case BX_SYS_SEGMENT_BUSY_386_TSS:
      break;
    case BX_SYS_SEGMENT_BUSY_286_TSS:
      if (!x86_64_guest)
        break;
      // fall through
    default:
      break;
      DEBUG_PRINT(L"VMENTER FAIL: VMCS guest incorrect TR type\r\n");
  }

  //
  // Load and Check Guest State from VMCS - MSRS
  //

  guest.ia32_debugctl_msr = vmread(VMCS_64BIT_GUEST_IA32_DEBUGCTL);
  guest.smbase = vmread(VMCS_32BIT_GUEST_SMBASE);

  guest.sysenter_esp_msr = vmread(VMCS_GUEST_IA32_SYSENTER_ESP_MSR);
  guest.sysenter_eip_msr = vmread(VMCS_GUEST_IA32_SYSENTER_EIP_MSR);
  guest.sysenter_cs_msr = vmread(VMCS_32BIT_GUEST_IA32_SYSENTER_CS_MSR);

#if BX_SUPPORT_X86_64
  if (!IsCanonical(guest.sysenter_esp_msr)) {
    DEBUG_PRINT(L"VMENTER FAIL: VMCS guest SYSENTER_ESP_MSR non canonical\r\n");
    return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
  }
  if (!IsCanonical(guest.sysenter_eip_msr)) {
    DEBUG_PRINT(L"VMENTER FAIL: VMCS guest SYSENTER_EIP_MSR non canonical\r\n");
    return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
  }
#endif

#if BX_SUPPORT_VMX >= 2
  if (vmentry_ctrls & VMX_VMENTRY_CTRL1_LOAD_PAT_MSR) {
    guest.pat_msr = vmread(VMCS_64BIT_GUEST_IA32_PAT);
    if (!isValidMSR_PAT(guest.pat_msr)) {
      DEBUG_PRINT(L"VMENTER FAIL: invalid Memory Type in guest MSR_PAT\r\n");
      guest.pat_msr = makeValidMSR_PAT(guest.pat_msr);
      vmwrite(VMCS_64BIT_GUEST_IA32_PAT, guest.pat_msr);
    }
  }
#endif

  guest.rip = vmread(VMCS_GUEST_RIP);
  guest.rsp = vmread(VMCS_GUEST_RSP);

#if BX_SUPPORT_VMX >= 2 && BX_SUPPORT_X86_64
  if (vmentry_ctrls & VMX_VMENTRY_CTRL1_LOAD_EFER_MSR) {
    guest.efer_msr = vmread(VMCS_64BIT_GUEST_IA32_EFER);
    if (guest.efer_msr & ~((uint64_t)MSR_EFER)) {
      DEBUG_PRINT(L"VMENTER FAIL: VMCS guest EFER reserved bits set !\r\n");
      guest.efer_msr &= (uint64_t)MSR_EFER;
      vmwrite(VMCS_64BIT_GUEST_IA32_EFER, guest.efer_msr);
    }
    bool lme = (guest.efer_msr >> 8) & 0x1;
    bool lma = (guest.efer_msr >> 10) & 0x1;
    if (lma != x86_64_guest) {
      DEBUG_PRINT(
          L"VMENTER FAIL: VMCS guest EFER.LMA doesn't match x86_64_guest!\r\n");
      if (lma == 0) {
        lma = 1;
        guest.efer_msr |= 1 << 10;
      } else {
        lma = 0;
        guest.efer_msr &= ~(1 << 10);
      }
      vmwrite(VMCS_64BIT_GUEST_IA32_EFER, guest.efer_msr);
    }
    if (lma != lme && (guest.cr0 & BX_CR0_PG_MASK) != 0) {
      DEBUG_PRINT(
          L"VMENTER FAIL: VMCS guest EFER (0x%08x) inconsistent value!\r\n",
          (uint32_t)guest.efer_msr);
      if (lme == 0) {
        lme = 1;
        guest.efer_msr |= 1 << 8;
      } else {
        lme = 0;
        guest.efer_msr &= ~(1 << 8);
      }
      vmwrite(VMCS_64BIT_GUEST_IA32_EFER, guest.efer_msr);
    }
  }

  if (!x86_64_guest || !guest.sregs[BX_SEG_REG_CS].cache.u.segment.l) {
    if (GET32H(guest.rip) != 0) {
      DEBUG_PRINT(L"VMENTER FAIL: VMCS guest RIP > 32 bit\r\n");
      return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
    }
  }
#endif

  //
  // Load and Check Guest Non-Registers State from VMCS
  //

  vm.vmcs_linkptr = vmread(VMCS_64BIT_GUEST_LINK_POINTER);
  if (vm.vmcs_linkptr != BX_INVALID_VMCSPTR) {
    if (!IsValidPageAlignedPhyAddr(vm.vmcs_linkptr)) {
      *qualification = (uint64_t)VMENTER_ERR_GUEST_STATE_LINK_POINTER;
      DEBUG_PRINT(L"VMFAIL: VMCS link pointer malformed\r\n");
    }

    uint32_t revision = VMXReadRevisionID((bx_phy_address)vm.vmcs_linkptr);
    if (vm.vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_VMCS_SHADOWING) {
      if ((revision & BX_VMCS_SHADOW_BIT_MASK) == 0) {
        *qualification = (uint64_t)VMENTER_ERR_GUEST_STATE_LINK_POINTER;
        DEBUG_PRINT(
            L"VMFAIL: VMCS link pointer must indicate shadow VMCS revision ID "
            L"= %x\r\n",
            revision);
        revision |= BX_VMCS_SHADOW_BIT_MASK;
        VMXWriteRevisionID(vm.vmcs_linkptr, revision);
      }
      revision &= ~BX_VMCS_SHADOW_BIT_MASK;
    }
    uint64_t current_vmcsptr;
    vmptrst(&current_vmcsptr);
    if (revision != VMXReadRevisionID((bx_phy_address)current_vmcsptr)) {
      *qualification = (uint64_t)VMENTER_ERR_GUEST_STATE_LINK_POINTER;
      DEBUG_PRINT(
          L"VMFAIL: VMCS link pointer incorrect revision ID %x != %x\r\n",
          revision, VMXReadRevisionID((bx_phy_address)current_vmcsptr));
      if (vm.vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_VMCS_SHADOWING) {
        VMXWriteRevisionID(
            vm.vmcs_linkptr,
            BX_VMCS_SHADOW_BIT_MASK |
                VMXReadRevisionID((bx_phy_address)current_vmcsptr));
      } else {
        VMXWriteRevisionID(vm.vmcs_linkptr,
                           VMXReadRevisionID((bx_phy_address)current_vmcsptr));
      }
    }

    if (!in_smm || (vmentry_ctrls & VMX_VMENTRY_CTRL1_SMM_ENTER) != 0) {
      if (vm.vmcs_linkptr == current_vmcsptr) {
        *qualification = (uint64_t)VMENTER_ERR_GUEST_STATE_LINK_POINTER;
        DEBUG_PRINT(
            L"VMFAIL: VMCS link pointer equal to current VMCS pointer\r\n");
      }
    } else {
      if (vm.vmcs_linkptr == vmxonptr) {
        *qualification = (uint64_t)VMENTER_ERR_GUEST_STATE_LINK_POINTER;
        DEBUG_PRINT(L"VMFAIL: VMCS link pointer equal to VMXON pointer\r\n");
      }
    }
  }

  guest.tmpDR6 = (uint32_t)vmread(VMCS_GUEST_PENDING_DBG_EXCEPTIONS);
  if (guest.tmpDR6 & 0xFFFFFFFFFFFFAFF0) {
    guest.tmpDR6 &= ~0xFFFFFFFFFFFFAFF0;
    vmwrite(VMCS_GUEST_PENDING_DBG_EXCEPTIONS, guest.tmpDR6);
  }

  guest.activity_state = vmread(VMCS_32BIT_GUEST_ACTIVITY_STATE);
  if (guest.activity_state > BX_VMX_LAST_ACTIVITY_STATE) {
    guest.activity_state = 0;
    vmwrite(VMCS_32BIT_GUEST_ACTIVITY_STATE, guest.activity_state);
  }
  if ((((VMX_MSR_MISC >> 6) & 0x7) & 0x1) == 0 && guest.activity_state == 1) {
    guest.activity_state = 0;
    vmwrite(VMCS_32BIT_GUEST_ACTIVITY_STATE, guest.activity_state);
  }
  if ((((VMX_MSR_MISC >> 6) & 0x7) & 0x2) == 0 && guest.activity_state == 2) {
    guest.activity_state = 0;
    vmwrite(VMCS_32BIT_GUEST_ACTIVITY_STATE, guest.activity_state);
  }
  if ((((VMX_MSR_MISC >> 6) & 0x7) & 0x4) == 0 && guest.activity_state == 3) {
    guest.activity_state = 0;
    vmwrite(VMCS_32BIT_GUEST_ACTIVITY_STATE, guest.activity_state);
  }
  if (guest.activity_state == BX_ACTIVITY_STATE_HLT) {
    if (guest.sregs[BX_SEG_REG_SS].cache.dpl != 0) {
      guest.activity_state = 0;
      vmwrite(VMCS_32BIT_GUEST_ACTIVITY_STATE, guest.activity_state);
    }
  }

  guest.interruptibility_state =
      vmread(VMCS_32BIT_GUEST_INTERRUPTIBILITY_STATE);
  if (guest.interruptibility_state & ~BX_VMX_INTERRUPTIBILITY_STATE_MASK) {
    guest.interruptibility_state &= BX_VMX_INTERRUPTIBILITY_STATE_MASK;
    vmwrite(VMCS_32BIT_GUEST_INTERRUPTIBILITY_STATE,
            guest.interruptibility_state);
  }

  if (guest.interruptibility_state & 0x3) {
    if (guest.activity_state != BX_ACTIVITY_STATE_ACTIVE) {
      guest.interruptibility_state &= ~(0x3);
      vmwrite(VMCS_32BIT_GUEST_INTERRUPTIBILITY_STATE,
              guest.interruptibility_state);
    }
  }

  if ((guest.interruptibility_state & BX_VMX_INTERRUPTS_BLOCKED_BY_STI) &&
      (guest.interruptibility_state & BX_VMX_INTERRUPTS_BLOCKED_BY_MOV_SS)) {
    guest.interruptibility_state &= ~BX_VMX_INTERRUPTS_BLOCKED_BY_MOV_SS;
    vmwrite(VMCS_32BIT_GUEST_INTERRUPTIBILITY_STATE,
            guest.interruptibility_state);
  }

  if ((guest.rflags & EFlagsIFMask) == 0) {
    if (guest.interruptibility_state & BX_VMX_INTERRUPTS_BLOCKED_BY_STI) {
      guest.interruptibility_state &= ~BX_VMX_INTERRUPTS_BLOCKED_BY_STI;
      vmwrite(VMCS_32BIT_GUEST_INTERRUPTIBILITY_STATE,
              guest.interruptibility_state);
    }
  }
  if (guest.rflags & EFlagsTFMask) {
    if (guest.interruptibility_state & BX_VMX_INTERRUPTS_BLOCKED_BY_STI ||
        guest.interruptibility_state & BX_VMX_INTERRUPTS_BLOCKED_BY_MOV_SS ||
        guest.activity_state == BX_ACTIVITY_STATE_HLT) {
      if (!(guest.ia32_debugctl_msr & 1)) {
        guest.tmpDR6 |= 1 << 14;
        vmwrite(VMCS_GUEST_PENDING_DBG_EXCEPTIONS, guest.tmpDR6);
      }
    }
  }

  if (VMENTRY_INJECTING_EVENT(vm.vmentry_interr_info)) {
    unsigned event_type = (vm.vmentry_interr_info >> 8) & 7;
    unsigned vector = vm.vmentry_interr_info & 0xff;
    if (event_type == BX_EXTERNAL_INTERRUPT) {
      if ((guest.interruptibility_state & 0x3) != 0 ||
          (guest.rflags & EFlagsIFMask) == 0) {
        guest.interruptibility_state &= ~(0x3);
        guest.rflags |= EFlagsIFMask;
        vmwrite(VMCS_32BIT_GUEST_INTERRUPTIBILITY_STATE,
                guest.interruptibility_state);
        vmwrite(VMCS_GUEST_RFLAGS, guest.rflags);
      }
    }
    if (event_type == BX_NMI) {
      if ((guest.interruptibility_state & 0x3) != 0) {
        guest.interruptibility_state &= ~(0x3);
        vmwrite(VMCS_32BIT_GUEST_INTERRUPTIBILITY_STATE,
                guest.interruptibility_state);
      }
    }
    if (guest.activity_state == BX_ACTIVITY_STATE_WAIT_FOR_SIPI) {
      guest.activity_state = BX_ACTIVITY_STATE_ACTIVE;
      vmwrite(VMCS_32BIT_GUEST_ACTIVITY_STATE, guest.activity_state);
    }
    if (guest.activity_state == BX_ACTIVITY_STATE_SHUTDOWN &&
        event_type != BX_NMI && vector != BX_MC_EXCEPTION) {
      guest.activity_state = BX_ACTIVITY_STATE_ACTIVE;
      vmwrite(VMCS_32BIT_GUEST_ACTIVITY_STATE, guest.activity_state);
    }
  }

  if (vmentry_ctrls & VMX_VMENTRY_CTRL1_SMM_ENTER) {
    if (!(guest.interruptibility_state &
          BX_VMX_INTERRUPTS_BLOCKED_SMI_BLOCKED)) {
      guest.activity_state |= BX_VMX_INTERRUPTS_BLOCKED_SMI_BLOCKED;
      vmwrite(VMCS_32BIT_GUEST_ACTIVITY_STATE, guest.activity_state);
    }

    if (guest.activity_state == BX_ACTIVITY_STATE_WAIT_FOR_SIPI) {
      guest.activity_state = BX_ACTIVITY_STATE_ACTIVE;
      vmwrite(VMCS_32BIT_GUEST_ACTIVITY_STATE, guest.activity_state);
    }
  }

  if (guest.interruptibility_state & BX_VMX_INTERRUPTS_BLOCKED_SMI_BLOCKED) {
    if (!in_smm) {
      guest.interruptibility_state &= ~BX_VMX_INTERRUPTS_BLOCKED_SMI_BLOCKED;
      vmwrite(VMCS_32BIT_GUEST_INTERRUPTIBILITY_STATE,
              guest.interruptibility_state);
    }
  }

  // if (guest.interruptibility_state & BX_VMX_INTERRUPTS_BLOCKED_NMI_BLOCKED) {
  //   if (vm.vmexec_ctrls1 & VMX_VM_EXEC_CTRL1_VIRTUAL_NMI)
  //     mask_event(BX_EVENT_VMX_VIRTUAL_NMI);
  //   else
  //     mask_event(BX_EVENT_NMI);
  // }
  // not supported
  //   if (! x86_64_guest && (guest.cr4 & BX_CR4_PAE_MASK) != 0 && (guest.cr0 &
  //   BX_CR0_PG_MASK) != 0) {
  // #if BX_SUPPORT_VMX >= 2
  //     if (vm.vmexec_ctrls3 & VMX_VM_EXEC_CTRL3_EPT_ENABLE) {
  //       for (n=0;n<4;n++)
  //          guest.pdptr[n] = vmread(VMCS_64BIT_GUEST_IA32_PDPTE0 + 2*n);

  //       if (! CheckPDPTR(guest.pdptr)) {
  //          *qualification = VMENTER_ERR_GUEST_STATE_PDPTR_LOADING;
  //          // DEBUG_PRINT(L"VMENTER: EPT Guest State PDPTRs Checks
  //          Failed\r\n"); return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
  //       }
  //     }
  //     else
  // #endif
  //     {
  //       if (! CheckPDPTR_CR3(guest.cr3)) {
  //          *qualification = VMENTER_ERR_GUEST_STATE_PDPTR_LOADING;
  //          // DEBUG_PRINT(L"VMENTER: Guest State PDPTRs Checks Failed\r\n");
  //          return VMX_VMEXIT_VMENTRY_FAILURE_GUEST_STATE;
  //       }
  //     }
  //   }

  return VMXERR_NO_ERROR;
}

uint32_t VMX_Read_Virtual_APIC_VTPR(void) {
  uintptr_t vtpr_ptr = vmread(0x2012) + 0x80;
  uint32_t* vtpr = (uint32_t*)vtpr_ptr;
  return vtpr[0];
}
uint32_t VMXReadRevisionID(bx_phy_address pAddr) {
  uintptr_t vmcs_ptr = pAddr;
  uint32_t* vmcs = (uint32_t*)vmcs_ptr;
  return vmcs[0];
}
void VMXWriteRevisionID(bx_phy_address pAddr, uint32_t value) {
  uintptr_t vmcs_ptr = pAddr;
  uint32_t* vmcs = (uint32_t*)vmcs_ptr;
  vmcs[0] = value;
}

int InitializeVMCS(uint64_t host_entry, uint64_t guest_entry) {
  uint32_t revision_id, error;
  struct registers regs;
  uint32_t eax, ecx, ebx, edx;
  // check the presence of VMX support
  asm volatile("cpuid" : "=c"(ecx) : "a"(1) : "ebx", "edx");

  if ((ecx & 0x20) == 0) {  // CPUID.1:ECX.VMX[bit 5] != 1
    wprintf(L"VMX is not supported in this processor\r\n");
    return -1;
  }
  wprintf(L"VMX is supported\r\n");

  // enable VMX
  wprintf(L"Enable VMX\r\n");
  asm volatile("mov %%cr4, %0" : "=r"(regs.cr4));
  regs.cr4 |= 0x2000;  // CR4.VME[bit 13] = 1
  asm volatile("mov %0, %%cr4" ::"r"(regs.cr4));

  // enable VMX operation
  wprintf(L"Enable VMX operation\r\n");
  regs.ia32_feature_control = rdmsr(0x3a);
  if ((regs.ia32_feature_control & 0x1) == 0) {
    regs.ia32_feature_control |= 0x5;  // firmware should set this
    wrmsr(0x3a, regs.ia32_feature_control);
  } else if ((regs.ia32_feature_control & 0x4) == 0) {
    wprintf(L"VMX is disabled by the firmware\r\n");
    return -1;
  }

  // apply fixed bits to CR0 & CR4
  uint64_t apply_fixed_bits(uint64_t reg, uint32_t fixed0, uint32_t fixed1) {
    reg |= rdmsr(fixed0);
    reg &= rdmsr(fixed1);
    return reg;
  }
  asm volatile("mov %%cr0, %0" : "=r"(regs.cr0));
  regs.cr0 = apply_fixed_bits(regs.cr0, 0x486, 0x487);
  asm volatile("mov %0, %%cr0" ::"r"(regs.cr0));
  asm volatile("mov %%cr4, %0" : "=r"(regs.cr4));
  regs.cr4 = apply_fixed_bits(regs.cr4, 0x488, 0x489);
  asm volatile("mov %0, %%cr4" ::"r"(regs.cr4));

  // enter VMX operation
  wprintf(L"Enter VMX operation\r\n");
  revision_id = rdmsr(0x480);
  uint32_t* ptr = (uint32_t*)vmxon_region;
  vmxonptr = (uintptr_t)ptr;
  ptr[0] = revision_id;
  asm volatile("vmxon %1" : "=@ccbe"(error) : "m"(ptr));
  if (error) {
    wprintf(L"VMXON failed.\r\n");
    return -1;
  }
  asm volatile("vmxoff");
  asm volatile("vmxon %1" : "=@ccbe"(error) : "m"(ptr));
  if (error) {
    wprintf(L"VMXON failed.\r\n");
    return -1;
  }
  // initialize VMCS
  wprintf(L"Initialize VMCS\r\n");

  ptr = (uint32_t*)vmcs;
  ptr[0] = revision_id;
  if (!current_evmcs) {
    asm volatile("vmclear %1" : "=@ccbe"(error) : "m"(ptr));
    if (error) {
      wprintf(L"VMCLEAR failed.\r\n");
      return -1;
    }
    asm volatile("vmptrld %1" : "=@ccbe"(error) : "m"(ptr));
    if (error) {
      wprintf(L"VMPTRLD failed.\r\n");
      return -1;
    }
  }

  // initialize control fields
  uint32_t apply_allowed_settings(uint32_t value, uint64_t msr_index) {
    uint64_t msr_value = rdmsr(msr_index);
    value |= (msr_value & 0xffffffff);
    value &= (msr_value >> 32);
    return value;
  }

  void vmwrite_gh(uint32_t guest_id, uint32_t host_id, uint64_t value) {
    vmwrite(guest_id, value);
    vmwrite(host_id, value);
  }

  // 16-Bit Guest and Host State Fields
  asm volatile("mov %%es, %0" : "=m"(regs.es));
  asm volatile("mov %%cs, %0" : "=m"(regs.cs));
  asm volatile("mov %%ss, %0" : "=m"(regs.ss));
  asm volatile("mov %%ds, %0" : "=m"(regs.ds));
  asm volatile("mov %%fs, %0" : "=m"(regs.fs));
  asm volatile("mov %%gs, %0" : "=m"(regs.gs));
  asm volatile("sldt %0" : "=m"(regs.ldt));
  asm volatile("str %0" : "=m"(regs.tr));
  vmwrite_gh(0x0800, 0x0c00, regs.es);  // ES selector
  vmwrite_gh(0x0802, 0x0c02, regs.cs);  // CS selector
  vmwrite_gh(0x0804, 0x0c04, regs.ss);  // SS selector
  vmwrite_gh(0x0806, 0x0c06, regs.ds);  // DS selector
  vmwrite_gh(0x0808, 0x0c08, regs.fs);  // FS selector
  vmwrite_gh(0x080a, 0x0c0a, regs.gs);  // GS selector

  vmwrite(0x080c, regs.ldt);            // Guest LDTR selector
  vmwrite_gh(0x080e, 0x0c0c, regs.tr);  // TR selector
  vmwrite(0x812, 0x10);                 // pml index
  vmwrite(0x0c0c, 0x08);                // dummy TR selector for real hardware

  // 64-Bit Guest and Host State Fields
  vmwrite(0x2802, 0);  // Guest IA32_DEBUGCTL
  regs.ia32_efer = rdmsr(0xC0000080);
  vmwrite_gh(0x2806, 0x2c02, regs.ia32_efer);  // IA32_EFER
  // 32-Bit Guest and Host State Fields
  asm volatile("sgdt %0" : "=m"(regs.gdt));
  asm volatile("sidt %0" : "=m"(regs.idt));

  vmwrite(0x4800, get_seg_limit(regs.es));   // Guest ES limit
  vmwrite(0x4802, get_seg_limit(regs.cs));   // Guest CS limit
  vmwrite(0x4804, get_seg_limit(regs.ss));   // Guest SS limit
  vmwrite(0x4806, get_seg_limit(regs.ds));   // Guest DS limit
  vmwrite(0x4808, get_seg_limit(regs.fs));   // Guest FS limit
  vmwrite(0x480a, get_seg_limit(regs.gs));   // Guest GS limit
  vmwrite(0x480c, get_seg_limit(regs.ldt));  // Guest LDTR limit
  uint32_t tr_limit = get_seg_limit(regs.tr);
  if (tr_limit == 0)
    tr_limit = 0x0000ffff;
  vmwrite(0x480e, tr_limit);                        // Guest TR limit
  vmwrite(0x4810, regs.gdt.limit);                  // Guest GDTR limit
  vmwrite(0x4812, regs.idt.limit);                  // Guest IDTR limit
  vmwrite(0x4814, get_seg_access_rights(regs.es));  // Guest ES access rights
  vmwrite(0x4816, get_seg_access_rights(regs.cs));  // Guest CS access rights
  vmwrite(0x4818, get_seg_access_rights(regs.ss));  // Guest SS access rights
  vmwrite(0x481a, get_seg_access_rights(regs.ds));  // Guest DS access rights
  vmwrite(0x481c, get_seg_access_rights(regs.fs));  // Guest FS access rights
  vmwrite(0x481e, get_seg_access_rights(regs.gs));  // Guest GS access rights
  uint32_t ldtr_access_rights = get_seg_access_rights(regs.ldt);
  if (ldtr_access_rights == 0)
    ldtr_access_rights = 0x18082;
  vmwrite(0x4820, ldtr_access_rights);  // Guest LDTR access rights
  uint32_t tr_access_rights = get_seg_access_rights(regs.tr);
  if (tr_access_rights == 0)
    tr_access_rights = 0x0808b;
  vmwrite(0x4822, tr_access_rights);  // Guest TR access rights

  vmwrite(0x6000, 0xffffffffffffffff);  // CR0 guest/host mask
  vmwrite(0x6002, 0xffffffffffffffff);  // CR4 guest/host mask
  vmwrite(0x6004, ~regs.cr0);           // CR0 read shadow
  vmwrite(0x6006, ~regs.cr4);           // CR4 read shadow
  // Natual-Width Control Fields
  asm volatile("mov %%cr3, %0" : "=r"(regs.cr3));
  vmwrite_gh(0x6800, 0x6c00, regs.cr0);
  vmwrite_gh(0x6802, 0x6c02, regs.cr3);
  vmwrite_gh(0x6804, 0x6c04, regs.cr4);

  vmwrite(0x6806, get_seg_base(regs.es));   // es base
  vmwrite(0x6808, get_seg_base(regs.cs));   // cs base
  vmwrite(0x680a, get_seg_base(regs.ss));   // ss base
  vmwrite(0x680c, get_seg_base(regs.ds));   // ds base
  vmwrite(0x680e, get_seg_base(regs.fs));   // fs base
  vmwrite(0x6810, get_seg_base(regs.gs));   // gs base
  vmwrite(0x6812, get_seg_base(regs.ldt));  // LDTR base
  vmwrite(0x6814, (uint64_t)tss);           // TR base

  vmwrite_gh(0x6816, 0x6C0C, regs.gdt.base);  // GDTR base
  vmwrite_gh(0x6818, 0x6C0E, regs.idt.base);  // IDT base

  vmwrite(0x6C14, (uint64_t)&host_stack[sizeof(host_stack)]);    // HOST_RSP
  vmwrite(0x6C16, (uint64_t)host_entry);                         // Host RIP
  vmwrite(0x681C, (uint64_t)&guest_stack[sizeof(guest_stack)]);  // GUEST_RSP
  vmwrite(0x681E, (uint64_t)guest_entry);                        // Guest RIP

  asm volatile("pushf; pop %%rax" : "=a"(regs.rflags));
  regs.rflags &= ~0x200ULL;  // clear interrupt enable flag
  vmwrite(0x6820, regs.rflags);

  memset(&io_bitmap_a, 0xaa, sizeof(io_bitmap_a));
  vmwrite(0x2000, (uint64_t)io_bitmap_a);
  memset(&io_bitmap_b, 0x55, sizeof(io_bitmap_b));
  vmwrite(0x2002, (uint64_t)io_bitmap_b);

  // set up msr bitmap to vmexit from L2
  memset(&msr_bitmap, 0xff, sizeof(msr_bitmap));
  vmwrite(0x2004, (uint64_t)msr_bitmap);

  for (int i = 0; i < 512; i++) {
    msr_store[i * 2] = 0x10;
    msr_store[i * 2 + 1] = 0x10;
    msr_load[i * 2] = 0x10;
    msr_load[i * 2 + 1] = 0x20;
    // vmentry_msr_load[i*2] = (uint64_t)0xC0000100;
    vmentry_msr_load[i * 2] = (uint64_t)0x10;
    vmentry_msr_load[i * 2 + 1] = (uint64_t)0x10;
    // vmentry_msr_load[i*2+1] = (uint64_t)rdmsr(0x40000073);
  }

  for (int i = 0; i < 8; i++) {
    posted_int_desc[i] = 0;
  }
  uintptr_t posted_int_desc_addr = (uintptr_t)posted_int_desc;
  vmwrite(0x2006, (uint64_t)msr_store);
  vmwrite(0x2008, (uint64_t)msr_load);
  vmwrite(0x200a, (uint64_t)vmentry_msr_load);
  vmwrite(0x400e, 511);
  vmwrite(0x4010, 511);
  vmwrite(0x4014, 511);

  vmwrite(0x200c, (uint64_t)vmxonptr);
  vmwrite(0x200e, (uint64_t)pml);
  vmwrite(0x2010, (uint64_t)-1);
  vmwrite(0x2012, (uint64_t)virtual_apic);
  vmwrite(0x2014, (uint64_t)apic_access);
  vmwrite(0x2016, (uint64_t)posted_int_desc);
  vmwrite(0x2018, 0x1);  // VMFUNC_CTRLS
  for (int i = 0; i < 4096; i++) {
    virtual_apic[i] = 0xff;
  }
  virtual_apic[0x16] = 0x16;
  virtual_apic[0x80] = 0x80;
  virtual_apic[0x80] = 0xff;

  uint64_t eptp = (uint64_t)pml4_table;
  uint64_t eptp2 = (uint64_t)pml4_table_2;
  eptp |= 0x5e;  // WB
  // eptp |= 0x58; // UC
  eptp2 |= 0x5e;
  // eptp2 |= 0x58;
  vmwrite(0x201a, eptp);

  eptp_list[0] = eptp;
  eptp_list[1] = eptp2;
  eptp_list[2] = eptp2;
  eptp_list[3] = eptp2;
  eptp_list[4] = eptp2;
  uint64_t eptp_list_addr = (uint64_t)eptp_list;
  vmwrite(0x2024, eptp_list_addr);

  vmwrite(0x2026, (uint64_t)vmread_bitmap);
  vmwrite(0x2028, (uint64_t)vmwrite_bitmap);
  vmwrite(0x202a, (uint64_t)excep_info_area);
  vmwrite(0x2032, 0xffffffffffffffff);
  vmwrite(0x202c, 0xffffffffffffffff);

  uint32_t* shadow_ptr = (uint32_t*)shadow_vmcs;
  shadow_ptr[0] = rdmsr(0x480) | BX_VMCS_SHADOW_BIT_MASK;
  vmwrite(0x2800, (uint64_t)shadow_vmcs);
  vmwrite(0x2802, 0xFFFFFFFFFFFF203C);

  vmwrite(0x482e, 0xffffffff);

  vmwrite(0x4004, 0x0);  // Exception bitmap

  vmwrite(0x0, 0xffff);

  vmwrite(0x4006, 0x0);
  vmwrite(0x4008, -1);
  vmwrite(0x400a, 0x0);

  // Pin-based VM-execution controls
  vmwrite(0x4000, apply_allowed_settings(0x00, 0x481));

  // Primary processor-based VM-execution controls
  uint32_t ctrls2 = 0 | 1 << 2 | 1 << 3 | 1 << 7 | 1 << 9 | 1 << 10 | 1 << 11 |
                    1 << 12 | 1 << 15 | 1 << 16 | 1 << 19 | 1 << 20 | 1 << 21 |
                    1 << 22 | 1 << 23 | 1 << 24 | 1 << 25 |
                    // 1 << 27 |
                    1 << 28 | 1 << 29 | 1 << 30 | 1 << 31;
  vmwrite(0x4002, apply_allowed_settings(ctrls2, 0x482));

  uint32_t ctrls3 = 0 | 1 << 0 | 1 << 1 | 1 << 2 | 1 << 3 | 1 << 4 | 1 << 5 |
                    1 << 6 | 1 << 7 | 1 << 8 | 1 << 9 | 1 << 10 | 1 << 11 |
                    1 << 12 | 1 << 13 | 1 << 14 |
                    //   1 << 15 |
                    1 << 16 | 1 << 17 | 1 << 18 | 1 << 19 | 1 << 20 | 1 << 22 |
                    1 << 23 | 1 << 24 | 1 << 25 | 1 << 26 | 1 << 27 | 1 << 28;
  vmwrite(0x401e, apply_allowed_settings(ctrls3, 0x48b));

  uint32_t exit_ctls = apply_allowed_settings(0xffffffff, 0x483);
  vmwrite(0x400c, exit_ctls);  // VM-exit controls
  uint32_t entry_ctls = apply_allowed_settings(0xffffffff, 0x484);
  vmwrite(0x4012, entry_ctls & ~(1 << 15));  // VM-entry controls

  vmwrite(0x4016, 0x00000000);  // vmentry_intr_info
  vmwrite(0x401c, 0xf);
  vmwrite(0x4824, 0x8);

#ifdef XEN
  vmwrite(0x2800, 0xffffffffffffffff);
#endif

  return 0;
}