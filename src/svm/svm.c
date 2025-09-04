// SPDX-License-Identifier: GPL-2.0-only
/*
 * Portions Copyright (c) 2011-2018 Stanislav Shwartsman
 *        Written by Stanislav Shwartsman [sshwarts at sourceforge net]
 * Portions Copyright (C) 2020, Red Hat, Inc.
 */

#include "svm.h"
#include "../common/uefi.h"

#ifdef DEBUG
#define DEBUG_PRINT(...) wprintf(__VA_ARGS__)
#else
#define DEBUG_PRINT(...)
#endif

uint64_t rflags;
struct gpr64_regs guest_regs;

static void vmcb_set_seg(struct vmcb_seg* seg,
                         u16 selector,
                         u64 base,
                         u32 limit,
                         u32 attr) {
  seg->selector = selector;
  seg->attrib = attr;
  seg->limit = limit;
  seg->base = base;
}

void generic_svm_setup(struct svm_test_data* svm,
                       void* guest_rip,
                       void* guest_rsp) {
  struct vmcb* vmcb = svm->vmcb;
  uint64_t vmcb_gpa = svm->vmcb_gpa;
  struct vmcb_save_area* save = &vmcb->save;
  struct vmcb_control_area* ctrl = &vmcb->control;
  u32 data_seg_attr = 3 | SVM_SELECTOR_S_MASK | SVM_SELECTOR_P_MASK |
                      SVM_SELECTOR_DB_MASK | SVM_SELECTOR_G_MASK;
  u32 code_seg_attr = 9 | SVM_SELECTOR_S_MASK | SVM_SELECTOR_P_MASK |
                      SVM_SELECTOR_L_MASK | SVM_SELECTOR_G_MASK;
  uint64_t efer;

  efer = rdmsr(MSR_EFER);
  wrmsr(MSR_EFER, efer | EFER_SVME);
  wrmsr(MSR_VM_HSAVE_PA, svm->save_area_gpa);

  __builtin_memset(vmcb, 0, sizeof(*vmcb));
  asm volatile("vmsave %0\n\t" : : "a"(vmcb_gpa) : "memory");
  vmcb_set_seg(&save->es, get_es(), 0, -1U, data_seg_attr);
  vmcb_set_seg(&save->cs, get_cs(), 0, -1U, code_seg_attr);
  vmcb_set_seg(&save->ss, get_ss(), 0, -1U, data_seg_attr);
  vmcb_set_seg(&save->ds, get_ds(), 0, -1U, data_seg_attr);
  struct desc_ptr gdt, idt;
  get_gdt(&gdt);
  get_idt(&idt);
  vmcb_set_seg(&save->gdtr, 0, gdt.address, gdt.size, 0);
  vmcb_set_seg(&save->idtr, 0, idt.address, idt.size, 0);

  ctrl->asid = 1;
  save->cpl = 0;
  save->efer = rdmsr(MSR_EFER);
  asm volatile("mov %%cr4, %0" : "=r"(save->cr4) : : "memory");
  asm volatile("mov %%cr3, %0" : "=r"(save->cr3) : : "memory");
  asm volatile("mov %%cr0, %0" : "=r"(save->cr0) : : "memory");
  asm volatile("mov %%dr7, %0" : "=r"(save->dr7) : : "memory");
  asm volatile("mov %%dr6, %0" : "=r"(save->dr6) : : "memory");
  asm volatile("mov %%cr2, %0" : "=r"(save->cr2) : : "memory");
  save->g_pat = rdmsr(MSR_IA32_CR_PAT);
  save->dbgctl = rdmsr(MSR_IA32_DEBUGCTLMSR);
  ctrl->intercept = (1ULL << INTERCEPT_VMRUN) | (1ULL << INTERCEPT_VMMCALL);
  ctrl->msrpm_base_pa = svm->msr_gpa;

  vmcb->save.rip = (u64)guest_rip;
  vmcb->save.rsp = (u64)guest_rsp;

  guest_regs.rdi = (uint64_t)&svm;
}

/*
 * selftests do not use interrupts so we dropped clgi/sti/cli/stgi
 * for now. registers involved in LOAD/SAVE_GPR_C are eventually
 * unmodified so they do not need to be in the clobber list.
 */
int run_guest(struct vmcb* vmcb, uint64_t vmcb_gpa) {
  asm volatile("vmload\n\t" ::"a"(vmcb_gpa));

  asm volatile(
      "mov %1, %%r15\n\t"  // rflags
      "mov %%r15, %0\n\t"
      "mov %2, %%r15\n\t"  // rax
      : "=r"(vmcb->save.rflags)
      : "r"(rflags), "r"(guest_regs.rax)
      : "r15");

  asm volatile("mov %%r15, %0\n\t" : "=r"(vmcb->save.rax));
  asm volatile("mov %%rbp, %0\n\t" : "=r"(guest_regs.rbp));

  asm volatile(
      "xchg %%rbx, %0\n\t"
      "xchg %%rcx, %1\n\t"
      "xchg %%rdx, %2\n\t"
      "xchg %%rbp, %3\n\t"
      "xchg %%rsi, %4\n\t"
      "xchg %%rdi, %5\n\t"
      "xchg %%r8,  %6\n\t"
      "xchg %%r9,  %7\n\t"
      "xchg %%r10, %8\n\t"
      "xchg %%r11, %9\n\t"
      "xchg %%r12, %10\n\t"
      "xchg %%r13, %11\n\t"
      "xchg %%r14, %12\n\t"
      "xchg %%r15, %13\n\t"
      : "+m"(guest_regs.rbx), "+m"(guest_regs.rcx), "+m"(guest_regs.rdx),
        "+m"(guest_regs.rbp), "+m"(guest_regs.rsi), "+m"(guest_regs.rdi),
        "+m"(guest_regs.r8), "+m"(guest_regs.r9), "+m"(guest_regs.r10),
        "+m"(guest_regs.r11), "+m"(guest_regs.r12), "+m"(guest_regs.r13),
        "+m"(guest_regs.r14), "+m"(guest_regs.r15));

  int rc;
  asm volatile(
      "vmrun \n\t"
      "jc 1f\n\t"
      "movl $0, %0\n\t"
      "jmp 2f\n\t"
      "1:\n\t"
      "movl $1, %0\n\t"
      "2:\n\t"
      : "=r"(rc)
      : "a"(vmcb_gpa)
      : "memory", "cc");

  asm volatile(
      "xchg %%rbx, %0\n\t"
      "xchg %%rcx, %1\n\t"
      "xchg %%rdx, %2\n\t"
      "xchg %%rbp, %3\n\t"
      "xchg %%rsi, %4\n\t"
      "xchg %%rdi, %5\n\t"
      "xchg %%r8,  %6\n\t"
      "xchg %%r9,  %7\n\t"
      "xchg %%r10, %8\n\t"
      "xchg %%r11, %9\n\t"
      "xchg %%r12, %10\n\t"
      "xchg %%r13, %11\n\t"
      "xchg %%r14, %12\n\t"
      "xchg %%r15, %13\n\t"
      : "+m"(guest_regs.rbx), "+m"(guest_regs.rcx), "+m"(guest_regs.rdx),
        "+m"(guest_regs.rbp), "+m"(guest_regs.rsi), "+m"(guest_regs.rdi),
        "+m"(guest_regs.r8), "+m"(guest_regs.r9), "+m"(guest_regs.r10),
        "+m"(guest_regs.r11), "+m"(guest_regs.r12), "+m"(guest_regs.r13),
        "+m"(guest_regs.r14), "+m"(guest_regs.r15));
  asm volatile(
      "mov %1, %%r15\n\t"  // rflags
      "mov %%r15, %0\n\t"
      : "=r"(rflags)
      : "r"(vmcb->save.rflags)
      : "r15");
  asm volatile(
      "mov %1, %%r15\n\t"  // rax
      "mov %%r15, %0 \n\t"
      : "=r"(guest_regs.rax)
      : "r"(vmcb->save.rax)
      : "r15");
  asm volatile("vmsave %%rax\n\t" ::"a"(vmcb_gpa));

  return rc;
}

void print_vmcb_control(struct svm_test_data* svm) {
  wprintf(
      L"**********\r\n"
      L"intercept_cr 0x%x\r\n"
      L"intercept_dr 0x%x\r\n"
      L"intercept_exceptions 0x%x\r\n"
      L"intercept 0x%x\r\n"
      L"pause_filter_thresh 0x%x\r\n"
      L"pause_filter_count 0x%x\r\n"
      L"iopm_base_pa 0x%x\r\n"
      L"msrpm_base_pa 0x%x\r\n"
      L"tsc_offset 0x%x\r\n"
      L"asid 0x%x\r\n"
      L"int_ctl 0x%x\r\n"
      L"int_vector 0x%x\r\n"
      L"int_state 0x%x\r\n"
      L"exit_code 0x%x\r\n"
      L"exit_code_hi 0x%x\r\n"
      L"exit_info_1 0x%x\r\n"
      L"exit_info_2 0x%x\r\n"
      L"exit_int_info 0x%x\r\n"
      L"exit_int_info_err 0x%x\r\n"
      L"nested_ctl 0x%x\r\n"
      L"avic_vapic_bar 0x%x\r\n"
      L"event_inj 0x%x\r\n"
      L"event_inj_err 0x%x\r\n"
      L"nested_cr3 0x%x\r\n"
      L"virt_ext 0x%x\r\n"
      L"clean 0x%x\r\n"
      L"reserved_5 0x%x\r\n"
      L"next_rip 0x%x\r\n"
      L"tlb_ctl 0x%x\r\n"
      L"insn_len 0x%x\r\n"
      L"avic_backing_page 0x%x\r\n"
      L"avic_logical_id 0x%x\r\n"
      L"avic_physical_id 0x%x\r\n"
      L"**********\r\n",
      svm->vmcb->control.intercept_cr, svm->vmcb->control.intercept_dr,
      svm->vmcb->control.intercept_exceptions, svm->vmcb->control.intercept,
      svm->vmcb->control.pause_filter_thresh,
      svm->vmcb->control.pause_filter_count, svm->vmcb->control.iopm_base_pa,
      svm->vmcb->control.msrpm_base_pa, svm->vmcb->control.tsc_offset,
      svm->vmcb->control.asid, svm->vmcb->control.int_ctl,
      svm->vmcb->control.int_vector, svm->vmcb->control.int_state,
      svm->vmcb->control.exit_code, svm->vmcb->control.exit_code_hi,
      svm->vmcb->control.exit_info_1, svm->vmcb->control.exit_info_2,
      svm->vmcb->control.exit_int_info, svm->vmcb->control.exit_int_info_err,
      svm->vmcb->control.nested_ctl, svm->vmcb->control.avic_vapic_bar,
      svm->vmcb->control.event_inj, svm->vmcb->control.event_inj_err,
      svm->vmcb->control.nested_cr3, svm->vmcb->control.virt_ext,
      svm->vmcb->control.clean, svm->vmcb->control.reserved_5,
      svm->vmcb->control.next_rip, svm->vmcb->control.tlb_ctl,
      svm->vmcb->control.insn_len, svm->vmcb->control.avic_backing_page,
      svm->vmcb->control.avic_logical_id, svm->vmcb->control.avic_physical_id);
  return;
}

void print_vmcb_save(struct svm_test_data* svm) {
  wprintf(
      L"**********\r\n"
      L"cpl 0x%x\r\n"
      L"efer 0x%x\r\n"
      L"cr4 0x%x\r\n"
      L"cr3 0x%x\r\n"
      L"cr0 0x%x\r\n"
      L"dr7 0x%x\r\n"
      L"dr6 0x%x\r\n"
      L"rflags 0x%x\r\n"
      L"rip 0x%x\r\n"
      L"rsp 0x%x\r\n"
      L"rax 0x%x\r\n"
      L"star 0x%x\r\n"
      L"lstar 0x%x\r\n"
      L"cstar 0x%x\r\n"
      L"sfmask 0x%x\r\n"
      L"kernel_gs_base 0x%x\r\n"
      L"sysenter_cs 0x%x\r\n"
      L"sysenter_esp 0x%x\r\n"
      L"sysenter_eip 0x%x\r\n"
      L"cr2 0x%x\r\n"
      L"g_pat 0x%x\r\n"
      L"dbgctl 0x%x\r\n"
      L"br_from 0x%x\r\n"
      L"br_to 0x%x\r\n"
      L"last_excp_from 0x%x\r\n"
      L"last_excp_to 0x%x\r\n"
      L"**********\r\n",
      svm->vmcb->save.cpl, svm->vmcb->save.efer, svm->vmcb->save.cr4,
      svm->vmcb->save.cr3, svm->vmcb->save.cr0, svm->vmcb->save.dr7,
      svm->vmcb->save.dr6, svm->vmcb->save.rflags, svm->vmcb->save.rip,
      svm->vmcb->save.rsp, svm->vmcb->save.rax, svm->vmcb->save.star,
      svm->vmcb->save.lstar, svm->vmcb->save.cstar, svm->vmcb->save.sfmask,
      svm->vmcb->save.kernel_gs_base, svm->vmcb->save.sysenter_cs,
      svm->vmcb->save.sysenter_esp, svm->vmcb->save.sysenter_eip,
      svm->vmcb->save.cr2, svm->vmcb->save.g_pat, svm->vmcb->save.dbgctl,
      svm->vmcb->save.br_from, svm->vmcb->save.br_to,
      svm->vmcb->save.last_excp_from, svm->vmcb->save.last_excp_to);
  return;
}

int SvmEnterLoadCheckControls(struct svm_test_data* svm) {
  struct vmcb* vmcb = svm->vmcb;
  struct vmcb_save_area* save = &vmcb->save;
  struct vmcb_control_area* ctrls = &vmcb->control;

  if (!SVM_INTERCEPT(INTERCEPT_VMRUN)) {
    ctrls->intercept |= ((uint64_t)1 << (INTERCEPT_VMRUN & 63));
    DEBUG_PRINT(L"VMRUN: VMRUN intercept bit is not set!\r\n");
  }

  // force 4K page alignment
  if (!IsValidPhyAddr(ctrls->iopm_base_pa)) {
    ctrls->iopm_base_pa &= ~BX_PHY_ADDRESS_RESERVED_BITS;
    DEBUG_PRINT(L"VMRUN: invalid IOPM Base Address!\r\n");
  }

  // force 4K page alignment
  if (!IsValidPhyAddr(ctrls->msrpm_base_pa)) {
    ctrls->msrpm_base_pa &= ~BX_PHY_ADDRESS_RESERVED_BITS;
    DEBUG_PRINT(L"VMRUN: invalid MSRPM Base Address!\r\n");
  }

  if (ctrls->asid == 0) {
    ctrls->asid = 1;
    DEBUG_PRINT(L"VMRUN: attempt to run guest with host ASID!\r\n");
  }

  uint64_t svm_extensions_bitmask;
  asm volatile("cpuid"
               : "=d"(svm_extensions_bitmask)
               : "a"(0x8000000A)
               : "ebx", "ecx");

  uint8_t nested_paging = ctrls->nested_ctl & 0x1;
  if (!BX_SUPPORT_SVM_EXTENSION(BX_CPUID_SVM_NESTED_PAGING)) {
    if (nested_paging) {
      DEBUG_PRINT(
          L"VMRUN: Nesting paging is not supported in this SVM "
          L"configuration!\r\n");
      ctrls->nested_ctl = 0;
    }
  }

  if (nested_paging) {
    if (!(get_cr0() & BX_CR0_PG_MASK)) {
      nested_paging = 0;
      ctrls->nested_ctl &= ~(0x1);
      DEBUG_PRINT(
          L"VMRUN: attempt to enter nested paging mode when host paging "
          L"is disabled!\r\n");
    } else if (!isValidMSR_PAT(save->g_pat)) {
      save->g_pat = rdmsr(MSR_IA32_CR_PAT);
      DEBUG_PRINT(L"VMRUN: invalid memory type in guest PAT_MSR!\r\n");
    }

    else if (long_mode()) {
      if (!IsValidPhyAddr(ctrls->nested_cr3)) {
        DEBUG_PRINT(L"VMRUN(): NCR3 reserved bits set!\r\n");
        return -1;
      }
    }
  }

  return 0;
}

int SvmEnterLoadCheckGuestState(struct svm_test_data* svm) {
  struct vmcb* vmcb = svm->vmcb;
  struct vmcb_save_area* save = &vmcb->save;
  struct vmcb_control_area* ctrls = &vmcb->control;

  if (save->efer >> 32) {
    DEBUG_PRINT(L"VMRUN: Guest EFER[63:32] is not zero\r\n");
    save->efer &= 0xFFFFFFFF;
  }

  if ((save->efer & 0xFFFFFFFF) & EFER_RESERVED) {
    DEBUG_PRINT(L"VMRUN: Guest EFER reserved bits set\r\n");
    save->efer &= ~EFER_RESERVED;
  }

  if (!(save->efer & EFER_SVME)) {
    DEBUG_PRINT(L"VMRUN: Guest EFER.SVME = 0\r\n");
    save->efer |= EFER_SVME;
  }

  if (save->cr0 >> 32) {
    DEBUG_PRINT(L"VMRUN: Guest CR0[63:32] is not zero\r\n");
    save->cr0 &= 0xFFFFFFFF;
  }

  if (save->cr4 >> 32) {
    DEBUG_PRINT(L"VMRUN: Guest CR4[63:32] is not zero\r\n");
    save->cr4 &= 0xFFFFFFFF;
  }

  if ((save->cr4 & 0xFFFFFFFF) & CR4_RESERVED) {
    DEBUG_PRINT(L"VMRUN: Guest CR4 reserved bits set\r\n");
    save->cr4 &= ~CR4_RESERVED;
  }

  if (save->dr6 >> 32) {
    DEBUG_PRINT(L"VMRUN: Guest DR6[63:32] is not zero\r\n");
    save->dr6 &= 0xFFFFFFFF;
  }

  if (save->dr7 >> 32) {
    DEBUG_PRINT(L"VMRUN: Guest DR7[63:32] is not zero\r\n");
    save->dr7 &= 0xFFFFFFFF;
  }

  if (!(save->cr0 & BX_CR0_CD_MASK) && (save->cr0 & BX_CR0_NW_MASK)) {
    save->cr0 |= BX_CR0_CD_MASK;
    DEBUG_PRINT(L"Attempt to set CR0.NW with CR0.CD cleared!\r\n");
  }

  if ((save->efer & EFER_LME) && (save->cr0 & BX_CR0_PG_MASK) &&
      !(save->cr0 & BX_CR0_PE_MASK)) {
    save->cr0 |= BX_CR0_PE_MASK;
    DEBUG_PRINT(L"Attempt to set EFER.LME and CR0.PG with CR0.PE cleared!\r\n");
  }

  if ((save->efer & EFER_LME) && (save->cr0 & BX_CR0_PG_MASK) &&
      !(save->cr4 & BX_CR4_PAE_MASK)) {
    save->cr4 |= BX_CR4_PAE_MASK;
    DEBUG_PRINT(
        L"Attempt to set EFER.LME and CR0.PG with CR4.PAE cleared!\r\n");
  }

  return 0;
}
