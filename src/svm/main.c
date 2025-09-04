#include <stddef.h>
#include <stdint.h>

#include "../common/cpu.h"
#include "../common/input.h"
#include "../common/uefi.h"
#include "fuzz.h"
#include "svm.h"

#define HARNESS_COUNT 1
#define INVALIDATE_COUNT 1

EFI_SYSTEM_TABLE* SystemTable;
extern uint64_t rflags;
extern struct gpr64_regs guest_regs;

static int env[28];
uint8_t* input_buf;

uint64_t loop_count, index_count, index_selector_count = 0x700;

char vmcb[4096] __attribute__((aligned(4096)));
char vmcb2[4096] __attribute__((aligned(4096)));
char save_area[4096] __attribute__((aligned(4096)));
char msr[4096] __attribute__((aligned(4096)));
char host_stack[4096] __attribute__((aligned(4096)));
char guest_stack[4096] __attribute__((aligned(4096)));

struct hv_enlightened_vmcs* current_evmcs;
struct hv_vp_assist_page* current_vp_assist;
char vp_assist[4096] __attribute__((aligned(4096)));
char pgs_gpa[4096] __attribute__((aligned(4096)));
char hv_pages[4096] __attribute__((aligned(4096)));
char partition_assist[4096] __attribute__((aligned(4096)));
char enlightened_vmcs[4096] __attribute__((aligned(4096)));

void FuzzState(struct svm_test_data* svm) {
  struct vmcb* vmcb = svm->vmcb;
  struct vmcb_save_area* save = &vmcb->save;
  struct vmcb_control_area* ctrls = &vmcb->control;

  // fuzz control fields
  // ctrls->

  // fuzz guest state fields

  return;
}

void print_register() {
  wprintf(
      L"guest_regs.rbx= 0x%x guest_regs.rcx= 0x%x guest_regs.rdx= 0x%x "
      L"guest_regs.rbp= 0x%x\r\n"
      L"guest_regs.rsi= 0x%x guest_regs.rdi= 0x%x guest_regs.r8= 0x%x "
      L"guest_regs.r9= 0x%x\r\n"
      L"guest_regs.r10= 0x%x guest_regs.r11= 0x%x guest_regs.r12= 0x%x "
      L"guest_regs.r13= 0x%x\r\n"
      L"guest_regs.r14= 0x%x guest_regs.r15= 0x%x\r\n",
      guest_regs.rbx, guest_regs.rcx, guest_regs.rdx, guest_regs.rbp,
      guest_regs.rsi, guest_regs.rdi, guest_regs.r8, guest_regs.r9,
      guest_regs.r10, guest_regs.r11, guest_regs.r12, guest_regs.r13,
      guest_regs.r14, guest_regs.r15);
  return;
}

void print_vmexit_code(struct svm_test_data* svm) {
  struct vmcb* vmcb = svm->vmcb;
  struct vmcb_control_area* ctrls = &vmcb->control;
  wprintf(
      L"**********\r\n"
      L"exit_code = 0x%x\r\n"
      L"exit_info = 0x%x , 0x%x\r\n"
      L"exit_int_info = 0x%x, 0x%x\r\n"
      L"**********\r\n",
      (uint64_t)ctrls->exit_code_hi << 32 | ctrls->exit_code,
      ctrls->exit_info_1, ctrls->exit_info_2, ctrls->exit_int_info,
      ctrls->exit_int_info_err);
}

void invalidate_VMCB(struct svm_test_data* svm) {
  struct vmcb* vmcb = svm->vmcb;
  struct vmcb_save_area* save = &vmcb->save;
  struct vmcb_control_area* ctrls = &vmcb->control;

  for (int i = 0; i < INVALIDATE_COUNT; i++) {
    int index;
    index = get16b(index_count) % (0x400 + 0x298);
    index_count += 2;
    ((uint8_t*)(vmcb + index))[0] ^= 1 << input_buf[index_count++] % 8;
  }
}

_Noreturn void guest_entry(void) {
  uint64_t unused;
  uint64_t rax = 0x100;
  uint16_t instr_selector;

  loop_count += 1;
  if (loop_count == 1) {
    if (current_vp_assist) {
      __hyperv_hypercall(
          HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE | HV_HYPERCALL_FAST_BIT, 0x0,
          HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES | HV_FLUSH_ALL_PROCESSORS,
          &unused);
    } else {
      asm volatile("vmcall");
    }
  }

  asm volatile("mov %0, %%rax" ::"r"(rax));

  for (int i = 0; i < HARNESS_COUNT; i++) {
    int selector = input_buf[index_selector_count++] % (L2_TABLE_SIZE);
    exec_l2_table[selector].func();
  }

  if (current_vp_assist) {
    __hyperv_hypercall(
        HVCALL_FLUSH_VIRTUAL_ADDRESS_SPACE | HV_HYPERCALL_FAST_BIT, 0x0,
        HV_FLUSH_ALL_VIRTUAL_ADDRESS_SPACES | HV_FLUSH_ALL_PROCESSORS, &unused);
  } else {
    asm volatile("vmcall");
  }
  while (1)
    ;
}

void zero_division_handler() {
  wprintf(L"Zero Division Exception!\r\n");
  uint8_t* memory;
  memory = (uint8_t*)0xffffffff80000000;
  memory[0] = 0;
  while (1)
    ;
}

void setup_idt(uint8_t vector,
               void* handler,
               uint16_t selector,
               uint8_t flags) {
  struct desc_ptr idt;
  get_idt(&idt);
  wprintf(L"idt 0x%x, 0x%x\r\n", idt.address, idt.size);
  idt_entry_t* idt_entries = (idt_entry_t*)idt.address;

  uint64_t offset = (uint64_t)handler;
  idt_entries[0].offset_low = offset & 0xFFFF;
  idt_entries[0].offset_mid = (offset >> 16) & 0xFFFF;
  idt_entries[0].offset_high = (offset >> 32) & 0xFFFFFFFF;

  idt_entries[0].selector = selector;
  idt_entries[0].flags = flags;
}

void setup_gdt() {
  struct desc_ptr gdt;
  get_gdt(&gdt);
  wprintf(L"gdt 0x%x, 0x%x\r\n", gdt.address, gdt.size);
  // TODO
}

void check_VMCB(struct svm_test_data* svm) {
#ifdef STATE_VALIDATOR
  if (SvmEnterLoadCheckControls(svm) == 0) {
    wprintf(L"VMCB control OK\r\n");
  } else {
    wprintf(L"VMCB control NG\r\n");
  }
  if (SvmEnterLoadCheckGuestState(svm) == 0) {
    wprintf(L"VMCB guest state OK\r\n");
  } else {
    wprintf(L"VMCB guest state NG\r\n");
  }
#endif
}

void setup_hyperv(struct svm_test_data* svm) {
  struct hv_vmcb_enlightenments* hve;
  hve = &svm->vmcb->control.hv_enlightenments;
  uint32_t ecx, ebx, edx, eax;

  asm volatile("cpuid"
               : "=a"(eax), "=c"(ecx), "=b"(ebx), "=d"(edx)
               : "a"(0x40000080)
               :);
  if (ebx == 0x7263694D && ecx == 0x666F736F &&
      edx == 0x53562074) {  // Microsoft HV
    wprintf(L"Enable hyper-v\r\n");
    wrmsr(HV_X64_MSR_GUEST_OS_ID, HYPERV_LINUX_OS_ID);
    wrmsr(HV_X64_MSR_HYPERCALL, *pgs_gpa);
    uint64_t vp_addr = (uint64_t)vp_assist | 0x1;
    wrmsr(0x40000073, vp_addr);
    current_vp_assist = (void*)vp_assist;
    /* L2 TLB flush setup */
    hve->partition_assist_page = (uint64_t)partition_assist;
    hve->hv_enlightenments_control.nested_flush_hypercall = 1;
    hve->hv_vm_id = 1;
    hve->hv_vp_id = 1;
    current_vp_assist->nested_control.features.directhypercall = 1;
    hve->hv_enlightenments_control.msr_bitmap = 1;
  }
}
EFI_STATUS
EFIAPI
EfiMain(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE* _SystemTable) {
  struct svm_test_data svm;

  SystemTable = _SystemTable;
  wprintf(L"!Starting NecoFuzz ...\r\n");

  SetupIdentityPageTable();

  input_buf = (void*)(input_mem);
  for (int i = 0; i < 10; i++) {
    wprintf(L"input_buf[0x%x] = 0x%x\r\n", i, input_buf[i]);
  }
  wprintf(L"Initialize VMCB\r\n");

  svm.vmcb = (struct vmcb*)vmcb;
  svm.vmcb_gpa = (uint64_t)vmcb;
  svm.save_area = (struct vmcb_save_area*)save_area;

  svm.save_area_gpa = (uint64_t)save_area;
  svm.msr = (void*)msr;
  svm.msr_gpa = (uint64_t)msr;

  generic_svm_setup(&svm, guest_entry, guest_stack);

  setup_hyperv(&svm);

  __builtin_memcpy(vmcb2, vmcb, sizeof(struct vmcb));

  svm.vmcb->control.intercept = 1 << 31 | 0xFFFFFFF;
  svm.vmcb->control.int_ctl |= 1 << 31;
  setup_idt(0, zero_division_handler, 0x38, 0x8E);

  initialize_apic();
  svm.vmcb->control.avic_vapic_bar = *apic_base;

  check_VMCB(&svm);

  int rc = run_guest(svm.vmcb, svm.vmcb_gpa);
  print_vmexit_code(&svm);

  wprintf(L"#%d guest_regs.rax = %x\r\n", loop_count, guest_regs.rax);
  if (rc == 1) {
    wprintf(L"VMRUN ERROR\r\n");
    __builtin_longjmp(env, 1);
  }

  __builtin_memcpy(vmcb, input_buf, 0x400);
  __builtin_memcpy(vmcb + 0x4a0, input_buf + 0x4a0,
                   0x1f8);  // skip segment register
  index_count = 0x6a0;
  while (1) {
    if (index_count >= 0x700) {
      __builtin_longjmp(env, 1);
    }
    if (loop_count > 8) {
      __builtin_longjmp(env, 1);
    }

    svm.vmcb->control.intercept |= 1ULL << INTERCEPT_VMMCALL;
    svm.vmcb->control.msrpm_base_pa = svm.msr_gpa;
    svm.vmcb->control.tlb_ctl = 0x0;
    svm.vmcb->control.event_inj &= ~0x04FFFF000;
    svm.vmcb->control.event_inj &= ~(1 << 31);
    svm.vmcb->save.efer |= 1 << 10 | 1 << 8;
    svm.vmcb->save.g_pat = rdmsr(MSR_IA32_CR_PAT);
    svm.vmcb->control.clean |= HV_VMCB_NESTED_ENLIGHTENMENTS;

    asm volatile("mov %%cr3, %0" : "=r"(svm.vmcb->save.cr3) : : "memory");
    svm.vmcb->control.nested_cr3 = (uint64_t)pml4_table;

    check_VMCB(&svm);
    invalidate_VMCB(&svm);
    #ifdef XEN
    svm.vmcb->save.cr4 &= 0x750fff;
    #endif

    for (int i = 0; i < HARNESS_COUNT; i++) {
      int selector = input_buf[index_selector_count++] % (L1_TABLE_SIZE);
      wprintf(L"Harness  %s\r\n", exec_l1_table[selector].name);
      exec_l1_table[selector].func();
    }

    svm.vmcb->save.rip = (u64)guest_entry;
    svm.vmcb->save.rsp = (u64)guest_stack;

    rc = run_guest(svm.vmcb, svm.vmcb_gpa);
    if (rc == 1) {
      wprintf(L"VMRUN ERROR\r\n");
    }
    loop_count += 1;
    print_vmexit_code(&svm);
    wprintf(L"#%d guest_regs.rax = %x\r\n", loop_count, guest_regs.rax);
  }

  return EFI_SUCCESS;
}
