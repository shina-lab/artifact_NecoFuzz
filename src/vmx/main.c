/******************************************************************************

  The MIT License (MIT)

  Copyright (c) 2017 Takahiro Shinagawa (The University of Tokyo)

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.

******************************************************************************/

/** ***************************************************************************
 * @file main.c
 * @brief The VMX benchmark (VMXbench)
 * @copyright Copyright (c) 2017 Takahiro Shinagawa (The University of Tokyo)
 * @license The MIT License (http://opensource.org/licenses/MIT)
 *************************************************************************** */

// #include <stdbool.h>
#include <stdint.h>
#include "../common/cpu.h"
#include "../common/input.h"
#include "../common/msr.h"
#include "../common/uefi.h"
#include "fuzz.h"
#include "vmx.h"
int l2_harnes_num = 0;

#ifndef HARNESS_COUNT
#define HARNESS_COUNT 1
#endif

#ifndef L2_HARNESS_COUNT
// #define L2_HARNESS_COUNT 20
#define L2_HARNESS_COUNT 20
#endif

#ifndef INVALIDATE_COUNT
#define INVALIDATE_COUNT 1
#endif

EFI_SYSTEM_TABLE* SystemTable;
static int env[28];

uint16_t vmcs_index[] = {
    0x0000, 0x0002, 0x0004, 0x0800, 0x0802, 0x0804, 0x0806, 0x0808, 0x080a,
    0x080c, 0x080e, 0x0810, 0x0812, 0x0c00, 0x0c02, 0x0c04, 0x0c06, 0x0c08,
    0x0c0a, 0x0c0c, 0x2000, 0x2002, 0x2004, 0x2006, 0x2008, 0x200a, 0x200c,
    0x200e, 0x2010, 0x2012, 0x2014, 0x2016, 0x2018, 0x201a, 0x201c, 0x201e,
    0x2020, 0x2022, 0x2024, 0x2026, 0x2028, 0x202a, 0x202c, 0x202e, 0x2030,
    0x2032, 0x2400, 0x2800, 0x2802, 0x2804, 0x2806, 0x2808, 0x280a, 0x280c,
    0x280e, 0x2810, 0x2812, 0x2814, 0x2818, 0x2c00, 0x2c02, 0x2c04, 0x2c06,
    0x4000, 0x4002, 0x4004, 0x4006, 0x4008, 0x400a, 0x400c, 0x400e, 0x4010,
    0x4012, 0x4014, 0x4016, 0x4018, 0x401a, 0x401c, 0x401e, 0x4020, 0x4022,
    0x4400, 0x4402, 0x4404, 0x4406, 0x4408, 0x440a, 0x440c, 0x440e, 0x4800,
    0x4802, 0x4804, 0x4806, 0x4808, 0x480a, 0x480c, 0x480e, 0x4810, 0x4812,
    0x4814, 0x4816, 0x4818, 0x481a, 0x481c, 0x481e, 0x4820, 0x4822, 0x4824,
    0x4826, 0x4828, 0x482a, 0x482e, 0x4c00, 0x6000, 0x6002, 0x6004, 0x6006,
    0x6008, 0x600a, 0x600c, 0x600e, 0x6400, 0x6404, 0x6402, 0x6408, 0x6406,
    0x640a, 0x6800, 0x6802, 0x6804, 0x6806, 0x6808, 0x680a, 0x680c, 0x680e,
    0x6810, 0x6812, 0x6814, 0x6816, 0x6818, 0x681a, 0x681c, 0x681e, 0x6820,
    0x6822, 0x6824, 0x6826, 0x6828, 0x682a, 0x682c, 0x6c00, 0x6c02, 0x6c04,
    0x6c06, 0x6c08, 0x6c0a, 0x6c0c, 0x6c0e, 0x6c10, 0x6c12, 0x6c14, 0x6c16,
    0x6c18, 0x6c1a, 0x6c1c};

const int vmcs_num = sizeof(vmcs_index) / sizeof(uint16_t);

uint8_t* input_buf;
struct hv_vp_assist_page* current_vp_assist;
struct hv_enlightened_vmcs* current_evmcs;

uint64_t loop_count = 0;
uint64_t index_count = 0x500;
uint64_t index_selector_count = 0x700;

_Noreturn void guest_entry(void);

#ifdef DEBUG
int debug_skip = -1;
uint64_t skip_buf[200] = {0};
#endif

void print_exitreason(uint64_t reason) {
  uint64_t q = vmread(0x6400);
  uint64_t rip = vmread(0x681E);
  uint64_t rsp = vmread(0x681C);
  wprintf(L"Unexpected VM exit: reason=0x%x, qualification=0x%x\r\n", reason,
          q);
  wprintf(L"rip: %08x, rsp: %08x\r\n", rip, rsp);
  for (int i = 0; i < 16; i++, rip++)
    wprintf(L"%02x ", *(uint8_t*)rip);
  wprintf(L"\r\n");
  for (int i = 0; i < 16; i++, rsp += 8)
    wprintf(L"%016x: %016x\r\n", rsp, *(uint64_t*)rsp);
  wprintf(L"\r\n");
}

void invalidate_vmcs(uint32_t field, uint32_t bits) {
  uint64_t value = vmread(field);
  value = value ^ (1 << bits);
  vmwrite(field, value);
}

void check_vmcs(void) {
  enum VMX_error_code vmentry_check_failed = VMenterLoadCheckVmControls();
  if (!vmentry_check_failed) {
    // wprintf(L"VMX CONTROLS OK!\r\n");
  } else {
    wprintf(L"VMX CONTROLS ERROR %0d\r\n", vmentry_check_failed);
  }
  vmentry_check_failed = VMenterLoadCheckHostState();
  if (!vmentry_check_failed) {
    // wprintf(L"HOST STATE OK!\r\n");
  } else {
    wprintf(L"HOST STATE ERROR %0d\r\n", vmentry_check_failed);
  }
  uint64_t qualification;
  uint32_t is_error = VMenterLoadCheckGuestState(&qualification);
  if (!is_error) {
    // wprintf(L"GUEST STATE OK!\r\n");
  } else {
    wprintf(L"GUEST STATE ERROR %0d\r\n", qualification);
    wprintf(L"GUEST STATE ERROR %0d\r\n", is_error);
  }
}

void dump_vmcs(void) {
  for (int i = 0; i < vmcs_num; i++) {
    uint64_t v = vmread(vmcs_index[i]);
    wprintf(L"vmwrite(0x%x, 0x%x);\r\n", vmcs_index[i], v);
  }
}

void fuzz_vmcs(int skip) {
  uint64_t wvalue;
  uint16_t windex;
  for (int i = 0; i < vmcs_num; i += 1) {
    if (i == skip) {
      continue;
    }
    windex = vmcs_index[i];
    vmread(windex);
    if (
        /* VMCS 64-bit control fields 0x20xx */
        0 ||
        // Address fields
        windex == 0x2000 || windex == 0x2002 || windex == 0x2004 ||
        windex == 0x2006 || windex == 0x2008 || windex == 0x200a ||
        windex == 0x200c || windex == 0x200e || windex == 0x2012 ||
        windex == 0x2014 || windex == 0x2016 || windex == 0x2024 ||
        windex == 0x201a || windex == 0x2026 || windex == 0x2028 ||
        windex == 0x202a || windex == 0x2800 ||
        windex == 0x2802
        // || windex == 0x2804 // PAT
        // || windex == 0x2806 // EFER
        || windex == 0x2808  // IA32_PERF_GLOBAL_CTRL
        || (windex >= 0x280a && windex < 0x2C00)
        /* VMCS natural width guest state fields 0x68xx */
        // || (windex & 0xff00) == 0x6800
        || windex == 0x6802  // GUEST_CR3
        // || windex == 0x6806 // VMCS_GUEST_ES_BASEa
        // || windex == 0x6808 // VMCS_GUEST_CS_BASEa
        // || windex == 0x680a // VMCS_GUEST_SS_BASEa
        // || windex == 0x680c // VMCS_GUEST_DS_BASEa
        // || windex == 0x680e // VMCS_GUEST_FS_BASEa
        // || windex == 0x6810 // VMCS_GUEST_GS_BASEa
        // || windex == 0x6812 // VMCS_GUEST_LDTR_BASEa
        || windex == 0x6814  // VMCS_GUEST_TR_BASE
        // || windex == 0x6816 // VMCS_GUEST_GDTR_BASEa
        || windex == 0x6818  // VMCS_GUEST_IDTR_BASE
        // || windex == 0x681a  // VMCS_GUEST_DR7
        || windex == 0x681c  // VMCS_GUEST_RSP
        || windex == 0x681e  // VMCS_GUEST_RIP
        // || windex == 0x6820 // VMCS_GUEST_RFLAGSa
        || windex == 0x6822  // VMCS_GUEST_PENDING_DBG_EXCEPTIONS 0x800000021
        || windex == 0x6824  // VMCS_GUEST_IA32_SYSENTER_ESP_MSR
        || windex == 0x6826  // VMCS_GUEST_IA32_SYSENTER_EIP_MSR
        || windex == 0x6828  // VMCS_GUEST_IA32_S_CET
        || windex == 0x682a  // VMCS_GUEST_SSP
        || windex == 0x682c  // VMCS_GUEST_INTERRUPT_SSP_TABLE_ADDR

        /* VMCS host state fields */
        || (windex & 0xfff0) == 0xc00 /* VMCS 16-bit host-state fields 0xc0x */
        ||
        (windex & 0xff00) == 0x2c00 /* VMCS 64-bit host state fields 0x2cxx */
        ||
        (windex & 0xff00) == 0x4c00 /* VMCS 64-bit host state fields 0x2cxx */
        || (windex & 0xff00) ==
               0x6c00 /* VMCS natural width host state fields 0x6cxx*/

        // LIMIT
        || windex == 0x480c  // ldtr limit
        || windex == 0x480e  // tr limit

        // || windex == 0x4814 // ES_ACCESS_RIGHTS
        || windex == 0x4816  // CS_ACCESS_RIGHTS
        || windex == 0x4818  // SS_ACCESS_RIGHTS
                             // || windex == 0x481a // DS_ACCESS_RIGHTS
                             // || windex == 0x481c // FS_ACCESS_RIGHTS
                             // || windex == 0x481e // GS_ACCESS_RIGHTS

        // RO fields
        //  ||(windex & 0xff00) == 0x2400
        //  ||(windex & 0xff00) == 0x4400
        //  ||(windex & 0xff00) == 0x6400
        //  || windex ==0x400a
    ) {
      continue;
    }
    // */
    if (windex < 0x2000) {  // 16b
      wvalue = get_vmcs_value64(i) & 0xFFFF;
    } else if (windex < 0x4000) {  // 64b
      wvalue = get_vmcs_value64(i);
    } else if (windex < 0x6000) {  // 32b
      wvalue = get_vmcs_value64(i) & 0xFFFFFFFF;
    } else {  // 64b
      wvalue = get_vmcs_value64(i);
    }

    if (windex == 0x4002) {
      wvalue &= ~(1 << 22);  // sometimes hang
      wvalue &= ~(1 << 27);  // sometimes hang
    }

    if (windex == 0x4012) {
      wvalue |= 1 << 9;  //  IA-32e mode guest
    }
    if (windex == 0x400e || windex == 0x4010 || windex == 0x4014) {
      wvalue &= 0x1ff;  // It is recommended that this count not exceed 512.
    }

    if (windex == 0x4822) {  // SS access rights
      wvalue &= ~0xf;
      wvalue |= 0xb;
      // wvalue &= ~(1<<4);
      // wvalue &= ~(1<<16);
    }
    if (windex == 0x4826) {
      wvalue = wvalue % (BX_ACTIVITY_STATE_MWAIT_IF + 1);
      // wvalue = (wvalue == 1 || wvalue == 3 ? 0 : wvalue);
    }
    if (windex == 0x482e) {
      wvalue = wvalue % 0xffff;
    }
    if (windex == 0x6820) {
      wvalue &= ~0x100;
    }

    vmwrite(windex, wvalue);
    // wprintf(L"%d vmwrite(0x%x, 0x%x);\r\n",i, windex, wvalue);
  }
}

static const uint32_t reinit_reasons[] = {0,  1,  2,  7,  8, 29,
                                          37, 43, 47, 48, 52};

static const uint32_t resume_reasons[] = {
    10, 11, 12, 13, 14, 15, 16, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
    30, 31, 32, 36, 39, 40, 46, 50, 51, 53, 54, 55, 57, 58, 59, 61, 62};

static inline bool in_table(int reason, const uint32_t* table, size_t count) {
  for (size_t i = 0; i < count; i++) {
    if (reason == table[i])
      return true;
  }
  return false;
}

void host_entry(uint64_t arg) {
  uint64_t reason = vmread(0x4402);
  uint64_t rip = vmread(0x681E);
  uint64_t len = vmread(0x440C);
  uint16_t windex;
  uint64_t wvalue;
  uint32_t bits;

  wprintf(L"VMEXIT reason = %d(0x%x), %s\r\n", reason, reason,
          VMX_vmexit_reason_name[reason]);

  if (in_table(reason, reinit_reasons,
               sizeof(reinit_reasons) / sizeof(uint32_t))) {
    vmwrite(0x681E, (uint64_t)guest_entry);
    vmwrite(0x440c, 0);
    goto fuzz;
  }

  if (in_table(reason, resume_reasons,
               sizeof(resume_reasons) / sizeof(uint32_t))) {
    vmwrite(0x681E, rip + len);
    asm volatile("vmresume\n\t");
  }

  if (reason != 18) {
    wprintf(L"VM exit reason %d\n", reason);

    if (reason == 65) {
      __builtin_longjmp(env, 1);
    }

    vmwrite(0x681E, rip + len);
    asm volatile("vmresume\n\t");
  }

#ifdef DEBUG
  if (debug_skip >= vmcs_num) {
    for (int i = 0; i < vmcs_num; i++) {
      if (skip_buf[i] != 0)
        wprintf(L"i == %d || ", i);
    }
    wprintf(L"\r\n");
    __builtin_longjmp(env, 1);
  }
  if (reason == 18) {
    skip_buf[debug_skip] = 0;
  }
  if (reason & 0x80000000) {
    skip_buf[debug_skip] = 1;
    wprintf(L"Error Number is %d\r\n", vmread(0x4400));
  }
#endif
fuzz:
#ifdef DEBUG
  debug_skip += 1;

  wprintf(L"debug_skip %d, 0x%x\r\n", debug_skip, vmcs_index[debug_skip]);
  for (int i = 0; i < vmcs_num; i++) {
    vmwrite(vmcs_index[i], restore_vmcs[i]);
  }
  vmwrite(0x482e, 0xffffffff);

  fuzz_vmcs(debug_skip);

  vmwrite(0x4800, get_seg_limit(vmread(0x800)));
  vmwrite(0x4802, get_seg_limit(vmread(0x802)));
  vmwrite(0x4804, get_seg_limit(vmread(0x804)));
  vmwrite(0x4806, get_seg_limit(vmread(0x806)));
  vmwrite(0x4808, get_seg_limit(vmread(0x808)));
  vmwrite(0x480a, get_seg_limit(vmread(0x80a)));

  check_vmcs();
  vmwrite(0x681E, (uint64_t)guest_entry);
  vmwrite(0x440c, 0);
  asm volatile("vmresume\n\t");
  wprintf(L"VMRESUME failed: \r\n");
  skip_buf[debug_skip] = -1;
  goto fuzz;
#endif

  loop_count++;
  wprintf(L"l2 harness %d\r\n", l2_harnes_num);

  if (loop_count > 10) {
    __builtin_longjmp(env, 1);
  }
  wprintf(L"# %d\r\n", loop_count);

  if (loop_count <= 1) {
    vmwrite(0x2, loop_count);
    wprintf(L"Fuzzing start\r\n");

    fuzz_vmcs(-1);
    vmwrite(0x4800, get_seg_limit(vmread(0x800)));
    vmwrite(0x4802, get_seg_limit(vmread(0x802)));
    vmwrite(0x4804, get_seg_limit(vmread(0x804)));
    vmwrite(0x4806, get_seg_limit(vmread(0x806)));
    vmwrite(0x4808, get_seg_limit(vmread(0x808)));
    vmwrite(0x480a, get_seg_limit(vmread(0x80a)));

#ifdef STATE_VALIDATOR
    check_vmcs();
#endif

    for (int i = 0; i < vmcs_num; i++) {
      restore_vmcs[i] = vmread(vmcs_index[i]);
    }

  } else {
    for (int i = 0; i < vmcs_num; i++) {
      vmwrite(vmcs_index[i], restore_vmcs[i]);
    }
  }

  for (int i = 0; i < INVALIDATE_COUNT; i++) {
    windex = vmcs_index[get16b(index_count) % vmcs_num];  // at 0x500 byte
    index_count += 2;
    bits = get8b(index_count++);

    if (windex < 0x2000) {
      bits %= 16;
    } else if (windex < 0x4000) {
      bits %= 64;
    } else if (windex < 0x6000) {
      bits %= 32;
    } else {
      bits %= 64;
    }
    invalidate_vmcs(windex, bits);
    wprintf(L"Bitflip #%d bit of 0x%x\r\n", bits, windex);
    wprintf(L"vmread(0x482e)  0x%x\r\n", vmread(0x482e));

    // if ((windex & 0x0f00) != 0xc00)
    // {
    //     if (windex == 0x400e || windex == 0x681c || windex == 0x681e ||
    //     windex == 0x6816 || windex == 0x681E || windex == 0x2800 || windex
    //     == 0x2000 || windex == 0x2002 || windex == 0x2004 || windex ==
    //     0x2006 || windex == 0x2008 || windex == 0x200a || windex == 0x200c
    //     || windex == 0x200e || windex == 0x2012 || windex == 0x2014 ||
    //     windex == 0x2016 || windex == 0x2024 || windex == 0x2026 || windex
    //     == 0x2028 || windex == 0x202a)
    //     {
    //         // vmwrite(windex, 0x3fffffffe000);
    //         wvalue = get64b(index_count);
    //         index_count += 8;
    //         vmwrite(windex, wvalue & ~(0xFFF));
    //     }
    // }
  }

  if (current_evmcs) {
    /* HOST_RIP */
    current_evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1;
    /* HOST_RSP */
    current_evmcs->hv_clean_fields &=
        ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER;
  } else {
    vmwrite(0x681E, (uint64_t)guest_entry);
    vmwrite(0x440c, 0);
  }

  for (int i = 0; i < HARNESS_COUNT; i++) {
    int selector = get16b(index_selector_count) % L1_TABLE_SIZE;
    index_selector_count += 2;
    wprintf(L"Harness  %s\r\n", fuzz_l1_table[selector].name);
    fuzz_l1_table[selector].func();
  }

  asm volatile("vmresume\n\t");
  wprintf(L"VMRESUME failed: \r\n");
  goto fuzz;
}

void __host_entry(void);
void _host_entry(void) {
  asm volatile(
      "__host_entry:\n\t"
      "call host_entry\n\t"
      "vmresume\n\t"
      "loop: jmp loop\n\t");
}

_Noreturn void guest_entry(void) {
  while (1) {
    l2_harnes_num = 0;
    if (loop_count == 0) {
      vmcall(1);
    }

    for (int i = 0; i < L2_HARNESS_COUNT; i++) {
      l2_harnes_num++;
      int selector = get16b(index_selector_count) % L2_TABLE_SIZE;
      index_selector_count += 2;
      fuzz_l2_table[selector].func();
    }

    vmcall(1);
  }
}

void setup_hyperv() {
  uint32_t eax, ecx, ebx, edx;

  asm volatile("cpuid"
               : "=a"(eax), "=c"(ecx), "=b"(ebx), "=d"(edx)
               : "a"(0x40000080)
               :);
  if (ebx == 0x7263694D && ecx == 0x666F736F &&
      edx == 0x53562074) {  // Microsoft SV?
    wprintf(L"Enable evmcs\r\n");
    uint64_t vp_addr = (uint64_t)vp_assist | 0x1;
    wrmsr(0x40000073, vp_addr);
    current_vp_assist = (void*)vp_assist;
    current_vp_assist->current_nested_vmcs = (uint64_t)vmcs;
    current_vp_assist->enlighten_vmentry = 1;
    current_evmcs = (struct hv_enlightened_vmcs*)vmcs;
  }
}

EFI_STATUS
EFIAPI
EfiMain(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE* _SystemTable) {
  uint32_t revision_id;
  uint32_t error;
  struct registers regs;

  SystemTable = _SystemTable;
  wprintf(L"!Starting NecoFuzz ...\r\n");
  wprintf(L"count %d\r\n", HARNESS_COUNT);
  wprintf(L"vmcs_num %d\r\n", vmcs_num);

  input_buf = input_mem;

#ifdef DEBUG
  for (int i = 0; i < 10; i++) {
    wprintf(L"input_buf[0x%x] = 0x%x\r\n", i, input_buf[i]);
  }
#endif

  initialize_apic();
  setup_hyperv();

  SetupIdentityPageTable();
  error = InitializeVMCS((uint64_t)__host_entry, (uint64_t)guest_entry);
  if (error != 0) {
    goto exit;
  }

  wprintf(L"Check VMCS\r\n");
  check_vmcs();
  vmwrite(0x4824, 0);

#ifdef DEBUG
  for (int i = 0; i < vmcs_num; i++) {
    restore_vmcs[i] = vmread(vmcs_index[i]);
    if (current_evmcs)
      evmcs_vmwrite(vmcs_index[i], restore_vmcs[i]);
  }
#endif

  if (current_evmcs) {
    current_evmcs->hv_clean_fields = 0;
    // current_evmcs->revision_id = 1;
  }
  if (!__builtin_setjmp(env)) {
    wprintf(L"Launch a VM\r\n");
    asm volatile("cli");
    asm volatile("vmlaunch" ::: "memory");
    goto error_vmx;
  } else
    goto disable_vmx;

error_vmx:
  wprintf(L"VMLAUNCH failed: ");
  wprintf(L"Error Number is %d\r\n", vmread(0x4400));
  goto disable_vmx;

disable_vmx:
  asm volatile("vmxoff");
  asm volatile("mov %%cr4, %0" : "=r"(regs.cr4));
  regs.cr4 &= ~0x2000;  // CR4.VME[bit 13] = 0
  asm volatile("mov %0, %%cr4" ::"r"(regs.cr4));
  goto exit;

exit:
  putws(L"Press any key to go back to the UEFI menu\r\n");
  getwchar();
  return EFI_SUCCESS;
}
