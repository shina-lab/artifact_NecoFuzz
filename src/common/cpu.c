#include "cpu.h"

void save_registers(struct registers* regs) {
  asm volatile("mov %%cr0, %0" : "=r"(regs->cr0));
  asm volatile("mov %%cr3, %0" : "=r"(regs->cr3));
  asm volatile("mov %%cr4, %0" : "=r"(regs->cr4));
  regs->ia32_efer = rdmsr(0xC0000080);
  asm volatile("pushf; pop %%rax" : "=a"(regs->rflags));
  asm volatile("mov %%cs, %0" : "=m"(regs->cs));
}

void print_registers(struct registers* regs) {
  wprintf(L"CR0: %016x, CR3: %016x, CR4: %016x\r\n", regs->cr0, regs->cr3,
          regs->cr4);
  wprintf(L"RFLAGS: %016x\r\n", regs->rflags);
  wprintf(L"CS: %04x\r\n", regs->cs);
  wprintf(L"IA32_EFER: %016x\r\n", regs->ia32_efer);
  wprintf(L"IA32_FEATURE_CONTROL: %016x\r\n", rdmsr(0x3a));
}

uint32_t get_seg_limit(uint32_t selector) {
  uint32_t limit;
  asm volatile("lsl %1, %0" : "=r"(limit) : "r"(selector));
  return limit;
}
int32_t get_seg_access_rights(uint32_t selector) {
  uint32_t access_rights;
  asm volatile("lar %1, %0" : "=r"(access_rights) : "r"(selector));
  return access_rights >> 8;
}
uint64_t get_seg_base(uint32_t selector) {
  return 0;
}

uint64_t* apic_base;

uint64_t get_apic_base() {
  uint32_t edx = 0;
  uint32_t eax = 0;
  asm volatile("rdmsr" : "=a"(eax), "=d"(edx) : "c"(MSR_IA32_APICBASE));
  return ((uint64_t)edx << 32) | eax;
}

void initialize_apic() {
  uint64_t apic_addr = get_apic_base();
  apic_base = (uint64_t*)(apic_addr & 0xFFFFFFFFFFFFF000);
  apic_base[APIC_SVR / 4] = 0xFF | APIC_ENABLE;
  apic_base[APIC_TPR / 4] = 0;
}

void* memset(void* dest, int val, int len) {
  unsigned char* ptr = dest;
  while (len-- > 0)
    *ptr++ = val;
  return dest;
}

const uint64_t kPageSize4K = 4096;
const uint64_t kPageSize2M = 512 * kPageSize4K;
const uint64_t kPageSize1G = 512 * kPageSize2M;
uint64_t pml4_table[512] __attribute__((aligned(4096)));
uint64_t pdp_table[512] __attribute__((aligned(4096)));
uint64_t page_directory[512][512] __attribute__((aligned(4096)));
uint64_t pml4_table_2[512] __attribute__((aligned(4096)));
uint64_t* SetupIdentityPageTable() {
  pml4_table[0] = (uint64_t)&pdp_table[0] | 0x407;
  pml4_table_2[0] = (uint64_t)&pdp_table[0] | 0x407;
  for (int i_pdpt = 0; i_pdpt < 512; ++i_pdpt) {
    pdp_table[i_pdpt] = (uint64_t)&page_directory[i_pdpt] | 0x407;
    for (int i_pd = 0; i_pd < 512; ++i_pd) {
      page_directory[i_pdpt][i_pd] =
          (i_pdpt * kPageSize1G + i_pd * kPageSize2M) | 0x4f7;
    }
  }
  return &pml4_table[0];
  //   SetCR3(reinterpret_cast<uint64_t>(&pml4_table[0]));
}