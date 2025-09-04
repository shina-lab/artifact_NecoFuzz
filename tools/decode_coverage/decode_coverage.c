#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <libgen.h>
#include <fcntl.h>
#include <unistd.h>
#include <gelf.h>
#include <libelf.h>
#include <sys/utsname.h>

#define INTEL 1
#define AMD 2
uint64_t MAX_KVM_ARCH;
uint64_t MAX_KVM;

char vendor_name[8];

char vendor_id;
uint8_t *kvm_arch_coverage, *kvm_coverage;
uint64_t prev_kvm_arch_cnt, prev_kvm_cnt, kvm_arch_cnt, kvm_cnt;
int coverage_enable;

static uint64_t check_text_size(char* filepath) {
  Elf* elf;
  Elf_Scn* scn = NULL;
  GElf_Shdr shdr;
  int fd;
  size_t shstrndx;  // Section header string table index

  // Open the file
  fd = open(filepath, O_RDONLY);
  if (fd < 0) {
    perror("open");
    return 1;
  }

  if (elf_version(EV_CURRENT) == EV_NONE) {
    // library out of date
    exit(1);
  }

  elf = elf_begin(fd, ELF_C_READ, NULL);

  // Retrieve the section header string table index
  if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
    perror("elf_getshdrstrndx");
    exit(1);
  }

  while ((scn = elf_nextscn(elf, scn)) != NULL) {
    if (gelf_getshdr(scn, &shdr) != &shdr) {
      // error
      exit(1);
    }

    if (shdr.sh_type == SHT_PROGBITS) {
      char* name;
      name = elf_strptr(elf, shstrndx, shdr.sh_name);  // Use shstrndx
      if (name && strcmp(name, ".text") == 0) {
        break;
      }
    }
  }

  elf_end(elf);
  close(fd);

  return (uint64_t)shdr.sh_size;
}

void check_cpu_vendor(void) {
  FILE* cpuinfo = fopen("/proc/cpuinfo", "rb");
  char buffer[255];
  char vendor[16];
  struct utsname utbuffer;
  char filepath[128];

  if (cpuinfo == NULL) {
    perror("fopen");
    return;
  }

  if (uname(&utbuffer) != 0) {
    perror("uname");
    return;
  }

  snprintf(filepath, 128, "/usr/lib/modules/%s/kernel/arch/x86/kvm/kvm.ko",
           utbuffer.release);

  MAX_KVM = check_text_size(filepath);

  while (fgets(buffer, 255, cpuinfo)) {
    if (strncmp(buffer, "vendor_id", 9) == 0) {
      sscanf(buffer, "vendor_id : %s", vendor);

      if (strcmp(vendor, "GenuineIntel") == 0) {
        snprintf(filepath, 128,
                 "/usr/lib/modules/%s/kernel/arch/x86/kvm/kvm-intel.ko",
                 utbuffer.release);
        MAX_KVM_ARCH = check_text_size(filepath);
        strncpy(vendor_name, "intel\0", sizeof(vendor_name));
        vendor_id = INTEL;
      } else if (strcmp(vendor, "AuthenticAMD") == 0) {
        snprintf(filepath, 128,
                 "/usr/lib/modules/%s/kernel/arch/x86/kvm/kvm-amd.ko",
                 utbuffer.release);
        MAX_KVM_ARCH = check_text_size(filepath);
        strncpy(vendor_name, "amd\0", sizeof(vendor_name));
        vendor_id = AMD;
      } else {
        printf("This is a CPU from another vendor: %s\n", vendor);
        MAX_KVM_ARCH = 0;
      }

      break;
    }
  }

  fclose(cpuinfo);
}

int main (int argc, char * argv[]){
    check_cpu_vendor();

	uint8_t *cov = malloc(MAX_KVM);
    char* filePath = strdup(argv[1]);
    char* dirPath = strdup(argv[1]); 

    char* base = basename(filePath);
    char* dir = dirname(dirPath);

    char output[256];  // Buffer for the output file name

    snprintf(output, sizeof(output), "%s/cov_%s", dir, base);

    FILE * input_fp = fopen(argv[1],"rb");
	if (input_fp == NULL) {
		fprintf(stderr, "fopen failed\n");
		return 1;
	}

    FILE * output_fp = fopen(output,"w");
	if (output_fp == NULL) {
		fprintf(stderr, "fopen failed\n");
		return 1;
	}
	
	int n = fread(cov, sizeof(uint8_t), MAX_KVM, input_fp);
	for(int i = 0; i < n;i++){
		if (cov[i] == 1)
		fprintf(output_fp, "%x\n", i);
	}
	
    fclose(input_fp);
	fclose(output_fp);
	printf("%s\n", output);
	return 0;
}