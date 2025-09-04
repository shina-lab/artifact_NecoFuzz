#include "fuzz.h"
#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include "args.h"
#include "kvm_flags.h"

uint64_t MAX_KVM_ARCH;
uint64_t MAX_KVM;

#define SLEEP_TIME 0.1  // 0.1s
#define TIMEOUT_S 15    // 15s
const int TIMEOUT = TIMEOUT_S / SLEEP_TIME;

yaml_config_t* yaml_config;
extern uint8_t* coverage_bitmap;
char vendor_name[8];

char vendor_id;
uint8_t *kvm_arch_coverage, *kvm_coverage, *xen_coverage;
uint64_t prev_kvm_arch_cnt, prev_kvm_cnt, kvm_arch_cnt, kvm_cnt, prev_xen_cnt,
    xen_cnt;
int coverage_enable;
char xencov_name[256];
char gcov_name[256];
char cov_file[] = "/tmp/tmp.gcov";
char saved_input_file[256] = {0};
int new_coverage_found;

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

int check_cpu_vendor(void) {
  FILE* cpuinfo;
  char buffer[255];
  char vendor[16];
  struct utsname utbuffer;
  char filepath[128];

  cpuinfo = fopen("/proc/cpuinfo", "rb");
  if (cpuinfo == NULL) {
    fprintf(stderr, "Failed to fopen %s\n", "/proc/cpuinfo");
    return 1;
  }

  if (uname(&utbuffer) != 0) {
    fprintf(stderr, "Failed to uname\n");
    return 1;
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
        return 1;
      }

      break;
    }
  }
  fclose(cpuinfo);
  return 0;
}

static int create_directory(const char* path) {
  struct stat st;
  if (stat(path, &st) != 0) {
    if (mkdir(path, S_IRWXU | S_IRWXG | S_IRWXO) == 0) {
    } else {
      fprintf(stderr, "Failed to mkdir %s\n", path);
      return 1;
    }
  }

  return 0;
}

int save_input() {
  struct timeval tv;
  struct tm* tm;
  char d_name[192] = {0};
  struct stat st;
  FILE* fp;

  gettimeofday(&tv, NULL);
  tm = localtime(&tv.tv_sec);

  sprintf(d_name, "%s/%02d_%02d_%02d", yaml_config->fuzz_inputs, tm->tm_mon + 1,
          tm->tm_mday, tm->tm_hour);
  if (create_directory(d_name) != 0)
    return 1;

  sprintf(saved_input_file, "%s/input_%02d_%02d_%02d_%02d_%02d", d_name,
          tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
  fp = fopen(saved_input_file, "w");
  if (fp == NULL) {
    fprintf(stderr, "Failed to fopen %s\n", saved_input_file);
    return 1;
  }
  fwrite(input_buf, sizeof(uint8_t), INPUT_SIZE, fp);
  fclose(fp);
  return 0;
}

void delete_input() {
  if (remove(saved_input_file) != 0) {
    fprintf(stderr, "Failed to delete %s\n", saved_input_file);
  }
}
int create_input() {
  FILE* f;
  char* input_file = config->afl_input_name;
  char* srcdir = config->srcdir_name;
  char* header_file = malloc(strlen(srcdir) + strlen(INPUT_HEADER));
  if (!header_file) {
    fprintf(stderr, "Failed to malloc");
    return 1;
  }
  strcpy(header_file, srcdir);
  strcat(header_file, INPUT_HEADER);

  // Write header file
  f = fopen(header_file, "w");
  if (!f) {
    fprintf(stderr, "Failed to fopen %s", header_file);
    return 1;
  }

  fprintf(f, "#pragma once\n");
  fprintf(f, "#include <stdint.h>\n\n");
  fprintf(f, "#define BINARY_DATA_SIZE %d\n\n", INPUT_SIZE);
  fprintf(f, "extern uint8_t input_mem[BINARY_DATA_SIZE];\n\n");

  fclose(f);
  printf("create %s\n", header_file);
  // Write source file
  char* source_file = malloc(strlen(srcdir) + strlen(INPUT_SOURCE));
  if (!source_file) {
    fprintf(stderr, "Failed to malloc");
    return 1;
  }
  strcpy(source_file, srcdir);
  strcat(source_file, INPUT_SOURCE);

  f = fopen(source_file, "w");
  if (!f) {
    fprintf(stderr, "Failed to fopen %s", source_file);
    return 1;
  }

  fprintf(f, "#include \"input.h\"\n\n");
  fprintf(f, "uint8_t input_mem[] = {\n");

  for (long i = 0; i < INPUT_SIZE; i++) {
    fprintf(f, "0x%02x", input_buf[i]);
    if (i < INPUT_SIZE - 1)
      fprintf(f, ",");
  }

  fprintf(f, "\n};\n");
  fclose(f);
  printf("create %s\n", source_file);
  free(header_file);
  free(source_file);
  return 0;
}

void execute_command(const char* command) {
  pid_t pid = fork();

  if (pid == -1) {
    perror("fork");
    exit(EXIT_FAILURE);
  } else if (pid == 0) {
    char* args[128];
    char* mutable_command = strdup(command);
    char* token;
    int i = 0;

    token = strtok(mutable_command, " ");
    while (token != NULL) {
      args[i++] = token;
      token = strtok(NULL, " ");
      if (i >= 128 - 1)
        break;
    }
    args[i] = NULL;

    execvp(args[0], args);

    perror("execvp");
    free(mutable_command);
    exit(EXIT_FAILURE);
  } else {
    int status;

    if (waitpid(pid, &status, 0) == -1) {
      perror("waitpid");
      exit(EXIT_FAILURE);
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      fprintf(stderr, "Failed to execute command: %s\n", command);
      // exit(EXIT_FAILURE);
    }
  }
}

void execute_with_wrapper(const char* commandType, const char* command) {
  char buffer[1200];
  snprintf(buffer, sizeof(buffer), "tools/fuzz_runner/command_wrapper.sh %s %s",
           commandType, command);
  system(buffer);
}

void execute_kvm(const char* vendor_name,
                 const char* kvm_param,
                 const char* cpu_flags) {
  char command[1024];
  snprintf(command, sizeof(command), "start %s \"%s\" %s", vendor_name,
           kvm_param, cpu_flags);
  execute_with_wrapper("kvm", command);
}

int open_kvm_coverage(void) {
  int shm_fd, bitmap_fd, kvm_arch_fd, kvm_fd, err;
  char* sudo_uid = getenv("SUDO_UID");
  char* sudo_gid = getenv("SUDO_GID");
  kvm_arch_fd =
      shm_open(SHM_KVM_ARCH_COVERAGE, O_CREAT | O_EXCL | O_RDWR, 00666);
  if (kvm_arch_fd == -1) {
    if (errno == EEXIST) {
      // The shared memory object already exists
      kvm_arch_fd = shm_open(SHM_KVM_ARCH_COVERAGE, O_RDWR, 0);
      if (kvm_arch_fd == -1) {
        fprintf(stderr, "Failed to shm_open %s\n", SHM_KVM_ARCH_COVERAGE);
        exit(1);
      }
    } else {
      fprintf(stderr, "Failed to shm_open %s\n", SHM_KVM_ARCH_COVERAGE);
      exit(1);
    }
  } else {
    // Set permissions to allow read and write for all users
    if (fchmod(kvm_arch_fd, 0666) == -1) {
      fprintf(stderr, "fchown failed kvm_arch_fd\n");
      exit(1);
    }
    if (sudo_uid && sudo_gid) {
      uid_t uid = (uid_t)atoi(sudo_uid);
      gid_t gid = (gid_t)atoi(sudo_gid);

      if (fchown(kvm_arch_fd, uid, gid) == -1) {
        fprintf(stderr, "fchown failed kvm_arch_fd\n");
        exit(1);
      }
    } else {
      fprintf(stderr, "SUDO_UID and SUDO_GID environment variables not set.\n");
      exit(1);
    }
  }
  // Set the size of the shared memory segment
  if (ftruncate(kvm_arch_fd, MAX_KVM_ARCH) == -1) {
    fprintf(stderr, "ftruncate failed kvm_arch_fd\n");
    exit(1);
  }
  kvm_arch_coverage = (uint8_t*)mmap(NULL, MAX_KVM_ARCH, PROT_READ | PROT_WRITE,
                                     MAP_SHARED, kvm_arch_fd, 0);
  if ((void*)kvm_arch_coverage == MAP_FAILED) {
    fprintf(stderr, "Failed to mmap\n");
    close(kvm_arch_fd);
    return 1;
  }

  kvm_fd = shm_open(SHM_KVM_COVERAGE, O_CREAT | O_EXCL | O_RDWR, 00666);
  if (kvm_fd == -1) {
    if (errno == EEXIST) {
      // The shared memory object already exists
      kvm_fd = shm_open(SHM_KVM_COVERAGE, O_RDWR, 0);
      if (kvm_fd == -1) {
        fprintf(stderr, "Failed to shm_open %s\n", SHM_KVM_COVERAGE);
        exit(1);
      }
    } else {
      fprintf(stderr, "Failed to shm_open %s\n", SHM_KVM_COVERAGE);
      exit(1);
    }
  } else {
    // Set permissions to allow read and write for all users
    if (fchmod(kvm_fd, 0666) == -1) {
      fprintf(stderr, "fchown failed kvm_fd\n");
      exit(1);
    }
    if (sudo_uid && sudo_gid) {
      uid_t uid = (uid_t)atoi(sudo_uid);
      gid_t gid = (gid_t)atoi(sudo_gid);

      if (fchown(kvm_fd, uid, gid) == -1) {
        fprintf(stderr, "fchown failed kvm_fd\n");
        exit(1);
      }
    } else {
      fprintf(stderr, "SUDO_UID and SUDO_GID environment variables not set.\n");
      exit(1);
    }
  }
  // Set the size of the shared memory segment
  if (ftruncate(kvm_fd, MAX_KVM) == -1) {
    fprintf(stderr, "ftruncate failed kvm_fd\n");
    exit(1);
  }

  kvm_coverage = (uint8_t*)mmap(NULL, MAX_KVM, PROT_READ | PROT_WRITE,
                                MAP_SHARED, kvm_fd, 0);
  if ((void*)kvm_coverage == MAP_FAILED) {
    fprintf(stderr, "Failed to mmap\n");
    close(kvm_fd);
    munmap(kvm_arch_coverage, MAX_KVM_ARCH);
    close(kvm_arch_fd);
    return 1;
  }

  for (int i = 0; i < MAX_KVM; i++) {
    if (i < MAX_KVM_ARCH)
      prev_kvm_arch_cnt += kvm_arch_coverage[i];
    prev_kvm_cnt += kvm_coverage[i];
  }
  return 0;
}

int save_kvm_coverage(void) {
  for (int i = 0; i < MAX_KVM; i++) {
    if (i < MAX_KVM_ARCH)
      kvm_arch_cnt += kvm_arch_coverage[i];
    kvm_cnt += kvm_coverage[i];
  }
  if (kvm_cnt > prev_kvm_cnt) {
    new_coverage_found = 1;
    execute_with_wrapper("kvm", "covsave_kvm");
  }
  if (kvm_arch_cnt > prev_kvm_arch_cnt) {
    new_coverage_found = 1;
    execute_with_wrapper("kvm", "covsave_kvm_arch");
  }

  return 0;
}

void* unload_kvm_module_thread(void* arg) {
  execute_with_wrapper("kvm", "unload");
  return NULL;
}

void encode_coverage_bitmap() {
  int i;
  if (yaml_config->coverage_guided) {
    for (i = 0; i < BITMAP_SIZE; i++) {
      if (coverage_bitmap[i] >= 128)
        coverage_bitmap[i] = 0x80;
      else if (coverage_bitmap[i] >= 32)
        coverage_bitmap[i] = 0x40;
      else if (coverage_bitmap[i] >= 16)
        coverage_bitmap[i] = 0x20;
      else if (coverage_bitmap[i] >= 8)
        coverage_bitmap[i] = 0x10;
      else if (coverage_bitmap[i] >= 4)
        coverage_bitmap[i] = 0x08;
      else if (coverage_bitmap[i] >= 3)
        coverage_bitmap[i] = 0x04;
      else if (coverage_bitmap[i] >= 2)
        coverage_bitmap[i] = 0x02;
      else if (coverage_bitmap[i] >= 1)
        coverage_bitmap[i] = 0x01;
    }
  }
}
int fuzz_kvm() {
  char command[1024];
  char kvm_param[512] = {0};
  char cpu_flags[512];
  pid_t pid;
  int status;

  if (open_kvm_coverage() != 0) {
    return 1;
  }

  sprintf(cpu_flags, "host");
#ifdef VCPU_CONFIG
  setup_kvm_paramater(kvm_param, sizeof(kvm_param));
  setup_qemu_cpu_flags(cpu_flags, sizeof(cpu_flags));
#endif
  sprintf(command, "sudo modprobe kvm_%s %s", vendor_name, kvm_param);

  execute_kvm(vendor_name, kvm_param, cpu_flags);

  encode_coverage_bitmap();
  save_kvm_coverage();

  return 0;
}

int open_xen_coverage(void) {
  int xen_fd, err;

  xen_fd =
      shm_open(SHM_XEN_COVERAGE, O_CREAT | O_RDWR, S_IRWXU | S_IRWXG | S_IRWXO);
  if (xen_fd == -1) {
    fprintf(stderr, "Failed to shm_open %s\n", SHM_XEN_COVERAGE);
    return 1;
  }
  err = ftruncate(xen_fd, BITMAP_SIZE);
  if (err == -1) {
    fprintf(stderr, "Failed to ftruncate\n");
    close(xen_fd);
    return 1;
  }
  xen_coverage = (uint8_t*)mmap(NULL, BITMAP_SIZE, PROT_READ | PROT_WRITE,
                                MAP_SHARED, xen_fd, 0);
  if ((void*)xen_coverage == MAP_FAILED) {
    fprintf(stderr, "Failed to mmap\n");
    close(xen_fd);
    return 1;
  }

  for (int i = 0; i < BITMAP_SIZE; i++) {
    prev_xen_cnt += xen_coverage[i];
  }
  return 0;
}

int process_gcov_file(const char* filename) {
  int ind = 0;
  char line[256];
  FILE* file = fopen(filename, "r");
  if (!file) {
    fprintf(stderr, "Failed to fopen %s\n", filename);
    return -1;
  }

  while (fgets(line, sizeof(line), file)) {
    char left_part[256];
    char* colon_ptr = strchr(line, ':');
    if (!colon_ptr)
      continue;
    if (colon_ptr[-1] == '-') {
      continue;
    }

    strncpy(left_part, line, colon_ptr - line);
    left_part[colon_ptr - line] = '\0';
    if (strstr(left_part, "#")) {
      ind += 1;
      continue;
    }
    if (ind >= BITMAP_SIZE) {
      printf("index reached BITMAP_SIZE with %s", filename);
      return -1;
    }
    char* ptr = left_part;
    while (*ptr && isspace((unsigned char)*ptr))
      ptr++;
    if (*ptr) {
      char* end_ptr;
      long count = strtol(ptr, &end_ptr, 10);
      if (*end_ptr == '*')
        end_ptr++;
      if (*end_ptr == '\0') {
        if (yaml_config->coverage_guided) {
          if (count >= 128)
            coverage_bitmap[ind] |= 0x80;
          else if (count >= 32)
            coverage_bitmap[ind] |= 0x40;
          else if (count >= 16)
            coverage_bitmap[ind] |= 0x20;
          else if (count >= 8)
            coverage_bitmap[ind] |= 0x10;
          else if (count >= 4)
            coverage_bitmap[ind] |= 0x08;
          else if (count >= 3)
            coverage_bitmap[ind] |= 0x04;
          else if (count >= 2)
            coverage_bitmap[ind] |= 0x02;
          else if (count >= 1)
            coverage_bitmap[ind] |= 0x01;
        }
        if (xen_coverage[ind] == 0)
          xen_coverage[ind] = 1;
        ind += 1;
      }
    }
  }
  for (int i = 0; i < BITMAP_SIZE; i++) {
    xen_cnt += xen_coverage[i];
  }
  if (prev_xen_cnt < xen_cnt) {
    new_coverage_found = 1;
    execute_with_wrapper("xen", "covsave");
  }
  fclose(file);
  return 0;
}

int fuzz_xen(void) {
  if (open_xen_coverage() != 0) {
    return 1;
  }

  execute_with_wrapper("xen", "start");
  process_gcov_file(cov_file);
  return 0;
}

int fuzz_vbox(void) {
  execute_with_wrapper("vbox", "start");
  return 0;
}

int fuzz_vmware(void) {
  execute_with_wrapper("vmware", "start");
  return 0;
}
