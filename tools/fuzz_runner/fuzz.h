#pragma once
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <sys/utsname.h>
#include <unistd.h>
#include "my_yaml.h"
#include "args.h"

#define INPUT_SIZE 2048
#define INPUT_HEADER "input.h"
#define INPUT_SOURCE "input.c"
#define SHM_COVERAGE_BITMAP "/coverage_bitmap"
#define SHM_KVM_ARCH_COVERAGE "/kvm_arch_coverage"
#define SHM_KVM_COVERAGE "/kvm_coverage"
#define SHM_XEN_COVERAGE "/xen_coverage"

#define BITMAP_SIZE 65536  // 64kB
extern uint8_t input_buf[INPUT_SIZE];

extern uint64_t MAX_KVM_ARCH;
extern uint64_t MAX_KVM;
extern yaml_config_t* yaml_config;
extern args_config_t* config;
extern uint8_t* coverage_bitmap;
extern int new_coverage_found;
#define INTEL 1
#define AMD 2
extern char vendor_id;

static uint64_t check_text_size(char* filepath);

int check_cpu_vendor(void);

int save_input();

int create_input();
void delete_input();
void execute_command(const char* command);
void* unload_kvm_module_thread(void* arg);

int fuzz_kvm(void);
int fuzz_vbox(void);
int fuzz_xen(void);
int fuzz_vmware(void);

void execute_with_wrapper(const char* commandType, const char* command);