#pragma once
#include <yaml.h>

#define TARGET_KVM 0
#define TARGET_XEN 1
#define TARGET_VBOX 2
#define TARGET_VMWARE 3
#define TARGET_UNKNOWN -1

typedef struct {
  char qemu_path[128];
  char work_dir[128];
  char coverage_outputs[128];
  char fuzz_inputs[128];
  char xen_dir[128];
  int vcpu_config;
  int vmstate_validator;
  int harness;
  int coverage_guided;
  int target;
} yaml_config_t;

yaml_config_t* parse_config(char* path);
