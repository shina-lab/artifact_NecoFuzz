#pragma once

#include "fuzz.h"

void setup_kvm_paramater(char* kvm_param, int size);
void setup_qemu_cpu_flags(char* cpu_flags, int size);
