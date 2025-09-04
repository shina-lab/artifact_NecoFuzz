#pragma once
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_AFL_INPUT "afl_input"
#define DEFAULT_YAML_CONFIG "config.yaml"
#define DEFAULT_TARGET ""
#define DEFAULT_SRCDIR "src/common/"
#define DEFAULT_USERNAME ""
typedef struct {
  char shm_name[128];
  char bitmap_name[128];
  char afl_input_name[128];
  char yaml_config_name[128];
  char srcdir_name[128];
  char user_name[128];
} args_config_t;

static void print_usage();
args_config_t* parse_args(int argc, char** argv);
