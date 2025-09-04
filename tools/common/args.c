#include "args.h"

static void print_usage() {
  printf("Usage: program [-i afl_input_name] [-c config_file]\n");
  printf("  -i, --input    afl input file name\n");
  printf("  -c, --config   yaml config file name\n");
  printf("  -d, --srcdir   src directry name\n");
  printf("  -u, --username user name for make\n");
  printf("  -h, --help     show this help message\n");
}

args_config_t* parse_args(int argc, char** argv) {
  int c;
  args_config_t* config;
  config = malloc(sizeof(args_config_t));
  if (config == NULL) {
    fprintf(stderr, "malloc failed\n");
    return NULL;
  }
  strcpy(config->afl_input_name, DEFAULT_AFL_INPUT);
  strcpy(config->yaml_config_name, DEFAULT_YAML_CONFIG);
  strcpy(config->srcdir_name, DEFAULT_SRCDIR);
  strcpy(config->user_name, DEFAULT_USERNAME);

  static struct option long_options[] = {
                                         {"input", required_argument, 0, 'i'},
                                         {"config", required_argument, 0, 'c'},
                                         {"srcdir", required_argument, 0, 'd'},
                                         {"username", required_argument, 0, 'u'},
                                         {"help", no_argument, 0, 'h'},
                                         {0, 0, 0, 0}};

  int option_index = 0;
  while ((c = getopt_long(argc, argv, "i:c:d:u:h", long_options,
                          &option_index)) != -1) {
    switch (c) {
      case 'i':
        strncpy(config->afl_input_name, optarg,
                sizeof(config->afl_input_name) - 1);
        config->afl_input_name[sizeof(config->afl_input_name) - 1] = '\0';
        break;
      case 'c':
        strncpy(config->yaml_config_name, optarg,
                sizeof(config->yaml_config_name) - 1);
        config->yaml_config_name[sizeof(config->yaml_config_name) - 1] = '\0';
        break;
      case 'd':
        strncpy(config->srcdir_name, optarg, sizeof(config->srcdir_name) - 1);
        config->srcdir_name[sizeof(config->srcdir_name) - 1] = '\0';
        break;
      case 'u':
        strncpy(config->user_name, optarg, sizeof(config->user_name) - 1);
        config->user_name[sizeof(config->user_name) - 1] = '\0';
        break;
      case 'h':
        print_usage();
        exit(0);
      case '?':
        print_usage();
        exit(1);
      default:
        abort();
    }
  }
  return config;
}