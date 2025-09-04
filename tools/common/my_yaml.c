#include "my_yaml.h"

yaml_config_t* parse_config(char* path) {
  yaml_config_t* path_config;
  path_config = malloc(sizeof(yaml_config_t));
  yaml_parser_t parser;
  yaml_event_t event;  // Variables for parsing

  int level = 0;
  char level1_key[128] = {0};
  char level2_key[128] = {0};
  char* value;
  FILE* fh = fopen(path, "r");
  if (fh == NULL) {
    fprintf(stderr, "Failed to open file: %s\n", path);
    return NULL;
  }
  // Initialize parser
  if (!yaml_parser_initialize(&parser)) {
    fprintf(stderr, "Failed to initialize parser!\n");
    fclose(fh);
    return NULL;
  }

  // Set input file
  yaml_parser_set_input_file(&parser, fh);

  // Start parsing events
  while (1) {
    if (!yaml_parser_parse(&parser, &event)) {
      fprintf(stderr, "Parser error %d\n", parser.error);
      fclose(fh);
      yaml_parser_delete(&parser);
      return NULL;
    }

    switch (event.type) {
      case YAML_SCALAR_EVENT:
        if (level == 1) {
          strncpy(level1_key, (char*)event.data.scalar.value,
                  sizeof(level1_key) - 1);
          level1_key[sizeof(level1_key) - 1] = '\0';
        } else if (level == 2) {
          if (strcmp(level1_key, "program") == 0 &&
              strcmp(level2_key, "qemu") == 0) {
            strncpy(path_config->qemu_path, (char*)event.data.scalar.value,
                    sizeof(path_config->qemu_path) - 1);
            path_config->qemu_path[sizeof(path_config->qemu_path) - 1] = '\0';
          } else if (strcmp(level1_key, "directories") == 0) {
            if (strcmp(level2_key, "work_dir") == 0) {
              strncpy(path_config->work_dir, (char*)event.data.scalar.value,
                      sizeof(path_config->work_dir) - 1);
              path_config->work_dir[sizeof(path_config->work_dir) - 1] = '\0';
            } else if (strcmp(level2_key, "coverage_outputs") == 0) {
              strncpy(path_config->coverage_outputs,
                      (char*)event.data.scalar.value,
                      sizeof(path_config->coverage_outputs) - 1);
              path_config
                  ->coverage_outputs[sizeof(path_config->coverage_outputs) -
                                     1] = '\0';
            } else if (strcmp(level2_key, "fuzz_inputs") == 0) {
              strncpy(path_config->fuzz_inputs, (char*)event.data.scalar.value,
                      sizeof(path_config->fuzz_inputs) - 1);
              path_config->fuzz_inputs[sizeof(path_config->fuzz_inputs) - 1] =
                  '\0';
            } else if (strcmp(level2_key, "xen_dir") == 0) {
              strncpy(path_config->xen_dir, (char*)event.data.scalar.value,
                      sizeof(path_config->xen_dir) - 1);
              path_config->xen_dir[sizeof(path_config->xen_dir) - 1] = '\0';
            }
          } else if (strcmp(level1_key, "fuzzing") == 0) {
            if (strcmp(level2_key, "vcpu_config") == 0) {
              path_config->vcpu_config = atoi((char*)event.data.scalar.value);
            } else if (strcmp(level2_key, "vmstate_validator") == 0) {
              path_config->vmstate_validator =
                  atoi((char*)event.data.scalar.value);
            } else if (strcmp(level2_key, "harness") == 0) {
              path_config->harness = atoi((char*)event.data.scalar.value);
            } else if (strcmp(level2_key, "coverage_guided") == 0) {
              path_config->coverage_guided =
                  atoi((char*)event.data.scalar.value);
            } else if (strcmp(level2_key, "target") == 0) {
              if (strcmp((char*)event.data.scalar.value, "kvm") == 0) {
                path_config->target = TARGET_KVM;
              } else if (strcmp((char*)event.data.scalar.value, "xen") == 0) {
                path_config->target = TARGET_XEN;
              } else if (strcmp((char*)event.data.scalar.value, "vbox") == 0) {
                path_config->target = TARGET_VBOX;
              } else if (strcmp((char*)event.data.scalar.value, "vmware") == 0) {
                path_config->target = TARGET_VMWARE;
              } else {
                path_config->target = TARGET_UNKNOWN;
              }
            }
          }
          strncpy(level2_key, (char*)event.data.scalar.value,
                  sizeof(level2_key) - 1);
          level2_key[sizeof(level2_key) - 1] = '\0';
        }
        break;
      case YAML_MAPPING_START_EVENT:
        level++;
        break;
      case YAML_MAPPING_END_EVENT:
        if (level == 2) {
          memset(level2_key, 0, sizeof(level2_key));
        } else if (level == 1) {
          memset(level1_key, 0, sizeof(level1_key));
        }
        level--;
        break;
      default:
        break;
    }

    if (event.type == YAML_STREAM_END_EVENT) {
      break;
    }
    yaml_event_delete(&event);
  }

  // Cleanup
  yaml_parser_delete(&parser);
  fclose(fh);
  return path_config;
}