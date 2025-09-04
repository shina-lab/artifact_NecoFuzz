#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include "args.h"
#include "fuzz.h"
#include "my_yaml.h"

args_config_t* config;
uint8_t input_buf[INPUT_SIZE];
uint8_t* coverage_bitmap;
uint8_t* afl_area_ptr;
int bitmap_fd;

void cleanup_and_exit(int exit_code) {
  if (yaml_config->coverage_guided) {
    if (afl_area_ptr != NULL) {
      memcpy(afl_area_ptr, coverage_bitmap, BITMAP_SIZE);
      shmdt(afl_area_ptr);
    }
    if (coverage_bitmap != NULL && munmap(coverage_bitmap, BITMAP_SIZE) == -1) {
      fprintf(stderr, "munmap failed\n");
    }
    close(bitmap_fd);
  }

  free(config);
  free(yaml_config);
  exit(exit_code);
}

int save_create_input() {
  FILE* input_fp;
  input_fp = fopen(config->afl_input_name, "rb");
  if (input_fp == NULL) {
    fprintf(stderr, "fopen failed for %s\n", config->afl_input_name);
    return 1;
  }
  fread(input_buf, sizeof(uint8_t), INPUT_SIZE, input_fp);
  fclose(input_fp);
  if (save_input(input_buf) != 0) {
    return 1;
  }
  if (create_input() != 0) {
    return 1;
  }

  return 0;
}

int open_coverage_bitmap() {
  int afl_shm_id;
  int err;
  char* sudo_uid = getenv("SUDO_UID");
  char* sudo_gid = getenv("SUDO_GID");
  bitmap_fd = shm_open(SHM_COVERAGE_BITMAP, O_CREAT | O_EXCL | O_RDWR, 00666);
  if (bitmap_fd == -1) {
    if (errno == EEXIST) {
      // The shared memory object already exists
      bitmap_fd = shm_open(SHM_COVERAGE_BITMAP, O_RDWR, 0);
      if (bitmap_fd == -1) {
        fprintf(stderr, "Failed to shm_open %s\n", SHM_COVERAGE_BITMAP);
        exit(1);
      }
    } else {
      fprintf(stderr, "Failed to shm_open %s\n", SHM_COVERAGE_BITMAP);
      exit(1);
    }
  } else {
    // Set permissions to allow read and write for all users
    if (fchmod(bitmap_fd, 0666) == -1) {
      fprintf(stderr, "fchown failed bitmap_fd\n");
      exit(1);
    }
    if (sudo_uid && sudo_gid) {
      uid_t uid = (uid_t)atoi(sudo_uid);
      gid_t gid = (gid_t)atoi(sudo_gid);

      if (fchown(bitmap_fd, uid, gid) == -1) {
        fprintf(stderr, "fchown failed bitmap_fd\n");
        exit(1);
      }
    } else {
      fprintf(stderr, "SUDO_UID and SUDO_GID environment variables not set.\n");
      exit(1);
    }
    // Set the size of the shared memory segment
    if (ftruncate(bitmap_fd, 65536) == -1) {
      fprintf(stderr, "ftruncate failed bitmap_fd\n");
      exit(1);
    }
  }

  if (yaml_config->coverage_guided) {
    const char* afl_shm_id_str = getenv("__AFL_SHM_ID");
    if (afl_shm_id_str != NULL) {
      afl_shm_id = atoi(afl_shm_id_str);
      afl_area_ptr = shmat(afl_shm_id, NULL, 0);
    }

    coverage_bitmap = (uint8_t*)mmap(NULL, BITMAP_SIZE, PROT_READ | PROT_WRITE,
                                     MAP_SHARED, bitmap_fd, 0);
    if ((void*)coverage_bitmap == MAP_FAILED) {
      fprintf(stderr, "mmap failed\n");
      return 1;
    }
    memset(coverage_bitmap, 0, BITMAP_SIZE);
  }
  return 0;
}

int main(int argc, char** argv) {
  pthread_t kvm_unload_thread;
  config = parse_args(argc, argv);
  if (config == NULL)
    return 1;
  yaml_config = parse_config(config->yaml_config_name);

  if (yaml_config->target == TARGET_KVM) {
    if (pthread_create(&kvm_unload_thread, NULL, unload_kvm_module_thread,
                       NULL) != 0) {
      fprintf(stderr, "pthread_create for unload_module_thread");
      return 1;
    }
  }

  // Save the initial input to allow for reproduction in case the input host
  // crashes. If there's no impact on coverage, the saved input will be deleted
  // later.
  if (save_create_input() != 0) {
    return 1;
  }

  // Compile with input
  system("make");

  if (open_coverage_bitmap() != 0) {
    return 1;
  }

  if (yaml_config->target == TARGET_KVM) {
    if (check_cpu_vendor() != 0) {
      cleanup_and_exit(1);
    }
    pthread_join(kvm_unload_thread, NULL);
    if (fuzz_kvm() != 0) {
      cleanup_and_exit(1);
    }
    if (new_coverage_found) {
      delete_input();
    }
  } else if (yaml_config->target == TARGET_XEN) {
    if (fuzz_xen() != 0) {
      cleanup_and_exit(1);
    }
    if (new_coverage_found) {
      delete_input();
    }
  } else if (yaml_config->target == TARGET_VBOX) {
    fuzz_vbox();
  } else if (yaml_config->target == TARGET_VMWARE) {
    fuzz_vmware();
  } else {
  }
  if (yaml_config->coverage_guided) {
    if (afl_area_ptr != NULL) {
      memcpy(afl_area_ptr, coverage_bitmap, BITMAP_SIZE);
    }
  }

  cleanup_and_exit(0);
  return 0;
}