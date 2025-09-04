CC ?= gcc
CFLAGS := -Icommon
LDFLAGS := -lelf -lyaml
BIN_DIR := bin
EXCLUDE_DIRS := common scripts bin
SRC_DIRS := $(filter-out $(addsuffix /,$(EXCLUDE_DIRS)), $(wildcard */))
COMMON_SRC := common/args.c common/my_yaml.c

BINS := $(addprefix $(BIN_DIR)/, $(notdir $(SRC_DIRS:/=)))

DEFAULT_CONFIG_PATH = ../config.yaml
ifeq ($(CONFIG_PATH),)
	CONFIG_FILE := $(DEFAULT_CONFIG_PATH)
else
	CONFIG_FILE := $(CONFIG_PATH)
endif

CONFIG_HASH_FILE = .config_$(shell echo $(CFLAGS) | md5sum | cut -d' ' -f1)

VCPU_CONFIG=$(shell python3 -c 'import yaml,sys;print(yaml.safe_load(sys.stdin)["fuzzing"]["vcpu_config"])' < $(DEFAULT_CONFIG_PATH))
ifeq ($(VCPU_CONFIG),1)
	CFLAGS += -DVCPU_CONFIG
else
	CFLAGS += 
endif

all: $(BINS)

fuzz_runner: $(BIN_DIR)/fuzz_runner
decode_coverage: $(BIN_DIR)/decode_coverage

$(BIN_DIR)/%: %/*.c $(COMMON_SRC) $(CONFIG_HASH_FILE)
	mkdir -p $(BIN_DIR)
	$(CC) $^ -o $@ $(CFLAGS) $(LDFLAGS)

$(CONFIG_HASH_FILE):
	touch $@
	find . -type f -name '.config_*' ! -name '$@' -delete

.PHONY: all clean 

clean:
	rm -rf $(BIN_DIR)/
