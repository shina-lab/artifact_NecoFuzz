# Compiler and Flags
CC = x86_64-w64-mingw32-gcc
CFLAGS = -std=gnu11 -ffreestanding -shared -nostdlib -Wall -Werror \
	-fno-stack-check -fno-stack-protector -Wno-unused-variable \
	-Wno-maybe-uninitialized -Wno-unused-but-set-variable\
	-mno-stack-arg-probe -mno-red-zone -mno-sse -mno-ms-bitfields \
	-Wl,--subsystem,10 \
	-e EfiMain \

# Default Configuration
DEFAULT_CONFIG_PATH = config.yaml
ifeq ($(CONFIG_PATH),)
	CONFIG_FILE := $(DEFAULT_CONFIG_PATH)
else
	CONFIG_FILE := $(CONFIG_PATH)
endif

get_value_from_config = $(shell if [ ! -f $(DEFAULT_CONFIG_PATH) ]; then echo ""; else python3 -c 'import yaml,sys;print(yaml.safe_load(sys.stdin)["$(1)"]["$(2)"])' < $(DEFAULT_CONFIG_PATH); fi)

CONFIG_HASH_FILE = .config_$(shell echo $(CFLAGS) | md5sum | cut -d' ' -f1)

STATE_VALIDATOR = $(call get_value_from_config,fuzzing,vmstate_validator)
ifeq ($(STATE_VALIDATOR),1)
	CFLAGS += -DSTATE_VALIDATOR
else
	CFLAGS +=
endif

HARNESS = $(call get_value_from_config,fuzzing,harness)
IS_NUMBER = $(shell echo $(HARNESS) | grep -E '^[0-9]+$$')

ifeq ($(IS_NUMBER),$(HARNESS))
	CFLAGS += -D HARNESS_COUNT=$(HARNESS)
	CFLAGS += -D L2_HARNESS_COUNT=20
else
	CFLAGS +=
endif

TARGET_HYPERVISOR = $(call get_value_from_config,fuzzing,target)
ifeq ($(TARGET_HYPERVISOR),xen)
	CFLAGS += -DXEN
else ifeq ($(TARGET_HYPERVISOR),kvm)
	CFLAGS += -DKVM
else ifeq ($(TARGET_HYPERVISOR),vbox)
	CFLAGS += -DVBOX
else ifeq ($(TARGET_HYPERVISOR),vmware)
	CFLAGS += -DVMWARE
else
	CFLAGS +=
endif

# Debug Configuration
ifdef DEBUG
	CFLAGS += -DDEBUG
else
endif

# Vendor Check
ORIGINAL_VENDOR=$(shell grep -m 1 '^vendor_id' /proc/cpuinfo | awk -F ": " '{print $$2}')
ifeq ($(ORIGINAL_VENDOR),GenuineIntel)
	VENDOR=intel
	SRC = vmx/main.c vmx/vmx.c vmx/fuzz.c common/msr.c common/uefi.c common/input.c common/cpu.c
	CPU_OPT=vmx
else ifeq ($(ORIGINAL_VENDOR),AuthenticAMD)
	VENDOR=amd
	SRC = svm/main.c svm/svm.c svm/fuzz.c common/msr.c common/uefi.c common/input.c common/cpu.c
	CPU_OPT=svm
else
	VENDOR_CHECK=error
endif

# QEMU Configuration
QEMU = $(call get_value_from_config,program,qemu)
# QEMU=/usr/bin/qemu-system-x86_64
QEMU_DISK = 'json:{ "fat-type": 0, "dir": "kvm-necofuzz", "driver": "vvfat", "floppy": false, "rw": true }'
QEMU_OPTS =-nodefaults -enable-kvm -machine accel=kvm \
	-cpu host,$(CPU_OPT),hv-passthrough=off \
	-m 256 -smp 2 \
	-hda $(QEMU_DISK) -nographic -serial mon:stdio -no-reboot \
	-bios  /usr/share/qemu/OVMF.fd

# Log file name
VBOX_LOG := vbox-necofuzz/vbox-necofuzz.log
VMWARE_LOG:= vmware-necofuzz/vmware-necofuzz.log

# Source directory
VPATH = src

# Targets
.PHONY: all enable_nested disable_nested qemu clean check_vendor check_nested

all: check_vendor main.efi

OBJ_FILES = $(addprefix $(VPATH)/, $(SRC:.c=.o))
main.efi: $(OBJ_FILES)
	$(CC) $(CFLAGS) $^ -o $@

$(VPATH)/%.o: %.c $(CONFIG_HASH_FILE)
	$(CC) $(CFLAGS) -c $< -o $@

$(CONFIG_HASH_FILE):
	touch $@
	find .  -maxdepth 1 -type f -name '.config_*' ! -name '$@' -delete

check_vendor:
	@if [ "$(VENDOR_CHECK)" = "error" ]; then \
		echo "Error: Unknown vendor: $(ORIGINAL_VENDOR)"; \
		exit 1; \
	fi

kvm: kvm-necofuzz/EFI/BOOT/BOOTX64.EFI check_nested
	sudo $(QEMU) $(QEMU_OPTS)

kvm-necofuzz/EFI/BOOT/BOOTX64.EFI: main.efi
	mkdir -p kvm-necofuzz/EFI/BOOT
	ln -sf ../../../main.efi kvm-necofuzz/EFI/BOOT/BOOTX64.EFI

check_nested:
	@if [ ! -f /sys/module/kvm_$(VENDOR)/parameters/nested ] || [ "$$(cat /sys/module/kvm_$(VENDOR)/parameters/nested)" = "N" ]; then \
		$(MAKE) enable_nested; \
	fi

enable_nested:
	@echo Enabling nested virtualization in KVM ...
	sudo modprobe -r kvm_$(VENDOR)
	sudo modprobe kvm_$(VENDOR) nested=1

clean:
	rm -f main.efi
	rm -f src/common/*.o src/svm/*.o src/vmx/*.o
	rm -f .debug .nodebug
	rm -rf kvm-necofuzz
	rm -rf xen-necofuzz
	rm -rf vbox-necofuzz
	rm -rf vmware-necofuzz
	while VBoxManage list vms | grep -q "vbox-necofuzz"; do \
		VBoxManage controlvm vbox-necofuzz poweroff || true; \
		VBoxManage unregistervm vbox-necofuzz --delete; \
	done

vbox: vbox-necofuzz/vbox-necofuzz.vbox vbox-necofuzz/vbox_image.vdi
	VBoxManage startvm vbox-necofuzz --type headless

vbox-necofuzz/vbox_image.vdi: main.efi
	VBoxManage controlvm vbox-necofuzz poweroff || true;
	@ATTACHED=$$(VBoxManage showvminfo vbox-necofuzz --machinereadable | grep vbox-necofuzz/vbox_image.vdi); \
	if [ ! -z "$$ATTACHED" ]; then \
		VBoxManage storageattach vbox-necofuzz --storagectl "SATA Controller" --port 1 --device 0 --type hdd --medium none; \
		VBoxManage closemedium disk "$$PWD/vbox-necofuzz/vbox_image.vdi" --delete; \
		echo "VDI was attached and has been detached."; \
	else \
		echo "VDI is not attached."; \
	fi
	mkdir -p vbox-necofuzz/mnt
	qemu-img create -f raw vbox-necofuzz/vbox_image.img 50M
	mkfs.vfat vbox-necofuzz/vbox_image.img
	while cat /etc/mtab | grep -q "vbox-necofuzz/mnt"; do \
		fusermount -u vbox-necofuzz/mnt; \
		sleep 0.1; \
	done
	fusefat -o rw+ vbox-necofuzz/vbox_image.img vbox-necofuzz/mnt
	mkdir -p vbox-necofuzz/mnt/EFI/BOOT
	cp main.efi vbox-necofuzz/mnt/EFI/BOOT/BOOTX64.EFI
	while cat /etc/mtab | grep -q "vbox-necofuzz/mnt"; do \
		fusermount -u vbox-necofuzz/mnt; \
		sleep 0.1; \
	done
	qemu-img convert -f raw -O vdi vbox-necofuzz/vbox_image.img vbox-necofuzz/vbox_image.vdi
	VBoxManage storageattach "vbox-necofuzz" --storagectl "SATA Controller" --port 1 --device 0 --type hdd --medium "$$PWD/vbox-necofuzz/vbox_image.vdi"

vbox-necofuzz/vbox-necofuzz.vbox:
	@if [ ! -f vbox-necofuzz/vbox-necofuzz.vbox ]; then \
		VBoxManage createvm --name "vbox-necofuzz" --register --basefolder $$PWD; \
	fi
	VBoxManage modifyvm vbox-necofuzz --nested-hw-virt on --memory 1024 --firmware efi --uart1 0x3f8 4 --uartmode1 file "$$PWD/$(VBOX_LOG)"
	VBoxManage storagectl vbox-necofuzz --name "SATA Controller" --add sata --controller IntelAhci

xen: xen-necofuzz/xen-necofuzz.cfg xen-necofuzz/xen_image.img
	sudo xl create xen-necofuzz/xen-necofuzz.cfg -c

xen-necofuzz/xen_image.img: main.efi
	mkdir -p xen-necofuzz/mnt
	qemu-img create -f raw xen-necofuzz/xen_image.img 50M
	mkfs.vfat xen-necofuzz/xen_image.img
	while cat /etc/mtab | grep -q "xen-necofuzz/mnt"; do \
		fusermount -u xen-necofuzz/mnt; \
		sleep 0.1; \
	done
	fusefat -o rw+ xen-necofuzz/xen_image.img xen-necofuzz/mnt
	mkdir -p xen-necofuzz/mnt/EFI/BOOT
	cp main.efi xen-necofuzz/mnt/EFI/BOOT/BOOTX64.EFI
	while cat /etc/mtab | grep -q "xen-necofuzz/mnt"; do \
		fusermount -u xen-necofuzz/mnt; \
		sleep 0.1; \
	done

xen-necofuzz/xen-necofuzz.cfg:
	mkdir xen-necofuzz
	@echo "builder='hvm'" > $@
	@echo "memory = 512" >> $@
	@echo "name = \"necofuzz\"" >> $@
	@echo "vcpus=1" >> $@
	@echo "hap=1" >> $@
	@echo "nestedhvm=1" >> $@
	@echo "on_reboot=\"destroy\"" >> $@
	@echo "bios = \"ovmf\"" >> $@
	@echo "bios_path_override = './OVMF.fd'" >> $@
	@echo "disk = [ 'file:$$PWD/xen-necofuzz/xen_image.img,xvda,w' ]" >> $@
	@echo "serial='pty'" >> $@

vmware: vmware-necofuzz/vmware-necofuzz.vmdk
	rm -f $(VMWARE_LOG)
	vmrun start vmware-necofuzz/vmware-necofuzz.vmx nogui

vmware-necofuzz/vmware-necofuzz.vmdk: main.efi
	mkdir -p vmware-necofuzz/mnt
	qemu-img create -f raw vmware-necofuzz/vmware_image.img 50M
	mkfs.vfat vmware-necofuzz/vmware_image.img
	while cat /etc/mtab | grep -q "vmware-necofuzz/mnt"; do \
		fusermount -u vmware-necofuzz/mnt; \
		sleep 0.1; \
	done
	fusefat -o rw+ vmware-necofuzz/vmware_image.img vmware-necofuzz/mnt
	mkdir -p vmware-necofuzz/mnt/EFI/BOOT
	cp main.efi vmware-necofuzz/mnt/EFI/BOOT/BOOTX64.EFI
	while cat /etc/mtab | grep -q "vmware-necofuzz/mnt"; do \
		fusermount -u vmware-necofuzz/mnt; \
		sleep 0.1; \
	done
	qemu-img convert -f raw -O vmdk vmware-necofuzz/vmware_image.img vmware-necofuzz/vmware-necofuzz.vmdk

prepare: OVMF.fd
	@if [ ! -f $(DEFAULT_CONFIG_PATH) ]; then \
		echo "Creating default config from sample..."; \
		cp config/kvm_default.yaml $(DEFAULT_CONFIG_PATH); \
	else \
		echo "Config already exists."; \
	fi

	@FUZZ_INPUTS_DIR=$(call get_value_from_config,directories,fuzz_inputs); \
	if [ ! -d "$$FUZZ_INPUTS_DIR" ]; then \
		echo "Setting fuzz inputs directory..."; \
		mkdir -p "$$FUZZ_INPUTS_DIR"; \
	else \
		echo "Fuzz inputs directory exists."; \
	fi

	@SEED_DIR=$(call get_value_from_config,fuzzing,seed_dir); \
	if [ ! -d "$$SEED_DIR" ]; then \
		echo "Setting seed directory..."; \
		SEED_DIR="$$PWD/seeds"; \
		echo "Default seed directory created at $$SEED_DIR"; \
		python3 tools/scripts/update_config.py $(DEFAULT_CONFIG_PATH) "fuzzing" "seed_dir" "$$SEED_DIR"; \
		mkdir -p "$$SEED_DIR"; \
	else \
		echo "Seed directory exists."; \
	fi; \
	for i in $$(seq 1 2); do \
		dd if=/dev/urandom of="$$SEED_DIR/seed_$$i" bs=1K count=2; \
	done; \
	echo "2 seed files created in $$SEED_DIR."

	@echo "Please manually set the $(DEFAULT_CONFIG_PATH) variable to specify the path to your default configuration file."
OVMF.fd:
	wget http://downloads.sourceforge.net/project/edk2/OVMF/OVMF-X64-r15214.zip
	unzip OVMF-X64-r15214.zip OVMF.fd
	rm OVMF-X64-r15214.zip