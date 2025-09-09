#!/bin/bash
set -eu

# Source utilities and check config
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
source "$SCRIPT_DIR/utilities.sh"
check_file "$CONFIG_PATH"
# Get KVM directory from config
LINUX_SOURCE_DIR=$(python3 -c 'import yaml,sys;print(yaml.safe_load(sys.stdin)["directories"]["linux_source_dir"])' < "$CONFIG_PATH")

# Save original directory
ORIGINAL_DIR="$(pwd)"

sudo apt install -y ccache
# Check and add ccache PATH if not already present
if ! grep -q 'export PATH="/usr/lib/ccache:$PATH"' ~/.bashrc; then
    echo 'export PATH="/usr/lib/ccache:$PATH"' >> ~/.bashrc
    source ~/.bashrc
    echo "Added ccache to PATH in ~/.bashrc"
else
    echo "ccache PATH already exists in ~/.bashrc"
fi

# Check and add CCACHE_DIR if not already present
if ! grep -q 'export CCACHE_DIR="$HOME/.ccache"' ~/.bashrc; then
    echo 'export CCACHE_DIR="$HOME/.ccache"' >> ~/.bashrc
    echo "Added CCACHE_DIR to ~/.bashrc"
    source ~/.bashrc
else
    echo "CCACHE_DIR already exists in ~/.bashrc"
fi

# Apply changes to current session
export PATH="/usr/lib/ccache:$PATH"
export CCACHE_DIR="$HOME/.ccache"

cd "$LINUX_SOURCE_DIR"

cp /boot/config-$(uname -r) .config

cat > fragment.config << EOF
# Disable KASLR
# CONFIG_RANDOMIZE_BASE is not set

# KVM support
CONFIG_KVM=m
CONFIG_KVM_INTEL=m
CONFIG_KVM_AMD=m

# Coverage and debugging
CONFIG_FRAME_WARN=2048
CONFIG_KCOV=y
CONFIG_KCOV_INSTRUMENT_ALL=y
CONFIG_KCOV_ENABLE_COMPARISONS=y
CONFIG_DEBUG_FS=y

# Sanitizers
CONFIG_KASAN=y
CONFIG_KASAN_INLINE=y
CONFIG_UBSAN=y

# For networking in syzkaller
CONFIG_BINFMT_MISC=y

CONFIG_SYSTEM_REVOCATION_KEYS=""
CONFIG_SYSTEM_TRUSTED_KEYS=""

CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_NONE=n
EOF

./scripts/kconfig/merge_config.sh .config fragment.config

make -j"$(nproc)" KBUILD_MODPOST_WARN=1
make headers
sudo make -j"$(nproc)" INSTALL_MOD_STRIP=1 modules_install
sudo make install

cd "$ORIGINAL_DIR"
echo "Returned to original directory: $(pwd)"
