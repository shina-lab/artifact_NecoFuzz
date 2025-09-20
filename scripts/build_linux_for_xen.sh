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
git worktree add -f ../linux-xen v6.5
cd ../linux-xen
cp /boot/config-$(uname -r) .config

cat > fragment.config << EOF
CONFIG_LOCALVERSION="-xen"
CONFIG_LOCALVERSION_AUTO=n

# Disable KASLR
CONFIG_RANDOMIZE_BASE=y

# KVM support
CONFIG_KVM=n
CONFIG_KVM_INTEL=n
CONFIG_KVM_AMD=n

# Coverage and debugging
CONFIG_FRAME_WARN=2048
CONFIG_KCOV=n
CONFIG_KCOV_INSTRUMENT_ALL=n
CONFIG_KCOV_ENABLE_COMPARISONS=n
CONFIG_DEBUG_FS=n

# Sanitizers
CONFIG_KASAN=n
CONFIG_KASAN_INLINE=n
CONFIG_UBSAN=n

# For networking in syzkaller
CONFIG_BINFMT_MISC=y

CONFIG_SYSTEM_REVOCATION_KEYS=""
CONFIG_SYSTEM_TRUSTED_KEYS=""

CONFIG_DEBUG_INFO_DWARF5=n
CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_NONE=n

CONFIG_XEN_VIRTIO=y
CONFIG_XEN_GRANT_DMA_OPS=y
CONFIG_XEN_DEBUG_FS=y
EOF

./scripts/kconfig/merge_config.sh .config fragment.config

make -j"$(nproc)"
make headers
sudo make -j"$(nproc)" INSTALL_MOD_STRIP=1 modules_install
sudo make install

cd "$ORIGINAL_DIR"
echo "Returned to original directory: $(pwd)"
