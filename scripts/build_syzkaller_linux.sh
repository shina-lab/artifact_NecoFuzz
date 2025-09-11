#!/bin/bash
set -eu

# Source utilities and check config
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
source "$SCRIPT_DIR/utilities.sh"
check_file "$CONFIG_PATH"

# Get directories from config
LINUX_SOURCE_DIR=$(python3 -c 'import yaml,sys;print(yaml.safe_load(sys.stdin)["directories"]["linux_source_dir"])' < "$CONFIG_PATH")
SYZKALLER_LINUX_DIR=$(python3 -c 'import yaml,sys;print(yaml.safe_load(sys.stdin)["directories"]["syzkaller_linux_source_dir"])' < "$CONFIG_PATH")

# Save original directory
ORIGINAL_DIR="$(pwd)"

echo "Source directory: $LINUX_SOURCE_DIR"
echo "Syzkaller kernel directory: $SYZKALLER_LINUX_DIR"

# Copy source if syzkaller directory doesn't exist or ask user
if [ -d "$SYZKALLER_LINUX_DIR" ]; then
    read -p "Syzkaller kernel directory already exists. Remove and recreate? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Removing existing directory..."
        rm -rf "$SYZKALLER_LINUX_DIR"
    else
        echo "Using existing directory. Proceeding with build..."
    fi
fi

# Copy source directory if it doesn't exist
if [ ! -d "$SYZKALLER_LINUX_DIR" ]; then
    echo "Copying Linux source to syzkaller directory..."
    cp -r "$LINUX_SOURCE_DIR" "$SYZKALLER_LINUX_DIR"
    echo "Copy completed."
fi

# Apply ccache settings (same as original)
sudo apt install -y ccache

if ! grep -q 'export PATH="/usr/lib/ccache:$PATH"' ~/.bashrc; then
    echo 'export PATH="/usr/lib/ccache:$PATH"' >> ~/.bashrc
    echo "Added ccache to PATH in ~/.bashrc"
fi

if ! grep -q 'export CCACHE_DIR="$HOME/.ccache"' ~/.bashrc; then
    echo 'export CCACHE_DIR="$HOME/.ccache"' >> ~/.bashrc
    echo "Added CCACHE_DIR to ~/.bashrc"
fi

# Apply changes to current session
export PATH="/usr/lib/ccache:$PATH"
export CCACHE_DIR="$HOME/.ccache"

cd "$SYZKALLER_LINUX_DIR"

# Use existing .config if available, otherwise copy from boot
if [ ! -f .config ]; then
    echo "Copying current kernel config..."
    cp /boot/config-$(uname -r) .config
fi

# Create syzkaller-specific config fragment
cat > syzkaller_fragment.config << EOF
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

# Networking (for syzkaller)
CONFIG_NET=y
CONFIG_E100=y
CONFIG_E1000=y
CONFIG_E1000E=y

# Sanitizers
CONFIG_KASAN=y
CONFIG_KASAN_INLINE=y
CONFIG_UBSAN=y

# For networking in syzkaller
CONFIG_BINFMT_MISC=y
CONFIG_SYSTEM_REVOCATION_KEYS=""
CONFIG_SYSTEM_TRUSTED_KEYS=""

# Debug info (disable DWARF5 for compatibility)
CONFIG_DEBUG_INFO_DWARF5=n

# Additional syzkaller requirements
CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_REDUCED=n
CONFIG_CONFIGFS_FS=y
CONFIG_SECURITYFS=y
EOF

echo "Merging configuration..."
./scripts/kconfig/merge_config.sh .config syzkaller_fragment.config

echo "Starting kernel build for syzkaller..."
make -j"$(nproc)"

echo "Building headers..."
make headers

echo "Build completed!"
echo "vmlinux location: $SYZKALLER_LINUX_DIR/vmlinux"

# Verify vmlinux was created
if [ -f vmlinux ]; then
    echo "✓ vmlinux successfully created"
    ls -lh vmlinux
else
    echo "✗ vmlinux not found. Build may have failed."
    exit 1
fi

cd "$ORIGINAL_DIR"
echo "Returned to original directory: $(pwd)"