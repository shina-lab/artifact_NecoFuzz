#!/bin/bash
set -eu

# Source utilities and check config
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
source "$SCRIPT_DIR/utilities.sh"
check_file "$CONFIG_PATH"
# Get KVM directory from config
XEN_DIR=$(python3 -c 'import yaml,sys;print(yaml.safe_load(sys.stdin)["directories"]["xen_dir"])' < "$CONFIG_PATH")

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

echo $XEN_DIR
cd "$XEN_DIR"
cd ./xen
echo "CONFIG_LIVEPATCH=n
CONFIG_DEBUG=y
CONFIG_DEBUG_INFO=y
CONFIG_COVERAGE=y" >> .config
make olddefconfig
cd ../

./configure --libdir=/usr/local/lib --enable-coverage
make dist -j $(nproc)
sudo make install

if [ -f /usr/local/lib/libxlutil.so ]; then
    echo "✓ xentools successfully created"
else
    echo "✗ xentools not found. Build may have failed."
    exit 1
fi

cd "$ORIGINAL_DIR"
echo "Returned to original directory: $(pwd)"
