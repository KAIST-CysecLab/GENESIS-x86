#!/bin/bash
set -e

CURDIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
LINUX_ROOT=$CURDIR
WS=$( readlink -f "$CURDIR/.." )
SYSROOT=$WS/build/sysroot

DEB=$1
if [[ "$DEB" == "deb" ]]; then
  DEB="bindeb-pkg"
fi

# Check .config file
CONFIG_FILE=".config"
if [ ! -f "$CONFIG_FILE" ]; then
  echo "[-] Cannot find .config"
  exit 1
fi

# Spectre
$LINUX_ROOT/scripts/config -d RETPOLINE

# Para-virtualization
$LINUX_ROOT/scripts/config -d HYPERVISOR_GUEST

# Kernel Hardening
$LINUX_ROOT/scripts/config -d INIT_ON_ALLOC_DEFAULT_ON
$LINUX_ROOT/scripts/config -d INIT_ON_FREE_DEFAULT_ON
$LINUX_ROOT/scripts/config -e INIT_STACK_NONE
$LINUX_ROOT/scripts/config -d INIT_STACK_ALL_PATTERN
$LINUX_ROOT/scripts/config -d INIT_STACK_ALL_ZERO

# Cert
$LINUX_ROOT/scripts/config -d SYSTEM_TRUSTED_KEY
$LINUX_ROOT/scripts/config --set-str SYSTEM_TRUSTED_KEYS ""

# Just for reducing build time
$LINUX_ROOT/scripts/config -d SECURITY_LOCKDOWN_LSM
$LINUX_ROOT/scripts/config -d MODULE_SIG

# Genesis
$LINUX_ROOT/scripts/config -e NESTED_KERNEL
$LINUX_ROOT/scripts/config -e GENESIS_LABEL_CFI
#$LINUX_ROOT/scripts/config -d GENESIS_SHADOW_STACK
$LINUX_ROOT/scripts/config -d STACK_VALIDATION # disable warning

# LLVM
$LINUX_ROOT/scripts/config -d KCSAN
$LINUX_ROOT/scripts/config -d KASAN

# Debug
$LINUX_ROOT/scripts/config -e DEBUG_INFO
$LINUX_ROOT/scripts/config -e GDB_SCRIPTS
$LINUX_ROOT/scripts/config -d DEBUG_INFO_REDUCED
$LINUX_ROOT/scripts/config -d DEBUG_INFO_COMPRESSED
$LINUX_ROOT/scripts/config -d DEBUG_INFO_SPLIT
$LINUX_ROOT/scripts/config -d DEBUG_INFO_DWARF4
$LINUX_ROOT/scripts/config -d DEBUG_INFO_BTF

# Check whether intra-kernel privilege separation is enabled
if ! grep -Fxq "CONFIG_NESTED_KERNEL=y" $CONFIG_FILE; then
  echo "[-] Must enable CONFIG_NESTED_KERNEL option"
  exit 1
fi

# Check whether label cfi is enabled
if grep -Fxq "CONFIG_GENESIS_LABEL_CFI=y" $CONFIG_FILE; then
  IS_ENABLED_CFI=true
fi

# Check whether shadow stack is enabled
if grep -Fxq "CONFIG_GENESIS_SHADOW_STACK=y" $CONFIG_FILE; then
  IS_ENABLED_SHADOW_STACK=true
  $LINUX_ROOT/scripts/config -d STACK_VALIDATION # disable objtools
fi

# Set intra-kernel privilege separation flag
CFLAGS="-fsanitize=nested-kernel -mllvm -nested-kernel-blacklist=$WS/blacklist.txt"

# Set label cfi
if [ "$IS_ENABLED_CFI" = "true" ]; then
  CFLAGS="$CFLAGS -mllvm -enable-x86-genesis-cfi"
fi

# Set shadow stack
if [ "$IS_ENABLED_SHADOW_STACK" = "true" ]; then
  CFLAGS="$CFLAGS -mllvm -enable-x86-genesis-shadow-stack"
fi

# Set blacklist
if [ "$IS_ENABLED_SHADOW_STACK" = "true" ] || [ "$IS_ENABLED_CFI" = "true" ]; then
  CFLAGS="$CFLAGS -mllvm -genesis-cfi-blacklist=$WS/cfi_blacklist.txt"
fi

export PATH=$SYSROOT/bin:$PATH
THREAD=$(nproc)

set -x
make $DEB ARCH=x86_64 LLVM=1 KBUILD_CFLAGS_KERNEL="${CFLAGS}" KBUILD_CFLAGS_MODULE="-DMODULE ${CFLAGS}" -j${THREAD}
