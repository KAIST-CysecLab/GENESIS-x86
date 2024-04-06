#!/bin/bash

# SLR: Stack Layout Randomization
SCRIPT_PATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd -P)"
WS="$SCRIPT_PATH/.."
LLVM_DIR="$WS/llvm-workspace/llvm"
BUILD="$WS/build"
SYSROOT="$BUILD/sysroot"

echo "WS: $WS"
echo "LLVM_DIR : $LLVM_DIR"
echo "BUILD : $WC/build"
echo "SYSROOT = $BUILD/sysroot"

mkdir -p "$BUILD"
mkdir -p "$SYSROOT"

cd "$BUILD"
cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=RELEASE \
    -DCMAKE_INSTALL_PREFIX="$SYSROOT" \
    -DLLVM_BUILD_TOOLS=ON \
    -DLLVM_BUILD_TESTS=OFF \
    -DLLVM_BUILD_EXAMPLES=OFF \
    -DLLVM_INCLUDE_TESTS=OFF \
    -DLLVM_INCLUDE_EXAMPLES=OFF \
    -DLLVM_OPTIMIZED_TABLEGEN=ON \
    -DLLVM_TARGETS_TO_BUILD=X86 \
    -DLLVM_ENABLE_ASSERTIONS=ON \
    -DLLVM_ENABLE_PROJECTS="lld;clang" \
    -DLLVM_ENABLE_RUNTIMES="compiler-rt" \
    $LLVM_DIR
make -j$(nproc) && make install
