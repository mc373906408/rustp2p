#!/bin/bash
set -e

# 颜色代码
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

# 基本设置
TOOLCHAIN_PATH="/root/gcc-sigmastar-9.1.0-2019.11-x86_64_arm-linux-gnueabihf"
BUILD_DIR="examples/c_examples/build-arm"
RUST_LIB_PATH="target/armv7-unknown-linux-gnueabihf/release/librustp2p.so"
OPENSSL_PATH="$PWD/examples/c_examples/3rd/openssl/linux_armv7"

# 使用环境变量设置链接器
export RUSTFLAGS="-C linker=${TOOLCHAIN_PATH}/bin/arm-linux-gnueabihf-gcc"

# 确保ARM目标存在
rustup target add armv7-unknown-linux-gnueabihf 2>/dev/null || true

# 设置OpenSSL环境变量以供Rust构建使用
export OPENSSL_DIR="$OPENSSL_PATH"
export OPENSSL_LIB_DIR="$OPENSSL_PATH/lib"
export OPENSSL_INCLUDE_DIR="$OPENSSL_PATH/include"
export OPENSSL_STATIC=0

# 构建Rust库
echo -e "${YELLOW}编译Rust库...${NC}"
# 使用新的特性名称
cargo build --release --target=armv7-unknown-linux-gnueabihf --features "ffi use-kcp aes-gcm-openssl chacha20-poly1305-openssl"

# 设置Rust库的RPATH
echo -e "${YELLOW}设置Rust库的RPATH...${NC}"
# 使用系统的patchelf命令而不是交叉编译工具链中的命令
patchelf --set-rpath '$ORIGIN' $RUST_LIB_PATH || echo -e "${YELLOW}警告: 无法设置RPATH，可能需要手动设置LD_LIBRARY_PATH${NC}"

# 创建CMake工具链文件
mkdir -p examples/c_examples
cat > examples/c_examples/arm-toolchain.cmake <<EOF
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

# 设置编译器
set(CMAKE_C_COMPILER ${TOOLCHAIN_PATH}/bin/arm-linux-gnueabihf-gcc)
set(CMAKE_CXX_COMPILER ${TOOLCHAIN_PATH}/bin/arm-linux-gnueabihf-g++)
set(CMAKE_SYSROOT ${TOOLCHAIN_PATH}/arm-linux-gnueabihf/libc)

# 设置包含目录
include_directories(SYSTEM
    "${TOOLCHAIN_PATH}/lib/gcc/arm-linux-gnueabihf/9.1.0/include"
    "${TOOLCHAIN_PATH}/lib/gcc/arm-linux-gnueabihf/9.1.0/include-fixed"
    "${TOOLCHAIN_PATH}/arm-linux-gnueabihf/include"
    "${TOOLCHAIN_PATH}/arm-linux-gnueabihf/libc/usr/include"
)

# 设置查找路径
set(CMAKE_FIND_ROOT_PATH \${CMAKE_SYSROOT})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# 设置编译标志
set(CMAKE_C_FLAGS "\${CMAKE_C_FLAGS} -march=armv7-a -mfloat-abi=hard -mfpu=neon")
EOF

# 构建C示例
echo -e "${YELLOW}编译C示例...${NC}"
mkdir -p $BUILD_DIR
cp $RUST_LIB_PATH $BUILD_DIR/
cd $BUILD_DIR

# 使用绝对路径指定工具链文件
TOOLCHAIN_ABS_PATH="$PWD/../arm-toolchain.cmake"
echo -e "${YELLOW}使用工具链文件: $TOOLCHAIN_ABS_PATH${NC}"

# 构建C示例
cmake .. -DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN_ABS_PATH -DCMAKE_BUILD_TYPE=Release -DCMAKE_SYSTEM_PROCESSOR=arm
cmake --build .

# 创建部署包
if [ -f "p2p_program" ]; then
    cd ../../..
    mkdir -p deploy/arm
    
    # 安装所有文件到部署目录
    cmake --install $BUILD_DIR --prefix=`pwd`/deploy/arm
    
    # 创建样例配置文件
    echo -e "# rustp2p P2P测试配置文件\n\n# 本地配置\nlocal_ip=127.0.0.1\ntcp_port=8080\nudp_port=8080\npassword=password123\ngroup_code=1\n\n# P2P配置\n# rendezvous_server=1.2.3.4:9000\npeer_address=127.0.0.1:8081\nis_server=false" > deploy/arm/bin/p2p_config.ini
    
    echo -e "${GREEN}构建成功! 部署文件位于: deploy/arm/bin/${NC}"
    echo -e "${GREEN}已启用特性: ffi use-kcp aes-gcm-openssl chacha20-poly1305-openssl${NC}"
    echo -e "${GREEN}使用方法: ./p2p_program -h 查看帮助${NC}"
else
    cd ../../..
    echo -e "${RED}构建失败!${NC}"
    exit 1
fi 