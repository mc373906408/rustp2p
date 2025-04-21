#!/bin/bash
set -e

# 颜色代码
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

# 基本设置
ROOT_DIR=$PWD
BUILD_DIR="examples/c_examples/build"
RUST_LIB_PATH="target/release/librustp2p.so"
OPENSSL_DIR="3rd/openssl/linux_x64"

# 设置 OpenSSL 库的位置
export OPENSSL_DIR=$ROOT_DIR/$OPENSSL_DIR
export OPENSSL_INCLUDE_DIR=$OPENSSL_DIR/include
export OPENSSL_LIB_DIR=$OPENSSL_DIR/lib

# 构建Rust库
echo -e "${YELLOW}编译Rust库(x64版本)...${NC}"
cargo build --release --features "ffi use-kcp aes-gcm-openssl chacha20-poly1305-openssl"

# 设置Rust库的RPATH
echo -e "${YELLOW}设置Rust库的RPATH...${NC}"
patchelf --set-rpath '$ORIGIN' $RUST_LIB_PATH || echo -e "${YELLOW}警告: 无法设置RPATH，可能需要手动设置LD_LIBRARY_PATH${NC}"

# 创建构建目录
mkdir -p $BUILD_DIR
cp $RUST_LIB_PATH $BUILD_DIR/

# 复制OpenSSL库文件到构建目录
echo -e "${YELLOW}复制OpenSSL库文件到构建目录...${NC}"
cp $OPENSSL_LIB_DIR/libssl.so.1.1 $BUILD_DIR/
cp $OPENSSL_LIB_DIR/libcrypto.so.1.1 $BUILD_DIR/

# 构建C示例
echo -e "${YELLOW}编译C示例(x64版本)...${NC}"
cd $BUILD_DIR

# 使用CMake构建
cmake .. -DCMAKE_BUILD_TYPE=Release -DRUSTP2P_INCLUDE_DIR=$ROOT_DIR/include
cmake --build .

# 检查构建结果
if [ -f "p2p_test" ]; then
    # 设置p2p_test的RPATH
    echo -e "${YELLOW}设置p2p_test的RPATH...${NC}"
    patchelf --set-rpath '$ORIGIN' p2p_test || echo -e "${YELLOW}警告: 无法设置RPATH，可能需要手动设置LD_LIBRARY_PATH${NC}"

    cd $ROOT_DIR
    echo -e "${GREEN}构建成功! 可执行文件位于: examples/c_examples/build/p2p_test${NC}"
    echo -e "${GREEN}已启用特性: ffi use-kcp aes-gcm-openssl chacha20-poly1305-openssl${NC}"
    echo -e "${GREEN}使用方法: cd examples/c_examples/build && ./p2p_test <本地IP> <端口> <组代码> <模式> [对等节点地址]${NC}"
else
    cd $ROOT_DIR
    echo -e "${RED}构建失败!${NC}"
    exit 1
fi
