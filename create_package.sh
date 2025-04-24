#!/bin/bash

# Script to create a deployable package for rustp2p test program

# 设置输出文件名
PACKAGE_NAME="rustp2p_package.tar.gz"
TEMP_DIR="temp_package"

# 确保开始前删除旧文件
rm -f $PACKAGE_NAME
rm -rf $TEMP_DIR

# 创建临时目录
mkdir -p $TEMP_DIR

echo "正在创建P2P测试包..."

# 复制必要文件
echo "复制可执行文件..."
cp examples/c_examples/build/tcp_test $TEMP_DIR/ || { echo "错误: 可执行文件未找到，请先运行 ./build-x64.sh"; exit 1; }

echo "复制库文件..."
cp target/release/librustp2p.so $TEMP_DIR/ || { echo "错误: librustp2p.so 未找到，请先运行 ./build-x64.sh"; exit 1; }

echo "复制OpenSSL依赖库..."
cp examples/c_examples/build/libssl.so.1.1 $TEMP_DIR/ 2>/dev/null || echo "警告: libssl.so.1.1 未找到，可能会影响运行"
cp examples/c_examples/build/libcrypto.so.1.1 $TEMP_DIR/ 2>/dev/null || echo "警告: libcrypto.so.1.1 未找到，可能会影响运行"

# 复制协议信息脚本
echo "复制协议信息脚本..."
cp get_protocol_info.sh $TEMP_DIR/ || echo "警告: get_protocol_info.sh 未找到，将不包含在打包中"
chmod +x $TEMP_DIR/get_protocol_info.sh 2>/dev/null

# 创建运行指导
echo "创建README文件..."
cat > $TEMP_DIR/README.txt << EOF
RustP2P测试程序使用指南
======================

1. 解压文件
   tar -xzf $PACKAGE_NAME

2. 设置库路径
   export LD_LIBRARY_PATH="\$PWD:\$LD_LIBRARY_PATH"

3. 运行服务器模式
   ./tcp_test <本地IP> <TCP端口> <UDP端口> <组代码> -s

4. 运行客户端模式
   ./tcp_test <本地IP> <TCP端口> <UDP端口> <组代码> -c <服务器地址>

5. 客户端发送消息
   连接后，输入格式: <目标IP>:<消息内容>
   消息将直接发送给目标IP

注意：
- 确保所有节点使用相同的组代码
- 所有节点的TCP和UDP端口都必须开放
EOF

echo "创建启动脚本..."
cat > $TEMP_DIR/run_server.sh << EOF
#!/bin/bash
# 服务器模式启动脚本

# 设置库路径
export LD_LIBRARY_PATH="\$PWD:\$LD_LIBRARY_PATH"

# 获取本机IP
IP=\$(hostname -I | awk '{print \$1}')
if [ -z "\$IP" ]; then
    IP="127.0.0.1"
    echo "警告: 无法获取本机IP，使用 \$IP"
fi

# 设置端口和组代码
TCP_PORT=23333
UDP_PORT=23334
GROUP_CODE=12345678

echo "启动P2P服务器节点："
echo "IP: \$IP, TCP端口: \$TCP_PORT, UDP端口: \$UDP_PORT, 组代码: \$GROUP_CODE"
echo ""

# 运行服务器
./tcp_test \$IP \$TCP_PORT \$UDP_PORT \$GROUP_CODE -s
EOF

cat > $TEMP_DIR/run_client.sh << EOF
#!/bin/bash
# 客户端模式启动脚本

# 设置库路径
export LD_LIBRARY_PATH="\$PWD:\$LD_LIBRARY_PATH"

# 获取本机IP
IP=\$(hostname -I | awk '{print \$1}')
if [ -z "\$IP" ]; then
    IP="127.0.0.1"
    echo "警告: 无法获取本机IP，使用 \$IP"
fi

# 设置端口和组代码
TCP_PORT=23335
UDP_PORT=23336
GROUP_CODE=12345678

# 检查是否提供了服务器地址
if [ -z "\$1" ]; then
    echo "错误: 请提供服务器地址"
    echo "用法: \$0 <服务器IP>:<端口>"
    echo "例如: \$0 192.168.1.100:23333"
    exit 1
fi

SERVER_ADDR="\$1"

echo "启动P2P客户端节点："
echo "本地IP: \$IP, TCP端口: \$TCP_PORT, UDP端口: \$UDP_PORT, 组代码: \$GROUP_CODE"
echo "连接服务器: \$SERVER_ADDR"
echo ""

# 运行客户端
./tcp_test \$IP \$TCP_PORT \$UDP_PORT \$GROUP_CODE -c \$SERVER_ADDR
EOF

# 设置权限
chmod +x $TEMP_DIR/run_server.sh
chmod +x $TEMP_DIR/run_client.sh
chmod +x $TEMP_DIR/tcp_test

# 创建tar包
echo "创建归档文件 $PACKAGE_NAME..."
tar -czf $PACKAGE_NAME -C $TEMP_DIR .

# 清理临时目录
rm -rf $TEMP_DIR

echo "==============================================="
echo "归档包创建成功: $PACKAGE_NAME"
echo "内容:"
echo "- tcp_test (可执行文件)"
echo "- librustp2p.so (Rust P2P库)"
echo "- libssl.so.1.1 & libcrypto.so.1.1 (OpenSSL库)"
echo "- get_protocol_info.sh (协议信息脚本)"
echo "- README.txt (使用说明)"
echo "- run_server.sh (服务器启动脚本)"
echo "- run_client.sh (客户端启动脚本)"
echo ""
echo "部署指南:"
echo "1. 将 $PACKAGE_NAME 上传到目标服务器"
echo "2. 解压: tar -xzf $PACKAGE_NAME"
echo "3. 服务器模式: ./run_server.sh"
echo "4. 客户端模式: ./run_client.sh <服务器IP>:<端口>"
echo "===============================================" 