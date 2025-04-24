cmake_minimum_required(VERSION 3.10)
project(rustp2p_c_examples C)

# 设置C标准
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 设置头文件目录
if(DEFINED RUSTP2P_INCLUDE_DIR)
    set(INCLUDE_DIR ${RUSTP2P_INCLUDE_DIR})
else()
    set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../include)
endif()

# 设置OpenSSL库路径
set(OPENSSL_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../3rd/openssl/linux_x64)
set(OPENSSL_INCLUDE_DIR ${OPENSSL_ROOT_DIR}/include)
set(OPENSSL_LIBRARIES ${OPENSSL_ROOT_DIR}/lib)

# 设置Rust库路径
if(DEFINED RUSTP2P_LIB_PATH)
    set(RUSTP2P_LIB ${RUSTP2P_LIB_PATH})
else()
    set(RUSTP2P_LIB ${CMAKE_CURRENT_SOURCE_DIR}/../../target/release/librustp2p.so)
endif()

# 查找Rust库
message(STATUS "Found librustp2p.so at: ${RUSTP2P_LIB}")

# 添加可执行文件
# add_executable(p2p_test p2p_test.c)
# add_executable(p2p_file_transfer p2p_file_transfer.c)
add_executable(tcp_test tcp_test.c)

# 为目标添加头文件目录
# target_include_directories(p2p_test PRIVATE
#     ${INCLUDE_DIR}
# )

# target_include_directories(p2p_file_transfer PRIVATE
#     ${INCLUDE_DIR}
# )

target_include_directories(tcp_test PRIVATE
    ${INCLUDE_DIR}
)

# 链接库
# target_link_libraries(p2p_test
#     ${RUSTP2P_LIB}
#     pthread
#     dl
#     m
# )

# target_link_libraries(p2p_file_transfer
#     ${RUSTP2P_LIB}
#     pthread
#     dl
#     m
# )

target_link_libraries(tcp_test
    ${RUSTP2P_LIB}
    pthread
    dl
    m
)

# 链接OpenSSL库
# target_link_libraries(p2p_test
#     ${OPENSSL_LIBRARIES}/libssl.so.1.1
#     ${OPENSSL_LIBRARIES}/libcrypto.so.1.1
# )

# target_link_libraries(p2p_file_transfer
#     ${OPENSSL_LIBRARIES}/libssl.so.1.1
#     ${OPENSSL_LIBRARIES}/libcrypto.so.1.1
# )

target_link_libraries(tcp_test
    ${OPENSSL_LIBRARIES}/libssl.so.1.1
    ${OPENSSL_LIBRARIES}/libcrypto.so.1.1
)
