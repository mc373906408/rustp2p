#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>    // Include for bool type
#include <sys/select.h> // Added for select()
#include <sys/time.h>   // Added for struct timeval
#include <ctype.h>      // Added for tolower()
#include "rustp2p.h"    // Assumes rustp2p.h will be regenerated with new FFI

// Global state
EndpointHandle endpoint_handle = NULL;
volatile sig_atomic_t keep_running = 1;
volatile sig_atomic_t shutdown_initiated = 0; // Flag to prevent double shutdown
volatile sig_atomic_t sigint_received = 0;    // Flag set by signal handler

// Store server info when running as client
bool is_server_mode = true; // Assume server unless -c is used
uint32_t server_ip_host = 0;

// --- FFI Function Declarations (matching rewritten ffi.rs) ---
// 移除重复的函数声明，因为已经包含了rustp2p.h头文件

// --- Helper Functions ---

// --- Callback and Signal Handler ---

// Message callback function - Handles both server relay and client receive
void message_callback(const uint8_t *source_ip_ptr, const uint8_t *message_ptr, size_t message_len, TransportProtocolC protocol)
{
    // 直接从正确顺序的IP字节构建字符串
    char source_ip_str[INET_ADDRSTRLEN] = {0};
    snprintf(source_ip_str, sizeof(source_ip_str), "%u.%u.%u.%u",
             source_ip_ptr[0], source_ip_ptr[1], source_ip_ptr[2], source_ip_ptr[3]);

    // Temporary buffer for potential parsing/forwarding (ensure null termination)
    char received_message[1024 + 64]; // Extra space for prefix "[From XXX.XXX.XXX.XXX]: "
    size_t copy_len = message_len < (sizeof(received_message) - 64) ? message_len : (sizeof(received_message) - 64 - 1);
    memcpy(received_message, message_ptr, copy_len);
    received_message[copy_len] = '\0'; // Null-terminate the copied message

    // --- Server Relay Logic ---
    if (is_server_mode && endpoint_handle)
    { // Check if running as server
        char *separator = strchr(received_message, ':');

        // Check if format is <target_ip>:<content>
        if (separator != NULL && separator != received_message && *(separator + 1) != '\0')
        {
            *separator = '\0'; // Null-terminate the target IP part
            const char *target_ip_str = received_message;
            const char *actual_content = separator + 1;

            uint32_t target_ip_host = server_ip_host;

            if (target_ip_host != 0)
            { // Validate target IP
                printf("[Server] 收到来自 %s 的消息，准备转发给 %s\n", source_ip_str, target_ip_str);

                // Format message for forwarding: "[From source_ip]: content"
                char forward_message[1024 + 64]; // Ensure buffer is large enough
                snprintf(forward_message, sizeof(forward_message), "[From %s]: %s", source_ip_str, actual_content);

                // Use the async send function for forwarding
                printf("[Server] 提交异步转发任务给 %s...\n", target_ip_str); // Log submission
                int32_t protocol_used = -1;
                if (!rustp2p_send_message_async(endpoint_handle, target_ip_str, (const uint8_t *)forward_message, strlen(forward_message), &protocol_used))
                {
                    // Log only if spawning the task failed
                    fprintf(stderr, "[Server] 提交异步转发任务失败 for %s (无法生成任务)\n", target_ip_str);
                }
                // Message handling submitted, return immediately
                return;
            }
            else
            {
                printf("[Server] 收到来自 %s 的消息，但目标IP '%s' 无效，不转发。\n", source_ip_str, target_ip_str);
                return; // Let's return to avoid printing the invalid relay message
            }
        }
        // If not in relay format, fall through to print normally (or handle server-directed messages)
    }

    // --- Default Print Logic (Client or non-relay Server message) ---
    // Avoid printing if shutdown has started
    if (keep_running)
    {
        // 直接显示消息内容，不显示协议信息
        printf("\n[Callback] 收到来自 %s 的消息: %s\n> ", source_ip_str, received_message);
        fflush(stdout); // Ensure prompt is reprinted after message
    }
}

// Signal handler for SIGINT (Ctrl+C)
void sigint_handler(int sig)
{
    (void)sig;
    sigint_received = 1;
    keep_running = 0;
}

// --- Main Logic ---

void print_usage(const char *prog_name)
{
    fprintf(stderr, "用法: %s <本地IP> <TCP端口> <UDP端口> <组代码> <模式> [服务器地址]\n", prog_name);
    fprintf(stderr, "  模式:\n");
    fprintf(stderr, "    -s: 服务器模式 (仅接收和转发)\n");
    fprintf(stderr, "    -c <服务器地址>: 客户端模式 (连接到服务器并收发消息, 格式: <ip>:<port>)\n"); // Clarified peer address is server
}

int main(int argc, char *argv[])
{
    if (argc < 6)
    {
        print_usage(argv[0]);
        return 1;
    }

    const char *local_ip_str = argv[1];
    uint16_t local_tcp_port = (uint16_t)atoi(argv[2]);
    uint16_t local_udp_port = (uint16_t)atoi(argv[3]);
    uint32_t group_code = (uint32_t)strtoul(argv[4], NULL, 10);
    const char *mode = argv[5];
    const char *server_address_str = NULL;

    // --- Argument Parsing ---
    if (strcmp(mode, "-s") == 0)
    {
        printf("启动模式: 服务器\n");
        is_server_mode = true;
    }
    else if (strcmp(mode, "-c") == 0)
    {
        if (argc < 7)
        {
            fprintf(stderr, "错误: 客户端模式需要指定服务器地址\n");
            print_usage(argv[0]);
            return 1;
        }
        server_address_str = argv[6];
        printf("启动模式: 客户端, 连接服务器: %s\n", server_address_str);
        is_server_mode = false;

        // --- Store Server IP for Client ---
        char server_ip_part[INET_ADDRSTRLEN] = {0};
        const char *colon = strchr(server_address_str, ':');
        if (colon)
        {
            size_t len = colon - server_address_str;
            if (len < sizeof(server_ip_part))
            {
                strncpy(server_ip_part, server_address_str, len);
                server_ip_part[len] = '\0';

                // 将服务器IP地址直接存储，不需要转换为整数
                struct in_addr addr;
                if (inet_pton(AF_INET, server_ip_part, &addr) == 1)
                {
                    server_ip_host = ntohl(addr.s_addr);
                }
                else
                {
                    server_ip_host = 0;
                }
            }
        }
        else
        {
            // Assume the whole string is an IP if no colon
            strncpy(server_ip_part, server_address_str, sizeof(server_ip_part) - 1);
            server_ip_part[sizeof(server_ip_part) - 1] = '\0';

            // 将服务器IP地址直接存储，不需要转换为整数
            struct in_addr addr;
            if (inet_pton(AF_INET, server_ip_part, &addr) == 1)
            {
                server_ip_host = ntohl(addr.s_addr);
            }
            else
            {
                server_ip_host = 0;
            }
        }

        if (server_ip_host == 0)
        {
            fprintf(stderr, "错误: 无法解析服务器IP地址: %s\n", server_ip_part);
            return 1;
        }
        printf("服务器 IP (Host Order): %u\n", server_ip_host); // Debug print
    }
    else
    {
        fprintf(stderr, "错误: 无效模式 '%s'\n", mode);
        print_usage(argv[0]);
        return 1;
    }

    // 检查本地IP格式是否有效
    struct in_addr addr;
    if (inet_pton(AF_INET, local_ip_str, &addr) != 1)
    {
        fprintf(stderr, "错误: 无效的本地IP地址: %s\n", local_ip_str);
        return 1;
    }

    // --- Initialization ---
    printf("初始化 RustP2P (TCP 端口: %u, UDP 端口: %u, 无加密)...\n", local_tcp_port, local_udp_port);
    endpoint_handle = rustp2p_init(
        local_ip_str,
        local_tcp_port,
        local_udp_port,
        group_code,
        "", // No password
        0,  // CipherType_None
        0   // use_kcp = 0
    );

    if (!endpoint_handle)
    {
        fprintf(stderr, "错误: RustP2P 初始化失败\n");
        return 1;
    }
    printf("RustP2P 初始化成功!\n");

    // --- Signal Handling ---
    signal(SIGINT, sigint_handler);

    // --- Add Server as Peer (Client Mode) ---
    if (!is_server_mode && server_address_str)
    {
        printf("添加服务器对等节点: %s...\n", server_address_str);
        if (!rustp2p_add_peer(endpoint_handle, server_address_str))
        {
            fprintf(stderr, "错误: 添加服务器对等节点失败.\n");
            rustp2p_cleanup(endpoint_handle, 0);
            return 1;
        }
        printf("服务器对等节点添加成功.\n");
        printf("等待短暂时间让网络准备...\n");
        sleep(2); // Give time for potential connection/route discovery
    }

    // --- Start Receiver ---
    printf("启动消息接收器...\n");
    if (!rustp2p_start_receiver(endpoint_handle, message_callback))
    {
        fprintf(stderr, "错误: 启动消息接收器失败\n");
        rustp2p_cleanup(endpoint_handle, 0);
        return 1;
    }

    // --- Main Input Loop (Client Mode Only) ---
    if (!is_server_mode)
    {
        char input_buffer[1024];
        fd_set readfds;
        struct timeval tv;
        int select_result;

        printf("客户端准备就绪. 输入 '<目标IP>:<消息>' 直接发送消息给目标IP，或按 Ctrl+C 退出。\n> ");
        fflush(stdout);

        while (keep_running)
        {
            FD_ZERO(&readfds);
            FD_SET(STDIN_FILENO, &readfds); // Monitor standard input

            tv.tv_sec = 0;
            tv.tv_usec = 100000; // 100ms timeout

            select_result = select(STDIN_FILENO + 1, &readfds, NULL, NULL, &tv);

            if (select_result == -1)
            {
                if (errno == EINTR)
                {
                    errno = 0;
                    continue; // Check keep_running
                }
                else
                {
                    perror("select error");
                    keep_running = 0;
                    break;
                }
            }
            else if (select_result > 0)
            {
                if (FD_ISSET(STDIN_FILENO, &readfds))
                {
                    clearerr(stdin);
                    if (fgets(input_buffer, sizeof(input_buffer), stdin) == NULL)
                    {
                        if (feof(stdin))
                        {
                            printf("\n输入结束 (EOF)，关闭...\n");
                            keep_running = 0;
                        }
                        else if (errno == EINTR)
                        {
                            errno = 0;
                        }
                        else
                        {
                            perror("\n读取标准输入时出错");
                            keep_running = 0;
                        }
                        if (!keep_running)
                            break;
                        if (keep_running)
                        {
                            printf("> ");
                            fflush(stdout);
                        }
                        continue;
                    }

                    input_buffer[strcspn(input_buffer, "\n")] = 0;

                    if (strlen(input_buffer) == 0)
                    {
                        printf("> ");
                        fflush(stdout);
                        continue;
                    }

                    char *colon_ptr = strchr(input_buffer, ':');
                    if (colon_ptr == NULL || colon_ptr == input_buffer || *(colon_ptr + 1) == '\0')
                    {
                        fprintf(stderr, "格式错误: 请输入 '<目标IP>:<消息>'\n");
                    }
                    else
                    {
                        // 解析目标IP和消息
                        char target_ip_str[INET_ADDRSTRLEN];
                        size_t ip_len = colon_ptr - input_buffer;
                        if (ip_len >= INET_ADDRSTRLEN)
                        {
                            fprintf(stderr, "IP地址格式错误\n");
                        }
                        else
                        {
                            strncpy(target_ip_str, input_buffer, ip_len);
                            target_ip_str[ip_len] = '\0';

                            // 验证IP地址格式
                            struct in_addr addr;
                            uint32_t target_ip_host = 0;
                            if (inet_pton(AF_INET, target_ip_str, &addr) != 1)
                            {
                                fprintf(stderr, "无效的目标IP地址: %s\n", target_ip_str);
                            }
                            else
                            {
                                // 获取网络字节序的IP整数值
                                target_ip_host = ntohl(addr.s_addr);

                                // 获取消息内容
                                const char *message_content = colon_ptr + 1;

                                // 直接发送消息给目标IP
                                printf("正在发送消息给 %s: '%s'...\n", target_ip_str, message_content);

                                // 默认添加对等节点的两种协议路径，让库自动选择最佳协议
                                char tcp_peer_addr[64], udp_peer_addr[64];
                                bool tcp_added = false, udp_added = false;

                                // 添加TCP协议路径
                                snprintf(tcp_peer_addr, sizeof(tcp_peer_addr), "tcp://%s:%d", target_ip_str, local_tcp_port);
                                if (rustp2p_add_peer(endpoint_handle, tcp_peer_addr))
                                {
                                    printf("已添加TCP对等节点 %s\n", tcp_peer_addr);
                                    tcp_added = true;
                                }

                                // 添加UDP协议路径
                                snprintf(udp_peer_addr, sizeof(udp_peer_addr), "udp://%s:%d", target_ip_str, local_udp_port);
                                if (rustp2p_add_peer(endpoint_handle, udp_peer_addr))
                                {
                                    printf("已添加UDP对等节点 %s\n", udp_peer_addr);
                                    udp_added = true;
                                }

                                if (!tcp_added && !udp_added)
                                {
                                    printf("警告: 无法添加对等节点，尝试直接发送...\n");
                                }
                                else
                                {
                                    // 给网络一点时间建立连接
                                    sleep(1);
                                }

                                // 发送消息给目标IP
                                int32_t protocol_used = -1;
                                if (!rustp2p_send_message(endpoint_handle, target_ip_str,
                                                          (const uint8_t *)message_content,
                                                          strlen(message_content),
                                                          &protocol_used))
                                {
                                    fprintf(stderr, "发送消息失败，请确认目标节点在线并检查网络连接\n");
                                }
                                else
                                {
                                    printf("消息发送成功!\n");
                                }
                            }
                        }
                    }
                    printf("> ");
                    fflush(stdout);
                }
            }
        }
    }
    else
    {
        printf("服务器正在运行，等待客户端连接和消息转发... 按 Ctrl+C 退出。\n");
        while (keep_running)
        {
            sleep(1);
            if (sigint_received)
            {
                printf("\n服务器收到 SIGINT 信号，准备退出...\n");
                break;
            }
        }
    }

    printf("主循环退出。开始清理资源...\n");

    if (endpoint_handle && shutdown_initiated == 0)
    {
        shutdown_initiated = 1;
        printf("调用 rustp2p_cleanup 清理资源...\n");
        if (!rustp2p_cleanup(endpoint_handle, 1000))
        {
            fprintf(stderr, "[Main] 资源清理过程中出现问题.\n");
        }
        else
        {
            printf("资源清理完成.\n");
        }
        endpoint_handle = NULL;
    }
    else if (endpoint_handle)
    {
        printf("资源清理已经开始，跳过...\n");
    }

    printf("程序退出。\n");
    return 0;
}