#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>

#include <rustp2p.h>

#define MAX_MSG_LEN 1024
#define DEFAULT_PASSWORD "password"
#define DEFAULT_CIPHER_TYPE 1 // 0=不使用加密, 1=AES-GCM, 2=ChaCha20-Poly1305

// 全局变量
EndpointHandle endpoint = NULL;
int running = 1;

// 信号处理函数
void handle_signal(int sig)
{
    printf("\n接收到信号 %d，正在退出...\n", sig);
    running = 0;
}

// 消息接收回调函数
void message_callback(const uint8_t *source_ip, const uint8_t *message_ptr, size_t message_len)
{
    // 检查source_ip是否为NULL或无效
    if (!source_ip)
    {
        printf("\n警告: 收到消息，但source_ip无效 (0x%p)\n> ", source_ip);
        fflush(stdout);
        return;
    }

    // 打印source_ip的原始内容，以便调试
    printf("\n收到消息，source_ip的原始内容: ");
    for (int i = 0; i < 4; i++)
    {
        printf("%02x ", source_ip[i]);
    }
    printf("\n");

    // 从源IP地址获取发送者的IP地址
    // 使用inet_ntop函数将IP地址转换为字符串
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, source_ip, ip_str, INET_ADDRSTRLEN);
    printf("发送者IP: %s\n", ip_str);

    // 检查message_ptr是否为NULL或无效
    if (!message_ptr)
    {
        printf("\n收到来自 %s 的消息，但message_ptr无效 (0x%p)\n> ", ip_str, message_ptr);
        fflush(stdout);
        return;
    }

    // 检查message_len是否为0或过大
    if (message_len == 0 || message_len > MAX_MSG_LEN)
    {
        printf("\n收到来自 %s 的消息，但长度无效 (%u)\n> ", ip_str, message_len);
        fflush(stdout);
        return;
    }

    // 打印message_ptr的原始内容，以便调试
    printf("message_ptr的原始内容: ");
    for (int i = 0; i < message_len && i < 16; i++)
    {
        printf("%02x ", ((uint8_t *)message_ptr)[i]);
    }
    printf("\n");

    // 检查message_ptr是否包含可打印字符
    int is_printable = 1;
    for (int i = 0; i < message_len && i < MAX_MSG_LEN; i++)
    {
        uint8_t ch = ((uint8_t *)message_ptr)[i];
        if (ch < 32 || ch > 126)
        {
            is_printable = 0;
            break;
        }
    }

    if (is_printable)
    {
        // 打印接收到的消息
        const char *message = (const char *)message_ptr;
        printf("\n收到来自 %s 的消息: %.*s\n> ", ip_str, (int)message_len, message);
    }
    else
    {
        printf("\n收到来自 %s 的消息，但消息内容不可打印\n> ", ip_str);
    }
    fflush(stdout);
}

// 接收消息的线程函数
void *receive_thread(void *arg)
{
    while (running)
    {
        // 等待一段时间
        usleep(10000); // 10ms
    }
    return NULL;
}

// 输入处理线程函数
void *input_thread(void *arg)
{
    char input[MAX_MSG_LEN];
    char *peer_ip = (char *)arg;

    while (running)
    {
        printf("> ");
        fflush(stdout);

        if (!fgets(input, MAX_MSG_LEN, stdin))
        {
            break;
        }

        // 移除换行符
        input[strcspn(input, "\n")] = 0;

        if (strcmp(input, "exit") == 0)
        {
            running = 0;
            break;
        }

        // 转换IP地址为网络字节序
        struct in_addr peer_addr;
        inet_pton(AF_INET, peer_ip, &peer_addr);
        uint32_t peer_ip_uint32 = ntohl(peer_addr.s_addr);

        printf("发送消息到IP: %s (uint32: %u)\n", peer_ip, peer_ip_uint32);

        // 发送消息
        if (rustp2p_send_message(endpoint, peer_ip_uint32, (const uint8_t *)input, strlen(input)))
        {
            printf("消息已发送\n");
        }
        else
        {
            printf("发送消息失败\n");
        }
    }

    return NULL;
}

int main(int argc, char *argv[])
{
    if (argc < 5)
    {
        printf("用法: %s <本地IP> <端口> <组代码> <模式> [对等节点地址] [加密类型]\n", argv[0]);
        printf("模式: server 或 client\n");
        printf("对等节点地址格式: <IP>:<TCP端口>:<UDP端口>\n");
        printf("加密类型: 0=不使用加密, 1=AES-GCM, 2=ChaCha20-Poly1305 (默认: 1)\n");
        return 1;
    }

    // 解析命令行参数
    char *local_ip = argv[1];
    int port = atoi(argv[2]);
    int group_code = atoi(argv[3]);
    char *mode = argv[4];

    // 解析加密类型参数
    int cipher_type = DEFAULT_CIPHER_TYPE;
    if (argc >= 7)
    {
        cipher_type = atoi(argv[6]);
        if (cipher_type < 0 || cipher_type > 2) // 0=不使用加密, 1=AES-GCM, 2=ChaCha20-Poly1305
        {
            printf("无效的加密类型: %d\n", cipher_type);
            printf("使用默认加密类型: %d\n", DEFAULT_CIPHER_TYPE);
            cipher_type = DEFAULT_CIPHER_TYPE;
        }
    }

    // 转换IP地址为网络字节序
    struct in_addr addr;
    inet_pton(AF_INET, local_ip, &addr);
    uint32_t ip_uint32 = ntohl(addr.s_addr);

    printf("初始化 rustp2p...\n");
    printf("本地IP: %s (uint32: %u)\n", local_ip, ip_uint32);
    printf("端口: %d\n", port);
    printf("组代码: %d\n", group_code);
    printf("模式: %s\n", mode);
    printf("加密类型: %d (%s)\n", cipher_type,
           cipher_type == 0 ? "不使用加密" : cipher_type == 1 ? "AES-GCM"
                                                              : "ChaCha20-Poly1305");

    // 初始化rustp2p
    printf("调用 rustp2p_init(ip=%u, tcp_port=%d, udp_port=%d, group_code=%d, password=\"%s\", cipher_type=%d)\n",
           ip_uint32, port, port, group_code, DEFAULT_PASSWORD, cipher_type);

    endpoint = rustp2p_init(ip_uint32, port, port, group_code, DEFAULT_PASSWORD, cipher_type);
    if (!endpoint)
    {
        printf("初始化失败! 返回值为NULL\n");
        return 1;
    }
    printf("初始化成功!\n");

    // 设置消息回调
    rustp2p_start_receiver(endpoint, message_callback);

    // 如果是客户端模式，添加对等节点
    if (strcmp(mode, "client") == 0)
    {
        if (argc < 6)
        {
            printf("客户端模式需要指定对等节点地址\n");
            rustp2p_cleanup(endpoint);
            return 1;
        }

        char *peer = argv[5];
        char peer_ip[64];
        int peer_tcp_port, peer_udp_port;

        // 解析对等节点地址
        if (sscanf(peer, "%[^:]:%d:%d", peer_ip, &peer_tcp_port, &peer_udp_port) != 3)
        {
            printf("对等节点地址格式错误，应为: <IP>:<TCP端口>:<UDP端口>\n");
            rustp2p_cleanup(endpoint);
            return 1;
        }

        // 添加TCP对等节点
        char tcp_addr[128];
        sprintf(tcp_addr, "tcp://%s:%d", peer_ip, peer_tcp_port);
        printf("添加对等节点: %s\n", tcp_addr);

        if (rustp2p_add_peer(endpoint, tcp_addr))
        {
            printf("成功添加对等节点: %s\n", tcp_addr);
        }
        else
        {
            printf("添加对等节点失败: %s\n", tcp_addr);
            rustp2p_cleanup(endpoint);
            return 1;
        }
    }

    // 创建接收线程
    pthread_t tid;
    printf("启动接收循环...\n");
    pthread_create(&tid, NULL, receive_thread, NULL);

    // 设置信号处理
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // 主循环
    if (strcmp(mode, "client") == 0)
    {
        // 客户端模式：发送消息
        printf("客户端模式启动，可以发送消息\n");
        printf("输入格式: <消息>\n");
        printf("输入'exit'退出\n");

        // 等待路由建立
        printf("等待路由建立 (3秒)...\n");
        sleep(1);
        printf("尝试建立路由...\n");

        // 触发路由发现
        // 提取对等节点IP
        char *peer_ip = strtok(argv[5], ":");
        printf("\n提取的IP地址: %s\n", peer_ip);

        // 使用对等节点的IP作为目标ID
        struct in_addr peer_addr;
        inet_pton(AF_INET, peer_ip, &peer_addr);
        uint32_t target_id = ntohl(peer_addr.s_addr);
        printf("\n目标ID: %u\n", target_id);
        if (rustp2p_trigger_route_discovery(endpoint, target_id, 3))
        {
            printf("路由建立成功!\n");
        }
        else
        {
            printf("路由建立失败!\n");
        }

        char input[MAX_MSG_LEN];

        // 创建输入处理线程
        pthread_t input_tid;
        pthread_create(&input_tid, NULL, input_thread, peer_ip);

        // 等待线程结束
        while (running)
        {
            sleep(1);
        }

        // 等待输入线程结束
        pthread_join(input_tid, NULL);
    }
    else
    {
        // 服务器模式：等待接收消息
        printf("服务器模式启动，等待接收消息...\n");
        printf("按Ctrl+C退出\n");

        while (running)
        {
            sleep(1);
        }
    }

    // 清理
    running = 0;
    pthread_join(tid, NULL);
    rustp2p_cleanup(endpoint);
    printf("已退出\n");

    return 0;
}
