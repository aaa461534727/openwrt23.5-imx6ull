#include "sniffer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#define MAX_PAYLOAD 8192

// 进程异常退出时进入该函数
static void main_stop_handle(int sig) {
    exit(0);
}

//提取rid数据
void get_data_from_index(unsigned char *data, int data_size, int start_index, int len, unsigned char *buffer) {
    if (start_index < 0 || start_index >= data_size) {
        printf("Error: start_index out of bounds\n");
        return;
    }
    if (start_index + len > data_size) {
        printf("Error: len is too large, exceeds array bounds\n");
        return;
    }

    // 使用memcpy从data数组复制数据到buffer
    memcpy(buffer, data + start_index, len);
}

// 发送数据到内核
void send_data_to_kernel(int sock_fd, struct sockaddr_nl *dest_addr,
                        unsigned char data_type, const void *data, int data_len) {
    struct nlmsghdr *nlh;
    struct msghdr msg;
    struct iovec iov;
    char buffer[MAX_PAYLOAD] = {0};

    // 设置Netlink消息头
    nlh = (struct nlmsghdr *)buffer;
    nlh->nlmsg_len = NLMSG_LENGTH(1 + data_len); // 类型字节 + 数据长度
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    // 填充消息内容
    buffer[NLMSG_HDRLEN] = data_type; // 第一个字节为数据类型
    memcpy(buffer + NLMSG_HDRLEN + 1, data, data_len); // 实际数据

    // 设置IO向量
    iov.iov_base = buffer;
    iov.iov_len = nlh->nlmsg_len;

    // 设置消息结构
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)dest_addr;
    msg.msg_namelen = sizeof(*dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    // 发送消息
    if (sendmsg(sock_fd, &msg, 0) < 0) {
        perror("sendmsg failed");
    }
}

int main(int argc, char *argv[]) {
    // 注册信号
    signal(SIGTSTP, main_stop_handle);   // Ctrl+Z
    signal(SIGINT, main_stop_handle);    // Ctrl+C
    signal(SIGTERM, main_stop_handle);   // 终止信号

    // Netlink 初始化
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct msghdr msg;
    struct iovec iov;
    int sock_fd;

    // 创建套接字
    sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (sock_fd < 0) {
        perror("socket failed");
        return -1;
    }

    // 绑定地址
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid(); // 绑定当前PID
    if (bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
        perror("bind failed");
        close(sock_fd);
        return -1;
    }

    // 准备接收消息
    char buffer[MAX_PAYLOAD] = {0};
    nlh = (struct nlmsghdr *)buffer;
    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    // 构造注册消息
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;      // 目标为内核
    dest_addr.nl_groups = 0;

    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    strcpy(NLMSG_DATA(nlh), "REGISTER"); // 发送注册命令

    // 发送消息
    if (sendmsg(sock_fd, &msg, 0) < 0) {
        perror("sendmsg failed");
        close(sock_fd);
        return -1;
    }
    printf("Sent registration request\n");

    // 发送三种类型数据给内核
    const char *test_str = "Hello from user space!";
    send_data_to_kernel(sock_fd, &dest_addr, TYPE_STRING, test_str, strlen(test_str));

    unsigned char test_hex[] = {0xDE, 0xAD, 0xBE, 0xEF};
    send_data_to_kernel(sock_fd, &dest_addr, TYPE_HEX, test_hex, sizeof(test_hex));

    int test_int = -50;
    send_data_to_kernel(sock_fd, &dest_addr, TYPE_INT, &test_int, sizeof(test_int));

    int test_float = 12345;
    send_data_to_kernel(sock_fd, &dest_addr, TYPE_FLOAT, &test_float, sizeof(test_float));

    // 循环接收数据
    printf("User: Waiting for kernel messages...\n");
    while (1) {
        ssize_t len = recvmsg(sock_fd, &msg, 0);
        if (len < 0) {
            perror("recvmsg failed");
            continue ;
        }

        // 计算有效载荷长度
        size_t payload_len = nlh->nlmsg_len - NLMSG_HDRLEN;
        unsigned char *payload = NLMSG_DATA(nlh);

        // 直接打印接收到的文本信息
        // 内核已经格式化好了，我们只需要原样输出
        fwrite(payload, 1, payload_len, stdout);
        fflush(stdout);
    }

    close(sock_fd);
    return 0;
}
