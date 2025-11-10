#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <termios.h>
#include <string.h>
#include <sys/select.h>
#include <errno.h>

#define SERIAL_PORT "/dev/ttyS2"  // 根据实际设备修改
#define BAUDRATE B115200            // 常用波特率
#define BUFFER_SIZE 256

int serial_init(const char *port, speed_t baudrate) {
    int fd = open(port, O_RDWR | O_NOCTTY | O_NDELAY);
    if (fd == -1) {
        perror("open_port");
        return -1;
    }

    struct termios tty;
    memset(&tty, 0, sizeof(tty));
    
    // 获取当前配置
    if (tcgetattr(fd, &tty) != 0) {
        perror("tcgetattr");
        close(fd);
        return -1;
    }

    // 基础配置
    cfsetispeed(&tty, baudrate);
    cfsetospeed(&tty, baudrate);
    tty.c_cflag |= (CLOCAL | CREAD);    // 本地连接，启用接收
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= CS8;                 // 8位数据位
    tty.c_cflag &= ~PARENB;             // 无奇偶校验
    tty.c_cflag &= ~CSTOPB;             // 1位停止位
    tty.c_cflag &= ~CRTSCTS;            // 禁用硬件流控

    // 输入模式配置
    tty.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);  // 非规范模式
    tty.c_iflag &= ~(IXON | IXOFF | IXANY);          // 禁用软件流控

    // 超时设置
    tty.c_cc[VMIN]  = 0;    // 非阻塞读取
    tty.c_cc[VTIME] = 10;   // 1秒超时

    // 应用配置
    if (tcsetattr(fd, TCSANOW, &tty) != 0) {
        perror("tcsetattr");
        close(fd);
        return -1;
    }

    tcflush(fd, TCIFLUSH);
    return fd;
}

int main() {
    int fd = serial_init(SERIAL_PORT, BAUDRATE);
    if (fd == -1) {
        fprintf(stderr, "Failed to initialize serial port\n");
        return EXIT_FAILURE;
    }

    // 配置非阻塞模式
    fcntl(fd, F_SETFL, O_NONBLOCK);

    char tx_buffer[] = "Hello Serial Loopback!\n";
    char rx_buffer[BUFFER_SIZE];
    fd_set readfds;
    struct timeval tv;
    int total_sent = 0, total_received = 0;

    while(1) {
        // 发送数据
        ssize_t sent = write(fd, tx_buffer, strlen(tx_buffer));
        if (sent > 0) {
            total_sent += sent;
            printf("Sent %zd bytes (Total: %d)\n", sent, total_sent);
        }

        // 设置select监听
        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int ret = select(fd+1, &readfds, NULL, NULL, &tv);
        if (ret == -1) {
            perror("select");
            break;
        } else if (ret) {
            // 接收数据
            ssize_t received = read(fd, rx_buffer, BUFFER_SIZE-1);
            if (received > 0) {
                total_received += received;
                rx_buffer[received] = '\0';
                printf("Received %zd bytes (Total: %d)\n", received, total_received);
                printf("Data: %s\n", rx_buffer);
            }
        }

        usleep(200000); // 200ms间隔
    }

    close(fd);
    return EXIT_SUCCESS;
}
