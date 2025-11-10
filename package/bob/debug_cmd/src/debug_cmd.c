#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <locale.h>

#define DEBUG_DATA_TEMP "/tmp/debug_data"
#define SERIAL_PORT "/dev/ttyS2"
#define BAUD_RATE B115200
#define BUFFER_SIZE 4096

int serial_fd;
volatile int command_executed = 0;
char* user_command = NULL;
int login_count;
volatile time_t last_receive_time = 0;
unsigned char* hex_data = NULL;
size_t hex_data_len = 0;

// 状态枚举
typedef enum {
    STATE_WAIT_FOR_BOOT,
    STATE_ENTER_SYS,
    STATE_EXECUTE_COMMAND,
    STATE_EXECUTE_HEX_COMMAND,
    STATE_EXIT
} LoginState;
LoginState state = STATE_WAIT_FOR_BOOT;

// 初始化串口配置
int init_serial() {
    // 打开串口设备
    serial_fd = open(SERIAL_PORT, O_RDWR | O_NOCTTY);
    if (serial_fd < 0) {
        perror("Error opening serial port");
        return -1;
    }

    // 获取当前串口设置
    struct termios tty;
    memset(&tty, 0, sizeof(tty));
    if (tcgetattr(serial_fd, &tty) != 0) {
        perror("tcgetattr failed");
        return -1;
    }

    // 设置波特率
    cfsetispeed(&tty, BAUD_RATE);
    cfsetospeed(&tty, BAUD_RATE);

    tty.c_iflag &= ~(IGNCR | ICRNL | INLCR);  // 禁止输入转换
    tty.c_cc[VTIME] = 5;  // 阻塞读取超时 0.5秒
    tty.c_cc[VMIN] = 0;   // 无最小字符要求

    // 配置串口参数
    tty.c_cflag &= ~PARENB;   // 无奇偶校验
    tty.c_cflag &= ~CSTOPB;   // 1位停止位
    tty.c_cflag &= ~CSIZE;    // 清除数据位掩码
    tty.c_cflag |= CS8;       // 8位数据位
    tty.c_cflag &= ~CRTSCTS;  // 禁用硬件流控
    tty.c_cflag |= CREAD | CLOCAL; // 启用接收器，忽略调制解调器状态

    // 本地模式配置
    tty.c_lflag &= ~ICANON;   // 非规范模式
    tty.c_lflag &= ~ECHO;     // 禁用回显
    tty.c_lflag &= ~ECHOE;    // 禁用擦除字符回显
    tty.c_lflag &= ~ECHONL;   // 禁用换行回显
    tty.c_lflag &= ~ISIG;     // 禁用信号字符

    // 输入模式配置
    tty.c_iflag &= ~(IXON | IXOFF | IXANY); // 禁用软件流控
    tty.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL);

    // 输出模式配置
    tty.c_oflag &= ~OPOST;    // 原始输出模式
    tty.c_oflag &= ~ONLCR;    // 禁止转换换行符

    // 超时设置：立即返回读取的数据
    tty.c_cc[VMIN] = 1;       // 至少有1个字符才返回
    tty.c_cc[VTIME] = 0;      // 无超时等待

    // 应用配置
    if (tcsetattr(serial_fd, TCSANOW, &tty) != 0) {
        perror("tcsetattr failed");
        return -1;
    }

    // 清空输入输出缓冲区
    tcflush(serial_fd, TCIOFLUSH);
    return 0;
}

static void save_result_data_to_tmp(const char *str)
{
    FILE *file = fopen(DEBUG_DATA_TEMP, "a");  // 追加模式
    if (file == NULL) {
        perror("Failed to open debug data file");
        return;
    }
    if (fputs(str, file) == EOF) {
        perror("Failed to write debug data");
    }
    fclose(file);
}

// 接收线程函数
void* receive_thread(void* arg) {
    char buffer[BUFFER_SIZE + 1];
    ssize_t bytes_read;
    
    printf("Receive thread started\n");
    
    int flags = fcntl(serial_fd, F_GETFL, 0);
    fcntl(serial_fd, F_SETFL, flags | O_NONBLOCK);
    
    while (1) {
        // 检查退出条件
        if (state == STATE_EXIT) {
            printf("Receive thread exiting (state exit)\n");
            break;
        }
        bytes_read = read(serial_fd, buffer, BUFFER_SIZE);
        if (bytes_read < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(10000);
                continue;
            } else if (errno == EBADF) {
                printf("Serial port closed, exiting receive thread\n");
                break;
            }
            perror("Read error");
            continue;
        }
        
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0';
            fwrite(buffer, 1, bytes_read, stdout);
            fflush(stdout);
            last_receive_time = time(NULL);

            //保存数据
            if(state == STATE_ENTER_SYS || state == STATE_EXECUTE_COMMAND || state == STATE_EXECUTE_HEX_COMMAND)
            {
                save_result_data_to_tmp(buffer);
            } 
        }
    }
    return NULL;
}

void send_data_in_parts(const void *data, size_t len, int is_hex) {
    const size_t max_chunk = 11;  // 每个片段最大字节数
    size_t sent = 0;
    const char *ptr = (const char *)data;  // 通用指针，处理字符和二进制数据

    while (sent < len) {
        // 计算本次发送的大小
        size_t to_send = (len - sent) > max_chunk ? max_chunk : (len - sent);
        
        // 发送数据片段
        ssize_t n = write(serial_fd, ptr + sent, to_send);
        if (n < 0) {
            perror(is_hex ? "Hex write error" : "Command write error");
            break;
        }
        sent += n;

        // 非最后一次发送时等待设备处理
        if (sent < len) {
            usleep(100000);  // 100ms等待
        }
    }

    // 如果是字符串命令，添加回车符
    if (!is_hex) {
        write(serial_fd, "\r", 1);
    }
}
void wait_for_data_response(void){

    time_t start = time(NULL);
    time_t last_active = start;
    int received_data = 0;
    
    while (1) {
        time_t now = time(NULL);
        
        // 检查是否超过最大等待时间
        if (now - start > 55) {
            printf("Maximum wait time exceeded\n");
            break;
        }
        
        // 检查是否有新数据
        if (last_receive_time > last_active) {
            last_active = last_receive_time;
            received_data = 1;
        }
        
        // 如果1秒内没有新数据则退出
        if (now - last_active >= 1) {
            if (received_data) {
                printf("No data for 1 second, exiting\n");
            } else {
                printf("No data received, exiting\n");
            }
            break;
        }
        
        usleep(100000); // 100ms
    }
}
// 发送线程函数
void* send_thread(void* arg) {
    time_t last_cr_time = 0;
    
    printf("Send thread started\n");
    
    while (1) {       
        // 检查退出条件
        if (state == STATE_EXIT) {
            printf("Send thread exiting\n");
            break;
        }
        
        switch (state) {
            case STATE_ENTER_SYS:
            case STATE_EXECUTE_COMMAND:
            {
                // STATE_ENTER_SYS 需要额外发送两个回车
                if (state == STATE_ENTER_SYS) {
                    write(serial_fd, "\r", 1);
                    usleep(100000); 
                    write(serial_fd, "\r", 1);
                    usleep(100000); 
                }

                // 清空旧文件内容
                FILE *file = fopen(DEBUG_DATA_TEMP, "w");
                if (file) fclose(file);

                char command[256];
                send_data_in_parts(user_command, strlen(user_command), 0);  // 0表示字符串
                printf("Executing command: %s\n", user_command);
                
                wait_for_data_response();

                command_executed = 1;
                state = STATE_EXIT;
                break;
            }

            case STATE_EXECUTE_HEX_COMMAND:  // 处理十六进制命令
            {
                // 清空旧文件内容
                FILE *file = fopen(DEBUG_DATA_TEMP, "w");
                if (file) fclose(file);

                send_data_in_parts(hex_data, hex_data_len, 1);  // 1表示十六进制数据
                printf("Executing hex command\n");
                
                wait_for_data_response();

                command_executed = 1;
                state = STATE_EXIT;
                break;
            }

            default:
                break;
        }

        usleep(10000); // 10ms等待，降低CPU使用率
    }
    return NULL;
}

// 等待线程退出的超时函数
void wait_thread_exit(pthread_t tid, const char* thread_name, int timeout_ms) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    
    // 毫秒转秒/纳秒
    ts.tv_sec += timeout_ms / 1000;
    ts.tv_nsec += (timeout_ms % 1000) * 1000000;
    
    // 处理纳秒溢出
    if (ts.tv_nsec >= 1000000000) {
        ts.tv_sec += 1;
        ts.tv_nsec -= 1000000000;
    }
    
    int result = pthread_timedjoin_np(tid, NULL, &ts);
    if (result == ETIMEDOUT) {
        printf("%s thread timeout, canceling...\n", thread_name);
        pthread_cancel(tid); // 强制终止线程
    } else if (result != 0) {
        perror("pthread_timedjoin_np error");
    }
}

int parse_hex_args(char **argv, int argc, unsigned char **data, size_t *len) {
    size_t data_size = argc * sizeof(unsigned char);
    *data = malloc(data_size);
    if (!*data) {
        perror("Memory allocation for hex data failed");
        return -1;
    }

    int count = 0;
    int i = 0;
    char *p;
    for (i = 0; i < argc; i++) {
        char *arg = argv[i];
        unsigned long val;
        char *endptr;
        
        // 跳过"0x"前缀（如果存在）
        if (strncmp(arg, "0x", 2) == 0) {
            arg += 2;
        }
        
        // 检查是否为有效的十六进制字符串
        if (strlen(arg) == 0 || strlen(arg) > 2) {
            fprintf(stderr, "Invalid hex byte: %s\n", argv[i]);
            free(*data);
            return -1;
        }
        
        for (p = arg; *p; p++) {
            if (!isxdigit(*p)) {
                fprintf(stderr, "Invalid hex character: %c\n", *p);
                free(*data);
                return -1;
            }
        }
        
        val = strtoul(arg, &endptr, 16);
        if (*endptr != '\0' || val > 0xFF) {
            fprintf(stderr, "Invalid hex byte: %s\n", argv[i]);
            free(*data);
            return -1;
        }
        
        (*data)[count++] = (unsigned char)val;
    }
    
    *len = count;
    return 0;
}

int main(int argc, char *argv[]) {
    setlocale(LC_ALL, "en_US.UTF-8");
    int i =0;
    // 解析命令行参数 
    if (argc > 1) {
        // 检查是否为十六进制模式
        if (strcmp(argv[1], "hex") == 0) {
            if (argc < 3) {
                printf("Hex mode requires at least one hex byte\n");
                exit(EXIT_FAILURE);
            }
            
            if (parse_hex_args(&argv[2], argc - 2, &hex_data, &hex_data_len) != 0) {
                exit(EXIT_FAILURE);
            }
            
            state = STATE_EXECUTE_HEX_COMMAND;

            printf("Hex command :");
            for(i = 0;i< hex_data_len; i++) {
                printf("0x%02x ", hex_data[i]);
            }
            printf("\n");
        }
        else
        {
            // 计算所需总长度
            size_t total_len = 0;
            for (i = 1; i < argc; i++) {
                total_len += strlen(argv[i]) + 1; // +1 用于空格分隔符
            }
            
            // 动态分配内存
            user_command = (char*)malloc(total_len);
            if (!user_command) {
                perror("Memory allocation failed");
                exit(EXIT_FAILURE);
            }
            
            // 拼接所有参数
            user_command[0] = '\0'; // 初始化空字符串
            for (i = 1; i < argc; i++) {
                strcat(user_command, argv[i]);
                if (i < argc - 1) strcat(user_command, " "); // 添加空格分隔
            }
            printf("User command: %s\n", user_command);
            if((strstr(user_command, "root") != NULL)) {
                    state = STATE_ENTER_SYS;
            }
            else{   
                state = STATE_EXECUTE_COMMAND;
            }
        }
    } 
    else
    {
        printf("No command specified, will exit\n");
        // 清空旧文件内容
        FILE *file = fopen(DEBUG_DATA_TEMP, "w");
        if (file) fclose(file);
        return -1;
    }

    // 初始化串口
    if (init_serial() != 0) {
        fprintf(stderr, "Serial initialization failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Serial port %s opened at %d baud\n", SERIAL_PORT, 115200);

    // 创建线程
    pthread_t recv_tid, send_tid;
    
    if (pthread_create(&recv_tid, NULL, receive_thread, NULL)) {
        perror("Failed to create receive thread");
        close(serial_fd);
        exit(EXIT_FAILURE);
    }
    
    if (pthread_create(&send_tid, NULL, send_thread, NULL)) {
        perror("Failed to create send thread");
        close(serial_fd);
        exit(EXIT_FAILURE);
    }

    // 等待命令执行完成
    while (!command_executed && state != STATE_EXIT) {
        usleep(10000); // 10ms等待
    }

    // 设置退出状态，给线程通知
    state = STATE_EXIT;
    
    // 给线程一点时间响应退出
    usleep(100000); 

    // 关闭串口 - 这会触发接收线程退出
    close(serial_fd);
    printf("Serial port closed, waiting for threads to exit...\n");

    // 等待发送线程退出（超时1秒）
    wait_thread_exit(send_tid, "Send", 100);
    
    // 等待接收线程退出（超时1秒）
    wait_thread_exit(recv_tid, "Receive", 100);

    printf("Program exiting\n");
    free(user_command);
    free(hex_data);
    return 0;
}
