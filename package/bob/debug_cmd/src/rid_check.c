#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <time.h>
#include <sys/select.h>
#include <sys/stat.h>

#define RID_CHECK_PID_FILE "/var/run/rid_check.pid"
#define PORT 8888
#define BUFFER_SIZE 256
#define HEARTBEAT_INTERVAL 5      // 检测间隔(秒)
#define MAX_MISSED_HEARTBEATS 24   // 最大允许丢失的心跳次数,总时间 = 120秒

// 全局状态变量
int net_online = 1;               // 网络状态（1:在线, 0:离线）
int tty_online = 1;              // TTY状态（1:在线, 0:离线）
int tty_missed_count = 0;            // 连续丢失次数计数器
int last_net_status = 1;          // 上次网络状态（用于状态变化检测）
int max_wait_count = 0;           // 最大等待次数
time_t last_heartbeat_time = 0;   // 最后有效心跳时间
pthread_mutex_t heartbeat_mutex = PTHREAD_MUTEX_INITIALIZER;

void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

// 统一的网络检测线程函数
void *rid_net_checker(void *arg) {
    int sockfd;
    char buffer[BUFFER_SIZE];
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);

    // 创建UDP套接字
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        die("socket creation failed");
    }

    // 配置服务器地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    // 绑定套接字到端口
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        close(sockfd);
        die("bind failed");
    }

    printf("UDP Server listening on port %d...\n", PORT);
    printf("Heartbeat monitoring started. Checking every %d seconds.\n", HEARTBEAT_INTERVAL);

    // 初始化心跳时间
    pthread_mutex_lock(&heartbeat_mutex);
    last_heartbeat_time = time(NULL);
    pthread_mutex_unlock(&heartbeat_mutex);

    // 主循环：接收数据+心跳检测
    while (1) {
        fd_set readfds;
        struct timeval timeout;
        timeout.tv_sec = HEARTBEAT_INTERVAL;
        timeout.tv_usec = 0;
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);

        // 使用select同时处理接收和超时检测
        int activity = select(sockfd + 1, &readfds, NULL, NULL, &timeout);
        
        if (activity < 0) {
            perror("select failed");
            continue;
        }
        
        //  有数据到达
        if (activity > 0 && FD_ISSET(sockfd, &readfds)) {
            // 接收客户端数据
            ssize_t recv_len = recvfrom(
                sockfd, buffer, BUFFER_SIZE - 1, 0,
                (struct sockaddr*)&client_addr, &addr_len
            );
            
            if (recv_len == -1) {
                perror("recvfrom failed");
                continue;
            }

            buffer[recv_len] = '\0';
            // printf("Received from %s:%d: %s\n", 
            //        inet_ntoa(client_addr.sin_addr),
            //        ntohs(client_addr.sin_port),
            //        buffer);

            // 仅当收到rid_online时才更新心跳时间
            if (strncmp(buffer, "rid_online", 10) == 0) {
                pthread_mutex_lock(&heartbeat_mutex);
                last_heartbeat_time = time(NULL);  // 更新最后有效心跳时间
                // printf("[RID_NET] Reset heartbeat timer\n");
                pthread_mutex_unlock(&heartbeat_mutex);
                
                // 发送响应
                if (sendto(
                    sockfd, "OK", 2, 0,
                    (struct sockaddr*)&client_addr, addr_len
                ) == -1) {
                    perror("sendto failed");
                }
            }
        }

        // 心跳状态检测
        pthread_mutex_lock(&heartbeat_mutex);
        time_t current_time = time(NULL);
        double time_diff = difftime(current_time, last_heartbeat_time);
        
        // 仅在状态变化时打印
        if (time_diff > HEARTBEAT_INTERVAL * MAX_MISSED_HEARTBEATS) {
            if (net_online == 1) {  // 状态从在线变为离线
                net_online = 0;
                printf("[RID_NET] No RID heartbeat for %.0f sec. Status: OFFLINE\n", time_diff);
                last_net_status = 0;  // 记录状态变化
            }
        } else {
            if (net_online == 0) {  // 状态从离线恢复在线
                net_online = 1;
                printf("[RID_NET] Connection restored. Status: ONLINE\n");
                last_net_status = 1;  // 记录状态变化
            }
        }
        pthread_mutex_unlock(&heartbeat_mutex);
    }
    
    close(sockfd);
    return NULL;
}

// 读取文件内容到缓冲区的函数
int read_file_to_buffer(const char* filename, char** buf, size_t* size) {
    FILE* file = fopen(filename, "rb");  // 以二进制模式打开文件
    if (!file) {
        //perror("Failed to open file");
        return -1;
    }
    
    // 获取文件大小
    struct stat st;
    if (fstat(fileno(file), &st) != 0) {  // 获取文件状态
        perror("fstat failed");
        fclose(file);
        return -1;
    }
    
    *size = st.st_size;
    if (*size == 0) {
        *buf = NULL;
        fclose(file);
        return 0;
    }
    
    // 分配缓冲区
    *buf = (char*)malloc(*size + 1);  // 动态内存分配
    if (!*buf) {
        perror("Memory allocation failed");
        fclose(file);
        return -1;
    }
    
    // 读取整个文件内容
    size_t bytes_read = fread(*buf, 1, *size, file);
    if (bytes_read != *size) {
        perror("File read error");
        free(*buf);
        *buf = NULL;
        fclose(file);
        return -1;
    }
    
    (*buf)[*size] = '\0';  // 添加字符串终止符
    fclose(file);
    return 0;
}

// 统一的TTY检测线程函数
void *rid_tty_checker(void *arg) 
{
    while(1){

        char* file_buffer = NULL,*debug_data_buffer = NULL;
        size_t file_size = 0 , debug_data_size = 0;
        
        int result = read_file_to_buffer("/tmp/iot_cmd_running", &file_buffer, &file_size);

        if (result == 0 && file_size > 0 && (strcmp(file_buffer, "1") == 0)) {
            // 检查文件内容是否包含关键字符串
            printf("[RID_TTY] IOT_CMD is running\n");
            sleep(2);  // 等待2秒后再次执行
            max_wait_count++;
            if (max_wait_count >= 5) {
                max_wait_count = 0;
                system("rm -f /tmp/iot_cmd_running >/dev/null 2>&1");  // 删除文件
            }
            free(file_buffer);
            file_buffer = NULL;
            continue;
        } 
        else {
            FILE *udp_file = fopen("/tmp/udp_cmd_running", "w");
            if (udp_file) {
                fprintf(udp_file, "1");
                fclose(udp_file);
            }
            system("/usr/bin/debug_cmd root >/dev/null 2>&1");
            int data_result = read_file_to_buffer("/tmp/debug_data", &debug_data_buffer, &debug_data_size);
            // 3. 检查文件状态
            if (data_result == 0 && debug_data_size > 0) {
                // 检查文件内容是否包含关键字符串
                if (strstr(debug_data_buffer, "Password") != NULL)
                {
                    tty_missed_count = 0;  // 重置丢失计数器
                    usleep(500000); // 500ms等待
                    system("/usr/bin/debug_cmd XX@RyH1s >/dev/null 2>&1");
                }
                else if((strstr(debug_data_buffer, "-sh: root: not found") != NULL)) 
                {
                    tty_missed_count = 0;  // 重置丢失计数器
                    if (tty_online == 0) { // 状态恢复
                        tty_online = 1;
                        printf("[RID_TTY] Connection restored. Status: ONLINE\n");
                    }
                } else {
                    tty_missed_count++;  // 内容不符合要求
                }
            } else {
                tty_missed_count++;  // 文件读取失败或空文件
            }
            
            // 4. 检查是否超时（连续5次失败）
            if (tty_missed_count >= MAX_MISSED_HEARTBEATS) {
                if (tty_online == 1) {
                    tty_online = 0;
                    printf("[RID_TTY] No valid response for %d times. Status: OFFLINE\n", 
                        tty_missed_count);
                }
            }
            // 释放分配的内存
            if (debug_data_buffer) {
                free(debug_data_buffer);
                debug_data_buffer = NULL;
            }
            system("rm -f /tmp/udp_cmd_running >/dev/null 2>&1");  // 删除文件
            // 5. 等待5秒后再次执行
            sleep(HEARTBEAT_INTERVAL);
        }
        // 释放文件缓冲
        if (file_buffer) {
            free(file_buffer);
            file_buffer = NULL;
        }
    }
    return NULL;
}
int main() 
{
    int wait_sys_up = 1;
    int wait_count = 0;
    char *debug_data_buffer = NULL;
    size_t  debug_data_size = 0;
    int data_result = 0;
    // 获取进行pid,写入到文件保存
    pid_t pid;
    pid = getpid();
    FILE *PID_FILE = fopen(RID_CHECK_PID_FILE, "w");
    if (PID_FILE != NULL) {
        fprintf(PID_FILE, "%d\n", pid);
        fclose(PID_FILE);
    } else {
        perror("fopen pid file");
    }
    
    // 等待D548系统起来
    while(wait_sys_up)
    {
        if (debug_data_buffer) {
            free(debug_data_buffer);
            debug_data_buffer = NULL;
        }
        //先登录
        system("/usr/bin/debug_cmd root >/dev/null 2>&1");
        data_result = read_file_to_buffer("/tmp/debug_data", &debug_data_buffer, &debug_data_size);
        if (data_result == 0 && debug_data_size > 0) {
            // 检查文件内容是否包含关键字符串
            if (strstr(debug_data_buffer, "-sh: root: not found") != NULL) {
                printf("[RID_TTY] Login successful.\n");
                wait_sys_up = 0;
            }
            else if(strstr(debug_data_buffer, "Password") != NULL) {
                system("/usr/bin/debug_cmd XX@RyH1s >/dev/null 2>&1");
                data_result = read_file_to_buffer("/tmp/debug_data", &debug_data_buffer, &debug_data_size);
                if (data_result == 0 && debug_data_size > 0) {
                    // 检查文件内容是否包含关键字符串
                    if (strstr(debug_data_buffer, "root@CS:") != NULL || 
                        strstr(debug_data_buffer, "/home/root") != NULL) {
                        printf("[RID_TTY] Login successful.\n");
                        wait_sys_up = 0;
                    }
                }
            }
        }
        sleep(3);  // 等待3秒后再次执行
        wait_count++;
        if (wait_count >= 40) 
        {  
            wait_count = 0;
            printf("[RID_TTY] Waiting for system timeout...\n");
            break;
        }
        printf("[RID_TTY] Waiting for system to come up...\n");
    }
    if (debug_data_buffer) 
    {
        free(debug_data_buffer);  // 仅释放非空指针
    }

    pthread_t net_checker_thread, tty_checker_thread;
    // 创建网络检测线程
    if (pthread_create(&net_checker_thread, NULL, rid_net_checker, NULL) != 0) {
        die("Failed to create network checker thread");
    }

    // 创建tty检测线程
    if (pthread_create(&tty_checker_thread, NULL, rid_tty_checker, NULL) != 0) {
        die("Failed to create tty checker thread");
    }

    while (1)
    {
        if(net_online == 0 && tty_online == 0) {
            printf("Device is offline, waiting for recovery...\n");
            system("echo 18 > /sys/class/gpio/export");
            system("echo \"out\" > /sys/class/gpio/gpio18/direction");
            system("echo 1 > /sys/class/gpio/gpio18/value");
            sleep(1);  // 等待系统起来
            system("echo 0 > /sys/class/gpio/gpio18/value");
            sleep(1);  
            exit(EXIT_FAILURE);         // 退出整个进程
        } else {
            printf("Device is online.\n");
        }
        sleep(10);  // 主线程保持运行状态
    }
    
    // 主线程等待网络检测线程
    pthread_join(net_checker_thread, NULL);
    pthread_join(tty_checker_thread, NULL);
    pthread_mutex_destroy(&heartbeat_mutex);
    return 0;
}
