#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <pthread.h>
#include <sys/select.h>
#include <time.h>

#define SERIAL_PORT "/dev/ttyS2"
#define BAUD_RATE   B115200
#define BUF_SIZE    10240
#define AT_TIMEOUT_MS 3000
#define CMD_BUF_SIZE 256  // 新增命令缓冲区大小

typedef enum {
    AT_OK,
    AT_ERROR,
    AT_TIMEOUT,
    AT_PENDING
} AT_Status;

typedef struct {
    char buffer[BUF_SIZE];
    int head;
    int tail;
    int capacity;
} RingBuffer;

typedef struct {
    int fd;
    pthread_t rx_thread;
    pthread_mutex_t mutex;
    RingBuffer rx_buf;
} AT_Handler;

/* 串口初始化 */
int serial_init(const char *port, speed_t baud) {
    int fd = open(port, O_RDWR | O_NOCTTY);
    if (fd < 0) {
        perror("open serial failed");
        return -1;
    }

    tcflush(fd, TCIOFLUSH);
    fcntl(fd, F_SETFL, O_NONBLOCK);

    struct termios options;
    tcgetattr(fd, &options);
    
    options.c_cflag = baud | CS8 | CLOCAL | CREAD;
    options.c_iflag = IGNPAR;
    options.c_oflag = 0;
    options.c_lflag = 0;
    options.c_cc[VTIME] = 1;
    options.c_cc[VMIN]  = 0;

    tcsetattr(fd, TCSANOW, &options);
    return fd;
}

/* 线程安全环形缓冲区操作 */
void ringbuf_push(AT_Handler *h, const char *data, int len) {
    pthread_mutex_lock(&h->mutex);
    RingBuffer *buf = &h->rx_buf;
    for (int i = 0; i < len; i++) {
        int next = (buf->head + 1) % buf->capacity;
        if (next == buf->tail) break;
        buf->buffer[buf->head] = data[i];
        buf->head = next;
    }
    pthread_mutex_unlock(&h->mutex);
}

int ringbuf_pop(AT_Handler *h, char *out, int max) {
    pthread_mutex_lock(&h->mutex);
    RingBuffer *buf = &h->rx_buf;
    int count = 0;
    while (buf->tail != buf->head && count < max) {
        out[count++] = buf->buffer[buf->tail];
        buf->tail = (buf->tail + 1) % buf->capacity;
    }
    pthread_mutex_unlock(&h->mutex);
    return count;
}

/* 增强版数据打印 */
void print_raw(const char *data, int len, const char *dir) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    printf("\n[%.6f] %s RAW (%d bytes):\n", 
          ts.tv_sec + ts.tv_nsec/1e9, dir, len);
    for(int i=0; i<len; i++) {
        printf("%02X%c", (unsigned char)data[i], (i+1)%16==0?'\n':' ');
    }
    printf("\nASCII: ");
    for(int i=0; i<len; i++) {
        putchar(data[i] >= 32 && data[i] <= 126 ? data[i] : '.');
    }
    printf("\n------------------------------------------------");
}

/* 接收线程 */
void* rx_thread(void *arg) {
    AT_Handler *h = arg;
    char temp[256];  // 修正1：改为字符数组
    
    while(1) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(h->fd, &fds);
        
        struct timeval tv = {0, 50000};
        if(select(h->fd+1, &fds, NULL, NULL, &tv) > 0) {
            int n = read(h->fd, temp, sizeof(temp));  // 正确读取方式
            if(n > 0) {
                //print_raw(temp, n, "RECV");
                ringbuf_push(h, temp, n);
            }
        }
    }
    return NULL;
}

/* 响应解析 */
AT_Status at_cmd(AT_Handler *h, const char *cmd, char *resp, const char *expect, int max_retries) 
{
    const int retry_delay_ms = 3000;  // 延长重试间隔
    int retry_count = 0;
    const int dynamic_timeout = 8000; // 基础超时8秒
    const int per_kb_timeout = 150;   // 每KB数据增加150ms
    const size_t expect_len = strlen(expect);

    // 新增：预检查缓冲区是否足够
    if(expect_len >= BUF_SIZE) {
        fprintf(stderr, "Expect pattern too long (%zd > %d)\n", expect_len, BUF_SIZE);
        return AT_ERROR;
    }

    while(retry_count <= max_retries) {
        char full_cmd[CMD_BUF_SIZE];
        int cmd_len = snprintf(full_cmd, sizeof(full_cmd), "%s\r\n", cmd);
        write(h->fd, full_cmd, cmd_len);

        char accum[BUF_SIZE] = {0};
        int accum_len = 0;
        int last_match_pos = -1; // 新增：记录上次匹配位置
        struct timespec last_data_time;
        clock_gettime(CLOCK_MONOTONIC, &last_data_time);

        while(1) {
            char chunk[BUF_SIZE];
            int chunk_len = ringbuf_pop(h, chunk, sizeof(chunk));
            
            if(chunk_len > 0) {
                // 优化拷贝逻辑：保留至少expect_len空间
                int remaining = BUF_SIZE - accum_len - expect_len - 1;
                if(remaining > 0) {
                    int copy_len = chunk_len < remaining ? chunk_len : remaining;
                    memcpy(accum + accum_len, chunk, copy_len);
                    accum_len += copy_len;
                    accum[accum_len] = '\0';
                    
                    // 优化匹配：仅扫描新数据区域
                    int scan_start = (last_match_pos == -1) ? 0 : 
                                   (accum_len - copy_len - expect_len + 1);
                    scan_start = scan_start < 0 ? 0 : scan_start;
                    
                    for(int i = scan_start; i <= accum_len - expect_len; i++) {
                        if(memcmp(accum + i, expect, expect_len) == 0) {
                            if(resp) {
                                strncpy(resp, accum, BUF_SIZE-1);
                                resp[BUF_SIZE-1] = '\0';
                            }
                            return AT_OK;
                        }
                    }
                    last_match_pos = accum_len - copy_len;
                }
                clock_gettime(CLOCK_MONOTONIC, &last_data_time);
            }

            // 超时检测（动态调整）
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            long elapsed = (now.tv_sec - last_data_time.tv_sec)*1000 + 
                          (now.tv_nsec - last_data_time.tv_nsec)/1e6;
            int current_timeout = dynamic_timeout + (accum_len/1024)*per_kb_timeout;
            
            if(elapsed > current_timeout) {
                printf("[FINAL TIMEOUT] Total waited: %ldms\n", elapsed);
                break;
            }

            usleep(20000); // 延长检测间隔到20ms
        }

        if(++retry_count <= max_retries) {
            printf("[SMART RETRY] Attempt %d, keep previous %d bytes\n", 
                  retry_count, accum_len);
            
            // 保留未匹配的尾部数据（最多保留expect_len*2）
            if(accum_len > expect_len*2) {
                memmove(accum, accum + accum_len - expect_len*2, expect_len*2);
                accum_len = expect_len*2;
            }
            accum[accum_len] = '\0';
        }
    }

    return AT_ERROR;
}

int main() {
    AT_Handler h = {
        .rx_buf = {.capacity = BUF_SIZE}
    };
    
    if((h.fd = serial_init(SERIAL_PORT, BAUD_RATE)) < 0) 
        exit(1);
    
    pthread_mutex_init(&h.mutex, NULL);
    pthread_create(&h.rx_thread, NULL, rx_thread, &h);

    char resp[BUF_SIZE];
    AT_Status s;
    //first init sle

    while(1) {
        memset(resp, 0, sizeof(resp));
        s = at_cmd(&h, "AT", resp,"OK",5);
        printf("\nCMD: AT\nStatus: %d\nResponse:\n%s\n", s, resp);
        sleep(1);

        memset(resp, 0, sizeof(resp));
        s = at_cmd(&h, "AT+GMR", resp,"OK",5);
        printf("\nCMD: AT+GMR\nStatus: %d\nResponse:\n%s\n", s, resp);
        sleep(1);
        memset(resp, 0, sizeof(resp));
        s = at_cmd(&h, "AT+CWINIT=1", resp,"OK",5);
        printf("\nCMD: AT+CWINIT=1\nStatus: %d\nResponse:\n%s\n", s, resp);
        sleep(1);
        memset(resp, 0, sizeof(resp));
        s = at_cmd(&h, "AT+CWMODE=1", resp,"OK",5);
        printf("\nCMD: AT+CWMODE=1\nStatus: %d\nResponse:\n%s\n", s, resp);
        sleep(1);
        memset(resp, 0, sizeof(resp));
        s = at_cmd(&h, "AT+CWLAP", resp,"OK",5);
        printf("\nCMD: AT+CWLAP\nStatus: %d\nResponse:\n%s\n", s, resp);
        sleep(1);

        memset(resp, 0, sizeof(resp));
        s = at_cmd(&h, "AT+CMD?", resp,"OK",5);
        printf("\nCMD: AT+CMD?\nStatus: %d\nResponse:\n%s\n", s, resp);
        sleep(1);
    }

    close(h.fd);
    return 0;
}
