#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
// #include <nvram_linux.h>


#define MAX_OUTPUT_LEN 4096
#define MAX_RETRIES 5
#define HASH_LEN 65


// 执行命令并捕获输出
int run_command(const char *command, char *output, int output_max_len, char *extracted_hash) {
    FILE *fp = popen(command, "r");
    if (!fp) {
        perror("popen failed");
        return -1;
    }

    output[0] = '\0';
    char buf[256];
    int hash_extracted = 0;

    while (fgets(buf, sizeof(buf), fp)) {
        // 实时输出到终端
        printf("%s", buf);
        
        // 保存到输出缓冲区
        if (strlen(output) + strlen(buf) < output_max_len) {
            strcat(output, buf);
        }

        // 提取hash值（如果有）
        if (extracted_hash && !hash_extracted) {
            char *hash_start = strstr(buf, "hash:");
            if (hash_start) {
                hash_start += 5; // 跳过"hash:"
                if (strlen(hash_start) >= 64) {
                    strncpy(extracted_hash, hash_start, 64);
                    extracted_hash[64] = '\0';
                    hash_extracted = 1;
                }
            }
        }
    }

    int status = pclose(fp);
    return WEXITSTATUS(status);
}

// 固件升级流程
int firmware_upgrade() {
    const char *conn = "dev=/dev/ttyS1,baud=115200";
    char command[512];
    char output[MAX_OUTPUT_LEN];
    char hash[HASH_LEN] = {0};
    int retries, status;
    //首先复位蓝牙
    for (retries = 0; retries < MAX_RETRIES; retries++) {
        snprintf(command, sizeof(command),
                "cmcumgr -t 60 --conntype=serial --connstring=\"%s\" reset",
                conn);
        
        printf("Executing: %s\n", command);
        memset(output, 0, sizeof(output));
        status = run_command(command, output, sizeof(output), NULL);
        
        if (status == 0) {
            printf("First reset succeeded\n");
            printf("\r\n");
            break;
        }
        printf("Reset1 attempt %d failed. Retrying...\n", retries + 1);
        sleep(10);
    }
    sleep(3);

    // 步骤1: 上传固件
    for (retries = 0; retries < MAX_RETRIES; retries++) {
        snprintf(command, sizeof(command), 
                "cmcumgr --retries=5 --conntype=serial --connstring=\"%s\" image upload \"/tmp/zephyr.signed.bin\"",
                conn);

        printf("Executing: %s\n", command);
        memset(output, 0, sizeof(output));
        status = run_command(command, output, sizeof(output), hash);
        
        if (status == 0 && strstr(output, "Done") && hash[0] != '\0') {
            printf("Upload succeeded. Hash: %s\n", hash);
            printf("\r\n");
            break;
        }
        
        printf("Upload attempt %d failed. Retrying...\n", retries + 1);
        sleep(10);
    }
    if (retries == MAX_RETRIES) {
        fprintf(stderr, "Firmware upload failed after %d retries\n", MAX_RETRIES);
        return 1;
    }

    // 步骤2: 列出镜像
    for (retries = 0; retries < MAX_RETRIES; retries++) {
        snprintf(command, sizeof(command),
                "cmcumgr --conntype=serial --connstring=\"%s\" image list",
                conn);
        
        printf("Executing: %s\n", command);
        memset(output, 0, sizeof(output));
        status = run_command(command, output, sizeof(output), NULL);
        
        if (status == 0) {
            printf("Image list retrieved\n");
            printf("\r\n");
            break;
        }
        
        printf("List attempt %d failed. Retrying...\n", retries + 1);
        sleep(10);
    }
    if (retries == MAX_RETRIES) {
        fprintf(stderr, "Image listing failed after %d retries\n", MAX_RETRIES);
        return 2;
    }

    // 步骤3: 测试镜像
    for (retries = 0; retries < MAX_RETRIES; retries++) {
        snprintf(command, sizeof(command),
                "cmcumgr --conntype=serial --connstring=\"%s\" image test %s",
                conn, hash);
        
        printf("Executing: %s\n", command);
        memset(output, 0, sizeof(output));
        status = run_command(command, output, sizeof(output), NULL);
        
        if (status == 0 && strstr(output, "pending") && strstr(output, hash)) {
            printf("Image test succeeded\n");
            printf("\r\n");
            break;
        }
        
        printf("Test attempt %d failed. Retrying...\n", retries + 1);
        sleep(10);
    }
    if (retries == MAX_RETRIES) {
        fprintf(stderr, "Image test failed after %d retries\n", MAX_RETRIES);
        return 3;
    }

    // 步骤4: 第一次重启
    for (retries = 0; retries < MAX_RETRIES; retries++) {
        snprintf(command, sizeof(command),
                "cmcumgr -t 60 --conntype=serial --connstring=\"%s\" reset",
                conn);
        
        printf("Executing: %s\n", command);
        memset(output, 0, sizeof(output));
        status = run_command(command, output, sizeof(output), NULL);
        
        if (status == 0) {
            printf("First reset succeeded\n");
            printf("\r\n");
            break;
        }
        
        printf("Reset1 attempt %d failed. Retrying...\n", retries + 1);
        sleep(10);
    }
    if (retries == MAX_RETRIES) {
        fprintf(stderr, "First reset failed after %d retries\n", MAX_RETRIES);
        return 4;
    }
    //等待蓝牙固件交换
    printf("watting ble firmware swap....");
    printf("\r\n");
    sleep(60);

    // 步骤5: 确认固件
    for (retries = 0; retries < MAX_RETRIES; retries++) {
        snprintf(command, sizeof(command),
                "cmcumgr --conntype=serial --connstring=\"%s\" image confirm",
                conn);
        
        printf("Executing: %s\n", command);
        memset(output, 0, sizeof(output));
        status = run_command(command, output, sizeof(output), NULL);
        
        if (status == 0 && strstr(output, "confirmed") && strstr(output, hash)) {
            printf("Image confirmed\n");
            printf("\r\n");
            break;
        }
        
        printf("Confirm attempt %d failed. Retrying...\n", retries + 1);
        sleep(10);
    }
    if (retries == MAX_RETRIES) {
        fprintf(stderr, "Image confirmation failed after %d retries\n", MAX_RETRIES);
        return 5;
    }

    // 步骤6: 最终重启
    for (retries = 0; retries < MAX_RETRIES; retries++) {
        snprintf(command, sizeof(command),
                "cmcumgr -t 60 --conntype=serial --connstring=\"%s\" reset",
                conn);
        
        printf("Executing: %s\n", command);
        memset(output, 0, sizeof(output));
        status = run_command(command, output, sizeof(output), NULL);
        
        if (status == 0) {
            printf("Final reset succeeded\n");
            break;
        }
        
        printf("Reset2 attempt %d failed. Retrying...\n", retries + 1);
        sleep(10);
    }
    if (retries == MAX_RETRIES) {
        fprintf(stderr, "Final reset failed after %d retries\n", MAX_RETRIES);
        return 6;
    }

    printf("\n[SUCCESS] Firmware upgrade completed\n");
    return 0;
}

int main(int argc, const char *argv[]) 
{
    char *host; //= nvram_safe_get("remote_id_host");
	char *port; //= nvram_safe_get("remote_id_port");
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "/usr/sbin/rid_blue \"%s\" \"%s\" &", host, port);
    system("killall -9 cmcumgr 2> /dev/null");
    system("killall -9 watchdog 2> /dev/null");
    system("killall -9 rid_blue 2> /dev/null");
    int ret = firmware_upgrade();  // 执行完整升级流程
    if(ret)
    {
        return 1;
    }
    else
    {
        system(cmd);
        system("/sbin/watchdog &");
        return 0;
    }

}