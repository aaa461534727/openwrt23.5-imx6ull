#include "mqtt.h"

//------------------------MODBUS部分-----------------------------------------------------
// 主机rtu
void master_rtu_process(void *arg)
{
    pthread_detach(pthread_self());

    rtu_info_t *slave_info = (rtu_info_t *)arg;
    modbus_t *ctx = NULL;
    int ret = -1;
    int nums = 0;
    int addr = 0;
    int i = 0;
    int cnt = 0;
    int j = 0;
    // 定义指针保存读写数据
    uint8_t *coil_write_bits = NULL;
    uint8_t *coil_read_bits = NULL;
    uint8_t *coil_read_input_bits = NULL;
    uint8_t *hold_read_registers = NULL;
    uint8_t *hold_write_registers = NULL;
    uint8_t *input_read_registers = NULL;

    // 1. 创建一个RTU类型的变量
    // 设置串口设备  波特率 奇偶校验 数据位 停止位
    ctx = modbus_new_rtu("/dev/ttyS2", 9600, 'N', 8, 1);
    if (NULL == ctx)
    {
        fprintf(stderr, "Error: %s\n", modbus_strerror(errno));
        return 1;
    }
    else
    {
        printf("set tty success\n");
    }

    // 4. 在RTU模式下打开串口
    ret = modbus_connect(ctx);
    if (-1 == ret)
    {
        fprintf(stderr, "Connection failed: %s\n", modbus_strerror(errno));
        modbus_free(ctx);
        return 1;
    }

    if (debug_mode)
    {
        // 3. 设置Debug模式
        ret = modbus_set_debug(ctx, TRUE);
        if (-1 == ret)
        {
            fprintf(stderr, "Error: set debug fail");
            modbus_free(ctx);
            return 1;
        }
    }

    // 6. 申请内存 保存发送的数据
    coil_write_bits = (uint8_t *)malloc((nums + 1) * sizeof(uint8_t));
    if (NULL == coil_write_bits)
    {
        fprintf(stderr, "malloc failed\n");
        modbus_free(ctx);
        return 1;
    }
    else
    {
        memset(coil_write_bits, 0, (nums + 1) * sizeof(uint8_t));
    }

    // 6. 申请内存 保存接收线圈的数据
    coil_read_bits = (uint8_t *)malloc((nums + 1) * sizeof(uint8_t));
    if (NULL == coil_read_bits)
    {
        fprintf(stderr, "malloc failed\n");
        modbus_free(ctx);
        return 1;
    }
    else
    {
        memset(coil_read_bits, 0, (nums + 1) * sizeof(uint8_t));
    }

    // 申请内存 保存接收离散输入的数据
    coil_read_input_bits = (uint8_t *)malloc((nums + 1) * sizeof(uint8_t));
    if (NULL == coil_read_input_bits)
    {
        fprintf(stderr, "malloc failed\n");
        modbus_free(ctx);
        return 1;
    }
    else
    {
        memset(coil_read_input_bits, 0, (nums + 1) * sizeof(uint8_t));
    }

    // 申请内存 保存寄存器发送和接收的数据
    hold_write_registers = (uint16_t *)malloc((nums + 1) * sizeof(uint16_t));
    if (NULL == hold_write_registers)
    {
        fprintf(stderr, "malloc failed\n");
        modbus_free(ctx);
        return 1;
    }
    else
    {
        memset(hold_write_registers, 0, (nums + 1) * sizeof(uint16_t));
    }

    hold_read_registers = (uint16_t *)malloc((nums + 1) * sizeof(uint16_t));
    if (NULL == hold_read_registers)
    {
        fprintf(stderr, "malloc failed\n");
        modbus_free(ctx);
        return 1;
    }
    else
    {
        memset(hold_read_registers, 0, (nums + 1) * sizeof(uint16_t));
    }
    // 申请内存 保存输入寄存器接收的数据
    input_read_registers = (uint16_t *)malloc((nums + 1) * sizeof(uint16_t));
    if (NULL == input_read_registers)
    {
        fprintf(stderr, "malloc failed\n");
        modbus_free(ctx);
        return 1;
    }
    else
    {
        memset(input_read_registers, 0, (nums + 1) * sizeof(uint16_t));
    }

    while (1)
    {
        // 循环读取总线上的从设备数据
        for (cnt = 1; cnt <= MAX_SLAVE_NUM; cnt++)
        {
            // 2. 设置从机地址
            ret = modbus_set_slave(ctx, cnt);
            if (-1 == ret)
            {
                fprintf(stderr, "Error:set slave addr fail\n");
                modbus_free(ctx);
                continue;
            }

            // 5. 计算需测试的寄存器个数
            nums = ADDRESS_END - ADDRESS_START;

            // 读取多个线圈
            ret = modbus_read_bits(ctx, addr, nums + 1, coil_read_bits);
            if (nums + 1 != ret)
            {
                printf("Error modbus_read_bits: %d\n", ret);
                continue;
            }
            else
            {
                // 输出
                for (i = 0; i <= nums; i++)
                {
                    pthread_mutex_lock(&data_mutex);
                    slave_info[cnt].coil_read_bits[i] = coil_read_bits[i];
                    pthread_mutex_unlock(&data_mutex);
                    if (test_mode)
                    {
                        if (0 == i)
                        {
                            printf("coil_bit_value: ");
                        }
                        printf("%hd ", coil_read_bits[i]);
                    }
                }
                // 换行
                // printf("\n");
            }

            // 读取多个离散输入
            ret = modbus_read_input_bits(ctx, addr, nums + 1, coil_read_input_bits);
            if (nums + 1 != ret)
            {
                printf("Error modbus_read_input_bits: %d\n", ret);
                continue;
            }
            else
            {
                // 输出
                for (i = 0; i <= nums; i++)
                {
                    pthread_mutex_lock(&data_mutex);
                    slave_info[cnt].coil_read_input_bits[i] = coil_read_input_bits[i];
                    pthread_mutex_unlock(&data_mutex);
                    if (test_mode)
                    {
                        if (0 == i)
                        {
                            printf("input_bit_value: ");
                        }
                        printf("%hd ", coil_read_input_bits[i]);
                    }
                }
                // 换行
                // printf("\n");
            }

            // 读取多个保持寄存器的数据
            ret = modbus_read_registers(ctx, addr, nums + 1, hold_read_registers);
            if (nums + 1 != ret)
            {
                printf("Error hold_read_registers: %d\n", ret);
                continue;
            }
            else
            {
                j = 0;
                // 输出
                for (i = 0; i <= nums * 2; i += 2)
                {
                    pthread_mutex_lock(&data_mutex);
                    slave_info[cnt].hold_read_registers[j] = (hold_read_registers[i + 1] << 8) | hold_read_registers[i];
                    pthread_mutex_unlock(&data_mutex);
                    if (test_mode)
                    {
                        if (0 == i)
                        {
                            printf("hold_read_registers: ");
                        }
                        printf("%hd ", (hold_read_registers[i + 1] << 8) | hold_read_registers[i]);
                    }
                    j++;
                }
                // 换行
                // printf("\n");
            }

            // 读取多个输入寄存器的数据
            ret = modbus_read_input_registers(ctx, addr, nums + 1, input_read_registers);
            if (nums + 1 != ret)
            {
                printf("Error input_read_registers: %d\n", ret);
                continue;
            }
            else
            {
                j = 0;
                // 输出与装填数据
                for (i = 0; i <= nums * 2; i += 2)
                {
                    pthread_mutex_lock(&data_mutex);
                    slave_info[cnt].input_read_registers[j] = (input_read_registers[i + 1] << 8) | input_read_registers[i];
                    pthread_mutex_unlock(&data_mutex);
                    if (test_mode)
                    {
                        if (0 == i)
                        {
                            printf("input_registers_value: ");
                        }
                        printf("%hd ", (input_read_registers[i + 1] << 8) | input_read_registers[i]);
                    }
                    j++;
                }
                if (test_mode)
                {
                    // 换行
                    printf("\n");
                    printf("----------\n");
                }
            }
        }
        // if (test_mode)
        // {
        //     printf("-----rtu-----share_data- start----------\n");

        //     // 打印数据
        //     for (cnt = 1; cnt <= MAX_SLAVE_NUM; cnt++)
        //     {
        //         printf("\ncoli ");
        //         for (i = 0; i <= nums; i++)
        //         {
        //             pthread_mutex_lock(&data_mutex);
        //             printf(" %hd ", slave_info[cnt].coil_read_bits[i]);
        //             pthread_mutex_unlock(&data_mutex);
        //         }
        //         printf("\n coli_input ");
        //         for (i = 0; i <= nums; i++)
        //         {
        //             pthread_mutex_lock(&data_mutex);
        //             printf(" %hd ", slave_info[cnt].coil_read_input_bits[i]);
        //             pthread_mutex_unlock(&data_mutex);
        //         }
        //         printf("\n reg ");
        //         for (i = 0; i <= nums; i++)
        //         {
        //             pthread_mutex_lock(&data_mutex);
        //             printf(" %hd ", slave_info[cnt].hold_read_registers[i]);
        //             pthread_mutex_unlock(&data_mutex);
        //         }
        //         printf("\ninput_reg ");
        //         for (i = 0; i <= nums; i++)
        //         {
        //             pthread_mutex_lock(&data_mutex);
        //             printf(" %hd ", slave_info[cnt].input_read_registers[i]);
        //             pthread_mutex_unlock(&data_mutex);
        //         }
        //     }
        //     pthread_mutex_unlock(&data_mutex);
        //     printf("\n-----rtu-----share_data- end----------\n");
        // }
    }
    // 8. 释放内存
    free(coil_read_bits);
    free(coil_read_input_bits);
    free(coil_write_bits);
    free(hold_read_registers);
    free(hold_write_registers);
    free(input_read_registers);

    // 9. 断开连接
    modbus_close(ctx);
    modbus_free(ctx);

    // 10. 退出线程
    pthread_exit(0);

    return;
}

//------------------------MQTT部分-----------------------------------------------------
// 当接收到消息时调用的回调函数
void on_message(struct mosquitto *mosq, void *userdata, const struct mosquitto_message *message)
{
    printf("Received message on topic %s: %.*s\n", message->topic, message->payloadlen, (char *)message->payload);
}

// 当连接成功时调用的回调函数
void on_connect(struct mosquitto *mosq, void *userdata, int result)
{
    if (result == MOSQ_SUCCESS)
    {
        printf("Connected to MQTT server.\n");
        // 订阅主题
        mosquitto_subscribe(mosq, NULL, TOPIC, 1);
        mosquitto_subscribe(mosq, NULL, TOPIC2, 1);
    }
    else
    {
        fprintf(stderr, "Failed to connect to MQTT server with code %d.\n", result);
    }
}

// 当连接断开时调用的回调函数
void on_disconnect(struct mosquitto *mosq, void *userdata, int rc)
{
    printf("Disconnected from MQTT server with code %d.\n", rc);
    // 断开连接后我们将退出程序
    // exit(0);
}

void mqtt_rw_process(void *arg)
{
    pthread_detach(pthread_self());

    rtu_info_t *slave_info = (rtu_info_t *)arg;
    struct mosquitto *mosq;
    int rc;
    int nums;
    int i;
    int cnt;

    // 初始化Mosquitto库
    mosquitto_lib_init();

    // 创建一个新的Mosquitto实例
    mosq = mosquitto_new(NULL, true, NULL);
    if (!mosq)
    {
        fprintf(stderr, "Error creating Mosquitto instance.\n");
        return EXIT_FAILURE;
    }

    // 设置回调函数
    mosquitto_message_callback_set(mosq, on_message);
    mosquitto_connect_callback_set(mosq, on_connect);
    mosquitto_disconnect_callback_set(mosq, on_disconnect);

    // 连接到MQTT服务器
    rc = mosquitto_connect(mosq, HOST, PORT, 60);
    if (rc != MOSQ_SUCCESS)
    {
        fprintf(stderr, "Failed to connect to MQTT server with code %d.\n", rc);
        mosquitto_destroy(mosq);
        mosquitto_lib_cleanup();
        return EXIT_FAILURE;
    }

    // 进入主循环，处理网络事件等
    while (true)
    {
        rc = mosquitto_loop(mosq, -1, 1);
        if (rc != MOSQ_SUCCESS && rc != MOSQ_SUCCESS_WITH_INFO)
        {
            fprintf(stderr, "Error in mosquitto_loop: %d\n", rc);
            break;
        }

        // 发送一条消息（每隔2秒发送一次）
        static int counter = 0;
        if (counter % 2 == 0)
        {
            if (test_mode)
            {
                // 打印RTU的消息
                printf("\n-----mqtt-----share_data- start----------\n");
                // 打印数据
                nums = ADDRESS_END - ADDRESS_START;
                for (cnt = 1; cnt <= MAX_SLAVE_NUM; cnt++)
                {
                    printf("\ncoli ");
                    for (i = 0; i <= nums; i++)
                    {
                        pthread_mutex_lock(&data_mutex);
                        printf(" %hd ", slave_info[cnt].coil_read_bits[i]);
                        pthread_mutex_unlock(&data_mutex);
                    }
                    printf("\n coli_input ");
                    for (i = 0; i <= nums; i++)
                    {
                        pthread_mutex_lock(&data_mutex);
                        printf(" %hd ", slave_info[cnt].coil_read_input_bits[i]);
                        pthread_mutex_unlock(&data_mutex);
                    }
                    printf("\n reg ");
                    for (i = 0; i <= nums; i++)
                    {
                        pthread_mutex_lock(&data_mutex);
                        printf(" %hd ", slave_info[cnt].hold_read_registers[i]);
                        pthread_mutex_unlock(&data_mutex);
                    }
                    printf("\ninput_reg ");
                    for (i = 0; i <= nums; i++)
                    {
                        pthread_mutex_lock(&data_mutex);
                        printf(" %hd ", slave_info[cnt].input_read_registers[i]);
                        pthread_mutex_unlock(&data_mutex);
                    }
                }
                printf("\n-----mqtt-----share_data- end------%d----\n", counter);
            }
            // char payload[256];
            // snprintf(payload, sizeof(payload), "Hello MQTT! Message %d", counter / 2 + 1);
            // mosquitto_publish(mosq, NULL, TOPIC, strlen(payload), payload, 1, false);
            // mosquitto_publish(mosq, NULL, TOPIC2, strlen(payload), payload, 1, false);
            // printf("Sent message: %s\n", payload);
        }
        counter++;
    }

    // 断开连接并销毁Mosquitto实例
    mosquitto_disconnect(mosq);
    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();
}

//------------------------main部分-----------------------------------------------------
// 进程异常退出时进入该函数
static void main_stop_handle(int sig)
{
    pthread_cancel(master_rtu_thread);
    pthread_cancel(mqtt_thread);
    pthread_mutex_destroy(&data_mutex);
    exit(0);
}

int main(int argc, char *argv[])
{
    if (argv[1] && strcmp(argv[1], "debug") == 0)
        debug_mode = 1;
    else if (argv[1] && strcmp(argv[1], "test") == 0)
        test_mode = 1;

    // 注册信号
    signal(SIGTSTP, main_stop_handle);   // 通常是在用户按下Ctrl+Z组合键时由终端发送
    signal(SIGINT, main_stop_handle);    // 通常是在用户按下Ctrl+C组合键时由终端发送
    signal(SIGTERM, main_stop_handle);   // 通常由系统管理员或进程管理工具发送

    // 要传递给线程的参数
    rtu_info_t slave_info[MAX_SLAVE_NUM] = {0};

    // RTU主机线程
    pthread_create(&master_rtu_thread, NULL, master_rtu_process, (void *)&slave_info);
    // MQTT线程
    pthread_create(&mqtt_thread, NULL, mqtt_rw_process, (void *)&slave_info);

    while (1)
    {
        sleep(2);
    }

    return EXIT_SUCCESS;
}
