#ifndef MQTT_H
#define MQTT_H

#include <errno.h>
#include "modbus.h"
#include <mosquitto.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

// 相关参数设置
#define MAX_SLAVE_NUM 3   // 总线下挂载的设备数量
#define SERVER_ID     1   // 从设备开始地址
#define ADDRESS_START 0   // 寄存器起始地址
#define ADDRESS_END   9   // 寄存器结束地址

#define HOST                   "broker.emqx.io"   // 替换为你的MQTT服务器地址
#define PORT                   1883               // MQTT服务器的端口号
#define TOPIC                  "9527"             // 要订阅和发布的主题
#define TOPIC2                 "213"              // 要订阅和发布的主题
#define MOSQ_SUCCESS           0
#define MOSQ_SUCCESS_WITH_INFO 1

int debug_mode = 0;   // 输出debug信息
int test_mode = 0;    // 输出打印信息

// 总线下设备数据结构体
typedef struct rtu_info
{
    bool coil_read_bits[ADDRESS_END - ADDRESS_START + 1];
    bool coil_read_input_bits[ADDRESS_END - ADDRESS_START + 1];
    int hold_read_registers[ADDRESS_END - ADDRESS_START + 1];
    int input_read_registers[ADDRESS_END - ADDRESS_START + 1];
    pthread_mutex_t mutex;
} rtu_info_t;   // 声明结构体


// 线程
pthread_t master_rtu_thread;
pthread_t mqtt_thread;

pthread_mutex_t data_mutex;

#endif