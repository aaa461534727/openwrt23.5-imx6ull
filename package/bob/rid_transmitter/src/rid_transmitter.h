#ifndef _RID_TRANSMITTER_H_
#define _RID_TRANSMITTER_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>  
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <termios.h>
#include <errno.h>
#include <time.h>
#include <locale.h>
#include "opendroneid.h"

//定义rid信息
static ODID_BasicID_encoded BasicID_enc;
static ODID_BasicID_data BasicID;

static ODID_Location_encoded Location_enc;
static ODID_Location_data Location;

static ODID_Auth_encoded Auth0_enc;
static ODID_Auth_encoded Auth1_enc;
static ODID_Auth_data Auth0;
static ODID_Auth_data Auth1;

static ODID_SelfID_encoded SelfID_enc;
static ODID_SelfID_data SelfID;

static ODID_System_encoded System_enc;
static ODID_System_data System_data;

static ODID_OperatorID_encoded OperatorID_enc;
static ODID_OperatorID_data operatorID;

static ODID_MessagePack_encoded pack_enc;
static ODID_MessagePack_data pack;
static ODID_UAS_Data uasData;

// 定义 GPS 数据结构体
typedef struct {
    double latitude;    // 纬度（单位：度）
    double longitude;   // 经度（单位：度）
    char timestamp[20]; // 时间戳（格式：YYYY-MM-DD HH:MM:SS）
    float speed;        // 速度（单位：米/秒）
    uint8_t satellites; // 可见卫星数
    bool fix_status;    // 定位状态（true=有效定位，false=无效）
} GPS_Data_t;

GPS_Data_t gpsData;         // GPS 数据实例

pthread_mutex_t gps_Mutex;

#endif
