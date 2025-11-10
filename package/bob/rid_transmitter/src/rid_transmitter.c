#include "rid_transmitter.h"

#define SYSFS_PATH "/sys/kernel/bcn/custom_data"
#define DATA_SIZE 178
#define SERIAL_PORT "/dev/ttyS0"
#define BAUD_RATE B115200
#define BUFFER_SIZE 4096
#define BCN_NUMBER 3
int serial_fd,bcn_fd;
int test_mode =0;

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

void print_analysis_results(unsigned char *buffer)
{
    // ========== 解析数据包 ==========
    // 无人机类型解析 
    const char* uav_types[] = {"未知", "固定翼", "多旋翼", "自转旋翼机", "垂直起降", 
                            "扑翼机", "滑翔机", "风筝", "自由气球", "系留气球", 
                            "飞艇", "降落伞", "火箭", "系留动力机", "地面障碍物", "其他"};
    uint8_t uav_type = buffer[3] & 0x0F;  // 取低4位
    const char* type_str = (uav_type <= 15) ? uav_types[uav_type] : "未知";
    
    // 无人机状态解析
    const char* states[] = {"未知", "地面", "空中", "紧急"};
    uint8_t uav_state = buffer[4] & 0x03;  // 取低2位
    const char* state_str = (uav_state <= 3) ? states[uav_state] : "未知";
    
    // 位置数据解析（大端序）
    int32_t longitude = (buffer[5] << 24) | (buffer[6] << 16) | (buffer[7] << 8) | buffer[8];
    int32_t latitude = (buffer[9] << 24) | (buffer[10] << 16) | (buffer[11] << 8) | buffer[12];
    double lon_deg = longitude / 10000000.0;
    double lat_deg = latitude / 10000000.0;
    
    // 高度数据解析
    uint16_t altitude = (buffer[13] << 8) | buffer[14];     // 海拔高度
    uint16_t ground_height = (buffer[15] << 8) | buffer[16]; // 距地高度
    
    // 速度数据解析
    uint16_t hor_speed_raw = (buffer[17] << 8) | buffer[18];
    int16_t ver_speed_raw = (buffer[19] << 8) | buffer[20];
    double hor_speed = hor_speed_raw / 10.0;   // 水平速度(m/s)
    double ver_speed = ver_speed_raw / 100.0;  // 垂直速度(m/s)
    
    // 航向角解析
    uint16_t heading = (buffer[21] << 8) | buffer[22];  // 单位度
    
    // 飞手位置解析
    int32_t op_longitude = (buffer[23] << 24) | (buffer[24] << 16) | (buffer[25] << 8) | buffer[26];
    int32_t op_latitude = (buffer[27] << 24) | (buffer[28] << 16) | (buffer[29] << 8) | buffer[30];
    double op_lon_deg = op_longitude / 10000000.0;
    double op_lat_deg = op_latitude / 10000000.0;
    uint16_t op_altitude = (buffer[31] << 8) | buffer[32];  // 飞手海拔
    
    // 帧计数器
    uint16_t frame_counter = (buffer[43] << 8) | buffer[44];
    
    // ========== 打印解析结果 ==========
    printf("\n====== UAV Telemetry Data [Frame:%u] ======\n", frame_counter);
    printf("Type: %s (%u)\tState: %s\n", type_str, uav_type, state_str);
    printf("Position: %.7f°N, %.7f°E\n", lat_deg, lon_deg);
    printf("Altitude: %um (AGL: %um)\n", altitude, ground_height);
    printf("Speed: %.1fm/s (H) %+.2fm/s (V)\n", hor_speed, ver_speed);
    printf("Heading: %u°\n", heading);
    printf("Operator Position: %.7f°N, %.7f°E @%um\n", op_lat_deg, op_lon_deg, op_altitude);
    printf("========================================\n");

}

void fill_rid_data_from_buffer(unsigned char *buffer)
{
    if (buffer[0] != 0xA0 || buffer[1] != 0xFE || buffer[2] != 0x01 || buffer[45] !=0xAE) {
        return; // 无效帧头帧尾
    }

    if (ODID_AUTH_MAX_PAGES < 2) {
        fprintf(stderr, "Program compiled with ODID_AUTH_MAX_PAGES < 2\n");
        return;
    }

    // 解析无人机类型和状态
    uint8_t uav_type = buffer[3];
    uint8_t uav_state = buffer[4];
    
    // 解析位置数据
    int32_t longitude = (buffer[5] << 24) | (buffer[6] << 16) | (buffer[7] << 8) | buffer[8];
    int32_t latitude = (buffer[9] << 24) | (buffer[10] << 16) | (buffer[11] << 8) | buffer[12];
    double lon_deg = longitude / 10000000.0;
    double lat_deg = latitude / 10000000.0;
    
    // 解析高度数据
    uint16_t altitude = (buffer[13] << 8) | buffer[14];
    uint16_t ground_height = (buffer[15] << 8) | buffer[16];
    
    // 解析速度数据
    uint16_t hor_speed_raw = (buffer[17] << 8) | buffer[18];
    int16_t ver_speed_raw = (buffer[19] << 8) | buffer[20];
    double hor_speed = hor_speed_raw / 10.0;
    double ver_speed = ver_speed_raw / 100.0;
    
    // 航向角
    uint16_t heading = (buffer[21] << 8) | buffer[22];
    
    // 飞手位置
    int32_t op_longitude = (buffer[23] << 24) | (buffer[24] << 16) | (buffer[25] << 8) | buffer[26];
    int32_t op_latitude = (buffer[27] << 24) | (buffer[28] << 16) | (buffer[29] << 8) | buffer[30];
    double op_lon_deg = op_longitude / 10000000.0;
    double op_lat_deg = op_latitude / 10000000.0;
    uint16_t op_altitude = (buffer[31] << 8) | buffer[32];
    
    // 更新帧计数器
    uint16_t frame_counter = (buffer[43] << 8) | buffer[44];

    //0X00
    odid_initBasicIDData(&BasicID);
    BasicID.IDType = ODID_IDTYPE_CAA_REGISTRATION_ID;
    BasicID.UAType = uav_type;
    char id[] = "12345678901234567890";
    strncpy(BasicID.UASID, id, sizeof(BasicID.UASID));
    encodeBasicIDMessage(&BasicID_enc, &BasicID);

    //0X01
    odid_initLocationData(&Location);
    Location.Status = uav_state;
    Location.Direction = (float)heading;
    Location.SpeedHorizontal = (float)hor_speed;
    Location.SpeedVertical = (float)ver_speed;
    Location.Latitude = lat_deg;
    Location.Longitude = lon_deg;
    Location.AltitudeBaro = (float)altitude;
    Location.AltitudeGeo = (float)ground_height;
    Location.HeightType = ODID_HEIGHT_REF_OVER_GROUND;
    Location.Height = (float)ground_height;
    Location.HorizAccuracy = createEnumHorizontalAccuracy(2.5f);
    Location.VertAccuracy = createEnumVerticalAccuracy(0.5f);
    Location.BaroAccuracy = createEnumVerticalAccuracy(1.5f);
    Location.SpeedAccuracy = createEnumSpeedAccuracy(0.5f);
    Location.TSAccuracy = createEnumTimestampAccuracy(0.2f);
    Location.TimeStamp = frame_counter; // 使用帧计数器作为时间戳       
    encodeLocationMessage(&Location_enc, &Location);

    //0X02
    odid_initAuthData(&Auth0);
    Auth0.AuthType = ODID_AUTH_UAS_ID_SIGNATURE;
    Auth0.DataPage = 0;
    Auth0.LastPageIndex = 1;
    Auth0.Length = 40;
    Auth0.Timestamp = 28000000;
    char auth0_data[] = "12345678901234567";
    memcpy(Auth0.AuthData, auth0_data, MINIMUM(sizeof(auth0_data), sizeof(Auth0.AuthData)));
    encodeAuthMessage(&Auth0_enc, &Auth0);

    odid_initAuthData(&Auth1);
    Auth1.AuthType = ODID_AUTH_UAS_ID_SIGNATURE;
    Auth1.DataPage = 1;
    char auth1_data[] = "12345678901234567890123";
    memcpy(Auth1.AuthData, auth1_data, MINIMUM(sizeof(auth1_data), sizeof(Auth1.AuthData)));
    encodeAuthMessage(&Auth1_enc, &Auth1);

    //0X03
    odid_initSelfIDData(&SelfID);
    SelfID.DescType = ODID_DESC_TYPE_TEXT;
    char description[] = "DronesRUS: Real Estate";
    strncpy(SelfID.Desc, description, sizeof(SelfID.Desc));
    encodeSelfIDMessage(&SelfID_enc, &SelfID);

    //0X04
    odid_initSystemData(&System_data);
    System_data.OperatorLocationType = ODID_OPERATOR_LOCATION_TYPE_TAKEOFF;
    System_data.ClassificationType = ODID_CLASSIFICATION_TYPE_EU;
    System_data.OperatorLatitude = op_lat_deg;
    System_data.OperatorLongitude = op_lon_deg;
    System_data.AreaCount = 35;
    System_data.AreaRadius = 75;
    System_data.AreaCeiling = 176.9f;
    System_data.AreaFloor = 41.7f;
    System_data.CategoryEU = ODID_CATEGORY_EU_SPECIFIC;
    System_data.ClassEU = ODID_CLASS_EU_CLASS_3;
    System_data.OperatorAltitudeGeo = (float)op_altitude;
    System_data.Timestamp = 28000000;
    encodeSystemMessage(&System_enc, &System_data);

    //0X05
    odid_initOperatorIDData(&operatorID);
    operatorID.OperatorIdType = ODID_OPERATOR_ID;
    char operatorId[] = "98765432100123456789";
    strncpy(operatorID.OperatorId, operatorId, sizeof(operatorID.OperatorId));
    encodeOperatorIDMessage(&OperatorID_enc, &operatorID);

    odid_initMessagePackData(&pack);
    pack.MsgPackSize = BCN_NUMBER;
    memcpy(&pack.Messages[0], &BasicID_enc, ODID_MESSAGE_SIZE);
    memcpy(&pack.Messages[1], &Location_enc, ODID_MESSAGE_SIZE);
    memcpy(&pack.Messages[2], &System_enc, ODID_MESSAGE_SIZE);
    // memcpy(&pack.Messages[3], &Auth1_enc, ODID_MESSAGE_SIZE);
    // memcpy(&pack.Messages[4], &SelfID_enc, ODID_MESSAGE_SIZE);
    // memcpy(&pack.Messages[5], &System_enc, ODID_MESSAGE_SIZE);
    // memcpy(&pack.Messages[6], &OperatorID_enc, ODID_MESSAGE_SIZE);
    encodeMessagePack(&pack_enc, &pack);
   if(test_mode)
   {
        printf("\n-------------------------------------Encoded Data-----------------------------------\n");
        printf("            0- 1- 2- 3- 4- 5- 6- 7- 8- 9- 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24\n");
        printf("BasicID:    ");
        printByteArray((uint8_t*) &BasicID_enc, ODID_MESSAGE_SIZE, 1);

        printf("Location:   ");
        printByteArray((uint8_t*) &Location_enc, ODID_MESSAGE_SIZE, 1);

        printf("Auth0:      ");
        printByteArray((uint8_t*) &Auth0_enc, ODID_MESSAGE_SIZE, 1);

        printf("Auth1:      ");
        printByteArray((uint8_t*) &Auth1_enc, ODID_MESSAGE_SIZE, 1);

        printf("SelfID:     ");
        printByteArray((uint8_t*) &SelfID_enc, ODID_MESSAGE_SIZE, 1);

        printf("System:     ");
        printByteArray((uint8_t*) &System_enc, ODID_MESSAGE_SIZE, 1);

        printf("OperatorID: ");
        printByteArray((uint8_t*) &OperatorID_enc, ODID_MESSAGE_SIZE, 1);

        printf("----------pack_enc: -------\n");
        printByteArray((uint8_t*) &pack_enc, ODID_MESSAGE_SIZE*BCN_NUMBER + 3, 1);
        printf("\n-------------------------------------end Data-----------------------------------\n");
   }

    // 计算实际编码数据长度
    size_t pack_enc_size = ODID_MESSAGE_SIZE * BCN_NUMBER + 3; // 根据编码规则调整
    // 写入二进制数据
    uint8_t *pack_data = (uint8_t*)&pack_enc;
    int ret;
    // 使用实际长度
    if ((ret = write(bcn_fd, pack_data, pack_enc_size)) != pack_enc_size) {
        perror("write fail\n");
        close(bcn_fd);
        return EXIT_FAILURE;
    }
    else
    {   
        if(test_mode)
            printf("write success %zu byte\n", ret);
    } 
}

// 接收线程函数
void* receive_thread(void* arg) {
    unsigned char buffer[BUFFER_SIZE + 1];
    ssize_t bytes_read;   
    int cnt;
    int flags = fcntl(serial_fd, F_GETFL, 0);
    fcntl(serial_fd, F_SETFL, flags | O_NONBLOCK);

    while (1) {

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
            if(test_mode)
            {
                printf("byte %d received: [", bytes_read);
                for (cnt = 0; cnt < bytes_read; cnt++)
                    printf("%02X ", buffer[cnt]);
                printf("]\n\r");
            }
            if (buffer[0] == 0xA0 && buffer[1] == 0xFE && buffer[2] == 0x01 && buffer[45] == 0xAE) {
                // 处理特定数据包
                if (test_mode)
                {
                    print_analysis_results(buffer);
                }
                fill_rid_data_from_buffer(buffer);
            }
        }
    }
    return NULL;
}

static void rid_stop_handle(int sig)
{
    close(serial_fd);
    close(bcn_fd);
    exit(0);
}

int main(int argc, char* argv[]) 
{
    int ret;
    if (argv[1] && strcmp(argv[1], "test") == 0)
    {
        test_mode = 1;
    }

    /* 注册信号 */
    signal(SIGINT, rid_stop_handle);  // 通常是在用户按下Ctrl+C组合键时由终端发送
    signal(SIGTERM, rid_stop_handle); // 通常由系统管理员或进程管理工具发送
    
    // 初始化串口
    if (init_serial() != 0) {
        fprintf(stderr, "Serial initialization failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Serial port %s opened at %d baud\n", SERIAL_PORT, 115200);

    // 创建线程
    pthread_t recv_tid;
    if (pthread_create(&recv_tid, NULL, receive_thread, NULL)) {
        perror("Failed to create receive thread");
        close(serial_fd);
        exit(EXIT_FAILURE);
    }

    // 打开设备文件
    if ((bcn_fd = open(SYSFS_PATH, O_WRONLY)) == -1) {
        perror("open file fail\n");
        return EXIT_FAILURE;
    }

    while(1)
    {
        sleep(3);
    }

    close(bcn_fd);
    return EXIT_SUCCESS;
}