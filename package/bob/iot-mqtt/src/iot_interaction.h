
#ifndef _IOT_INTERACTION_H__
#define _IOT_INTERACTION_H__

#include "iot_shared.h"


void mqtt_data_handle(struct mosquitto *mosq, json_object* request);
int publish_data(struct mosquitto *mosq, char *tp, const char *msg);
void local_bind_iotm(struct mosquitto *mosq);
void set_bind_status(int success);
#if defined(SU_ZHUAN_WANG)
void zhuan_lteinfo_send_iotm();
#else
void lteinfo_send_iotm();
#endif
void gpsdata_send_iotm();
#if defined(BOARD_GPIO_SIM_CHANGE)	
void nettype_send_iotm();
#endif
void warning_send_iotm(); 
void local_bind_handle(struct mosquitto *mosq);
void iotm_settimer();
void send_mqtt_offline();

#endif

