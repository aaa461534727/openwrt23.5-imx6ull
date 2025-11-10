/*
Copyright (c) 2014-2018 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License v1.0
and Eclipse Distribution License v1.0 which accompany this distribution.
 
The Eclipse Public License is available at
   http://www.eclipse.org/legal/epl-v10.html
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
 
Contributors:
   Roger Light - initial implementation and documentation.
*/

#ifndef _IOT_SHARED_H
#define _IOT_SHARED_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <dlfcn.h>
#include <time.h>   
#include <signal.h>   
#include <sys/wait.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/time.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <mosquitto.h>
#include <iot_shared.h>

#include <cJSON.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>

#include <json-c/json.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <sys/sysinfo.h>

#include "cs_uci.h"
#include "cs_uci_fun.h"
#include "cs_common.h"

/* pub_client.c modes */
#define MSGMODE_NONE 0
#define MSGMODE_CMD 1
#define MSGMODE_STDIN_LINE 2
#define MSGMODE_STDIN_FILE 3
#define MSGMODE_FILE 4
#define MSGMODE_NULL 5

#define CLIENT_PUB 1
#define CLIENT_SUB 2


enum {
	CONNECT_SUCCESS=0,
	CONNECT_FAIL,
	CONNECT_ING,
	BING_SUCCESS,
	BING_FAIL,
	BING_NO,
};

#define SMALL_STR_LEN                                    8
#define SHORT_STR_LEN                                    16
#define RESULT_STR_LEN                                   32
#define OPTION_STR_LEN                                   64
#define TEMP_STR_LEN                                     128
#define CMD_STR_LEN                                      256
#define LIST_STR_LEN                                     512
#define LONG_BUFF_LEN                                    1024
#define LONGLONG_BUFF_LEN                                8192
#define true      1

enum {
	L_CRIT=0,
	L_WARNING,
	L_NOTICE,
	L_INFO,
	L_DEBUG
};

struct timers
{
    int interval; //定时时间
    void(*handler)(); //处理函数
};



struct mosq_config {
	char *id;
	char *id_prefix;
	int protocol_version;
	int keepalive;
	char *host;
	int port;
	int qos;
	bool retain;
	int pub_mode; /* pub */
	char *file_input; /* pub */
	char *message; /* pub */
	long msglen; /* pub */
	char *topic; /* pub */
	char *bind_address;
#ifdef WITH_SRV
	bool use_srv;
#endif
	bool debug;
	bool quiet;
	unsigned int max_inflight;
	char *username;
	char *password;
	char *will_topic;
	char *will_payload;
	long will_payloadlen;
	int will_qos;
	bool will_retain;
#ifdef WITH_TLS
	char *cafile;
	char *capath;
	char *certfile;
	char *keyfile;
	char *ciphers;
	bool insecure;
	char *tls_version;
#  ifdef WITH_TLS_PSK
	char *psk;
	char *psk_identity;
#  endif
#endif
	bool clean_session; /* sub */
	char **topics; /* sub */
	int topic_count; /* sub */
	bool no_retain; /* sub */
	char **filter_outs; /* sub */
	int filter_out_count; /* sub */
	bool verbose; /* sub */
	bool eol; /* sub */
	int msg_count; /* sub */
#ifdef WITH_SOCKS
	char *socks5_host;
	int socks5_port;
	char *socks5_username;
	char *socks5_password;
#endif
};

int client_config_load(struct mosq_config *config, int pub_or_sub, int argc, char *argv[]);
void client_config_cleanup(struct mosq_config *cfg);
int client_opts_set(struct mosquitto *mosq, struct mosq_config *cfg);
void init_config(struct mosq_config *cfg);
void add_str_to_json_obj(json_object *json_obj_out, char *object, const char *string);
void add_int_to_json_obj(json_object *json_obj_out, char *object, int value);
void add_bollean_to_json_obj(json_object *json_obj_out, char *object, json_bool value);
void add_int2str_to_json_obj(json_object *json_obj_out, char *object, int value);
void log_message(int priority, const char *format, ...);
void json_object_object_add_string(struct json_object *obj, const char *key, char *value);
const char *json_object_object_get_string(const struct json_object *jso, const char *key);
char *get_string_from_json(json_object *js_obj, char *key);
int getiotISPinfo(char *ISP);
int GetGpsParameter(char *lattitude,char *longitude);
void json_object_object_add_int(json_object *json_obj_out, char *object, int value);
char *getDateFromMacro(char const *time);
int Rand(int minimum_rand,int maxmum_rand);
void getStrFromFile(char* path, char* tmpbuf);
int getIfBytes(const char *ifname, unsigned long long *rxb, unsigned long long *txb);
void getSysUptime( char *tmpBuf);

#endif
