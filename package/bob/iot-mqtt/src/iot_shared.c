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


#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef WIN32
#include <unistd.h>
#else
#include <process.h>
#include <winsock2.h>
#define snprintf sprintf_s
#endif

#include <mosquitto.h>
#include "iot_shared.h"
//#include "iot.h"

//static int mosquitto__parse_socks_url(struct mosq_config *cfg, char *url);
//static int client_config_line_proc(struct mosq_config *cfg, int pub_or_sub, int argc, char *argv[]);

void init_config(struct mosq_config *cfg)
{
	int intVal=0;
	static char host[32]={0}, user_name[32]={0}, password[64]={0}, mac[18]={0};
	
	memset(cfg, 0, sizeof(*cfg));

	Uci_Get_Int(PKG_IOT_CONFIG, "default", "max_inflight", &intVal);
	
	if(intVal == 0)
		cfg->max_inflight = 20;
	else
		cfg->max_inflight = intVal;
	
	Uci_Get_Int(PKG_IOT_CONFIG, "iotm", "keep_alive", &intVal);
	if(intVal == 0)
		cfg->keepalive = 60;
	else
		cfg->keepalive = intVal;
		
	cfg->clean_session = true;
	cfg->eol = true;
	cfg->protocol_version = MQTT_PROTOCOL_V31;

	Uci_Get_Str(PKG_IOT_CONFIG, "iotm", "server_host", host);
	cfg->host = host;
	
	Uci_Get_Int(PKG_IOT_CONFIG, "iotm", "port", &intVal);
	cfg->port = intVal;

	Uci_Get_Str(PKG_IOT_CONFIG, "iotm", "user_name", user_name);
	cfg->username = user_name;

	Uci_Get_Str(PKG_IOT_CONFIG, "iotm", "password", password);
	cfg->password = password;
//	cfg->id = nvram_safe_get("iotm_client_id");
	getIfMac("br-lan", mac);
	cfg->id = mac; 
	
	log_message(L_DEBUG, "cfg->host = %s\n",cfg->host);
	log_message(L_DEBUG, "cfg->port = %d\n",cfg->port);
	log_message(L_DEBUG, "cfg->username = %s\n",cfg->username);
	log_message(L_DEBUG, "cfg->password = %s\n",cfg->password);
	log_message(L_DEBUG, "cfg->id = %s\n",cfg->id);
	log_message(L_DEBUG, "cfg->keepalive = %d\n",cfg->keepalive);
	log_message(L_DEBUG, "cfg->max_inflight = %d\n",cfg->max_inflight);

	
}
char *get_string_from_json(json_object *js_obj, char *key)
{
	json_object *js_tmp = NULL;
	char *str = NULL;

	js_tmp = json_object_object_get(js_obj, key);

	if (js_tmp != NULL) {
		str = (char *) json_object_get_string(js_tmp);

		if (str != NULL) {
			return str;
		}
	}

	return "";
}




int getiotImsi(char *imsi)
{
	char imsi_buf [RESULT_STR_LEN] = {0};
	cJSON *ubus_root;
	char tmp_buf[128],ubus_data[2048];
	int ret = 0;

	memset(ubus_data, '\0', sizeof(ubus_data));
	ret = cs_ubus_cli_call("cm", "get_link_context",ubus_data);
	if(ret != -1)
	{		
		ubus_root = cJSON_Parse(ubus_data);
		if(ubus_root) 
		{
			cJSON *imeiObj = cJSON_GetObjectItem(ubus_root, "celluar_basic_info");
			if(imeiObj) {
		
				get_cjson_string(imeiObj, "IMSI", imsi_buf, sizeof(imsi_buf));
				strcpy(imsi, imsi_buf);	
			
			}
		
			cJSON_Delete(ubus_root);
		}
		
	}
	return 0;
}

int getiotISPinfo(char *ISP)
{
	char imsi [RESULT_STR_LEN] = {0};
	
	getiotImsi(imsi);
	if (strstr(imsi,"46000")||strstr(imsi,"46002")||strstr(imsi,"46007")||strstr(imsi,"46008")||strstr(imsi,"46004"))
	{
		strcpy(ISP,"1");//yidong
	}
	else if (strstr(imsi,"46001")||strstr(imsi,"46006")||strstr(imsi,"46009")||strstr(imsi,"46010"))
	{
		strcpy(ISP,"2");//liantong
	}
	else if (strstr(imsi,"46005")||strstr(imsi,"46011") ||strstr(imsi,"46003"))
	{
		strcpy(ISP,"3");//dianxin
	}
	else if (strstr(imsi,"46020"))
	{
		strcpy(ISP,"4");//qita
	}else
	{
		strcpy(ISP,"4");//qita
	}

	return 0;
}






int GetGpsParameter(char *lattitude,char *longitude)
{
	int ret = 0;
	char gpsdata[LONG_BUFF_LEN] = {0};
	json_object *root = NULL;
	char gps_date_file[32] = {0};
#if defined(BOARD_CH610WF)||defined(BOARD_C735PR)||defined(BOARD_C735SR)||defined(BOARD_C735TR)||defined(BOARD_C735IR)||defined(BOARD_CH1313WF)||defined (USB_SERIAL_CH341)
	sprintf(gps_date_file, "/tmp/gps_data");
#else	
	int modem_num = 0; //Only one module
	sprintf(gps_date_file, "/tmp/gps_data_%d", modem_num);
#endif
	ret = f_read_string(gps_date_file, gpsdata, sizeof(gpsdata));
	if(ret < 0)
		return ret;
	root = json_tokener_parse(gpsdata);

	strcpy(lattitude,get_string_from_json(root, "lattitude"));
	strcpy(longitude,get_string_from_json(root, "longitude"));

	json_object_put(root);
	return 1;
}


void add_str_to_json_obj(json_object *json_obj_out, char *object, const char *string)
{
	json_object *json_obj_tmp = json_object_new_string(string);
	json_object_object_add(json_obj_out, object, json_obj_tmp);
}

void add_int_to_json_obj(json_object *json_obj_out, char *object, int value)
{
	json_object *json_obj_tmp = json_object_new_int(value);
	json_object_object_add(json_obj_out, object, json_obj_tmp);
}

void add_int2str_to_json_obj(json_object *json_obj_out, char *object, int value)
{
	char int_str[16] = {0};
	sprintf(int_str, "%d", value);
	json_object *json_obj_tmp = json_object_new_string(int_str);
	json_object_object_add(json_obj_out, object, json_obj_tmp);
}

void add_bollean_to_json_obj(json_object *json_obj_out, char *object, json_bool value)
{
	json_object *json_obj_tmp = json_object_new_boolean(value);
	json_object_object_add(json_obj_out, object, json_obj_tmp);
}



const char *json_object_object_get_string(const struct json_object *jso, const char *key)
{
	struct json_object *j;

	j = json_object_object_get(jso, key);
	if(j)
		return json_object_get_string(j);
	else
		return NULL;
}

void json_object_object_add_string(struct json_object *obj, const char *key, char *value)
{
	if(strlen(key) == 0)
		return;
	
	json_object_object_add(obj, key, json_object_new_string(value));
}

void json_object_object_add_int(json_object *json_obj_out, char *object, int value)
{
	json_object *json_obj_tmp = json_object_new_int(value);
	json_object_object_add(json_obj_out, object, json_obj_tmp);
}

void client_config_cleanup(struct mosq_config *cfg)
{
	int i;
	free(cfg->id);
	free(cfg->id_prefix);
	free(cfg->host);
	free(cfg->file_input);
	free(cfg->message);
	free(cfg->topic);
	free(cfg->bind_address);
	free(cfg->username);
	free(cfg->password);
	free(cfg->will_topic);
	free(cfg->will_payload);
#ifdef WITH_TLS
	free(cfg->cafile);
	free(cfg->capath);
	free(cfg->certfile);
	free(cfg->keyfile);
	free(cfg->ciphers);
	free(cfg->tls_version);
#  ifdef WITH_TLS_PSK
	free(cfg->psk);
	free(cfg->psk_identity);
#  endif
#endif
	if(cfg->topics){
		for(i=0; i<cfg->topic_count; i++){
			free(cfg->topics[i]);
		}
		free(cfg->topics);
	}
	if(cfg->filter_outs){
		for(i=0; i<cfg->filter_out_count; i++){
			free(cfg->filter_outs[i]);
		}
		free(cfg->filter_outs);
	}
#ifdef WITH_SOCKS
	free(cfg->socks5_host);
	free(cfg->socks5_username);
	free(cfg->socks5_password);
#endif
}



char *getDateFromMacro(char const *time) {
    char s_month[5];
    int month, day, year;
    static const char month_names[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
	
    sscanf(time, "%s %d %d", s_month, &day, &year);
	static char cmd[128] = {0};

    month = ((strstr(month_names, s_month)-month_names)/3)+1;
	if(month < 10 || day < 10)
	{
		if(month<10 && day < 10)
			sprintf(cmd,"%d0%d0%d",year,month,day);
		else if(month<10 && day > 10)
			sprintf(cmd,"%d0%d%d",year,month,day);
		else
			sprintf(cmd,"%d%d0%d",year,month,day);
	}
	else 
		sprintf(cmd,"%d%d%d",year,month,day);
	
	//printf("cmd is :%s\n",cmd);

   return cmd;
}

int Rand(int minimum_rand,int maxmum_rand)
{
	int ret=0;
	float maxmum_float;
	maxmum_float=(float)maxmum_rand;

	srand((int)time(0));	
	ret=minimum_rand+(int)(maxmum_float*(rand())/(RAND_MAX+1.0));

	return ret;

}

void getStrFromFile(char* path, char* tmpbuf)
{
	char tmp[2] = {0};
	FILE *fp;
	int i = 0;
	strcpy(tmpbuf,"");
	fp = fopen(path, "r");
	if (!fp) {
		fprintf(stderr, "Read file error:%s!\n",path);
		return ;
	}
	while(!feof(fp)){
		fread(tmp,1,1,fp);
		tmpbuf[i++] = tmp[0];
	}
	tmpbuf[i-2]='\0';//del "\n\r"
	
	fclose(fp);
	return;
}


int getIfBytes(const char *ifname, unsigned long long *rxb, unsigned long long *txb)
{
	char path[TEMP_STR_LEN] = {0};
	char bytes[OPTION_STR_LEN] = {0};

	snprintf(path, TEMP_STR_LEN, "/sys/class/net/%s/statistics/tx_bytes", ifname);
	getStrFromFile(path, bytes);
	*txb = strtoull (bytes, NULL, 10);

	snprintf(path, TEMP_STR_LEN, "/sys/class/net/%s/statistics/rx_bytes", ifname);
	getStrFromFile(path, bytes);
	*rxb = strtoull (bytes, NULL, 10);

	return 0;
}




extern int logging_level;



void log_message(int priority, const char *format, ...)
{
	va_list args;
	char buf[1024];
	
	char *logheader = "iotm";
	
	if ((priority < logging_level)) {
		va_start(args, format);
		vsnprintf(buf, sizeof(buf), format, args);
#if 0
		dbg("buff=%s\n",buf);
#else
		openlog(logheader, 0, 0);
		syslog(0, "%s", buf);
		closelog();
#endif
		va_end(args);
	}
}

/*
 * Convert Ethernet address string representation to binary data
 * @param	a	string in xx:xx:xx:xx:xx:xx notation
 * @param	e	string in xxxxxxxxxxxx
 * @return	TRUE if conversion was successful and FALSE otherwise
 */
int
mac_del_split(const char *a, char *e)
{
	char *c = (char *) a;
	int i = 0, j = 0;

	for (i = 0; i < 17; i++) {
		if(c[i] != ':') {
			e[j] = c[i];
			j++;
		}
	}

	return 0;
}

static uint64_t
get_ifstats_counter(const char *ifname, const char *cnt_name)
{
	FILE *fp;
	uint64_t cnt_val64 = 0;
	char cnt_path[64], cnt_data[32];

	snprintf(cnt_path, sizeof(cnt_path), "/sys/class/net/%s/statistics/%s", ifname, cnt_name);
	fp = fopen(cnt_path, "r");

	if (fp) {
		if (fgets(cnt_data, sizeof(cnt_data), fp))
			cnt_val64 = strtoull(cnt_data, NULL, 10);

		fclose(fp);
	}

	return cnt_val64;
}


uint64_t
get_ifstats_bytes_rx(const char *ifname)
{
	return get_ifstats_counter(ifname, "rx_bytes");
}

uint64_t
get_ifstats_bytes_tx(const char *ifname)
{
	return get_ifstats_counter(ifname, "tx_bytes");
}


void get_modem_param_value(char *action, char *name, char *value)
{
	int ret;
	char data[1024]={0}, buf[16]={0};
	cJSON *root;
	
	memset(data, 0, sizeof(data));
	ret = cs_ubus_cli_call("urild", action, data);
	if(ret != -1){
		root = cJSON_Parse(data);
		if(root){
			get_cjson_string(root, name, buf, sizeof(buf));
			sprintf(value, "%s", buf);
			cJSON_Delete(root);
		}else{
			strcpy(value, "");
		}
	}else{
		strcpy(value, "");
	}

	return ;
}

void get_pci_to_obj(struct json_object *root)
{
	char p_json[LONGLONG_BUFF_LEN]={0};
	int ret=0;
	cJSON *cell_root;
	char pci[33]={0},net_type[33]={0}, result[256] = {0};
	char str[32]={0};

	ret = cs_ubus_cli_call("cm", "get_eng_info",p_json);
	cell_root = cJSON_Parse(p_json);
	if(cell_root != NULL){
		cJSON *object= cJSON_GetObjectItem(cell_root, "eng");
		if(object){
			
			cJSON *subObj = cJSON_GetObjectItem(object,"lte");
			if(subObj){

				memset(str, '\0', sizeof(str));
				get_cjson_string(subObj, "phy_cell_id", str, sizeof(str));	
				json_object_object_add_string(root, "cpi", str);
				
				memset(str, '\0', sizeof(str));
				get_cjson_string(subObj, "rsrp", str, sizeof(str));
				json_object_object_add_string(root, "rsrp", str);

				memset(str, '\0', sizeof(str));
				get_cjson_string(subObj, "sinr", str, sizeof(str));
				json_object_object_add_string(root, "sinr", str);

				
			}else{
				json_object_object_add_string(root, "cpi", "");
				json_object_object_add_string(root, "rsrp", "");
				json_object_object_add_string(root, "sinr", "");
			}
		}			
		cJSON_Delete(cell_root);
	}else{
		json_object_object_add_string(root, "cpi", "");
		json_object_object_add_string(root, "rsrp", "");
		json_object_object_add_string(root, "sinr", "");
	}
	
	return ;
}


void get_imei_to_obj(struct json_object *root)
{
	char p_json[LONGLONG_BUFF_LEN]={0};
	int ret=0;
	cJSON *cell_root;
	char pci[33]={0},net_type[33]={0}, result[256] = {0};
	char str[32]={0};
	
	ret = cs_ubus_cli_call("cm", "get_link_context",p_json);
	cell_root = cJSON_Parse(p_json);
	
	if(cell_root != NULL){
		cJSON *subObj = cJSON_GetObjectItem(cell_root,"celluar_basic_info");
		if(subObj){
			
			memset(str, '\0', sizeof(str));
			get_cjson_string(subObj, "IMEI", str, sizeof(str));	
			json_object_object_add_string(root, "imei", str);
			
			memset(str, '\0', sizeof(str));
			get_cjson_string(subObj, "IMSI", str, sizeof(str));
			json_object_object_add_string(root, "imsi", str);

			get_cjson_string(subObj, "sys_mode", net_type, sizeof(net_type));
			if(atoi(net_type)==2){
				json_object_object_add_string(root, "netType", "4G");
			}else if(atoi(net_type)==1){
				json_object_object_add_string(root, "netType", "3G");
			}			
			
		}
				
		cJSON_Delete(cell_root);
	}
	return ;
}

void get_signal( char *current_singal)
{
	char *p = NULL;
	int i_signal = 0,sinagl_buf[32]={0};
	char buf[64]={0}, tmpBuf[64] = {0};
	char signal[8]={0};
	
	FILE *fp_csq = popen("cli_atc AT+CSQ", "r");
	if(!fp_csq) return 0;

	while(fgets(buf, sizeof(buf), fp_csq) != NULL)
	{
		if(p=strstr(buf, "\n"))
		{
			p[0]='\0';
		}
		if(strstr(buf,"+CSQ")){
			memset(tmpBuf, '\0', sizeof(tmpBuf));
			strcpy(tmpBuf,buf);
			break;
		}
	}
	pclose(fp_csq);
	get_sub_value(sinagl_buf, tmpBuf, sizeof(sinagl_buf), ':', ',');
	i_signal = atoi(sinagl_buf);

	if ( 0 < i_signal && i_signal <= 31 )
		i_signal = i_signal * 100 / 31;
	else if ( 100 <= i_signal && i_signal < 199 )//+CSQ: 25,199
		i_signal = i_signal - 100;
	else
		i_signal = 0;
	sprintf(signal,"%d",i_signal);
	strcpy(current_singal,signal);
	
	return ;
}
void get_rsrp_to_obj(struct json_object *root)
{
	char *p = NULL;
	char buf[64]={0}, tmpBuf[32] = {0};
	char signal[4]={0}, rsrp[4]={0}, s_rsrp[8]={0};
	int i_signal = 0,sinagl_buf[32]={0};
	
	
	FILE *fp = popen("cli_atc AT*CESQ", "r");
	if(!fp) return 0;

	while(fgets(buf, sizeof(buf), fp) != NULL)
	{
		if(p=strstr(buf, "\n"))
		{
			p[0]='\0';
		}
		if(strstr(buf,"*CESQ")){
			memset(tmpBuf, '\0', sizeof(tmpBuf));
			strcpy(tmpBuf,buf);
			break;
		}
	}
	pclose(fp);
	getNthValueSafe(5, tmpBuf, ',', rsrp, sizeof(rsrp));
	json_object_object_add_string(root, "rsrp", rsrp);

	
	return ;
}

void get_modem_rsrp_value(char *str)
{
	char *p = NULL;
	char buf[64]={0}, tmpBuf[32] = {0};
	char signal[4]={0}, rsrp[4]={0};
	
	FILE *fp = popen("cli_atc at^hcsq?", "r");
	if(!fp) return 0;

	while(fgets(buf, sizeof(buf), fp) != NULL)
	{
		if(p=strstr(buf, "\n"))
		{
			p[0]='\0';
		}
		if(strstr(buf,"HCSQ:")){
			memset(tmpBuf, '\0', sizeof(tmpBuf));
			strcpy(tmpBuf,buf);
			break;
		}
	}
	pclose(fp);

	if(strstr(tmpBuf,"LTE")){
		getNthValueSafe(2, tmpBuf, ',', rsrp, sizeof(rsrp));

		snprintf(str,sizeof(rsrp),"-%s",rsrp);
	}else if(strstr(tmpBuf,"NR")){
		getNthValueSafe(2, tmpBuf, ',', rsrp, sizeof(rsrp));

		snprintf(str,sizeof(rsrp),"-%s",rsrp);
	}

	return ;
}

void getSysUptime( char *tmpBuf)
{
	unsigned long sec, mn, hr, day;
	struct sysinfo info;


	sysinfo(&info);

	sec = (unsigned long) info.uptime ;


	day = sec / 86400;
	//day -= 10957; // day counted from 1970-2000

	sec %= 86400;
	hr = sec / 3600;
	sec %= 3600;
	mn = sec / 60;
	sec %= 60;

	sprintf(tmpBuf, "%lu;%lu;%lu;%lu", day, hr, mn, sec);

	return ;
}
