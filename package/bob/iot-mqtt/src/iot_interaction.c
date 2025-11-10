#include "iot_interaction.h"


extern char publishTmp[128];
extern struct mosquitto *mosqAll;


struct itimerval one_timer;
struct timers  warn_timer; //Alarm and alarm recovery report timer
struct timers  gpsd_timer; // gps data report timer
struct timers  nettype_timer; //nettype data report timer
struct timers  lteinfo_timer; //lteinfo data report timer
struct timers  zhuan_lteinfo_timer; //zhuan wang lteinfo data report timer
struct timers  sysinfo_timer;

int warning_interval = 300;
int gpsdata_interval = 86400;
int nettype_data_interval = 60;
int zhuan_lteinfo_interval = 300;
int lteinfo_interval = 3600;
int BindOKFlag=0;
int sysinfo_interval = 300;

char *get_string_json_object(json_object *js_obj, char *key)
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

int get_int_json_object(json_object *js_obj, char *key)
{
	json_object *js_tmp = NULL;
	char *str = NULL;

	js_tmp = json_object_object_get(js_obj, key);

	if (js_tmp != NULL) {
		str = (char *) json_object_get_string(js_tmp);

		if (str != NULL) {
			return atoi(str);
		}
	}

	return 0;
}




/*
ret 
MOSQ_ERR_CONN_PENDING = -1,
MOSQ_ERR_SUCCESS = 0,
MOSQ_ERR_NOMEM = 1,
MOSQ_ERR_PROTOCOL = 2,
MOSQ_ERR_INVAL = 3,
MOSQ_ERR_NO_CONN = 4,
MOSQ_ERR_CONN_REFUSED = 5,
MOSQ_ERR_NOT_FOUND = 6,
MOSQ_ERR_CONN_LOST = 7,
MOSQ_ERR_TLS = 8,
MOSQ_ERR_PAYLOAD_SIZE = 9,
MOSQ_ERR_NOT_SUPPORTED = 10,
MOSQ_ERR_AUTH = 11,
MOSQ_ERR_ACL_DENIED = 12,
MOSQ_ERR_UNKNOWN = 13,
MOSQ_ERR_ERRNO = 14,
MOSQ_ERR_EAI = 15,
MOSQ_ERR_PROXY = 16
*/
int publish_data(struct mosquitto *mosq, char *tp, const char *msg)
{
    char topic[128]= {0};
    int mid_sent = 0;
	int ret = -1;
    sprintf(topic,"%s",tp);
	log_message(L_INFO, "topic: %s\n",topic);
	log_message(L_INFO, "msg: %s\n",msg);
    ret = mosquitto_publish(mosq, &mid_sent, topic, strlen(msg), msg, 0, 0);


	return ret;
}

void send_set_respond(struct mosquitto *mosq, char *publishTmp, char *action, json_object* request)
{
	char lan_ip[16]={0}, mac[18]={0};
	json_object *respond_obj = NULL;
	const char *output = NULL;

	respond_obj = json_object_new_object();

	getIfIp("br-lan", lan_ip);
	getIfMac("br-lan", mac);
	
	json_object_object_add_string(respond_obj,"action", action);
	json_object_object_add_string(respond_obj,"mac", mac);
	json_object_object_add_string(respond_obj,"lan_ip", lan_ip);
	json_object_object_add_string(respond_obj,"error", "0");
	add_bollean_to_json_obj(respond_obj,"success", 1);

	if(json_object_object_get(request, "taskId") != NULL && get_int_json_object(request, "taskId") > 0)
		json_object_object_add_int(respond_obj,"taskId", get_int_json_object(request, "taskId"));

	output = json_object_to_json_string(respond_obj);
	publish_data(mosq,publishTmp,output);
	json_object_put(respond_obj);
}

void set_bind_status(int success)
{
	if(success == CONNECT_FAIL){
		datconf_set_by_key(TEMP_IOT_FILE, "iotm_connect_status", "1");
	}else if(success == CONNECT_SUCCESS){
		datconf_set_by_key(TEMP_IOT_FILE, "iotm_connect_status", "2");
	}else if(success == CONNECT_ING){
		datconf_set_by_key(TEMP_IOT_FILE, "iotm_connect_status", "3");
	}else if(success == BING_FAIL){
		datconf_set_by_key(TEMP_IOT_FILE, "iotm_bind_status", "1");
	}else if(success == BING_SUCCESS){
		datconf_set_by_key(TEMP_IOT_FILE, "iotm_bind_status", "2");
	}else if(success == BING_NO){
		datconf_set_by_key(TEMP_IOT_FILE, "iotm_bind_status", "3");
	}
}


void send_mqtt_offline()
{
	struct json_object *obj_all  = json_object_new_object();
	const char *output = NULL;
	char tmp_buf[18]={0};
	getIfMac("br-lan", tmp_buf);
	
	add_str_to_json_obj(obj_all,"action", "offline");
	add_str_to_json_obj(obj_all,"mac", tmp_buf);
	output = json_object_to_json_string(obj_all);
	mosquitto_will_set(mosqAll, publishTmp, strlen( output),  output, 2, true);
	json_object_put(obj_all);
}


void getFlowInfo(char *flow_up,char *flow_down, char *ifname)
{
	char current_flow_down[OPTION_STR_LEN] = {0},current_flow_up[OPTION_STR_LEN] = {0};
	char statistic_flow_down[OPTION_STR_LEN] = {0},statistic_flow_up[OPTION_STR_LEN] = {0};
	char last_flow_up[OPTION_STR_LEN] = {0},last_flow_down[OPTION_STR_LEN] = {0};
	char wan_tx[32],wan_rx[32];
	unsigned long long val_down =0 ,val_up = 0;

	snprintf(wan_tx, sizeof(wan_tx), "%llu", get_ifstats_bytes_tx(ifname));
	snprintf(wan_rx, sizeof(wan_rx), "%llu", get_ifstats_bytes_rx(ifname));


	snprintf(current_flow_down,OPTION_STR_LEN,"%d",(atoi(wan_tx))/1024);
	snprintf(current_flow_up,OPTION_STR_LEN,"%d",(atoi(wan_rx))/1024);

	datconf_get_by_key(TEMP_IOT_FILE, "iotm_flow_up", last_flow_up, sizeof(last_flow_up));
	datconf_get_by_key(TEMP_IOT_FILE, "iotm_flow_down", last_flow_down, sizeof(last_flow_down));

	if(atoi(last_flow_down)>atoi(current_flow_down))
	{
		sprintf(last_flow_down, "%s","0");
	}

	if(atoi(last_flow_up)>atoi(current_flow_up))
	{
		sprintf(last_flow_up, "%s","0");
	}
	val_down = atoi(current_flow_down)-atoi(last_flow_down);
	val_up = atoi(current_flow_up)-atoi(last_flow_up);
	snprintf(statistic_flow_down,OPTION_STR_LEN,"%llu",val_down);
	snprintf(statistic_flow_up,OPTION_STR_LEN,"%llu",val_up);

	if(strlen(statistic_flow_down) == 0)
		sprintf(statistic_flow_down, "%s","0");

	if(strlen(statistic_flow_up) == 0)
		sprintf(statistic_flow_up, "%s","0");

	datconf_set_by_key(TEMP_IOT_FILE, "iotm_flow_up", current_flow_up);
	datconf_set_by_key(TEMP_IOT_FILE, "iotm_flow_down", current_flow_down);

	sprintf(flow_up, "%s", statistic_flow_down);
	sprintf(flow_down, "%s", statistic_flow_up);

	return ;

}

int getUpTime()
{
	struct sysinfo info;
	
	sysinfo(&info);

	log_message(L_INFO, "info.uptime: %d\n",info.uptime);

	return (unsigned long) info.uptime ;

}


void local_bind_iotm(struct mosquitto *mosq)
{
	
	const char* output;
	int publish_ret = -1;
	unsigned long sec;
	int iotm_reboot_times = 0;
	char tmp_buf[32]={0}, mac[18]={0};
	struct interface_status status_modem, status_net;
	
	struct json_object *obj_all  = json_object_new_object();
	add_str_to_json_obj(obj_all,"action", "bind");

	getIfMac("br-lan", mac);
	add_str_to_json_obj(obj_all,"mac", mac);

	sec = getUpTime() ;

	if (sec < 120){
		Uci_Get_Int(PKG_IOT_CONFIG, "status", "reboot_times", &iotm_reboot_times);
		sprintf(tmp_buf, "%d", iotm_reboot_times+1);
		Uci_Set_Str(PKG_IOT_CONFIG, "status", "reboot_times", tmp_buf);
	}
		



/******************************************************************************************************
										data info start
*******************************************************************************************************/

	char version[RESULT_STR_LEN]={0};
	char network[SHORT_STR_LEN]={0};
	int sim = 1;

	struct json_object *obj_data = json_object_new_object();
	json_object_object_add(obj_all,"data", obj_data); 

	memset(tmp_buf, 0, sizeof(tmp_buf));
	Uci_Get_Str(PKG_IOT_CONFIG, "iotm", "bind_code", tmp_buf);
	add_str_to_json_obj(obj_data,"bindcode", tmp_buf);

	add_str_to_json_obj(obj_data,"gatewayIsReset", "1");

	memset(tmp_buf, 0, sizeof(tmp_buf));
	Uci_Get_Str(PKG_PRODUCT_CONFIG,"custom","csid",tmp_buf);
	add_str_to_json_obj(obj_data,"csid", tmp_buf);

	memset(tmp_buf, 0, sizeof(tmp_buf));
	Uci_Get_Str(PKG_PRODUCT_CONFIG,"sysinfo","soft_model",tmp_buf);
	add_str_to_json_obj(obj_data,"model", tmp_buf);

	get_soft_version(version,sizeof(version));
	add_str_to_json_obj(obj_data,"fwver", version);

	memset(&status_net, 0, sizeof(struct interface_status));
	get_wan_status(&status_net);
	if(status_net.up)
	{
		add_str_to_json_obj(obj_data, "ip", status_net.ipaddr_v4);	
		add_str_to_json_obj(obj_data, "mask", status_net.mask_v4);
		add_str_to_json_obj(obj_data, "gw", status_net.gateway_v4);	
	}else{
		add_str_to_json_obj(obj_data, "ip", "");
		add_str_to_json_obj(obj_data, "mask", "");	
		add_str_to_json_obj(obj_data, "gw", "");
	}

#if defined(BOARD_GPIO_SIM_CHANGE)
	sim = nvram_get_int("modem_sim");
	if(sim == 1){
		strcpy(network,"priv");
	}else if(sim == 2){
		strcpy(network,"pub");
	}
#else
	strcpy(network,"pub");
#endif
	add_str_to_json_obj(obj_data,"network", network);
	

/******************************************************************************************************
										data info end
*******************************************************************************************************/	


/******************************************************************************************************
										gps info start
*******************************************************************************************************/

	char *gpsReport = NULL;
	char longitude[SHORT_STR_LEN] = {0}, latitude[SHORT_STR_LEN] = {0};
	int ret = 0, support=0;

	struct json_object *obj_gps = json_object_new_object();
	json_object_object_add(obj_data,"gps", obj_gps); 

	Uci_Get_Int(PKG_PRODUCT_CONFIG, "custom", "GpsSupport", &support);
	if (1 == support)
	{
		json_object_object_add_int(obj_gps,"gps_support", support);
		
		Uci_Get_Str(PKG_WAN_MODEM_CONFIG, "gps", "manual_report", gpsReport);
		if(atoi(gpsReport)){
			Uci_Get_Str(PKG_WAN_MODEM_CONFIG, "gps", "longitude", longitude);
			Uci_Get_Str(PKG_WAN_MODEM_CONFIG, "gps", "lattitude", latitude);
			json_object_object_add_string(obj_gps, "longitude", longitude);
			json_object_object_add_string(obj_gps, "latitude", latitude);
		}else{
			ret = GetGpsParameter(latitude,longitude);
			if(ret){
				json_object_object_add_string(obj_gps,"longitude", longitude);
				json_object_object_add_string(obj_gps,"latitude", latitude);
			}else{
				json_object_object_add_string(obj_gps,"longitude", "0");
				json_object_object_add_string(obj_gps,"latitude", "0");
			}
		}
		
	}
	else{
		json_object_object_add_int(obj_gps,"gps_support", 0);
		json_object_object_add_string(obj_gps,"longitude", "0");
		json_object_object_add_string(obj_gps,"latitude", "0");
		
		datconf_set_by_key(TEMP_IOT_FILE, "iot_gps_not_report", "1");
	}

	
/******************************************************************************************************
										gps info end
*******************************************************************************************************/

/******************************************************************************************************
										lte info start
*******************************************************************************************************/

	int modem_link = 0;
	char statistic_flow_down[OPTION_STR_LEN] = {0},statistic_flow_up[OPTION_STR_LEN] = {0},signal[OPTION_STR_LEN] = {0};
	char *modem_isp = NULL;
	char isp_imsi[8] = {0};

	struct json_object *obj_lte = json_object_new_object();
	json_object_object_add(obj_data,"lte_info", obj_lte); 

	memset(&status_modem, 0, sizeof(struct interface_status));
	get_interface_status(&status_modem, "wan0");
	modem_link = status_modem.up;
	if (modem_link)
	{
		getFlowInfo(statistic_flow_up,statistic_flow_down, status_modem.device);
		
	}

	if(modem_link)
	{
		json_object_object_add_string(obj_lte, "ip", status_modem.ipaddr_v4);		
	}else{
		json_object_object_add_string(obj_lte, "ip", status_net.ipaddr_v4);
	}

	json_object_object_add_string(obj_lte, "iccid", "0");
	json_object_object_add_string(obj_lte, "eci", "0");

	get_pci_to_obj(obj_lte);
	get_imei_to_obj(obj_lte);
	get_signal(signal);
	json_object_object_add_string(obj_lte, "signal", signal);
	
	
	if(strlen(statistic_flow_up)>0)
		json_object_object_add_string(obj_lte, "flow_up", statistic_flow_up);
	else
		json_object_object_add_string(obj_lte, "flow_up", "0");


	if(strlen(statistic_flow_down)>0)
		json_object_object_add_string(obj_lte, "flow_down", statistic_flow_down);
	else
		json_object_object_add_string(obj_lte, "flow_down", "0");	
	
	
#if 0
	modem_isp = nvram_safe_get("modem_isp");
	if ( !strcmp(modem_isp, "China Telecom") )
		json_object_object_add_string(obj_lte, "isp", "3");
	else if ( !strcmp(modem_isp, "China Mobile") )
		json_object_object_add_string(obj_lte, "isp", "1");
	else if ( !strcmp(modem_isp, "China Unicom") )
		json_object_object_add_string(obj_lte, "isp", "2");
	else if ( !strcmp(modem_isp, "China Railcom") )
		json_object_object_add_string(obj_lte, "isp", "4");
	else if ( !strcmp(modem_isp, "China Spacecom") )
		json_object_object_add_string(obj_lte, "isp", "1"); /* FIXME */
	else
#endif
	{
		getiotISPinfo(isp_imsi);
		if(strlen(isp_imsi)>0)
			json_object_object_add_string(obj_lte, "isp", isp_imsi);
		else
			json_object_object_add_string(obj_lte, "isp", "0");
	}

/******************************************************************************************************
										lte info end
*******************************************************************************************************/

	output = json_object_to_json_string(obj_all);
	publish_ret = publish_data(mosq,publishTmp,output);
	json_object_put(obj_all); 
	

	return ;
}


#if defined(SU_ZHUAN_WANG)

void zhuan_lteinfo_send_iotm()
{
	log_message(L_DEBUG,"enter zhuan_lteinfo_send_iotm.\n\n", __FUNCTION__, __LINE__);
	int interval=300;
	char isp_imsi[8] = {0},				version[RESULT_STR_LEN]={0};
	char *modem_isp = NULL;
	const char* output;
	int publish_ret = -1;
	int modem_link = 0;
	char statistic_flow_down[OPTION_STR_LEN] = {0},statistic_flow_up[OPTION_STR_LEN] = {0};
	char timesTamp[RESULT_STR_LEN]={0},timesHoure[RESULT_STR_LEN]={0};
	struct interface_status status_modem;
	char tmp_buf[32]={0}, mac[18]={0};
	
	Uci_Get_Int(PKG_IOT_CONFIG, "iotm", "zhuan_lte_interval", &interval);
	if(interval > 0)
		zhuan_lteinfo_interval = interval;
	
	log_message(L_DEBUG,"iotm_zhuan_lteinfo_interval is: %d\n",zhuan_lteinfo_interval);
	
	struct json_object *obj_all  = json_object_new_object();
	json_object_object_add_string(obj_all,"action", "lte_info");
	getIfMac("br-lan", mac);
	json_object_object_add_string(obj_all,"mac", mac);
	

	struct json_object *obj_data = json_object_new_object();

	getCmdStr("date +%s",timesTamp,sizeof(timesTamp));
	json_object_object_add_string(obj_data, "date", timesTamp);

	getCmdStr("date +%H",timesHoure,sizeof(timesHoure));
	json_object_object_add_int(obj_data, "hour", atoi(timesHoure));


	memset(&status_modem, 0, sizeof(struct interface_status));
	get_interface_status(&status_modem, "wwan");
	modem_link = status_modem.up;
	if (modem_link)
	{
		getFlowInfo(statistic_flow_up,statistic_flow_down, status_modem.device);
		json_object_object_add_string(obj_data,"flow_up", statistic_flow_up);
		json_object_object_add_string(obj_data,"flow_down", statistic_flow_down);
	}else{
		json_object_object_add_string(obj_data,"flow_up", "0");
		json_object_object_add_string(obj_data,"flow_down", "0");
	}
	//only dianli need the three

	//json_object_object_add_string(obj_data, "eci",get_wan_unit_value(unit, "eci"));


	getCmdStr("date +%s",timesTamp,sizeof(timesTamp));
	json_object_object_add_string(obj_data, "date", timesTamp);

	getCmdStr("date +%H",timesHoure,sizeof(timesHoure));
	json_object_object_add_int(obj_data, "hour", atoi(timesHoure));



	if(modem_link == 1)
	{
		json_object_object_add_string(obj_data, "ip", status_modem.ipaddr_v4);		
	}else{
		memset(tmp_buf, 0, sizeof(tmp_buf));
		getIfIp(WAN_IFNAME, tmp_buf);
		json_object_object_add_string(obj_data, "ip", tmp_buf);
	}

#if 0
	modem_isp = nvram_safe_get("modem_isp");
	if ( !strcmp(modem_isp, "China Telecom") )
		json_object_object_add_string(obj_data, "isp", "3");
	else if ( !strcmp(modem_isp, "China Mobile") )
		json_object_object_add_string(obj_data, "isp", "1");
	else if ( !strcmp(modem_isp, "China Unicom") )
		json_object_object_add_string(obj_data, "isp", "2");
	else if ( !strcmp(modem_isp, "China Railcom") )
		json_object_object_add_string(obj_data, "isp", "4");
	else if ( !strcmp(modem_isp, "China Spacecom") )
		json_object_object_add_string(obj_data, "isp", "1"); /* FIXME */
	else
#endif
	{
		getiotISPinfo(isp_imsi);
		json_object_object_add_string(obj_data, "isp", isp_imsi);
	}

	json_object_object_add_string(obj_data, "iccid", "");

	memset(tmp_buf, 0, sizeof(tmp_buf));
	get_modem_param_value("get_sinr", "sinr", tmp_buf);
	json_object_object_add_string(obj_data, "sinr", tmp_buf);

	get_pci_to_obj(obj_data);
	get_imei_to_obj(obj_data);
	
	get_soft_version(version,sizeof(version));
	json_object_object_add_string(obj_data,"fwver", version);
	
	json_object_object_add(obj_all,"data", obj_data); 
	output = json_object_to_json_string(obj_all);
	publish_ret = publish_data(mosqAll,publishTmp,output);
	json_object_put(obj_all); 
}

#else

void lteinfo_send_iotm()
{
	log_message(L_DEBUG,"enter lteinfo_send_iotm.\n\n", __FUNCTION__, __LINE__);	
	
	char isp_imsi[8] = {0},	version[RESULT_STR_LEN]={0},timesTamp[RESULT_STR_LEN]={0},timesHoure[RESULT_STR_LEN]={0},signal[RESULT_STR_LEN]={0};
	char *modem_isp = NULL;
	const char* output;
	int publish_ret = -1;
	int interval=3600;
	int modem_link = 0;
	char statistic_flow_down[OPTION_STR_LEN] = {0},statistic_flow_up[OPTION_STR_LEN] = {0};
	char tmp_buf[32], mac[18]={0};
	struct interface_status status_modem;
	
	Uci_Get_Int(PKG_IOT_CONFIG, "iotm", "lte_interval", &interval);
	if(interval > 0)
		lteinfo_interval = interval;
	
	log_message(L_DEBUG,"iotm_lteinfo_interval is: %d\n",lteinfo_interval);
	
	struct json_object *obj_all  = json_object_new_object();
	json_object_object_add_string(obj_all,"action", "lte_info");
	getIfMac("br-lan", mac);
	json_object_object_add_string(obj_all,"mac", mac);

	struct json_object *obj_data = json_object_new_object();


	getCmdStr("date +%s",timesTamp,sizeof(timesTamp));
	json_object_object_add_string(obj_data, "date", timesTamp);

	getCmdStr("date +%H",timesHoure,sizeof(timesHoure));
	json_object_object_add_int(obj_data, "hour", atoi(timesHoure));

	memset(&status_modem, 0, sizeof(struct interface_status));
	get_interface_status(&status_modem, "wan0");
	modem_link = status_modem.up;
	if (modem_link)
	{
		getFlowInfo(statistic_flow_up,statistic_flow_down, status_modem.device);
		json_object_object_add_string(obj_data,"flow_up", statistic_flow_up);
		json_object_object_add_string(obj_data,"flow_down", statistic_flow_down);
	}else{
		json_object_object_add_string(obj_data,"flow_up", "0");
		json_object_object_add_string(obj_data,"flow_down", "0");
	}

	if(modem_link == 1)
	{
		json_object_object_add_string(obj_data, "ip", status_modem.ipaddr_v4);		
	}else{
		getIfIp(WAN_IFNAME, tmp_buf);
		json_object_object_add_string(obj_data, "ip", tmp_buf);
	}
#if 0
	modem_isp = nvram_safe_get("modem_isp");
	if ( !strcmp(modem_isp, "China Telecom") )
		json_object_object_add_string(obj_data, "isp", "3");
	else if ( !strcmp(modem_isp, "China Mobile") )
		json_object_object_add_string(obj_data, "isp", "1");
	else if ( !strcmp(modem_isp, "China Unicom") )
		json_object_object_add_string(obj_data, "isp", "2");
	else if ( !strcmp(modem_isp, "China Railcom") )
		json_object_object_add_string(obj_data, "isp", "4");
	else if ( !strcmp(modem_isp, "China Spacecom") )
		json_object_object_add_string(obj_data, "isp", "1"); /* FIXME */
	else
#endif
	{
		getiotISPinfo(isp_imsi);
		json_object_object_add_string(obj_data, "isp", isp_imsi);
	}
	
	get_soft_version(version,sizeof(version));
	json_object_object_add_string(obj_data,"fwver", version);
	
	memset(tmp_buf, 0, sizeof(tmp_buf));
	get_modem_param_value("get_sinr", "sinr", tmp_buf);
	json_object_object_add_string(obj_data, "sinr", tmp_buf);

	get_pci_to_obj(obj_data);
	get_imei_to_obj(obj_data);
	get_signal(signal);
	json_object_object_add_string(obj_data, "signal",signal);
#if 1	
	json_object_object_add_string(obj_data, "iccid", "");
	json_object_object_add_string(obj_data, "eci", "");
#endif
	json_object_object_add(obj_all,"data", obj_data); 
	output = json_object_to_json_string(obj_all);
	publish_ret = publish_data(mosqAll,publishTmp,output);

	json_object_put(obj_all); 
}

#endif

void gpsdata_send_iotm()
{
	int support=0, not_report=0;

	Uci_Get_Int(PKG_PRODUCT_CONFIG, "custom", "GpsSupport", &support);
	Uci_Get_Int(PKG_IOT_CONFIG, "itom", "gps_not_report", &not_report);
	if(1 == not_report && 0 == support){
		log_message(L_DEBUG,"iotm: %s %d,1 == iot_gps_not_report && gps_support == 0\n\n", __FUNCTION__, __LINE__);
		return;
	}
	

	char longitude[SHORT_STR_LEN] = {0}, latitude[SHORT_STR_LEN] = {0}, mac[18]={0};
	int gps_interval = 0;
	int ret = 0,gps_enable = 1;
	char *gpsReport = NULL;
	const char* output;
	int publish_ret = -1;

	Uci_Get_Int(PKG_WAN_MODEM_CONFIG, "gps", "enable", &gps_enable);
	if(gps_enable == 0){
		log_message(L_DEBUG,"gps_enable : %d\n",gps_enable);
		return;
	}	

	//gps_interval = nvram_get_int("gps_interval_new");
	if(gps_interval == 0)
		gpsdata_interval = 86400;
	else{
		if(gps_interval > 0)
			gpsdata_interval = gps_interval;
	}

	log_message(L_DEBUG,"gpsdata_interval is: %d\n",gpsdata_interval);

	struct json_object *obj_all  = json_object_new_object();
	json_object_object_add_string(obj_all,"action", "gpsdata");
	getIfMac("br-lan", mac);
	json_object_object_add_string(obj_all,"mac", mac);
	


	struct json_object *obj_data = json_object_new_object();
	if (1 == support)
	{
		json_object_object_add_string(obj_data,"gps_support", support);		
		Uci_Get_Str(PKG_WAN_MODEM_CONFIG, "gps", "manual_report", gpsReport);
		
		if(atoi(gpsReport)){
			Uci_Get_Str(PKG_WAN_MODEM_CONFIG, "gps", "longitude", longitude);
			Uci_Get_Str(PKG_WAN_MODEM_CONFIG, "gps", "lattitude", latitude);
			json_object_object_add_string(obj_data, "longitude", longitude);
			json_object_object_add_string(obj_data, "latitude", latitude);
		}else{
			ret = GetGpsParameter(latitude,longitude);
			if(ret){
				json_object_object_add_string(obj_data,"longitude", longitude);
				json_object_object_add_string(obj_data,"latitude", latitude);
			}else{
				json_object_object_add_string(obj_data,"longitude", "");
				json_object_object_add_string(obj_data,"latitude", "");
			}
		}
		
		log_message(L_DEBUG,"ret_gpsdata : %d\n",ret);
		log_message(L_DEBUG,"[%s:%d] longitude:%s;latitude:%s\n", __FUNCTION__, __LINE__,longitude,latitude);
	}
	else{
		json_object_object_add_string(obj_data,"gps_support", "0");
		json_object_object_add_string(obj_data,"longitude", "");
		json_object_object_add_string(obj_data,"latitude", "");
		datconf_set_by_key(TEMP_IOT_FILE, "iot_gps_not_report", "1");
	}
	
	json_object_object_add(obj_all,"data", obj_data); 
	output = json_object_to_json_string(obj_all);
	publish_ret = publish_data(mosqAll,publishTmp,output);
	json_object_put(obj_all); 

}


void getSysInfo(){
    
    const char *output = NULL;
    int publish_ret = -1;
    char tmpBuf[64] = {0};
	char lan_hwaddr[16]={0};
	
	json_object *respond_obj = NULL, *root = NULL;
    respond_obj = json_object_new_object();
    // 添加 action 字段
    json_object_object_add_string(respond_obj, "action", "getSysInfo");
	Uci_Get_Str(PKG_NETWORK_CONFIG, "lan", "macaddr",lan_hwaddr);
	json_object_object_add_string(respond_obj,"mac", lan_hwaddr);
   	getSysUptime(tmpBuf);
	json_object_object_add_string(respond_obj,"upTime", tmpBuf);
    output = json_object_to_json_string(respond_obj);
	//printf("output [%s]\n",output);
	publish_ret = publish_data(mosqAll,publishTmp,output);
	json_object_put(respond_obj);

	return ;
  
}

#if defined(BOARD_GPIO_SIM_CHANGE)	
void nettype_send_iotm()
{
	log_message(L_DEBUG,"enter nettype_send_iotm.\n\n", __FUNCTION__, __LINE__);

	char network[SHORT_STR_LEN]={0}, mac[18]={0};
	int nettype_interval=60;
	static char current_sim[SHORT_STR_LEN]={0};
	const char* output;
	int publish_ret = -1;

	Uci_Get_Int(PKG_IOT_CONFIG, "iotm", "nettype_interval", nettype_interval);
	if(nettype_interval <= 0)
		nettype_interval=60;
		
	int sim = nvram_get_int("modem_sim");

	log_message(L_DEBUG,"current_sim is: %s,sim is %d\n",current_sim,sim);

	if(sim != atoi(current_sim))
	{
		sprintf(current_sim,"%d",sim);
	
		log_message(L_DEBUG,"current_sim is: %s,sim is %d\n",current_sim,sim);
		if(atoi(current_sim) == 1){
			strcpy(network,"priv");
		}else if(atoi(current_sim) == 2){
			strcpy(network,"pub");
		}
	
		struct json_object *obj_all  = json_object_new_object();
		json_object_object_add_string(obj_all,"action", "network_type");
		getIfMac("br-lan", mac);
		json_object_object_add_string(obj_all,"mac", mac);
		

		struct json_object *obj_data = json_object_new_object();
		json_object_object_add_string(obj_data,"network", network);
		json_object_object_add(obj_all,"data", obj_data); 
		output = json_object_to_json_string(obj_all);
		publish_ret = publish_data(mosqAll,publishTmp,output);

		json_object_put(obj_all); 
	}

}

#endif


int GetWarningRecover()
{	
	char signal[OPTION_STR_LEN] = {0},sinr[OPTION_STR_LEN] = {0};
	char startTimes[SHORT_STR_LEN] = {0};
	char current_signal[OPTION_STR_LEN] = {0},current_sinr[OPTION_STR_LEN] = {0};
	char current_startTimes[SHORT_STR_LEN] = {0};
	char type[OPTION_STR_LEN] = {0}, signal_warning[SHORT_STR_LEN] = {0};
	char sinr_warning[SHORT_STR_LEN] = {0},reboot_warning[SHORT_STR_LEN] = {0};
	char mac[18]={0};
	int resume = 0;
	long uptime = 0;
	const char* output;
	int publish_ret = -1, iotm_signal=0, iotm_sinr=0, iotm_start_times=0;
	unsigned long sec;
	
	struct json_object *obj_all  = json_object_new_object();
	struct json_object *data = json_object_new_array(); 

	json_object_object_add_string(obj_all,"action", "warning_resume");
	getIfMac("br-lan", mac);
	json_object_object_add_string(obj_all,"mac", mac);
	
	get_signal(current_signal);
	get_modem_param_value("get_sinr", "sinr", current_sinr);
	
	Uci_Get_Int(PKG_IOT_CONFIG, "iotm", "signal", &iotm_signal);
	if(iotm_signal == 0)
		sprintf(signal, "%s", "30");
	else
		sprintf(signal, "%d", iotm_signal);

	Uci_Get_Int(PKG_IOT_CONFIG, "iotm", "sinr", &iotm_sinr);
	if(iotm_sinr == 0)
		sprintf(sinr, "%s", "15");
	else
		sprintf(sinr, "%d", iotm_sinr);

	Uci_Get_Int(PKG_IOT_CONFIG, "iotm", "startTimes", &iotm_start_times);
	if(iotm_start_times == 0)
		sprintf(startTimes, "%s", "3");
	else
		sprintf(startTimes, "%d", iotm_start_times);


	Uci_Get_Str(PKG_IOT_CONFIG, "status", "reboot_times", current_startTimes);
	Uci_Get_Str(PKG_IOT_CONFIG, "status", "signal_warning", signal_warning);
	Uci_Get_Str(PKG_IOT_CONFIG, "status", "sinr_warning", sinr_warning);
	Uci_Get_Str(PKG_IOT_CONFIG, "status", "reboot_warning", reboot_warning);

	//printf("signal,sinr,startTimes is:%s,%s,%s\n",signal,sinr,startTimes);
	//printf("current_signal,current_sinr,current_startTimes is:%s,%s,%s\n",current_signal,current_sinr,current_startTimes);

	struct json_object *dataObj1 = json_object_new_object();
	struct json_object *dataObj2 = json_object_new_object();
	struct json_object *dataObj3 = json_object_new_object();

	if(atoi(current_signal)<=atoi(signal))
	{
		Uci_Set_Str(PKG_IOT_CONFIG, "status", "signal_warning", "1");
	}
	else
	{
		if(atoi(signal_warning)==1)
		{
			Uci_Set_Str(PKG_IOT_CONFIG, "status", "signal_warning", "0");
			sprintf(type, "signal");
			json_object_object_add_string(dataObj1,"type", type);
			json_object_object_add_int(dataObj1,"val", atoi(current_signal));
			json_object_array_add(data, dataObj1);
			resume=1;
		}
	}
	
	if(atoi(current_sinr)<atoi(sinr))
	{
		Uci_Set_Str(PKG_IOT_CONFIG, "status", "sinr_warning", "1");
	}
	else
	{
		if(atoi(sinr_warning)==1)
		{
			Uci_Set_Str(PKG_IOT_CONFIG, "status", "sinr_warning", "0");
			sprintf(type, "sinr");
			json_object_object_add_string(dataObj2,"type", type);
			json_object_object_add_int(dataObj2,"val", atoi(current_sinr));
			json_object_array_add(data, dataObj2);
			resume=1;
		}
	}

	if(atoi(startTimes)<=atoi(current_startTimes))
	{
		Uci_Set_Str(PKG_IOT_CONFIG, "status", "reboot_warning", "1");
	}
	else
	{
		if(atoi(reboot_warning)==1)
		{
			Uci_Set_Str(PKG_IOT_CONFIG, "status", "reboot_warning", "0");
			sprintf(type, "restart");
			json_object_object_add_string(dataObj3,"type", type);
			json_object_object_add_int(dataObj3,"val", atoi(current_startTimes));
			json_object_array_add(data, dataObj3);
			resume=1;
		}
	}
	
	json_object_object_add(obj_all,"data", data);
/*	
	sec = getUpTime() ;
	if (sec>90)//Run correctly
	{
		nvram_set("iotm_reboot_times", "0");
	}
*/
	Uci_Commit(PKG_IOT_CONFIG);
	
	if(resume ==1){
		output = json_object_to_json_string(obj_all);
		publish_ret = publish_data(mosqAll,publishTmp,output);
	}

	
	resume = 0;
	json_object_put(obj_all);
	return 0;

}


int GetWarningParameter()
{	
	log_message(L_DEBUG,"iotm: %s %d\n\n", __FUNCTION__, __LINE__);
	char signal[OPTION_STR_LEN] = {0},sinr[OPTION_STR_LEN] = {0};
	char startTimes[SHORT_STR_LEN] = {0};
	char current_signal[OPTION_STR_LEN] = {0},current_sinr[OPTION_STR_LEN] = {0};
	char current_startTimes[SHORT_STR_LEN] = {0};
	char iot_sinal_warning_finish[OPTION_STR_LEN] = {0},iot_sinr_warning_finish[OPTION_STR_LEN] = {0},iot_reboot_warning_finish[OPTION_STR_LEN] = {0};
	char type[OPTION_STR_LEN] = {0}, mac[18]={0};
	int sinagl_ret=0,sinr_ret=0,reboot_ret=0, iotm_start_times=0;
	//int sys_reboot = 0;
	long uptime = 0;
	const char* output;
	int publish_ret = -1, iotm_signal=0, iotm_sinr=0 ;
	unsigned long sec;
	
	struct json_object *obj_all  = json_object_new_object();
	struct json_object *data = json_object_new_array(); 

	json_object_object_add_string(obj_all,"action", "warning");
	getIfMac("br-lan", mac);
	json_object_object_add_string(obj_all,"mac", mac);
	
	get_signal(current_signal);
	get_modem_param_value("get_sinr", "sinr", current_sinr);

	Uci_Get_Int(PKG_IOT_CONFIG, "iotm", "signal", &iotm_signal);
	if(iotm_signal == 0)
		sprintf(signal, "%s", "30");
	else
		sprintf(signal, "%d", iotm_signal);

	Uci_Get_Int(PKG_IOT_CONFIG, "iotm", "sinr", &iotm_sinr);
	if(iotm_sinr == 0)
		sprintf(sinr, "%s", "15");
	else
		sprintf(sinr, "%d", iotm_sinr);

	Uci_Get_Int(PKG_IOT_CONFIG, "iotm", "startTimes", &iotm_start_times);
	if(iotm_start_times == 0)
		sprintf(startTimes, "%s", "3");
	else
		sprintf(startTimes, "%d", iotm_start_times);
	
	Uci_Get_Str(PKG_IOT_CONFIG, "status", "reboot_times", current_startTimes);
	Uci_Get_Str(PKG_IOT_CONFIG, "status", "sinal_warning_finish", iot_sinal_warning_finish);
	Uci_Get_Str(PKG_IOT_CONFIG, "status", "sinr_warning_finish", iot_sinr_warning_finish);
	Uci_Get_Str(PKG_IOT_CONFIG, "status", "reboot_warning_finish", iot_reboot_warning_finish);
	
	//strcpy(signal,"90");//Debugging data
	//strcpy(sinr,"3");
	
	log_message(L_DEBUG, "signal,sinr,startTimes is:%s,%s,%s\n",signal,sinr,startTimes);
	log_message(L_DEBUG, "current_signal,current_sinr,current_startTimes is:%s,%s,%s\n",current_signal,current_sinr,current_startTimes);
	log_message(L_DEBUG, "iot_sinal_warning_finish,iot_sinr_warning_finish,iot_reboot_warning_finish is:%s,%s,%s\n",iot_sinal_warning_finish,iot_sinr_warning_finish,iot_reboot_warning_finish);

	struct json_object *dataObj1 = json_object_new_object();
	struct json_object *dataObj2 = json_object_new_object();
	struct json_object *dataObj3 = json_object_new_object();
	//struct json_object *dataObj4 = json_object_new_object();

	if(atoi(current_signal)<atoi(signal))
	{
		if(atoi(iot_sinal_warning_finish)==1){
			sinagl_ret=0;
		}else{
			sinagl_ret=1;
			sprintf(type, "signal");
			json_object_object_add_string(dataObj1,"type", type);
			json_object_object_add_int(dataObj1,"val", atoi(current_signal));
			json_object_array_add(data, dataObj1);
		}
		log_message(L_DEBUG,"iot_sinal_warning_finish: %s %d ret = %d\n\n", __FUNCTION__, __LINE__,sinagl_ret);	
		Uci_Set_Str(PKG_IOT_CONFIG, "status", "sinal_warning_finish", "1");
	}else{
		Uci_Set_Str(PKG_IOT_CONFIG, "status", "sinal_warning_finish", "0");
	}
	
	if(atoi(current_sinr)<atoi(sinr))
	{
		
		if(atoi(iot_sinr_warning_finish)==1){
			sinr_ret=0;
		}else{
			sinr_ret=1;	
			sprintf(type, "sinr");
			json_object_object_add_string(dataObj2,"type", type);
			json_object_object_add_int(dataObj2,"val", atoi(current_sinr));
			json_object_array_add(data, dataObj2);
		}
		log_message(L_DEBUG,"iot_sinr_warning_finish: %s %d ret = %d\n\n", __FUNCTION__, __LINE__,sinr_ret);
		Uci_Set_Str(PKG_IOT_CONFIG, "status", "sinr_warning_finish", "1");
	}else{
		Uci_Set_Str(PKG_IOT_CONFIG, "status", "sinr_warning_finish", "0");
	}

	if(atoi(startTimes)<=atoi(current_startTimes))
	{
		if(atoi(iot_reboot_warning_finish)==1){
		   	reboot_ret=0;
		}else{
			reboot_ret=1;
			sprintf(type, "restart");
			json_object_object_add_string(dataObj3,"type", type);
			json_object_object_add_int(dataObj3,"val", atoi(current_startTimes));
			json_object_array_add(data, dataObj3);
		}
		log_message(L_DEBUG,"iot_reboot_warning_finish: %s %d ret = %d\n\n", __FUNCTION__, __LINE__,reboot_ret);
		Uci_Set_Str(PKG_IOT_CONFIG, "status", "reboot_warning_finish", "1");
	}else{
		Uci_Set_Str(PKG_IOT_CONFIG, "status", "reboot_warning_finish", "0");
	}


	json_object_object_add(obj_all,"data", data);

	

	sec = getUpTime() ;
	if (sec>120)//Run correctly
	{
		Uci_Set_Str(PKG_IOT_CONFIG, "status", "reboot_times", "0");
	}

	log_message(L_DEBUG,"iotm: %s %d sinagl_ret = %d ,sinr_ret=%d,reboot_ret=%d\n\n", __FUNCTION__, __LINE__,sinagl_ret,sinr_ret,reboot_ret);
	if(sinr_ret==1 || sinagl_ret==1 ||  reboot_ret==1){
		output = json_object_to_json_string(obj_all);
		publish_ret = publish_data(mosqAll,publishTmp,output);

	}
	
	Uci_Commit(PKG_IOT_CONFIG);
	
	sinagl_ret=0;
	sinr_ret=0;
	reboot_ret=0;
	json_object_put(obj_all);
	return 0;

}


void warning_send_iotm() 
{

	int iotm_warning_interval=3600;

	Uci_Get_Int(PKG_IOT_CONFIG, "iotm", "warning_interval", &iotm_warning_interval);
	if(iotm_warning_interval > 0)
		warning_interval = iotm_warning_interval;
	
	log_message(L_DEBUG,"warning_interval is: %d\n",warning_interval);

	GetWarningRecover();
	GetWarningParameter();
}


void getLanConfig(struct mosquitto *mosq)
{
	json_object *respond_obj = NULL;
	const char *output = NULL;
	int intVal=0;
	char lanIp[16]={0}, mac[18]={0};
	char lanNetmask[16]={0}, dhcpServer[8]={0};
	char dhcpStart[16]={0}, dhcpEnd[16]={0}, *dhcpLease = NULL;
	int publish_ret = -1;

	respond_obj = json_object_new_object();

	
	getIfIp("br-lan", lanIp);
	getIfMask("br-lan", lanNetmask);
	Uci_Get_Int(PKG_DHCP_CONFIG,"lan","ignore",&intVal);
	if(intVal == 0)
		strcpy(dhcpServer, "1");
	else
		strcpy(dhcpServer, "0");

	get_uci2json(respond_obj, PKG_DHCP_CONFIG, "lan", "start",	 	 "dhcpStart");
	get_uci2json(respond_obj, PKG_DHCP_CONFIG, "lan", "dhcp_e",	 "dhcpEnd");
	Uci_Get_Str(PKG_DHCP_CONFIG, "lan", "start",	dhcpStart);
	Uci_Get_Str(PKG_DHCP_CONFIG, "lan", "dhcp_e",	dhcpEnd);
	Uci_Get_Str(PKG_DHCP_CONFIG, "lan", "leasetime",	dhcpLease);

	json_object_object_add_string(respond_obj, "action", "getLanConfig");
	getIfMac("br-lan", mac);
	json_object_object_add_string(respond_obj, "mac", mac);

	json_object_object_add_string(respond_obj, "lanIp", lanIp);
	json_object_object_add_string(respond_obj, "lanNetmask", lanNetmask);
	json_object_object_add_string(respond_obj, "dhcpServer", dhcpServer);
	json_object_object_add_string(respond_obj, "dhcpStart", dhcpStart);
	json_object_object_add_string(respond_obj, "dhcpEnd", dhcpEnd);
	json_object_object_add_string(respond_obj, "dhcpLease", dhcpLease);

	json_object_object_add_string(respond_obj, "lanIpv6", "");
	json_object_object_add_string(respond_obj, "ipv6Mode", "1");
	json_object_object_add_string(respond_obj, "ipv6Start", "");
	json_object_object_add_string(respond_obj, "ipv6End", "");
	json_object_object_add_string(respond_obj, "ipv6Lease", "7200");

	output = json_object_to_json_string(respond_obj);
	publish_ret = publish_data(mosq,publishTmp,output);
	json_object_put(respond_obj);

	return ;
}


void setIotConfig (struct mosquitto *mosq, json_object* request)
{
	json_object *request_obj;

	int interval = 0;
	char tmp_buf[16]={0};
	
	request_obj = json_object_object_get(request, "data");
	
 	interval = get_int_json_object(request_obj, "interval");

	if(interval > 0){
		warn_timer.interval = interval;
		sprintf(tmp_buf, "%d", interval);
		Uci_Set_Str(PKG_IOT_CONFIG, "iotm", "warning_interval", tmp_buf);
	}
	memset(tmp_buf, 0, sizeof(tmp_buf));
	sprintf(tmp_buf, "%d", get_int_json_object(request_obj, "singnal"));
	Uci_Set_Str(PKG_IOT_CONFIG, "iotm", "signal", tmp_buf);

	memset(tmp_buf, 0, sizeof(tmp_buf));
	sprintf(tmp_buf, "%d", get_int_json_object(request_obj, "sinr"));
	Uci_Set_Str(PKG_IOT_CONFIG, "iotm", "sinr", tmp_buf);

	memset(tmp_buf, 0, sizeof(tmp_buf));
	sprintf(tmp_buf, "%d", get_int_json_object(request_obj, "startTime"));
	Uci_Set_Str(PKG_IOT_CONFIG, "iotm", "startTimes", tmp_buf);
		
	Uci_Commit(PKG_IOT_CONFIG);

	send_set_respond(mosq,publishTmp,"setIotConfig",request);
//	notify_rc("restart_iot");

}

// 读取文件内容到缓冲区的函数
int read_file_to_buffer(const char* filename, char** buf, size_t* size) {
    FILE* file = fopen(filename, "rb");  // 以二进制模式打开文件
    if (!file) {
        perror("Failed to open file");
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
void debug_cmd(struct mosquitto *mosq, json_object* request)
{	 
	const char *output = NULL;
	int publish_ret = -1;
	char *cmd = get_string_json_object(request, "cmd");
	char *uuid = get_string_json_object(request, "uuid");
    char buf[512];
	char* udp_file_buffer = NULL;
	size_t udp_file_size = 0;
	int udp_result = read_file_to_buffer("/tmp/udp_cmd_running", &udp_file_buffer, &udp_file_size);
	if (udp_result == 0 && udp_file_size > 0 && (strcmp(udp_file_buffer, "1") == 0)) {
            // 检查文件内容是否包含关键字符串
            dbg("[RID_TTY] UDP_CMD is running\n");
            sleep(2);  // 等待2秒后再次执行
    }
	
	FILE *iot_file = fopen("/tmp/iot_cmd_running", "w");
	if (iot_file) {
		fprintf(iot_file, "1");
		fclose(iot_file);
	}
    snprintf(buf, sizeof(buf), "/usr/bin/debug_cmd %s", cmd);
	system("killall -9 debug_cmd 2> /dev/null");
	system(buf);

	// 读取文件到缓冲区
    char* file_buffer = NULL;
    size_t file_size = 0;
    int result = read_file_to_buffer("/tmp/debug_data", &file_buffer, &file_size);

	char lanaddr[16]={0};
	Uci_Get_Str(PKG_NETWORK_CONFIG, "lan", "macaddr",	lanaddr);
	json_object *respond_obj = NULL;
	respond_obj = json_object_new_object();
	json_object_object_add_string(respond_obj,"mac",lanaddr);
	json_object_object_add_string(respond_obj, "action","debug_cmd");
	json_object_object_add_string(respond_obj, "uuid", uuid);
	json_object_object_add_string(respond_obj, "cmd", cmd);

	if (result == 0) {
		if(file_size > 0)
		{
			json_object_object_add_string(respond_obj, "status","OK");
			json_object_object_add_string(respond_obj, "data", file_buffer);
		}
		else
		{
			json_object_object_add_string(respond_obj, "status","error");
			json_object_object_add_string(respond_obj, "data", "");
		}

		if (file_buffer) 
		{
			free(file_buffer);  // 仅释放非空指针
		}
	}
	else
	{
		json_object_object_add_string(respond_obj, "status","error");
		json_object_object_add_string(respond_obj, "data", "");
	}

	output = json_object_to_json_string(respond_obj);
	publish_ret = publish_data(mosqAll,publishTmp,output);
	json_object_put(respond_obj);
	system("rm -f /tmp/iot_cmd_running >/dev/null 2>&1");  // 删除文件
}

void returnBindState (struct mosquitto *mosq, json_object* request)
{
	if(strcmp(get_string_json_object(request, "bindState"),"1") == 0)
		set_bind_status(BING_SUCCESS);
	else if(strcmp(get_string_json_object(request, "bindState"),"2") == 0)
		set_bind_status(BING_FAIL);
	else
		set_bind_status(BING_NO);
	
	send_set_respond(mosq,publishTmp,"returnBindState",request);
}



void multi_timer_iotm()
{

    warn_timer.interval--;
    if(warn_timer.interval==0)
    {
        warn_timer.handler();
		warn_timer.interval=warning_interval;
    }

	gpsd_timer.interval--;
    if(gpsd_timer.interval==0)
    {
        gpsd_timer.handler();
		gpsd_timer.interval=gpsdata_interval;
    }


	
#if defined(SU_ZHUAN_WANG)
	zhuan_lteinfo_timer.interval--;
    if(zhuan_lteinfo_timer.interval==0)
    {
        zhuan_lteinfo_timer.handler();
		zhuan_lteinfo_timer.interval=zhuan_lteinfo_interval;
    }
#else
	lteinfo_timer.interval--;
    if(lteinfo_timer.interval==0)
    {
        lteinfo_timer.handler();
		lteinfo_timer.interval=lteinfo_interval;
    }
#endif

	sysinfo_timer.interval--;
    if(sysinfo_timer.interval==0)
    {
        sysinfo_timer.handler();
		sysinfo_timer.interval=sysinfo_interval;
    }
}


void iotm_timer_loop()
{
    struct timespec last_time, current_time;
    clock_gettime(CLOCK_MONOTONIC, &last_time);
    
    while(1) {
       
        clock_gettime(CLOCK_MONOTONIC, &current_time);
        long elapsed_ms = (current_time.tv_sec - last_time.tv_sec) * 1000 + 
                        (current_time.tv_nsec - last_time.tv_nsec) / 1000000;
        
        if(elapsed_ms >= 1000) { 
            last_time = current_time;
            
            multi_timer_iotm();
        }
        
        usleep(10000);
    }
}

void iotm_settimer()
{
	int intVal=0;
	log_message(L_INFO, "%s %d:\n", __FUNCTION__, __LINE__);
	#if 0
	signal(SIGALRM, multi_timer_iotm);
    one_timer.it_interval.tv_sec = 1;
    one_timer.it_value.tv_sec = 1;
    setitimer(ITIMER_REAL, &one_timer, NULL);    
	#endif

    if(warning_interval > 0)
    {	Uci_Get_Int(PKG_IOT_CONFIG, "iotm", "warning_interval", &intVal);
        warn_timer.interval = intVal?intVal:warning_interval;
        warn_timer.handler = warning_send_iotm;
    }
	
	if(gpsdata_interval > 0)
    {	
	    Uci_Get_Int(PKG_WAN_MODEM_CONFIG, "gps", "interval_new", &intVal);
		gpsd_timer.handler = gpsdata_send_iotm;
        gpsd_timer.interval = intVal?intVal:gpsdata_interval;
    }

#if defined(SU_ZHUAN_WANG)
	if(zhuan_lteinfo_interval > 0)
	{
		Uci_Get_Int(PKG_IOT_CONFIG, "iotm", "zhuan_lte_interval", &intVal);
		zhuan_lteinfo_timer.interval = intVal?intVal:zhuan_lteinfo_interval;
		zhuan_lteinfo_timer.handler = zhuan_lteinfo_send_iotm;
	}
	
#else

	if(lteinfo_interval > 0)
	{
		Uci_Get_Int(PKG_IOT_CONFIG, "iotm", "lte_interval", &intVal);
		lteinfo_timer.interval = intVal?intVal:lteinfo_interval;
		lteinfo_timer.handler = lteinfo_send_iotm;
	}

#endif
	if(sysinfo_interval > 0)
    {
		Uci_Get_Int(PKG_IOT_CONFIG, "iotm", "sysinfo_interval", &intVal);
		sysinfo_timer.interval  = intVal?intVal:sysinfo_interval;
		sysinfo_timer.handler = getSysInfo;
    }
	// 创建单独线程运行RID定时器循环
    pthread_t timer_thread;
    if(pthread_create(&timer_thread, NULL, (void*)iotm_timer_loop, NULL) != 0) {
        log_message(L_INFO, "Failed to create timer thread");
    }
}





void local_bind_handle(struct mosquitto *mosq)
{

	local_bind_iotm(mosq);

#if 0	
	warning_send_iotm();
#if defined(SU_ZHUAN_WANG)
	zhuan_lteinfo_send_iotm();
#else
	lteinfo_send_iotm();
#endif
#if defined(BOARD_GPIO_SIM_CHANGE)
	nettype_send_iotm();
#endif
	gpsdata_send_iotm(); 
#endif

	return;

}




void mqtt_data_handle(struct mosquitto *mosq, json_object* request)
{
	char *action = NULL, *mac = NULL, lanMac[18]={0};
	long long int taskId = -1;
	
	action = get_string_json_object(request, "action");
	
	if(strlen(action) == 0){
		action = get_string_json_object(request, "topicurl");
	}
	
	mac = get_string_json_object(request, "mac");
	
	if(json_object_object_get(request, "taskId") != NULL)
		taskId = get_int_json_object(request, "taskId");

	log_message(L_INFO, "action: %s\n",action);
	log_message(L_INFO, "mac: %s \n",mac);
	log_message(L_INFO, "taskId: %lld \n",taskId);

	getIfMac("br-lan", lanMac);

	if(strlen(action) == 0)
		goto OUT;

	if(!strcmp(action,"returnBindState")){
		returnBindState(mosq,request);
	}else if(!strcmp(action,"getLanConfig")){
		getLanConfig(mosq);
	}else if(!strcmp(action,"setIotConfig")){
		setIotConfig(mosq,request);
	}else if(!strcmp(action,"debug_cmd")){
		debug_cmd(mosq,request);
	}else{
		
/******************************************************************************************************
										get cgi json
*******************************************************************************************************/
	
		char http_h[512] = {0},http_b[1536] = {0},w_buff[2048] = {0},r_buff[4096] = {0},tmpBuf[1024] = {0};
		int server_sk_new, ret=0, markId = -1;
		char *outDate = NULL;
		const char *output = NULL;
		const char *pudate = NULL;
		unsigned long ul = 1;
		
		struct timeval tv;
		struct sockaddr_in server_addr;
		fd_set rdfds;
		int len = sizeof(int);

		//set flag, don't web_ex.c Auth
		if(taskId >= 0){
			memset(tmpBuf, 0, sizeof(tmpBuf));
			sprintf(tmpBuf, "%d", taskId);
			datconf_set_by_key(TEMP_IOT_FILE, "task_id", tmpBuf);
		}else{
			datconf_set_by_key(TEMP_IOT_FILE, "task_id", "id_is_null");
		}	
		//------------------------------
		
		output = json_object_to_json_string(request);

		memset(w_buff, 0x00, 2048);
		memset(http_b, 0x00, 1536);
		memset(http_h, 0x00, 512);

		sprintf(http_b, "%s", output);
		sprintf(http_h, 
			"POST %s HTTP/1.0\r\n"\
			"Host: %s\r\n"\
			"Content-Type: application/x-www-form-urlencoded\r\n"\
			"Content-Length: %d\r\n"\
			"Connection: keep-alive\r\n\r\n", \
			"/cgi-bin/cstecgi.cgi", \
			"127.0.0.1", \
			strlen(http_b));

		strcpy(w_buff, http_h);
		strcat(w_buff, http_b);
		
		log_message(L_DEBUG,"w_buff = %s\n\n",w_buff);
		
		if( (server_sk_new = socket(AF_INET, SOCK_STREAM, 0)) == -1 ) {
			log_message(L_DEBUG, "create socket error!!!\n");
			return ;
		}

		memset(&server_addr, 0, sizeof(server_addr));
		server_addr.sin_family = AF_INET;
		server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
		server_addr.sin_port = htons(80);

		/*Setting socket to non-blocking mode */
		ioctl(server_sk_new, FIONBIO, &ul);

		if(connect(server_sk_new, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
			tv.tv_sec  = 6;
			tv.tv_usec = 0;
			FD_ZERO(&rdfds);
			FD_SET(server_sk_new, &rdfds);

			ret = select(server_sk_new+1, NULL, &rdfds, NULL, &tv);
			
			if (ret == 0) {
				getsockopt(server_sk_new, SOL_SOCKET, SO_ERROR, &markId, (socklen_t *)&len);

				if (markId == 0) {
					log_message(L_DEBUG, "connect timeout\n");
				} else {
					log_message(L_DEBUG, "Cann't connect to server!");
				}
				goto end;
			} else if ( ret == -1) {
				log_message(L_DEBUG, "connect error");
				goto end;
			} else {
				log_message(L_DEBUG, "Connect success!\n");
			}
		} else {
			log_message(L_DEBUG, "Connect success!\n");
			ret = 1;
		}
		ul = 0;
		ioctl(server_sk_new, FIONBIO, &ul);
		
		FD_ZERO(&rdfds);
		FD_SET(server_sk_new, &rdfds);
		tv.tv_sec = 5;
		tv.tv_usec = 500000;
		ret = send(server_sk_new, w_buff, strlen(w_buff), 0);
		
		if( ret < 0) {
			log_message(L_DEBUG, "send msg error!!!\n");
			goto end;
		}
		ret = select(server_sk_new + 1, &rdfds, NULL, NULL, &tv);
		
		if(ret < 0)
			log_message(L_DEBUG, "select error!\n");
		else if(ret == 0)
			log_message(L_DEBUG,"iotm: %s %d\n\n", __FUNCTION__, __LINE__);
		else {
			if(FD_ISSET(server_sk_new, &rdfds)) {
				ret = recv(server_sk_new, r_buff, 4096, 0);
				if(ret == 0) {
					goto end;
				}
				log_message(L_INFO, "r_buff = %s \n",r_buff);
				outDate = strstr(r_buff, "{");
				
				if(outDate){
					
					json_object *root = json_tokener_parse(outDate);
					if(!root){
						log_message(L_CRIT, "[%s][%d] cJSON_Parse error!\n[%s]\n",__FUNCTION__,__LINE__,outDate);
						goto end;
					}
					json_object_object_add_string(root,"action", action);	
					json_object_object_add_string(root,"mac", lanMac);
					if(taskId >= 0)
						json_object_object_add_int(root,"taskId", taskId);
					
					pudate = json_object_to_json_string(root);
					publish_data(mosq,publishTmp,pudate);	
					json_object_put(root);
				}else{
					memset(tmpBuf, 0, sizeof(tmpBuf));
					if(taskId >= 0)
						sprintf(tmpBuf,"{\"action\":\"%s\",\"mac\":\"%s\",\"success\": false,\"errorInfo\":\"no active\",\"taskId\": %lld}\n", action, lanMac, taskId);
					else
						sprintf(tmpBuf,"{\"action\":\"%s\",\"mac\":\"%s\",\"success\": false,\"errorInfo\":\"no active\"}\n", action, lanMac);
					publish_data(mosq,publishTmp,tmpBuf);
				}
							
			}
		}
end:
		if(server_sk_new > 0) {
			close(server_sk_new);
			server_sk_new = -1;
		}		
	}

OUT:
	return;


}




