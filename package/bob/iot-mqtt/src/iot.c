#include "iot.h"

#include <sys/syscall.h> 

bool process_messages = true;
int msg_count = 0;

int logging_level = L_DEBUG;
int connect_state = CONNECT_SUCCESS;
char subscribeTmp[128] = {0},publishTmp[128] = {0};

struct mosquitto *send_mosq = NULL;

//------------------------------------------------------------------------------------------------------------------

static int
client_connect_async(struct mosquitto *mosq, struct mosq_config *cfg)
{
	return mosquitto_connect_async(mosq, cfg->host, cfg->port, cfg->keepalive);
}

//-------------------------------------------------------------------------------------------------------------------------------

int mqtt_process_publish_msg(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
    int ret=0;

	json_object *root = json_tokener_parse(message->payload);

    if(!root){
		log_message(L_CRIT, "[%s][%d] cJSON_Parse error!\n[%s]\n",__FUNCTION__,__LINE__,message->payload);
        return -1;
    }
	
	log_message(L_INFO, "topic:%s,\n",message->topic);
	log_message(L_INFO, "msg:[%s]\n",message->payload);

	mqtt_data_handle(mosq, root);

	json_object_put(root);

    return ret;
}

void my_message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
	struct mosq_config *cfg;
	int i;
	bool res;
	
	log_message(L_NOTICE, "my_message_callback\n");
	if(process_messages == false) return;

	assert(obj);
	cfg = (struct mosq_config *)obj;

	if(message->retain && cfg->no_retain) return;
	if(cfg->filter_outs){
		for(i=0; i<cfg->filter_out_count; i++){
			mosquitto_topic_matches_sub(cfg->filter_outs[i], message->topic, &res);
			if(res) return;
		}
	}
#if 1
	if(cfg->verbose){
		if(message->payloadlen){
			printf("%s ", message->topic);
			fwrite(message->payload, 1, message->payloadlen, stdout);
			if(cfg->eol){
				printf("\n");
			}
		}else{
			if(cfg->eol){
				printf("%s (null)\n", message->topic);
			}
		}
		fflush(stdout);
	}
#endif
	if(cfg->msg_count>0){
		msg_count++;
		if(cfg->msg_count == msg_count){
			process_messages = false;
			mosquitto_disconnect(mosq);
		}
	}

	mqtt_process_publish_msg(mosq, obj, message);
}


void my_connect_callback(struct mosquitto *mosq, void *obj, int result)
{

	struct mosq_config *cfg;
	assert(obj);
	cfg = (struct mosq_config *)obj;

	if(!result){
		mosquitto_subscribe(mosq, NULL, subscribeTmp, cfg->qos);
	}else{
		if(result && !cfg->quiet){
			log_message(L_WARNING, "%s\n", mosquitto_connack_string(result));
		}
	}

	connect_state = CONNECT_SUCCESS;
	
	log_message(L_INFO, "%s %d:\n", __FUNCTION__, __LINE__);

	local_bind_handle(mosq);
	set_bind_status(CONNECT_SUCCESS);
	iotm_settimer();

}

void my_disconnect_callback(struct mosquitto *mosq, void *obj, int result)
{

	connect_state = CONNECT_FAIL;
	
	log_message(L_INFO, "%s %d:\n", __FUNCTION__, __LINE__);
	set_bind_status(CONNECT_FAIL);
	exit(1);

}



void init_subject_info()
{
	char macbuf[32] = {0}, tmp_buf[32]={0},mac[18]={0};
	int i = 0;
	pid_t pid;
	FILE *fp;

	pid = getpid();
	/* write pid */
	if ((fp = fopen("/var/run/iotMqtt.pid", "w")) != NULL) {
		fprintf(fp, "%d", pid);
		fclose(fp);
	}

	Uci_Get_Int(PKG_IOT_CONFIG, "default", "log_level", &logging_level);
	
	memset(subscribeTmp, 0, sizeof(subscribeTmp));
	memset(publishTmp, 0, sizeof(publishTmp));
	memset(macbuf, 0, sizeof(macbuf));

	memset(tmp_buf, 0, sizeof(0));
	Uci_Get_Str(PKG_IOT_CONFIG, "default", "publish_subject", tmp_buf);
	
	if(strlen(tmp_buf) > 0)
		sprintf(publishTmp, "%s", tmp_buf);
	else
		sprintf(publishTmp, "%s", "device/report");

	getIfMac("br-lan", mac);
	mac_del_split(mac, macbuf);

	for(i=0;i<strlen(macbuf);i++){
		if(macbuf[i]>='A' && macbuf[i]<='Z')
			macbuf[i]=macbuf[i]+32;
	}
	sprintf(subscribeTmp, "device/%s", macbuf);
	
	log_message(L_INFO, "logging_level = %d\n",logging_level);
	log_message(L_INFO, "subscribeTmp = %s\n",subscribeTmp);
	log_message(L_INFO, "publishTmp = %s\n",publishTmp);

	
}

struct mosquitto *mosqAll = NULL;
/* Process a tokenised single line from a file or set of real argc/argv */

int client_opts_set(struct mosquitto *mosq, struct mosq_config *cfg)
{
	int rc;
	if(cfg->will_topic && mosquitto_will_set(mosq, cfg->will_topic,
				cfg->will_payloadlen, cfg->will_payload, cfg->will_qos,
				cfg->will_retain)){

		if(!cfg->quiet) log_message(L_INFO, "Error: Problem setting will.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
	if(cfg->username && mosquitto_username_pw_set(mosq, cfg->username, cfg->password)){
		if(!cfg->quiet) log_message(L_INFO, "Error: Problem setting username and password.\n");
		mosquitto_lib_cleanup();
		return 1;
	}
	mosquitto_max_inflight_messages_set(mosq, cfg->max_inflight);
	mosquitto_opts_set(mosq, MOSQ_OPT_PROTOCOL_VERSION, &(cfg->protocol_version));
	return MOSQ_ERR_SUCCESS;
}

int main(int argc, char *argv[])
{
	struct mosq_config cfg;
	
	int rc, enable=0;
	int reconnection = 20, delay_time=0;

	Uci_Get_Int(PKG_IOT_CONFIG, "iotm", "enable", &enable);

	if(enable != 1) return 0;

#if 0	
	if (daemon(0, 0) < 0) {
		log_message(L_INFO, "iotMqtt error\n");
		exit(0);
	}
#endif

	system("touch /var/cste/temp_iot_status");
	
	set_bind_status(CONNECT_ING);
	set_bind_status(BING_NO);

	Uci_Get_Int(PKG_IOT_CONFIG, "default", "delay_time", &delay_time);
	if(delay_time == 0)
		sleep(Rand(1,6));
	else
		sleep(Rand(1,delay_time));

	init_subject_info();

	init_config(&cfg);


	mosquitto_lib_init();
	
	mosqAll = mosquitto_new(cfg.id, cfg.clean_session, &cfg);
	if(!mosqAll){
		switch(errno){
			case ENOMEM:
				log_message(L_INFO, "Error: Out of memory\n");
				break;
			case EINVAL:
				log_message(L_INFO, "Error: Invalid id and/or clean_session\n");
				break;
		}
		mosquitto_lib_cleanup();
		return 1;
	}
	if(client_opts_set(mosqAll, &cfg)){
		client_config_cleanup(&cfg);
		return 1;
	}
	
	send_mqtt_offline();
	
	mosquitto_connect_callback_set(mosqAll, my_connect_callback);					//连接成功回调函数
	mosquitto_disconnect_callback_set(mosqAll, my_disconnect_callback);			//连接失败回调函数
	mosquitto_message_callback_set(mosqAll, my_message_callback);

	rc = client_connect_async(mosqAll, &cfg);
	if(rc) {
		log_message(L_WARNING, "%s %d: fail\n", __FUNCTION__, __LINE__);
		while(rc != 0){
			sleep(10);
			rc =  client_connect_async(mosqAll, &cfg);
			reconnection--;
			if (reconnection == 0) 
				goto end;
		}
	}
	
	send_mosq = mosqAll;

	rc = mosquitto_loop_start(mosqAll);
	if(rc){
		log_message(L_WARNING, "%s %d: loop error\n", __FUNCTION__, __LINE__);
		mosquitto_destroy(mosqAll);
		mosquitto_lib_cleanup();
		return -1;
	}
		

	while(1) {
		pause();
	}

end:
	mosquitto_loop_stop(mosqAll, false);
	mosquitto_destroy(mosqAll);
	mosquitto_lib_cleanup();

	log_message(L_WARNING, "%s %d: mqtt end\n", __FUNCTION__, __LINE__);
	if(cfg.msg_count>0 && rc == MOSQ_ERR_NO_CONN) {
		rc = 0;
	}
	if(rc) {
		log_message(L_WARNING, "Error: %s\n", mosquitto_strerror(rc));
	}
	if(!cfg.id){
		free(cfg.id);
	}
	return rc;
}


