#include "../defs.h"

typedef enum
{
	UNREG = 0,
	REG_HOME,
	REG_SEARCHING,
	REG_DENY,
	REG_UNKOWN,
	REG_ROAMING,
	REG_SMS_ONLY_HOME,
	REG_SMS_ONLY_ROAMING,
	REG_IDEL
}SIM_STATUS;

enum sys_mode
{
	E_NO_SERVICE,
	E_2G_3G,
	E_LTE,
	E_LTEP
};

enum
{
	_MODE_INIT,
	MODE_LTE,
	MODE_UMTS,
	MODE_TD,
	MODE_GSM
};

typedef enum
{
    RADIO_TECH_UNKNOWN = 0,
    RADIO_TECH_GPRS = 1,
    RADIO_TECH_EDGE = 2,
    RADIO_TECH_UMTS = 3,
    RADIO_TECH_IS95A = 4,
    RADIO_TECH_IS95B = 5,
    RADIO_TECH_1xRTT =  6,
    RADIO_TECH_EVDO_0 = 7,
    RADIO_TECH_EVDO_A = 8,
    RADIO_TECH_HSDPA = 9,
    RADIO_TECH_HSUPA = 10,
    RADIO_TECH_HSPA = 11,
    RADIO_TECH_EVDO_B = 12,
    RADIO_TECH_EHRPD = 13,
    RADIO_TECH_LTE = 14,
    RADIO_TECH_HSPAP = 15, // HSPA+
    RADIO_TECH_GSM = 16, // Only supports voice
    RADIO_TECH_TD_SCDMA = 17,
    RADIO_TECH_IWLAN = 18,
    RADIO_TECH_LTEP = 19,
    RADIO_TECH_DC_HSPA = 20
} RIL_RadioTechnology;


int getSimConnStatus()
{
	char p_json[LONGLONG_BUFF_LEN]={0}, str[8]={0};
	int ret = 0;
	cJSON *root = NULL;
	
	ret = cs_ubus_cli_call("network.interface.wan0", "status",p_json);
	if(ret == -1){
		return 0;
	}
	
	root = cJSON_Parse(p_json);
	if(root){
		get_cjson_string(root, "up", str, sizeof(str));	
		
		cJSON_Delete(root);
	}
	
	return atoi(str);
}

int getISPinfo(char *imsi,char *ISP)
{	
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
		strcpy(ISP,"4");//tietong
	}else
	{
		strcpy(ISP,"0");//qita
	}

	return CGI_TRUE;
}

int getSimStatus(char *key)
{
	char p_json[LONGLONG_BUFF_LEN]={0}, str[8]={0};
	int ret = 0;
	cJSON *root = NULL;
	
	ret = cs_ubus_cli_call("sim", "get_sim_status",p_json);
	if(ret == -1){
		return 0;
	}
	
	root = cJSON_Parse(p_json);
	if(root){
		cJSON *subObj = cJSON_GetObjectItem(root,"pin_puk");
		get_cjson_string(subObj, key, str, sizeof(str));	

		cJSON_Delete(root);
	}
	
	return atoi(str);
}

int getInfofromCmContextlist(char *key, char *buff)
{
	int ret=-1;
	char p_json[LONGLONG_BUFF_LEN]={0}, str[64]={0};
	cJSON *root = NULL;
	
	ret = cs_ubus_cli_call("cm", "get_link_context",p_json);
	if(ret == -1)
		return -1;

	root = cJSON_Parse(p_json);
	if(root){
		cJSON *subObj = cJSON_GetObjectItem(root,"contextlist");
		if(subObj){
			int arrayLen=cJSON_GetArraySize(subObj);
			if(arrayLen>0){
				cJSON *tmpObj = cJSON_GetArrayItem(subObj,0);
				get_cjson_string(tmpObj, "apn", str, sizeof(str));	
				strcpy(buff, str);
			}
		}

		cJSON_Delete(root);
	}

	return ret;
}

int cmGetLinkContextBasic(cJSON *json,char *key,char *buff)
{
	int ret=-1;
	char p_json[LONGLONG_BUFF_LEN]={0}, str[32]={0};
	char tmp[15]={0};
	cJSON *root = NULL;
	
	ret = cs_ubus_cli_call("cm", "get_link_context",p_json);
	if(ret == -1)
		return -1;

	root = cJSON_Parse(p_json);
	if(root){
		cJSON *subObj = cJSON_GetObjectItem(root,"celluar_basic_info");
		if(subObj){
			get_cjson_string(subObj, "sys_mode", str, sizeof(str));
			ret=atoi(str);
			
			if(strcmp(key,"") != 0){
				memset(str, '\0', sizeof(str));
				get_cjson_string(subObj, key, str, sizeof(str));	
				strcpy(buff, str);
			}else{
				if(ret == E_NO_SERVICE){
					ret=0;
					cJSON_AddStringToObject(root,"netType","");
				}else if(ret == E_LTE){
					ret = MODE_LTE;
					cJSON_AddStringToObject(json,"netType","LTE");
				}else{
					get_cjson_string(subObj, "data_mode", str, sizeof(str));
					ret=atoi(str);
					if ((ret == RADIO_TECH_GPRS) || (ret == RADIO_TECH_EDGE) \
						|| (ret == RADIO_TECH_GSM)) {
						ret = MODE_GSM;
						cJSON_AddStringToObject(json,"netType","GSM");
					} else if (ret == RADIO_TECH_TD_SCDMA) {
						ret = MODE_TD;
						cJSON_AddStringToObject(json,"netType","TD");
					} else {
						ret = MODE_UMTS;
						cJSON_AddStringToObject(json,"netType","UMTS");
					}
				}
				
				memset(str, '\0', sizeof(str));
				get_cjson_string(subObj, "rssi", str, sizeof(str));
				#if 1
					cJSON_AddStringToObject(json,"signal",str);
				#else
				int signal=atoi(str);
				if(signal >= 0 && signal < 63){
					sprintf(tmp, "-%d",1+(110-signal));
					cJSON_AddStringToObject(json,"signal",tmp);
				}else
					cJSON_AddStringToObject(json,"signal","");
				#endif
				
				memset(str, '\0', sizeof(str));
				get_cjson_string(subObj, "IMEI", str, sizeof(str));
				cJSON_AddStringToObject(json,"imei",str);

				memset(str, '\0', sizeof(str));
				get_cjson_string(subObj, "IMSI", str, sizeof(str));
				cJSON_AddStringToObject(json,"imsi",str);

				getISPinfo(str, tmp);
				cJSON_AddStringToObject(json,"isp",tmp);	
			}
		}
		cJSON_Delete(root);
	}
	return ret;
}

#if 1
CGI_BOOL getCurrentCell(json_object *request, FILE *conn_fp)
{
	cJSON *root;
	int modem_idx = 0;
	char tmp_buf[64]={0}, key_name[64]={0}, modem_slot[32]={0};
	
	root = cJSON_CreateObject();

	modem_idx = atoi(webs_get_string(request,"modem_idx"));
	snprintf(modem_slot, sizeof(modem_slot), "modem%d", modem_idx+1);

	snprintf(key_name, sizeof(key_name), "%s_net_type", modem_slot);
	datconf_get_by_key(TEMP_MODEM_FILE, key_name, tmp_buf, sizeof(tmp_buf));
	cJSON_AddStringToObject(root, "netType", tmp_buf);

	snprintf(key_name, sizeof(key_name), "%s_pci", modem_slot);
	datconf_get_by_key(TEMP_MODEM_FILE, key_name, tmp_buf, sizeof(tmp_buf));
	cJSON_AddStringToObject(root, "pci", tmp_buf);

	snprintf(key_name, sizeof(key_name), "%s_band", modem_slot);
	datconf_get_by_key(TEMP_MODEM_FILE, key_name, tmp_buf, sizeof(tmp_buf));
	cJSON_AddStringToObject(root, "bandLte", tmp_buf);

	snprintf(key_name, sizeof(key_name), "%s_arfcn", modem_slot);
	datconf_get_by_key(TEMP_MODEM_FILE, key_name, tmp_buf, sizeof(tmp_buf));
	cJSON_AddStringToObject(root, "arfcn", tmp_buf);

	snprintf(key_name, sizeof(key_name), "%s_scs", modem_slot);
	datconf_get_by_key(TEMP_MODEM_FILE, key_name, tmp_buf, sizeof(tmp_buf));
	cJSON_AddStringToObject(root, "scs", tmp_buf);

	send_cgi_json_respond(conn_fp, root);
	
	return CGI_TRUE;
}


CGI_BOOL getCellInfo(json_object *request, FILE *conn_fp)
{
	char cmd[64] = {0}, result[256] = {0};
	int ret=-1,i=0;
	char rat[32] = {0},arfcn[32] = {0};
	char pci_hex[32] = {0},pci[32] = {0};
	char rsrp[32] = {0};
	cJSON *data_call_root,*cell_root,*tmpObj,*root,*each_root;
	
	root = cJSON_CreateArray();
	
	FILE *fp = NULL;
	int count=0, pci_int=0;
	char buffer[128] = {0},rat_buf[64] = {0};;

	system("atsh AT^MONNC > /tmp/scanCell");
	
	fp = fopen("/tmp/scanCell", "r");
	if (NULL == fp){
		goto end;
	}	
	while(fgets(buffer, sizeof(buffer), fp) != NULL) 
	{
		if(count>=1){
			if ( strlen(buffer)<=2 )
				break;
			getNthValueSafe(0, buffer, ',', rat_buf, sizeof(rat_buf));
			getNthValueSafe(1, rat_buf, ':', rat, sizeof(rat));
			
			if (strcmp(rat," LTE")==0 ||strcmp(rat," NR")==0){
				getNthValueSafe(1, buffer, ',', arfcn, sizeof(arfcn));
				getNthValueSafe(2, buffer, ',', pci_hex, sizeof(pci_hex));
				getNthValueSafe(3, buffer, ',', rsrp, sizeof(rsrp));
			
				sscanf(pci_hex, "%x", &pci_int);
				sprintf(pci,"%d",pci_int);			

				each_root = cJSON_CreateObject();	//tmp_obj = json_object_new_object();
				cJSON_AddStringToObject(each_root, "rat", rat);
				cJSON_AddStringToObject(each_root, "arfcn", arfcn);
				cJSON_AddStringToObject(each_root, "pci", pci);
				cJSON_AddStringToObject(each_root, "rsrp", rsrp);
				cJSON_AddItemToArray(root,each_root); //json_object_array_add(respond_arry,tmp_obj);
				
			}
		}		
		count ++;
	
	}
	fclose(fp);
	
end:
	
	send_cgi_json_respond(conn_fp, root);
	
	return CGI_TRUE;
}

CGI_BOOL lockCell(json_object *request, FILE *conn_fp)
{
	char cmd[128] = {0};
	char *arfcn_lock = webs_get_string(request, "arfcn");
	char *pci_lock = webs_get_string(request, "pci");
	char *bandLock5g = webs_get_string(request, "bandLock5g");
	char *scsType = webs_get_string(request, "scsType");
	char *rat = webs_get_string(request, "rat");

	if(strstr(rat,"LTE")){
		if( strlen(arfcn_lock)>0){
			
			Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "status", "lte_arfcn", arfcn_lock);
			Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "status", "lock_cell_enable", "1");
			doSystem("ubus call urild lock_arfcn_band '{\"lock_cell_enable\":\"1\",\"modem_arfcn\":\"%s\"}'",arfcn_lock);
		}
	}else if (strstr(rat,"NR")){
		if(strlen(pci_lock)>0 && strlen(arfcn_lock)>0 && strlen(scsType)>0 && strlen(bandLock5g)>0){

			Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "status", "lock_cell_enable", "2");
			Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "status", "scstype", scsType);
			Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "status", "lte_pci", pci_lock);
			Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "status", "lte_arfcn", arfcn_lock);
			Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "status", "band_lock5g", bandLock5g);
			doSystem("ubus call urild lock_arfcn_band '{\"lock_cell_enable\":\"2\",\"modem_scstype\":\"%s\",\"modem_band_lock5g\":\"%s\",\"modem_arfcn\":\"%s\",\"modem_pci\":\"%s\"}'", scsType,bandLock5g,arfcn_lock,pci_lock);			
		}	
	}
	
	Uci_Commit(PKG_WAN_MODEM_CONFIG);
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "15", "reserv");

	return CGI_TRUE;
}



#else
CGI_BOOL getCurrentCell(json_object *request, FILE *conn_fp)
{
	int ret, system_mode=0;
	cJSON *cmJson, *root;
	char p_json[LONGLONG_BUFF_LEN]={0}, str[32]={0};
	char tmpBuf[128]={0}, buff[32]={0};
	
	root = cJSON_CreateObject();
	
	ret = cmGetLinkContextBasic(NULL, "sys_mode", tmpBuf);
	system_mode = atoi(tmpBuf);
	
	if(ret == -1 || system_mode == 0){
		goto End;
		cJSON_AddStringToObject(root,"currentCell","ERROR");
	}else{
		ret = cs_ubus_cli_call("cm", "get_eng_info",p_json);
		if(ret == -1){
			goto End;
			cJSON_AddStringToObject(root,"currentCell","ERROR");
		}

		cmJson = cJSON_Parse(p_json);
		if(cmJson){
			cJSON *object = cJSON_GetObjectItem(cmJson,"eng");
			if(object){
				memset(tmpBuf, '\0', sizeof(tmpBuf));
				
				if(system_mode == E_LTE ){
					cJSON *subObj = cJSON_GetObjectItem(object,"lte");
					if(subObj){
						sprintf(tmpBuf, " LTE");
						get_cjson_string(subObj, "mcc", str, sizeof(str));
						sprintf(buff, ",%s", str);
						strcat(tmpBuf, buff);
						
						memset(str, '\0', sizeof(str));
						memset(buff, '\0', sizeof(buff));
						get_cjson_string(subObj, "mnc", str, sizeof(str));
						sprintf(buff, ",%s", str);
						strcat(tmpBuf, buff);

						memset(str, '\0', sizeof(str));
						memset(buff, '\0', sizeof(buff));
						get_cjson_string(subObj, "cell_id", str, sizeof(str));
						sprintf(buff, ",%s", str);
						strcat(tmpBuf, buff);

						memset(str, '\0', sizeof(str));
						memset(buff, '\0', sizeof(buff));
						get_cjson_string(subObj, "phy_cell_id", str, sizeof(str));
						sprintf(buff, ",%s", str);
						strcat(tmpBuf, buff);
						
						memset(str, '\0', sizeof(str));
						memset(buff, '\0', sizeof(buff));
						get_cjson_string(subObj, "tac", str, sizeof(str));
						sprintf(buff, ",%s", str);
						strcat(tmpBuf, buff);
						
												
						memset(str, '\0', sizeof(str));
						memset(buff, '\0', sizeof(buff));
						get_cjson_string(subObj, "rsrp", str, sizeof(str));
						sprintf(buff, ",%s", str);
						strcat(tmpBuf, buff);
						
						memset(str, '\0', sizeof(str));
						memset(buff, '\0', sizeof(buff));
						get_cjson_string(subObj, "rsrq", str, sizeof(str));
						sprintf(buff, ",%s", str);
						strcat(tmpBuf, buff);
						
						memset(str, '\0', sizeof(str));
						memset(buff, '\0', sizeof(buff));
						get_cjson_string(subObj, "rssi", str, sizeof(str));
						sprintf(buff, ",%s", str);
						strcat(tmpBuf, buff);
					}else{
						ret=-1;
					}
				}
				else{
					cJSON *subJson= cJSON_GetObjectItem(object,"umts");
					if(subJson){
						sprintf(tmpBuf, " UMTS");
						get_cjson_string(subJson, "mcc", tmpBuf, sizeof(str));
						sprintf(buff, ",%s", str);
						strcat(tmpBuf, buff);
						
						get_cjson_string(subJson, "mnc", str, sizeof(str));
						sprintf(buff, ",%s", str);
						strcat(tmpBuf, buff);

						memset(str, '\0', sizeof(str));
						memset(buff, '\0', sizeof(buff));
						get_cjson_string(subJson, "arfcn", str, sizeof(str));
						sprintf(buff, ",%s", str);
						strcat(tmpBuf, buff);
						
						memset(str, '\0', sizeof(str));
						memset(buff, '\0', sizeof(buff));
						get_cjson_string(subJson, "cell_id", str, sizeof(str));
						sprintf(buff, ",%s", str);
						strcat(tmpBuf, buff);
						
						memset(str, '\0', sizeof(str));
						memset(buff, '\0', sizeof(buff));
						get_cjson_string(subJson, "lac", str, sizeof(str));
						sprintf(buff, ",%s", str);
						strcat(tmpBuf, buff);
						
												
						memset(str, '\0', sizeof(str));
						memset(buff, '\0', sizeof(buff));
						get_cjson_string(subJson, "rscp", str, sizeof(str));
						sprintf(buff, ",%s", str);
						strcat(tmpBuf, buff);
						
						memset(str, '\0', sizeof(str));
						memset(buff, '\0', sizeof(buff));
						get_cjson_string(subJson, "rsrq", str, sizeof(str));
						sprintf(buff, ",%s", str);
						strcat(tmpBuf, buff);
						
						memset(str, '\0', sizeof(str));
						memset(buff, '\0', sizeof(buff));
						get_cjson_string(subJson, "rssi", str, sizeof(str));
						sprintf(buff, ",%s", str);
						strcat(tmpBuf, buff);
					}
					else{
						ret=-1;
					}
				}
			}
			else{
				ret=-1;
			}
			
			cJSON_Delete(cmJson);
			
			if(ret==-1)
				cJSON_AddStringToObject(root,"currentCell","ERROR");
			else
				cJSON_AddStringToObject(root,"currentCell",tmpBuf);
		}
		else{
			cJSON_AddStringToObject(root,"currentCell","ERROR");
		}
	}
	
	
End:
	send_cgi_json_respond(conn_fp, root);
	
	return CGI_TRUE;
}
#endif
int getLteEngInfo(cJSON *json)
{
	int ret=-1;
	char p_json[LONGLONG_BUFF_LEN]={0}, str[32]={0};
	char tmp[15]={0};
	cJSON *root = NULL;
	
	ret = cs_ubus_cli_call("cm", "get_eng_info",p_json);
	if(ret == -1)
		return -1;

	root = cJSON_Parse(p_json);
	if(root){
		cJSON *object = cJSON_GetObjectItem(root,"eng");
		if(object){
			cJSON *subObj = cJSON_GetObjectItem(object,"lte");
			if(subObj){
				get_cjson_string(subObj, "cell_id", str, sizeof(str));
				cJSON_AddStringToObject(json,"cellId",str);	

				memset(str, '\0', sizeof(str));
				get_cjson_string(subObj, "phy_cell_id", str, sizeof(str));
				cJSON_AddStringToObject(json,"pci",str);	
				
				memset(str, '\0', sizeof(str));
				get_cjson_string(subObj, "rsrp", str, sizeof(str));
				cJSON_AddStringToObject(json,"rsrp",str);	

				memset(str, '\0', sizeof(str));
				get_cjson_string(subObj, "sinr", str, sizeof(str));
				cJSON_AddStringToObject(json,"sinr",str);

				memset(str, '\0', sizeof(str));
				get_cjson_string(subObj, "band", str, sizeof(str));
				cJSON_AddStringToObject(json,"bandLte",str);
			}
		}
		cJSON_Delete(root);
	}
	
	return ret;
}

int getUmtsEngInfo(cJSON *json)
{
	int ret=-1;
	char p_json[LONGLONG_BUFF_LEN]={0}, str[32]={0};
	char tmp[15]={0};
	cJSON *root = NULL;
	
	ret = cs_ubus_cli_call("cm", "get_eng_info",p_json);
	if(ret == -1)
		return -1;

	root = cJSON_Parse(p_json);
	if(root){
		cJSON *object = cJSON_GetObjectItem(root,"eng");
		if(object){
			cJSON *subObj = cJSON_GetObjectItem(object,"umts");
			if(subObj){
				get_cjson_string(subObj, "cell_id", str, sizeof(str));
				cJSON_AddStringToObject(json,"cellId",str);	

				memset(str, '\0', sizeof(str));
				get_cjson_string(subObj, "phy_cell_id", str, sizeof(str));
				cJSON_AddStringToObject(json,"pci",str);	
				
				memset(str, '\0', sizeof(str));
				get_cjson_string(subObj, "lac", str, sizeof(str));
				cJSON_AddStringToObject(json,"lac",str);	
			}
		}
		cJSON_Delete(root);
	}
	
	return ret;
}

int getModemUptime(char *uptime)
{
	char p_json[LONGLONG_BUFF_LEN]={0}, str[16]={0};
	int ret = 0, day, hr, mn;;
	unsigned long ltime, system_sec, wan_uptime, sec;
	cJSON *root = NULL;
	
	ret = cs_ubus_cli_call("network.interface.wan0", "status",p_json);
	if(ret == -1){
		return -1;
	}
	
	root = cJSON_Parse(p_json);
	if(root){
		get_cjson_string(root, "uptime", str, sizeof(str));
		ltime = atol(str);
		struct sysinfo info;
		sysinfo(&info);

		system_sec = (unsigned long) info.uptime ;
				
		sec = system_sec - wan_uptime ;  // 4g up time
		day = sec / 86400;
		sec %= 86400;
		hr = sec / 3600;
		sec %= 3600;
		mn = sec / 60;
		sec %= 60;

		sprintf(uptime, "%d;%d;%d;%ld", day, hr, mn, sec);
		
		cJSON_Delete(root);
	}
	else{
		sprintf(uptime, "%d;%d;%d;%ld", 0, 0, 0, 0);
	}
	return ret;
}

void pares_uptime(long sec, char *uptime)
{
	int day, hr, mn;
	
	day = sec / 86400;
	sec %= 86400;
	hr = sec / 3600;
	sec %= 3600;
	mn = sec / 60;
	sec %= 60;

	sprintf(uptime, "%d;%d;%d;%ld", day, hr, mn, sec);
	return ;
}

#define SIM_OK	 1<<0
#define REG_OK 	 1<<1
#define CONN_OK  1<<2

CGI_BOOL getLteAllInfo(json_object *request, FILE *conn_fp)
{
	cJSON *root, *cell_root, *data_root, *stat_json;
	char modem_slot[32]={0};
	char p_json[LONGLONG_BUFF_LEN]={0}, tmpBuf[64]={0}, path[32]={0}, uptime[32]={0};
	char ip[16]={0}, imsi[32]={0};
	int reg_status=0, rsrp=0, i_signal=0,prio;

	root = cJSON_CreateObject();

	int modem_idx = 0;
	char tmp_buf[64]={0}, modem_section[32]={0}, key_name[64]={0};

	
	//priority
	Uci_Get_Int(PKG_WAN_MODEM_CONFIG,"strategy","prio", &prio);
	
	if(prio == PRIO_ONLY_WIRE)
	{
		cJSON_AddStringToObject(root, "imei", "");
		cJSON_AddStringToObject(root, "imsi", "");
		cJSON_AddStringToObject(root, "isp", "");
		cJSON_AddStringToObject(root, "netType", "");
		cJSON_AddStringToObject(root, "bandLte", "");
		cJSON_AddStringToObject(root, "model", "");
		cJSON_AddStringToObject(root, "modemVersion", "");
		cJSON_AddStringToObject(root, "pci", "");
		cJSON_AddStringToObject(root, "sinr", "");
		cJSON_AddStringToObject(root, "rsrp", "");
		cJSON_AddStringToObject(root, "signal", "");
		cJSON_AddStringToObject(root, "wan4gConnStatus", "");
		cJSON_AddStringToObject(root, "wan4gUptime", "0;0;0;0");
		cJSON_AddStringToObject(root, "wan4gIp", "");
		cJSON_AddStringToObject(root, "registStatus", "");

		goto end;
	}

	
	modem_idx = atoi(webs_get_string(request,"modem_idx"));
	snprintf(modem_slot, sizeof(modem_slot), "modem%d", modem_idx+1);
	if(modem_idx == 0) {
		snprintf(modem_section, sizeof(modem_section), "wan_modem");
	}
	else {
		snprintf(modem_section, sizeof(modem_section), "wan_modem%d", modem_idx+1);
	}

	snprintf(key_name, sizeof(key_name), "%s_imei", modem_slot);
	datconf_get_by_key(TEMP_MODEM_FILE, key_name, tmp_buf, sizeof(tmp_buf));
	cJSON_AddStringToObject(root, "imei", tmp_buf);

	snprintf(key_name, sizeof(key_name), "%s_imsi", modem_slot);
	datconf_get_by_key(TEMP_MODEM_FILE, key_name, imsi, sizeof(imsi));
	cJSON_AddStringToObject(root, "imsi", imsi);

	memset(tmpBuf, 0, sizeof(tmpBuf));
	getISPinfo(imsi, tmpBuf);
	cJSON_AddStringToObject(root, "isp", tmpBuf);
	
	snprintf(key_name, sizeof(key_name), "%s_net_type", modem_slot);
	datconf_get_by_key(TEMP_MODEM_FILE, key_name, tmp_buf, sizeof(tmp_buf));
	cJSON_AddStringToObject(root, "netType", tmp_buf);

	snprintf(key_name, sizeof(key_name), "%s_band", modem_slot);
	datconf_get_by_key(TEMP_MODEM_FILE, key_name, tmp_buf, sizeof(tmp_buf));
	cJSON_AddStringToObject(root, "bandLte", tmp_buf);

	snprintf(key_name, sizeof(key_name), "%s_modem_name", modem_slot);
	datconf_get_by_key(TEMP_MODEM_FILE, key_name, tmp_buf, sizeof(tmp_buf));
	cJSON_AddStringToObject(root, "model", tmp_buf);

	snprintf(key_name, sizeof(key_name), "%s_version", modem_slot);
	datconf_get_by_key(TEMP_MODEM_FILE, key_name, tmp_buf, sizeof(tmp_buf));
	cJSON_AddStringToObject(root, "modemVersion", tmp_buf);
	
	snprintf(key_name, sizeof(key_name), "%s_pci", modem_slot);
	datconf_get_by_key(TEMP_MODEM_FILE, key_name, tmp_buf, sizeof(tmp_buf));
	cJSON_AddStringToObject(root, "pci", tmp_buf);

	snprintf(key_name, sizeof(key_name), "%s_sinr", modem_slot);
	datconf_get_by_key(TEMP_MODEM_FILE, key_name, tmp_buf, sizeof(tmp_buf));
	cJSON_AddStringToObject(root, "sinr", tmp_buf);

	snprintf(key_name, sizeof(key_name), "%s_rsrp", modem_slot);
	datconf_get_by_key(TEMP_MODEM_FILE, key_name, tmp_buf, sizeof(tmp_buf));
	cJSON_AddStringToObject(root, "rsrp", tmp_buf);
	rsrp = atoi(tmp_buf);
	if(!strlen(tmp_buf)){
		i_signal=0;
	}else if(rsrp > -75){
		i_signal=100;
	}else if(rsrp > -85 && rsrp <= -75){
		i_signal=80;
	}else if(rsrp > -95 && rsrp <= -85){
		i_signal=60;
	}else if(rsrp > -105 && rsrp <= -95){
		i_signal=40;
	}else if( rsrp > -115 && rsrp <= -105){
		i_signal=20;
	}else if(rsrp> -140 && rsrp <= -115){
		i_signal=5;
	}else if(rsrp < -140){
		i_signal=0;
	}
	memset(tmpBuf, 0, sizeof(tmpBuf));
	sprintf(tmpBuf, "%d", i_signal);
	cJSON_AddStringToObject(root, "signal", tmpBuf);

	memset(tmp_buf, 0, sizeof(tmp_buf));
	snprintf(key_name, sizeof(key_name), "%s_sim_status", modem_slot);
	datconf_get_by_key(TEMP_MODEM_FILE, key_name, tmp_buf, sizeof(tmp_buf));
	if(!strcmp(tmp_buf, "READY")){
		reg_status |= SIM_OK;
	}

	memset(tmp_buf, 0, sizeof(tmp_buf));
	snprintf(key_name, sizeof(key_name), "%s_reg_status", modem_slot);
	datconf_get_by_key(TEMP_MODEM_FILE, key_name, tmp_buf, sizeof(tmp_buf));
	if(!strcmp(tmp_buf, "regHome")){
		reg_status |= REG_OK;
	}

	//ubus call network.interface.[wan_name] status
	snprintf(path, sizeof(path)-1,"network.interface.%s", modem_section);
	if(cs_ubus_cli_call(path, "status", p_json) != -1){
		stat_json = cJSON_Parse(p_json);
		
		memset(tmpBuf, 0, sizeof(tmpBuf));
		get_cjson_string(stat_json, "up",	tmpBuf, sizeof(tmpBuf));
		
		if(strcmp(tmpBuf, "1") == 0){//true
			cJSON_AddStringToObject(root, "wan4gConnStatus", "connected");
			reg_status |= CONN_OK;
		}else
			cJSON_AddStringToObject(root, "wan4gConnStatus", "disconnected");

		memset(tmpBuf, 0, sizeof(tmpBuf));
		get_cjson_string(stat_json, "uptime", tmpBuf, sizeof(tmpBuf));
		
		if(atol(tmpBuf) > 0){
			pares_uptime(atol(tmpBuf), uptime);
			cJSON_AddStringToObject(root, "wan4gUptime", uptime);
		}else{
			cJSON_AddStringToObject(root, "wan4gUptime", "0;0;0;0");
		}

		cJSON *ip_data_root = cJSON_GetObjectItem(stat_json,"ipv4-address");
		if(ip_data_root){
			int arrayLen=cJSON_GetArraySize(ip_data_root);
			if(arrayLen>0){
				cJSON *tmpObj = cJSON_GetArrayItem(ip_data_root,0);
				memset(tmpBuf, 0, sizeof(tmpBuf));
				get_cjson_string(tmpObj, "address", tmpBuf, sizeof(tmpBuf));	
				getNthValueSafe(0, tmpBuf, ' ', ip, sizeof(ip));
				cJSON_AddStringToObject(root, "wan4gIp", ip);
			}
		}else{
			cJSON_AddStringToObject(root, "wan4gIp", "");
		}
		cJSON_Delete(stat_json);
	}
	
	//sim/reg status
	if(reg_status & CONN_OK || reg_status & REG_OK)
		cJSON_AddStringToObject(root, "registStatus", "regHome");
	else if(reg_status & SIM_OK)
		cJSON_AddStringToObject(root, "registStatus", "unReg");
	else
		cJSON_AddStringToObject(root, "registStatus", "noSim");

end:

	send_cgi_json_respond(conn_fp, root);
	
	return CGI_TRUE;
}

CGI_BOOL setModemCfg(json_object *request, FILE *conn_fp)
{
	char tmpBuf[32]={0}, rules[2048]={0}, authtype[16]={0},ubus_cmd[1024]={0};
	char modem_dial[16]={0}, old_dial[16]={0};
	int currentIdx=0,apn_idx=0, num = 0, idx = 0, intVal=0, i,ret;
	struct array_list *subnet;
	char *apn, *user, *pass, *auth;
	
	//kock net_type
	char *netType = webs_get_string(request,"netType5g");
	if(strcmp(netType, "LTE") ==0)
		Uci_Set_Str(PKG_NETWORK_CONFIG, IFACE_3GPP_WAN, "modem_mode", "lte");
	else if (strcmp(netType, "NR5G-SA") == 0)
		Uci_Set_Str(PKG_NETWORK_CONFIG, IFACE_3GPP_WAN, "modem_mode", "sa");
	else if (strcmp(netType, "NR5G-NSA") == 0)
		Uci_Set_Str(PKG_NETWORK_CONFIG, IFACE_3GPP_WAN, "modem_mode", "nsa");
	else
		Uci_Set_Str(PKG_NETWORK_CONFIG, IFACE_3GPP_WAN, "modem_mode", "auto");

	char *rtl8111hEnable = webs_get_string(request,"rtl8111hEnable");
	Uci_Get_Str(PKG_NETWORK_CONFIG, IFACE_3GPP_WAN, "modem_dial", old_dial);
	if(atoi(rtl8111hEnable) == 1) {
		strcpy(modem_dial, "PCIE_RC");
		Uci_Set_Str(PKG_NETWORK_CONFIG, IFACE_3GPP_WAN, "modem_dial", "PCIE_RC");
	}
	else {
		strcpy(modem_dial, "NONE");
		Uci_Set_Str(PKG_NETWORK_CONFIG, IFACE_3GPP_WAN, "modem_dial", "NONE");
	}

	//set拨号方式
	char *dialWay = webs_get_string(request,"dialWay");
	memset(tmpBuf, '\0', sizeof(tmpBuf));
	
	if(atoi(dialWay) == 1){
		strcpy(tmpBuf, "dhcp");
	}else if(atoi(dialWay) == 2){
		strcpy(tmpBuf, "ppp");
	}else{
		strcpy(tmpBuf, "auto");
	}
	Uci_Set_Str(PKG_NETWORK_CONFIG, IFACE_3GPP_WAN, "proto", tmpBuf);
	Uci_Set_Str(PKG_NETWORK_CONFIG, IFACE_3GPP_WAN, "modem_type", dialWay);


	char *sim = webs_get_string(request,"sim");
	Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "main", "sim", sim);

	//lock arfcn_band
	char *lockCellEnable = webs_get_string(request,"lockCellEnable");
	char *lock_band = webs_get_string(request,"band");
	char *scsType = webs_get_string(request,"scsType");
	char *ltePci = webs_get_string(request,"ltePci");
	char *lteArfcn = webs_get_string(request,"lteArfcn");
	char *bandLock5g = webs_get_string(request,"bandLock5g");
	char cmd[256]={0};
	Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "status", "lock_cell_enable", lockCellEnable);
	Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "status", "lock_band", lock_band);
	Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "status", "scstype", scsType);
	Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "status", "lte_pci", ltePci);
	Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "status", "lte_arfcn", lteArfcn);
	Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "status", "band_lock5g", bandLock5g);


	char *dialNum = webs_get_string(request,"dialNum");
	Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "status", "dial_num", dialNum);

	/*********************apn start*************************************/
	Uci_Get_Int(PKG_WAN_MODEM_CONFIG, "apnlist", "num", &num);
	if(num > 0){
		Uci_Get_Str(PKG_WAN_MODEM_CONFIG,"apnlist","rules",rules);
		for(i=num; i>0; i--){
			memset(tmpBuf, '\0', sizeof(tmpBuf));
			get_nth_val_safe((i-1), rules, ' ', tmpBuf, sizeof(tmpBuf));
			Uci_Del_List(PKG_WAN_MODEM_CONFIG, "apnlist", "rules", tmpBuf);
		}	
		num=0;
		Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "apnlist", "num", "0");

		Uci_Set_Str(PKG_NETWORK_CONFIG, IFACE_3GPP_WAN, "modem_apn", "");
		Uci_Set_Str(PKG_NETWORK_CONFIG, IFACE_3GPP_WAN, "modem_user", "");
		Uci_Set_Str(PKG_NETWORK_CONFIG, IFACE_3GPP_WAN, "modem_pass", "");
		Uci_Set_Str(PKG_NETWORK_CONFIG, IFACE_3GPP_WAN, "modem_auth", "");
	}
	
	currentIdx = atoi(webs_get_string(request,"currentIdx"));
	json_object_object_foreach(request, key, val) {
		if (strcmp(key, "subnet") == 0) {

			subnet = json_object_get_array(val);
			num = json_object_array_length(val);
			memset(tmpBuf, 0, sizeof(tmpBuf));
			sprintf(tmpBuf, "%d", num);
			Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "apnlist", "num", tmpBuf);
			
			for(idx = 0; idx < num; idx++) {
				struct json_object *subnet_x = (struct json_object *)array_list_get_idx(subnet, idx);
				apn = webs_get_string(subnet_x, "apn");
				user = webs_get_string(subnet_x, "user4g");
				pass = webs_get_string(subnet_x, "pass4g");
				auth = webs_get_string(subnet_x, "auth");
				apn_idx=webs_get_int(subnet_x, "idx");
				memset(rules, 0, sizeof(rules));
				memset(authtype, 0, sizeof(authtype));
				intVal = atoi(auth);
				if(intVal == AUTH_NONE)
					sprintf(authtype, "%s", "NONE");
				else if(intVal == AUTH_PAP)
					sprintf(authtype, "%s", "PAP");
				else if(intVal == AUTH_CHAP)
					sprintf(authtype, "%s", "CHAP");
				else
					sprintf(authtype, "%s", "PAP+CHAP");
				
				sprintf(rules, "%s,%s,%s,%s",apn, authtype, user, pass);
				Uci_Add_List(PKG_WAN_MODEM_CONFIG, "apnlist", "rules", rules);
				
				if(currentIdx==apn_idx){
					Uci_Set_Str(PKG_NETWORK_CONFIG, IFACE_3GPP_WAN, "modem_apn", apn);
					Uci_Set_Str(PKG_NETWORK_CONFIG, IFACE_3GPP_WAN, "modem_user", user);
					Uci_Set_Str(PKG_NETWORK_CONFIG, IFACE_3GPP_WAN, "modem_pass", pass);
					Uci_Set_Str(PKG_NETWORK_CONFIG, IFACE_3GPP_WAN, "modem_auth", auth);
				}
			}
		}
	}

#if 0
	int modem_tactics=3, old_tactics_route=0, tactics_route=1;
	char section[128]={0};
	
	Uci_Get_Int(PKG_WAN_MODEM_CONFIG, "main", "tactics_route", &old_tactics_route);
	num = get_cmd_val("uci show network | grep route | grep target= |  wc -l");
	
	if(modem_tactics==3)
	{
		Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "main", "tactics_route", "1");
		Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "main", "tactics_route_if",	"usb1");
		Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "main", "tactics_route_ip",	"10.0.200.0");
		Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "main", "tactics_route_mask", "255.255.255.0");
		Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "main", "tactics_route_gw",	"0.0.0.0");

		if(old_tactics_route==0)
		{
			Uci_Add_Section(PKG_NETWORK_CONFIG,"route");
			memset(section,0,sizeof(section));
			snprintf(section,sizeof(section)-1,"@route[%d]",num);
			
		}else{
			memset(section,0,sizeof(section));
			snprintf(section,sizeof(section)-1,"@route[%d]",num-1);	
		}
		
		{
			Uci_Set_Str(PKG_NETWORK_CONFIG,section,"interface","usb1");			
			Uci_Set_Str(PKG_NETWORK_CONFIG,section,"target", "10.0.200.0");
			Uci_Set_Str(PKG_NETWORK_CONFIG,section,"gateway", "0.0.0.0");
			Uci_Set_Str(PKG_NETWORK_CONFIG,section,"metric", "0");
			Uci_Set_Str(PKG_NETWORK_CONFIG,section,"netmask", "255.255.255.0");;			
		}
		
	}else{

		if(old_tactics_route==1)
		{
			Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "main", "tactics_route", "0");			
			snprintf(section,sizeof(section)-1, "@route[%d]", num-1);
			Uci_Del_Section(PKG_NETWORK_CONFIG,section);
		}
	
	}
#endif

	Uci_Commit(PKG_WAN_MODEM_CONFIG);
	Uci_Commit(PKG_NETWORK_CONFIG);
	
	if(strcmp(modem_dial, old_dial)) {
		set_lktos_effect("mcm");
		send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "30", "reserv");
	}
	else {
		datconf_set_ival(TEMP_MODEM_FILE, "modem1_control", 1);
		send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "15", "reserv");
	}

	return CGI_TRUE;
}


#if 1
CGI_BOOL setSmsCfg(json_object *request, FILE *conn_fp)
{
    char * online_enable = webs_get_string(request, "onlineEnable");
    char * online_text = webs_get_string(request, "onlineText");	
	char * offline_enable = webs_get_string(request, "offlineEnable");
	char * offline_text=webs_get_string(request,"offlineText");
    char * reboot_enable = webs_get_string(request, "rebootEnable");
    char * reboot_text = webs_get_string(request, "rebootText");
	char * phone0=webs_get_string(request,"phone0");
	char * phone1=webs_get_string(request,"phone1");
	char * phone2=webs_get_string(request,"phone2");
	char * phone3=webs_get_string(request,"phone3");
	char * phone4=webs_get_string(request,"phone4");
	char * phone5=webs_get_string(request,"phone5");

	Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "smsInfo", "onlineEnable", online_enable);
	if (atoi(online_enable) == 1)
		Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "smsInfo", "onlineText", online_text);

	Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "smsInfo", "offlineEnable", offline_enable);
	if (atoi(offline_enable) == 1)
		Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "smsInfo", "offlineText", offline_text);
	
	Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "smsInfo", "rebootEnable", reboot_enable);
	if (atoi(reboot_enable) == 1)
		Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "smsInfo", "rebootText", reboot_text);

	Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "smsInfo", "phone0", phone0);
	Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "smsInfo", "phone1", phone1);
	Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "smsInfo", "phone2", phone2);
	Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "smsInfo", "phone3", phone3);
	Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "smsInfo", "phone4", phone4);
	Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "smsInfo", "phone5", phone5);
	
	Uci_Commit(PKG_WAN_MODEM_CONFIG);

	// take effect
	
	
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "5", "reserv");
	return CGI_TRUE;
	
}


CGI_BOOL getSmsCfg(json_object *request, FILE *conn_fp)
{
	char online_enable[4]={0},online_text[32]={0},offline_enable[4]={0},offline_text[32]={0},reboot_enable[4]={0},reboot_text[32]={0};
	char phone0[16]={0},phone1[16]={0},phone2[16]={0},phone3[16]={0},phone4[16]={0},phone5[16]={0};

	cJSON *root;
	root = cJSON_CreateObject();

	Uci_Get_Str(PKG_WAN_MODEM_CONFIG,"smsInfo","onlineEnable",online_enable);
	Uci_Get_Str(PKG_WAN_MODEM_CONFIG,"smsInfo","onlineText",online_text);
	Uci_Get_Str(PKG_WAN_MODEM_CONFIG,"smsInfo","offlineEnable",offline_enable);
	Uci_Get_Str(PKG_WAN_MODEM_CONFIG,"smsInfo","offlineText",offline_text);
	Uci_Get_Str(PKG_WAN_MODEM_CONFIG,"smsInfo","rebootEnable",reboot_enable);
	Uci_Get_Str(PKG_WAN_MODEM_CONFIG,"smsInfo","rebootText",reboot_text);
	Uci_Get_Str(PKG_WAN_MODEM_CONFIG,"smsInfo","phone0",phone0);
	Uci_Get_Str(PKG_WAN_MODEM_CONFIG,"smsInfo","phone1",phone1);
	Uci_Get_Str(PKG_WAN_MODEM_CONFIG,"smsInfo","phone2",phone2);
	Uci_Get_Str(PKG_WAN_MODEM_CONFIG,"smsInfo","phone3",phone3);
	Uci_Get_Str(PKG_WAN_MODEM_CONFIG,"smsInfo","phone4",phone4);
	Uci_Get_Str(PKG_WAN_MODEM_CONFIG,"smsInfo","phone5",phone5);

	cJSON_AddStringToObject(root, "onlineEnable", online_enable);
	cJSON_AddStringToObject(root, "onlineText", online_text);	
	cJSON_AddStringToObject(root, "offlineEnable", offline_enable);
	cJSON_AddStringToObject(root, "offlineText", offline_text);
	cJSON_AddStringToObject(root, "rebootEnable", reboot_enable);
	cJSON_AddStringToObject(root, "rebootText", reboot_text);
	cJSON_AddStringToObject(root, "phone0", phone0);
	cJSON_AddStringToObject(root, "phone1", phone1);
	cJSON_AddStringToObject(root, "phone2", phone2);
	cJSON_AddStringToObject(root, "phone3", phone3);
	cJSON_AddStringToObject(root, "phone4", phone4);
	cJSON_AddStringToObject(root, "phone5", phone5);
	
	send_cgi_json_respond(conn_fp, root);
	
	return CGI_TRUE;
}
#else

void replace_string(char *result, char *source, char* s1, char *s2)
{
	char *q=NULL;
	char *p=NULL;

	p=source;
	while((q=strstr(p, s1))!=NULL)
	{
		strncpy(result, p, q-p);
		result[q-p]= '\0';//very important, must attention!
		strcat(result, s2);
		strcat(result, q+strlen(s1));
		strcpy(p,result);
	}
	strcpy(result, p); 
}



CGI_BOOL getSmsCfg(json_object *request, FILE *conn_fp)
{
	char nvram_key[32] = {0},date[16],time[16],buff[16],*p;
	char tmp_buf[10240]={0};
	int i,num;

	cJSON *root,*obj_t,*obj_b,*entry;
	char *output;
	
	root = cJSON_CreateObject();
	
	char modem_status[32]={0};
	datconf_get_by_key(TEMP_MODEM_FILE, "reg_status", modem_status, sizeof(modem_status));
	
	if(!strcmp(modem_status,"connected") || !strcmp(modem_status,"regHome") || !strcmp(modem_status,"regRoaming"))
		cJSON_AddStringToObject(root,"noSIM","0");
	else
		cJSON_AddStringToObject(root,"noSIM","1");
	
	//SMS_MODE, 0-GSM7, 1-TXT
	memset(tmp_buf, '\0', sizeof(tmp_buf));
	Uci_Get_Str(PKG_PRODUCT_CONFIG, "custom", "mcm_sms_mode", tmp_buf);
	cJSON_AddStringToObject(root,"smsMode",tmp_buf);
	
	//inbox
	obj_t = cJSON_CreateObject();
	entry = cJSON_CreateArray();
	cJSON_AddItemToObject(obj_t, "smsText", entry);
	cJSON_AddItemToObject(root, "receive", obj_t);

	datconf_get_by_key(ETC_MODEM_SMS_FILE, "sms_rec_num", tmp_buf, sizeof(tmp_buf));
	num = atoi(tmp_buf);
	cJSON_AddNumberToObject(obj_t, "used", num);
	cJSON_AddStringToObject(obj_t, "maximum", "100");		

	for(i = 0; i < num; i++) {

		obj_b = cJSON_CreateObject();
		cJSON_AddNumberToObject(obj_b, "idx", i + 1);

		snprintf(nvram_key, sizeof(nvram_key), "sms_rec_number_x%d", i);
		datconf_get_by_key(ETC_MODEM_SMS_FILE, nvram_key, tmp_buf, sizeof(tmp_buf));
		cJSON_AddStringToObject(obj_b, "number", tmp_buf);
		
		snprintf(nvram_key, sizeof(nvram_key), "sms_rec_time_x%d", i);
		datconf_get_by_key(ETC_MODEM_SMS_FILE, nvram_key, tmp_buf, sizeof(tmp_buf));
		bzero(date, sizeof(date));
		bzero(time, sizeof(time));
		bzero(buff, sizeof(time));
		get_nth_val_safe(0, tmp_buf, ',', date, sizeof(date));
		get_nth_val_safe(1, tmp_buf, ',', time, sizeof(time));
		
		p = strstr(time,"+32");
		if(p)
			strncpy(buff,time,p-time);
		else 	
			strcpy(buff,time);
		cJSON_AddStringToObject(obj_b, "date", date);
		cJSON_AddStringToObject(obj_b, "time", buff);

		snprintf(nvram_key, sizeof(nvram_key), "sms_rec_id_x%d", i);
		datconf_get_by_key(ETC_MODEM_SMS_FILE, nvram_key, tmp_buf, sizeof(tmp_buf));
		cJSON_AddStringToObject(obj_b, "msg_id", tmp_buf);

		snprintf(nvram_key, sizeof(nvram_key), "sms_rec_fragment_x%d", i);
		datconf_get_by_key(ETC_MODEM_SMS_FILE, nvram_key, tmp_buf, sizeof(tmp_buf));
		cJSON_AddStringToObject(obj_b, "fragment_num", tmp_buf);

		memset(tmp_buf, 0, sizeof(tmp_buf));
		snprintf(nvram_key, sizeof(nvram_key), "sms_rec_text_num_x%d", i);
		int text_num=datconf_get_ival(ETC_MODEM_SMS_FILE, nvram_key);
		int j=0;
		char buf[1024]={0};
		for( j=0; j<text_num; j++)
		{
			snprintf(nvram_key, sizeof(nvram_key), "sms_rec_text_x%d_%d", i, j);
			datconf_get_by_key(ETC_MODEM_SMS_FILE, nvram_key, buf, sizeof(buf));
			strcat(tmp_buf, buf);
		}
		if( tmp_buf && strcmp(tmp_buf,"")==0 ){
			snprintf(tmp_buf, 8, "0020");
		}
		cJSON_AddStringToObject(obj_b, "text", tmp_buf);

		cJSON_AddNumberToObject(obj_b, "delidx", i);
		cJSON_AddItemToArray(entry,obj_b);
	}

	//outbox
	obj_t = cJSON_CreateObject();
	entry = cJSON_CreateArray();
	cJSON_AddItemToObject(obj_t, "smsText", entry);
	cJSON_AddItemToObject(root, "send", obj_t);

	datconf_get_by_key(ETC_MODEM_SMS_FILE, "sms_send_num", tmp_buf, sizeof(tmp_buf));
	num = atoi(tmp_buf);
	cJSON_AddNumberToObject(obj_t, "used", num);
	cJSON_AddStringToObject(obj_t, "maximum", "100");		

	for(i = 0; i < num; i++) {

		obj_b = cJSON_CreateObject();
		cJSON_AddNumberToObject(obj_b, "idx", i + 1);

		snprintf(nvram_key, sizeof(nvram_key), "sms_send_number_x%d", i);
		datconf_get_by_key(ETC_MODEM_SMS_FILE, nvram_key, tmp_buf, sizeof(tmp_buf));
		cJSON_AddStringToObject(obj_b, "number", tmp_buf);

		snprintf(nvram_key, sizeof(nvram_key), "sms_send_time_x%d", i);
		datconf_get_by_key(ETC_MODEM_SMS_FILE, nvram_key, tmp_buf, sizeof(tmp_buf));
		bzero(date, sizeof(date));
		bzero(time, sizeof(time));
		get_nth_val_safe(0, tmp_buf, ',', date, sizeof(date));
		get_nth_val_safe(1, tmp_buf, ',', time, sizeof(time));
		cJSON_AddStringToObject(obj_b, "date", date);
		cJSON_AddStringToObject(obj_b, "time", time);

		memset(tmp_buf, 0, sizeof(tmp_buf));
		snprintf(nvram_key, sizeof(nvram_key), "sms_send_text_num_x%d", i);
		int text_num=datconf_get_ival(ETC_MODEM_SMS_FILE, nvram_key);
		int j=0;
		char buf[1024]={0};
		for( j=0; j<text_num; j++)
		{
			snprintf(nvram_key, sizeof(nvram_key), "sms_send_text_x%d_%d", i, j);
			datconf_get_by_key(ETC_MODEM_SMS_FILE, nvram_key, buf, sizeof(buf));
			strcat(tmp_buf, buf);
		}
		cJSON_AddStringToObject(obj_b, "text", tmp_buf);

		cJSON_AddNumberToObject(obj_b, "delidx", i);
		cJSON_AddItemToArray(entry,obj_b);
	}

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}

CGI_BOOL setSmsCfg(json_object *request, FILE *conn_fp)
{
	int idx, i=0;
	int text_len=500, text_num=0;
	char nvram_key[32] = {0},buff[64] = {0};
	char *text = webs_get_string(request, ("text"));
	char *phoneNumber = webs_get_string(request, ("phoneNumber"));
	char *date = webs_get_string(request, ("outboxDate"));
	char *time = webs_get_string(request, ("outboxTime"));
	int encode_type = webs_get_int(request, ("gsm7"));// 1:gsm7bit; 0: ucs2
	
	char textcode[1024]={0}, textcode1[1024]={0},text1[1024]={0}, text_buf[1024]={0};

	replace_string(text1,text,"+","%20");
	urldecode(text1,textcode);

	idx = datconf_get_ival(ETC_MODEM_SMS_FILE, "sms_send_num");
	datconf_set_ival(ETC_MODEM_SMS_FILE, "sms_send_num", idx + 1);
	
	snprintf(buff,sizeof(buff)-1,"%s,%s",date,time);
	snprintf(nvram_key, sizeof(nvram_key), "sms_send_time_x%d", idx);
	datconf_set_by_key(ETC_MODEM_SMS_FILE, nvram_key, buff);

	snprintf(nvram_key, sizeof(nvram_key), "sms_send_number_x%d", idx);
	datconf_set_by_key(ETC_MODEM_SMS_FILE, nvram_key, phoneNumber);

	text_num=(strlen(textcode)-1)/text_len+1;
	snprintf(nvram_key, sizeof(nvram_key), "sms_send_text_num_x%d", idx);
	datconf_set_ival(ETC_MODEM_SMS_FILE, nvram_key, text_num);
	for( i=0; i<text_num; i++)
	{
		snprintf(nvram_key, sizeof(nvram_key), "sms_send_text_x%d_%d", idx, i);
		memcpy(text_buf, textcode + (i*text_len) , text_len);
		datconf_set_by_key(ETC_MODEM_SMS_FILE, nvram_key, text_buf);
	}

	snprintf(nvram_key, sizeof(nvram_key), "sms_send_status_x%d", idx);
	datconf_set_by_key(ETC_MODEM_SMS_FILE, nvram_key, "0");

	snprintf(nvram_key, sizeof(nvram_key), "sms_encode_type_x%d", idx);
	datconf_set_ival(ETC_MODEM_SMS_FILE, nvram_key, encode_type);
	
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

	return CGI_TRUE;
}


#endif

CGI_BOOL getModemCfg(json_object *request, FILE *conn_fp)
{
	char tmpBuf[64] = {0}, buff[32]={0};
	char sRule[128]={0}, sRules[2048]={0}, mode[16]={0};
	char apn[33]={0}, user[33]={0}, pass[33]={0}, auth[16]={0}, result[256] = {0};
	char p_json[LONGLONG_BUFF_LEN]={0},arfcn[33]={0},pci[33]={0},net_type[33]={0};
	int nw_mode = 0,prefer_mode = 0, proto = 0;
	int i, iRulesNum, auto_apn;
	int ret =0;
	cJSON *root, *apnObj, *apnArry, *cell_root, *data, *lock_band;
	cJSON *sim_array, *tmp_obj;

	char tmp_buf[64]={0}, modem_section[32]={0}, key_name[64]={0};
	char modem_slot[32]={0};
	int modem_idx = 0;

	modem_idx = atoi(webs_get_string(request,"modem_idx"));
	snprintf(modem_slot, sizeof(modem_slot), "modem%d", modem_idx+1);
	if(modem_idx == 0) {
		snprintf(modem_section, sizeof(modem_section), "wan_modem");
	}
	else {
		snprintf(modem_section, sizeof(modem_section), "wan_modem%d", modem_idx+1);
	}
	root = cJSON_CreateObject();

	snprintf(key_name, sizeof(key_name), "%s_modem_name", modem_slot);
	datconf_get_by_key(TEMP_MODEM_FILE, key_name, tmp_buf, sizeof(tmp_buf));
	cJSON_AddStringToObject(root, "modemModel", tmp_buf);
	
	memset(tmpBuf, 0, sizeof(tmpBuf));
	Uci_Get_Str(PKG_NETWORK_CONFIG, modem_section, "proto", tmpBuf);
	
	if(strcmp(tmpBuf, "ppp") == 0){
		strcpy(buff, "2");
	}else if(strcmp(tmpBuf, "dhcp") == 0 || strcmp(tmpBuf, "tdmi") == 0){
		strcpy(buff, "1");
	}else{
		strcpy(buff, "0");
	}
	cJSON_AddStringToObject(root, "dialWay", buff);

	memset(tmpBuf, 0, sizeof(tmpBuf));
	Uci_Get_Str(PKG_NETWORK_CONFIG, modem_section, "dial_num", tmpBuf);
	cJSON_AddStringToObject(root, "dialNum", tmpBuf);

	memset(tmpBuf, 0, sizeof(tmpBuf));
	Uci_Get_Str(PKG_NETWORK_CONFIG, modem_section, "modem_dial", tmpBuf);
	if(strstr(tmpBuf, "PCIE_RC") != NULL) {
		cJSON_AddStringToObject(root, "rtl8111hEnable", "1");
	}
	else {
		cJSON_AddStringToObject(root, "rtl8111hEnable", "0");
	}

	cJSON_AddStringToObject(root, "user4g", "");
	cJSON_AddStringToObject(root, "pass4g", "");
	
	cJSON_AddStringToObject(root, "pinCode", "");
	//cJSON_AddStringToObject(root, "bandLock", "");
	cJSON_AddStringToObject(root, "saEnable", "");

	/* ppp auth */
	cJSON_AddStringToObject(root, "chap", "");
	cJSON_AddStringToObject(root, "pap", "");
	cJSON_AddStringToObject(root, "mschap", "");
	cJSON_AddStringToObject(root, "ms2chap", "");
	
	memset(tmpBuf, 0, sizeof(tmpBuf));
	Uci_Get_Str(PKG_WAN_MODEM_CONFIG, "main", "sim", tmpBuf);
	cJSON_AddStringToObject(root, "sim", tmpBuf);

	sim_array = cJSON_CreateArray();
	cJSON_AddItemToObject(root, "simlist", sim_array);
	for (i = 0; sim_slot_list[i].idx != NULL; i++)
	{
		tmp_obj = cJSON_CreateObject();
		cJSON_AddItemToArray(sim_array, tmp_obj);
		cJSON_AddStringToObject(tmp_obj, "idx", sim_slot_list[i].idx);
		cJSON_AddStringToObject(tmp_obj, "lable", sim_slot_list[i].lable);
		cJSON_AddStringToObject(tmp_obj, "value", sim_slot_list[i].value);
	}

	memset(tmpBuf, 0, sizeof(tmpBuf));
	Uci_Get_Str(PKG_NETWORK_CONFIG, modem_section, "modem_mode", mode);
	if(strcmp(mode, "auto") == 0)
		strcpy(tmpBuf, "AUTO");
	else if(strcmp(mode, "lte") == 0)
		strcpy(tmpBuf, "LTE");
	else if(strcmp(mode, "sa") == 0)
		strcpy(tmpBuf, "NR5G-SA");
	else if(strcmp(mode, "nsa") == 0)
		strcpy(tmpBuf, "NR5G-NSA");
	else
		strcpy(tmpBuf, "AUTO");
	
	cJSON_AddStringToObject(root, "netType", tmpBuf);
	cJSON_AddStringToObject(root, "netType5g", tmpBuf);

	cJSON_AddStringToObject(root, "modem_lock_band", "1");
	
	memset(tmpBuf, 0, sizeof(tmpBuf));
	Uci_Get_Str(PKG_WAN_MODEM_CONFIG, "status", "lock_cell_enable", tmpBuf);
	if(strlen(tmpBuf)==0)
		cJSON_AddStringToObject(root, "lockCellEnable", "0");
	else
		cJSON_AddStringToObject(root, "lockCellEnable", tmpBuf);

	memset(tmpBuf, 0, sizeof(tmpBuf));
	Uci_Get_Str(PKG_WAN_MODEM_CONFIG, "status", "lte_pci", tmpBuf);
	cJSON_AddStringToObject(root, "ltePci", tmpBuf);

	memset(tmpBuf, 0, sizeof(tmpBuf));
	Uci_Get_Str(PKG_WAN_MODEM_CONFIG, "status", "lte_arfcn", tmpBuf);
	cJSON_AddStringToObject(root, "lteArfcn", tmpBuf);

	memset(tmpBuf, 0, sizeof(tmpBuf));
	Uci_Get_Str(PKG_WAN_MODEM_CONFIG, "status", "band_lock5g", tmpBuf);
	cJSON_AddStringToObject(root, "bandLock5g", tmpBuf);

	memset(tmpBuf, 0, sizeof(tmpBuf));
	Uci_Get_Str(PKG_WAN_MODEM_CONFIG, "status", "scstype", tmpBuf);
	cJSON_AddStringToObject(root, "scsType", tmpBuf);

	lock_band = cJSON_CreateObject();
	cJSON_AddItemToObject(root, "lock_band", lock_band);
	snprintf(tmpBuf, sizeof(tmpBuf), "/tmp/modem/modem-config-%02d.cfg", modem_idx);
	if(f_exists(tmpBuf) && lock_band) {
		cJSON_AddNumberToObject(lock_band, "pci", config_lazy_get_int("lock_band.pci", tmpBuf));
		cJSON_AddNumberToObject(lock_band, "band", config_lazy_get_int("lock_band.band", tmpBuf));
		cJSON_AddNumberToObject(lock_band, "arfcn", config_lazy_get_int("lock_band.arfcn", tmpBuf));
		cJSON_AddNumberToObject(lock_band, "scs", config_lazy_get_int("lock_band.scs", tmpBuf));
	}
	else {
		cJSON_AddNumberToObject(lock_band, "pci", 0);
		cJSON_AddNumberToObject(lock_band, "band", 0);
		cJSON_AddNumberToObject(lock_band, "arfcn", 0);
		cJSON_AddNumberToObject(lock_band, "scs", 0);
	}

	memset(tmpBuf, 0, sizeof(tmpBuf));
	Uci_Get_Str(PKG_NETWORK_CONFIG, modem_section, "modem_apn", tmpBuf);
	cJSON_AddStringToObject(root, "currenApn", tmpBuf);
	
	apnArry = cJSON_CreateArray();
	cJSON_AddItemToObject(root, "rule", apnArry);
	Uci_Get_Int(PKG_WAN_MODEM_CONFIG,"apnlist","num",&iRulesNum);
	Uci_Get_Str(PKG_WAN_MODEM_CONFIG,"apnlist","rules",sRules);
	for(i=0;i<iRulesNum;i++)
	{
		get_nth_val_safe(i, sRules, ' ', sRule, sizeof(sRule));
		if((get_nth_val_safe(0, sRule, ',', apn, sizeof(apn)) == -1)) {
			continue;
		}

		if((get_nth_val_safe(1, sRule, ',', auth, sizeof(auth)) == -1)) {
			continue;
		}

		if((get_nth_val_safe(2, sRule, ',', user, sizeof(user)) == -1)) {
			continue;
		}

		if((get_nth_val_safe(3, sRule, ',', pass, sizeof(pass)) == -1)) {
			continue;
		}

		apnObj = cJSON_CreateObject();

		memset(tmpBuf, 0, sizeof(tmpBuf));
		sprintf(tmpBuf, "%d", i+1);
		cJSON_AddStringToObject(apnObj,"idx", tmpBuf);
		cJSON_AddStringToObject(apnObj,"apn", apn);

		memset(tmpBuf, 0, sizeof(tmpBuf));
		if(strcmp(auth, "NONE") == 0)
			sprintf(tmpBuf, "%d", 0);
		if(strcmp(auth, "PAP") == 0)
			sprintf(tmpBuf, "%d", 1);
		if(strcmp(auth, "CHAP") == 0)
			sprintf(tmpBuf, "%d", 2);
		if(strcmp(auth, "PAP+CHAP") == 0)
			sprintf(tmpBuf, "%d", 3);

		cJSON_AddStringToObject(apnObj,"auth", tmpBuf);
		cJSON_AddStringToObject(apnObj,"user4g", user);
		cJSON_AddStringToObject(apnObj,"pass4g", pass);
		memset(tmpBuf, 0, sizeof(tmpBuf));
		snprintf(tmpBuf,SHORT_STR_LEN,"delRule%d",i);
		cJSON_AddStringToObject(apnObj, "delRuleName", tmpBuf);
		cJSON_AddItemToArray(apnArry,apnObj);
	}

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}

CGI_BOOL setApnCfg(json_object *request, FILE *conn_fp)
{

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");
	return CGI_TRUE;
}

//---------------------------------------------------------------------------------
CGI_HANDLE_TABLE modem_handle_t[]={
	{"getLteAllInfo", getLteAllInfo, 1},

	{"setModemCfg", setModemCfg, 1},
	{"getModemCfg", getModemCfg, 	1},
	{"getCurrentCell", getCurrentCell,  1},
	{"getCellInfo", getCellInfo,  1},
	{"lockCell", lockCell,  1},

	{"setApnCfg", setApnCfg,		1},
	{"setSmsCfg", setSmsCfg,		1},
	{"getSmsCfg", getSmsCfg,		1},
	
	{"", NULL, 0},
};

