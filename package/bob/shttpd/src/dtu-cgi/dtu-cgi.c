
#include "../defs.h"

CGI_HANDLE_TABLE get_handle_t[MAX_TOPIC_NUM];
CGI_HANDLE_TABLE set_handle_t[MAX_TOPIC_NUM];
CGI_HANDLE_TABLE other_handle_t[MAX_TOPIC_NUM];

void utc_to_local_time(utc_to_local *data, int8_t timezone)
{
	

    int year, month, day, hour;
    int cur_month_day = 0;
    int last_month_day = 0;

    year = data->year;
    month = data->month;
    day = data->day;
    hour = data->hour + timezone;

    if (month == 1 || month == 3 || month == 5 || month == 7 || month == 8 || month == 10 || month == 12) {
        cur_month_day = 31;
        last_month_day = 30;
        if (month == 3) {
            if ((year % 400 == 0) || (year % 4 == 0 && year % 100 != 0))
                last_month_day = 29;
            else
                last_month_day = 28;
        }
        if (month == 8 || month == 1)
            last_month_day = 31;
    } else if (month == 4 || month == 6 || month == 9 || month == 11) {
        cur_month_day = 30;
        last_month_day = 31;
    } else {
        last_month_day = 31;
        if ((year % 400 == 0) || (year % 4 == 0 && year % 100 != 0))
            cur_month_day = 29;
        else
            cur_month_day = 28;
    }

    if (hour >= 24) {
        hour -= 24;
        day += 1;
        if (day > cur_month_day) {
            day -= cur_month_day;
            month += 1;
            if (month > 12) {
                month -= 12;
                year += 1;
            }
        }
    }

    if (hour < 0) {
        hour += 24;
        day -= 1;
        if (day < 1) {
            day = last_month_day;
            month -= 1;
            if (month < 1) {
                month = 12;
                year -= 1;
            }
        }
    }

    data->year = year;
    data->month = month;
    data->day = day;
    data->hour = hour;
}



static int get_info_value(char **info, char *value)
{
    char *vernier = 0;
    int i = 0;
    vernier = *info;
    while((*vernier == ' ') || (*vernier == '\n'))
    {
        vernier++;
    }
    for(i = 0; *vernier != 32 && *vernier != '\n' && *vernier != '\0' && i < 64;i++)
    {
        value[i] = *vernier;
        vernier++;
    }
    if(*vernier == '\0')
    {
        return 0;
    }
    *info = vernier;
    return - 1;
}


static int analysis_monut_info(char *buf, char *path)
{
    char *info = buf;
    char value[128] = {0};
    int ret = 1; 
    while(0 != ret)
    {
        sprintf(path, "%s", value);
        memset(value, 0, sizeof(value));
        ret = get_info_value(&info, value);
    }
    return ret;
}

int GetUDiskMountPath(char * mnt_path,char *mount_file,char *mount_name)
{
    int fd = 0, ret = 0, rdsize = 0;
    char buf[1024] = {0},cmd[1024] = {0};
    fd = open(mount_file, O_CREAT | O_RDWR | O_NONBLOCK | O_TRUNC, 0777);
    if(fd < 0)
    {
        dbg("open error\n");
        return - 1;
    }    

	sprintf(cmd,"df -h |grep %s > %s",mount_name,mount_file);
    ret = system(cmd);
    if(ret)
    {
        return - 1;
    }
    
    rdsize = read(fd, buf, sizeof(buf));
    if(rdsize < 2)
    {
        return - 1;
    }

    ret = analysis_monut_info(buf, mnt_path);

    close(fd);
    return ret;
}

int getCmdStr(const char *cmd, char *strVal, int len)
{
	char *p;
	int ret = 0;

	FILE *fp = popen(cmd, "r");
	if(!fp) 
		return -1;

	if(fgets(strVal, len, fp) != NULL){
		if(p=strstr(strVal, "\n"))
			p[0]='\0';
	}else{
		*strVal = '\0';
		ret = -1;
	}
	pclose(fp);

	return ret;
}

char *websGetVar(cJSON *object, char *var, char *defaultGetValue)
{
	cJSON	*sp;

    assert(var && *var);
 
	if ((sp = cJSON_GetObjectItem(object, var)) != NULL) {
		if (sp->valuestring) 
		{
			return sp->valuestring;
		}
		else if (sp->type==cJSON_False)
		{
			return "0";
		}
		else if (sp->type==cJSON_True)
		{
			return "1";
		}
		else if (sp->type==cJSON_Number)
		{
			static char tmp[32] = { 0 };
			sprintf(tmp, "%d", sp->valueint);
			return tmp;
		}		
		else if (!sp->valuestring) 
		{
			return defaultGetValue;
		}
		else 
		{
			return "";
		}
	}
	return defaultGetValue;
}


int getNthValueSafe(int index, char *value, char delimit, char *result, int len)
{
	int i = 0, result_len = 0;
	char *begin, *end;

	if(!value || !result || !len)
		return -1;

	begin = value;
	end = strchr(begin, delimit);

	while(i < index && end) {
		begin = end + 1;
		end = strchr(begin, delimit);
		i++;
	}

	//no delimit
	if(!end) {
		if(i == index) {
			end = begin + strlen(begin);
			result_len = (len - 1) < (end - begin) ? (len - 1) : (end - begin);
		} else
			return -1;
	} else
		result_len = (len - 1) < (end - begin) ? (len - 1) : (end - begin);

	memcpy(result, begin, result_len );
	*(result + result_len ) = '\0';

	return 0;
}

void register_handle_table(CGI_HANDLE_TABLE module_handle[], int *idx_get, int *idx_set, int *idx_oth)
{
	int i;

	for(i = 0;(module_handle[i].fun != NULL);i++){
		if(strncmp(module_handle[i].topicurl,"get",3)==0 && *idx_get < MAX_TOPIC_NUM){
			get_handle_t[*idx_get]=module_handle[i];
			*idx_get+=1;
		}
		else if(strncmp(module_handle[i].topicurl,"set",3)==0  && *idx_set < MAX_TOPIC_NUM){
			set_handle_t[*idx_set]=module_handle[i];
			*idx_set+=1;
		}
		else if( *idx_oth < MAX_TOPIC_NUM){
			other_handle_t[*idx_oth]=module_handle[i];
			*idx_oth+=1;
		}
	}

}

void init_handle_table()
{
	int idx_get, idx_set, idx_oth;

	idx_get=idx_set=idx_oth=0;

	memset((void *)get_handle_t,   0, sizeof(CGI_HANDLE_TABLE)*MAX_TOPIC_NUM);
	memset((void *)set_handle_t,   0, sizeof(CGI_HANDLE_TABLE)*MAX_TOPIC_NUM);
	memset((void *)other_handle_t, 0, sizeof(CGI_HANDLE_TABLE)*MAX_TOPIC_NUM);

	register_handle_table(global_handle_t,   &idx_get, &idx_set, &idx_oth);

	register_handle_table(network_handle_t, &idx_get, &idx_set, &idx_oth);

	register_handle_table(gloset_handle_t,   &idx_get, &idx_set, &idx_oth);
#if defined(WIFI_SUPPORT)
	register_handle_table(wireless_handle_t, &idx_get, &idx_set, &idx_oth);
#endif
	register_handle_table(system_handle_t, &idx_get, &idx_set, &idx_oth);

	register_handle_table(firewall_handle_t, &idx_get, &idx_set, &idx_oth);

	register_handle_table(modem_handle_t, &idx_get, &idx_set, &idx_oth);

	register_handle_table(vpn_handle_t, &idx_get, &idx_set, &idx_oth);
	
	dbg("Topic Num: get=%d, set=%d, oth=%d\n", idx_get, idx_set, idx_oth);

}

void free_priv_data(PersonalData *priv_data)
{
	if((priv_data) && (priv_data->request_obj)) {
		json_object_put(priv_data->request_obj);
		free(priv_data);
		priv_data = NULL;			//necessary
	}
}

PersonalData *do_SaveSettingTopic()
{
	int i=0;
	PersonalData *priv_data;
	char buf[256]={0}, topicurl[32]={0};
	
	priv_data = (PersonalData *)malloc(sizeof(PersonalData));
	if(priv_data == NULL) {
		dbg("malloc fail");
		return NULL;
	}
	
	priv_data->topicurl = NULL;
	priv_data->p_tab = NULL;
	priv_data->cgi_type = CGI_NULL;

	strcpy(topicurl, "saveSystemSetting");

	sprintf(buf,"{\"topicurl\":\"%s\"}",topicurl);
	
	priv_data->request_obj = json_tokener_parse(buf);	
	
	for(i = 0;(other_handle_t[i].fun != NULL);i++){
		if(strncmp(topicurl,other_handle_t[i].topicurl, sizeof(other_handle_t[i].topicurl)) == 0){
			priv_data->topicurl = (char*)(topicurl);
			priv_data->p_tab = &other_handle_t[i];
			priv_data->cgi_type = CGI_OTHER;
			break;
		}
	}	

	if(priv_data->p_tab == NULL) {
		dbg("unknow request topicurl:%s\n",topicurl);
		free_priv_data(priv_data);
		return NULL;
	}
	
	return priv_data;
}

PersonalData *do_SaveSslvpnCert(char *topicurl)
{
	int i=0;
	PersonalData *priv_data;
	char buf[256]={0};
	
	priv_data = (PersonalData *)malloc(sizeof(PersonalData));
	if(priv_data == NULL) {
		dbg("malloc fail");
		return NULL;
	}
	
	priv_data->topicurl = NULL;
	priv_data->p_tab = NULL;
	priv_data->cgi_type = CGI_NULL;


	sprintf(buf,"{\"topicurl\":\"%s\"}",topicurl);

	priv_data->request_obj = json_tokener_parse(buf);	
	
	for(i = 0;(set_handle_t[i].fun != NULL);i++){
		if(strncmp(topicurl,set_handle_t[i].topicurl, sizeof(set_handle_t[i].topicurl)) == 0){
			priv_data->topicurl = (char*)(topicurl);
			priv_data->p_tab = &set_handle_t[i];
			priv_data->cgi_type = CGI_SET;
			break;
		}
	}	

	if(priv_data->p_tab == NULL) {
		dbg("unknow request topicurl:%s\n",topicurl);
		free_priv_data(priv_data);
		return NULL;
	}
	
	return priv_data;
}


PersonalData *loginData(char *input)
{
	int i=0;
	PersonalData *priv_data;
	cJSON *root;
	char buf[256]={0}, tmpbuf[128]={0},topicurl[32]={0};
	char username[64]={0},password[64]={0};
	char *ptr=NULL;
	
	priv_data = (PersonalData *)malloc(sizeof(PersonalData));
	if(priv_data == NULL) {
		dbg("malloc fail");
		return NULL;
	}
	priv_data->topicurl = NULL;
	priv_data->p_tab = NULL;
	priv_data->cgi_type = CGI_NULL;

	strcpy(topicurl, "loginAuth");

	getNthValueSafe(0, input, '&', tmpbuf, sizeof(tmpbuf));
	getNthValueSafe(1, tmpbuf, '=', username, sizeof(username));
	
	memset(tmpbuf, 0, sizeof(tmpbuf));
	getNthValueSafe(1, input, '&', tmpbuf, sizeof(tmpbuf));
	getNthValueSafe(1, tmpbuf, '=', password, sizeof(password));
	
	sprintf(buf,"{\"topicurl\":\"%s\",\"username\":\"%s\",\"password\":\"%s\"}",topicurl,username,password);
	
	priv_data->request_obj = json_tokener_parse(buf);	
	
	for(i = 0;(other_handle_t[i].fun != NULL);i++){
		if(strncmp(topicurl,other_handle_t[i].topicurl, sizeof(other_handle_t[i].topicurl)) == 0){
			priv_data->topicurl = (char*)(topicurl);
			priv_data->p_tab = &other_handle_t[i];
			priv_data->cgi_type = CGI_OTHER;
			break;
		}
	}	

	if(priv_data->p_tab == NULL) {
		dbg("unknow request topicurl:%s\n",topicurl);
		free_priv_data(priv_data);
		return NULL;
	}

	return priv_data;
	
}

PersonalData *json_to_topic(char *input)
{
	int i = 0;
	PersonalData *priv_data;
	json_object *topicurl_obj = NULL;
	const char *topicurl = NULL;
	int js_type = json_type_null;

	priv_data = (PersonalData *)malloc(sizeof(PersonalData));
	if(priv_data == NULL) {
		dbg("malloc fail");
		return NULL;
	}

	priv_data->topicurl = NULL;
	priv_data->p_tab = NULL;
	priv_data->cgi_type = CGI_NULL;
	priv_data->request_obj = json_tokener_parse(input);
	if(priv_data->request_obj == NULL) {
		dbg("request obj is null\n");
		free_priv_data(priv_data);
		return NULL;
	}

	if(!json_object_object_get_ex(priv_data->request_obj, "topicurl", &topicurl_obj)) {
		dbg("request obj has not topicurl\n");
		free_priv_data(priv_data);
		return NULL;
	}
	js_type = (int)json_object_get_type(priv_data->request_obj);
	if (js_type == json_type_object ){

		topicurl = json_object_get_string(topicurl_obj);
	
		if(strstr(topicurl,"get")){
			for(i = 0;(get_handle_t[i].fun != NULL);i++){
				if(strncmp(topicurl,get_handle_t[i].topicurl, sizeof(get_handle_t[i].topicurl)) == 0){
					priv_data->topicurl = topicurl;
					priv_data->p_tab = &get_handle_t[i];
					priv_data->cgi_type = CGI_GET;
					break;
				}
			}
		}else if(strstr(topicurl,"set")){
			for(i = 0;(set_handle_t[i].fun != NULL);i++){
				if(strncmp(topicurl,set_handle_t[i].topicurl, sizeof(set_handle_t[i].topicurl)) == 0){
					priv_data->topicurl = topicurl;
					priv_data->p_tab = &set_handle_t[i];
					priv_data->cgi_type = CGI_SET;
					break;
				}
			}
		}else{
			for(i = 0;(other_handle_t[i].fun != NULL);i++){
				if(strncmp(topicurl,other_handle_t[i].topicurl, sizeof(other_handle_t[i].topicurl)) == 0){
					priv_data->topicurl = topicurl;
					priv_data->p_tab = &other_handle_t[i];
					priv_data->cgi_type = CGI_OTHER;
					break;
				}
			}
		}
	}
	else if ( js_type == json_type_array ){	
	
	}

	if(priv_data->p_tab == NULL) {
		dbg("unknow request topicurl:%s\n",topicurl);
		free_priv_data(priv_data);
		return NULL;
	}

	return priv_data;
}

//-----------------------------------------------------------------------------------------------------------------------------------
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

void add_bollean_to_json_obj(json_object *json_obj_out, char *object, json_bool value)
{
	json_object *json_obj_tmp = json_object_new_boolean(value);
	json_object_object_add(json_obj_out, object, json_obj_tmp);
}

const char *json_common_get_string(json_object *js_obj, char *key)
{
	json_object *js_tmp = NULL;
	if(!json_object_object_get_ex(js_obj, key, &js_tmp))
		return NULL;

	return json_object_get_string(js_tmp);
}

const int json_common_get_int(json_object *js_obj, char *key)
{
	json_object *js_tmp = NULL;
	if(!json_object_object_get_ex(js_obj, key, &js_tmp))
		return -1;

	return json_object_get_int(js_tmp);
}

char *webs_get_string(json_object *js_obj, char *key)
{
	json_object *js_tmp = NULL;
	char *str = NULL;

	if(json_object_object_get_ex(js_obj, key, &js_tmp)) {
		str = (char *)json_object_get_string(js_tmp);
		if (str != NULL)
			return str;
	}

	return "";
}

int webs_get_int(json_object *js_obj, char *key)
{
	json_object *js_tmp = NULL;
	char *str = NULL;

	if(json_object_object_get_ex(js_obj, key, &js_tmp)) {
		str = (char *)json_object_get_string(js_tmp);
		if(str != NULL)
			return atoi(str);
	}

	return 0; 
}

void send_cgi_set_respond(FILE *conn_fp, json_bool success, char *error, const char *lan_ip, char *wtime, char *reserv)
{
	json_object *respond_obj = NULL;
	const char *respond = NULL;
	char tmp_ip[18]={0};

	if(lan_ip==NULL){
		get_ifname_ipaddr("br-lan", tmp_ip);
	}else{
		snprintf(tmp_ip,sizeof(tmp_ip),"%s",lan_ip);
	}

	respond_obj = json_object_new_object();
	add_bollean_to_json_obj(respond_obj, "success", success);
	add_str_to_json_obj(respond_obj, "error", error);
	add_str_to_json_obj(respond_obj, "lan_ip", tmp_ip);
	add_str_to_json_obj(respond_obj, "wtime", wtime);
	add_str_to_json_obj(respond_obj, "reserv", reserv);
	respond = json_object_to_json_string(respond_obj);
	fprintf(conn_fp, "%s", respond);

	json_object_put(respond_obj);
}

void send_cgi_json_respond(FILE *conn_fp, cJSON *data)
{
	const char *respond = NULL;

	respond= cJSON_Print(data);

	fprintf(conn_fp, "%s", respond);

	cJSON_Delete(data);

	free(respond);
}


void send_check_auth_respond(int err_code, char *err_msg, FILE *conn_fp)
{
	const char *respond = NULL;

	cJSON *data;

	data= cJSON_CreateObject();

	cJSON_AddNumberToObject(data, "errcode", err_code);
	cJSON_AddStringToObject(data, "errmsg", err_msg);

	respond= cJSON_Print(data);

	fprintf(conn_fp, "%s", respond);

	cJSON_Delete(data);

	free(respond);
}

/*
agentAddress  udp:192.168.1.1:161
view all included .1 80
 rocommunity public  default
 trapsink     localhost public
 trap2sink    localhost public
authtrapenable 1
//iquerySecName administrator
linkUpDownNotifications yes
defaultMonitors yes

#Process checks
proc sendmail 10 1

#disk checks
disk / 100000

#Check for loads
load 5 5 5

#CPU usage
notificationEvent userCPU ssCpuRawUser
notificationEvent sysCPU ssCpuRawSystem
monitor -r 60 -e userCPU "User CPU use percentage" ssCpuRawUser > 100
monitor -r 60 -e sysCPU "System CPU use percentage" ssCpuRawSystem > 100

#Memory usage
notificationEvent memTotalTrap memTotalReal memTotalSwap
notificationEvent memAvailTrap memAvailReal memAvailSwap memTotalFree
monitor -r 10 -e memTotalTrap "Total memory" memTotalReal < 1000000000000
monitor -r 10 -e memAvailTrap "Available memory" memTotalFree < 1000000000000
*/
int DealSnmpdConf(void)
{
	char conf_file[OPTION_STR_LEN] = {0};
	char interface[RESULT_STR_LEN] = {0},ipaddr[RESULT_STR_LEN] = {0};
	char agentAddress_buff[CMD_STR_LEN] = {0};
	char community_buff[CMD_STR_LEN] = {0};
	char trap_buff[CMD_STR_LEN] = {0};
	char paramName[OPTION_STR_LEN] = {0};
	char username[OPTION_STR_LEN] = {0};
	char mode[SMALL_STR_LEN]={0};
	char password[OPTION_STR_LEN] = {0},hash[SHORT_STR_LEN] = {0};
	char encryption[SHORT_STR_LEN] = {0},key[OPTION_STR_LEN] = {0};
	char trapIp[OPTION_STR_LEN]={0};
	char trapPort[SHORT_STR_LEN]={0};

	char debug[SHORT_STR_LEN]={0};

	char tmp_buff[TEMP_STR_LEN] = {0};
	char sRules[LONG_BUFF_LEN] = {0},sRule[TEMP_STR_LEN] = {0},iRulesNum[8]={0};
	FILE *fpp = NULL;

	doSystem("rm %s",SNMP_CONF);
	doSystem("touch %s",SNMP_CONF);
	sprintf(conf_file, "%s",SNMP_CONF);

	fpp = fopen(conf_file, "w");
	if(fpp == NULL)
	{
		dbg("open /etc/snmp/snmpd.conf fail!\n");
		return -1;
	}

	Uci_Get_Str(PKG_SNMP_CONFIG, "general", "interface", interface);
	if(strstr(interface,"default")){
		Uci_Get_Str(PKG_NETWORK_CONFIG, "lan", "ipaddr",tmp_buff);
		sprintf(ipaddr, "%s", tmp_buff);
	}else if(strstr(interface,"br0")){
		Uci_Get_Str(PKG_NETWORK_CONFIG, "lan", "ipaddr",tmp_buff);
		sprintf(ipaddr, "%s", tmp_buff);
	}else if(strstr(interface,"eth2.2")){
		get_ifname_ipaddr("eth0.3", tmp_buff);
		sprintf(ipaddr, "%s", tmp_buff);
	}else if(strstr(interface,"mdoem")){+
		get_cmd_result("ubus call network.interface.wan_modem status | jsonfilter -e '@[\"ipv4-address\"][0].address'", tmp_buff,sizeof(tmp_buff));
		sprintf(ipaddr, "%s", tmp_buff);
	}

	Uci_Get_Str(PKG_SNMP_CONFIG, "general", "serverPort",tmp_buff);
	sprintf(agentAddress_buff, "agentAddress  udp:%s:%s\n", ipaddr,tmp_buff);
	fwrite(agentAddress_buff, 1, strlen(agentAddress_buff), fpp);
	fwrite("view all included .1\n", 1, strlen("view all included .1\n"), fpp);

	Uci_Get_Str(PKG_SNMP_CONFIG, "general", "community",tmp_buff);
	sprintf(community_buff, " rocommunity %s  default\n", tmp_buff);
	fwrite(community_buff, 1, strlen(community_buff), fpp);

	//createUser

	int idx=0;

	Uci_Get_Str(PKG_SNMP_CONFIG, "general", "snmpv3_num", iRulesNum);
	Uci_Get_Str(PKG_SNMP_CONFIG, "general", "rules", sRules);

	for (idx = 0; idx < atoi(iRulesNum);idx++){
		getNthValueSafe(idx, sRules, ' ', sRule, sizeof(sRule));

		if((getNthValueSafe(0, sRule, ',', mode, sizeof(mode)) == -1))
		{
				continue;
		}
		if((getNthValueSafe(1, sRule, ',', username, sizeof(username)) == -1))
		{
				continue;
		}
		if((getNthValueSafe(2, sRule, ',', password, sizeof(password)) == -1))
		{
				continue;
		}
		if((getNthValueSafe(3, sRule, ',', hash, sizeof(hash)) == -1))
		{
				continue;
		}
		if((getNthValueSafe(4, sRule, ',', encryption, sizeof(encryption)) == -1))
		{
				continue;
		}
		if((getNthValueSafe(5, sRule, ',', key, sizeof(key)) == -1))
		{
				continue;
		}

		if (atoi(mode) == 2){//NoAuthNoPriv
			sprintf(paramName, "rouser %s noauth\n", username);
			fwrite(paramName, 1, strlen(paramName), fpp);
			sprintf(paramName, "createUser %s\n", username);
			fwrite(paramName, 1, strlen(paramName), fpp);
		}else if(atoi(mode) == 1){//AuthNoPriv
			sprintf(paramName, "rouser %s\n auth", username);
			fwrite(paramName, 1, strlen(paramName), fpp);
			sprintf(paramName, "createUser %s %s %s\n", username,hash,password);
			fwrite(paramName, 1, strlen(paramName), fpp);
		}else if(atoi(mode) == 0){//AuthPriv
			sprintf(paramName, "rouser %s priv\n", username);
			fwrite(paramName, 1, strlen(paramName), fpp);
			sprintf(paramName, "createUser %s %s %s %s %s\n", username,hash,password,encryption,key);
			fwrite(paramName, 1, strlen(paramName), fpp);
		}
	}

	Uci_Get_Str(PKG_SNMP_CONFIG, "general", "trapIp",trapIp);
	Uci_Get_Str(PKG_SNMP_CONFIG, "general", "trapPort",trapPort);
	//trapd
	sprintf(trap_buff, "trapsink  %s:%s public\n", trapIp,trapPort);
	fwrite(trap_buff, 1, strlen(trap_buff), fpp);
	sprintf(trap_buff, "trap2sink  %s:%s public\n", trapIp,trapPort);
	fwrite(trap_buff, 1, strlen(trap_buff), fpp);

	fwrite("engineIDType 3\n", 1, strlen("engineIDType 3\n"), fpp);
	fwrite("engineIDNic eth0\n", 1, strlen("engineIDNic eth0\n"), fpp);
	fwrite("authtrapenable 1\n", 1, strlen("authtrapenable 1\n"), fpp);
//	fwrite("rwuser administrator\n", 1, strlen("rwuser administrator\n"), fpp);
	fwrite("iquerySecName administrator\n", 1, strlen("iquerySecName administrator\n"), fpp);
	fwrite("linkUpDownNotifications yes\n", 1, strlen("linkUpDownNotifications yes\n"), fpp);
	fwrite("defaultMonitors yes\n", 1, strlen("defaultMonitors yes\n"), fpp);

	fwrite("proc sendmail 10 1\n", 1, strlen("proc sendmail 10 1\n"), fpp);
	fwrite("disk / 100000\n", 1, strlen("disk / 100000\n"), fpp);
	fwrite("load 5 5 5\n", 1, strlen("load 5 5 5\n"), fpp);
	//#CPU usage
	fwrite("notificationEvent userCPU ssCpuRawUser\n", 1, strlen("notificationEvent userCPU ssCpuRawUser\n"), fpp);
	fwrite("notificationEvent sysCPU ssCpuRawSystem\n", 1, strlen("notificationEvent sysCPU ssCpuRawSystem\n"), fpp);
	fwrite("monitor -r 60 -e userCPU \"User CPU use percentage\" ssCpuRawUser > 100\n", 1, 
		strlen("monitor -r 60 -e userCPU \"User CPU use percentage\" ssCpuRawUser > 100\n"), fpp);
	fwrite("monitor -r 60 -e sysCPU \"System CPU use percentage\" ssCpuRawSystem > 100\n", 1, 
		strlen("monitor -r 60 -e sysCPU \"System CPU use percentage\" ssCpuRawSystem > 100\n"), fpp);
	//#Memory usage	
	fwrite("notificationEvent memTotalTrap memTotalReal memTotalSwap\n", 1, 
		strlen("notificationEvent memTotalTrap memTotalReal memTotalSwap\n"), fpp);
	fwrite("notificationEvent memAvailTrap memAvailReal memAvailSwap memTotalFree\n", 1, 
		strlen("notificationEvent memAvailTrap memAvailReal memAvailSwap memTotalFree\n"), fpp);
	fwrite("monitor -r 10 -e memTotalTrap \"Total memory\" memTotalReal < 1000000000000\n", 1, 
		strlen("monitor -r 10 -e memTotalTrap \"Total memory\" memTotalReal < 1000000000000\n"), fpp);
	fwrite("monitor -r 10 -e memAvailTrap \"Available memory\" memTotalFree < 1000000000000\n", 1, 
		strlen("monitor -r 10 -e memAvailTrap \"Available memory\" memTotalFree < 1000000000000\n"), fpp);

	fclose(fpp);
	return 0;
}

