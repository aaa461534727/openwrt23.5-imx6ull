#include "../defs.h"


CGI_BOOL setLanguageCfg(json_object *request, FILE *conn_fp)
{
	const char *lang = webs_get_string(request,"lang");
	const char *langAutoFlag = webs_get_string(request,"langAutoFlag");
	int autoflag = 0;

	Uci_Set_Str(PKG_SYSTEM_CONFIG, "main", "lang_type", lang);

	Uci_Get_Int(PKG_SYSTEM_CONFIG, "main", "lang_auto_flag", &autoflag);
	if(atoi(langAutoFlag) != autoflag){
		Uci_Set_Str(PKG_SYSTEM_CONFIG, "main", "lang_auto_flag", langAutoFlag);
	}
	Uci_Commit(PKG_SYSTEM_CONFIG);
		
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");
	
	return CGI_TRUE;
}

int opmodeWebToSys(char *input, char *ouput)
{
	int mode=atoi(input);
	if(mode == 0)
		sprintf(ouput,"%s", "br");
	else if(mode == 1)
		sprintf(ouput,"%d", "gw");
	else if(mode == 2)
		sprintf(ouput,"%d", "rpt");
	else if(mode == 3)
		sprintf(ouput,"%d", "wisp");
	else
		sprintf(ouput,"%d", "gw");

	return 0;
}

CGI_BOOL set_repeater_info(cJSON *request)
{
	int  wifi_idx,wl_radio;

	char *ptr;

	char apcli_radio[16]={0}, opmode[8]={0};

	char *opmode_custom = webs_get_string(request, "opmode");
	
	char *ssid     = webs_get_string(request, "ssid_rpt");
	char *bssid    = webs_get_string(request, "bssid_rpt");
	char *channel  = webs_get_string(request, "channel_rpt");
	char *encrypt  = webs_get_string(request, "encrypt_rpt");
	char *cipher   = webs_get_string(request, "cipher_rpt");
	char *password = webs_get_string(request, "password_rpt");
	
	opmodeWebToSys(opmode_custom, opmode);
	if(0 != strcmp(opmode, "rpt") && 0 != strcmp(opmode, "wisp")){
		wificonf_set_by_key(WLAN_APCLI,"disabled","1");
		Uci_Commit(PKG_WIRELESS_CONFIG);
		return CGI_TRUE;
	}

	wifi_idx = atoi(webs_get_string(request, "wifiIdx_rpt"));

	if(0 == wifi_idx) {
		wl_radio=W24G_RADIO;
	} else {
		wl_radio=W58G_RADIO;
	}

	strcpy(apcli_radio,WL_IF[wl_radio].section_name);

	wificonf_set_by_key(WLAN_APCLI,"device",apcli_radio);
	wificonf_set_by_key(WLAN_APCLI,"disabled","0");
	wificonf_set_by_key(WLAN_APCLI,"ssid",ssid);
	wificonf_set_by_key(WLAN_APCLI,"bssid",bssid);
	wificonf_set_by_key(WLAN_APCLI,"channel",channel);

	wificonf_set_by_key(wl_radio,"channel",channel);

	if(!strcmp(encrypt, "NONE") || !strcmp(encrypt, "OPEN")) {
		wificonf_set_by_key(WLAN_APCLI,"encryption","none");
		wificonf_set_by_key(WLAN_APCLI,"key","");
	} else {
		if(!strcmp(encrypt, "WPAPSK")|| !strcmp(encrypt, "WPAPSKWPA2PSK")) {
			wificonf_set_by_key(WLAN_APCLI,"encryption","psk2");
		} else {
			wificonf_set_by_key(WLAN_APCLI,"encryption","psk2");
		}

		wificonf_set_by_key(WLAN_APCLI,"key",password);
	}
	Uci_Commit(PKG_WIRELESS_CONFIG);

	return CGI_TRUE;
}

CGI_BOOL setOpModeCfg(json_object *request, FILE *conn_fp)
{
	char *ptr = NULL;

	char old_opmode_custom[SHORT_STR_LEN] = {0},opmode[8]={0};

	char *opmode_custom = webs_get_string(request, "operationMode");
	
	opmodeWebToSys(opmode_custom, opmode);
	
		
	Uci_Get_Str(PKG_SYSTEM_CONFIG,"opmode","opmode_custom",old_opmode_custom);

	Uci_Set_Str(PKG_SYSTEM_CONFIG,"opmode","opmode_custom",opmode);

	if(!strcmp(opmode, "br")) 
	{
		Uci_Set_Str(PKG_NETWORK_CONFIG,"wan","ifname","");
		Uci_Set_Str(PKG_NETWORK_CONFIG,"lan","ifname","usbnet0 eth0.1 eth0.2");

		Uci_Set_Str(PKG_NETWORK_CONFIG,"lan","proto","dhcp");
		Uci_Set_Str(PKG_DHCP_CONFIG,"lan","ignore","1");
		Uci_Set_Str(PKG_DHCP_CONFIG,"dnsmasq","disabled","1");
		Uci_Set_Str(PKG_NETWORK_CONFIG, "vpn", "proto", "");
	} 
	else if(!strcmp(opmode, "rpt"))
	{
		Uci_Set_Str(PKG_NETWORK_CONFIG,"wan","ifname","");
		Uci_Set_Str(PKG_NETWORK_CONFIG,"lan","ifname","usbnet0 eth0.1 eth0.2");

		Uci_Set_Str(PKG_NETWORK_CONFIG,"stabridge","proto","relay");
		Uci_Set_Str(PKG_NETWORK_CONFIG,"stabridge","network","lan wwan");
		Uci_Set_Str(PKG_NETWORK_CONFIG, "wwan", "proto", "dhcp");

		Uci_Set_Str(PKG_NETWORK_CONFIG,"lan","proto","static");
		Uci_Set_Str(PKG_DHCP_CONFIG,"lan","ignore","1");
		Uci_Set_Str(PKG_DHCP_CONFIG,"dnsmasq","disabled","1");
		Uci_Set_Str(PKG_NETWORK_CONFIG, "vpn", "proto", "");

		Uci_Set_Str(PKG_WIRELESS_CONFIG,"schedule","enable","0");
	} 
	else if(!strcmp(opmode, "wisp"))
	{
		Uci_Set_Str(PKG_NETWORK_CONFIG,"wan","proto","static");
		Uci_Set_Str(PKG_NETWORK_CONFIG,"wan","ifname","eth0.2");
		Uci_Set_Str(PKG_NETWORK_CONFIG,"lan","ifname","usbnet0 eth0.1 eth0.2");

		Uci_Set_Str(PKG_NETWORK_CONFIG,"lan","proto","static");
		Uci_Set_Str(PKG_DHCP_CONFIG,"lan","ignore","0");
		Uci_Set_Str(PKG_DHCP_CONFIG,"dnsmasq","disabled","0");

		Uci_Set_Str(PKG_WIRELESS_CONFIG,"schedule","enable","0");

		Uci_Set_Str(PKG_NETWORK_CONFIG,"stabridge","proto","");
		Uci_Set_Str(PKG_NETWORK_CONFIG,"stabridge","network","");

		Uci_Set_Str(PKG_NETWORK_CONFIG, "vpn", "proto", "");

		if(0 != strcmp(old_opmode_custom, opmode)) {
			Uci_Set_Str(PKG_NETWORK_CONFIG, "wwan", "proto", "dhcp");
			Uci_Set_Str(PKG_NETWORK_CONFIG, "wwan", "mtu", "1500");
		}
	}
	else 
	{//gw
		Uci_Set_Str(PKG_NETWORK_CONFIG,"wan","ifname","eth0.2");
		Uci_Set_Str(PKG_NETWORK_CONFIG,"lan","ifname","usbnet0 hsicnet0 eth0");

		Uci_Set_Str(PKG_NETWORK_CONFIG, "wan", "proto", "dhcp");
		Uci_Set_Str(PKG_NETWORK_CONFIG, "wan", "mtu", "1500");

		Uci_Set_Str(PKG_NETWORK_CONFIG, "lan","proto","static");
		Uci_Set_Str(PKG_NETWORK_CONFIG, "lan", "dns", "");

		Uci_Set_Str(PKG_DHCP_CONFIG,"lan","ignore","0");
		Uci_Set_Str(PKG_DHCP_CONFIG,"dnsmasq","disabled","0");
	}

	if(0 == strcmp(opmode, "gw") || 0 == strcmp(opmode, "wisp")){
		setWanCfg(request, conn_fp);
	}

	//set_repeater_info(request);

end_label:

	Uci_Commit(PKG_NETWORK_CONFIG);
	Uci_Commit(PKG_DHCP_CONFIG);
	Uci_Commit(PKG_SYSTEM_CONFIG);
	Uci_Commit(PKG_WANDUCK_CONFIG);
	Uci_Commit(PKG_WIRELESS_CONFIG);

	set_lktos_effect("network");

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "15", "reLogin");

	return CGI_TRUE;
}

int setTelnetCfg(json_object *request, FILE *conn_fp)
{
	char *enable = webs_get_string(request, "telnet_enabled");

	if(atoi(enable)==0){
		CsteSystem("killall -q telnetd", CSTE_PRINT_CMD);
		Uci_Set_Str(PKG_SYSTEM_CONFIG,"telnetd","enable",enable);
		Uci_Commit(PKG_SYSTEM_CONFIG);
	}else if(atoi(enable)==1){
		CsteSystem("echo '1' > /var/lock/tlt.lock", 0);
		CsteSystem("telnetd -l /bin/login &", CSTE_PRINT_CMD);
		Uci_Set_Str(PKG_SYSTEM_CONFIG,"telnetd","enable",enable);
		Uci_Commit(PKG_SYSTEM_CONFIG);
	}

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

	return CGI_TRUE;

}

CGI_BOOL setLedCfg(json_object *request, FILE *conn_fp)
{
	char *enable;
	int i_enable;

	enable = webs_get_string(request, "enable");
	i_enable=atoi(enable);

	if(strlen(enable)> 0 && (i_enable==0 || i_enable==1)){
		Uci_Set_Str(PKG_SYSTEM_CONFIG,"main","led_status", enable);

		Uci_Commit(PKG_SYSTEM_CONFIG);

		set_led_status(i_enable);
	}

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

	return CGI_TRUE;
}

CGI_BOOL setUpgradeFW(json_object *request, FILE *conn_fp)
{
	char wtime[8] = {0}, lan_ip[18] = {0};

	//const char *is_reset = webs_get_string(request,"resetFlags");
	const char *is_reset = webs_get_string(request,"Flags");
	const char *is_cloud = webs_get_string(request,"cloudFlag");

	
	datconf_set_by_key(TEMP_STATUS_FILE, "ugrade_reset", is_reset);

	if (0 == atoi(is_cloud))
	{
		snprintf(wtime, sizeof(wtime), "%d", 100);
	}
	else
	{
		snprintf(wtime, sizeof(wtime), "%d", 130);
	}

	if (1 == atoi(is_reset)){
		Uci_Get_Str(PKG_NETWORK_CONFIG,"lan","ipaddr",lan_ip);
	}else{
		get_ifname_ipaddr("br-lan", lan_ip);
	}

	set_lktos_effect("fwupgrade");

	send_cgi_set_respond(conn_fp, TRUE_W, "", lan_ip, wtime, "reserv");

	return CGI_TRUE;
}


CGI_BOOL setUploadSetting(json_object *request, FILE *conn_fp)
{
	long con_len;

	cJSON *root;

	char  cmd[256]={0},key[32]={0};

	const char *file_name = webs_get_string(request,"file_name");
	const char *content_length = webs_get_string(request,"content_length");

	const char *cfg_file="/tmp/upgcfg.tar.gz";

	root=cJSON_CreateObject();

	con_len = strtol(content_length, NULL, 10) +1;
	if(con_len < 1000){
		cJSON_AddStringToObject(root, "settingERR","MSG_config_error");
		goto err;
	}

	memset(cmd,0,sizeof(cmd));
	snprintf(cmd,sizeof(cmd),"rm -f %s >/dev/null 2>&1", cfg_file);
	CsteSystem(cmd,0);
	
	Uci_Get_Str(PKG_PRODUCT_CONFIG,"custom","csid",key);
#if defined(CONFIG_CS_COMMON_SSL)
	char input[30720]={0}, output[30720]={0};
	int len=0, size=0;
	
	len=f_read(file_name, input, sizeof(input));
	size =aes_decrypt_pkcs5pading(input, len, key, (unsigned char *)SSL_IV, \
		output, sizeof(output));
	
	f_write(cfg_file, output, size, 0, 0);
#else
	if(f_exists("/usr/bin/openssl")){
		memset(cmd,0,sizeof(cmd));
		snprintf(cmd,sizeof(cmd),"/usr/bin/openssl des3 -d -k %s -salt -in %s -out %s >/dev/null 2>/tmp/sslrst", key, file_name, cfg_file);
		CsteSystem(cmd,0);

		if(f_size("/tmp/sslrst")>0)
		{
			cJSON_AddStringToObject(root, "settingERR","MSG_config_error");

			goto err;
		}
	}
	else{
		doSystem("mv %s %s",file_name, cfg_file);
	}
#endif
	datconf_set_by_key(TEMP_STATUS_FILE, "upload_settings_path", cfg_file);

	cJSON_AddStringToObject(root, "settingERR","1");

	set_lktos_effect("uploadsetting");

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;

err:
	unlink(file_name);

	send_cgi_json_respond(conn_fp, root);

	return 0;

}

CGI_BOOL getSmartQosCfg(json_object *request, FILE *conn_fp)
{
	int i = 0, num = 0;

	char rules[LIST_STR_LEN] = {0},rule[TEMP_STR_LEN] = {0},del_rule[SHORT_STR_LEN] = {0};
	char enable [SHORT_STR_LEN]={0}, default_bw[SHORT_STR_LEN],upbw[SHORT_STR_LEN]={0},downbw[SHORT_STR_LEN]={0};
	char ip[RESULT_STR_LEN] = {0},max_up[SMALL_STR_LEN] = {0},max_down[SMALL_STR_LEN] = {0};

	cJSON *root, *conn_array,*conn_entry;

	root = cJSON_CreateObject();
	conn_array = cJSON_CreateArray();
	cJSON_AddItemToObject(root,"qos_rules",conn_array);

	Uci_Get_Str(PKG_QOS_CONFIG,"smartqos","enable",enable);
	Uci_Get_Str(PKG_QOS_CONFIG,"smartqos","upbw",upbw);
	Uci_Get_Str(PKG_QOS_CONFIG,"smartqos","downbw",downbw);
	Uci_Get_Str(PKG_QOS_CONFIG,"smartqos","default_bw",default_bw);

	cJSON_AddStringToObject(root,"qos_enable",enable);
	cJSON_AddStringToObject(root,"qos_up_bw",upbw);
	cJSON_AddStringToObject(root,"qos_down_bw",downbw);
	cJSON_AddStringToObject(root,"bandWidth",default_bw);

	Uci_Get_Str(PKG_QOS_CONFIG, "iplimit", "rules", rules);
	Uci_Get_Int(PKG_QOS_CONFIG, "iplimit", "num", &num);

	for(i=0;i<num;i++)
	{
		get_nth_val_safe(i, rules, ' ', rule, sizeof(rule));

		if((get_nth_val_safe(0, rule, ',', ip, sizeof(ip)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(1, rule, ',', max_up, sizeof(max_up)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(2, rule, ',', max_down, sizeof(max_down)) == -1))
		{
			continue;
		}

		snprintf(del_rule,sizeof(del_rule),"delRule%d",i);

		conn_entry = cJSON_CreateObject();
		cJSON_AddNumberToObject(conn_entry,"idx",(i+1));
		cJSON_AddStringToObject(conn_entry,"ip",ip);
		cJSON_AddStringToObject(conn_entry,"maxDownload",max_down);
		cJSON_AddStringToObject(conn_entry,"maxUpload",  max_up);
		cJSON_AddStringToObject(conn_entry,"delRuleName",del_rule);
		cJSON_AddItemToArray(conn_array,conn_entry);

		memset(ip,0,sizeof(ip));
		memset(del_rule,0,sizeof(del_rule));
		memset(max_down,0,sizeof(max_down));
		memset(max_up,0,  sizeof(max_up));
	}

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}

CGI_BOOL setSmartQosCfg(json_object *request, FILE *conn_fp)
{
	int rule_num = 0;
	char sRulesNum[4] = {0},ipLimitRules[LIST_STR_LEN] = {0};
	char *addEffect = webs_get_string(request, "addEffect");
	char *qos_enable = webs_get_string(request, "qos_enable");

	if(atoi(addEffect) == 0 && atoi(qos_enable) == 1)
	{
		Uci_Set_Str(PKG_QOS_CONFIG,"smartqos","enable","1");
	}
	else if(atoi(addEffect) == 0 && atoi(qos_enable) == 0)
	{
		Uci_Set_Str(PKG_QOS_CONFIG,"smartqos","enable","0");
	}

	if(atoi(addEffect) == 3)//network upbw and downbw
	{
		char *qos_up_bw = webs_get_string(request, "qos_up_bw");
		char *qos_down_bw = webs_get_string(request, "qos_down_bw");

		Uci_Set_Str(PKG_QOS_CONFIG, "smartqos", "upbw", qos_up_bw);
		Uci_Set_Str(PKG_QOS_CONFIG, "smartqos", "downbw", qos_down_bw);
	}
	else if(atoi(addEffect) == 1 || atoi(addEffect) == 2)//iplimit rule; 1:add , 2: modify
	{
		char *qos_ip = webs_get_string(request, "ip");
		char *qos_mac = webs_get_string(request, "mac");
		char *maxUpload = webs_get_string(request, "maxUpload");
		char *maxDownload = webs_get_string(request, "maxDownload");

		if(atoi(addEffect) == 1 )
		{
			if(strlen(qos_mac) > 0)
			{
				str_del_char_bak(qos_mac,':');
				snprintf(ipLimitRules, sizeof(ipLimitRules), "%s,%d,%d,%d,%s", qos_ip, atoi(maxUpload), atoi(maxDownload), 6, qos_mac);
			}
			else
			{
				snprintf(ipLimitRules, sizeof(ipLimitRules), "%s,%d,%d,%d,%s", qos_ip, atoi(maxUpload), atoi(maxDownload), 6, "000000000000");
			}
		}

		if(atoi(addEffect) == 1)
		{
			Uci_Get_Int(PKG_QOS_CONFIG, "iplimit", "num", &rule_num);
			if (rule_num>FILTER_RULE_NUM)
			{
				return CGI_FALSE;
			}

			if( strlen(maxUpload) > 0 && strlen(maxDownload) > 0 )
			{
				Uci_Add_List(PKG_QOS_CONFIG, "iplimit", "rules", ipLimitRules);
				rule_num++;
				sprintf(sRulesNum, "%d", rule_num);
				Uci_Set_Str(PKG_QOS_CONFIG, "iplimit", "num", sRulesNum);
			}
		}
		else
		{
			int i = 0, j = 0;
			char sRules[4096] = {0},Rules[4096] = {0},rulesNum[8] = {0},SaveRules[FILTER_RULE_NUM][256] = {0};
			char mac[32]={0};
			char *idx=webs_get_string(request, "idx");

			Uci_Get_Str(PKG_QOS_CONFIG, "iplimit", "rules", sRules);
			Uci_Get_Str(PKG_QOS_CONFIG,"iplimit","num",rulesNum);
			
			get_nth_val_safe(atoi(idx)-1, sRules, ' ', Rules, sizeof(Rules));
			get_nth_val_safe(4, Rules, ',', mac, sizeof(mac));

			for(i=atoi(idx),j=0;i<atoi(rulesNum);i++)
			{
				get_nth_val_safe(i, sRules, ' ', SaveRules[j], sizeof(SaveRules[j]));
				Uci_Del_List(PKG_QOS_CONFIG, "iplimit", "rules", SaveRules[j]);
				j++;
			}
			Uci_Del_List(PKG_QOS_CONFIG, "iplimit", "rules", Rules);
			snprintf(ipLimitRules, sizeof(ipLimitRules), "%s,%d,%d,%d,%s",  
				qos_ip, atoi(maxUpload), atoi(maxDownload), 6, mac);
			Uci_Add_List(PKG_QOS_CONFIG, "iplimit", "rules", ipLimitRules);

			for(i=atoi(idx),j=0;i<atoi(rulesNum);i++)
			{
				Uci_Add_List(PKG_QOS_CONFIG, "iplimit", "rules", SaveRules[j]);
				j++;
			}
		}
	}

	Uci_Commit(PKG_QOS_CONFIG);

	set_lktos_effect("firewall");

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

	return CGI_TRUE;
}


CGI_BOOL delSmartQosCfg(json_object *request, FILE *conn_fp)
{
	int i=0, num=0, count=0;

	char tmp_buf[8]={0};

	char rules[4096]={0}, rule[128]={0}, name_buf[16]={0};

	char *value;

	Uci_Get_Int(PKG_QOS_CONFIG, "iplimit", "num", &num);

	count=num;

	Uci_Get_Str(PKG_QOS_CONFIG,"iplimit","rules",rules);

	for(i=0; i< num; i++){
		snprintf(name_buf,sizeof(name_buf),"delRule%d",i);
		value = webs_get_string(request, name_buf);

		if(strlen(value) > 0){
			get_nth_val_safe(atoi(value), rules, ' ', rule, sizeof(rule));
			Uci_Del_List(PKG_QOS_CONFIG, "iplimit", "rules", rule);
			count--;
		}

	}

	snprintf(tmp_buf,sizeof(tmp_buf), "%d", count);
	Uci_Set_Str(PKG_QOS_CONFIG, "iplimit", "num", tmp_buf);
	
	Uci_Commit(PKG_QOS_CONFIG);

	set_lktos_effect("firewall");

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

	return CGI_TRUE;
}

#if defined(CONFIG_TR069_SUPPORT)
CGI_BOOL getTr069Cfg(json_object *request, FILE *conn_fp)
{
	cJSON *root;
	root=cJSON_CreateObject();

	get_uci2json(root, PKG_ICWMP_CONFIG, "acs", "userid", "user");
	get_uci2json(root, PKG_ICWMP_CONFIG, "acs", "passwd", "pass");
	get_uci2json(root, PKG_ICWMP_CONFIG, "acs", "periodic_inform_enable",   "informEnable");
	get_uci2json(root, PKG_ICWMP_CONFIG, "acs", "periodic_inform_interval", "interval");
	get_uci2json(root, PKG_ICWMP_CONFIG, "acs", "url", "url");

	get_num_uci2json(root, PKG_ICWMP_CONFIG, "acs", "enable", "enable");
	get_uci2json(root, PKG_ICWMP_CONFIG, "cpe", "userid", "requestUser");
	get_uci2json(root, PKG_ICWMP_CONFIG, "cpe", "passwd", "requestPass");
	get_uci2json(root, PKG_ICWMP_CONFIG, "cpe", "path", "path");
	get_uci2json(root, PKG_ICWMP_CONFIG, "cpe", "port", "port");

	get_uci2json(root, PKG_STUN_CONFIG, "stun", "enable",         "stunEnable");
	get_uci2json(root, PKG_STUN_CONFIG, "stun", "server_address", "stunServerAddr");
	get_uci2json(root, PKG_STUN_CONFIG, "stun", "server_port",    "stunPort");
	get_uci2json(root, PKG_STUN_CONFIG, "stun", "max_keepalive",  "stunMaxAlive");
	get_uci2json(root, PKG_STUN_CONFIG, "stun", "min_keepalive",   "stunMinAlive");

	cJSON_AddStringToObject(root,"acs","1");
	cJSON_AddStringToObject(root,"request","1");

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}

CGI_BOOL setTr069Cfg(json_object *request, FILE *conn_fp)
{
	char *add_effect = webs_get_string(request, "addEffect");

	char *enable = webs_get_string(request, "enable");

	if(atoi(add_effect))
	{
		Uci_Set_Str(PKG_ICWMP_CONFIG, "acs", "enable", enable);
		Uci_Set_Str(PKG_ICWMP_CONFIG, "cpe", "enable", enable);
		if(atoi(enable) == 0)
		{
			Uci_Set_Str(PKG_STUN_CONFIG, "stun", "enable", enable);
		}
	}
	else {
		//acs
		char *url = webs_get_string(request,  "url");
		char *user = webs_get_string(request, "user");
		char *pass = webs_get_string(request, "pass");
		char *informEnable = webs_get_string(request, "informEnable");
		char *interval = webs_get_string(request, "interval");
		Uci_Set_Str(PKG_ICWMP_CONFIG, "acs", "periodic_inform_enable", informEnable);
		Uci_Set_Str(PKG_ICWMP_CONFIG, "acs", "periodic_inform_interval", interval);
		Uci_Set_Str(PKG_ICWMP_CONFIG, "acs", "userid", user);
		Uci_Set_Str(PKG_ICWMP_CONFIG, "acs", "passwd", pass);
		Uci_Set_Str(PKG_ICWMP_CONFIG, "acs", "url", url);
		Uci_Set_Str(PKG_ICWMP_CONFIG, "acs", "enable", enable);

		//cpe
		char *requestUser = webs_get_string(request, "requestUser");
		char *requestPass = webs_get_string(request, "requestPass");
		char *path = webs_get_string(request, "path");
		char *port = webs_get_string(request, "port");

		Uci_Set_Str(PKG_ICWMP_CONFIG, "cpe", "enable", enable);
		Uci_Set_Str(PKG_ICWMP_CONFIG, "cpe", "userid", requestUser);
		Uci_Set_Str(PKG_ICWMP_CONFIG, "cpe", "passwd", requestPass);
		Uci_Set_Str(PKG_ICWMP_CONFIG, "cpe", "path", path);
		Uci_Set_Str(PKG_ICWMP_CONFIG, "cpe", "port", port);

		//stun
		char *stun_enable = webs_get_string(request, "stunEnable");
		char *stun_serverAddr = webs_get_string(request, "stunServerAddr");
		char *stun_port = webs_get_string(request, "stunPort");
		char *stun_max_alive = webs_get_string(request, "stunMaxAlive");
		char *stun_min_alive = webs_get_string(request, "stunMinAlive");

		Uci_Set_Str(PKG_STUN_CONFIG, "stun", "enable",         stun_enable);
		Uci_Set_Str(PKG_STUN_CONFIG, "stun", "server_address", stun_serverAddr);
		Uci_Set_Str(PKG_STUN_CONFIG, "stun", "server_port",    stun_port);
		Uci_Set_Str(PKG_STUN_CONFIG, "stun", "max_keepalive",  stun_max_alive);
		Uci_Set_Str(PKG_STUN_CONFIG, "stun", "min_keepalive",  stun_min_alive);
	}
	Uci_Commit(PKG_ICWMP_CONFIG);
	Uci_Commit(PKG_STUN_CONFIG);

	CsteSystem("rm -f /tmp/cste/stun", CSTE_PRINT_CMD);
	CsteSystem("/etc/init.d/cwmp restart", CSTE_PRINT_CMD);
	CsteSystem("/etc/init.d/stund restart", CSTE_PRINT_CMD);

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

	return CGI_TRUE;
}
#endif

#if defined(CONFIG_DDNS_SUPPORT)
CGI_BOOL setDdnsCfg(json_object *request, FILE *conn_fp)
{
	char cmd[CMD_STR_LEN] = {0};
    char * enable = webs_get_string(request, "ddnsEnabled");
    char * ddns_provider = webs_get_string(request, "ddnsProvider");
    char * ddns_domain   = webs_get_string(request, "ddnsDomain");
    char * ddns_acc      = webs_get_string(request, "ddnsAccount");
    char * ddns_pass     = webs_get_string(request, "ddnsPassword");

    if(!strncmp(enable, "1", 2))
	{
		Uci_Set_Str(PKG_DDNS_CONFIG,"wan","enable", "1");
		Uci_Set_Str(PKG_DDNS_CONFIG,"wan","provider", ddns_provider);

		if (!strcmp(ddns_provider, "oray.com"))
		{
			Uci_Set_Str(PKG_DDNS_CONFIG,"wan","account", ddns_acc);
			Uci_Set_Str(PKG_DDNS_CONFIG,"wan","password", ddns_pass);
			Uci_Set_Str(PKG_DDNS_CONFIG,"wan","domain", "");
		}
		else
        {
			Uci_Set_Str(PKG_DDNS_CONFIG,"wan","account", ddns_acc);
			Uci_Set_Str(PKG_DDNS_CONFIG,"wan","password", ddns_pass);
			Uci_Set_Str(PKG_DDNS_CONFIG,"wan","domain", ddns_domain);
		}
	}
	else
	{
		Uci_Set_Str(PKG_DDNS_CONFIG,"wan","enable", "0");
	}

	datconf_set_by_key(TEMP_STATUS_FILE, "ddns_link", "0");
	datconf_set_by_key(TEMP_STATUS_FILE, "ddns_bind_ip", "0.0.0.0");

	Uci_Commit(PKG_DDNS_CONFIG);

	set_lktos_effect("ddns");

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

	return CGI_TRUE;
}
#endif

#if defined (CONFIG_DTU_SUPPORT)
CGI_BOOL setDtuCfg(json_object *request, FILE *conn_fp)
{
	char *lan_ip = webs_get_string(request, "lan_ipaddr"); 
	char *enable = webs_get_string(request, "enable");
	
	if(atoi(enable) == 1){
		const char *mode = webs_get_string(request, "mode");
		const char *localPort = webs_get_string(request, "localPort");
		const char *protocol = webs_get_string(request, "protocol");
		const char *serialPacketMaxLength = webs_get_string(request, "serialPacketMaxLength");
		const char *channelType = webs_get_string(request, "channelType");
		const char *netReceiveTimeout = webs_get_string(request, "netReceiveTimeout");
		const char *serialReceiveTimeout = webs_get_string(request, "serialReceiveTimeout");
		const char *encryption = webs_get_string(request, "encryption");
		const char *key = webs_get_string(request, "key");
		const char *serverIp1 = webs_get_string(request, "serverIp1");
		const char *serverPort1 = webs_get_string(request, "serverPort1");
		const char *serverIp2 = webs_get_string(request, "serverIp2");
		const char *serverPort2 = webs_get_string(request, "serverPort2");
		const char *serverIp3 = webs_get_string(request, "serverIp3");
		const char *serverPort3 = webs_get_string(request, "serverPort3");
		const char *serverIp4 = webs_get_string(request, "serverIp4");
		const char *serverPort4 = webs_get_string(request, "serverPort4");
		const char *reTryInterval = webs_get_string(request, "reTryInterval");
		const char *reTryCount = webs_get_string(request, "reTryCount");
		const char *registMsg = webs_get_string(request, "registMsg");
		const char *heartBeatInterval = webs_get_string(request, "heartBeatInterval");
		const char *heartBeatData = webs_get_string(request, "heartBeatData");
		const char *rate = webs_get_string(request, "rate");
		const char *parity = webs_get_string(request, "parity");
		const char *dataBit = webs_get_string(request, "dataBit");
		const char *stopBit = webs_get_string(request, "stopBit");
		const char *flowControl = webs_get_string(request, "flowControl");
		const char *type = webs_get_string(request, "type");
		const char *isModbus = webs_get_string(request, "isModbus");

		Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_enable", enable);
		Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_mode", mode);
		Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_local_port", localPort);
		Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_protocol", protocol);
		if(strcmp(protocol, "udp") == 0) {
			Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_serial_packet_max_length", serialPacketMaxLength);
		} else {
			Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_serial_packet_max_length", "");
		}
		
		Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_channel_type", channelType);
		Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_net_receive_timeout", netReceiveTimeout);
		Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_serial_receive_timeout", serialReceiveTimeout);
		Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_encryption", encryption);
		
		if(strcmp(encryption, "aes") == 0) {
			Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_key", key);
		} else {
			Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_key", "");
		}
		
		Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_server_ipaddr_1", serverIp1);
		Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_server_port_1", serverPort1);
		Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_server_ipaddr_2", serverIp2);
		Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_server_port_2", serverPort2);
		Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_server_ipaddr_3", serverIp3);
		Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_server_port_3", serverPort3);
		Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_server_ipaddr_4", serverIp4);
		Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_server_port_4", serverPort4);
		Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_interval", reTryInterval);
		Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_retry", reTryCount);
		Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_regdata", registMsg);
		Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_heartbeat_time", heartBeatInterval);
		Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_heartbeat_data", heartBeatData);
		Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_serial_baud_rate", rate);
		Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_serial_prity", parity);
		Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_serial_data_bits", dataBit);
		Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_serial_stop_bits", stopBit);
		Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_serial_flow_control", flowControl);
		Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_serial_type", type);
	}
	else{
		Uci_Set_Str(PKG_DTU_CONFIG,"dtu_ctrl","dtu_enable", "0");
	}
	Uci_Commit(PKG_DTU_CONFIG);

	
	system("/etc/init.d/dtu_ctrl stop");	
	if(enable)
		system("/etc/init.d/dtu_ctrl start");	
	
	
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

	return CGI_TRUE;
}


#endif

CGI_BOOL setVrrpCfg(json_object *request, FILE *conn_fp)
{
	char *enabled = webs_get_string(request, "enabled");
	char *interface = webs_get_string(request, "vrInterface");
	char *ip = webs_get_string(request, "virtualIp");
	char *id = webs_get_string(request, "virtualId");
	char *priority = webs_get_string(request, "priority");
	char *timers = webs_get_string(request, "noticeTimers");
	char lan_ifname[16]={0};
	
	Uci_Set_Str(PKG_VRRPD_CONFIG, "vrrpd", "vrrp_enable", enabled);
	if(atoi(enabled) == 1)
	{
		if(strcmp(interface,"br0")==0)
		{
			Uci_Get_Str(PKG_NETWORK_CONFIG, "lan", "device", lan_ifname);
			Uci_Set_Str(PKG_VRRPD_CONFIG, "vrrpd", "vrrp_interface", lan_ifname);
		}else
		{	
			Uci_Set_Str(PKG_VRRPD_CONFIG, "vrrpd", "vrrp_interface", interface);
		}
		Uci_Set_Str(PKG_VRRPD_CONFIG, "vrrpd", "vrrp_virtual_ip", ip);
		Uci_Set_Str(PKG_VRRPD_CONFIG, "vrrpd", "vrrp_virtual_id", id);
		Uci_Set_Str(PKG_VRRPD_CONFIG, "vrrpd", "vrrp_priority", priority);
		Uci_Set_Str(PKG_VRRPD_CONFIG, "vrrpd", "vrrp_notice_timers", timers);
	}

	Uci_Commit(PKG_VRRPD_CONFIG);

	system("/etc/init.d/cs_vrrpd stop");	
	if(enabled)
		system("/etc/init.d/cs_vrrpd start");
	
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "15", "reserv");
	return CGI_TRUE;

}


#if defined(CONFIG_USER_FAST_NAT)
CGI_BOOL setHwNatCfg(json_object *request, FILE *conn_fp)
{
	char *enable;
	int i_enable,old_enable;

	enable = webs_get_string(request, "hwNatEnable");
	i_enable=atoi(enable);

	Uci_Get_Int(PKG_CSFW_CONFIG,"firewall","hwnat_enable", &old_enable);

	if(strlen(enable)> 0 && (i_enable ==0 || i_enable ==1) && (i_enable!=old_enable))
	{
		Uci_Set_Str(PKG_CSFW_CONFIG,"firewall","hwnat_enable", enable);
		Uci_Set_Str(PKG_QOS_CONFIG,"smartqos","enable","0");
		
		Uci_Commit(PKG_CSFW_CONFIG);
		set_lktos_effect("hw_nat");
		set_lktos_effect("firewall");
	}

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

	return CGI_TRUE;
}
#endif


//#if defined(CONFIG_APP_TCPDUMP)
CGI_BOOL setTcpdumpPackCfg(json_object *request, FILE *conn_fp)
{
	struct interface_status status_paremeter;
	
	char *enable = webs_get_string(request, "enabled"); 
	char *iface = webs_get_string(request, "iface");
	char *file_size = webs_get_string(request, "fileSize");

	Uci_Set_Str(PKG_SYSTEM_CONFIG,"tcpdump","enable", enable);
	

	if(atoi(enable) == 1){
		Uci_Set_Str(PKG_SYSTEM_CONFIG, "tcpdump", "packsize", file_size);
		Uci_Set_Str(PKG_SYSTEM_CONFIG, "tcpdump", "ifname", iface);

		if(!is_interface_up(iface)){
			datconf_set_by_key(TEMP_STATUS_FILE, "tcpdump_status", "ifaceError");
		}else{
			datconf_set_by_key(TEMP_STATUS_FILE, "tcpdump_ifname", iface);
			datconf_set_by_key(TEMP_STATUS_FILE, "tcpdump_status", "start");
		}

	}
	else{
		datconf_set_by_key(TEMP_STATUS_FILE,"tcpdump_status","");
	}

	Uci_Commit(PKG_SYSTEM_CONFIG);
	
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

	return CGI_TRUE;
}
//#endif

CGI_BOOL setDebugLog(json_object *request, FILE *conn_fp)
{
	char *debugMode,*lteDial,*lteRsrp,*lteCsq,*lteCheck,*wanDial,*iotLog,*tntLog,*openvpnLog;

	debugMode = webs_get_string(request, "debugMode");
	Uci_Set_Str(PKG_SYSTEM_CONFIG, "debuglog", "debug_mode", debugMode);
	
	if(atoi(debugMode) != DEBUG_LOG_CLOSE){
		lteDial = webs_get_string(request, "lteDial");
		lteRsrp = webs_get_string(request, "lteRsrp");
		lteCsq = webs_get_string(request, "lteCsq");
		lteCheck = webs_get_string(request, "lteCheck");
		wanDial = webs_get_string(request, "wanDial");
		iotLog = webs_get_string(request, "iotLog");
		tntLog = webs_get_string(request, "tntLog");
		openvpnLog = webs_get_string(request, "openvpnLog");

		Uci_Set_Str(PKG_SYSTEM_CONFIG, "debuglog", "lte_dial", lteDial);
		
		Uci_Set_Str(PKG_SYSTEM_CONFIG, "debuglog", "lte_rsrp", lteRsrp);
		
		Uci_Set_Str(PKG_SYSTEM_CONFIG, "debuglog", "lte_csq", lteCsq);
		
		Uci_Set_Str(PKG_SYSTEM_CONFIG, "debuglog", "lte_check", lteCheck);
		
		Uci_Set_Str(PKG_SYSTEM_CONFIG, "debuglog", "wan_dial", wanDial);
		
		Uci_Set_Str(PKG_SYSTEM_CONFIG, "debuglog", "iot_log", iotLog);
		
		Uci_Set_Str(PKG_SYSTEM_CONFIG, "debuglog", "tnt_log", tntLog);

		Uci_Set_Str(PKG_SYSTEM_CONFIG, "debuglog", "openvpn_log", openvpnLog);
		
		if ( access("/etc/storage/openvpn/client/client.conf",0) == 0){
			if(atoi(openvpnLog) == 1){
				doSystem("sed -i 's/verb 0/verb 9/' %s", "/etc/storage/openvpn/client/client.conf");
			}else{
				doSystem("sed -i 's/verb 9/verb 0/' %s", "/etc/storage/openvpn/client/client.conf");
			}
		}

		if(atoi(debugMode) == DBUG_LOG_UPDATE_SERVER)
			doSystem("rm -rf %s", "/etc/syslog.log");
	}else{
		Uci_Set_Str(PKG_SYSTEM_CONFIG, "debuglog", "lte_dial", "0");
		
		Uci_Set_Str(PKG_SYSTEM_CONFIG, "debuglog", "lte_rsrp", "0");
		
		Uci_Set_Str(PKG_SYSTEM_CONFIG, "debuglog", "lte_csq", "0");
		
		Uci_Set_Str(PKG_SYSTEM_CONFIG, "debuglog", "lte_check", "0");
		
		Uci_Set_Str(PKG_SYSTEM_CONFIG, "debuglog", "wan_dial", "0");
		
		Uci_Set_Str(PKG_SYSTEM_CONFIG, "debuglog", "iot_log", "0");
		
		Uci_Set_Str(PKG_SYSTEM_CONFIG, "debuglog", "tnt_log", "0");

		Uci_Set_Str(PKG_SYSTEM_CONFIG, "debuglog", "openvpn_log", "0");

		if ( access("/etc/storage/openvpn/client/client.conf",0) == 0) {
			doSystem("sed -i 's/verb 9/verb 0/' %s", "/etc/storage/openvpn/client/client.conf");
		}
		
		doSystem("rm -rf %s", "/etc/syslog.log");
	}

	Uci_Commit(PKG_SYSTEM_CONFIG);


	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");
	return CGI_TRUE;
}


CGI_BOOL setGpsReportCfg(json_object *request, FILE *conn_fp)
{	
	char gpsdata[512]={0};
	cJSON *root,*respond_obj;
	char *auto_longitude,*auto_lattitude;

	const char *gpsInterval = webs_get_string(request,"gpsReportTime");
	const char *enable = webs_get_string(request, "enable");
	const char *longitude = webs_get_string(request,"longitude");
	const char *lattitude = webs_get_string(request, "latitude");
	const char *gps_type = webs_get_string(request, "gps_type");

	if(atoi(enable))
	{
		int ret = f_read_string("/tmp/gps_data", gpsdata, sizeof(gpsdata));
		if(ret > 0)
		{
			respond_obj = cJSON_Parse(gpsdata);

			if(respond_obj != NULL)
			{
				auto_longitude = websGetVar(respond_obj,"longitude"); 
				auto_lattitude = websGetVar(respond_obj,"lattitude"); 
			}
		}
		else
		{
			auto_longitude="0.000000";
			auto_lattitude="0.000000";
		}
		
		Uci_Set_Str(PKG_GPSD_CONFIG,"gps","gpsReportTime",gpsInterval);
		Uci_Set_Str(PKG_GPSD_CONFIG,"gps","enable",enable);
		Uci_Set_Str(PKG_GPSD_CONFIG,"gps","gps_type",gps_type);

		if(atof(auto_longitude)<=0 && atof(auto_lattitude)<=0)
		{
			Uci_Set_Str(PKG_GPSD_CONFIG,"gps","longitude",longitude);
			Uci_Set_Str(PKG_GPSD_CONFIG,"gps","lattitude",lattitude);
		
		}
	}
	else
	{
		Uci_Set_Str(PKG_GPSD_CONFIG,"gps","enable",enable);
	}

	
	Uci_Commit(PKG_GPSD_CONFIG);
	
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");
	return CGI_TRUE;
}


CGI_BOOL setCwmpdCfg(json_object *request,FILE *conn_fp)
{
	char *enable = webs_get_string(request, "enable");

	Uci_Set_Str(PKG_ICWMP_CONFIG,"acs","enable",enable);

	if(atoi(enable) == 1){
		char *acsUrl=webs_get_string(request,"acsUrl");
		char *acsUsername=webs_get_string(request,"acsUsername");
		char *acsPassword=webs_get_string(request,"acsPassword");
		char *periodicEnable=webs_get_string(request, "periodicEnable");
		char *cpeUsername=webs_get_string(request,"cpeUsername");
		char *cpePassword=webs_get_string(request,"cpePassword");
		char *port=webs_get_string(request, "port");
		
		Uci_Set_Str(PKG_ICWMP_CONFIG,"acs","url",acsUrl);
		Uci_Set_Str(PKG_ICWMP_CONFIG,"acs","userid",acsUsername);
		Uci_Set_Str(PKG_ICWMP_CONFIG,"acs","passwd",acsPassword);
		Uci_Set_Str(PKG_ICWMP_CONFIG,"acs","periodic_inform_enable",periodicEnable);

		if(atoi(periodicEnable) == 1){
			char *periodicInterval=webs_get_string(request, "periodicInterval");
			Uci_Set_Str(PKG_ICWMP_CONFIG,"acs","periodic_inform_interval",periodicInterval);
		}

		Uci_Set_Str(PKG_ICWMP_CONFIG,"cpe","userid",cpeUsername);
		Uci_Set_Str(PKG_ICWMP_CONFIG,"cpe","passwd",cpePassword);
		Uci_Set_Str(PKG_ICWMP_CONFIG,"cpe","port",port);
	}

	Uci_Commit(PKG_ICWMP_CONFIG);

	CsteSystem("/etc/init.d/cwmp restart", CSTE_PRINT_CMD);

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");
	return CGI_TRUE;

}

#if 1 //defined (CONFIG_SNMP_SUPPORT)
CGI_BOOL getSnmpCfg(json_object *request, FILE *conn_fp)
{
	int idx=0;
	char iRulesNum[8]={0},sIdx[4]={0};

	char paramName[OPTION_STR_LEN] = {0}, tmpBuf[TEMP_STR_LEN] = {0};
	char sRules[LONG_BUFF_LEN] = {0}, sRule[TEMP_STR_LEN] = {0};
	char mode[SMALL_STR_LEN]={0}, username[TEMP_STR_LEN]={0}, password[TEMP_STR_LEN]={0};
	char hash[RESULT_STR_LEN]={0}, encryption[RESULT_STR_LEN]={0}, key[TEMP_STR_LEN]={0};

	cJSON *root, *connEntry, *connArray;

	root = cJSON_CreateObject();

	get_uci2json(root, PKG_SNMP_CONFIG, "general", "enabled", "enabled");
	get_uci2json(root, PKG_SNMP_CONFIG, "general", "version", "version");
	get_uci2json(root, PKG_SNMP_CONFIG, "general", "interface", "interface");
	get_uci2json(root, PKG_SNMP_CONFIG, "general", "serverPort", "serverPort");
	get_uci2json(root, PKG_SNMP_CONFIG, "general", "community", "community");
	get_uci2json(root, PKG_SNMP_CONFIG, "general", "trapIp", "trapIp");
	get_uci2json(root, PKG_SNMP_CONFIG, "general", "trapPort", "trapPort");

	connArray = cJSON_CreateArray();
	cJSON_AddItemToObject(root, "rule", connArray);

	Uci_Get_Str(PKG_SNMP_CONFIG, "general", "snmpv3_num", iRulesNum);
	Uci_Get_Str(PKG_SNMP_CONFIG, "general", "rules", sRules);
	for (idx = 0; idx < atoi(iRulesNum);idx++)
	{
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
		connEntry = cJSON_CreateObject();
		sprintf(sIdx, "%d", idx+1);
		//cJSON_AddStringToObject(connEntry, "idx", sIdx);
		cJSON_AddStringToObject(connEntry, "mode", mode);
		cJSON_AddStringToObject(connEntry, "username", username);
		cJSON_AddStringToObject(connEntry, "password", password);
		cJSON_AddStringToObject(connEntry, "hash", hash);
		cJSON_AddStringToObject(connEntry, "encryption", encryption);
		cJSON_AddStringToObject(connEntry, "key", key);
		cJSON_AddItemToArray(connArray, connEntry);
	}
	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}

CGI_BOOL setSnmpCfg (json_object *request, FILE *conn_fp)
{
	int num = 0, idx = 0;
	char paramName[OPTION_STR_LEN] = {0};
    char num_idx[8]={0};
	char rules[LONG_BUFF_LEN]={0};
	char *addEffect		= webs_get_string(request,  "addEffect");
	char *version	 	= webs_get_string(request,  "version");
	char *enabled 		= webs_get_string(request,  "enabled");
	json_object *c_request,*subnet, *item;

	if (atoi(enabled) == 0 && atoi(addEffect)== 0)
	{
		Uci_Set_Str(PKG_SNMP_CONFIG, "general", "enabled", enabled);
		goto end;
	}

	if(atoi(addEffect) == 1)
	{
		Uci_Set_Str(PKG_SNMP_CONFIG, "general", "enabled", "1");
		Uci_Set_Str(PKG_SNMP_CONFIG, "general", "version", "1");

		json_object_object_get_ex(request,"subnet",&subnet);

		if(subnet != NULL)
		{
			num = json_object_array_length(subnet);
			sprintf(num_idx,"%d",num);
			Uci_Set_Str(PKG_SNMP_CONFIG, "general", "snmpv3_num", num_idx);
			Uci_Del_List_All(PKG_SNMP_CONFIG,"general","rules");
			for(idx = 0; idx < num; idx++)
			{
				item = json_object_array_get_idx(subnet, idx);

				char *mode 		= webs_get_string(item,"mode");
				char *username 	= webs_get_string(item,"username");
				char *password 	= webs_get_string(item,"password");
				char *hash 		= webs_get_string(item,"hash");
				char *encryption= webs_get_string(item,"encryption");
				char *key 		= webs_get_string(item,"key");
				snprintf(rules, sizeof(rules),"%s,%s,%s,%s,%s,%s",mode,username,password,hash,encryption,key);
				Uci_Add_List(PKG_SNMP_CONFIG,"general","rules",rules);
			}
		}
	}
	else{
		Uci_Set_Str(PKG_SNMP_CONFIG, "general", "enabled", "1");
		if(atoi(version) == 0 ){
			Uci_Set_Str(PKG_SNMP_CONFIG, "general", "version", "0");
			Uci_Set_Str(PKG_SNMP_CONFIG, "general", "serverPort",	webs_get_string(request,  "serverPort"));
			Uci_Set_Str(PKG_SNMP_CONFIG, "general", "interface",	webs_get_string(request,  "interface"));
			Uci_Set_Str(PKG_SNMP_CONFIG, "general", "community",	webs_get_string(request,  "community"));
			Uci_Set_Str(PKG_SNMP_CONFIG, "general", "trapIp",		webs_get_string(request,  "trapIp"));
			Uci_Set_Str(PKG_SNMP_CONFIG, "general", "trapPort",		webs_get_string(request,  "trapPort"));
		}
		if (atoi(version) == 1) {
			Uci_Set_Str(PKG_SNMP_CONFIG, "general", "version", "1");
			Uci_Set_Str(PKG_SNMP_CONFIG, "general", "serverPort",   webs_get_string(request,  "serverPort"));
			Uci_Set_Str(PKG_SNMP_CONFIG, "general", "interface",    webs_get_string(request,  "interface"));
		}
	}
	Uci_Commit(PKG_SNMP_CONFIG);

	DealSnmpdConf();

	CsteSystem("/etc/init.d/snmpd restart", CSTE_PRINT_CMD);
end:
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

	return CGI_TRUE;
}

#endif


CGI_HANDLE_TABLE gloset_handle_t[] = {
	{"setLanguageCfg",   setLanguageCfg,   0},
	{"setOpMode",     setOpModeCfg,     1},
	{"setUpgradeFW",     setUpgradeFW,     1},
	{"setUploadSetting", setUploadSetting, 1},
	{"setLedCfg",        setLedCfg,        1},

	{"getSmartQosCfg",   getSmartQosCfg,   1},
	{"setSmartQosCfg",   setSmartQosCfg,   1},
	{"delSmartQosCfg",	 delSmartQosCfg,   1},

#if defined(CONFIG_TR069_SUPPORT)
	{"getTr069Cfg",      getTr069Cfg,      1},
	{"setTr069Cfg",      setTr069Cfg,      1},
#endif

#if defined(CONFIG_DDNS_SUPPORT)
	{"setDdnsCfg",       	setDdnsCfg,             1},
#endif

#if defined (CONFIG_DTU_SUPPORT)
	{"setDtuCfg", 			setDtuCfg,				1},
#endif

//#if defined (CONFIG_DTU_SUPPORT)
		{"setVrrpCfg",		setVrrpCfg,				1},
//#endif

	
#if defined(CONFIG_USER_FAST_NAT)
	{"setHwNatCfg",             setHwNatCfg,              1},
#endif


//#if defined(CONFIG_APP_TCPDUMP)
	{"setTcpdumpPackCfg", setTcpdumpPackCfg,		1},
//#endif

#if 1 //defined (CONFIG_SNMP_SUPPORT)
        {"getSnmpCfg",   getSnmpCfg,       1},
        {"setSnmpCfg",   setSnmpCfg,       1},
#endif

	{"setDebugLog", setDebugLog, 	1},
	{"setGpsReportCfg", setGpsReportCfg, 1},
	{"setCwmpdCfg", setCwmpdCfg, 1},
	
	{"setTelnetCfg", setTelnetCfg, 1},

	{"", NULL, 0},
};
