
#include "../defs.h"


CGI_BOOL getLoginCfg(json_object *request, FILE *conn_fp)
{
	char tmp_buf[OPTION_STR_LEN];
	
	int login_flag = 0;
	cJSON *root;
	 
	root = cJSON_CreateObject();

	get_uci2json(root, PKG_NETWORK_CONFIG,  "lan",	 "ipaddr", "lanIp");

	get_uci2json(root, PKG_SYSTEM_CONFIG,  "main",   "Username", "loginUser");

	get_uci2json(root, PKG_SYSTEM_CONFIG,  "main",   "loginPasswordFlag", "loginPasswordFlag");

	if (0 == f_exists("/tmp/login_flag")){
		login_flag=0;
	}else{
		login_flag=1;
		system("rm -f /tmp/login_flag");
	}

	snprintf(tmp_buf,OPTION_STR_LEN,"%d",login_flag);
	cJSON_AddStringToObject(root,"loginFlag",tmp_buf);
	
	send_cgi_json_respond(conn_fp, root);

 	return CGI_TRUE;
}

CGI_BOOL getSysStatusCfg(json_object *request, FILE *conn_fp)
{
	char tmp_buf[TEMP_STR_LEN] = {0};
	char channel_real[8] = {0}, encryption[8] = {0}, key[64] = {0}, proto[8] = {0};
	int dhcp_ignore=0;
	cJSON *root;
	struct sockaddr hwaddr;
	
	root = cJSON_CreateObject();

	sprintf(tmp_buf,"%d", getOpmodeVal());
	cJSON_AddStringToObject(root, "operationMode", tmp_buf);
	
	//sysInfo
	memset(tmp_buf,0,sizeof(tmp_buf));
	get_soft_version(tmp_buf,sizeof(tmp_buf));
	cJSON_AddStringToObject(root, "fmVersion", tmp_buf);

	memset(tmp_buf,0,sizeof(tmp_buf));
	Uci_Get_Str(PKG_PRODUCT_CONFIG,"sysinfo","build_time",tmp_buf);
	cJSON_AddStringToObject(root,"buildTime",tmp_buf);
	
	get_uci2json(root, PKG_PRODUCT_CONFIG, "sysinfo", "soft_model", "model");

	get_uci2json(root, PKG_PRODUCT_CONFIG, "sysinfo", "hard_model", "hardModel");

	cJSON_AddStringToObject(root, "bootVersion", "0");
	
	//lanInfo
	getInAddr("br-lan", HW_ADDR_T, (void *)&hwaddr);
	memset(tmp_buf, '\0', sizeof(tmp_buf));
	sprintf(tmp_buf,	"%02X:%02X:%02X:%02X:%02X:%02X", hwaddr.sa_data[0],hwaddr.sa_data[1], \
		hwaddr.sa_data[2],hwaddr.sa_data[3],hwaddr.sa_data[4],hwaddr.sa_data[5]);
	cJSON_AddStringToObject(root, "lanMac", tmp_buf);	
	
	memset(tmp_buf, '\0', sizeof(tmp_buf));
	get_ifname_ipaddr(LAN_DEV_NAME, tmp_buf);
	if(strlen(tmp_buf) == 0)
		Uci_Get_Str(PKG_NETWORK_CONFIG, "lan", "ipaddr", tmp_buf);
	cJSON_AddStringToObject(root, "lanIp", tmp_buf);
	
	Uci_Get_Int(PKG_DHCP_CONFIG, "lan", "ignore", &dhcp_ignore);
	if(dhcp_ignore == 0)
		cJSON_AddStringToObject(root, "lanDhcpServer", "1");
	else
		cJSON_AddStringToObject(root, "lanDhcpServer", "0");

#if defined(WIFI_SUPPORT)
	cJSON_AddStringToObject(root, "wifiDualband", "1");
#else
	//wlanInfo
	cJSON_AddStringToObject(root, "wifiDualband", "0");	/* single : 0, dualband : 1 */
#endif

/*	//2g
	cJSON_AddNumberToObject(root, "wifiOff", is_ssid_disabled(W24G_IF));

	get_cmd_result("cs mac r 2g | awk '{print $2}'", tmp_buf,sizeof(tmp_buf));
	cJSON_AddStringToObject(root, "bssid", tmp_buf);

	wificonf_get_by_key(W24G_MH,"mapmode",tmp_buf,sizeof(tmp_buf));
	if(strcmp(tmp_buf, "1") ==0){
		get_channel(W24G_IF, channel_real);
		cJSON_AddStringToObject(root, "channel", channel_real);
		//map_enable = 1;
	}else{
		wificonf_get_by_key(W24G_RADIO,"channel",tmp_buf,sizeof(tmp_buf));
		if(strcmp(tmp_buf,"0") == 0){
			cJSON_AddStringToObject(root, "channel", "0");
		
			get_channel(W24G_IF, channel_real);
			cJSON_AddStringToObject(root, "autoChannel", channel_real);
		}else{
			cJSON_AddStringToObject(root, "channel", tmp_buf);
		}	
	}

	wificonf_get_by_key(W24G_IF,"ssid",tmp_buf,sizeof(tmp_buf));
	cJSON_AddStringToObject(root, "ssid", tmp_buf);

	wificonf_get_by_key(W24G_IF,"key",key,sizeof(key));
	cJSON_AddStringToObject(root, "key", key);

	wificonf_get_by_key(W24G_IF,"encryption",tmp_buf,sizeof(tmp_buf));
	get_encryption_ui(W24G_IF,	tmp_buf, key);
	cJSON_AddStringToObject(root, "encryptionWay", tmp_buf);*/

#if BOARD_HAS_5G_RADIO
	//5g
	cJSON_AddNumberToObject(root, "wifiOff5g", is_ssid_disabled(W58G_IF));

	get_cmd_result("cs mac r 5g | awk '{print $2}'", tmp_buf,sizeof(tmp_buf));
	cJSON_AddStringToObject(root, "bssid5g", tmp_buf);

	wificonf_get_by_key(W58G_MH,"mapmode",tmp_buf,sizeof(tmp_buf));
	printf("5g mapmode:%s\n", tmp_buf);
	if(strcmp(tmp_buf, "1") ==0){
		get_channel(W58G_IF, channel_real);
		cJSON_AddStringToObject(root, "channel5g", channel_real);
	}else{
		wificonf_get_by_key(W58G_RADIO,"channel",tmp_buf,sizeof(tmp_buf));
		if(strcmp(tmp_buf,"auto") == 0){
			cJSON_AddStringToObject(root, "channel5g", "0");

			get_channel(W58G_IF, channel_real);
			cJSON_AddStringToObject(root, "autoChannel5g", channel_real);
		}else{
			cJSON_AddStringToObject(root, "channel5g", tmp_buf);
		}
	}
	wificonf_get_by_key(W58G_IF,"ssid",tmp_buf,sizeof(tmp_buf));
	cJSON_AddStringToObject(root, "ssid5g1", tmp_buf);

	get_encryption_ui(W58G_IF, tmp_buf, key);
	cJSON_AddStringToObject(root, "encryptionWay5g", tmp_buf);

	wificonf_get_by_key(W58G_IF,"key",key,sizeof(key));
	cJSON_AddStringToObject(root, "key5g1", key);

#endif

	//2g
	cJSON_AddNumberToObject(root, "wifiOff", is_ssid_disabled(W24G_IF));
	
	if(is_ssid_disabled(W24G_IF) == 0){
		wificonf_get_by_key(W24G_IF,"ssid",tmp_buf,sizeof(tmp_buf));
		cJSON_AddStringToObject(root, "ssid", tmp_buf);

		wificonf_get_by_key(W24G_RADIO,"channel",tmp_buf,sizeof(tmp_buf));
		if(strcmp(tmp_buf,"auto") == 0){
			cJSON_AddStringToObject(root, "channel", "0");
			
			get_channel(W24G_IF, channel_real);
			cJSON_AddStringToObject(root, "autoChannel", channel_real);
		}else{
			//cJSON_AddStringToObject(root, "channel", tmp_buf);
			if(strcmp(tmp_buf,"0") == 0){
				cJSON_AddStringToObject(root, "channel", "0");
			
				get_channel(W24G_IF, channel_real);
				cJSON_AddStringToObject(root, "autoChannel", channel_real);
			}else{
				cJSON_AddStringToObject(root, "channel", tmp_buf);
			}	
		}	

		get_cmd_result("cs mac r 2g | awk '{print $2}'", tmp_buf,sizeof(tmp_buf));
		cJSON_AddStringToObject(root, "bssid", tmp_buf);

		wificonf_get_by_key(W24G_IF,"encryption",tmp_buf,sizeof(tmp_buf));
		if(strcmp(tmp_buf,"none") == 0){
			cJSON_AddStringToObject(root, "key", "");
		}else{
			wificonf_get_by_key(W24G_IF,"key",key,sizeof(key));
			cJSON_AddStringToObject(root, "key", key);
		}
	}
			
	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}

static void get_port_layport(cJSON *root)
{
    int prio;
    int num = 0, status = 0, port = 0;

    char *sptr, *ptr, name[18] = {0};
    char port_layout[] = "WL1L2L3L4";//ETH_PORT_LAYOUT; //WL1L2L3L4
    
    cJSON *tmp_obj, *array_obj;

    array_obj = cJSON_CreateArray();
    cJSON_AddItemToObject(root, "portLinkStatus", array_obj);

    Uci_Get_Int(PKG_WAN_MODEM_CONFIG, "strategy", "prio", &prio);
    for (sptr = ptr = port_layout; ptr - sptr < strlen(port_layout); ptr++)
    {
        tmp_obj = cJSON_CreateObject();
        cJSON_AddItemToArray(array_obj, tmp_obj);

        // Check if the current character is 'W' or 'L' (WAN or LAN)
        if (*ptr == 'W') {
            if (prio == PRIO_ONLY_WIRE || prio == PRIO_WIRE_FRIST) {
                snprintf(name, sizeof(name), "WAN");
                port = (num == 0) ? 0 : num + 1;
            } else {
                if (ptr == sptr) {
                    num = atoi(ptr + 2);  // Get number after 'WLnLn...'
                    port = num - 1;
                } else {
                    num = atoi(ptr - 1);  // Get number before 'LnLnW'
                    port = num + 1;
                }

                snprintf(name, sizeof(name), "LAN%d", (num == 1) ? 0 : num + 1);
            }
        } else {
            ptr++; 
            num = atoi(ptr);
            port = num;
            snprintf(name, sizeof(name), "LAN%d", num);
        }

        status = is_phyport_connected(port+4);

        cJSON_AddNumberToObject(tmp_obj, "port", port);
        cJSON_AddStringToObject(tmp_obj, "name", name);
        cJSON_AddNumberToObject(tmp_obj, "link", status);
    }
}


CGI_BOOL getNetInfo(json_object *request, FILE *conn_fp)
{
	struct timeval tv;
	char *ifname = NULL;
	char tmp_buf[TEMP_STR_LEN] = {0};
	char opmode_custom[SHORT_STR_LEN] = {0}, proto[SHORT_STR_LEN] = {0}, if_wan[RESULT_STR_LEN] = {0};
	char wan_mode[32]={0},result[128]={0},cmd[128]={0};

	char wan_section[SHORT_STR_LEN] = {0}, wan_dns[OPTION_STR_LEN]={0};
	int dns_mode=0;
	struct sockaddr hwaddr;
	unsigned long long in_bytes=0,out_bytes=0;

	unsigned long long rxb=0, txb=0;
	int arrayLen=0,i=0, num, linkstatus=0;
	cJSON *root;

	struct interface_status status_paremeter;
	root = cJSON_CreateObject();
	
	gettimeofday(&tv, NULL);
	sprintf(tmp_buf, "%ld", tv.tv_sec);
	cJSON_AddStringToObject(root, "timestamp", tmp_buf);
	
	memset(tmp_buf, '\0', sizeof(tmp_buf));
	get_sys_uptime(tmp_buf);
	cJSON_AddStringToObject(root, "upTime", tmp_buf);
	
	//lan info
	memset(tmp_buf, '\0', sizeof(tmp_buf));
	datconf_get_by_key(TEMP_DATAS_FILE, "client_num", tmp_buf, sizeof(tmp_buf));
	cJSON_AddStringToObject(root, "lanUserNum", tmp_buf);
		
	Uci_Get_Str(PKG_SYSTEM_CONFIG, "opmode", "opmode_custom", opmode_custom);

	//web port map 
	get_port_layport(root);
	//sysinfo
	cJSON_AddNumberToObject(root, "memRatio", get_mem_ratio());

	datconf_get_by_key(TEMP_DATAS_FILE, "cpu_percent", tmp_buf, sizeof(tmp_buf));
	cJSON_AddStringToObject(root, "cpuRatio", tmp_buf);

	cJSON_AddNumberToObject(root, "curConnectNum", f_read_int("/proc/sys/net/netfilter/nf_conntrack_count"));
	cJSON_AddNumberToObject(root, "maxconnectNum", f_read_int("/proc/sys/net/nf_conntrack_max"));

	if(strcmp(opmode_custom, "rpt") == 0 || strcmp(opmode_custom, "wisp") == 0)
	{
		if(get_apcli_connected(WLAN_APCLI) == 1)
		{
			cJSON_AddStringToObject(root, "rptConnStatus", "success");
		}
		else
		{
			cJSON_AddStringToObject(root, "rptConnStatus", "fail");
		}

		wificonf_get_by_key(WLAN_APCLI,"ssid",tmp_buf,sizeof(tmp_buf));
		cJSON_AddStringToObject(root, "apcliSsid", tmp_buf);

		wificonf_get_by_key(WLAN_APCLI,"bssid",tmp_buf,sizeof(tmp_buf));
		cJSON_AddStringToObject(root, "apcliBssid", tmp_buf);
	}

	//wan info
	strcpy(wan_section,WAN_IFNAME);
	get_ifname_mask(wan_section, tmp_buf);
	cJSON_AddStringToObject(root, "wiredwanMask", tmp_buf);

	get_current_gateway(tmp_buf);
	cJSON_AddStringToObject(root, "wiredwanGw", tmp_buf);

	get_current_dns(1, tmp_buf, 0);
	cJSON_AddStringToObject(root,"priDns",tmp_buf);

	get_current_dns(2, tmp_buf, 0);
	cJSON_AddStringToObject(root,"secDns",tmp_buf);

	memset(tmp_buf, '\0', sizeof(tmp_buf));
	get_ifname_ipaddr(wan_section, tmp_buf);

	Uci_Get_Str(PKG_NETWORK_CONFIG, "wan", "proto", wan_mode);
	
	if(strcmp(wan_mode,"static") == 0)
	{
		snprintf(cmd,sizeof(cmd),"swconfig dev switch0 port 0 show | grep link");
		get_cmd_result(cmd, result, sizeof(result));
		cJSON_AddStringToObject(root, "wiredWanIp", tmp_buf);

		if(strstr(result,"link:up"))
		{
			cJSON_AddStringToObject(root, "wanConnStatus", "connected");
		}
		else
		{
			cJSON_AddStringToObject(root, "wanConnStatus", "disconnected");
		}
	}
	else if(strcmp(wan_mode,"pppoe") == 0)
	{
		memset(tmp_buf, '\0', sizeof(tmp_buf));
		get_ifname_ipaddr(WAN_PPPOE_IFNAME, tmp_buf);

		if(is_ip_valid(tmp_buf))
		{
			cJSON_AddStringToObject(root, "wanConnStatus", "connected");
			cJSON_AddStringToObject(root, "wiredWanIp", tmp_buf);
		}
		else
		{
			cJSON_AddStringToObject(root, "wanConnStatus", "disconnected");
			cJSON_AddStringToObject(root, "wiredWanIp", "0.0.0.0");
		}
	}
	else
	{
		if(is_ip_valid(tmp_buf))
		{
			cJSON_AddStringToObject(root, "wanConnStatus", "connected");
			cJSON_AddStringToObject(root, "wiredWanIp", tmp_buf);
		}else
		{
			cJSON_AddStringToObject(root, "wanConnStatus", "disconnected");
			cJSON_AddStringToObject(root, "wiredWanIp", "0.0.0.0");
		}
	}


	memset(tmp_buf, '\0', sizeof(tmp_buf));
	get_ifname_macaddr(WAN_IFNAME, tmp_buf);
	cJSON_AddStringToObject(root, "wanMac", tmp_buf);
	
	memset(tmp_buf, '\0', sizeof(tmp_buf));
	datconf_get_by_key(TEMP_DATAS_FILE, "rate_up", tmp_buf,sizeof(tmp_buf));
	out_bytes = atoll(tmp_buf);
	snprintf(tmp_buf, sizeof(tmp_buf), "%u", (unsigned )out_bytes/(8));
	cJSON_AddStringToObject(root, "up", tmp_buf);

	datconf_get_by_key(TEMP_DATAS_FILE, "rate_down", tmp_buf,sizeof(tmp_buf));
	in_bytes = atoll(tmp_buf);
	snprintf(tmp_buf, sizeof(tmp_buf), "%u", (unsigned )in_bytes/(8));
	cJSON_AddStringToObject(root, "down", tmp_buf);

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}

CGI_BOOL getOpModeCfg(json_object *request, FILE *conn_fp)
{
	cJSON *root;

	char tmpBuf[64]={0};

	root = cJSON_CreateObject();
	sprintf(tmpBuf, "%d", getOpmodeVal());
	cJSON_AddStringToObject(root, "operationMode", tmpBuf);
	
	memset(tmpBuf, 0, sizeof(tmpBuf));
	Uci_Get_Str(PKG_SYSTEM_CONFIG,"opmode","opmode_support",tmpBuf);
	cJSON_AddStringToObject(root, "opModeSupport", tmpBuf);
	
	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}

CGI_BOOL getOnlineMsg(json_object *request, FILE *conn_fp)
{
	cJSON *js_client = NULL,*item=NULL;

	cJSON *root, *js_entry;

	unsigned long file_len;

	char *ptr=NULL;

	char accesslist[LONG_BUFF_LEN] = {0},rules[CMD_STR_LEN] = {0};

	char tmp_buf[128];

	char mac[24]={0}, hostname[128]={0};

	int  i=0, j=0, client_num=0;

	int  idx=0, only_wlan, wifi_idx;

	ptr = webs_get_string(request, "wifiIdx");
	if(strlen(ptr)>0){
		wifi_idx = atoi(ptr);
	}else{
		wifi_idx = 2;
	}

	only_wlan  = atoi(webs_get_string(request, "only_wlan")); //2.4g=0; 5g=1

	root = cJSON_CreateArray();

	file_len = f_size(TEMP_CLIENT_FILE);
	if(file_len > 0) {
		ptr = (char *)malloc(sizeof(char)*file_len+1);
		if(ptr) {
			memset(ptr,'\0',sizeof(char)*file_len+1);
			f_read(TEMP_CLIENT_FILE, ptr, file_len);

			js_client = cJSON_Parse(ptr);
			if(js_client!=NULL) {
				client_num=cJSON_GetArraySize(js_client);
			}
			else {
				js_client = cJSON_CreateArray();
				client_num=0;
			}
			free(ptr);
		}
		else {
			js_client = cJSON_CreateArray();
			client_num=0;
		}
	}
	else {
		js_client = cJSON_CreateArray();
		client_num=0;
	}

	Uci_Get_Str(PKG_CSFW_CONFIG, "accesslist", "rules", accesslist);

	for(i=0;i<client_num;i++){
		item = cJSON_GetArrayItem(js_client,i);

		//link_type
		get_cjson_string(item, "link_type", tmp_buf, sizeof(tmp_buf));
		if(only_wlan==1 && strcmp(tmp_buf,"PC")==0){
			continue;
		}

		if(wifi_idx != 2){
			if((wifi_idx == 0 && strcmp(tmp_buf,"5g")==0) || \
			   (wifi_idx == 1 && strcmp(tmp_buf,"2g")==0))
				continue;
		}

		js_entry = cJSON_CreateObject();
		cJSON_AddItemToArray(root,js_entry);

		//idx
		idx++;
		sprintf(tmp_buf,"%d",idx);
		cJSON_AddStringToObject(js_entry, "idx", tmp_buf);

		//mac
		get_cjson_string(item, "mac", mac, sizeof(mac));
		cJSON_AddStringToObject(js_entry, "mac", mac);

		//ip
		memset(tmp_buf,0,sizeof(tmp_buf));
		get_cjson_string(item, "ip", tmp_buf, sizeof(tmp_buf));
		cJSON_AddStringToObject(js_entry, "ip", tmp_buf);

		//hostname
		memset(hostname,0,sizeof(hostname));
		get_cjson_string(item, "hostname", hostname, sizeof(hostname));

		if((strlen(accesslist) != 0) && (strstr(accesslist,mac))){
			j = 0;
			while (get_nth_val_safe(j++, accesslist, ' ', rules, sizeof(rules)) != -1 ){
				if(!strstr(rules,mac)){
					continue;
				}else{
					memset(tmp_buf,0,sizeof(tmp_buf));
					get_nth_val_safe(2, rules, ';', tmp_buf, sizeof(tmp_buf));
					if(strlen(tmp_buf)>0)
						strcpy(hostname,tmp_buf);
					break;
				}
			}
		}
		cJSON_AddStringToObject(js_entry, "name", hostname);
	}

	send_cgi_json_respond(conn_fp, root);

	cJSON_Delete(js_client);

	return CGI_TRUE;
}

#if defined(CONFIG_DDNS_SUPPORT)
CGI_BOOL getDdnsCfg(json_object *request, FILE *conn_fp)
{	   
	char tmpBuf[RESULT_STR_LEN] = {0};
	int result=0;
	char DDNSEnable[SHORT_STR_LEN]={0}, DDNSProvider[RESULT_STR_LEN]={0}, DDNSDomain[RESULT_STR_LEN]={0};
	char DDNSAccount[RESULT_STR_LEN]={0}, DDNSPassword[RESULT_STR_LEN+1]={0}, DDNSDomainList[LIST_STR_LEN];

	cJSON *root;

	root = cJSON_CreateObject();

	Uci_Get_Str(PKG_DDNS_CONFIG,"wan","enable",DDNSEnable);
	Uci_Get_Str(PKG_DDNS_CONFIG,"wan","provider",DDNSProvider);
	Uci_Get_Str(PKG_DDNS_CONFIG,"wan","domain",DDNSDomain);
	Uci_Get_Str(PKG_DDNS_CONFIG,"wan","account",DDNSAccount);
	Uci_Get_Str(PKG_DDNS_CONFIG,"wan","password",DDNSPassword);

	cJSON_AddStringToObject(root,"ddnsEnabled",DDNSEnable);	   
	cJSON_AddStringToObject(root,"ddnsProvider",DDNSProvider);
	cJSON_AddStringToObject(root,"ddnsDomain",DDNSDomain);
	cJSON_AddStringToObject(root,"ddnsAccount",DDNSAccount);
	cJSON_AddStringToObject(root,"ddnsPassword",DDNSPassword);

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;

}

int getDdnsStatus(json_object *request, FILE *conn_fp)
{
	char ddns_ip[RESULT_STR_LEN]={0}, ddns_link[4] = {0};

	struct interface_status status_paremeter;

	int result=0;

	cJSON *root;

	root = cJSON_CreateObject();

	get_wan_status(&status_paremeter);

	datconf_get_by_key(TEMP_STATUS_FILE, "ddns_bind_ip", ddns_ip, sizeof(ddns_ip));
	cJSON_AddStringToObject(root, "ddnsIPAddr", ddns_ip);

	if(status_paremeter.up==0){
		result=DDNS_FAIL;
	}else {
		datconf_get_by_key(TEMP_STATUS_FILE, "ddns_link", ddns_link, sizeof(ddns_link));
		if(atoi(ddns_link)==DDNS_SUCCESS)
		{
			result=DDNS_SUCCESS;
		}
		else
		{
			result=DDNS_FAIL;
		}
	}

	cJSON_AddNumberToObject(root, "ddnsStatus", result);

	send_cgi_json_respond(conn_fp, root);

    return CGI_TRUE;
}
#endif

#if defined(CONFIG_DTU_SUPPORT)


CGI_BOOL getDtuCfg(json_object *request, FILE *conn_fp)
{
	cJSON *root;

	root = cJSON_CreateObject();

	get_uci2json(root,PKG_DTU_CONFIG,"dtu_ctrl","dtu_enable","enable");
	get_uci2json(root,PKG_DTU_CONFIG,"dtu_ctrl","dtu_modbus","isModbus");
	get_uci2json(root,PKG_DTU_CONFIG,"dtu_ctrl","dtu_mode","mode");
	get_uci2json(root,PKG_DTU_CONFIG,"dtu_ctrl","dtu_local_port","localPort");
	get_uci2json(root,PKG_DTU_CONFIG,"dtu_ctrl","dtu_protocol","protocol");
	get_uci2json(root,PKG_DTU_CONFIG,"dtu_ctrl","dtu_serial_packet_max_length","serialPacketMaxLength");
	get_uci2json(root,PKG_DTU_CONFIG,"dtu_ctrl","dtu_channel_type","channelType");
	get_uci2json(root,PKG_DTU_CONFIG,"dtu_ctrl","dtu_net_receive_timeout","netReceiveTimeout");
	get_uci2json(root,PKG_DTU_CONFIG,"dtu_ctrl","dtu_serial_receive_timeout","serialReceiveTimeout");
	get_uci2json(root,PKG_DTU_CONFIG,"dtu_ctrl","dtu_encryption","encryption");
	get_uci2json(root,PKG_DTU_CONFIG,"dtu_ctrl","dtu_key","key");
	get_uci2json(root,PKG_DTU_CONFIG,"dtu_ctrl","dtu_server_ipaddr_1","serverIp1");
	get_uci2json(root,PKG_DTU_CONFIG,"dtu_ctrl","dtu_server_port_1","serverPort1");
	get_uci2json(root,PKG_DTU_CONFIG,"dtu_ctrl","dtu_server_ipaddr_2","serverIp2");
	get_uci2json(root,PKG_DTU_CONFIG,"dtu_ctrl","dtu_server_port_2","serverPort2");
	get_uci2json(root,PKG_DTU_CONFIG,"dtu_ctrl","dtu_server_ipaddr_3","serverIp3");
	get_uci2json(root,PKG_DTU_CONFIG,"dtu_ctrl","dtu_server_port_3","serverPort3");
	get_uci2json(root,PKG_DTU_CONFIG,"dtu_ctrl","dtu_server_ipaddr_4","serverIp4");
	get_uci2json(root,PKG_DTU_CONFIG,"dtu_ctrl","dtu_server_port_4","serverPort4");
	get_uci2json(root,PKG_DTU_CONFIG,"dtu_ctrl","dtu_interval","reTryInterval");
	get_uci2json(root,PKG_DTU_CONFIG,"dtu_ctrl","dtu_retry","reTryCount");
	get_uci2json(root,PKG_DTU_CONFIG,"dtu_ctrl","dtu_regdata","registMsg");
	get_uci2json(root,PKG_DTU_CONFIG,"dtu_ctrl","dtu_heartbeat_time","heartBeatInterval");
	get_uci2json(root,PKG_DTU_CONFIG,"dtu_ctrl","dtu_heartbeat_data","heartBeatData");
	get_uci2json(root,PKG_DTU_CONFIG,"dtu_ctrl","dtu_serial_baud_rate","rate");
	get_uci2json(root,PKG_DTU_CONFIG,"dtu_ctrl","dtu_serial_prity","parity");
	get_uci2json(root,PKG_DTU_CONFIG,"dtu_ctrl","dtu_serial_data_bits","dataBit");
	get_uci2json(root,PKG_DTU_CONFIG,"dtu_ctrl","dtu_serial_stop_bits","stopBit");
	get_uci2json(root,PKG_DTU_CONFIG,"dtu_ctrl","dtu_serial_flow_control","flowControl");
	get_uci2json(root,PKG_DTU_CONFIG,"dtu_ctrl","dtu_serial_type","type");

	cJSON *array_obj = cJSON_CreateArray();
	cJSON_AddItemToObject(root, "rs_serial", array_obj);
	for (int i = 0; serial_port_list[i].port != NULL; i++)
	{
		cJSON *tmp_obj = cJSON_CreateObject();
		cJSON_AddItemToArray(array_obj, tmp_obj);
		cJSON_AddStringToObject(tmp_obj, "idx", serial_port_list[i].idx);
		cJSON_AddStringToObject(tmp_obj, "port", serial_port_list[i].port);
		cJSON_AddStringToObject(tmp_obj, "name", serial_port_list[i].name);
	}

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}
#endif

CGI_BOOL getVrrpCfg(json_object *request, FILE *conn_fp)
{
	char lan_ifname[64]={0}, vrrpd_ifname[64]={0}, enable[8]={0};
	char vrrp_state[64] = "None";
	cJSON *root;

	root = cJSON_CreateObject();

	Uci_Get_Str(PKG_VRRPD_CONFIG, "vrrpd", "vrrp_enable", enable);
	cJSON_AddStringToObject(root, "enabled", enable);
	
	cJSON_AddStringToObject(root, "vrInterface", "br0");
	
	get_uci2json(root,PKG_VRRPD_CONFIG,"vrrpd","vrrp_virtual_ip","virtualIp");
	get_uci2json(root,PKG_VRRPD_CONFIG,"vrrpd","vrrp_virtual_id","virtualId");
	get_uci2json(root,PKG_VRRPD_CONFIG,"vrrpd","vrrp_priority","priority");
	get_uci2json(root,PKG_VRRPD_CONFIG,"vrrpd","vrrp_notice_timers","noticeTimers");
	
	if(atoi(enable)!=0)
		strcpy(vrrp_state, "Initialize");
	if(0 == access("/tmp/.vrrp_master", F_OK))
		strcpy(vrrp_state, "Master");
	else if(0 == access("/tmp/.vrrp_backup", F_OK))
		strcpy(vrrp_state, "Backup");

	cJSON_AddStringToObject(root, "status", vrrp_state);
	
	send_cgi_json_respond(conn_fp, root);
	return CGI_TRUE;	

}

typedef struct {
    char *config;
	char *uisupport;
	char *describe;
} custom_support;


CGI_BOOL getInitConfig(json_object *request, FILE *conn_fp)
{
	cJSON *root, *custom;
	char tmpBuf[TEMP_STR_LEN]={0}, copyrightStr[TEMP_STR_LEN] = {0}, lang[8] = {0};
	char helpurl_key[OPTION_STR_LEN] = {0}, helpurl_val[OPTION_STR_LEN] = {0};
	
	root = cJSON_CreateObject();

	/*activation*/
	if(f_exists("/tmp/activation_success") || f_exists("/etc/web_show_active") || f_exists("/etc/web_copyright") ) {
		cJSON_AddStringToObject(root, "activation", "1");
	} else {
		cJSON_AddStringToObject(root, "activation", "0");
	}

	get_uci2json(root,PKG_PRODUCT_CONFIG, "custom", "csid",    "csid");
	get_uci2json(root,PKG_PRODUCT_CONFIG, "sysinfo", "soft_model",    "model");

#if defined(WIFI_SUPPORT)
	cJSON_AddStringToObject(root, "wifiSupport", "1");
#else
	cJSON_AddStringToObject(root, "wifiSupport", "0");
#endif
	cJSON_AddStringToObject(root, "modelType", "5g");

	cJSON_AddStringToObject(root, "wifiDualband", "1");
	cJSON_AddStringToObject(root, "onlyLoadDefSet", "0");
	
	memset(tmpBuf, '\0', sizeof(tmpBuf));
	sprintf(tmpBuf, "%d", getOpmodeVal());
	cJSON_AddStringToObject(root, "operationMode", tmpBuf);
	
	cJSON_AddStringToObject(root, "wanStrategy", "0");
	cJSON_AddStringToObject(root, "hasMobile", "0");
	cJSON_AddStringToObject(root, "lanNum", "1");
	
	get_uci2json(root,PKG_SYSTEM_CONFIG, "main", "lang_support",   "showLanguage");	
	get_uci2json(root,PKG_SYSTEM_CONFIG, "main", "lang_type",      "defaultLang");
	get_uci2json(root,PKG_SYSTEM_CONFIG, "main", "lang_auto_flag", "langAutoFlag");
	get_uci2json(root,PKG_PRODUCT_CONFIG, "custom", "web_title", 	  "webTitle");
	
	memset(tmpBuf, '\0', sizeof(tmpBuf));
	Uci_Get_Str(PKG_PRODUCT_CONFIG,"custom","copyright",copyrightStr);
	if(strlen(copyrightStr) > 0) {
		snprintf(tmpBuf, sizeof(tmpBuf), "Copyright &copy; [date] %s", copyrightStr);
		cJSON_AddStringToObject(root, "copyRight", tmpBuf);
	} else {
		cJSON_AddStringToObject(root, "copyRight", "");
	}
	
	Uci_Get_Str(PKG_SYSTEM_CONFIG,"main","lang_type",lang);
	memset(helpurl_key, '\0', sizeof(helpurl_key));
	memset(helpurl_val, '\0', sizeof(helpurl_val));
	snprintf(helpurl_key,sizeof(helpurl_key),"helpurl_%s",lang);
	Uci_Get_Str(PKG_PRODUCT_CONFIG,"custom",helpurl_key,helpurl_val);
	if(strlen(helpurl_val)) {
		cJSON_AddStringToObject(root, "showHelp", "1");
		memset(tmpBuf, '\0', sizeof(tmpBuf));
		snprintf(tmpBuf,sizeof(tmpBuf),"http://%s", helpurl_val);
		cJSON_AddStringToObject(root, "helpUrl", tmpBuf);
	} else {
		cJSON_AddStringToObject(root, "showHelp", "0");
		cJSON_AddStringToObject(root, "helpUrl", "");
	}
	
	get_uci2json(root,PKG_PRODUCT_CONFIG, "custom", "vendor",	    "cs");
	cJSON_AddStringToObject(root, "wifiSupport5gOnly", "0");
	cJSON_AddStringToObject(root, "wifi11axSupport", "1");

	custom = cJSON_CreateObject();
	get_uci2json(custom,PKG_SYSTEM_CONFIG,  "opmode", "opmode_support",		    "opmodeSupport");
	get_uci2json(custom,PKG_PRODUCT_CONFIG, "custom", "wan_type_list",	    "wanTypeList");

	cJSON_AddStringToObject(custom, "versionControlSupport", "0");

	custom_support suppor[]={
		{"WiredWanSupport"			, "wiredWanSupport"			, 	"WAN设置"				},
		{"DetectNetSupport"			, "detectNetSupport"		, 	NULL				},
		{"LinkSwtichSupport"		, "linkSwtichSupport"		, 	"链路优先级"				},
		
		{"L2tpClientSupport"		, "l2tpClientSupport"		, 	"VPDN L2TP"			},
		{"PptpClientSupport"		, "pptpClientSupport"		, 	"VPDN PPTP"			},
		{"VpnMultiClientSupport"	, "vpnMultiClientSupport"	, 	"VPND (列表菜单 L2TP/PPTP)"	},
		
		{"PptpServerSupport"		, "pptpServerSupport"		, 	NULL				},
		
		{"VpncDmzSupport"			, "vpncDmzSupport"			, 	NULL},		
		{"OpenVpnServerSupport"		, "openVpnServerSupport"	, 	"OpenVPN账号管理"		},
		{"OpenVpnClientSupport"		, "openVpnClientSupport"	, 	"OpenVPN"			},
		{"PppoeSpecSupport"			, "pppoeSpecSupport"		, 	NULL				},
		
		{"pptpSupport"				, "pptpSupport"				, 	"PPTP"				},
		{"l2tpSupport"				, "l2tpSupport"				, 	"L2TP"				},
		{"DdnsSupport"				, "ddnsSupport"				, 	"DDNS"				},
		{"QosSupport"				, "qosSupport"				, 	"智能QoS"				},
		
		{"SmsSupport"				, "smsSupport"				, 	"短信服务"				},
		{"MacAuthSupport"			, "macAuthSupport"			, 	NULL				},
		{"IpsecSupport"				, "ipsecSupport"			, 	"IPSec网对网 / IPSec点对网 / XAuth IPSec"},
		{"Ipv6Support"				, "ipv6Support"				, 	"IPv6设置"			},
		
		{"StaticrouteSupport"		, "staticRouteSupport"		, 	"静态路由"				},
		{"DtuSupport"				, "dtuSupport"				, 	"DTU设置"				},
		{"FirewallSupport"			, "firewallSupport"			,	NULL				},	
		{"SnmpSupport"				, "snmpSupport"				, 	"SNMP"				},

		{"RipSupport"				, "ripSupport"				, 	"RIP"				},
		{"OspfSupport"				, "ospfSupport"				, 	"OSPF"				},
		{"BgpSupport"				, "bgpSupport"				,	NULL				},
		{"SnmpSupport"				, "snmpSupport"				, 	"BGP"				},
		
		{"EoipSupport"				, "eoipSupport"				, 	"EoIP"				},
		{"VrrpSupport"				, "vrrpSupport"				, 	"VRRP"				},
		{"BandLockSupport"			, "bandLockSupport"			,	NULL				},
		{"TunnelSupport"			, "tunnelSupport"			, 	"隧道设置"			},

		{"CertSupport"				, "certSupport"				, 	"Cert"				},
		{"DmvpnSupport"				, "dmvpnSupport"			, 	"DMVPN"				},
		{"RnatSupport"				, "rnatSupport"				,	"NAT"				},
		{"AlgSupport"				, "algSupport"				, 	"ALG服务"			},
		
		{"RemoteLogSupport"			, "remoteLogSupport"		, 	"远程日志"			},
		{"GpsSupport"				, "gpsSupport"				, 	"GPS定位"			},
		{"SaSupport"				, "saSupport"				,	NULL				},
		{"NetCustomSupport"			, "netcustomSupport"		, 	NULL				},

		{"BaseStationSupport"		, "baseStationSupport"		, 	NULL				},
		{"FotaSupport"				, "fotaSupport"				, 	"FOTA升级"			},
		{"WanRouteSupport"			, "wanRouteSupport"			,	NULL				},
		{"Rtl8111hSupport"			, "rtl8111hSupport"			,	NULL				},
		{"TfSupport"				, "tfSupport"				, 	"TF"				},

		{"SimChangeSupport"			, "simChangeSupport"		, 	NULL				},
		{"ModemPpsSupport"			, "modemPpsSupport"			, 	NULL				},
		{"CellLockSupport"			, "cellLockSupport"			,	NULL				},
		{"CwmpdSupport"				, "cwmpdSupport"			, 	"TR069"				},
		
		{"TcpdumpPackSupport"		, "tcpdumpPackSupport"		, 	"抓包分析"			},
		{"TimingSupport"			, "timingSupport"			,	"时间设置下拉框"			},
		{"NssaiSupport"				, "nssaiSupport"			, 	NULL				},
		
		{"sslVpnSupport"			, "sslVpnSupport"			, 	"SSLVPN"			},
		{"vxlanSupport"				, "vxlanSupport"			, 	"VXLAN"				},
		{"WireguardSupport"			, "wireguardSupport"		, 	"Wireguard"			},
		{"modemSupport"				, "modemSupport"			, 	"Modem设置"			}
	};

	cJSON_AddStringToObject(custom, "qosDefSingleIpSupport", "1");

	cJSON_AddStringToObject(custom, "bioSupport", "0");
	cJSON_AddStringToObject(custom, "policyRouteSupport", "0");
	cJSON_AddStringToObject(custom, "ttyServerSupport", "0");
	cJSON_AddStringToObject(custom, "iotSupport", "0");
	cJSON_AddStringToObject(custom, "lteTestSupport", "0");
	cJSON_AddStringToObject(custom, "actStatusSupport", "0");
	
	cJSON_AddStringToObject(custom, "attackSupport", "0");
	cJSON_AddStringToObject(custom, "diffnetListSupport", "0");
	cJSON_AddStringToObject(custom, "diffnetSupport", "0");

	cJSON_AddStringToObject(custom, "diffnetSwitchSupport", "0");
	cJSON_AddStringToObject(custom, "radiusSupport", "0");
	cJSON_AddStringToObject(custom, "actStatusSupport", "0");

	
	cJSON_AddStringToObject(custom, "vpnDetectionSupport", "0");
	cJSON_AddStringToObject(custom, "mqttSupport", "0");

	cJSON_AddStringToObject(custom, "gps3Support", "0");

	cJSON_AddStringToObject(custom, "manageCloudSupport", "0");
	
	cJSON_AddStringToObject(custom, "mirrorPortSupport", "0");
	
	
	cJSON_AddStringToObject(custom, "staticDhcpSupport", "0");

	cJSON_AddStringToObject(custom, "thirdSystemSupport", "0");

#if defined(CONFIG_USER_FAST_NAT)
	cJSON_AddStringToObject(custom, "hwNatSupport", "1");
#else
	cJSON_AddStringToObject(custom, "hwNatSupport", "0");
#endif

	cJSON_AddStringToObject(custom, "iotMqttSupport", "0");

	cJSON_AddStringToObject(custom, "iotMqttWebShowUserPass", "0");
	cJSON_AddStringToObject(custom, "dtuDualband", "0");
	cJSON_AddStringToObject(custom, "wifiWpa2Wpa3Support", "0");
	cJSON_AddStringToObject(custom, "terminalSupport", "0");

	cJSON_AddStringToObject(custom, "newActiveSupport", "0");
	cJSON_AddStringToObject(custom, "aliyunMqttSupport", "0");
	cJSON_AddStringToObject(custom, "dtuAliyunMqttSupport", "0");

	for(int i=0; i < sizeof(suppor)/sizeof(suppor[0]); i++)
	{
		get_num_uci2json(custom,PKG_PRODUCT_CONFIG, "custom",suppor[i].config , suppor[i].uisupport);
	}
		

	cJSON_AddStringToObject(custom, "debugLogSupport", "0");

	get_uci2json(custom,PKG_PRODUCT_CONFIG, "custom", "slbDongleSupport","slbDongleSupport");
	get_uci2json(custom,PKG_PRODUCT_CONFIG, "custom", "slbAPSupport","slbAPSupport");

	cJSON_AddItemToObject(root,"custom",custom);
	
	send_cgi_json_respond(conn_fp, root);

    return CGI_TRUE;	
}

#if defined(CONFIG_USER_FAST_NAT)
CGI_BOOL getHwNatCfg(json_object *request, FILE *conn_fp)
{	
	cJSON *root;

	root = cJSON_CreateObject();

	get_num_uci2json(root,PKG_CSFW_CONFIG,"firewall","hwnat_enable","hwNatEnable");

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;

}
#endif



//#if defined(CONFIG_APP_TCPDUMP)
CGI_BOOL getTcpdumpPackCfg(json_object *request, FILE *conn_fp)
{	
	int i, num;
	cJSON *root, *if_array, *tmp_obj;

	root = cJSON_CreateObject();

	net_interface_t ifname_list[10];
	memset(ifname_list, 0, sizeof(ifname_list));
	num = get_interface_list(&ifname_list);

	if_array = cJSON_CreateArray();
	cJSON_AddItemToObject(root, "ifname_list", if_array);

	for (i = 0; i < num; i++) {
		tmp_obj = cJSON_CreateObject();
		cJSON_AddItemToArray(if_array, tmp_obj);
		cJSON_AddStringToObject(tmp_obj, "idx", ifname_list[i].idx);
		cJSON_AddStringToObject(tmp_obj, "lable", ifname_list[i].lable);
		cJSON_AddStringToObject(tmp_obj, "value", ifname_list[i].value);
	}

	get_uci2json(root,PKG_SYSTEM_CONFIG,"tcpdump","enable","enable");
	get_uci2json(root,PKG_SYSTEM_CONFIG,"tcpdump","ifname","iface");
	get_uci2json(root,PKG_SYSTEM_CONFIG,"tcpdump","packsize","fileSize");
	get_uci2json(root,PKG_SYSTEM_CONFIG,"tcpdump","interface","interface");
	
	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}

CGI_BOOL getTcpdumpPackStatus(json_object *request, FILE *conn_fp)
{
	cJSON *root;
	char status[32]={0};
	
	root = cJSON_CreateObject();

	datconf_get_by_key(TEMP_STATUS_FILE, "tcpdump_status", status,  sizeof(status));
	cJSON_AddStringToObject(root, "status", status);
	
	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}
//#endif

CGI_BOOL getDebugLog(json_object *request, FILE *conn_fp)
{
	cJSON *root;

	root = cJSON_CreateObject();

	get_num_uci2json(root,PKG_SYSTEM_CONFIG,"debuglog","debug_mode","debugMode");
	
	get_num_uci2json(root,PKG_SYSTEM_CONFIG,"debuglog","lte_dial","lteDial");
	get_num_uci2json(root,PKG_SYSTEM_CONFIG,"debuglog","lte_rsrp","lteRsrp");
	get_num_uci2json(root,PKG_SYSTEM_CONFIG,"debuglog","lte_csq","lteCsq");
	get_num_uci2json(root,PKG_SYSTEM_CONFIG,"debuglog","lte_check","lteCheck");
	
	get_num_uci2json(root,PKG_SYSTEM_CONFIG,"debuglog","wan_dial","wanDial");
	get_num_uci2json(root,PKG_SYSTEM_CONFIG,"debuglog","iot_log","iotLog");
	get_num_uci2json(root,PKG_SYSTEM_CONFIG,"debuglog","tnt_log","tntLog");
	get_num_uci2json(root,PKG_SYSTEM_CONFIG,"debuglog","openvpn_log","openvpnLog");
	
	get_num_uci2json(root,PKG_SYSTEM_CONFIG,"debuglog","save_action","saveAction");
	
	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}

CGI_BOOL getGps3Status(json_object *request, FILE *conn_fp)
{
	cJSON *root;

	root = cJSON_CreateObject();
	
	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}
CGI_BOOL getGpsReportCfg(json_object *request, FILE *conn_fp)
{
	char gpsdata[512] = {0};
	char *auto_longitude=NULL,*auto_lattitude=NULL;
	char module[128]={0},gpsInterval[128]={0},enable[128]={0};
	char gps_long[128]={0},gps_latt[128]={0};
	char gps_type[32]={0};
	
	cJSON *root,*respond_obj;

	root = cJSON_CreateObject();

	Uci_Get_Str(PKG_GPSD_CONFIG,"gps","module",module);
	Uci_Get_Str(PKG_GPSD_CONFIG,"gps","gpsReportTime",gpsInterval);
	Uci_Get_Str(PKG_GPSD_CONFIG,"gps","enable",enable);
	Uci_Get_Str(PKG_GPSD_CONFIG,"gps","gps_type",gps_type);

			
	respond_obj = cJSON_CreateObject();
	

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


	if(atof(auto_longitude)<=0 && atof(auto_lattitude)<=0)
	{
		Uci_Get_Str(PKG_GPSD_CONFIG,"gps","longitude",gps_long);
		Uci_Get_Str(PKG_GPSD_CONFIG,"gps","lattitude",gps_latt);
		cJSON_AddStringToObject(root, "longitude",gps_long);
		cJSON_AddStringToObject(root, "latitude",gps_latt);
		cJSON_AddStringToObject(root, "gpsReport","1");
	}
	else
	{
		cJSON_AddStringToObject(root, "longitude",auto_longitude);
		cJSON_AddStringToObject(root, "latitude",auto_lattitude);
		cJSON_AddStringToObject(root, "gpsReport","0");
	}

	cJSON_AddStringToObject(root, "gps_type",gps_type);
	cJSON_AddStringToObject(root, "module",module);
	cJSON_AddStringToObject(root, "gpsReportTime",strlen(gpsInterval)>0?gpsInterval:"86400");
	cJSON_AddStringToObject(root, "enable",enable);
	
	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}


CGI_BOOL getCwmpdCfg(json_object *request,FILE *conn_fp)
{
	char acs_enable[256]={0},acs_username[256]={0},acs_password[265]={0},acs_url[256]={0};
	char acs_inform_enable[256]={0},acs_periodic_interval[256]={0};
	char cpe_username[256]={0},cpe_password[256]={0},httpd_port[256]={0};
	cJSON *root;

	root = cJSON_CreateObject();

	Uci_Get_Str(PKG_ICWMP_CONFIG,"acs","enable",acs_enable);

	Uci_Get_Str(PKG_ICWMP_CONFIG,"acs","userid",acs_username);
	Uci_Get_Str(PKG_ICWMP_CONFIG,"acs","passwd",acs_password);
	Uci_Get_Str(PKG_ICWMP_CONFIG,"acs","url",acs_url);
	Uci_Get_Str(PKG_ICWMP_CONFIG,"acs","periodic_inform_interval",acs_periodic_interval);
	Uci_Get_Str(PKG_ICWMP_CONFIG,"acs","periodic_inform_enable",acs_inform_enable);

	Uci_Get_Str(PKG_ICWMP_CONFIG,"cpe","userid",cpe_username);
	Uci_Get_Str(PKG_ICWMP_CONFIG,"cpe","passwd",cpe_password);
	Uci_Get_Str(PKG_ICWMP_CONFIG,"cpe","port",httpd_port);

	cJSON_AddStringToObject(root, "enable", acs_enable);
	cJSON_AddStringToObject(root, "acsUrl", acs_url);
	cJSON_AddStringToObject(root, "acsUsername", acs_username);
	cJSON_AddStringToObject(root, "acsPassword", acs_password);

	cJSON_AddStringToObject(root, "periodicEnable", acs_inform_enable);
	cJSON_AddStringToObject(root, "periodicInterval", acs_periodic_interval);

	cJSON_AddStringToObject(root, "cpeUsername", cpe_username);
	cJSON_AddStringToObject(root, "cpePassword", cpe_password);
	cJSON_AddStringToObject(root, "port", httpd_port);

	
	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}

int getTelnetCfg(json_object *request,FILE *conn_fp)
{
	cJSON *root;

	root = cJSON_CreateObject();

	get_num_uci2json(root,PKG_SYSTEM_CONFIG,"telnetd","enable","telnet_enabled");
	
	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;

}


CGI_HANDLE_TABLE global_handle_t[] = {
	{"getInitConfig",		getInitConfig,		        0},
	{"getLoginCfg",         getLoginCfg,                0},
	{"getSysStatusCfg",     getSysStatusCfg,            0},
	{"getNetInfo",          getNetInfo,                 1},
	{"getOnlineMsg",        getOnlineMsg,               1},
	{"getOpMode",           getOpModeCfg,               1},

#if defined(CONFIG_DDNS_SUPPORT)
	{"getDdnsCfg",          getDdnsCfg,                 1},
	{"getDdnsStatus",       getDdnsStatus,              1},
#endif

#if defined(CONFIG_DTU_SUPPORT)
	{"getDtuCfg",		   getDtuCfg,					1},
#endif

	{"getVrrpCfg",		   getVrrpCfg,					1},

#if defined(CONFIG_USER_FAST_NAT)
	{"getHwNatCfg",         getHwNatCfg,                1},
#endif

//#if defined(CONFIG_APP_TCPDUMP)
	{"getTcpdumpPackCfg",   getTcpdumpPackCfg,		    1},
	{"getTcpdumpPackStatus",getTcpdumpPackStatus,	    1},
//#endif

	{"getDebugLog",         getDebugLog,		        1},

	{"getGps3Status", getGps3Status, 1},
	{"getGpsReportCfg", getGpsReportCfg, 1},
	{"getCwmpdCfg", getCwmpdCfg, 1},
	
	
	{"getTelnetCfg", getTelnetCfg, 1},
	
	{"", NULL, 0},
};
