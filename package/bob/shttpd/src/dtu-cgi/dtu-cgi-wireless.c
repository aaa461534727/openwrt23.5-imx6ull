#include "../defs.h"

#if defined(WIFI_SUPPORT)
CGI_BOOL getWiFiBasicConfig(json_object *request, FILE *conn_fp)
{	
	int wl_idx, wl_radio;
	char tmpBuf[64]={0}, chReal[8]={0}, key[64]={0};
	cJSON *root;

	root= cJSON_CreateObject();
	
	int wifiIdx = atoi(webs_get_string(request, "wifiIdx"));
	if(wifiIdx == 0){
		//2.4G
		wl_radio = W24G_RADIO;
		wl_idx   = W24G_IF;
	}else{
		//5G
		wl_radio = W58G_RADIO;
		wl_idx   = W58G_IF;
	}

	
#if BOARD_HAS_5G_RADIO
	cJSON_AddStringToObject(root, "wifiDualband", "1"); //5G : 1
#else
	cJSON_AddStringToObject(root,"wifiDualband","0");	/*2.4G : 0 */
#endif

	cJSON_AddStringToObject(root, "operationMode", "0");

	cJSON_AddNumberToObject(root, "wifiOff", is_ssid_disabled(wl_idx));


	wificonf_get_by_key(wl_idx,"ssid", tmpBuf, sizeof(tmpBuf));
	cJSON_AddStringToObject(root, "ssid", tmpBuf);
	
	memset(tmpBuf, 0, sizeof(tmpBuf));
	wificonf_get_by_key(wl_radio,"channel", tmpBuf, sizeof(tmpBuf));
	if(strcmp(tmpBuf,"auto") == 0){
		cJSON_AddStringToObject(root, "channel", "0");
		
		get_channel(wl_idx, chReal);
		cJSON_AddStringToObject(root, "autoChannel", chReal);
	}else{
		cJSON_AddStringToObject(root, "channel", tmpBuf);
	}

	memset(tmpBuf, 0, sizeof(tmpBuf));
	wificonf_get_by_key(wl_idx,"hidden",tmpBuf,sizeof(tmpBuf));
	cJSON_AddStringToObject(root, "hssid", tmpBuf);

	wificonf_get_by_key(wl_radio,"hw_show", tmpBuf, sizeof(tmpBuf));
	cJSON_AddStringToObject(root, "band", tmpBuf);

	wificonf_get_by_key(wl_radio,"ht_show", tmpBuf, sizeof(tmpBuf));
	cJSON_AddStringToObject(root, "bw", tmpBuf);
	
	wificonf_get_by_key(wl_idx,"key", key, sizeof(key));
	wificonf_get_by_key(wl_idx,"encryption", tmpBuf, sizeof(tmpBuf));
	if(strcmp(tmpBuf,"none") == 0){
		cJSON_AddStringToObject(root, "authMode", "NONE");
		cJSON_AddStringToObject(root, "key", "");
	}else{
		
		cJSON_AddStringToObject(root, "encrypType", tmpBuf);	
		cJSON_AddStringToObject(root, "authMode", "2");
		cJSON_AddStringToObject(root, "key", key);
	}

	cJSON_AddStringToObject(root, "countryBt", "1");
	
	memset(tmpBuf, 0, sizeof(tmpBuf));
	//wificonf_switch_country(wl_radio, NULL, tmpBuf);
	cJSON_AddStringToObject(root, "countryCode", tmpBuf);

	cJSON_AddStringToObject(root, "countryCodeList", "US,EU,CN,IA,OT");
	
	memset(tmpBuf, 0, sizeof(tmpBuf));
	wificonf_get_by_key(wl_idx,"isolate", tmpBuf, sizeof(tmpBuf));
	cJSON_AddStringToObject(root, "noForwarding", tmpBuf);
	
	send_cgi_json_respond(conn_fp, root);
	
	return CGI_TRUE;
}

CGI_BOOL setWiFiBasicConfig(json_object *request, FILE *conn_fp)
{
	int  wl_radio, wl_idx;
	char *ptr;
	int wifiIdx=atoi(webs_get_string(request, "wifiIdx"));

	wl_radio = W24G_RADIO;
	wl_idx = W24G_IF;

#if BOARD_HAS_5G_RADIO
	// 0:2.4G; 1:5G;s
	if(wifiIdx)
	{
		wl_radio = W58G_RADIO;
		wl_idx	 = W58G_IF;
	}
#endif	

	int addEffect = atoi(webs_get_string(request,"addEffect"));
	if(addEffect){
		ptr = webs_get_string(request,"wifiOff");
		wificonf_set_disabled(wl_radio, atoi(ptr));
	}else{
		ptr = webs_get_string(request,"noForwarding");
		if(atoi(ptr)==0 || atoi(ptr)==1){
			wificonf_set_by_key(wl_idx,  "isolate", ptr);
		}
		
		ptr = webs_get_string(request,"hssid");
		if(atoi(ptr)==0 || atoi(ptr)==1){
			wificonf_set_by_key(wl_idx,  "hidden", ptr);
		}

		ptr = webs_get_string(request,"ssid");	
		wificonf_set_by_key(wl_idx,  "ssid", ptr);

		ptr = webs_get_string(request,"channel");	
		if(atoi(ptr) == 0)
			wificonf_set_by_key(wl_radio,  "channel","auto");
		else
			wificonf_set_by_key(wl_radio,  "channel", ptr);

		ptr = webs_get_string(request,"countryCode");
		wificonf_set_by_key(wl_radio, "country", ptr);
		
		ptr = webs_get_string(request,"bw");
		int ibw=atoi(ptr);
		if((wl_radio == W24G_RADIO && ibw>=0 && ibw<=3)
		 || (wl_radio == W58G_RADIO && ibw>=1 && ibw<=4)){
		 	wificonf_set_by_key(wl_radio, "ht_show", ptr);
		}

		ptr = webs_get_string(request,"band");
		int iband = atoi(ptr);
		if((wl_radio == W24G_RADIO && (iband==1||iband==4||iband==6||iband==9||iband==16))
		 || (wl_radio == W58G_RADIO && (iband==2||iband==8||iband==14 || iband==17))){
			wificonf_set_by_key(wl_radio, "hw_show", ptr);
		}

		ptr = webs_get_string(request,"key");
		
		if(strlen(ptr) > 7){
			wificonf_set_by_key(wl_idx, "key", ptr);
			wificonf_set_by_key(wl_idx, "authmode",    "WPAPSKWPA2PSK");
			wificonf_set_by_key(wl_idx, "encryption",  "AES");
		}else{
			wificonf_set_by_key(wl_idx, "key", "");
			wificonf_set_by_key(wl_idx, "authmode",    "OPEN");
			wificonf_set_by_key(wl_idx, "encryption",  "NONE");
		}
	}
	Uci_Commit(PKG_WIRELESS_CONFIG);
	set_lktos_effect("wireless");
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "6", "reserv");
	
	return CGI_TRUE;
}

CGI_BOOL getWiFiAclRules(json_object *request, FILE *conn_fp)
{
	int  i, wifi_idx, wl_idx, acl_mode;

	char tmp_buf[128], rules[4096]={0}, rule[128]={0};
	char mac[18],des[64];

	cJSON *root, *connArray, *connEntry;

	root= cJSON_CreateObject();
	connArray = cJSON_CreateArray();
	cJSON_AddItemToObject(root,"rule",connArray);

	wifi_idx = atoi(webs_get_string(request, "wifiIdx"));

	wl_idx   = W24G_IF;

#if BOARD_HAS_5G_RADIO
	cJSON_AddStringToObject(root, "wifiDualband", "1");	//5G : 1
	if(wifi_idx) { // 0:2.4G; 1:5G;
		wl_idx   = W58G_IF;
	}
#else
	cJSON_AddStringToObject(root,"wifiDualband","0");	/*2.4G : 0 */
#endif

	cJSON_AddNumberToObject(root, "wifiOff", is_ssid_disabled(wl_idx));

	wificonf_get_by_key(wl_idx, "macfilter", tmp_buf, sizeof(tmp_buf));
	if(strcmp(tmp_buf,"allow")==0){
		acl_mode=1;
	}else if(strcmp(tmp_buf,"deny")==0){
		acl_mode=2;
	}else{
		acl_mode=0;
	}
	cJSON_AddNumberToObject(root, "authMode", acl_mode);

	wificonf_get_by_key(wl_idx, "maclist", rules, sizeof(rules));

	i=0;
	while(get_nth_val_safe(i++, rules, ' ', rule, sizeof(rule))==0){

		memset(mac,0,sizeof(mac));
		memset(des,0,sizeof(des));

		if((get_nth_val_safe(0, rule, ',', mac, sizeof(mac)) == -1)){
			continue;
		}

		if((get_nth_val_safe(1, rule, ',', des, sizeof(des)) == -1)){
			continue;
		}

		connEntry = cJSON_CreateObject();
		cJSON_AddItemToArray(connArray,connEntry);

		cJSON_AddNumberToObject(connEntry,"idx", i);
		cJSON_AddStringToObject(connEntry,"mac", mac);
		cJSON_AddStringToObject(connEntry,"desc", des);
		snprintf(tmp_buf,sizeof(tmp_buf),"delRule%d",(i-1));
		cJSON_AddStringToObject(connEntry, "delRuleName", tmp_buf);
	}

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}

CGI_BOOL setWiFiAclRules(json_object *request, FILE *conn_fp)
{
	struct array_list *subArry;
	int  add_effect, acl_mode;
	int  wifi_idx, wl_radio, wl_idx;
	int i, num, idx;
	char *ptr;
	char rule[128]={0},tmpBuf[8]={0};

	ptr = webs_get_string(request,"addEffect");
	add_effect=atoi(ptr);

	ptr = webs_get_string(request,"authMode");
	acl_mode=atoi(ptr);

	ptr = webs_get_string(request,"wifiIdx");
	wifi_idx=atoi(ptr);

	wl_radio  = W24G_RADIO;
	wl_idx    = W24G_IF;

#if BOARD_HAS_5G_RADIO
	if(wifi_idx) { // 0:2.4G; 1:5G;
		wl_radio  = W58G_RADIO;
		wl_idx    = W58G_IF;
	}
#endif

	if (add_effect == 0) {
		if(acl_mode == 0) {//disabled
			wificonf_set_by_key(wl_idx,   "macfilter", "");

			wificonf_del_by_key(wl_idx,    "maclist", "");

			wificonf_set_by_key(wl_radio,   "maclist_num", "0");
		} else if(acl_mode == 1) {//white list
			wificonf_set_by_key(wl_idx,   "macfilter", "allow");
		} else if(acl_mode == 2) {//black list
			wificonf_set_by_key(wl_idx,   "macfilter", "deny");
		}
	} else {
		json_object_object_foreach(request, key, val){
			if(strcmp(key, "subnet") == 0){
				subArry = json_object_get_array(val);
				num = json_object_array_length(val);
				
				snprintf(tmpBuf, sizeof(tmpBuf), "%d", num);
				wificonf_set_by_key(wl_radio,	"maclist_num", tmpBuf);
				wificonf_del_by_key(wl_idx,    "maclist", "");
				for(idx = 0; idx < num ; idx++){				
					struct json_object *objet_x = (struct json_object *)array_list_get_idx(subArry, idx);				

					char *macAddress = webs_get_string(objet_x, "mac");
					char *comment = webs_get_string(objet_x, "desc");
					
					memset(rule, '\0', sizeof(rule));
					snprintf(rule, sizeof(rule), "%s,%s", macAddress,comment);
					wificonf_add_by_key(wl_idx, "maclist", rule);
				}
				break;
			}
		}		
	}

	Uci_Commit(PKG_WIRELESS_CONFIG);

	set_lktos_effect("wireless");

	set_lktos_effect("firewall");

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "5", "reserv");

	return CGI_TRUE;
}

//---------------------------------------------------------------------------------
CGI_HANDLE_TABLE wireless_handle_t[]={
	{"getWiFiBasicConfig", getWiFiBasicConfig, 1},
	{"setWiFiBasicConfig", setWiFiBasicConfig, 1},

	{"getWiFiAclRules",  getWiFiAclRules,  1},
	{"setWiFiAclRules",  setWiFiAclRules,  1},
	
	{"", NULL, 0},
};
#endif
