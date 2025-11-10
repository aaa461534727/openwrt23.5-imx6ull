#include "../defs.h"


//加密证书
#define ENC_CERT_FILE  "enc_cert.cer"
//签名证书
#define SIGN_CERT_FILE "sign_cert.cer"
//根证书
#define CA_CERT_FILE "ca.cer"
//加密密钥对
#define ENC_KEY_FILE "encPrivateKey.txt"

#define CERT_PATH "/opt/ssl/cert"

#define KEY_NO_FOUND 0x0A00001B


CGI_BOOL getEoipCfg(json_object *request, FILE *conn_fp)
{
	int num=0, i=0;
	char rule[64]={0}, rules[512]={0}, tmpBuf[8]={0};
	char eoipId[16]={0}, name[8]={0}, ip[16]={0}, iface[16]={0};
	char section[OPTION_STR_LEN]={0};
	cJSON *root, *array;
	
	root = cJSON_CreateObject();
	array = cJSON_CreateArray();

	cJSON_AddItemToObject(root, "rule", array);
	
	num = get_cmd_val("uci show eoip | grep eoip | grep dst |  wc -l");

	if(num > 0)
	{
		for(i=0; i< num; i++)
		{
			snprintf(section, OPTION_STR_LEN, "@eoip[%d]", i);
			
			cJSON *sub_json = cJSON_CreateObject();
			
			get_uci2json(sub_json,PKG_EOIP_CONFIG,section,"idtun","eoipId");
			get_uci2json(sub_json,PKG_EOIP_CONFIG,section,"name","eoipName");
			get_uci2json(sub_json,PKG_EOIP_CONFIG,section,"dst","dstAddress");

			cJSON_AddItemToArray(array, sub_json);
		}	
	}
	
	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}

CGI_BOOL setEoipCfg(json_object *request, FILE *conn_fp)
{
	struct array_list *subnet;
	char tmpBuf[64] = {0}, rule[64]={0};
	int i = 0, num = 0;
	char section[SHORT_STR_LEN] = {0};
	char index[SHORT_STR_LEN] = {0};

	num = get_cmd_val("uci show eoip | grep eoip | grep dst |  wc -l");
	if (num > 0  || num == 0)
	{	
		for (i = 0; i <= num; i++)                
			{
				memset(section, 0 , sizeof(section));
				snprintf(section, sizeof(section)-1, "@eoip[%d]", i);

				memset(index, 0, sizeof(index));
				Uci_Get_Str(PKG_EOIP_CONFIG, section, "name", index);

				memset(tmpBuf, 0, sizeof(tmpBuf));
				snprintf(tmpBuf, sizeof(tmpBuf)-1, "zeoip%s", index);
				
				Uci_Del_List(PKG_NETWORK_CONFIG, "@device[0]", "ports", tmpBuf); 
			}
			
		Uci_Del_Section(PKG_EOIP_CONFIG, "@eoip[0]");
		uci_del_list_item_all(PKG_EOIP_CONFIG,"eoip","dst=");
	}
		
	json_object_object_foreach(request, key, val) 
	{
		if (strcmp(key, "rule") == 0) 
		{
			subnet = json_object_get_array(val);
			num = json_object_array_length(val);
			for(i = 0; i < num; i++) 
			{
				struct json_object *subnet_x = (struct json_object *)array_list_get_idx(subnet, i);

				char *idtun = webs_get_string(subnet_x, "eoipId");
				char *name	= webs_get_string(subnet_x, "eoipName");
				char *dst = webs_get_string(subnet_x, "dstAddress");

				Uci_Add_Section(PKG_EOIP_CONFIG, "eoip");
				memset(section, 0 , sizeof(section));
				snprintf(section, sizeof(section)-1, "@eoip[%d]", i);

				Uci_Set_Str(PKG_EOIP_CONFIG, section, "name", name);
				Uci_Set_Str(PKG_EOIP_CONFIG, section, "idtun", idtun);
				Uci_Set_Str(PKG_EOIP_CONFIG, section, "dst", dst);
				Uci_Set_Str(PKG_EOIP_CONFIG, section, "enabled", "1");

				memset(tmpBuf, 0, sizeof(tmpBuf));
				snprintf(tmpBuf, sizeof(tmpBuf)-1, "zeoip%s", name);

				Uci_Add_List(PKG_NETWORK_CONFIG, "@device[0]", "ports", tmpBuf);
			}
		}
	}
	
	Uci_Commit(PKG_NETWORK_CONFIG);
	Uci_Commit(PKG_EOIP_CONFIG);
	
	doSystem("killall %s", "eoip");
	if(num > 0)
		doSystem("/etc/init.d/eoip restart &");

		doSystem("/etc/init.d/network restart &");
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "15", "reserv");
	
	return CGI_TRUE;
}

CGI_BOOL getTunnelCfg(json_object *request, FILE *conn_fp)
{
	int num=0, i=0,j,total=0;
	char rule[128]={0}, rules[1024]={0}, tmpBuf[8]={0};
	char enable[4]={0}, name[8]={0}, localVirIp[16]={0}, peerVirIp[16]={0};
	char mode[8]={0}, localExtIp[16]={0}, peerExtIp[16]={0};
	char localIface[16]={0}, ifaceType[16]={0};

	char proto_list[3][16]={"gre","ipip","mgre"};
	
	cJSON *root, *array;
	
	root = cJSON_CreateObject();
	array = cJSON_CreateArray();

	cJSON_AddItemToObject(root, "rule", array);

	for (int i = 0;  i< ARRAY_SIZE(proto_list); i++)
	{
		Uci_Get_Int(PKG_TUNNEL_CONFIG, proto_list[i], "num", &num);
		
		if(num > 0)
		{
			Uci_Get_Str(PKG_TUNNEL_CONFIG,proto_list[i],"rules",rules);
			
			for(j=0; j< num; j++)
			{
				get_nth_val_safe(j, rules, ' ', rule, sizeof(rule));
	
				get_nth_val_safe(0, rule, ',', enable, sizeof(enable));
				get_nth_val_safe(1, rule, ',', name, sizeof(name));
				get_nth_val_safe(2, rule, ',', mode, sizeof(mode));
				get_nth_val_safe(3, rule, ',', localVirIp, sizeof(localVirIp));
				get_nth_val_safe(4, rule, ',', peerVirIp, sizeof(peerVirIp));
				get_nth_val_safe(5, rule, ',', peerExtIp, sizeof(peerExtIp));
				get_nth_val_safe(6, rule, ',', localExtIp, sizeof(localExtIp));
				get_nth_val_safe(7, rule, ',', ifaceType, sizeof(ifaceType));
				get_nth_val_safe(8, rule, ',', localIface, sizeof(localIface));
				
				cJSON *sub_json = cJSON_CreateObject();
				
				
				sprintf(tmpBuf, "%d", total);
				cJSON_AddStringToObject(sub_json, "idx", tmpBuf);
				cJSON_AddStringToObject(sub_json, "enabled", enable);
				cJSON_AddStringToObject(sub_json, "name", name);
				cJSON_AddStringToObject(sub_json, "mode", mode);
				cJSON_AddStringToObject(sub_json, "localVirtualIp", localVirIp);
				cJSON_AddStringToObject(sub_json, "peerVirtualIp", peerVirIp);
				cJSON_AddStringToObject(sub_json, "peerExternIp", peerExtIp);
				
				if(strcmp(ifaceType, "interface") == 0){
					cJSON_AddStringToObject(sub_json, "interfaceType", "interface");
					cJSON_AddStringToObject(sub_json, "localInterface", localIface);
				}else{
					cJSON_AddStringToObject(sub_json, "interfaceType", "staticIp");
					cJSON_AddStringToObject(sub_json, "localExternIp", localExtIp);
				}

				total++;

				cJSON_AddItemToArray(array, sub_json);
			}	
		}
	}
	

	
	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}

CGI_BOOL setTunnelCfg(json_object *request, FILE *conn_fp)
{
	
	struct array_list *subnet;
	json_object *array_obj;
	char rule[256]={0}, rules[1024]={0};
	int i = 0, j=0, num=0;

	char proto_list[3][16]={"gre","ipip","mgre"};
	int proto_list_num[3]={0};
	
	char if_name1[32]={0},if_name2[32]={0},name_t[32]={0},proto[8]={0};

	for(i=0; i<ARRAY_SIZE(proto_list); i++)
	{
		Uci_Get_Int(PKG_TUNNEL_CONFIG, proto_list[i], "num", &num);
		if(num > 0)
		{
			Uci_Get_Str(PKG_TUNNEL_CONFIG,proto_list[i],"rules",rules);
						
			for(j = 0; j < num; j++)
			{
			
				get_nth_val_safe(j, rules, ' ', rule, sizeof(rule));
				get_nth_val_safe(1, rule, ',', name_t, sizeof(name_t));
				get_nth_val_safe(2, rule, ',', proto, sizeof(proto));

				snprintf(if_name1,sizeof(if_name1),"%s%s",proto,name_t);
				snprintf(if_name2,sizeof(if_name2),"%s%s_t",proto,name_t);
				
				Uci_Del_Section(PKG_NETWORK_CONFIG,if_name1);
				Uci_Del_Section(PKG_NETWORK_CONFIG,if_name2);
				doSystem("ifdown %s",if_name1);				
				doSystem("ifdown %s",if_name2);
				
				Uci_Del_List(PKG_TUNNEL_CONFIG, proto_list[i], "rules", rule);
			}
		}
	}

	
	Uci_Commit(PKG_NETWORK_CONFIG);

	array_obj = json_object_object_get(request, "rule");
	subnet = json_object_get_array(array_obj);	
	
	for(i = 0; i < subnet->length; i++) {
		char *enabled = webs_get_string(subnet->array[i], "enabled");
		char *name	= webs_get_string(subnet->array[i], "name");
		char *mode = webs_get_string(subnet->array[i], "mode");
		char *localVirtualIp = webs_get_string(subnet->array[i], "localVirtualIp");
		char *peerVirtualIp  = webs_get_string(subnet->array[i], "peerVirtualIp");
		char *peerExternIp = webs_get_string(subnet->array[i], "peerExternIp");
		char *localExternIp = webs_get_string(subnet->array[i], "localExternIp");
		char *interfaceType  = webs_get_string(subnet->array[i], "interfaceType");
		char *localInterface = webs_get_string(subnet->array[i], "localInterface");

		if(strcmp(mode,"gre") == 0)
		{
		
			snprintf(rule, sizeof(rule)-1, "%s,%s,%s,%s,%s,%s,%s,%s,%s", enabled, \
				name, mode, localVirtualIp, peerVirtualIp, peerExternIp, localExternIp, \
				interfaceType, localInterface);
			
			Uci_Add_List(PKG_TUNNEL_CONFIG, proto_list[0], "rules", rule);
			proto_list_num[0]++;
		}
		else if(strcmp(mode,"ipip") == 0)
		{
			snprintf(rule, sizeof(rule)-1, "%s,%s,%s,%s,%s,%s,%s,%s,%s", enabled, \
				name, mode, localVirtualIp, peerVirtualIp, peerExternIp, localExternIp, \
				interfaceType, localInterface);

				
			Uci_Add_List(PKG_TUNNEL_CONFIG, proto_list[1], "rules", rule);
			proto_list_num[1]++;
		}
		else if(strcmp(mode,"mgre") == 0)
		{
			snprintf(rule, sizeof(rule)-1, "%s,%s,%s,%s,%s,%s,%s,%s,%s", enabled, \
				name, mode, localVirtualIp, peerVirtualIp, peerExternIp, localExternIp, \
				interfaceType, localInterface);
		
			Uci_Add_List(PKG_TUNNEL_CONFIG, proto_list[2], "rules", rule);
			proto_list_num[2]++;
		}
		
	}

	for(i=0; i<ARRAY_SIZE(proto_list); i++)
	{
		char str[8]={0};
		snprintf(str, sizeof(str)-1,"%d",proto_list_num[i]);
		Uci_Set_Str(PKG_TUNNEL_CONFIG, proto_list[i], "num", str);
	}

	Uci_Commit(PKG_TUNNEL_CONFIG);
	
	
	set_lktos_effect("tunnel");

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "25", "reserv");

	return CGI_TRUE;
}


CGI_BOOL getIpsecHost2NetCfg(json_object *request, FILE *conn_fp)
{
	char ipsecH2nEnable[4]={0},left[64]={0},leftid[128]={0},leftsubnet[64]={0},psk[256]={0},keyexchange[32]={0},ike_cipher[256]={0};
	char ikelifetime[16]={0},esp_cipher[256]={0},dpdaction[16]={0},lifetime[16]={0},compress[16]={0},rekey[16]={0},dpddelay[16]={0},dpdtimeout[16]={0};

	cJSON *root;

	root = cJSON_CreateObject();

	Uci_Get_Str(PKG_IPSEC_CONFIG, "host2net", "enable",ipsecH2nEnable);

	cJSON_AddStringToObject(root, "ipsecH2nEnable", ipsecH2nEnable);
	//if(atoi(ipsecH2nEnable) == 1)
	//{
		Uci_Get_Str(PKG_IPSEC_CONFIG, "host2net", "ipsecH2nLeft",left);
		Uci_Get_Str(PKG_IPSEC_CONFIG, "host2net", "ipsecH2nLeftid",leftid);
		Uci_Get_Str(PKG_IPSEC_CONFIG, "host2net", "ipsecH2nLeftsubnet",leftsubnet);
		Uci_Get_Str(PKG_IPSEC_CONFIG, "host2net", "ipsecH2nPsk",psk);
		Uci_Get_Str(PKG_IPSEC_CONFIG, "host2net", "ipsecH2nKeyexchange",keyexchange);
		Uci_Get_Str(PKG_IPSEC_CONFIG, "host2net", "ipsecH2nIkeCipher",ike_cipher);
		Uci_Get_Str(PKG_IPSEC_CONFIG, "host2net", "ipsecH2nIkelifetime",ikelifetime);
		Uci_Get_Str(PKG_IPSEC_CONFIG, "host2net", "ipsecH2nEspCipher",esp_cipher);
		Uci_Get_Str(PKG_IPSEC_CONFIG, "host2net", "ipsecH2nDpdaction",dpdaction);
		Uci_Get_Str(PKG_IPSEC_CONFIG, "host2net", "ipsecH2nLifetime",lifetime);
		Uci_Get_Str(PKG_IPSEC_CONFIG, "host2net", "ipsecH2nCompress",compress);
		Uci_Get_Str(PKG_IPSEC_CONFIG, "host2net", "ipsecH2nRekey",rekey);
		Uci_Get_Str(PKG_IPSEC_CONFIG, "host2net", "ipsecH2nDpddelay",dpddelay);
		Uci_Get_Str(PKG_IPSEC_CONFIG, "host2net", "ipsecH2nDpdtimeout",dpdtimeout);
	
		cJSON_AddStringToObject(root, "ipsecH2nLeft", left);
		cJSON_AddStringToObject(root, "ipsecH2nLeftid", leftid);
		cJSON_AddStringToObject(root, "ipsecH2nLeftsubnet", leftsubnet);
		cJSON_AddStringToObject(root, "ipsecH2nPsk", psk);
		cJSON_AddStringToObject(root, "ipsecH2nKeyexchange", keyexchange);
		cJSON_AddStringToObject(root, "ipsecH2nIkeCipher", ike_cipher);
		cJSON_AddStringToObject(root, "ipsecH2nIkelifetime", ikelifetime);
		cJSON_AddStringToObject(root, "ipsecH2nEspCipher", esp_cipher);
		cJSON_AddStringToObject(root, "ipsecH2nDpdaction", dpdaction);
		cJSON_AddStringToObject(root, "ipsecH2nLifetime", lifetime);
		cJSON_AddStringToObject(root, "ipsecH2nCompress", compress);
		cJSON_AddStringToObject(root, "ipsecH2nRekey", rekey);
		cJSON_AddStringToObject(root, "ipsecH2nDpddelay", dpddelay);
		cJSON_AddStringToObject(root, "ipsecH2nDpdtimeout", dpdtimeout);
	//}
	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}


CGI_BOOL setIpsecHost2NetCfg(json_object *request, FILE *conn_fp)
{
	char *ipsecH2nEnable = webs_get_string(request, "ipsecH2nEnable");
	
	Uci_Set_Str(PKG_IPSEC_CONFIG, "host2net", "enable",ipsecH2nEnable);
	
	if(atoi(ipsecH2nEnable) == 1) {
	
		char *left = webs_get_string(request, "ipsecH2nLeft");
		char *leftid = webs_get_string(request, "ipsecH2nLeftid");
		char *leftsubnet = webs_get_string(request, "ipsecH2nLeftsubnet");
		char *psk = webs_get_string(request, "ipsecH2nPsk");
		char *keyexchange = webs_get_string(request, "ipsecH2nKeyexchange");
		char *ike_cipher = webs_get_string(request, "ipsecH2nIkeCipher");
		char *ikelifetime = webs_get_string(request, "ipsecH2nIkelifetime");
		char *esp_cipher = webs_get_string(request, "ipsecH2nEspCipher");
		char *dpdaction = webs_get_string(request, "ipsecH2nDpdaction");
		char *dpddelay = webs_get_string(request, "ipsecH2nDpddelay");
		char *dpdtimeout = webs_get_string(request, "ipsecH2nDpdtimeout");
		char *lifetime = webs_get_string(request, "ipsecH2nLifetime");
		char *compress = webs_get_string(request, "ipsecH2nCompress");
		char *rekey = webs_get_string(request, "ipsecH2nRekey");
	
		Uci_Set_Str(PKG_IPSEC_CONFIG, "net2net", "enable","0");
		Uci_Set_Str(PKG_IPSEC_CONFIG, "ipsec_l2tp", "ipsecL2tpEnable","0");
		Uci_Set_Str(PKG_IPSEC_CONFIG, "ipsec_l2tp", "ipsecXauthEnable","0");
		
		Uci_Set_Str(PKG_IPSEC_CONFIG, "host2net", "ipsecH2nLeft",left);
		Uci_Set_Str(PKG_IPSEC_CONFIG, "host2net", "ipsecH2nLeftid",leftid);
		Uci_Set_Str(PKG_IPSEC_CONFIG, "host2net", "ipsecH2nLeftsubnet",leftsubnet);
		Uci_Set_Str(PKG_IPSEC_CONFIG, "host2net", "ipsecH2nPsk",psk);
		Uci_Set_Str(PKG_IPSEC_CONFIG, "host2net", "ipsecH2nKeyexchange",keyexchange);
		Uci_Set_Str(PKG_IPSEC_CONFIG, "host2net", "ipsecH2nIkeCipher",ike_cipher);
		Uci_Set_Str(PKG_IPSEC_CONFIG, "host2net", "ipsecH2nIkelifetime",ikelifetime);
		Uci_Set_Str(PKG_IPSEC_CONFIG, "host2net", "ipsecH2nEspCipher",esp_cipher);
		Uci_Set_Str(PKG_IPSEC_CONFIG, "host2net", "ipsecH2nDpdaction",dpdaction);
		Uci_Set_Str(PKG_IPSEC_CONFIG, "host2net", "ipsecH2nLifetime",lifetime);
		Uci_Set_Str(PKG_IPSEC_CONFIG, "host2net", "ipsecH2nCompress",compress);
		Uci_Set_Str(PKG_IPSEC_CONFIG, "host2net", "ipsecH2nRekey",rekey);

		
		if(atoi(dpdaction) != 0) {
			Uci_Set_Str(PKG_IPSEC_CONFIG, "host2net", "ipsecH2nDpddelay",dpddelay);
			Uci_Set_Str(PKG_IPSEC_CONFIG, "host2net", "ipsecH2nDpdtimeout",dpdtimeout);
		}
	}
	
	Uci_Commit(PKG_IPSEC_CONFIG);

	//set_lktos_effect("restart_ipsec");
	set_lktos_effect("ipsecfw");
	set_lktos_effect("ipsec");
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");
	
	return CGI_TRUE;

}

CGI_BOOL getIpsecHeartCheckCfg(json_object *request, FILE *conn_fp)
{
	char enable[4]={0},heartCheckIp[32]={0},heartCheckTime[4]={0},debugOption[1024]={0};
	cJSON *root = cJSON_CreateObject();

	Uci_Get_Str(PKG_IPSEC_CONFIG, "ipsec_heart", "heartCheckEnable",enable);
	Uci_Get_Str(PKG_IPSEC_CONFIG, "ipsec_heart", "heartCheckIp",heartCheckIp);
	Uci_Get_Str(PKG_IPSEC_CONFIG, "ipsec_heart", "heartCheckTime",heartCheckTime);
	Uci_Get_Str(PKG_IPSEC_CONFIG, "ipsec_heart", "debugOption",debugOption);

	cJSON_AddStringToObject(root, "heartCheckEnable", enable);
	cJSON_AddStringToObject(root, "heartCheckIp", heartCheckIp);
	cJSON_AddStringToObject(root, "heartCheckTime", heartCheckTime);
	cJSON_AddStringToObject(root, "interface", "dmn 4, mgr 4, ike 4, chd 4, job 4, cfg 4, knl 4, net 4, asn 4, enc 4, lib 4, esp 4, tls 4, tnc 4, imc 4, imv 4, pts 4");
	cJSON_AddStringToObject(root, "debugAction", "/web/cgi-bin/ExportSyslog.log");


	cJSON_AddStringToObject(root, "debugOption", debugOption);

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}


CGI_BOOL setIpsechHeartCheckCfg(json_object *request, FILE *conn_fp)
{
	char *debugOption=NULL;
	char *enable = webs_get_string(request, "heartCheckEnable");

	if(atoi(enable) == 1){

		char *heartCheckIp = webs_get_string(request, "heartCheckIp");
		char *heartCheckTime = webs_get_string(request, "heartCheckTime");

		Uci_Set_Str(PKG_IPSEC_CONFIG, "ipsec_heart", "heartCheckIp",heartCheckIp);
		Uci_Set_Str(PKG_IPSEC_CONFIG, "ipsec_heart", "heartCheckTime",heartCheckTime);
	}

	debugOption = webs_get_string(request, "debugOption");

	if(strlen(debugOption) > 0){
		Uci_Set_Str(PKG_IPSEC_CONFIG, "ipsec_heart", "debugOption",debugOption);
	}else{
		Uci_Set_Str(PKG_IPSEC_CONFIG, "ipsec_heart", "debugOption","");
	}
	
	Uci_Set_Str(PKG_IPSEC_CONFIG, "ipsec_heart", "heartCheckEnable",enable);
	Uci_Commit(PKG_IPSEC_CONFIG);

// reload ipsec /  debug  log
	set_lktos_effect("restart_ipsec");

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");
	
	return CGI_TRUE;
}



CGI_BOOL getIpsecCertCfg(json_object *request, FILE *conn_fp)
{
	char certs_en[256]={0},certs_cou_name[256]={0},certs_o_name[256]={0},certs_com_name[256]={0};

	cJSON *root = cJSON_CreateObject();

	Uci_Get_Str(PKG_IPSEC_CONFIG, "ipsec_certs", "ipsec_certs_enable",certs_en);
	Uci_Get_Str(PKG_IPSEC_CONFIG, "ipsec_certs", "ipsec_certs_country_name",certs_cou_name);
	Uci_Get_Str(PKG_IPSEC_CONFIG, "ipsec_certs", "ipsec_certs_organization_name",certs_o_name);
	Uci_Get_Str(PKG_IPSEC_CONFIG, "ipsec_certs", "ipsec_certs_common_name",certs_com_name);

	cJSON_AddStringToObject(root, "certEnable",certs_en );
	cJSON_AddStringToObject(root, "countryName",certs_cou_name );
	cJSON_AddStringToObject(root, "organizationName",certs_o_name);
	cJSON_AddStringToObject(root, "commonName", certs_com_name);
	cJSON_AddStringToObject(root, "dowanCertAction", "/cgi-bin/ExportIpsecCert.tar.gz");

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;

}


CGI_BOOL getIpsecStatus(json_object *request, FILE *conn_fp)
{
	cJSON *root = cJSON_CreateObject();
	char Log[LONGLONG_BUFF_LEN] = {0};
	char tmpBuf[100];

	snprintf(tmpBuf, 100, "echo ipsec statusall > %s", "/tmp/ipsecStatus");
	doSystem(tmpBuf);

	snprintf(tmpBuf, 100, "ipsec statusall >> %s", "/tmp/ipsecStatus");
	doSystem(tmpBuf);

	snprintf(tmpBuf, 100, "echo ip route show table 220  >> %s", "/tmp/ipsecStatus");
	doSystem(tmpBuf);

	snprintf(tmpBuf, 100, "ip route show table 220 >> %s", "/tmp/ipsecStatus");
	doSystem(tmpBuf);

	f_read("/tmp/ipsecStatus", Log,sizeof(Log));
	cJSON_AddStringToObject(root, "ipsecStatusLog", Log);

	send_cgi_json_respond(conn_fp, root);
	
	return CGI_TRUE;
}



CGI_BOOL getIpsecNet2NetCfg(json_object *request, FILE *conn_fp)
{
	int i = 0, num = 0;
	char tmpBuf[32] = {0}, section[16]={0};
	cJSON *connArray, *connEntry;
	cJSON *root = cJSON_CreateObject();

	get_uci2json(root,PKG_IPSEC_CONFIG,  "net2net",   "enable", "ipsecN2nEnable");
	
	connArray = cJSON_CreateArray();
	cJSON_AddItemToObject(root, "subnet", connArray);
	
	Uci_Get_Int(PKG_IPSEC_CONFIG, "net2net", "rules_num", &num);

	for(i = 0; i < num; i++) {

		connEntry = cJSON_CreateObject();
		cJSON_AddNumberToObject(connEntry, "idx", i + 1);

		memset(section,0,sizeof(section));
		snprintf(section,sizeof(section)-1,"@conn[%d]", i);

		get_uci2json(connEntry,PKG_IPSEC_CONFIG,  section,   "name", "ipsecName");
		
		get_uci2json(connEntry,PKG_IPSEC_CONFIG,  section,   "auto", "ipsecAuto");

		get_uci2json(connEntry,PKG_IPSEC_CONFIG,  section,   "auth", "ipsecAuthMode");


		get_uci2json(connEntry,PKG_IPSEC_CONFIG,  section,   "aggressive", "ipsecAggressive");

		get_uci2json(connEntry,PKG_IPSEC_CONFIG,  section,   "bind_iface", "ipsecBindIf");

		get_uci2json(connEntry,PKG_IPSEC_CONFIG,  section,   "left", "ipsecLeft");


		get_uci2json(connEntry,PKG_IPSEC_CONFIG,  section,   "left_id", "ipsecLeftid");

		get_uci2json(connEntry,PKG_IPSEC_CONFIG,  section,   "right", "ipsecRight");

		get_uci2json(connEntry,PKG_IPSEC_CONFIG,  section,   "right_id", "ipsecRightid");
		
		get_uci2json(connEntry,PKG_IPSEC_CONFIG,  section,   "left_subnet", "ipsecLeftsubnet");

		get_uci2json(connEntry,PKG_IPSEC_CONFIG,  section,   "right_subnet", "ipsecRightsubnet");

		get_uci2json(connEntry,PKG_IPSEC_CONFIG,  section,   "psk", "ipsecPsk");

		get_uci2json(connEntry,PKG_IPSEC_CONFIG,  section,   "key_exchange", "ipsecKeyexchange");

		get_uci2json(connEntry,PKG_IPSEC_CONFIG,  section,   "ike_lifetime", "ipsecIkelifetime");

		get_uci2json(connEntry,PKG_IPSEC_CONFIG,  section,   "ike_proposals", "ipsecIkeCipher");

		get_uci2json(connEntry,PKG_IPSEC_CONFIG,  section,   "esp_proposals", "ipsecEspCipher");

		get_uci2json(connEntry,PKG_IPSEC_CONFIG,  section,   "dpd_action", "ipsecDpdaction");
		
		get_uci2json(connEntry,PKG_IPSEC_CONFIG,  section,   "dpd_delay", "ipsecDpddelay");

		get_uci2json(connEntry,PKG_IPSEC_CONFIG,  section,   "dpd_timeout", "ipsecDpdtimeout");

		

		get_uci2json(connEntry,PKG_IPSEC_CONFIG,  section,   "lifetime", "ipsecLifetime");

		get_uci2json(connEntry,PKG_IPSEC_CONFIG,  section,   "compress", "ipsecCompress");

		get_uci2json(connEntry,PKG_IPSEC_CONFIG,  section,   "rekey", "ipsecRekey");

		get_num_uci2json(connEntry, PKG_IPSEC_CONFIG, section, "key_payload_close", "keyPayloadOff");
		
		//if(ipsec_status(left, leftId, right, rightId, leftNset, rightNet) == 1)
		if(0)
			cJSON_AddStringToObject(connEntry, "ipsecStatus", "1");
		else
			cJSON_AddStringToObject(connEntry, "ipsecStatus", "0");

		snprintf(tmpBuf, RESULT_STR_LEN, "delRule%d", i);
		cJSON_AddStringToObject(connEntry, "delRuleName", tmpBuf);

		cJSON_AddItemToArray(connArray, connEntry);
	}


	send_cgi_json_respond(conn_fp, root);
	return CGI_TRUE;
}




CGI_BOOL setIpsecNet2NetCfg(json_object *request, FILE *conn_fp)
{
	int idx = 0, enable = 0, addEffect = 0, modinum = 0, value=0;
	char section[32]={0}, buf[32]={0};
	//const char *lan_ip = nvram_safe_get("lan_ipaddr");

	addEffect = atoi(webs_get_string(request, "addEffect"));

	enable = atoi(webs_get_string(request, "ipsecN2nEnable"));
	
	modinum = (atoi(webs_get_string(request, "idx")) - 1);

	if(addEffect == 0) {
		snprintf(buf, sizeof(buf)-1, "%d", enable);
		Uci_Set_Str(PKG_IPSEC_CONFIG, "net2net", "enable", buf);
		if(enable == 1) {
			Uci_Set_Str(PKG_IPSEC_CONFIG, "host2net", "enable", "0");
		}

		Uci_Commit(PKG_IPSEC_CONFIG);
	} else if(addEffect == 1) {
		Uci_Get_Int(PKG_IPSEC_CONFIG, "net2net", "rules_num", &idx);
		Uci_Add_Section(PKG_IPSEC_CONFIG,"conn");
		memset(section,0,sizeof(section));
		snprintf(section,sizeof(section)-1,"@conn[%d]", idx);

#if 0
		if(nvram_get_int("ipsec_cert_support") == 1){
			sprintf(paramName, "ipsec_auth_mode_x%d", idx);
			nvram_set(paramName, webs_get_string(request, "ipsecAuthMode") );
		}
#endif
	
		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "name", webs_get_string(request, "ipsecName"));
		
		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "auto", webs_get_string(request, "ipsecAuto"));
		
		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "aggressive", webs_get_string(request, "ipsecAggressive"));

		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "bind_iface", webs_get_string(request, "ipsecBindIf"));
		
		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "left", webs_get_string(request, "ipsecLeft"));

		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "left_id", webs_get_string(request, "ipsecLeftid"));
		
		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "right", webs_get_string(request, "ipsecRight"));

		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "right_id", webs_get_string(request, "ipsecRightid"));
		
		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "left_subnet", webs_get_string(request, "ipsecLeftsubnet"));
		
		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "right_subnet", webs_get_string(request, "ipsecRightsubnet"));
		
		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "psk", webs_get_string(request, "ipsecPsk"));
		
		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "key_exchange", webs_get_string(request, "ipsecKeyexchange"));

		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "ike_lifetime", webs_get_string(request, "ipsecIkelifetime"));
		
		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "ike_proposals", webs_get_string(request, "ipsecIkeCipher"));

		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "esp_proposals", webs_get_string(request, "ipsecEspCipher"));
		
		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "dpd_action", webs_get_string(request, "ipsecDpdaction"));
		
		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "dpd_delay", webs_get_string(request, "ipsecDpddelay"));
		
		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "dpd_timeout", webs_get_string(request, "ipsecDpdtimeout"));
		
		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "lifetime", webs_get_string(request, "ipsecLifetime"));

		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "compress", webs_get_string(request, "ipsecCompress"));
		
		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "rekey", webs_get_string(request, "ipsecRekey"));

		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "key_payload_close", webs_get_string(request, "keyPayloadOff"));
		
		snprintf(buf, sizeof(buf)-1, "%d", idx+1);
		Uci_Set_Str(PKG_IPSEC_CONFIG, "net2net", "rules_num", buf);
		
		Uci_Commit(PKG_IPSEC_CONFIG);
		
	} else if(addEffect == 2) {

		memset(section,0,sizeof(section));
		snprintf(section,sizeof(section)-1,"@conn[%d]", modinum);

		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "name", webs_get_string(request, "ipsecName"));
		
		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "auto", webs_get_string(request, "ipsecAuto"));
		
		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "aggressive", webs_get_string(request, "ipsecAggressive"));

		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "bind_iface", webs_get_string(request, "ipsecBindIf"));
		
		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "left", webs_get_string(request, "ipsecLeft"));

		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "left_id", webs_get_string(request, "ipsecLeftid"));
		
		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "right", webs_get_string(request, "ipsecRight"));

		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "right_id", webs_get_string(request, "ipsecRightid"));
		
		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "left_subnet", webs_get_string(request, "ipsecLeftsubnet"));
		
		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "right_subnet", webs_get_string(request, "ipsecRightsubnet"));
		
		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "psk", webs_get_string(request, "ipsecPsk"));
		
		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "key_exchange", webs_get_string(request, "ipsecKeyexchange"));

		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "ike_lifetime", webs_get_string(request, "ipsecIkelifetime"));
		
		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "ike_proposals", webs_get_string(request, "ipsecIkeCipher"));

		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "esp_proposals", webs_get_string(request, "ipsecEspCipher"));
		
		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "dpd_action", webs_get_string(request, "ipsecDpdaction"));
		
		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "dpd_delay", webs_get_string(request, "ipsecDpddelay"));
		
		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "dpd_timeout", webs_get_string(request, "ipsecDpdtimeout"));
		
		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "lifetime", webs_get_string(request, "ipsecLifetime"));

		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "compress", webs_get_string(request, "ipsecCompress"));
		
		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "rekey", webs_get_string(request, "ipsecRekey"));

		Uci_Set_Str(PKG_IPSEC_CONFIG, section, "key_payload_close", webs_get_string(request, "keyPayloadOff"));
		
		Uci_Commit(PKG_IPSEC_CONFIG);
	}

	set_lktos_effect("ipsecfw");
	set_lktos_effect("ipsec");
	send_cgi_set_respond(conn_fp, TRUE_W, "", "", "10", "reserv");
	
	return CGI_TRUE;
}

CGI_BOOL delIpsecNet2NetCfg(json_object *request, FILE *conn_fp)
{
	char buf[4]={0};
	int num = uci_del_list_item(PKG_IPSEC_CONFIG,"conn","auto=",request);
	snprintf(buf, sizeof(buf), "%d", num);
	Uci_Set_Str(PKG_IPSEC_CONFIG, "net2net", "rules_num", buf);
	
	Uci_Commit(PKG_IPSEC_CONFIG);
	set_lktos_effect("ipsecfw");
	set_lktos_effect("ipsec");

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "10", "reserv");

	return CGI_TRUE;
}


CGI_BOOL getTfCfg(json_object *request, FILE *conn_fp)
{
	char *text_log=NULL;
	char tmpBuf[256]={0},path[256]={0};
	char log_buf[1024*256] = {0};

	cJSON *root = cJSON_CreateObject();
	
	int err = GetUDiskMountPath(path,"/tmp/monut_file_info","mmcblk0p");
	if(err == 0){
		cJSON_AddStringToObject(root, "tfStatus","1");
	}else{
		cJSON_AddStringToObject(root, "tfStatus","0");
	}

	getCmdStr("ifconfig | grep tun0 | wc -l", tmpBuf, sizeof(tmpBuf));
	
	if(strlen(tmpBuf) > 0)
	{
		cJSON_AddStringToObject(root, "vpnStatus",tmpBuf);
	}else{
		cJSON_AddStringToObject(root, "vpnStatus","0");
	}

	//log
	if( read_log( "/tmp/tvpn.log", log_buf ) != -1 )
	{
		cJSON_AddStringToObject(root,"tfLog",log_buf); 
	}else{			
		cJSON_AddStringToObject(root,"tfLog",""); 
	}

	get_uci2json(root,PKG_IPSEC_CONFIG,"ipsec_tf","vpns_tf_ip","ip");
	get_uci2json(root,PKG_IPSEC_CONFIG,"ipsec_tf","vpns_tf_port","port");

	send_cgi_json_respond(conn_fp, root);
	
	return CGI_TRUE;
}

CGI_BOOL setTfCfg(json_object *request, FILE *conn_fp)
{
    char * ip   = webs_get_string(request, "ip");
    char * port = webs_get_string(request, "port");	
	
	Uci_Get_Str(PKG_IPSEC_CONFIG,"ipsec_tf","vpns_tf_ip",ip);
	Uci_Get_Str(PKG_IPSEC_CONFIG,"ipsec_tf","vpns_tf_port",port);

	Uci_Commit(PKG_IPSEC_CONFIG);
	//set_lktos_effect("refresh_tfvpn");
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

	return CGI_TRUE;
}

int uci_del_muti_config_all(int title,char *section_name,char *keyword)
{
   int current_num = 0,i = 0;
   char *value,cmd_buf[128] = {0},name_buf[16] = {0},section[64] = {0};

   snprintf(cmd_buf,sizeof(cmd_buf)-1,"uci show %s | grep %s | grep %s |  wc -l",PKG_ID_TOFILE(title),section_name,keyword);
   current_num = get_cmd_val(cmd_buf);

   for(i = current_num; i > 0; i--) {
           snprintf(section,sizeof(section)-1,"%s%d",section_name,i-1);
           cs_uci_force_refresh_context(PKG_NETWORK_CONFIG);
           Uci_Del_Section(title,section);
   }

   return current_num;
}


CGI_BOOL getVpnMultiClientCfg(json_object *request, FILE *conn_fp)
{
	cJSON *root,*connArray, *netmaskArray,*item,*netmaskObj;
	root = cJSON_CreateObject();

	connArray = cJSON_CreateArray();

	char status_file[32]={0};
	char tmp_buf[8]={0}, ifname[16]={0}, proto[8]={0}, ppp_ip[16]={0};
	char paramName[OPTION_STR_LEN]={0}, section[OPTION_STR_LEN]={0};
	int i=0, num = 0, rule = 0, idx = 0;

	cJSON_AddStringToObject(root, "addEffect", "1");
	cJSON_AddItemToObject(root, "subnet", connArray);

	num = get_cmd_val("uci show network | grep vpn | grep server= |  wc -l");

	for(i=0;i<num;i++)
	{
		snprintf(section,OPTION_STR_LEN,"vpn%d",i);

		item = cJSON_CreateObject();
		
		get_uci2json(item,PKG_NETWORK_CONFIG,section,"type","type");
		get_uci2json(item,PKG_NETWORK_CONFIG,section,"enable","enable");
		get_uci2json(item,PKG_NETWORK_CONFIG,section,"server","serverIp");
		get_uci2json(item,PKG_NETWORK_CONFIG,section,"username","user");
		get_uci2json(item,PKG_NETWORK_CONFIG,section,"password","pass");
		get_uci2json(item,PKG_NETWORK_CONFIG,section,"defaultroute","default");
		get_uci2json(item,PKG_NETWORK_CONFIG,section,"dmzIp","dmzIp");
		get_uci2json(item,PKG_NETWORK_CONFIG,section,"ipMasq","ipMasq");
		get_uci2json(item,PKG_NETWORK_CONFIG,section,"lanMasq","lanMasq");

		memset(tmp_buf, 0, sizeof(tmp_buf));
		memset(status_file, 0, sizeof(status_file));
		snprintf(status_file, sizeof(status_file)-1, "/tmp/vpn_status/%s", section);
		datconf_get_by_key(status_file, section, tmp_buf, sizeof(tmp_buf));
		if(atoi(tmp_buf) > 0){
			cJSON_AddStringToObject(item, "state", "1");
			Uci_Get_Str(PKG_NETWORK_CONFIG, section, "proto", proto);
			snprintf(ifname, sizeof(ifname)-1, "%s-%s", proto, section);
			get_ifname_ipaddr(ifname, ppp_ip);
			cJSON_AddStringToObject(item, "addr", ppp_ip);
		}else{
			cJSON_AddStringToObject(item, "state", "0");
			cJSON_AddStringToObject(item, "addr", "");
		}
		
		get_uci2json(item,PKG_NETWORK_CONFIG,section,"localIp","localIp");
		get_uci2json(item,PKG_NETWORK_CONFIG,section,"tunnelSecret","tunnelSecret");
		get_uci2json(item,PKG_NETWORK_CONFIG,section,"tunnelLocalHostname","localHostname");
		get_uci2json(item,PKG_NETWORK_CONFIG,section,"tunnelRemoteHostname","remoteHostname");

		get_uci2json(item,PKG_NETWORK_CONFIG,section,"mppe","mppe");

		Uci_Get_Int(PKG_NETWORK_CONFIG, section, "netMaskNum",&rule);
		
		netmaskArray = cJSON_CreateArray();
		
		for(idx = 0; idx < rule; idx++){
			netmaskObj = cJSON_CreateObject();

			sprintf(paramName,"net%d",idx);
			get_uci2json(netmaskObj,PKG_NETWORK_CONFIG,section,paramName,"net");

			sprintf(paramName,"mask%d",idx);
			get_uci2json(netmaskObj,PKG_NETWORK_CONFIG,section,paramName,"mask");
			cJSON_AddItemToArray(netmaskArray,netmaskObj);
		}
		
		if(rule == 0){
			netmaskObj = cJSON_CreateObject();
			cJSON_AddStringToObject(netmaskObj, "net", "");
			cJSON_AddStringToObject(netmaskObj, "mask", "");
			cJSON_AddItemToArray(netmaskArray,netmaskObj);
		}
		
		cJSON_AddItemToObject(item, "netMask", netmaskArray);

		cJSON_AddItemToArray(connArray,item);
	}

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;

}



CGI_BOOL setVpnMultiClientCfg(json_object *request, FILE *conn_fp)
{

	struct array_list *subnet;
	struct array_list *netMask;
	json_object *array_obj;
	char *mppe, *net, *mask, *type;
	
	char cmd[128]={0},str_num[16]={0},tmpBuf[16]={0};
	char section[OPTION_STR_LEN] = {0},  paramName[OPTION_STR_LEN] = {0};
	int num = 0, idx = 0, unit = 0, addEffect=0, count=0, enable=0,disable_num=0;
	
	addEffect = webs_get_int(request, "addEffect");

	num = get_cmd_val("uci show network | grep vpn | grep server= |  wc -l");

	if(num > 0){
		uci_del_muti_config_all(PKG_NETWORK_CONFIG,"vpn","server=");
	}
	
	json_object_object_foreach(request, key, val) {
		if (strcmp(key, "subnet") == 0) {

			subnet = json_object_get_array(val);
			num = json_object_array_length(val);

			for(idx = 0; idx < num; idx++) {

				struct json_object *subnet_x = (struct json_object *)array_list_get_idx(subnet, idx);
				
				snprintf(cmd,sizeof(cmd)-1,"uci set network.vpn%d=interface",idx);
				CsteSystem(cmd,CSTE_PRINT_CMD);
				memset(section,0,sizeof(section));
				snprintf(section,sizeof(section)-1,"vpn%d",idx);
				
				type=webs_get_string(subnet_x, "type");//0:pptp; 1:l2tp
				Uci_Set_Str(PKG_NETWORK_CONFIG, section, "type", type);

				enable=webs_get_int(subnet_x, "enable");
				memset(tmpBuf, 0, sizeof(tmpBuf));
				if(enable == VPN_MULTI_SWITCH_ON){
					sprintf(tmpBuf, "%d", VPN_MULTI_SWITCH_ON);
				}else{
					sprintf(tmpBuf, "%d", VPN_MULTI_SWITCH_OFF);
					disable_num++;
				}	
				Uci_Set_Str(PKG_NETWORK_CONFIG, section, "enable", tmpBuf);

				Uci_Set_Str(PKG_NETWORK_CONFIG, section, "server",webs_get_string(subnet_x, "serverIp"));
				Uci_Set_Str(PKG_NETWORK_CONFIG, section, "username", webs_get_string(subnet_x, "user"));
				Uci_Set_Str(PKG_NETWORK_CONFIG, section, "password", webs_get_string(subnet_x, "pass"));

				Uci_Set_Str(PKG_NETWORK_CONFIG, section, "defaultroute", webs_get_string(subnet_x, "default"));
				Uci_Set_Str(PKG_NETWORK_CONFIG, section, "dmzIp", webs_get_string(subnet_x, "dmzIp"));
				Uci_Set_Str(PKG_NETWORK_CONFIG, section, "ipMasq", webs_get_string(subnet_x, "ipMasq"));
				Uci_Set_Str(PKG_NETWORK_CONFIG, section, "lanMasq", webs_get_string(subnet_x, "lanMasq"));

				if(atoi(type) == VPN_MULIT_TYPE_L2TP){
					if(enable == VPN_MULTI_SWITCH_ON)
						Uci_Set_Str(PKG_NETWORK_CONFIG, section, "proto", "l2tp");
					else
						Uci_Set_Str(PKG_NETWORK_CONFIG, section, "proto", "");
									
					if(strlen(webs_get_string(subnet_x, "localIp")))
						Uci_Set_Str(PKG_NETWORK_CONFIG, section, "localIp", webs_get_string(subnet_x, "localIp"));
					else
						Uci_Set_Str(PKG_NETWORK_CONFIG, section, "localIp", "");

					if(strlen(webs_get_string(subnet_x, "tunnelSecret")))
						Uci_Set_Str(PKG_NETWORK_CONFIG, section, "tunnelSecret", webs_get_string(subnet_x, "tunnelSecret"));
					else
						Uci_Set_Str(PKG_NETWORK_CONFIG, section, "tunnelSecret", "");

					if(strlen(webs_get_string(subnet_x, "localHostname")))
						Uci_Set_Str(PKG_NETWORK_CONFIG, section, "tunnelLocalHostname", webs_get_string(subnet_x, "localHostname"));
					else
						Uci_Set_Str(PKG_NETWORK_CONFIG, section, "tunnelLocalHostname", "");

					if(strlen(webs_get_string(subnet_x, "remoteHostname")))
						Uci_Set_Str(PKG_NETWORK_CONFIG, section, "tunnelRemoteHostname", webs_get_string(subnet_x, "remoteHostname"));
					else
						Uci_Set_Str(PKG_NETWORK_CONFIG, section, "tunnelRemoteHostname", "");

					Uci_Set_Str(PKG_NETWORK_CONFIG, section, "mppe", "0");
				}
				else{
					mppe = webs_get_string(subnet_x, "mppe");
					Uci_Set_Str(PKG_NETWORK_CONFIG, section, "mppe", mppe);
					if(atoi(mppe) == 1)
						Uci_Set_Str(PKG_NETWORK_CONFIG, section, "pppd_options", "nomppe");
					else
						Uci_Set_Str(PKG_NETWORK_CONFIG, section, "pppd_options", "mppe required,stateless");
					
					if(enable == VPN_MULTI_SWITCH_ON)
						Uci_Set_Str(PKG_NETWORK_CONFIG, section, "proto", "pptp");
					else
						Uci_Set_Str(PKG_NETWORK_CONFIG, section, "proto", "");
				}				

				Uci_Set_Str(PKG_NETWORK_CONFIG, section, "keepalive", "5 30");
				
				array_obj = json_object_object_get(subnet_x, "netMask");
				netMask = json_object_get_array(array_obj);

				if(netMask->length > 0) {
					count=0;
					for(unit = 0; unit < netMask->length; unit++) {
						net=webs_get_string(netMask->array[unit], "net");
						mask=webs_get_string(netMask->array[unit], "mask");
						if(strlen(net) == 0 || strlen(mask)==0)
							continue;
						
						sprintf(paramName, "net%d",unit);
						Uci_Set_Str(PKG_NETWORK_CONFIG, section, paramName, net);
				
						sprintf(paramName, "mask%d",unit);						
						Uci_Set_Str(PKG_NETWORK_CONFIG, section, paramName, mask);

						count++;
					}
					
					sprintf(str_num,"%d",count);
					Uci_Set_Str(PKG_NETWORK_CONFIG, section, "netMaskNum",str_num);
				}else{
					Uci_Set_Str(PKG_NETWORK_CONFIG, section, "netMaskNum","0");
				}

			}

		}
	}
	Uci_Commit(PKG_NETWORK_CONFIG);
	if (disable_num != num)
	{
		set_lktos_effect("l2tp_secrets");
	}
	set_lktos_effect("network");
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");
	
	return CGI_TRUE;

}

CGI_BOOL getVpnAccountCfg(json_object *request, FILE *conn_fp)
{

	
	return CGI_TRUE;
}


CGI_BOOL setVpnAccountCfg(json_object *request, FILE *conn_fp)
{

	
	return CGI_TRUE;
}



CGI_BOOL getUserInfo(json_object *request, FILE *conn_fp)
{

	
	return CGI_TRUE;
}




CGI_BOOL getOpenVpnClientCfg(json_object *request, FILE *conn_fp)
{
	cJSON *root;
	FILE *fp;
	int vpn_link = 0;
	char buf[4096]={0};
	char cert[4096]={0};
	char ifname[RESULT_STR_LEN]={0},addr[RESULT_STR_LEN]={0};
	char enabled[OPTION_STR_LEN]={0},def_route[OPTION_STR_LEN]={0};
	char remote[OPTION_STR_LEN]={0},port[OPTION_STR_LEN]={0},address[OPTION_STR_LEN]={0},cipher[OPTION_STR_LEN]={0};
	char proto[OPTION_STR_LEN]={0},dev[OPTION_STR_LEN]={0},comp_lzo[OPTION_STR_LEN]={0},mtu[OPTION_STR_LEN]={0};
	char script_security[OPTION_STR_LEN]={0},username[OPTION_STR_LEN]={0},password[OPTION_STR_LEN]={0};
	char certcheck[SMALL_STR_LEN]={0},tmpBuf[TEMP_STR_LEN]={0};

	root=cJSON_CreateObject();

	Uci_Get_Str(PKG_OPENVPND_CONFIG,"client","enabled",enabled);
	Uci_Get_Str(PKG_OPENVPND_CONFIG,"client","remote",remote);

	Uci_Get_Str(PKG_OPENVPND_CONFIG,"client","def_route",def_route);

	Uci_Get_Str(PKG_OPENVPND_CONFIG,"client","proto",proto);
	Uci_Get_Str(PKG_OPENVPND_CONFIG,"client","dev",dev);
	Uci_Get_Str(PKG_OPENVPND_CONFIG,"client","comp_lzo",comp_lzo);
	Uci_Get_Str(PKG_OPENVPND_CONFIG,"client","cipher",cipher);
	Uci_Get_Str(PKG_OPENVPND_CONFIG,"client","mtu",mtu);

	Uci_Get_Str(PKG_OPENVPND_CONFIG,"client","script_security",script_security);
	Uci_Get_Str(PKG_OPENVPND_CONFIG,"client","username",username);
	Uci_Get_Str(PKG_OPENVPND_CONFIG,"client","password",password);
	Uci_Get_Str(PKG_OPENVPND_CONFIG,"client","certcheck",certcheck);
	cJSON_AddStringToObject(root, "certManual",certcheck);

	sscanf(remote,"%s %s",address,port);

	cJSON_AddStringToObject(root, "enabled", enabled);
	
	cJSON_AddStringToObject(root, "address", address);
	cJSON_AddStringToObject(root, "port", port);

	cJSON_AddStringToObject(root, "proto", proto);
	cJSON_AddStringToObject(root, "devType", dev);

	cJSON_AddStringToObject(root, "def_route", def_route);

	if ( !strcmp(comp_lzo, "yes") )
		cJSON_AddStringToObject(root, "compLzo", "1");
	else if ( !strcmp(comp_lzo, "no") )
		cJSON_AddStringToObject(root, "compLzo", "0");
	else //adaptive
		cJSON_AddStringToObject(root, "compLzo", "2");
	
	cJSON_AddStringToObject(root, "cipher", cipher);
	cJSON_AddStringToObject(root, "mtu", mtu);
	cJSON_AddStringToObject(root, "auth",script_security);

	cJSON_AddStringToObject(root, "username",username);
	cJSON_AddStringToObject(root, "password",password);

	memset(buf, 0, 4096);
	if ((fp = fopen("/etc/openvpn/client/ca.crt", "r")) != NULL) 
	{
		fread(buf, 1, 4096, fp);
		fclose(fp);
	}
	cJSON_AddStringToObject(root, "ca", buf);

	memset(buf, 0, 4096);
	if ((fp = fopen("/etc/openvpn/client/ta.key", "r")) != NULL) 
	{
		fread(buf, 1, 4096, fp);
		fclose(fp);
	}
	cJSON_AddStringToObject(root, "ta", buf);

	memset(cert, 0, 4096);
	if ((fp = fopen("/etc/openvpn/client/client.crt", "r")) != NULL) 
	{
		fread(cert, 1, 4096, fp);
		fclose(fp);
	}
	cJSON_AddStringToObject(root, "cert", cert);

	memset(buf, 0, 4096);
	if ((fp = fopen("/etc/openvpn/client/client.key", "r")) != NULL) 
	{
		fread(buf, 1, 4096, fp);
		fclose(fp);
	}
	cJSON_AddStringToObject(root, "key", buf);

	memset(buf, 0, 4096);
	if ((fp = fopen("/etc/openvpn/client/extra.conf", "r")) != NULL) 
	{
		fread(buf, 1, 4096, fp);
		fclose(fp);
	}
	cJSON_AddStringToObject(root, "extra_config", buf);

	if(strcmp(dev,"tun") == 0){
		snprintf(ifname,sizeof(ifname),"%s","tun0");
	}else{
		snprintf(ifname,sizeof(ifname),"%s","tap0");
	}
	get_ifname_ipaddr(ifname, addr);
	
	
//	if (atoi(enabled)==1 && strlen(addr) > 4 && vpn_link == LINK_SUCC)
	if (atoi(enabled)==1 && strlen(addr) > 4)
	{
		cJSON_AddStringToObject(root, "openvpnConnect","2");
		cJSON_AddStringToObject(root, "ClientAddr",addr);
	}
/*
	else if(vpn_link == LINK_SUCC)
	{
		sprintf(tmpBuf,"%d",LINK_DIAL);
		cJSON_AddStringToObject(root, "openvpnConnect",tmpBuf);
		cJSON_AddStringToObject(root, "ClientAddr","0.0.0.0");
	}
*/
	else
	{
		sprintf(tmpBuf,"%d",0);
		cJSON_AddStringToObject(root, "openvpnConnect",tmpBuf);
		cJSON_AddStringToObject(root, "ClientAddr","0.0.0.0");
	}

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}

CGI_BOOL setOpenVpnClientCfg(json_object *request, FILE *conn_fp)
{
	FILE *fp;
	int lzo_int;
	char remote[OPTION_STR_LEN]={0},cmd[CMD_STR_LEN]={0};	
	int pptp_enable=0,l2tp_enable=0;

	dbg("[%s]%d\n",__FUNCTION__,__LINE__);
	
	char *enabled = webs_get_string(request, "enabled");
	char *address = webs_get_string(request, "address");
	char *port = webs_get_string(request, "port");
	char *proto = webs_get_string(request, "proto");
	char *def_route = webs_get_string(request,"def_route");
	char *dev = webs_get_string(request, "devType");
	char *cipher = webs_get_string(request,"cipher");
	char *comp_lzo = webs_get_string(request,"compLzo");
	char *mtu = webs_get_string(request, "mtu");
	char *ca = webs_get_string(request, "ca");
	char *ta = webs_get_string(request, "ta");
	char *cert = webs_get_string(request, "cert");
	char *key = webs_get_string(request, "key");
	char *extra_config = webs_get_string(request, "extra_config");
	char *script_security = webs_get_string(request, "auth");
	char *username = webs_get_string(request, "username");
	char *password = webs_get_string(request, "password");
	char *certcheck = webs_get_string(request, "certManual");
	char *tlsAuth = webs_get_string(request, "tlsAuth");

	dbg("[%s]%d;enabled->%s\n",__FUNCTION__,__LINE__,enabled);

	lzo_int = atoi(comp_lzo);
	snprintf(remote,OPTION_STR_LEN,"%s %s",address,port);
	
	Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","enabled",enabled);
	if(atoi(enabled) == 1)
	{
		Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","remote",remote);
		Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","server_domain",address);
		Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","def_route",def_route);
		Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","proto",proto);
		Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","dev",dev);
		Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","cipher",cipher);

		if ( 1 == lzo_int )
			Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","comp_lzo","yes");
		else if ( 0 == lzo_int )
			Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","comp_lzo","no");
		else //adaptive
			Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","comp_lzo","adaptive");

		Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","mtu",mtu);
		Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","script_security",script_security);

		Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","username",username);
		Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","password",password);

		Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","certcheck",certcheck);
		if(atoi(certcheck)==0)
		{
			if ((fp = fopen(OPENVPN_CLIENT_DIR"/ca.crt", "w+")) != NULL) 
			{
				fprintf(fp, "%s", ca);
				fclose(fp);
			}
			if ((fp = fopen(OPENVPN_CLIENT_DIR"/ta.key", "w+")) != NULL) 
			{
				fprintf(fp, "%s", ta);
				fclose(fp);
			}
			if ((fp = fopen(OPENVPN_CLIENT_DIR"/client.crt", "w+")) != NULL) 
			{
				fprintf(fp, "%s", cert);
				fclose(fp);
			}
			if ((fp = fopen(OPENVPN_CLIENT_DIR"/client.key", "w+")) != NULL) 
			{
				fprintf(fp, "%s", key);
				fclose(fp);
			}
		}
		if ((fp = fopen(OPENVPN_CLIENT_DIR"/extra.conf", "w+")) != NULL) 
		{
			fprintf(fp, "%s", extra_config);
			fclose(fp);
		}

		if(!strcmp(dev, "tap"))
		{	
			Uci_Del_List(PKG_NETWORK_CONFIG, "@device[0]", "ports", "tap0");
			Uci_Add_List(PKG_NETWORK_CONFIG, "@device[0]", "ports", "tap0");

			Uci_Commit(PKG_NETWORK_CONFIG);
		}
	}
	Uci_Commit(PKG_OPENVPND_CONFIG);
	
#if 0//ppl2tp
	Uci_Get_Int(PKG_VPN_CONFIG,"pptp","enable",&pptp_enable);
	Uci_Get_Int(PKG_VPN_CONFIG,"l2tp","enable",&l2tp_enable);
	if(pptp_enable) {
		Uci_Set_Str(PKG_VPN_CONFIG,"pptp","enable","0");
		Uci_Commit(PKG_VPN_CONFIG);
		setLktosEffect("pptp");
	}
	if(l2tp_enable) {
		Uci_Set_Str(PKG_VPN_CONFIG,"l2tp","enable","0");
		Uci_Commit(PKG_VPN_CONFIG);
		setLktosEffect("l2tp");
	}
#endif

//	snprintf(cmd,CMD_STR_LEN,"ibms_cmd set status vpn_link '%d'",LINK_DIAL);
//	CsteSystem(cmd,CSTE_PRINT_CMD);

	set_lktos_effect("openvpnc");
	if(!strcmp(dev, "tap"))
	{
		set_lktos_effect("network");
	}

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "25", "reserv");
	return CGI_TRUE;
}


CGI_BOOL getOpenVpnServerCfg(json_object *request, FILE *conn_fp)
{
	char buf[8192]={0};
	char enabled[32]={0},port[32]={0},subnet[32]={0},mask[32]={0},proto[32]={0},dev[32]={0};
	char mtu[32]={0},auth[32]={0},servername[32]={0},dayvalid[32]={0},script_security[32]={0};
	char country[32]={0},province[32]={0},city[32]={0},org[32]={0},email[32]={0},ou[32]={0},comp_lzo[32]={0},cipher[32]={0};
	FILE *fp;

	char ciphTable[15][128]={
		{"NONE"},
		{"DES-CBC"},
		{"DES-EDE-CBC"},
		{"BF-CBC"},
		{"AES-128-CBC"},
		{"AES-192-CBC"},
		{"DES-EDE3-CBC"},
		{"DESX-CBC"},
		{"AES-256-CBC"},
		{"CAMELLIA-128-CBC"},
		{"CAMELLIA-192-CBC"},
		{"CAMELLIA-256-CBC"},
		{"AES-128-GCM"},
		{"AES-192-GCM"},
		{"AES-256-GCM"}
	};
	
	cJSON *respond_obj=cJSON_CreateObject();

	Uci_Get_Str(PKG_OPENVPND_CONFIG,"server","enabled",enabled);
	Uci_Get_Str(PKG_OPENVPND_CONFIG,"server","port",port);
	Uci_Get_Str(PKG_OPENVPND_CONFIG,"server","subnet",subnet);
	Uci_Get_Str(PKG_OPENVPND_CONFIG,"server","mask",mask);
	Uci_Get_Str(PKG_OPENVPND_CONFIG,"server","proto",proto);
	Uci_Get_Str(PKG_OPENVPND_CONFIG,"server","dev",dev);
	Uci_Get_Str(PKG_OPENVPND_CONFIG,"server","mtu",mtu);
	Uci_Get_Str(PKG_OPENVPND_CONFIG,"server","auth",auth);

	
	Uci_Get_Str(PKG_OPENVPND_CONFIG,"server","cipher",cipher);
	Uci_Get_Str(PKG_OPENVPND_CONFIG,"server","script_security",script_security);
	
	Uci_Get_Str(PKG_OPENVPND_CONFIG,"server","comp_lzo",comp_lzo);			//lzo压缩
	Uci_Get_Str(PKG_OPENVPND_CONFIG,"server","servername",servername);		//通用名称
	Uci_Get_Str(PKG_OPENVPND_CONFIG,"server","dayvalid",dayvalid);			//有效天数
	Uci_Get_Str(PKG_OPENVPND_CONFIG,"server","country",country);			//国家	
	Uci_Get_Str(PKG_OPENVPND_CONFIG,"server","province",province);			//省份	
	Uci_Get_Str(PKG_OPENVPND_CONFIG,"server","city",city);					//城市
	Uci_Get_Str(PKG_OPENVPND_CONFIG,"server","org",org);					//组织	
	Uci_Get_Str(PKG_OPENVPND_CONFIG,"server","email",email);				//邮箱
	Uci_Get_Str(PKG_OPENVPND_CONFIG,"server","ou",ou);						//单位


	cJSON_AddStringToObject(respond_obj, "enabled",enabled);
	cJSON_AddStringToObject(respond_obj, "port",port);
	cJSON_AddStringToObject(respond_obj, "subnet",subnet);
	cJSON_AddStringToObject(respond_obj, "mask",mask);
	cJSON_AddStringToObject(respond_obj,"ifaceOption", "");
	

	if(strcmp(proto,"udp")==0) {
		cJSON_AddStringToObject(respond_obj,"proto","udp");
	}else if(strcmp(proto,"tcp")==0){
		cJSON_AddStringToObject(respond_obj,"proto","tcp");
	}else if(strcmp(proto,"udp6")==0){
		cJSON_AddStringToObject(respond_obj,"proto","udp6");
	}else if(strcmp(proto,"tcp6")==0){
		cJSON_AddStringToObject(respond_obj,"proto","tcp6");
	}

	if(strcmp(dev,"tun")==0) {
		cJSON_AddStringToObject(respond_obj,"devType","tun");
	}else{
		cJSON_AddStringToObject(respond_obj,"devType","tap");
	}

	cJSON_AddStringToObject(respond_obj, "cipher", cipher);


	if (strcmp(comp_lzo, "yes") == 0){
		cJSON_AddStringToObject(respond_obj, "compLzo", "1");
	}else if (strcmp(comp_lzo, "no") == 0){
		cJSON_AddStringToObject(respond_obj, "compLzo", "0");
	}else {//adaptive
		cJSON_AddStringToObject(respond_obj, "compLzo", "2");
	}
	
	cJSON_AddStringToObject(respond_obj,"mtu",mtu);
	
	//ca证书
	memset(buf, 0, sizeof(buf));
	f_read("/etc/storage/openvpn/server/ca.crt", buf,sizeof(buf));
	cJSON_AddStringToObject(respond_obj, "ca",buf);

	//ca密钥
	memset(buf, 0, sizeof(buf));
	f_read("/etc/storage/openvpn/server/ca.key", buf,sizeof(buf));
	cJSON_AddStringToObject(respond_obj, "caKey",buf);

	// dh 密钥
	memset(buf, 0, sizeof(buf));
	f_read("/etc/storage/openvpn/server/dh1024.pem", buf,sizeof(buf));
	cJSON_AddStringToObject(respond_obj, "dh",buf);

	//服务器证书
	memset(buf, 0, sizeof(buf));
	f_read("/etc/storage/openvpn/server/server.crt", buf,sizeof(buf));
	cJSON_AddStringToObject(respond_obj, "cert",buf);

	//服务器密钥
	memset(buf, 0, sizeof(buf));
	f_read("/etc/storage/openvpn/server/server.key", buf,sizeof(buf));
	cJSON_AddStringToObject(respond_obj, "key",buf);


	// extraCfg 	附加配置
	cJSON_AddStringToObject(respond_obj, "extraConfig","");

	//连接认证方式 2-证书认证、3-账号密码认证
	if(strcmp(script_security,"2") == 0){
		cJSON_AddStringToObject(respond_obj, "auth","2");
	}else if(strcmp(script_security,"3") == 0){
		cJSON_AddStringToObject(respond_obj, "auth","3");
	}


	cJSON_AddStringToObject(respond_obj, "serverName",servername);
	cJSON_AddStringToObject(respond_obj, "dayvalid",dayvalid);
	cJSON_AddStringToObject(respond_obj, "country",country);
	cJSON_AddStringToObject(respond_obj, "province",province);
	cJSON_AddStringToObject(respond_obj, "city",city);
	cJSON_AddStringToObject(respond_obj, "org",org);
	cJSON_AddStringToObject(respond_obj, "email",email);
	cJSON_AddStringToObject(respond_obj, "ou",ou);

	char *aa=cJSON_Print(respond_obj);
	dbg("%s\n",aa);
	free(aa);

	send_cgi_json_respond(conn_fp, respond_obj);

	return CGI_TRUE;
}

CGI_BOOL setOpenVpnServerCfg(json_object *request, FILE *conn_fp)
{
	FILE *fp;
	char *port=webs_get_string(request, "port");
	char *proto=webs_get_string(request, "proto");
	char *devType=webs_get_string(request, "devType");
	char *cipher=webs_get_string(request, "cipher");
	char *compLzo=webs_get_string(request, "compLzo");
	char *auth=webs_get_string(request, "auth");
	char *subnet=webs_get_string(request, "subnet");
	char *mask=webs_get_string(request, "mask");
	char *enabled=webs_get_string(request, "enabled");


	Uci_Set_Str(PKG_OPENVPND_CONFIG,"server","enabled",enabled);	
	if(atoi(enabled) == 1)
	{
		Uci_Set_Str(PKG_OPENVPND_CONFIG,"server","subnet",subnet);

		Uci_Set_Str(PKG_OPENVPND_CONFIG,"server","port",port);	
		Uci_Set_Str(PKG_OPENVPND_CONFIG,"server","proto",proto);
		Uci_Set_Str(PKG_OPENVPND_CONFIG,"server","dev",devType);
		Uci_Set_Str(PKG_OPENVPND_CONFIG,"server","cipher",cipher);	
	 	Uci_Set_Str(PKG_OPENVPND_CONFIG,"server","mask",mask);	

	 	if(atoi(compLzo) == 1){
	 		Uci_Set_Str(PKG_OPENVPND_CONFIG,"server","compLzo","yes");
	 	}else if(atoi(compLzo) == 0){
	 		Uci_Set_Str(PKG_OPENVPND_CONFIG,"server","compLzo","no");
	 	}
	 
	 	
	 	//连接认证方式 2-证书认证、3-账号密码认证
	 	if(atoi(auth) == 2 ){		
	 		Uci_Set_Str(PKG_OPENVPND_CONFIG,"server","script_security","2");	
	 	}else if(atoi(auth) == 3){
	 		Uci_Set_Str(PKG_OPENVPND_CONFIG,"server","script_security","3");	
	 	}
	 	
	}

	
	Uci_Commit(PKG_OPENVPND_CONFIG);
	set_lktos_effect("openvpnc");

	
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "25", "reserv");
	
	return CGI_TRUE;

}

CGI_BOOL UploadOpenVpnCert(json_object *request, FILE *conn_fp)
{

	long inLen=0;
	char cmd_buf[CMD_STR_LEN] = {0},tmp_buf[TEMP_STR_LEN] = {0};
	char tempfilename[TEMP_STR_LEN] = {0};
	cJSON *root,*opvnObj;
	char  *output;

	int opvnf;
	DIR *dir = NULL; 
	FILE *opvnfp = NULL;
	struct dirent *entry; 
	struct stat opvnst;
	struct dirent *opvnent;
	char *opvnname,*buffer;
	char remote_port[OPTION_STR_LEN]={0};

	char *script_security = NULL,*remote,*port,*proto;
	char *mtu,*dev,*comp_lzo,*cipher,*username,*password;

	root=cJSON_CreateObject();

	char *FileName = webs_get_string(request, "FileName");
	char *FullName = webs_get_string(request, "FullName");
	char *ContentLength= webs_get_string(request, "ContentLength");
	char *cert_type = webs_get_string(request, "cert_type");
	char *cert_name = webs_get_string(request, "cert_name");
	
	inLen= strtol(ContentLength, NULL, 10);
	
	if(inLen > 1024*1024 || inLen < 1 ){
		cJSON_AddStringToObject(root,"Result","Fail");
		goto err;
	}
	
	getNthValueSafe(1, cert_name, '=', tempfilename, sizeof(tempfilename));

	if(strstr(cert_type,"client")){

		if(strcmp(tempfilename,"confgz")==0){

			snprintf(cmd_buf,CMD_STR_LEN,"tar -zxf %s -C %s",FileName,OPENVPN_CLIENT_DIR);
			CsteSystem(cmd_buf,CSTE_PRINT_CMD);
		
			if((dir = opendir(OPENVPN_CLIENT_DIR))==NULL) 
			{ 
				cJSON_AddStringToObject(root,"Result","Fail");
				goto err;
			} 
			else 
			{ 
				while((opvnent=readdir(dir)) != NULL)
				{
					if(!strstr(opvnent->d_name,".ovpn"))
						continue;
					opvnname = (char *)malloc(sizeof(char)*FILE_DIR_LEN);
					memset(opvnname,'\0',sizeof(char)*FILE_DIR_LEN);
					strcpy(opvnname,OPENVPN_CLIENT_DIR);
					strcat(opvnname,"/");
					strcat(opvnname,opvnent->d_name);
					opvnf=stat(opvnname,&opvnst);
					if(opvnf != -1)
					{
						opvnfp = fopen(opvnname, "r+");
						if(!opvnfp){
							free(opvnname);
							continue;
						}
						buffer = (char *)malloc(sizeof(char)*opvnst.st_size+1);
						memset(buffer,'\0',sizeof(char)*opvnst.st_size+1);
						fread(buffer,opvnst.st_size,1,opvnfp);
						fclose(opvnfp);
						opvnObj = cJSON_Parse(buffer);
						if(!opvnObj){
							free(opvnname);
							free(buffer);
							cJSON_AddStringToObject(root,"Result","Fail");
							goto err;
						}
						script_security = webs_get_string(opvnObj,"auth");
						remote = webs_get_string(opvnObj,"remote");
						port = webs_get_string(opvnObj,"port");
						proto = webs_get_string(opvnObj,"proto");
						dev = webs_get_string(opvnObj,"dev");
						comp_lzo = webs_get_string(opvnObj,"compLzo");
						cipher = webs_get_string(opvnObj,"cipher");
						mtu = webs_get_string(opvnObj,"mtu");
						username = webs_get_string(opvnObj,"username");
						password = webs_get_string(opvnObj,"password");

						snprintf(remote_port,OPTION_STR_LEN,"%s %s",remote,port);
						
						Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","enabled","1");
						Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","remote",remote_port);
						Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","proto",proto);
						Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","dev",dev);
						Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","comp_lzo",comp_lzo);
						Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","cipher",cipher);
						Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","mtu",mtu);
						Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","script_security",script_security);
						Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","username",username);
						Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","password",password);
						Uci_Commit(PKG_OPENVPND_CONFIG);
						free(buffer);

						if(strcmp(script_security,"2")==0){

							snprintf(cmd_buf,CMD_STR_LEN,"cp -rf %s/%s.crt %s/client.crt",OPENVPN_CLIENT_DIR,username,OPENVPN_CLIENT_DIR);
							CsteSystem(cmd_buf,CSTE_PRINT_CMD);

							snprintf(cmd_buf,CMD_STR_LEN,"cp -rf %s/%s.key %s/client.key",OPENVPN_CLIENT_DIR,username,OPENVPN_CLIENT_DIR);
							CsteSystem(cmd_buf,CSTE_PRINT_CMD);

							snprintf(cmd_buf,CMD_STR_LEN,"rm -rf %s/%s.*",OPENVPN_CLIENT_DIR,username);
							CsteSystem(cmd_buf,CSTE_PRINT_CMD);
						}
						cJSON_Delete(opvnObj);
						set_lktos_effect("openvpnc");
					}
					free(opvnname);
				}
				closedir(dir);

				if(script_security==NULL){
					cJSON_AddStringToObject(root,"Result","Fail");
					goto err;
				}
			} 
		}else{

			if(strcmp(tempfilename,"ca.crt")==0){
				Uci_Get_Str(PKG_OPENVPND_CONFIG,"client","ca",tmp_buf);
				
			}else if(strcmp(tempfilename,"client.crt")==0){
				Uci_Get_Str(PKG_OPENVPND_CONFIG,"client","cert",tmp_buf);
			}else if(strcmp(tempfilename,"client.key")==0){
				Uci_Get_Str(PKG_OPENVPND_CONFIG,"client","key",tmp_buf);
			}else if(strcmp(tempfilename,"ta.key")==0){
				snprintf(tmp_buf,TEMP_STR_LEN,OPENVPN_CLIENT_DIR"/ta.key");
			}
			snprintf(cmd_buf,CMD_STR_LEN,"cp %s %s",FileName,tmp_buf);
		
			CsteSystem(cmd_buf,CSTE_PRINT_CMD);
		}
	}

	cJSON_AddStringToObject(root, "Result","Success");

	memset(cmd_buf, 0, sizeof(cmd_buf));
	sprintf(cmd_buf, "rm -f %s",FileName);
	CsteSystem(cmd_buf,CSTE_PRINT_CMD);

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;

err:
	memset(cmd_buf, 0, sizeof(cmd_buf));
	sprintf(cmd_buf, "rm -f %s",FileName);
	CsteSystem(cmd_buf,CSTE_PRINT_CMD);

	send_cgi_json_respond(conn_fp, root);
	return CGI_FALSE;
}


CGI_BOOL getTunnelRouteCfg(json_object *request, FILE *conn_fp)
{
	int i, iRulesNum=0;
	char *output=NULL;
	cJSON *root, *connArray, *connEntry;
	char sRules[2048]={0}, sRule[128]={0};
	char routeEnabled[8]={0}, tunnelName[32]={0}, ip[32]={0}, virtualIp[32]={0};
	char mask[32]={0},desc[32]={0};
	
	root = cJSON_CreateObject();
	connArray = cJSON_CreateArray();

	cJSON_AddItemToObject(root, "rule", connArray);
	Uci_Get_Int(PKG_TUNNEL_CONFIG,"tunnel_route_rule","num",&iRulesNum);
	Uci_Get_Str(PKG_TUNNEL_CONFIG,"tunnel_route_rule","rules",sRules);

	for(i=0;i<iRulesNum;i++)
	{
		get_nth_val_safe(i, sRules, ' ', sRule, sizeof(sRule));
	
		if((get_nth_val_safe(0, sRule, ',', routeEnabled ,sizeof(routeEnabled)) == -1))
		{
			continue;
		}
	
		if((get_nth_val_safe(1, sRule, ',', tunnelName, sizeof(tunnelName)) == -1))
		{
			continue;
		}
	
		if((get_nth_val_safe(2, sRule, ',', ip, sizeof(ip)) == -1))
		{
			continue;
		}
	
		if((get_nth_val_safe(3, sRule, ',', virtualIp, sizeof(virtualIp)) == -1))
		{
			continue;
		}
	
		if((get_nth_val_safe(4, sRule, ',', mask, sizeof(mask)) == -1))
		{
			continue;
		}
	
		if((get_nth_val_safe(5, sRule, ',', desc, sizeof(desc)) == -1))
		{
			continue;
		}
	
		connEntry = cJSON_CreateObject();

		cJSON_AddStringToObject(connEntry,"routeEnabled", routeEnabled);
		cJSON_AddStringToObject(connEntry,"tunnelName", tunnelName);
		cJSON_AddStringToObject(connEntry,"ip", ip);
		cJSON_AddStringToObject(connEntry,"virtualIp", virtualIp);
		cJSON_AddStringToObject(connEntry,"mask", mask);
		cJSON_AddStringToObject(connEntry,"desc", desc);

		cJSON_AddItemToArray(connArray,connEntry);
	}

	send_cgi_json_respond(conn_fp, root);
	return CGI_TRUE;
	
}

CGI_BOOL setTunnelRouteCfg(json_object *request, FILE *conn_fp)
{
	
	int num=0, i;
	cJSON *subnet;
	char rules[4096]={0}, tmpBuf[128]={0};
	
	//Delete the original rule
	Uci_Get_Int(PKG_TUNNEL_CONFIG, "tunnel_route_rule", "num", &num);
	if(num > 0){
		Uci_Get_Str(PKG_TUNNEL_CONFIG,"tunnel_route_rule","rules",rules);
		for(i=num; i>0; i--){
			memset(tmpBuf, '\0', sizeof(tmpBuf));
			get_nth_val_safe((i-1), rules, ' ', tmpBuf, sizeof(tmpBuf));
			Uci_Del_List(PKG_TUNNEL_CONFIG, "tunnel_route_rule", "rules", tmpBuf);
		}	
		num=0;
		Uci_Set_Str(PKG_TUNNEL_CONFIG, "tunnel_route_rule", "num", "0");
	}
		
	json_object_object_foreach(request, key, val) {
		if (strcmp(key, "rule") == 0) {
			subnet = json_object_get_array(val);

			num = json_object_array_length(val);				
			snprintf(tmpBuf, sizeof(tmpBuf), "%d", num);
			Uci_Set_Str(PKG_TUNNEL_CONFIG, "tunnel_route_rule", "num", tmpBuf);

			for(i = 0; i < num; i++) {
				struct json_object *subnet_x = (struct json_object *)array_list_get_idx(subnet, i);

				char *routeEnabled = webs_get_string(subnet_x, "routeEnabled");
				char *tunnelName  = webs_get_string(subnet_x, "tunnelName");
				char *ip = webs_get_string(subnet_x, "ip");
				char *virtualIp = webs_get_string(subnet_x, "virtualIp");
				char *mask  = webs_get_string(subnet_x, "mask");
				char *desc = webs_get_string(subnet_x, "desc");


				memset(rules, '\0', sizeof(rules));
				sprintf(rules, "%s,%s,%s,%s,%s,%s", routeEnabled,tunnelName, ip,virtualIp,mask,desc);
				Uci_Add_List(PKG_TUNNEL_CONFIG, "tunnel_route_rule", "rules", rules);
			}
		}
	}

	Uci_Commit(PKG_TUNNEL_CONFIG);
	
	doSystem("/etc/init.d/tunnel stop");
	if(num > 0)
		doSystem("/etc/init.d/tunnel start &");
	
	set_lktos_effect("firewall");
	set_lktos_effect("static_tunnel_route");
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

	return CGI_TRUE;
}

#if defined(CONFIG_SSLVPN_SUPPORT)

void cs_w_file(const char *format, ...) 
{
	char log[256]={0};
	
	Uci_Get_Str(PKG_SSLVPN_CONFIG,"ssl","log",log);

	if(atoi(log) == 1){

    	FILE *fp = fopen("/tmp/sslcert.log", "a");
    
    	if (fp) {
        	va_list args;
        	va_start(args, format);

        	vfprintf(fp, format, args);
        	fprintf(fp, "\n"); 

        	va_end(args);
        	fclose(fp);
    	} else {

        	perror("Failed to open log file");
    	}
	}

}

CGI_BOOL getSslVpnTunCfg(json_object *request, FILE *conn_fp)
{

	char ssl_data[2056]={0};	
	char crypto_spec[128]={0},engine_calc[128]={0};
	char gwip[128]={0},gwport[128]={0};
	cJSON *respond_obj=NULL,*root=NULL;

	respond_obj = cJSON_CreateObject();
	
	char vpn_ip[32] = {0},enabled[32]={0},type[32]={0};
	char log_buf[1024*256] = {0};
	
	Uci_Get_Str(PKG_SSLVPN_CONFIG,"ssl","enabled",enabled);
	
	cJSON_AddStringToObject(respond_obj, "enabled",enabled);

	int ret = f_read_string("/opt/ssl/ssl_proxy.json", ssl_data, sizeof(ssl_data));

	if(ret > 0){
		root = cJSON_Parse(ssl_data);
		if(root) 
		{	
						
			cJSON *channel = cJSON_GetObjectItem(root, "channel");
			cJSON *param = cJSON_GetObjectItem(root, "param");

			
			if(channel){
				get_cjson_string(channel, "gwip", gwip, sizeof(gwip));
				get_cjson_string(channel, "gwport", gwport, sizeof(gwport));
			}
			cJSON_AddStringToObject(respond_obj, "ip",gwip);
			cJSON_AddStringToObject(respond_obj, "port",gwport);
		

			if(param){
				get_cjson_string(param, "crypto_spec", crypto_spec, sizeof(crypto_spec));
				get_cjson_string(param, "engine_calc", engine_calc, sizeof(engine_calc));
			}
			
			if(!strcmp(crypto_spec,"skf") && atoi(engine_calc)==1 ){
				cJSON_AddStringToObject(respond_obj, "encrypt","hard-en");
			}else if(!strcmp(crypto_spec,"soft") && atoi(engine_calc)==0 ){
				cJSON_AddStringToObject(respond_obj, "encrypt","soft-en");
			}else if(!strcmp(crypto_spec,"skf") && atoi(engine_calc)==0 ){
				cJSON_AddStringToObject(respond_obj, "encrypt","hrad-soft");
			}

		}
		
		cJSON_Delete(root);
	}
	
	get_ifname_ipaddr("tun0", vpn_ip);
    if(is_ip_valid(vpn_ip)){
       	cJSON_AddStringToObject(respond_obj, "vpnIp",vpn_ip);
    }else{
    	cJSON_AddStringToObject(respond_obj, "vpnIp","");
    }

	char mapping_terminal[64]={0};
	Uci_Get_Str(PKG_SSLVPN_CONFIG,"ssl","mapping_terminal",mapping_terminal);
	
	cJSON_AddStringToObject(respond_obj, "mapping_terminal",mapping_terminal);

	cJSON_AddStringToObject(respond_obj, "disabled","1");	

	
	ret = f_read_string("/tmp/ssl_proxy.log", log_buf, sizeof(log_buf));
	if(ret > 0){
		cJSON_AddStringToObject(respond_obj, "vpnLog",log_buf);
	}else{
		cJSON_AddStringToObject(respond_obj, "vpnLog","SSLVPN without dial-up");
	}

	send_cgi_json_respond(conn_fp, respond_obj);

	return CGI_TRUE;
}

CGI_BOOL setSslVpnTunCfg(json_object *request, FILE *conn_fp)
{
	char *addEffect = webs_get_string(request, "addEffect");
	char *enabled	= webs_get_string(request, "enabled");
	char *ip	  = webs_get_string(request, "ip");
	char *port	  = webs_get_string(request, "port");
	char *encrypt = webs_get_string(request, "encrypt");
	char *mapping_terminal	  = webs_get_string(request, "mapping_terminal");

	char ssl_data[2056]={0};

	cJSON *root=NULL;
	
	Uci_Set_Str(PKG_SSLVPN_CONFIG,"ssl","enabled",enabled);
	
	//Uci_Set_Str(PKG_SSLVPN_CONFIG,"ssl","encrypt",encrypt);

	if(atoi(enabled) == 1){
		Uci_Set_Str(PKG_SSLVPN_CONFIG,"ssl","mapping_terminal",mapping_terminal);

		int ret = f_read_string("/opt/ssl/ssl_proxy.json", ssl_data, sizeof(ssl_data));

		if(ret > 0){
			root = cJSON_Parse(ssl_data);
			if(root) 
			{				
				cJSON *param = cJSON_GetObjectItem(root, "param");

				if(param){
				
			   		const char *crypto_spec = NULL;
                	bool engine_calc = false;
			
					if (!strcmp(encrypt, "hard-en")) {
                   	 	crypto_spec = "skf";
                    	engine_calc = true;
	                } else if (!strcmp(encrypt, "soft-en")) {
	                    crypto_spec = "soft";
	                    engine_calc = false;
	                } else if (!strcmp(encrypt, "hrad-soft")) {
	                    crypto_spec = "skf";
	                    engine_calc = false;
	                }	

					if (crypto_spec) {
	                    cJSON_ReplaceItemInObject(param, "crypto_spec", cJSON_CreateString(crypto_spec));
	                    cJSON_ReplaceItemInObject(param, "engine_calc", cJSON_CreateBool(engine_calc));
	                }
	   	 		}

				cJSON *channel = cJSON_GetObjectItem(root, "channel");

				if(channel){
					cJSON_ReplaceItemInObject(channel, "gwip", cJSON_CreateString(ip));
					cJSON_ReplaceItemInObject(channel, "gwport", cJSON_CreateNumber(atoi(port)));
				}

				char *updated_json = cJSON_Print(root);
				f_write_string("/opt/ssl/ssl_proxy.json",updated_json,0,0);
				free(updated_json);

			}
		}
		
		CsteSystem("/etc/init.d/ssl_proxy restart", CSTE_PRINT_CMD);
		
		cJSON_Delete(root);
	}
	else{
		CsteSystem("/etc/init.d/ssl_proxy stop", CSTE_PRINT_CMD);
	}

	//set_lktos_effect("restart_sslvpn");

	
	Uci_Commit(PKG_SSLVPN_CONFIG);

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");
	return CGI_TRUE;
	
}



CGI_BOOL getSslVpnCfg(json_object *request, FILE *conn_fp)
{
	cJSON *respond_obj = NULL;

	respond_obj = cJSON_CreateObject();
	

	cJSON_AddStringToObject(respond_obj, "disabled","1");	

	send_cgi_json_respond(conn_fp, respond_obj);

	return CGI_TRUE;
}

CGI_BOOL setSslVpnCfg(json_object *request, FILE *conn_fp)
{
	return CGI_TRUE;
}


int sslvpn_user_app(char *select,char *lan_mac)
{
	dbg("sslvpn_user_app\n");
	int i=0;
	CHAR buffsaNameList[128] = {0};
	ULONG ret;
	ULONG ulSize;
	ulSize = sizeof(buffsaNameList)-1;
	LPSTR saNameList = buffsaNameList;

	//枚举设备
	ret = SKF_EnumDev(TRUE, saNameList, &ulSize);
    cs_w_file("SKF_EnumDev ret=%X saNameList=%s ulSize=%d\n", ret, saNameList, ulSize);
    if(ret != 0) {
         goto end;
    }

	DEVHANDLE hDev = NULL;
	LPSTR szName = NULL;
    szName = (LPSTR)malloc(ulSize);
    memset(szName, 0, ulSize);
    strcpy(szName, saNameList);

	//连接设备
    ret = SKF_ConnectDev(szName, &hDev);
    cs_w_file("SKF_ConnectDev ret=%X hDev=%p *phDev=%d\n", ret, hDev, *(int *)hDev);
    if(ret != 0) {
		i=-1;
        goto end;
    }

	//获取设备信息
    DEVINFO dev_info = {0};
    ret = SKF_GetDevInfo(hDev, &dev_info);
    cs_w_file("SKF_GetDevInfo ret=%X\n", ret);
    if(ret != 0) {
		i=-1;
        goto end;
    }

	//枚举应用
    CHAR buffapp[128] = {0};
    LPSTR szAppName = buffapp;
    ulSize = sizeof(buffapp)-1;
    ret = SKF_EnumApplication(hDev, szAppName, &ulSize);
    cs_w_file("SKF_EnumApplication ret=%X szAppName=%s, ulSize=%d\n", ret, szAppName, ulSize);
    if(ret != 0) {
		i=-1;
		goto end;
    }

	//打开应用
	HAPPLICATION hApplication = NULL;
    ret = SKF_OpenApplication(hDev, szAppName, &hApplication);
    cs_w_file("SKF_OpenApplication ret=%X hApplication=%p\n", ret, hApplication);
    if(ret != 0) {
		i=-1;
		goto end;
    }

	ULONG pulRetryCount = 0;
    ULONG ulPINType = 1; 

	//用户登录
    ret = SKF_VerifyPIN(hApplication, ulPINType, SYS_DEFAULT_PIN_USER, &pulRetryCount);
    cs_w_file("SKF_VerifyPIN ret=%X pulRetryCount=%d\n", ret, pulRetryCount);

    CHAR buffszContainerName[128] = {0};
    LPSTR szContainerName = buffszContainerName;
    ulSize = sizeof(buffszContainerName)-1;

	//枚举容器
    ret = SKF_EnumContainer(hApplication, szContainerName, &ulSize);
    cs_w_file("SKF_EnumContainer ret=%X szContainerName=%s ulSize=%d\n", ret, szContainerName, ulSize);
    if(ret != 0) {
		 i=-1;
         goto end;
    }
	
	//if 没有容器，创建容器						 else容器存在，打开容器
	HCONTAINER hContainer = NULL;
    if(!strlen(szContainerName)) {
        LPSTR creatszContainerName = SYS_DEFAULT_CON_NAME;
        ret = SKF_CreateContainer(hApplication, creatszContainerName, &hContainer);
        cs_w_file("SKF_CreateContainer ret=%X hContainer=%p\n", ret, hContainer);
        cs_w_file("creatszContainerName=%s\n", creatszContainerName);
        if(ret != 0) {
			i=-1;
            goto end;
        }
    }
    else {
        ret = SKF_OpenContainer(hApplication, szContainerName, &hContainer);
        cs_w_file("SKF_OpenContainer ret=%X hContainer=%p\n", ret, hContainer);
        if(ret != 0) {
			i=-1;
            goto end;
        }
    }


	//生成证书
	if(!strcmp(select, "getcsr"))
	{
	
		ECCPKCS10SUBJECT req_p10;
		memset(&req_p10, 0, sizeof(req_p10));
		snprintf(req_p10.CN, sizeof(req_p10.CN), "%s", lan_mac);

		
		BYTE buffp10[1024] = {0};
		ulSize = sizeof(buffp10)-1;
		ret = SKF_CertRequest_Ex(hContainer, req_p10, buffp10, &ulSize);
		cs_w_file("SKF_CertRequest_Ex ret=%X ulSize=%d\n", ret, ulSize);

		if(ret == KEY_NO_FOUND)
		{
			ULONG ulAlgId = SGD_SM2;
        	ECCPUBLICKEYBLOB publicky_blob;
			memset(&publicky_blob, 0, sizeof(publicky_blob));
			ret = SKF_GenECCKeyPair(hContainer, ulAlgId, &publicky_blob);
			cs_w_file("SKF_CertRequest_Ex ret=%X\n",ret);
			if(ret != 0) {
				ret = SKF_GenECCKeyPair(hContainer, ulAlgId, &publicky_blob);
				cs_w_file("two SKF_CertRequest_Ex ret=%X\n",ret);
			}

			if(ret != 0) {
				i=-1;
		    	goto end;
			}
        	memset(buffp10, 0, sizeof(buffp10));
			ulSize = sizeof(buffp10)-1;
			ret = SKF_CertRequest_Ex(hContainer, req_p10, buffp10, &ulSize);

			cs_w_file("two SKF_CertRequest_Ex ret=%X ulSize=%d\n", ret, ulSize);
		}

		
		if(ret != 0) {
			i=-1;
		    goto end;
		}

		char base64[1024] = {0};
		base64_encode(buffp10, base64, ulSize);
		cs_w_file("base64_p10=[%d][%s]\n", strlen(base64), base64);

		BYTE buffp10_file[1024] = {0};
		strcat(buffp10_file, "-----BEGIN CERTIFICATE REQUEST-----\n");
		for(int t = 0; t < strlen(base64); t += 64) {
		    char tmp[65] = {0};
		    strncpy(tmp, base64+t, 64);
		    strcat(buffp10_file, tmp);
		    strcat(buffp10_file, "\n");
		}
		strcat(buffp10_file, "-----END CERTIFICATE REQUEST-----\n");

		char cfg_file_name[128]={0};
		snprintf(cfg_file_name, sizeof(cfg_file_name), "/web/%s.csr",lan_mac);
		ret = f_write_string(cfg_file_name, buffp10_file, 0, 0);
		cs_w_file("f_write=%s ret=%d\n", cfg_file_name, ret);
	}
	else if(!strcmp(select, "importcert"))//导入证书
	{
	
		ULONG byte_len;
   		BYTE blob_data[1024] = {0};
    	BYTE cert_pem[2048] = {0};
		char cert_path[256] = {0};
		BOOLL bSignFlag;
        BYTE *pbCert = NULL;
		cs_w_file("importcert\n");

		//签名
		snprintf(cert_path, sizeof(cert_path), "%s/%s", CERT_PATH, SIGN_CERT_FILE);
		if(f_exists(cert_path)){
			cs_w_file("cert_path %s\n",cert_path);
			bSignFlag = TRUE;
       		pbCert = blob_data;
        
        	BYTE *sign_cert = read_cert(cert_path);
        	if(!sign_cert) {
            	cs_w_file("read cert %s error\n", cert_path);
				i=-1;
            	goto end;
        	}
        	cs_w_file("sign_cert=[%s]\n", sign_cert);

        	memset(blob_data, 0, sizeof(blob_data));
       		byte_len = base64_decode(sign_cert, blob_data);
        	ret = SKF_ImportCertificate(hContainer, bSignFlag, pbCert, byte_len);
        	cs_w_file("SKF_ImportCertificate ret=%X\n", ret);
        	free(sign_cert);
        	if(ret != 0) {
				i=-1;
            	goto end;
        	}
		}
       
		//密钥对
		snprintf(cert_path, sizeof(cert_path), "%s/%s", CERT_PATH, ENC_KEY_FILE);
		if(f_exists(cert_path)){
			cs_w_file("cert_path %s\n",cert_path);
			memset(blob_data, 0, sizeof(blob_data));
			PENVELOPEDKEYBLOB pkey_pair = (PENVELOPEDKEYBLOB) blob_data;
       		memset(pkey_pair, 0, sizeof(ENVELOPEDKEYBLOB));
        	parse_asn1_key_pair(cert_path, pkey_pair);
            ret = SKF_ImportECCKeyPair(hContainer, pkey_pair);
            cs_w_file("SKF_ImportECCKeyPair ret=%X\n", ret);
            if(ret != 0) {
				i=-1;
            	goto end;
            }
        	
		}

		//加密
		snprintf(cert_path, sizeof(cert_path), "%s/%s", CERT_PATH, ENC_CERT_FILE);
		if(f_exists(cert_path)){
			cs_w_file("cert_path %s\n",cert_path);
			bSignFlag = FALSE;
        	pbCert = blob_data;

        	BYTE *enc_cert = read_cert(cert_path);
        	if(!enc_cert) {
            	cs_w_file("read cert %s error\n", cert_path);
				i=-1;
            	goto end;
        	}
        	cs_w_file("enc_cert=[%s]\n", enc_cert);

       		memset(blob_data, 0, sizeof(blob_data));
        	byte_len = base64_decode(enc_cert, blob_data);
        	ret = SKF_ImportCertificate(hContainer, bSignFlag, pbCert, byte_len);
        	cs_w_file("SKF_ImportCertificate ret=%X\n", ret);
        	free(enc_cert);
        	if(ret != 0) {
				i=-1;
            	goto end;
        	}
		}

	}
	
end:
    cs_w_file("\n");
    if(hContainer) {
        ret = SKF_CloseContainer(hContainer);
        cs_w_file("SKF_CloseContainer ret=%X\n", ret);
    }

    if(hApplication) {
        ret = SKF_CloseApplication(hApplication);
        cs_w_file("SKF_CloseApplication ret=%X\n", ret);
    }

    if(hDev) {
        ret = SKF_ConnectDev(szName, &hDev);
        cs_w_file("SKF_ConnectDev ret=%X\n", ret);
    }

    if(szName) {
        free(szName);
    }

	return i;

}

//导入配置应用
CGI_BOOL setSslVpnLoad(json_object *request,FILE *conn_fp)
{
	char enabled[32]={0};
	Uci_Get_Str(PKG_SSLVPN_CONFIG,"ssl","enabled",enabled);

	if(d_exists(SSL_CERT_PATH))
	{
		doSystem("cp -rf %s/* /opt/ssl/cert",SSL_CERT_PATH);

		int error = sslvpn_user_app("importcert",NULL);

		if(error == -1){
			send_cgi_set_respond(conn_fp, FALSE_W, "", NULL, "0", "reserv");
		}else{
			//set_lktos_effect("restart_sslvpn");
		
			if(atoi(enabled) == 1){
				CsteSystem("/etc/init.d/ssl_proxy restart", CSTE_PRINT_CMD);
			}else{
				CsteSystem("/etc/init.d/ssl_proxy stop", CSTE_PRINT_CMD);
			}

		}
	}else{
		
		send_cgi_set_respond(conn_fp, FALSE_W, "", NULL, "0", "reserv");
	}

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");
	
	return CGI_TRUE;
}

//导入配置显示
CGI_BOOL getSslVpnCertStatus(json_object *request, FILE *conn_fp)
{
	cJSON *respond_obj = NULL;

	respond_obj = cJSON_CreateObject();
	
	cJSON_AddStringToObject(respond_obj, "certStatus","1");	

	send_cgi_json_respond(conn_fp, respond_obj);
	
	return CGI_TRUE;
}

CGI_BOOL setSslVpnCertStatus(json_object *request, FILE *conn_fp)
{
	return CGI_TRUE;
}


CGI_BOOL setSslVpnCertCfg(json_object *request, FILE *conn_fp)
{
	char lan_mac[32]={0};
	char s[512]={0};
	char cfg_file_name[128]={0}, csr_file[128] = {0};

	//get_ifname_macaddr("br-lan",lan_mac);
	
	//config_lazy_set_int("cs_bat_dod", average, TEMP_DATAS_FILE);
	char imei[256]={0};
	get_cmd_result("atsh get cell | jsonfilter -e '$.data.imei'", imei, sizeof(imei));

	dbg("%s\n",imei);
	
	//switchMacFormat(lan_mac,lan_mac);

	snprintf(csr_file, sizeof(csr_file), "%s.csr",imei);
	
	sslvpn_user_app("getcsr",imei);

	snprintf(s, sizeof(s), "Location: /%s\r\n%s", csr_file, no_cache_IE);
	
	send_headers_sync(302, "Found", s, "text/html", NULL, conn_fp);
	
	fprintf(conn_fp, "%s", s);
	
	sleep(5);//需要延迟一下下，否则下载不了

	return CGI_TRUE;
}
#endif


CGI_BOOL getVxlanCfg(json_object *request, FILE *conn_fp)
{
	int iRulesNum=0;
	char Rules[512]={0},Rule[128]={0},sIdx[32]={0};
	char enabled[32]={0},vid[32]={0};
	char peer_ip[32]={0},peer_port[32]={0},source_ip[32]={0},interface_t[32]={0};
	
	Uci_Get_Str(PKG_VXLAN_CONFIG,"vxlan","enabled",enabled);
	Uci_Get_Int(PKG_VXLAN_CONFIG, "vxlan", "num", &iRulesNum);
	Uci_Get_Str(PKG_VXLAN_CONFIG, "vxlan", "rules", Rules);

	cJSON *root, *connArray, *connEntry;

	root = cJSON_CreateObject();

	connArray = cJSON_CreateArray();
	cJSON_AddItemToObject(root, "rule", connArray);


	for(int i=0;i<iRulesNum;i++)
	{
		get_nth_val_safe(i, Rules, ' ', Rule, sizeof(Rule));

		if((get_nth_val_safe(0, Rule, ',', vid, sizeof(vid)) == -1))
		{
			continue;
		}	
		
		if((get_nth_val_safe(1, Rule, ',', peer_ip, sizeof(peer_ip)) == -1))
		{
			continue;
		}
		
		if((get_nth_val_safe(2, Rule, ',', peer_port, sizeof(peer_port)) == -1))
		{
			continue;
		}
		
		if((get_nth_val_safe(3, Rule, ',', source_ip, sizeof(source_ip)) == -1))
		{
			continue;
		}
		
		if((get_nth_val_safe(4, Rule, ',', interface_t, sizeof(interface_t)) == -1))
		{
			continue;
		}
		
		sprintf(sIdx, "%d", i+1);

		connEntry = cJSON_CreateObject();
		cJSON_AddStringToObject(connEntry, "idx", sIdx);
		cJSON_AddStringToObject(connEntry, "vid",vid);
		cJSON_AddStringToObject(connEntry, "peer_ip",peer_ip);
		cJSON_AddStringToObject(connEntry, "peer_port",peer_port);
		cJSON_AddStringToObject(connEntry, "source_ip",source_ip);
		cJSON_AddStringToObject(connEntry, "interface",interface_t);

		cJSON_AddItemToArray(connArray, connEntry);
	}
	
	cJSON_AddStringToObject(root, "enabled",enabled);	

	send_cgi_json_respond(conn_fp, root);


	return CGI_TRUE;
}

CGI_BOOL setVxlanCfg(json_object *request, FILE *conn_fp)
{
	char *addEffect = webs_get_string(request, "addEffect");
	char *enabled = webs_get_string(request, "enabled");

	char buf[128]={0};
	char tmpBuf[4096]={0}, rules[256]={0};
	struct array_list *subArry;
	int num=0, i;

	if (atoi(enabled) == 1)
	{
		Uci_Get_Str(PKG_VXLAN_CONFIG, "vxlan", "num", &num);
		if(num > 0){
			Uci_Get_Str(PKG_VXLAN_CONFIG,"vxlan","rules",buf);
			for(i=num; i>0; i--){
				memset(tmpBuf, '\0', sizeof(tmpBuf));
				get_nth_val_safe((i-1), buf, ' ', tmpBuf, sizeof(tmpBuf));
				Uci_Del_List(PKG_VXLAN_CONFIG, "vxlan", "rules", tmpBuf);
			}	
			num=0;
			Uci_Set_Str(PKG_VXLAN_CONFIG, "vxlan", "num", "0");
		}
		
		memset(tmpBuf, '\0', sizeof(tmpBuf));
		json_object_object_foreach(request, key, val){
			if(strcmp(key, "subnet") == 0){
				subArry = json_object_get_array(val);
				num = json_object_array_length(val);

				snprintf(tmpBuf, sizeof(tmpBuf), "%d", num);
				Uci_Set_Str(PKG_VXLAN_CONFIG, "vxlan", "num", tmpBuf);
				for(i=0; i<num; i++){
					struct json_object *objet_x = (struct json_object *)array_list_get_idx(subArry, i);
					
					char *vid=webs_get_string(objet_x, "vid");
					char *peer_ip=webs_get_string(objet_x, "peer_ip");
					char *peer_port=webs_get_string(objet_x, "peer_port");
					char *source_ip=webs_get_string(objet_x, "source_ip");
					char *interface=webs_get_string(objet_x, "interface");
					
					memset(rules, '\0', sizeof(rules));
					snprintf(rules, sizeof(rules), "%s,%s,%s,%s,%s", vid,peer_ip,peer_port,source_ip,interface);
					Uci_Add_List(PKG_VXLAN_CONFIG, "vxlan", "rules", rules);
				}
				
				break;
			}
		}		
	}

	
	Uci_Set_Str(PKG_VXLAN_CONFIG, "vxlan", "enabled", enabled);

	Uci_Commit(PKG_VXLAN_CONFIG);


	set_lktos_effect("vxlan");

end_label:
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

	return CGI_TRUE;
}




CGI_BOOL getL2tpServerCfg(json_object *request, FILE *conn_fp)
{
	char ipsec_support[8]={0};

	cJSON *root = cJSON_CreateObject();

	get_uci2json(root, PKG_L2TPD_CONFIG, "xl2tpd", "enable", "enable");
	get_uci2json(root, PKG_L2TPD_CONFIG, "xl2tpd", "startip", "sip");
	get_uci2json(root, PKG_L2TPD_CONFIG, "xl2tpd", "endip", "eip");
	get_uci2json(root, PKG_L2TPD_CONFIG, "xl2tpd", "localip", "server");
	get_uci2json(root, PKG_L2TPD_CONFIG, "xl2tpd", "pridns", "priDns");
	get_uci2json(root, PKG_L2TPD_CONFIG, "xl2tpd", "secdns", "secDns");
	get_uci2json(root, PKG_L2TPD_CONFIG, "xl2tpd", "mtu", "mtu");
	get_uci2json(root, PKG_L2TPD_CONFIG, "xl2tpd", "mru", "mru");

	Uci_Get_Str(PKG_PRODUCT_CONFIG, "custom", "IpsecSupport", ipsec_support);
	if(1 == atoi(ipsec_support)){
		get_uci2json(root,PKG_L2TPD_CONFIG,  "xl2tpd",   "ipsec_l2tp_enable", "ipsecL2tpEnable");
		get_uci2json(root,PKG_L2TPD_CONFIG,  "xl2tpd",   "ipsec_l2tp_xauth_psk", "ipsecPsk");
	}

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}

CGI_BOOL setL2tpServerCfg(json_object *request,FILE *conn_fp)
{
	char ipsec_support[8]={0};
	char *enable = webs_get_string(request, "enable");
	char *sip = webs_get_string(request, "sip");
	char *eip = webs_get_string(request, "eip");
	char *server = webs_get_string(request, "server");
	char *priDns = webs_get_string(request, "priDns");
	char *secDns = webs_get_string(request, "secDns");
	char *mtu = webs_get_string(request, "mtu");
	char *mru = webs_get_string(request, "mru");

	Uci_Set_Str(PKG_L2TPD_CONFIG, "xl2tpd","enable",enable);
	if(1==atoi(enable))
	{
		if(is_ip_valid(sip) && is_ip_valid(eip) && is_ip_valid(server) &&is_ip_valid(priDns) \
			&& is_ip_valid(secDns)){
			Uci_Set_Str(PKG_L2TPD_CONFIG, "xl2tpd", "startip", sip);
			Uci_Set_Str(PKG_L2TPD_CONFIG, "xl2tpd", "endip", eip);
			Uci_Set_Str(PKG_L2TPD_CONFIG, "xl2tpd", "localip", server);
			Uci_Set_Str(PKG_L2TPD_CONFIG, "xl2tpd", "pridns", priDns);
			Uci_Set_Str(PKG_L2TPD_CONFIG, "xl2tpd", "secdns", secDns);
		}
		Uci_Set_Str(PKG_L2TPD_CONFIG, "xl2tpd", "mtu", mtu);
		Uci_Set_Str(PKG_L2TPD_CONFIG, "xl2tpd", "mru", mru);
		
		Uci_Get_Str(PKG_PRODUCT_CONFIG, "custom", "IpsecSupport", ipsec_support);
		
		if(atoi(ipsec_support) == 1){
			char *ipsecL2tpEnable = webs_get_string(request, "ipsecL2tpEnable");
			char *ipsecPsk = webs_get_string(request, "ipsecPsk");
			Uci_Set_Str(PKG_L2TPD_CONFIG, "xl2tpd", "ipsec_l2tp_enable", ipsecL2tpEnable);
			Uci_Set_Str(PKG_L2TPD_CONFIG, "xl2tpd", "ipsec_l2tp_xauth_psk", ipsecPsk);
		}

		Uci_Set_Str(PKG_CSFW_CONFIG,"firewall","hnat_enable","0");
		Uci_Commit(PKG_CSFW_CONFIG);
		doSystem("echo %s > /sys/kernel/debug/hnat/hook_toggle", "0");
	}
	else
	{
		char smartqos_enable[8]={0};
		Uci_Get_Str(PKG_QOS_CONFIG, "smartqos","enable",smartqos_enable);
		if(atoi(smartqos_enable)==0)
		{
			Uci_Set_Str(PKG_CSFW_CONFIG,"firewall","hnat_enable","1");
			Uci_Commit(PKG_CSFW_CONFIG);
			doSystem("echo %s > /sys/kernel/debug/hnat/hook_toggle", "1");
		}
	}

	Uci_Commit(PKG_L2TPD_CONFIG);
	set_lktos_effect("l2tpd");
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

	return CGI_TRUE;	
}

CGI_BOOL getVpdnCfg(json_object *request, FILE *conn_fp)
{
	int num;
	char value_t[8]={0},interface_t[8]={0};
	char rules[512]={0},rule[128]={0},tmp_buf[128]={0};
	const char *vpnType = webs_get_string(request, "vpnType"); //0:pptp; 1:l2tp
	
	struct interface_status status_paremeter;
	
	cJSON *root = cJSON_CreateObject();

	if(atoi(vpnType) == 0)//pptp
	{
		strcpy(interface_t,"pptp");
	}
	else if(atoi(vpnType) == 1)//l2tp
	{
		strcpy(interface_t,"l2tp");
	}

	
	Uci_Get_Str(PKG_NETWORK_CONFIG, interface_t, "disabled", value_t);
	if(atoi(value_t) == 0)
	{
		cJSON_AddStringToObject(root, "enablec", "1");
	}
	else
	{
		cJSON_AddStringToObject(root, "enablec", "0");
	}
	
	get_uci2json(root, PKG_NETWORK_CONFIG, interface_t, "server", "serverip");
	get_uci2json(root, PKG_NETWORK_CONFIG, interface_t, "username", "user");
	get_uci2json(root, PKG_NETWORK_CONFIG, interface_t, "password", "pass");
	get_uci2json(root, PKG_NETWORK_CONFIG, interface_t, "defaultroute", "defr");
	get_uci2json(root, PKG_NETWORK_CONFIG, interface_t, "lanMasq", "lanMasq");
	get_uci2json(root, PKG_NETWORK_CONFIG, interface_t, "snat", "ipMasq");
	

	memset(&status_paremeter, 0, sizeof(struct interface_status));
	get_interface_status(&status_paremeter, interface_t);
	if(status_paremeter.up){
		cJSON_AddStringToObject(root, "connect", "1");
		cJSON_AddStringToObject(root, "addr", status_paremeter.ipaddr_v4);
	}
	else{
		cJSON_AddStringToObject(root, "connect", "0");
		cJSON_AddStringToObject(root, "addr", "");
	}
	
	cJSON *array, *sub_obj;
	array = cJSON_CreateArray();
	cJSON_AddItemToObject(root,"subnet", array);
	Uci_Get_Int(PKG_NETWORK_CONFIG, interface_t, "router_num", &num);
	if(num > 0){
		Uci_Get_Str(PKG_NETWORK_CONFIG, interface_t, "rules", rules);
		for(int idx=0; idx< num; idx++)
		{
			sub_obj=cJSON_CreateObject();
			cJSON_AddItemToArray(array, sub_obj);
			
			get_nth_val_safe(idx, rules, ' ', rule, sizeof(rules));
			get_nth_val_safe(0, rule, ',', tmp_buf, sizeof(tmp_buf));
			cJSON_AddStringToObject(sub_obj, "net", tmp_buf);
			
			memset(tmp_buf, 0, sizeof(tmp_buf));
			get_nth_val_safe(1, rule, ',', tmp_buf, sizeof(tmp_buf));
			cJSON_AddStringToObject(sub_obj, "mask", tmp_buf);
		}
	}
	

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;	

}


CGI_BOOL setVpdnCfg(json_object *request, FILE *conn_fp)
{
	int num,idx;
	char rules[512]={0},rule[128]={0},tmp_buf[8]={0},interface_t[16]={0};
	
	const char *vpnType = webs_get_string(request, "vpnType"); //0:pptp; 1:l2tp
	
	char *enable = webs_get_string(request, "enablec");
	char *server = webs_get_string(request, "serverip");
	char *user = webs_get_string(request, "user");
	char *pass = webs_get_string(request, "pass");
	char *snat = webs_get_string(request, "ipMasq");
	char *lanMasq = webs_get_string(request, "lanMasq");
	char *defr = webs_get_string(request, "defr");


	if(atoi(vpnType) == 0)//pptp
	{
		strcpy(interface_t,"pptp");
		Uci_Set_Str(PKG_NETWORK_CONFIG, interface_t, "proto", "pptp");
	}
	else if(atoi(vpnType) == 1)//l2tp
	{
		strcpy(interface_t,"l2tp");
		Uci_Set_Str(PKG_NETWORK_CONFIG,interface_t, "proto", "l2tp");
	}

	
	if(atoi(enable) == 1) 
	{
		Uci_Set_Str(PKG_NETWORK_CONFIG, interface_t, "disabled", "0");
		Uci_Set_Str(PKG_NETWORK_CONFIG, interface_t, "server", server);
		Uci_Set_Str(PKG_NETWORK_CONFIG, interface_t, "username", user);
		Uci_Set_Str(PKG_NETWORK_CONFIG, interface_t, "password", pass);
		Uci_Set_Str(PKG_NETWORK_CONFIG, interface_t, "snat", snat);
		Uci_Set_Str(PKG_NETWORK_CONFIG, interface_t, "lanMasq", lanMasq);
		Uci_Set_Str(PKG_NETWORK_CONFIG, interface_t, "defaultroute", defr);
		Uci_Set_Str(PKG_NETWORK_CONFIG, interface_t, "defr", defr);
		

				//delete all rules
		Uci_Get_Int(PKG_NETWORK_CONFIG, interface_t, "router_num", &num);
		if(num > 0){
			Uci_Get_Str(PKG_NETWORK_CONFIG, interface_t, "rules", rules);
			for(idx=0; idx< num; idx++)
			{
				get_nth_val_safe(idx, rules, ' ', rule, sizeof(rules));
				Uci_Del_List(PKG_NETWORK_CONFIG, interface_t, "rules", rule);
			}
			Uci_Set_Str(PKG_NETWORK_CONFIG, interface_t, "router_num", "0");
		}

		json_object_object_foreach(request, key, val) {
			if (strcmp(key, "subnet") == 0) {
				struct array_list *subnet;
				subnet = json_object_get_array(val);
				num = json_object_array_length(val);
		
				sprintf(tmp_buf, "%d", num);
				Uci_Set_Str(PKG_NETWORK_CONFIG, interface_t, "router_num", tmp_buf);
		
				for(idx = 0; idx < num; idx++) {
		
					struct json_object *subnet_x = (struct json_object *)array_list_get_idx(subnet, idx);
		
					char *net = webs_get_string(subnet_x, "net");
					char *mask = webs_get_string(subnet_x, "mask");

					if(strlen(net) > 0){
						memset(rule, 0, sizeof(rule));
						sprintf(rule, "%s,%s", net, mask);
						Uci_Add_List(PKG_NETWORK_CONFIG, interface_t, "rules", rule);
					}
				}
			}
		}

	}
	else
	{
		Uci_Set_Str(PKG_NETWORK_CONFIG, interface_t, "disabled", "1");
	}

	set_lktos_effect("network");

	Uci_Commit(PKG_NETWORK_CONFIG);

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "10", "reserv");
}


CGI_BOOL getL2tpClientCfg(json_object *request, FILE *conn_fp)
{
	int value=0, num=0, idx=0;
	char rules[512]={0}, rule[32]={0}, tmp_buf[16]={0};
	struct interface_status status_paremeter;
	
	cJSON *root = cJSON_CreateObject();
	
	Uci_Get_Int(PKG_NETWORK_CONFIG, "vpn", "disabled", &value);
	if(value == 0){
		cJSON_AddStringToObject(root, "enablec", "1");
	}
	else{
		cJSON_AddStringToObject(root, "enablec", "0");
	}
	
	get_uci2json(root, PKG_NETWORK_CONFIG, "vpn", "server", "serverip");
	get_uci2json(root, PKG_NETWORK_CONFIG, "vpn", "username", "user");
	get_uci2json(root, PKG_NETWORK_CONFIG, "vpn", "password", "pass");

	get_uci2json(root, PKG_NETWORK_CONFIG, "vpn", "snat", "ipMasq");

	memset(&status_paremeter, 0, sizeof(struct interface_status));
	get_interface_status(&status_paremeter, "vpn");
	if(status_paremeter.up){
		cJSON_AddStringToObject(root, "connect", "1");
		cJSON_AddStringToObject(root, "addr", status_paremeter.ipaddr_v4);
	}
	else{
		cJSON_AddStringToObject(root, "connect", "0");
		cJSON_AddStringToObject(root, "addr", "");
	}

	cJSON *array, *sub_obj;
	array = cJSON_CreateArray();
	cJSON_AddItemToObject(root,"subnet", array);
	Uci_Get_Int(PKG_NETWORK_CONFIG, "vpn", "router_num", &num);
	if(num > 0){
		Uci_Get_Str(PKG_NETWORK_CONFIG, "vpn", "rules", rules);
		for(idx=0; idx< num; idx++)
		{
			sub_obj=cJSON_CreateObject();
			cJSON_AddItemToArray(array, sub_obj);
			
			get_nth_val_safe(idx, rules, ' ', rule, sizeof(rules));
			get_nth_val_safe(0, rule, ',', tmp_buf, sizeof(tmp_buf));
			cJSON_AddStringToObject(sub_obj, "net", tmp_buf);
			
			memset(tmp_buf, 0, sizeof(tmp_buf));
			get_nth_val_safe(1, rule, ',', tmp_buf, sizeof(tmp_buf));
			cJSON_AddStringToObject(sub_obj, "mask", tmp_buf);
		}
	}
	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;	
}

/*
	{"bindExport":"","vpnType":"1","enablec":"1","subnet":[],"serverip":"10.0.200.231","user":"test",\
	"pass":"test","ipMasq":"0","lanMasq":"0","topicurl":"setL2tpClientCfg"}: 
*/
CGI_BOOL setL2tpClientCfg(json_object *request,FILE *conn_fp)
{
	int idx=0, num=0;
	char rules[512]={0}, rule[64]={0}, tmp_buf[32]={0};
	
	char *enable = webs_get_string(request, "enablec");
	char *server = webs_get_string(request, "serverip");
	char *user = webs_get_string(request, "user");
	char *pass = webs_get_string(request, "pass");
	char *snat = webs_get_string(request, "ipMasq");
	
	if(atoi(enable) == 1){
		Uci_Set_Str(PKG_NETWORK_CONFIG, "vpn", "disabled", "0");
		Uci_Set_Str(PKG_NETWORK_CONFIG, "vpn", "proto", "l2tp");
		Uci_Set_Str(PKG_NETWORK_CONFIG, "vpn", "server", server);
		Uci_Set_Str(PKG_NETWORK_CONFIG, "vpn", "username", user);
		Uci_Set_Str(PKG_NETWORK_CONFIG, "vpn", "password", pass);
		Uci_Set_Str(PKG_NETWORK_CONFIG, "vpn", "snat", snat);
#if 1
		//delete all rules
		Uci_Get_Int(PKG_NETWORK_CONFIG, "vpn", "router_num", &num);
		if(num > 0){
			Uci_Get_Str(PKG_NETWORK_CONFIG, "vpn", "rules", rules);
			for(idx=0; idx< num; idx++)
			{
				get_nth_val_safe(idx, rules, ' ', rule, sizeof(rules));
				Uci_Del_List(PKG_NETWORK_CONFIG, "vpn", "rules", rule);
			}
			Uci_Set_Str(PKG_NETWORK_CONFIG, "vpn", "router_num", "0");
		}
	
		json_object_object_foreach(request, key, val) {
			if (strcmp(key, "subnet") == 0) {
				struct array_list *subnet;
				subnet = json_object_get_array(val);
				num = json_object_array_length(val);

				sprintf(tmp_buf, "%d", num);
				Uci_Set_Str(PKG_NETWORK_CONFIG, "vpn", "router_num", tmp_buf);

				for(idx = 0; idx < num; idx++) {

					struct json_object *subnet_x = (struct json_object *)array_list_get_idx(subnet, idx);

					char *net = webs_get_string(subnet_x, "net");
					char *mask = webs_get_string(subnet_x, "mask");

					memset(rule, 0, sizeof(rule));
					sprintf(rule, "%s,%s", net, mask);
					Uci_Add_List(PKG_NETWORK_CONFIG, "vpn", "rules", rule);
				}

			}
		}		
#endif
	}
	else{
		Uci_Set_Str(PKG_NETWORK_CONFIG, "vpn", "disabled", "1");
		Uci_Set_Str(PKG_NETWORK_CONFIG, "vpn", "proto", "");
	}	
	
	Uci_Commit(PKG_NETWORK_CONFIG);

	set_lktos_effect("network");

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "10", "reserv");

	return CGI_TRUE;
}

CGI_BOOL getPptpClientCfg(json_object *request, FILE *conn_fp)
{
	int value=0, num=0, idx=0;
	char rules[512]={0}, rule[32]={0}, tmp_buf[16]={0};
	struct interface_status status_paremeter;
	
	cJSON *root = cJSON_CreateObject();
	
	Uci_Get_Int(PKG_NETWORK_CONFIG, "vpn1", "disabled", &value);
	if(value == 0){
		cJSON_AddStringToObject(root, "enablec", "1");
	}
	else{
		cJSON_AddStringToObject(root, "enablec", "0");
	}
	
	get_uci2json(root, PKG_NETWORK_CONFIG, "vpn1", "server", "serverip");
	get_uci2json(root, PKG_NETWORK_CONFIG, "vpn1", "username", "user");
	get_uci2json(root, PKG_NETWORK_CONFIG, "vpn1", "password", "pass");

	get_uci2json(root, PKG_NETWORK_CONFIG, "vpn1", "snat", "ipMasq");
	get_uci2json(root, PKG_NETWORK_CONFIG, "vpn1", "mppe", "mppe");

	memset(&status_paremeter, 0, sizeof(struct interface_status));
	get_interface_status(&status_paremeter, "vpn1");
	if(status_paremeter.up){
		cJSON_AddStringToObject(root, "connect", "1");
		cJSON_AddStringToObject(root, "addr", status_paremeter.ipaddr_v4);
	}
	else{
		cJSON_AddStringToObject(root, "connect", "0");
		cJSON_AddStringToObject(root, "addr", "");
	}

	cJSON *array, *sub_obj;
	array = cJSON_CreateArray();
	cJSON_AddItemToObject(root,"subnet", array);
	Uci_Get_Int(PKG_NETWORK_CONFIG, "vpn1", "router_num", &num);
	if(num > 0){
		Uci_Get_Str(PKG_NETWORK_CONFIG, "vpn1", "rules", rules);
		for(idx=0; idx< num; idx++)
		{
			sub_obj=cJSON_CreateObject();
			cJSON_AddItemToArray(array, sub_obj);
			
			get_nth_val_safe(idx, rules, ' ', rule, sizeof(rules));
			get_nth_val_safe(0, rule, ',', tmp_buf, sizeof(tmp_buf));
			cJSON_AddStringToObject(sub_obj, "net", tmp_buf);
			
			memset(tmp_buf, 0, sizeof(tmp_buf));
			get_nth_val_safe(1, rule, ',', tmp_buf, sizeof(tmp_buf));
			cJSON_AddStringToObject(sub_obj, "mask", tmp_buf);
		}
	}
		
	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;	
}

/*
	{"bindExport":"","vpnType":"1","enablec":"1","subnet":[],"serverip":"10.0.200.231","user":"test",\
	"pass":"test","ipMasq":"0","lanMasq":"0","topicurl":"setL2tpClientCfg"}: 
*/
CGI_BOOL setPptpClientCfg(json_object *request,FILE *conn_fp)
{
	int idx=0, num=0;
	char rules[512]={0}, rule[64]={0}, tmp_buf[32]={0};

	char *enable = webs_get_string(request, "enablec");
	char *server = webs_get_string(request, "serverip");
	char *user = webs_get_string(request, "user");
	char *pass = webs_get_string(request, "pass");
	char *snat = webs_get_string(request, "ipMasq");
	char *mppe = webs_get_string(request, "mppe");
	
	if(atoi(enable) == 1){
		Uci_Set_Str(PKG_NETWORK_CONFIG, "vpn1", "disabled", "0");
		Uci_Set_Str(PKG_NETWORK_CONFIG, "vpn1", "proto", "pptp");
		Uci_Set_Str(PKG_NETWORK_CONFIG, "vpn1", "server", server);
		Uci_Set_Str(PKG_NETWORK_CONFIG, "vpn1", "username", user);
		Uci_Set_Str(PKG_NETWORK_CONFIG, "vpn1", "password", pass);
		Uci_Set_Str(PKG_NETWORK_CONFIG, "vpn1", "snat", snat);
		Uci_Set_Str(PKG_NETWORK_CONFIG, "vpn1", "mppe", mppe);

#if 1
		//delete all rules
		Uci_Get_Int(PKG_NETWORK_CONFIG, "vpn1", "router_num", &num);
		if(num > 0){
			Uci_Get_Str(PKG_NETWORK_CONFIG, "vpn1", "rules", rules);
			for(idx=0; idx< num; idx++)
			{
				get_nth_val_safe(idx, rules, ' ', rule, sizeof(rules));
				Uci_Del_List(PKG_NETWORK_CONFIG, "vpn1", "rules", rule);
			}
			Uci_Set_Str(PKG_NETWORK_CONFIG, "vpn1", "router_num", "0");
		}
	
		json_object_object_foreach(request, key, val) {
			if (strcmp(key, "subnet") == 0) {
				struct array_list *subnet;
				subnet = json_object_get_array(val);
				num = json_object_array_length(val);

				sprintf(tmp_buf, "%d", num);
				Uci_Set_Str(PKG_NETWORK_CONFIG, "vpn1", "router_num", tmp_buf);

				for(idx = 0; idx < num; idx++) {

					struct json_object *subnet_x = (struct json_object *)array_list_get_idx(subnet, idx);

					char *net = webs_get_string(subnet_x, "net");
					char *mask = webs_get_string(subnet_x, "mask");

					memset(rule, 0, sizeof(rule));
					sprintf(rule, "%s,%s", net, mask);
					Uci_Add_List(PKG_NETWORK_CONFIG, "vpn1", "rules", rule);
				}

			}
		}		
#endif
	}else{
		Uci_Set_Str(PKG_NETWORK_CONFIG, "vpn1", "disabled", "1");
		Uci_Set_Str(PKG_NETWORK_CONFIG, "vpn1", "proto", "");
	}
	
	Uci_Commit(PKG_NETWORK_CONFIG);

	set_lktos_effect("network");

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "10", "reserv");

	return CGI_TRUE;
}


CGI_HANDLE_TABLE vpn_handle_t[]={
	{"getEoipCfg", getEoipCfg, 1},
	{"setEoipCfg", setEoipCfg, 1},

	{"getTunnelCfg", getTunnelCfg, 1},
	{"setTunnelCfg", setTunnelCfg, 1},

	{"getIpsecHost2NetCfg", getIpsecHost2NetCfg, 1},
	{"setIpsecHost2NetCfg", setIpsecHost2NetCfg, 1},

	{"getIpsecHeartCheckCfg", getIpsecHeartCheckCfg, 1},
	{"setIpsechHeartCheckCfg", setIpsechHeartCheckCfg, 1},

	{"getIpsecStatus", getIpsecStatus, 1},

	{"getIpsecCertCfg", getIpsecCertCfg, 1},
	
	{"getIpsecNet2NetCfg", getIpsecNet2NetCfg, 1},
	{"setIpsecNet2NetCfg", setIpsecNet2NetCfg, 1},

	{"delIpsecNet2NetCfg", delIpsecNet2NetCfg, 1},

	{"getTfCfg", getTfCfg, 1},
	{"setTfCfg", setTfCfg, 1},

	{"getVpnMultiClientCfg", getVpnMultiClientCfg, 1},
	{"setVpnMultiClientCfg", setVpnMultiClientCfg, 1},
	
	{"getOpenVpnClientCfg", getOpenVpnClientCfg, 1},
	{"setOpenVpnClientCfg", setOpenVpnClientCfg, 1},
	{"UploadOpenVpnCert", UploadOpenVpnCert,1},

	{"getOpenVpnServerCfg", getOpenVpnServerCfg, 1},
	{"setOpenVpnServerCfg", setOpenVpnServerCfg, 1},
	{"getVpnAccountCfg", getVpnAccountCfg, 1},
	{"getUserInfo", getUserInfo, 1},
	
	{"getTunnelRouteCfg", getTunnelRouteCfg, 1},
	{"setTunnelRouteCfg", setTunnelRouteCfg, 1},

	{"getL2tpServerCfg", getL2tpServerCfg, 1},
	{"setL2tpServerCfg", setL2tpServerCfg, 1},
	
	{"getL2tpClientCfg", getL2tpClientCfg, 1},
	{"setL2tpClientCfg", setL2tpClientCfg, 1},
	
	{"getPptpClientCfg", getPptpClientCfg, 1},
	{"setPptpClientCfg", setPptpClientCfg, 1},

	{"getVpdnCfg", getVpdnCfg, 1},
	{"setVpdnCfg", setVpdnCfg, 1},
	
#if defined(CONFIG_SSLVPN_SUPPORT)
	{"getSslVpnTunCfg", getSslVpnTunCfg, 1},
	{"setSslVpnTunCfg", setSslVpnTunCfg, 1},


	{"getSslVpnCfg", getSslVpnCfg, 1},
	{"setSslVpnCfg", setSslVpnCfg, 1},

	{"setSslVpnCertCfg", setSslVpnCertCfg, 1},
	{"setSslVpnLoad", setSslVpnLoad, 1},

	{"getSslVpnCertStatus", getSslVpnCertStatus, 1},
	{"setSslVpnCertStatus", setSslVpnCertStatus, 1},
#endif


	{"getVxlanCfg", getVxlanCfg, 1},
	{"setVxlanCfg", setVxlanCfg, 1},

	{"", NULL, 0},
};

