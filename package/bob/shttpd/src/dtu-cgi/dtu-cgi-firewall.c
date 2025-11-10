#include "../defs.h"

CGI_BOOL getMacFilterRules(json_object *request, FILE *conn_fp)
{
	int iRulesNum=0, i=0;
	char sEnable[4]={0}, sLanIp[32]={0}, sLanMask[32]={0};
	char sRules[4096]={0}, sRule[512]={0},sDrop[4]={0};
	char sMac[RESULT_STR_LEN]={0}, sData[RESULT_STR_LEN]={0};
	char sTime[RESULT_STR_LEN]={0}, sCm[OPTION_STR_LEN]={0};
	char tmpBuf[SHORT_STR_LEN]={0};
	char sIdx[4]={0};

	char *output=NULL;
	cJSON *root, *connArray, *connEntry;
	root = cJSON_CreateObject();

	Uci_Get_Str(PKG_CSFW_CONFIG,"mac","enable",sEnable);
	cJSON_AddStringToObject(root,"enable", sEnable);
	if(atoi(sEnable) == 0){
		cJSON_AddStringToObject(root,"authMode", "0");
	}else{
		Uci_Get_Str(PKG_CSFW_CONFIG, "mac", "drop", sDrop);
		if(atoi(sDrop) == 0)//whilelist
			cJSON_AddStringToObject(root,"authMode", "1");
		else
			cJSON_AddStringToObject(root,"authMode", "2");
	}
	connArray = cJSON_CreateArray();
	cJSON_AddItemToObject(root, "rule", connArray);
	Uci_Get_Int(PKG_CSFW_CONFIG,"mac","num",&iRulesNum);
	Uci_Get_Str(PKG_CSFW_CONFIG,"mac","rules",sRules);
	
	for(i=0;i<iRulesNum;i++)
	{
		get_nth_val_safe(i, sRules, ' ', sRule, sizeof(sRule));

		if((get_nth_val_safe(0, sRule, ',', sMac, sizeof(sMac)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(1, sRule, ',', sData, sizeof(sData)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(2, sRule, ',', sTime, sizeof(sTime)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(3, sRule, ',', sCm, sizeof(sCm)) == -1))
		{
			continue;
		}

		connEntry = cJSON_CreateObject();
		sprintf(sIdx, "%d", i+1);
		cJSON_AddStringToObject(connEntry,"idx", sIdx);
		cJSON_AddStringToObject(connEntry,"mac", sMac);
		cJSON_AddStringToObject(connEntry,"desc", strlen(sCm)?sCm:"");
		cJSON_AddStringToObject(connEntry,"date", sData);
		cJSON_AddStringToObject(connEntry,"time", sTime);
		snprintf(tmpBuf,SHORT_STR_LEN,"delRule%d",i);
		cJSON_AddStringToObject(connEntry, "delRuleName", tmpBuf);
		cJSON_AddItemToArray(connArray,connEntry);
	}

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}


CGI_BOOL setMacFilterRules(json_object *request, FILE *conn_fp)
{
	struct array_list *subArry;
	int firewall_enabled=0;
	char *time, *date;
	char time_d[16] = {0}, date_d[16] = {0};
	char *mac, *comment;
	char rules[4096]={0}, tmpBuf[128]={0},enable[8]={0};
	int num=0, i;

	char *addEffect = webs_get_string(request, "addEffect");
	int authMode = atoi(webs_get_string(request, "authMode"));//0:disabled 1:whitelist 2:black
	
	

	if(atoi(addEffect) == 0)
	{
		if(authMode == 1){//whitelist
			firewall_enabled=1;
			Uci_Set_Str(PKG_CSFW_CONFIG, "mac", "drop", "0");
		}else if(authMode == 2){//black
			firewall_enabled=1;
			Uci_Set_Str(PKG_CSFW_CONFIG, "mac", "drop", "1");
		}else{
			firewall_enabled=0;
		}
		snprintf(enable, sizeof(enable), "%d", firewall_enabled);
		Uci_Set_Str(PKG_CSFW_CONFIG, "mac", "enable", enable);
	}
	else
	{
		//Delete the original rule
		Uci_Get_Int(PKG_CSFW_CONFIG, "mac", "num", &num);
		if(num > 0){
			Uci_Get_Str(PKG_CSFW_CONFIG,"mac","rules",rules);
			for(i=num; i>0; i--){
				memset(tmpBuf, '\0', sizeof(tmpBuf));
				get_nth_val_safe((i-1), rules, ' ', tmpBuf, sizeof(tmpBuf));
				Uci_Del_List(PKG_CSFW_CONFIG, "mac", "rules", tmpBuf);
			}	
			num=0;
			Uci_Set_Str(PKG_CSFW_CONFIG, "mac", "num", "0");
		}
		
		json_object_object_foreach(request, key, val) {
			if (strcmp(key, "subnet") == 0) {

				subArry = json_object_get_array(val);
				num = json_object_array_length(val);
				
				snprintf(tmpBuf, sizeof(tmpBuf), "%d", num);
				Uci_Set_Str(PKG_CSFW_CONFIG, "mac", "num", tmpBuf);
				for(i = 0; i < num; i++) {

					struct json_object *object_x = (struct json_object *)array_list_get_idx(subArry, i);

					mac=webs_get_string(object_x, "mac");
					comment=webs_get_string(object_x, "desc");
					time=webs_get_string(object_x, "time");
					date=webs_get_string(object_x, "date");

					if(strlen(time) > 0)
						strcpy(time_d, time);
					else
						strcpy(time_d, "00002359");

					if(strlen(date) > 0)
						strcpy(date_d, date);
					else
						strcpy(date_d, "1111111");
					
					memset(rules, '\0', sizeof(rules));
					sprintf(rules, "%s,%s,%s,%s", mac, time_d, date_d, comment);
					Uci_Add_List(PKG_CSFW_CONFIG, "mac", "rules", rules);
					
				}
				break;
			}
		}
	}

	Uci_Commit(PKG_CSFW_CONFIG);

	set_lktos_effect("firewall");

end_label:
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

	return CGI_TRUE;
}

CGI_BOOL getIpPortFilterRules(json_object *request, FILE *conn_fp)
{
	int iRulesNum=0, i=0;
	char sIdx[4]={0}, tmpBuf[SHORT_STR_LEN]={0};
	char sEnable[4]={0}, sLanIp[RESULT_STR_LEN]={0}, sLanMask[RESULT_STR_LEN]={0};
	char sRules[LONGLONG_BUFF_LEN]={0}, sRule[LIST_STR_LEN]={0};
	char ip[SHORT_STR_LEN]={0}, sPort[SMALL_STR_LEN]={0}, ePort[SMALL_STR_LEN]={0}; 
	char dIp[SHORT_STR_LEN]={0}, dsPort[SMALL_STR_LEN]={0}, dePort[SMALL_STR_LEN]={0};
	char inDir[SHORT_STR_LEN]={0}, outDir[8]={0}, proto[SHORT_STR_LEN]={0}, comment[33]={0};
	
	char *output=NULL;
	cJSON *connArray, *connEntry , *root;

	root = cJSON_CreateObject();

	Uci_Get_Str(PKG_CSFW_CONFIG, "ipport", "enable", sEnable);
	Uci_Get_Str(PKG_NETWORK_CONFIG, "lan", "ipaddr", sLanIp);
	Uci_Get_Str(PKG_NETWORK_CONFIG, "lan", "netmask", sLanMask);


	cJSON_AddStringToObject(root, "interface", "ALL,LAN,WAN,MODEM");

	cJSON_AddStringToObject(root, "authMode", sEnable);
	cJSON_AddStringToObject(root, "ip", sLanIp);
	cJSON_AddStringToObject(root, "mask", sLanMask);

	connArray = cJSON_CreateArray();
	cJSON_AddItemToObject(root, "rule", connArray);
	Uci_Get_Int(PKG_CSFW_CONFIG, "ipport", "num", &iRulesNum);
	Uci_Get_Str(PKG_CSFW_CONFIG, "ipport", "rules", sRules);

	for(i=0; i<iRulesNum; i++)
	{
		get_nth_val_safe(i, sRules, ' ', sRule, sizeof(sRule));
		//ip, sPort, ePort, dIp, dsPort, dePort, input, output, proto, comment
		
		if((get_nth_val_safe(0, sRule, ',', ip, sizeof(ip)) == -1))
		{
			i++;
			continue;
		}
		if(!is_netmask_valid(ip))
		{
			i++;
			continue;
		}

		if((get_nth_val_safe(1, sRule, ',', sPort, sizeof(sPort)) == -1))
		{
			i++;
			continue;
		}

		if((get_nth_val_safe(2, sRule, ',', ePort, sizeof(ePort)) == -1))
		{
			i++;
			continue;
		}

		if((get_nth_val_safe(3, sRule, ',', dIp, sizeof(dIp)) == -1))
		{
			i++;
			continue;
		}

		if(!is_netmask_valid(dIp))
		{
			i++;
			continue;
		}
		
		if((get_nth_val_safe(4, sRule, ',', dsPort, sizeof(dsPort)) == -1))
		{
			i++;
			continue;
		}

		if((get_nth_val_safe(5, sRule, ',', dePort, sizeof(dePort)) == -1))
		{
			i++;
			continue;
		}

		if((get_nth_val_safe(6, sRule, ',', inDir, sizeof(inDir)) == -1))
		{
			i++;
			continue;
		}

		if((get_nth_val_safe(7, sRule, ',', outDir, sizeof(outDir)) == -1))
		{
			i++;
			continue;
		}
		
		
		if((get_nth_val_safe(8, sRule, ',', proto, sizeof(proto)) == -1))
		{
			i++;
			continue;
		}

		if((get_nth_val_safe(9, sRule, ',', comment, sizeof(comment)) == -1))
		{
			i++;
			continue;
		}

		connEntry = cJSON_CreateObject();
		sprintf(sIdx, "%d", i+1);
		cJSON_AddStringToObject(connEntry,"idx", sIdx);
		cJSON_AddStringToObject(connEntry,"ip", ip);
		cJSON_AddStringToObject(connEntry,"sPort", sPort);
		cJSON_AddStringToObject(connEntry,"ePort", ePort);

		cJSON_AddStringToObject(connEntry,"dip", dIp);
		cJSON_AddStringToObject(connEntry,"dsPort", dsPort);
		cJSON_AddStringToObject(connEntry,"dePort", dePort);

		cJSON_AddStringToObject(connEntry,"input", inDir);
		cJSON_AddStringToObject(connEntry,"output", outDir);
		
		cJSON_AddStringToObject(connEntry,"proto", proto);
		cJSON_AddStringToObject(connEntry,"desc", strlen(comment)?comment:"");
		snprintf(tmpBuf,SHORT_STR_LEN,"delRule%d",i);
		cJSON_AddStringToObject(connEntry, "delRuleName", tmpBuf);
		cJSON_AddItemToArray(connArray,connEntry);
	}

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}


CGI_BOOL setIpPortFilterRules(json_object *request, FILE *conn_fp)
{
	char *ip, *sPort, *ePort;
	char *dIp, *dsPort, *dePort;
	char *inDir, *outDir, *proto, *comment;
	char tmpBuf[CMD_STR_LEN]={0};
	char rules[LONGLONG_BUFF_LEN]={0}, rule[CMD_STR_LEN]={0};

	int num=0, i;
	struct array_list *subArry;
	
	char *addEffect = webs_get_string(request, "addEffect");
	int authMode = atoi(webs_get_string(request, "authMode"));
	
	if (atoi(addEffect) == 0)
	{
		if(authMode == 1){//whitelist
			sprintf(tmpBuf, "%d", 1);
			Uci_Set_Str(PKG_CSFW_CONFIG, "ipport", "drop", "0");
		}else if(authMode == 2){//black
			sprintf(tmpBuf, "%d", 2);
			Uci_Set_Str(PKG_CSFW_CONFIG, "ipport", "drop", "1");
		}else{
			sprintf(tmpBuf, "%d", 0);
		}
		
		Uci_Set_Str(PKG_CSFW_CONFIG, "ipport", "enable", tmpBuf);
	}
	else 
	{
		Uci_Get_Int(PKG_CSFW_CONFIG, "ipport", "num", &num);
		if(num > 0){
			Uci_Get_Str(PKG_CSFW_CONFIG,"ipport","rules",rules);
			for(i=num; i>0; i--){
				memset(tmpBuf, '\0', sizeof(tmpBuf));
				get_nth_val_safe((i-1), rules, ' ', tmpBuf, sizeof(tmpBuf));
				Uci_Del_List(PKG_CSFW_CONFIG, "ipport", "rules", tmpBuf);
			}	
			num=0;
			Uci_Set_Str(PKG_CSFW_CONFIG, "ipport", "num", "0");
		}

		json_object_object_foreach(request, key, val) {
			if (strcmp(key, "subnet") == 0) {

				subArry = json_object_get_array(val);
				num = json_object_array_length(val);
				
				if(num > FILTER_RULE_NUM)
					snprintf(tmpBuf, sizeof(tmpBuf), "%d", FILTER_RULE_NUM);
				else
					snprintf(tmpBuf, sizeof(tmpBuf), "%d", num);
				Uci_Set_Str(PKG_CSFW_CONFIG, "ipport", "num", tmpBuf);
				
				for(i = 0; i < num; i++) {
					if(i > FILTER_RULE_NUM)
						goto end_labal;
					
					struct json_object *object_x = (struct json_object *)array_list_get_idx(subArry, i);

					ip=webs_get_string(object_x, "ip");
					sPort = webs_get_string(object_x, "sPort");
					ePort = webs_get_string(object_x, "ePort");
					
					dIp = webs_get_string(object_x, "dip");
					dsPort = webs_get_string(object_x, "dsPort");
					dePort = webs_get_string(object_x, "dePort");

					inDir =  webs_get_string(object_x, "input");
					outDir =  webs_get_string(object_x, "output");

					proto = webs_get_string(object_x, "proto");
					comment=webs_get_string(object_x, "desc");
					
					memset(rule, '\0', sizeof(rule));
					sprintf(rule, "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s", ip, sPort, ePort, dIp, \
						dsPort, dePort, inDir, outDir, proto, comment);
					Uci_Add_List(PKG_CSFW_CONFIG, "ipport", "rules", rule);
					
				}
				break;
			}
		}		
	}
end_labal:

	Uci_Commit(PKG_CSFW_CONFIG);

	set_lktos_effect("firewall");

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");
	
	return CGI_TRUE;	
}

CGI_BOOL getPortForwardRules(json_object *request, FILE *conn_fp)
{
	int iRulesNum=0, i=0, proto=0;
	char sEnable[4]={0}, sLanIp[32]={0}, sLanMask[32]={0};
	char sRules[4096]={0}, sRule[512]={0};
	char ip_address[RESULT_STR_LEN]={0};
	char comment[OPTION_STR_LEN]={0};
	char protocol[RESULT_STR_LEN]={0};
	char inPort[SHORT_STR_LEN]={0},outPort[SHORT_STR_LEN]={0},remoteEnabled[SHORT_STR_LEN]={0};
	char sIdx[4]={0},wanIdx[OPTION_STR_LEN]={0};
	char tmpBuf[SHORT_STR_LEN]={0}, port[SHORT_STR_LEN]={0};
	char *output=NULL;
	
	cJSON *connArray, *connEntry, *root;

	root = cJSON_CreateObject();
	
	Uci_Get_Str(PKG_CSFW_CONFIG, "portfw", "enable", sEnable);
	Uci_Get_Str(PKG_NETWORK_CONFIG, "lan", "ipaddr", sLanIp);
	Uci_Get_Str(PKG_NETWORK_CONFIG, "lan", "netmask", sLanMask);
	cJSON_AddStringToObject(root, "enable", sEnable);
	cJSON_AddStringToObject(root, "lanIp", sLanIp);
	cJSON_AddStringToObject(root, "lanNetmask", sLanMask);

	Uci_Get_Str(PKG_CSFW_CONFIG, "remote", "port", port);
	Uci_Get_Str(PKG_CSFW_CONFIG, "remote", "enable", remoteEnabled);

	if(atoi(remoteEnabled)==0)
	{
		cJSON_AddStringToObject(root, "remotePort", "0");
	}
	else if(atoi(remoteEnabled)==1)
	{
		cJSON_AddStringToObject(root, "remotePort", port);
	}

	connArray = cJSON_CreateArray();
	cJSON_AddItemToObject(root, "rule", connArray);

	Uci_Get_Int(PKG_CSFW_CONFIG, "portfw", "num", &iRulesNum);
	Uci_Get_Str(PKG_CSFW_CONFIG, "portfw", "rules", sRules);

	for(i=0;i<iRulesNum;i++)
	{
		get_nth_val_safe(i, sRules, ' ', sRule, sizeof(sRule));

		if((get_nth_val_safe(0, sRule, ',', ip_address, sizeof(ip_address)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(1, sRule, ',', protocol, sizeof(protocol)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(2, sRule, ',', inPort, sizeof(inPort)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(3, sRule, ',', outPort, sizeof(outPort)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(4, sRule, ',', comment, sizeof(comment)) == -1))
		{
			continue;
		}

		connEntry = cJSON_CreateObject();
		sprintf(sIdx, "%d", i+1);
		cJSON_AddStringToObject(connEntry, "idx", sIdx);
		cJSON_AddStringToObject(connEntry, "ip", ip_address);
		cJSON_AddStringToObject(connEntry, "proto", protocol);
		cJSON_AddStringToObject(connEntry, "ePort", outPort);
		cJSON_AddStringToObject(connEntry, "iPort", inPort);

		cJSON_AddStringToObject(connEntry, "desc", strlen(comment) ? comment : "");
		snprintf(tmpBuf,SHORT_STR_LEN, "delRule%d", i);
		cJSON_AddStringToObject(connEntry, "delRuleName", tmpBuf);
		cJSON_AddItemToArray(connArray, connEntry);
	}

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}


CGI_BOOL setPortForwardRules(json_object *request, FILE *conn_fp)
{
	char *addEffect = webs_get_string(request, "addEffect");
	char *portforwad_enabled = webs_get_string(request, "enable");
	char *ipAddress, *iPort, *ePort, *protocol, *comment;
	char rule[8192] = {0};
	char sRulesNum[8]={0};
	char *output=NULL;
	int rule_count=0;

	if (atoi(addEffect) == 0)
	{
		Uci_Set_Str(PKG_CSFW_CONFIG, "portfw", "enable", portforwad_enabled);
	}
	else
	{
		Uci_Get_Int(PKG_CSFW_CONFIG, "portfw", "num", &rule_count);

		ipAddress = webs_get_string(request, "ip");
		iPort = webs_get_string(request, "iPort");
		ePort = webs_get_string(request, "ePort");
		protocol = webs_get_string(request, "proto");
		comment = webs_get_string(request, "desc");

		if(!ipAddress && !strlen(ipAddress))
		{
			goto end_label;
		}

		if(rule_count>FILTER_RULE_NUM || strlen(comment) > 64 || strchr(comment, ';') || strchr(comment, ','))
		{
			goto end_label;
		}

		//if( !strcmp(protocol, "ALL")) {
			//sprintf(protocol, "BOTH");
		//}

		snprintf(rule, sizeof(rule), "%s,%s,%s,%s,%s", ipAddress, protocol, iPort, ePort, comment);

		if (atoi(addEffect) == 1)
		{
			Uci_Add_List(PKG_CSFW_CONFIG, "portfw", "rules", rule);
			rule_count++;
			sprintf(sRulesNum, "%d", rule_count);
			Uci_Set_Str(PKG_CSFW_CONFIG, "portfw", "num", sRulesNum);
		}
		else if(atoi(addEffect)==2)
		{
			char sRules[4096]={0},Rules[4096]={0};
			char SaveRules[FILTER_RULE_NUM][256]={0};
			int i=0,j=0;
			char *idx=webs_get_string(request, "idx");

			Uci_Get_Str(PKG_CSFW_CONFIG,"portfw","rules",sRules);
			get_nth_val_safe(atoi(idx)-1, sRules, ' ', Rules, sizeof(Rules));
		
			for(i=atoi(idx),j=0;i<rule_count;i++)
			{
				get_nth_val_safe(i, sRules, ' ', SaveRules[j], sizeof(SaveRules[j]));
				Uci_Del_List(PKG_CSFW_CONFIG, "portfw", "rules", SaveRules[j]);
				j++;
			}
		
			Uci_Del_List(PKG_CSFW_CONFIG, "portfw", "rules", Rules);
			Uci_Add_List(PKG_CSFW_CONFIG, "portfw", "rules", rule);
	
			for(i=atoi(idx),j=0;i<rule_count;i++)
			{
				Uci_Add_List(PKG_CSFW_CONFIG, "portfw", "rules", SaveRules[j]);
				j++;
			}
		}
	}
	Uci_Commit(PKG_CSFW_CONFIG);

	set_lktos_effect("firewall");
end_label:
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");
	return CGI_TRUE;
}


CGI_BOOL delPortForwardRules(json_object *request, FILE *conn_fp)
{
	int  i=0,iRulesCount=0 ,iRulesCount_con=0;
	char sRules[4096]={0},Rules[4096]={0},name_buf[16],sRulesNum[8]={0};
	char *value;

	Uci_Get_Int(PKG_CSFW_CONFIG, "portfw", "num", &iRulesCount);
	Uci_Get_Int(PKG_CSFW_CONFIG, "portfw", "num", &iRulesCount_con);
	Uci_Get_Str(PKG_CSFW_CONFIG,"portfw","rules",sRules);

	for(i=0; i< iRulesCount; i++)
	{
		snprintf(name_buf, 16, "delRule%d", i);
		value = webs_get_string(request, name_buf);

		if(strlen(value) > 0)
		{
			get_nth_val_safe(atoi(value), sRules, ' ', Rules, sizeof(Rules));
			Uci_Del_List(PKG_CSFW_CONFIG, "portfw", "rules", Rules);
			iRulesCount_con--;
		}
	}

	sprintf(sRulesNum, "%d", iRulesCount_con);
	Uci_Set_Str(PKG_CSFW_CONFIG, "portfw", "num", sRulesNum);
	Uci_Commit(PKG_CSFW_CONFIG);

	set_lktos_effect("firewall");

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

	return CGI_TRUE;
}


CGI_BOOL getUrlFilterRules(json_object *request, FILE *conn_fp)
{
	int iRulesNum=0, i=0;
	char sEnable[4]={0};
	char sRules[2048]={0}, sRule[128]={0};
	char sUrl[OPTION_STR_LEN]={0},sData[RESULT_STR_LEN]={0},sTime[RESULT_STR_LEN]={0};
	char tmpBuf[SHORT_STR_LEN]={0};
	char sIdx[4]={0};

	char *output=NULL;
	cJSON *root, *connArray, *connEntry;

	root = cJSON_CreateObject();
	Uci_Get_Str(PKG_CSFW_CONFIG, "url", "enable", sEnable);
	cJSON_AddStringToObject(root,"enable", sEnable);

	connArray = cJSON_CreateArray();
	cJSON_AddItemToObject(root, "rule", connArray);

	Uci_Get_Int(PKG_CSFW_CONFIG, "url", "num", &iRulesNum);
	Uci_Get_Str(PKG_CSFW_CONFIG, "url", "rules", sRules);

	for(i=0;i<iRulesNum;i++)
	{
		get_nth_val_safe(i, sRules, ' ', sRule, sizeof(sRule));

		if((get_nth_val_safe(0, sRule, ',', sUrl, sizeof(sUrl)) == -1))
		{
			continue;
		}

		connEntry = cJSON_CreateObject();
		sprintf(sIdx, "%d", i+1);
		cJSON_AddStringToObject(connEntry, "idx", sIdx);
		cJSON_AddStringToObject(connEntry, "url", sUrl);
		snprintf(tmpBuf,SHORT_STR_LEN, "delRule%d", i);
		cJSON_AddStringToObject(connEntry, "delRuleName", tmpBuf);
		cJSON_AddItemToArray(connArray, connEntry);
	}

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}


CGI_BOOL setUrlFilterRules(json_object *request, FILE *conn_fp)
{
	char *addEffect = webs_get_string(request, "addEffect");
	char *firewall_enabled = webs_get_string(request, "enable");

	char tmpBuf[128]={0};
	char urlBuff[4096]={0}, rules[256]={0};
	struct array_list *subArry;
	int num=0, i;

	if (atoi(addEffect) == 0)
	{
		Uci_Set_Str(PKG_CSFW_CONFIG, "url", "enable", firewall_enabled);
	}
	else
	{
		Uci_Get_Str(PKG_CSFW_CONFIG, "url", "num", &num);
		if(num > 0){
			Uci_Get_Str(PKG_CSFW_CONFIG,"url","rules",urlBuff);
			for(i=num; i>0; i--){
				memset(tmpBuf, '\0', sizeof(tmpBuf));
				get_nth_val_safe((i-1), urlBuff, ' ', tmpBuf, sizeof(tmpBuf));
				Uci_Del_List(PKG_CSFW_CONFIG, "url", "rules", tmpBuf);
			}	
			num=0;
			Uci_Set_Str(PKG_CSFW_CONFIG, "url", "num", "0");
		}
		
		memset(tmpBuf, '\0', sizeof(tmpBuf));
		json_object_object_foreach(request, key, val){
			if(strcmp(key, "subnet") == 0){
				subArry = json_object_get_array(val);
				num = json_object_array_length(val);

				snprintf(tmpBuf, sizeof(tmpBuf), "%d", num);
				Uci_Set_Str(PKG_CSFW_CONFIG, "url", "num", tmpBuf);
				for(i=0; i<num; i++){
					struct json_object *objet_x = (struct json_object *)array_list_get_idx(subArry, i);
					
					char *url=webs_get_string(objet_x, "url");
					
					memset(rules, '\0', sizeof(rules));
					snprintf(rules, sizeof(rules), "%s", url);
					Uci_Add_List(PKG_CSFW_CONFIG, "url", "rules", rules);
				}
				
				break;
			}
		}		
	}

	Uci_Commit(PKG_CSFW_CONFIG);

	datconf_set_by_key(TEMP_STATUS_FILE, "only_restart_url", "0");

	set_lktos_effect("firewall");

end_label:
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

	return CGI_TRUE;
}

CGI_BOOL getDmzCfg(json_object *request, FILE *conn_fp)
{
	int iRulesNum = 0, idx = 0;
	char tmpBuf[TEMP_STR_LEN] = {0};
	char sRules[4096]={0}, sRule[LIST_STR_LEN]={0}, comment[33]={0};
	char port[SMALL_STR_LEN]={0}, srcIp[SHORT_STR_LEN]={0}, destIp[SHORT_STR_LEN]={0};
	
	cJSON *root, *respond_arry = NULL, *tmp_obj = NULL;

	root=cJSON_CreateObject();

	Uci_Get_Str(PKG_CSFW_CONFIG, "dmz", "enable", tmpBuf);
	
	cJSON_AddStringToObject(root, "enable", tmpBuf);
	cJSON_AddStringToObject(root, "interface", "WAN,MODEM");

	respond_arry = cJSON_CreateArray();
	cJSON_AddItemToObject(root, "rule", respond_arry);
	
	Uci_Get_Int(PKG_CSFW_CONFIG, "dmz", "num", &iRulesNum);

	Uci_Get_Str(PKG_CSFW_CONFIG, "dmz", "rules",  sRules);
	for(idx = 0; idx < iRulesNum; idx++) {
		tmp_obj=cJSON_CreateObject();

		get_nth_val_safe(idx, sRules, ' ', sRule, sizeof(sRule));

		if((get_nth_val_safe(0, sRule, ',', port, sizeof(port)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(1, sRule, ',', destIp, sizeof(destIp)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(2, sRule, ',', srcIp, sizeof(srcIp)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(3, sRule, ',', comment, sizeof(comment)) == -1))
		{
			continue;
		}

		memset(tmpBuf, 0, sizeof(tmpBuf));
		sprintf(tmpBuf, "%d", idx+1);
		cJSON_AddStringToObject(tmp_obj, "idx", tmpBuf);
		cJSON_AddStringToObject(tmp_obj, "sip", srcIp);
		cJSON_AddStringToObject(tmp_obj, "dip", destIp);
		cJSON_AddStringToObject(tmp_obj, "port", port);
		cJSON_AddStringToObject(tmp_obj, "desc", comment);

		memset(tmpBuf, 0, sizeof(tmpBuf));
		snprintf(tmpBuf, RESULT_STR_LEN, "delRule%d", idx);
		cJSON_AddStringToObject(tmp_obj, "delRuleName", tmpBuf);

		cJSON_AddItemToArray(respond_arry, tmp_obj);
	}

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}

CGI_BOOL setDmzCfg(json_object *request, FILE *conn_fp)
{
	char *dmzE, *address;
	int num=0, i=0;
	char tmpBuf[128]={0}, rules[4096]={0};
	char iptables_tmp[512] = {0},iptables_cmd[4096] = {0};

	struct array_list *subArry;
	
	int addEffect = atoi(webs_get_string(request, "addEffect"));
	if(addEffect == 0){
		dmzE = webs_get_string(request, "enable");
		Uci_Set_Str(PKG_CSFW_CONFIG, "dmz", "enable", dmzE);
		append_iptables_rule_to_file("ENABLE_DMZ", 0, "NULL");
	}else{
		Uci_Set_Str(PKG_CSFW_CONFIG, "dmz", "enable", "1");

		Uci_Get_Str(PKG_CSFW_CONFIG, "dmz", "num", &num);
		if(num > 0){
			Uci_Get_Str(PKG_CSFW_CONFIG,"dmz","rules",rules);
			for(i=num; i>0; i--){
				memset(tmpBuf, '\0', sizeof(tmpBuf));
				get_nth_val_safe((i-1), rules, ' ', tmpBuf, sizeof(tmpBuf));
				Uci_Del_List(PKG_CSFW_CONFIG, "dmz", "rules", tmpBuf);
			}	
			num=0;
			Uci_Set_Str(PKG_CSFW_CONFIG, "dmz", "num", "0");
		}
		
		memset(tmpBuf, 0, sizeof(tmpBuf));
		json_object_object_foreach(request, key, val){
			if(strcmp(key, "subnet") == 0){
				subArry = json_object_get_array(val);
				num = json_object_array_length(val);

				snprintf(tmpBuf, sizeof(tmpBuf), "%d", num);
				Uci_Set_Str(PKG_CSFW_CONFIG, "dmz", "num", tmpBuf);
				for(i=0; i<num; i++){
					struct json_object *objet_x = (struct json_object *)array_list_get_idx(subArry, i);
					
					char *port=webs_get_string(objet_x, "port");
					char *srcIp=webs_get_string(objet_x, "sip");
					char *destIp=webs_get_string(objet_x, "dip");
					char *comment=webs_get_string(objet_x, "desc");

					if(strlen(srcIp) > 16 || strlen(destIp) > 16)
						continue;
					
					memset(rules, 0, sizeof(rules));
					snprintf(rules, sizeof(rules), "%s,%s,%s,%s", port, destIp, srcIp, comment);
					Uci_Add_List(PKG_CSFW_CONFIG, "dmz", "rules", rules);
					//set firewall config
					memset(iptables_tmp, 0, sizeof(iptables_tmp));
                    snprintf(iptables_tmp, sizeof(iptables_tmp), 
                            "iptables -t nat -A zone_vap_prerouting -d %s -j DNAT --to-destination %s\n", 
                            destIp, srcIp);
					if (strlen(iptables_cmd) + strlen(iptables_tmp) < sizeof(iptables_cmd) - 1) {
							strcat(iptables_cmd, iptables_tmp);
						}
				}
				append_iptables_rule_to_file("ENABLE_DMZ", 1, iptables_cmd);
				break;
			}
		}		
	}

	Uci_Commit(PKG_CSFW_CONFIG);

	set_lktos_effect("firewall");
	doSystem("/etc/init.d/firewall restart &");

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

	return CGI_TRUE;
}

CGI_BOOL setWanPingCfg(json_object *request, FILE *conn_fp)
{
	const char *wan_filter = webs_get_string(request, "wanPingFilter");
	const char *fwEnable = webs_get_string(request, "fwEnable");

	Uci_Set_Str(PKG_CSFW_CONFIG, "vpn", "wanping", wan_filter);
	Uci_Set_Str(PKG_CSFW_CONFIG, "dos", "spi", fwEnable);
	
	Uci_Commit(PKG_CSFW_CONFIG);

	set_lktos_effect("firewall");

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

	return CGI_TRUE;
}

CGI_BOOL getWanPingCfg(json_object *request, FILE *conn_fp)
{
	cJSON *root;
 
	root=cJSON_CreateObject();

	get_uci2json(root, PKG_CSFW_CONFIG, "vpn", "wanping", "wanPingFilter");
	get_uci2json(root, PKG_CSFW_CONFIG, "dos", "spi", "fwEnable");
	
	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}

CGI_BOOL getVpnPassCfg(json_object *request, FILE *conn_fp)
{
    cJSON *root;
 
	root=cJSON_CreateObject();

	get_uci2json(root, PKG_CSFW_CONFIG, "vpn", "wanping", "wanPingFilter");

	get_uci2json(root, PKG_CSFW_CONFIG, "vpn", "l2tp", "l2tpPassThru");
	get_uci2json(root, PKG_CSFW_CONFIG, "vpn", "pptp", "pptpPassThru");
	get_uci2json(root, PKG_CSFW_CONFIG, "vpn", "ipsec", "ipsecPassThru");

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}


CGI_BOOL setVpnPassCfg(json_object *request, FILE *conn_fp)
{
	char  *ptr;

	ptr = webs_get_string(request, "wanPingFilter");
	Uci_Set_Str(PKG_CSFW_CONFIG, "vpn", "wanping", ptr);

	ptr = webs_get_string(request, "l2tpPassThru");
	Uci_Set_Str(PKG_CSFW_CONFIG, "vpn", "l2tp", ptr);

	ptr = webs_get_string(request, "pptpPassThru");
	Uci_Set_Str(PKG_CSFW_CONFIG, "vpn", "pptp", ptr);

	ptr = webs_get_string(request, "ipsecPassThru");
	Uci_Set_Str(PKG_CSFW_CONFIG, "vpn", "ipsec", ptr);

	Uci_Commit(PKG_CSFW_CONFIG);

	set_lktos_effect("firewall");

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

   	return CGI_TRUE;
}

CGI_BOOL setParentalRules(json_object *request, FILE *conn_fp)
{
	int rule_count=0;
	int i=1,j=0,first_two=0,first_one=0;
	char ParentalBuff[2048]={0},sRulesNum[8]={0};
	char week_one[SHORT_STR_LEN]={0},week_two[SHORT_STR_LEN]={0};
	char count[SMALL_STR_LEN]={0};
	char *Enabled = webs_get_string(request, "enable");
	char *addEffect = webs_get_string(request, "addEffect");

	if (atoi(addEffect) == 1)
	{
		Uci_Set_Str(PKG_PARENTAL_CONFIG, "parental", "enable", Enabled);
	}
	else
	{
		char *mac = webs_get_string(request, "mac");
		char *desc = webs_get_string(request, "desc");
		char *week = webs_get_string(request, "week");
		char *sTime = webs_get_string(request, "sTime");
		char *eTime = webs_get_string(request, "eTime");
		char *state = webs_get_string(request, "state");

		if(!strstr(week,"0"))
		{
			for(i=1;i<=7;i++)
			{
				sprintf(count, "%d",i);
				if(strstr(week,count))
				{
					if(first_one==0)
					{
						first_one++;
					}
					else
					{
						strcat(week_one, ",");
					}
					strcat(week_one, count);
				}
				else
				{
					if(first_two==0)
					{
						first_two++;
					}
					else
					{
						strcat(week_two, ",");
					}
					strcat(week_two, count);
				}
			}
		}
		else
		{
			sprintf(week_one, "%s","1,2,3,4,5,6,7");
		}

		sprintf(ParentalBuff, "%s;%s;%s;%s;%s;%s", mac, desc, week_one,sTime, eTime, state);
		if (atoi(addEffect) == 0)
		{
			Uci_Add_List(PKG_PARENTAL_CONFIG, "parental", "rules", ParentalBuff);
			Uci_Get_Int(PKG_PARENTAL_CONFIG, "parental", "num", &rule_count);
			rule_count++;
			sprintf(sRulesNum, "%d", rule_count);
			Uci_Set_Str(PKG_PARENTAL_CONFIG, "parental", "num", sRulesNum);
		}
		else if(atoi(addEffect)==2)
		{
			char sRules[4096]={0},Rules[4096]={0},rulesNum[8]={0},SaveRules[32][256]={0};
			char *idx=webs_get_string(request, "idx");

			Uci_Get_Str(PKG_PARENTAL_CONFIG,"parental","rules",sRules);
			Uci_Get_Str(PKG_PARENTAL_CONFIG,"parental","num",rulesNum);

			get_nth_val_safe(atoi(idx)-1, sRules, ' ', Rules, sizeof(Rules));

			for(i=atoi(idx),j=0; i<atoi(rulesNum); i++)
			{
				get_nth_val_safe(i, sRules, ' ', SaveRules[j], sizeof(SaveRules[j]));
				Uci_Del_List(PKG_PARENTAL_CONFIG, "parental", "rules", SaveRules[j]);
				j++;
			}

			Uci_Del_List(PKG_PARENTAL_CONFIG, "parental", "rules", Rules);
			Uci_Add_List(PKG_PARENTAL_CONFIG, "parental", "rules", ParentalBuff);

			for(i=atoi(idx),j=0; i<atoi(rulesNum); i++)
			{
				Uci_Add_List(PKG_PARENTAL_CONFIG, "parental", "rules", SaveRules[j]);
				j++;
			}
		}
	}

	Uci_Commit(PKG_PARENTAL_CONFIG);

	set_lktos_effect("firewall");

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

	return CGI_TRUE;
}

int get_client_link_time(char *devmac, char *time)
{
	cJSON *Devices,*item;
	char mac[24]={0},macBuf[512]={0};
	int  client_num,i=0;
	unsigned long sec, mn, hr, day;

	size_t file_len = f_size("/tmp/client_info");
	client_num=0;
	if(file_len > 0)
	{
		char *buffer = (char *)malloc(sizeof(char)*file_len+1);
		if(buffer)
		{
			memset(buffer,'\0',sizeof(char)*file_len+1);
			f_read("/tmp/client_info", buffer, file_len);

			Devices = cJSON_Parse(buffer);
			if(Devices!=NULL)
			{
				client_num=cJSON_GetArraySize(Devices);
			}
			else
			{
				Devices = cJSON_CreateArray();
				client_num=0;
			}
			free(buffer);
		}
	}

	for(i=0;i<client_num;i++)
	{
		item = cJSON_GetArrayItem(Devices,i);

		char *mac_ptr = webs_get_string(item, "MacAddress");
		int sec = atoi(webs_get_string(item, "UpTime"));

		if(!strlen(mac_ptr))
			continue;

		memset(mac,0,sizeof(mac));
		add_mac_split(mac_ptr, mac);
		if(strlen(macBuf) > 0)
				strcat(macBuf,",");
			strcat(macBuf,mac);

		if(strcmp(mac,devmac) != 0)
			continue;

		day = sec / 86400;
		sec %= 86400;
		hr = sec / 3600;
		sec %= 3600;
		mn = sec / 60;
		sec %= 60;
		sprintf(time, "%d;%d;%d;%d", day, hr, mn, sec);
	}
	if(strstr(macBuf,devmac) == NULL)
	{
		return 1;
	}

	return 0;
}


CGI_BOOL getParentalRules(json_object *request, FILE *conn_fp)
{
	int iRulesNum=0, i=0,j=0,first_one=0,ret=0;
	char sEnable[4]={0};
	char sRules[4096]={0}, sRule[512]={0};
	char mac[RESULT_STR_LEN]={0},desc[RESULT_STR_LEN]={0};
	char sTime[RESULT_STR_LEN]={0},eTime[RESULT_STR_LEN]={0};
	char state[RESULT_STR_LEN]={0},time[RESULT_STR_LEN]={0};
	char weeks[RESULT_STR_LEN]={0},weeks_one[RESULT_STR_LEN]={0},hours[RESULT_STR_LEN]={0};
	char sIdx[4]={0};
	char tmpBuf[SHORT_STR_LEN]={0},link_time[RESULT_STR_LEN]={0};
	char count[SMALL_STR_LEN]={0};
	char *output=NULL;
	cJSON *connArray, *connEntry,*root;

	root = cJSON_CreateObject();
	connArray = cJSON_CreateArray();
	Uci_Get_Str(PKG_PARENTAL_CONFIG,"parental","enable",sEnable);
	cJSON_AddStringToObject(root,"enable", sEnable);

	Uci_Get_Int(PKG_PARENTAL_CONFIG,"parental","num",&iRulesNum);
	Uci_Get_Str(PKG_PARENTAL_CONFIG,"parental","rules",sRules);

	for(i=0; i<iRulesNum; i++)
	{
		get_nth_val_safe(i, sRules, ' ', sRule, sizeof(sRule));

		if((get_nth_val_safe(0, sRule, ';', mac, sizeof(mac)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(1, sRule, ';', desc, sizeof(desc)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(2, sRule, ';', weeks_one, sizeof(weeks_one)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(3, sRule, ';', sTime, sizeof(sTime)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(4,sRule, ';', eTime, sizeof(eTime)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(5, sRule, ';', state, sizeof(state)) == -1))
		{
			continue;
		}

		for(j=1; j<=7; j++)
		{
			sprintf(count, "%d",j);
			if(strstr(weeks_one,count))
			{
				if(first_one==0)
				{
					first_one++;
				}
				else
				{
					strcat(weeks, ";");
				}
				strcat(weeks, count);
			}
		}

		first_one = 0;
		snprintf(time,sizeof(time),"%s,%s,%s",weeks,sTime,eTime);

		memset(weeks,0,sizeof(weeks));
		memset(sTime,0,sizeof(sTime));
		memset(eTime,0,sizeof(eTime));

		connEntry = cJSON_CreateObject();
		cJSON_AddItemToArray(connArray, connEntry);
		sprintf(sIdx, "%d", i+1);
		cJSON_AddStringToObject(connEntry, "idx", sIdx);
		cJSON_AddStringToObject(connEntry, "mac", mac);
		ret = get_client_link_time(mac,link_time);
		cJSON_AddStringToObject(connEntry, ("linkTime"), link_time);
		if(ret == 0)
		{
			cJSON_AddStringToObject(connEntry, ("link"), "1");
		}
		else
		{
			cJSON_AddStringToObject(connEntry, ("link"), "0");
		}
		cJSON_AddStringToObject(connEntry, "desc", desc);
		cJSON_AddStringToObject(connEntry, "time", time);
		cJSON_AddStringToObject(connEntry, "state", state);
		snprintf(tmpBuf, sizeof(tmpBuf), "delRule%d", i);
		cJSON_AddStringToObject(connEntry, "delRuleName", tmpBuf);
	}

	cJSON_AddItemToObject(root, "rule", connArray);

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}




CGI_BOOL delParentalRules(json_object *request, FILE *conn_fp)
{
	int  i=0,iRulesCount=0 ,iRulesCount_con=0;
	char sRules[4096]={0},Rules[4096]={0},name_buf[16],sRulesNum[8]={0};
	char *value;

	Uci_Get_Int(PKG_PARENTAL_CONFIG, "parental", "num", &iRulesCount);
	Uci_Get_Int(PKG_PARENTAL_CONFIG, "parental", "num", &iRulesCount_con);
	Uci_Get_Str(PKG_PARENTAL_CONFIG,"parental","rules",sRules);

	for(i=0; i< iRulesCount; i++)
	{
		snprintf(name_buf, 16, "delRule%d", i);
		value = webs_get_string(request, name_buf);

		if(strlen(value) > 0)
		{
			get_nth_val_safe(atoi(value), sRules, ' ', Rules, sizeof(Rules));
			Uci_Del_List(PKG_PARENTAL_CONFIG, "parental", "rules", Rules);
			iRulesCount_con--;
		}
	}

	sprintf(sRulesNum, "%d", iRulesCount_con);
	Uci_Set_Str(PKG_PARENTAL_CONFIG, "parental", "num", sRulesNum);
	Uci_Commit(PKG_PARENTAL_CONFIG);

	set_lktos_effect("firewall");

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

	return CGI_TRUE;
}

CGI_BOOL setAccessDeviceCfg(json_object *request, FILE *conn_fp)
{
	int add_effect, i, j, len;

	char rules[4096]={0}, rule[128] = {0}, new_rule[128]={0};

	char *pmac, *ptype, *pname;

	struct array_list *js_mac,*js_obj;

	add_effect = atoi(webs_get_string(request, "addEffect"));

	Uci_Get_Str(PKG_CSFW_CONFIG, "accesslist", "rules", rules);

	if(add_effect == 0){
		pmac  = webs_get_string(request, "mac");
		ptype = webs_get_string(request, "modelType");
		pname = webs_get_string(request, "name");

		str_toupper(pmac);

		snprintf(new_rule, sizeof(new_rule), "%s;%s;%s",pmac,ptype,pname);

		if(strlen(rules) == 0 || strstr(rules, pmac)==NULL){
			Uci_Add_List(PKG_CSFW_CONFIG, "accesslist", "rules", new_rule);
		}
		else
		{
			i=0;
			while (get_nth_val_safe(i++, rules, ' ', rule, sizeof(rule)) != -1 ){
				if(strstr(rule,pmac)){
					Uci_Del_List(PKG_CSFW_CONFIG, "accesslist", "rules", rule);

					Uci_Add_List(PKG_CSFW_CONFIG, "accesslist", "rules", new_rule);
					break;
				}
			}
		}
	}
	else if(add_effect == 1)
	{
		json_object *js_tmp = NULL;

		if(json_object_object_get_ex(request, "mac_array", &js_tmp)) {
			js_mac = json_object_get_array(js_tmp);
			if(js_mac==NULL){
				goto end_label;
			}
		}else{
			goto end_label;
		}

		len=array_list_length(js_mac);

		ptype = webs_get_string(request, "modelType");

		for(j = 0; j<len; j++){
			js_obj = array_list_get_idx(js_mac,j);

			pmac  = webs_get_string(js_obj, "mac");

			pname = webs_get_string(js_obj, "name");

			str_toupper(pmac);

			memset(new_rule, 0, sizeof(new_rule));
			snprintf(new_rule, sizeof(new_rule), "%s;%s;%s",pmac,ptype,pname);

			if(strlen(rules) == 0 || strstr(rules, pmac)==NULL){
				Uci_Add_List(PKG_CSFW_CONFIG, "accesslist", "rules", new_rule);
			}
			else
			{
				i=0;
				while (get_nth_val_safe(i++, rules, ' ', rule, sizeof(rule)) != -1 ){
					if(strstr(rule,pmac)){
						Uci_Del_List(PKG_CSFW_CONFIG, "accesslist", "rules", rule);

						Uci_Add_List(PKG_CSFW_CONFIG, "accesslist", "rules", new_rule);
						break;
					}
				}
			}
		}
	}

	Uci_Commit(PKG_CSFW_CONFIG);

	set_lktos_effect("firewall");

end_label:

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

	return CGI_TRUE;
}

CGI_BOOL getRemoteCfg(json_object *request, FILE *conn_fp)
{
	cJSON *root;
	char port[RESULT_STR_LEN]={0}, remoteEnabled[RESULT_STR_LEN]={0};
	char wanIdx[RESULT_STR_LEN]={0}, ProductName[RESULT_STR_LEN]={0};
	root=cJSON_CreateObject();

	Uci_Get_Str(PKG_CSFW_CONFIG, "remote", "port", port);
	Uci_Get_Str(PKG_CSFW_CONFIG, "remote","enable",remoteEnabled);

	cJSON_AddStringToObject(root, "enable", remoteEnabled);
	cJSON_AddStringToObject(root, "port", port);

	send_cgi_json_respond(conn_fp, root);
    return CGI_TRUE;
}

CGI_BOOL setRemoteCfg(json_object *request, FILE *conn_fp)
{
	char  *ptr = NULL;

	ptr = webs_get_string(request, "enable");
	if(strcmp(ptr,"0")==0||strcmp(ptr,"1")==0){
		Uci_Set_Str(PKG_CSFW_CONFIG, "remote","enable",ptr);
	}

	ptr = webs_get_string(request, "port");
	if(atoi(ptr)>0&&atoi(ptr)<65536){
		Uci_Set_Str(PKG_CSFW_CONFIG, "remote","port",ptr);
	}

	Uci_Commit(PKG_CSFW_CONFIG);
	set_lktos_effect("firewall");

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

	return CGI_TRUE;
}

CGI_BOOL getNatRules(json_object *request, FILE *conn_fp)
{
	int iRulesNum=0, i=0, proto=0;
	char sEnable[4]={0}, sLanIp[32]={0}, sLanMask[32]={0};
	char sRules[4096]={0}, sRule[512]={0};
	char natType[RESULT_STR_LEN]={0};
	char oAddress[OPTION_STR_LEN]={0};
	char addressType[RESULT_STR_LEN]={0};
	char mAddress[RESULT_STR_LEN]={0};
	char mPort[RESULT_STR_LEN]={0},oPort[RESULT_STR_LEN]={0},protocol[RESULT_STR_LEN]={0};
	char sIdx[4]={0},wanIdx[OPTION_STR_LEN]={0};
	char tmpBuf[SHORT_STR_LEN]={0}, port[SHORT_STR_LEN]={0};
	char *output=NULL;
	
	cJSON *connArray, *connEntry, *root;

	root = cJSON_CreateObject();
	
	Uci_Get_Str(PKG_CSFW_CONFIG, "rnat", "enable", sEnable);
	Uci_Get_Str(PKG_NETWORK_CONFIG, "lan", "ipaddr", sLanIp);
	Uci_Get_Str(PKG_NETWORK_CONFIG, "lan", "netmask", sLanMask);
	cJSON_AddStringToObject(root, "enable", sEnable);
	cJSON_AddStringToObject(root, "lanIp", sLanIp);
	cJSON_AddStringToObject(root, "lanNetmask", sLanMask);
	cJSON_AddStringToObject(root, "interface", "WAN,MODEM");


	connArray = cJSON_CreateArray();
	cJSON_AddItemToObject(root, "rule", connArray);

	Uci_Get_Int(PKG_CSFW_CONFIG, "rnat", "num", &iRulesNum);
	Uci_Get_Str(PKG_CSFW_CONFIG, "rnat", "rules", sRules);

	for(i=0;i<iRulesNum;i++)
	{
		get_nth_val_safe(i, sRules, ' ', sRule, sizeof(sRule));

		if((get_nth_val_safe(0, sRule, ',', addressType, sizeof(addressType)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(1, sRule, ',', mAddress, sizeof(mAddress)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(2, sRule, ',', mPort, sizeof(mPort)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(3, sRule, ',', natType, sizeof(natType)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(4, sRule, ',', oAddress, sizeof(oAddress)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(5, sRule, ',', oPort, sizeof(oPort)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(6, sRule, ',', protocol, sizeof(protocol)) == -1))
		{
			continue;
		}

		connEntry = cJSON_CreateObject();
		sprintf(sIdx, "%d", i+1);
		cJSON_AddStringToObject(connEntry, "idx", sIdx);
		cJSON_AddStringToObject(connEntry, "natType", natType);
		cJSON_AddStringToObject(connEntry, "protocol", protocol);
		cJSON_AddStringToObject(connEntry, "addressType", addressType);
		cJSON_AddStringToObject(connEntry, "oAddress", oAddress);

		cJSON_AddStringToObject(connEntry, "oPort", oPort);
		cJSON_AddStringToObject(connEntry, "mAddress", mAddress);
		cJSON_AddStringToObject(connEntry, "mPort", mPort);
		snprintf(tmpBuf,SHORT_STR_LEN, "delRule%d", i);
		cJSON_AddStringToObject(connEntry, "delRuleName", tmpBuf);
		cJSON_AddItemToArray(connArray, connEntry);
	}

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}


CGI_BOOL setNatRules(json_object *request, FILE *conn_fp)
{
	char *addressType, *mAddress, *mPort;
	char *natType, *oAddress, *oPort;
	char *protocol, *outDir, *proto, *comment;
	char tmpBuf[CMD_STR_LEN]={0};
	char rules[LONGLONG_BUFF_LEN]={0}, rule[CMD_STR_LEN]={0};

	int num=0, i;
	struct array_list *subArry;
	
	char *addEffect = webs_get_string(request, "addEffect");
	
	if (atoi(addEffect) == 0)
	{	
		char *enable = webs_get_string(request,"enable");
		Uci_Set_Str(PKG_CSFW_CONFIG,"rnat","enable",enable);
	}
	else 
	{
		Uci_Set_Str(PKG_CSFW_CONFIG,"rnat","enable","1");
		Uci_Get_Int(PKG_CSFW_CONFIG, "rnat", "num", &num);
		if(num > 0){
			Uci_Get_Str(PKG_CSFW_CONFIG,"rnat","rules",rules);
			for(i=num; i>0; i--){
				memset(tmpBuf, '\0', sizeof(tmpBuf));
				get_nth_val_safe((i-1), rules, ' ', tmpBuf, sizeof(tmpBuf));
				Uci_Del_List(PKG_CSFW_CONFIG, "rnat", "rules", tmpBuf);
			}	
			num=0;
			Uci_Set_Str(PKG_CSFW_CONFIG, "rnat", "num", "0");
		}

		json_object_object_foreach(request, key, val) {
			if (strcmp(key, "subnet") == 0) {

				subArry = json_object_get_array(val);
				num = json_object_array_length(val);
				
				if(num > FILTER_RULE_NUM)
					snprintf(tmpBuf, sizeof(tmpBuf), "%d", FILTER_RULE_NUM);
				else
					snprintf(tmpBuf, sizeof(tmpBuf), "%d", num);
				Uci_Set_Str(PKG_CSFW_CONFIG, "rnat", "num", tmpBuf);
				
				for(i = 0; i < num; i++) {
					if(i > FILTER_RULE_NUM)
						goto end_labal;
					
					struct json_object *object_x = (struct json_object *)array_list_get_idx(subArry, i);

					addressType=webs_get_string(object_x, "addressType");
					mAddress = webs_get_string(object_x, "mAddress");
					mPort = webs_get_string(object_x, "mPort");
					
					natType = webs_get_string(object_x, "natType");
					oAddress = webs_get_string(object_x, "oAddress");
					oPort = webs_get_string(object_x, "oPort");

					protocol =  webs_get_string(object_x, "protocol");
					outDir =  webs_get_string(object_x, "output");

					proto = webs_get_string(object_x, "proto");
					comment=webs_get_string(object_x, "desc");
					
					memset(rule, '\0', sizeof(rule));
					sprintf(rule, "%s,%s,%s,%s,%s,%s,%s", addressType, mAddress, mPort, natType, \
						oAddress, oPort, protocol);
					Uci_Add_List(PKG_CSFW_CONFIG, "rnat", "rules", rule);
					
				}
				break;
			}
		}		
	}
end_labal:

	Uci_Commit(PKG_CSFW_CONFIG);

	set_lktos_effect("firewall");

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");
	
	return CGI_TRUE;	
}


CGI_BOOL getQosSetCfg(json_object *request, FILE *conn_fp)
{
	cJSON *root;
	char tmpBuf[32], buf[32]={0};
	
	root=cJSON_CreateObject();

	memset(tmpBuf, 0, sizeof(tmpBuf));
	memset(buf, 0, sizeof(buf));
	Uci_Get_Str(PKG_QOS_CONFIG,"smartqos","upbw",tmpBuf);
	sprintf(buf, "%d", atoi(tmpBuf) / 1024);//kbps -> Mbps
	cJSON_AddStringToObject(root, "totalUp", buf);

	memset(tmpBuf, 0, sizeof(tmpBuf));
	memset(buf, 0, sizeof(buf));
	Uci_Get_Str(PKG_QOS_CONFIG,"smartqos","downbw",tmpBuf);
	sprintf(buf, "%d", atoi(tmpBuf) / 1024);//kbps -> Mbps
	cJSON_AddStringToObject(root, "totalDown", buf);

	memset(tmpBuf, 0, sizeof(tmpBuf));
	Uci_Get_Str(PKG_QOS_CONFIG,"smartqos","uceil",tmpBuf);
	cJSON_AddStringToObject(root, "upPercent", tmpBuf);

	memset(tmpBuf, 0, sizeof(tmpBuf));
	Uci_Get_Str(PKG_QOS_CONFIG,"smartqos","dceil",tmpBuf);
	cJSON_AddStringToObject(root, "downPercent", tmpBuf);	

	memset(tmpBuf, 0, sizeof(tmpBuf));
	Uci_Get_Str(PKG_QOS_CONFIG,"smartqos","default_bw",tmpBuf);
	cJSON_AddStringToObject(root, "speedMax", tmpBuf);
	
	send_cgi_json_respond(conn_fp, root);
    return CGI_TRUE;
}

CGI_BOOL setQosSetCfg(json_object *request, FILE *conn_fp)
{
	char tmpbuf[32]={0};
	int addEffect = webs_get_int(request,"addEffect");

	if(addEffect == 0){
		char *enable = webs_get_string(request,"enable");
		Uci_Set_Str(PKG_QOS_CONFIG,"smartqos","enable",enable);
	}
	else{
		Uci_Set_Str(PKG_QOS_CONFIG,"smartqos","enable","1");
		char *uceil = webs_get_string(request, "upPercent");
		char *dceil = webs_get_string(request, "downPercent");
		char *up = webs_get_string(request, "totalUp");
		char *down = webs_get_string(request, "totalDown");

		Uci_Set_Str(PKG_QOS_CONFIG,"smartqos","uceil",uceil);
		Uci_Set_Str(PKG_QOS_CONFIG,"smartqos","dceil",dceil);
		sprintf(tmpbuf, "%d", atoi(up) * 1024);//Mbps -> kbps
		Uci_Set_Str(PKG_QOS_CONFIG,"smartqos","upbw",tmpbuf);
		memset(tmpbuf, 0, sizeof(tmpbuf));
		sprintf(tmpbuf, "%d", atoi(down) * 1024);//Mbps -> kbps
		Uci_Set_Str(PKG_QOS_CONFIG,"smartqos","downbw",tmpbuf);
	}

	Uci_Commit(PKG_QOS_CONFIG);
	set_lktos_effect("firewall");

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "5", "reserv");

	return CGI_TRUE;
}

CGI_BOOL getIpQosLimitCfg(json_object *request, FILE *conn_fp)
{
	cJSON *root, *ruleArray, *ruleEntry;
	char tmpBuf[32], desc[33]={0};
	char rules[LONG_BUFF_LEN] = {0},rule[TEMP_STR_LEN] = {0}, del_rule[SHORT_STR_LEN] = {0};
	char ip[SHORT_STR_LEN] = {0},max_up[SMALL_STR_LEN] = {0},max_down[SMALL_STR_LEN] = {0};
	int iRulesNum=0, i=0;
	
	root=cJSON_CreateObject();

	memset(tmpBuf, 0, sizeof(tmpBuf));
	Uci_Get_Str(PKG_QOS_CONFIG,"smartqos","enable",tmpBuf);
	cJSON_AddStringToObject(root, "enable", tmpBuf);

	get_uci2json(root, PKG_NETWORK_CONFIG, "lan", "ipaddr",	 "ip");
	get_uci2json(root, PKG_NETWORK_CONFIG, "lan", "netmask", "mask");

	memset(tmpBuf, 0, sizeof(tmpBuf));
	Uci_Get_Str(PKG_QOS_CONFIG,"smartqos","default_bw",tmpBuf);
	cJSON_AddStringToObject(root, "speedMax", tmpBuf);

	ruleArray = cJSON_CreateArray();
	cJSON_AddItemToObject(root, "rule", ruleArray);
	Uci_Get_Int(PKG_QOS_CONFIG,"iplimit","num",&iRulesNum);
	Uci_Get_Str(PKG_QOS_CONFIG,"iplimit","rules",rules);
	
	for(i=0;i<iRulesNum;i++)
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

		if((get_nth_val_safe(3, rule, ',', desc, sizeof(desc)) == -1))
		{
			continue;
		}
		
		snprintf(del_rule,sizeof(del_rule), "delRule%d",i);

		ruleEntry = cJSON_CreateObject();
		cJSON_AddNumberToObject(ruleEntry, "idx",(i+1));
		cJSON_AddStringToObject(ruleEntry, "ip",ip);

		memset(tmpBuf, 0, sizeof(tmpBuf));
		sprintf(tmpBuf, "%d", atoi(max_down) / 1024);
		cJSON_AddStringToObject(ruleEntry, "down",tmpBuf);

		memset(tmpBuf, 0, sizeof(tmpBuf));
		sprintf(tmpBuf, "%d", atoi(max_up) / 1024);
		cJSON_AddStringToObject(ruleEntry, "up",  tmpBuf);
		
		cJSON_AddStringToObject(ruleEntry, "desc",  desc);
		cJSON_AddStringToObject(ruleEntry, "delRuleName",del_rule);
		cJSON_AddItemToArray(ruleArray,ruleEntry);

		memset(ip, 0,sizeof(ip));
		memset(del_rule, 0,sizeof(del_rule));
		memset(max_down, 0,sizeof(max_down));
		memset(max_up, 0,  sizeof(max_up));
		memset(desc, 0,  sizeof(desc));
	}
	
	send_cgi_json_respond(conn_fp, root);
    return CGI_TRUE;
}

CGI_BOOL setIpQosLimitCfg(json_object *request, FILE *conn_fp)
{
	struct array_list* subnet;
	int num = 0, idx = 0, i = 0;
	char *ip, *up, *down, *desc;
	char tmpBuf[128]={0}, rules[1024]={0}, up_bw[16]={0}, down_bw[16]={0};
	
	//Delete the original rule
	Uci_Get_Int(PKG_QOS_CONFIG, "iplimit", "num", &num);
	if(num > 0){
		Uci_Get_Str(PKG_QOS_CONFIG,"iplimit","rules",rules);
		for(i=num; i>0; i--){
			memset(tmpBuf, '\0', sizeof(tmpBuf));
			get_nth_val_safe((i-1), rules, ' ', tmpBuf, sizeof(tmpBuf));
			Uci_Del_List(PKG_QOS_CONFIG, "iplimit", "rules", tmpBuf);
		}	
		num=0;
		Uci_Set_Str(PKG_QOS_CONFIG, "iplimit", "num", "0");
	}
		
	json_object_object_foreach(request, key, val){
		if (strcmp(key, "subnet") == 0){
			
			subnet = json_object_get_array(val);
			num = json_object_array_length(val);
			
			memset(tmpBuf, 0, sizeof(tmpBuf));
			sprintf(tmpBuf, "%d", num);
			Uci_Set_Str(PKG_QOS_CONFIG, "iplimit", "num", tmpBuf);
			
			for(idx = 0; idx < num; idx++){
				
				struct json_object* subnet_x = (struct json_object*)array_list_get_idx(subnet, idx);	

				ip = webs_get_string(subnet_x,"ip");
				up = webs_get_string(subnet_x,"up");
				down = webs_get_string(subnet_x,"down");//Mbps
				desc = webs_get_string(subnet_x,"desc");//Mbps

				memset(up_bw, 0, sizeof(up_bw));
				memset(down_bw, 0, sizeof(down_bw));
				sprintf(up_bw, "%d", (atoi(up) * 1024));//save up_bw kBs
				sprintf(down_bw, "%d", (atoi(down) * 1024));//save up_bw kBs
				memset(rules, '\0', sizeof(rules));
				sprintf(rules, "%s,%s,%s,%s", ip, up_bw, down_bw, desc);
				Uci_Add_List(PKG_QOS_CONFIG, "iplimit", "rules", rules);
			}
		}
	}

	Uci_Commit(PKG_QOS_CONFIG);
	set_lktos_effect("firewall");

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "5", "reserv");

	return CGI_TRUE;
}

CGI_BOOL getAlgServicesCfg(json_object *request, FILE *conn_fp)
{
	cJSON *root;
	root=cJSON_CreateObject();
	
	get_num_uci2json(root,PKG_CSFW_CONFIG, "vpn", "l2tp", "l2tpPassThru");
	get_num_uci2json(root,PKG_CSFW_CONFIG, "vpn", "pptp", "pptpPassThru");
	get_num_uci2json(root,PKG_CSFW_CONFIG, "vpn", "ipsec", "ipsecPassThru");
	
	send_cgi_json_respond(conn_fp, root);
    return CGI_TRUE;
}

CGI_BOOL setAlgServicesCfg(json_object *request, FILE *conn_fp)
{
	const char *l2tpPassThru = webs_get_string(request, "l2tpPassThru");
	const char *pptpPassThru = webs_get_string(request, "pptpPassThru");
	const char *ipsecPassThru = webs_get_string(request, "ipsecPassThru");
	
	Uci_Set_Str(PKG_CSFW_CONFIG, "vpn", "l2tp", l2tpPassThru);
	Uci_Set_Str(PKG_CSFW_CONFIG, "vpn", "pptp", pptpPassThru);
	Uci_Set_Str(PKG_CSFW_CONFIG, "vpn", "ipsec", ipsecPassThru);
	
	Uci_Commit(PKG_CSFW_CONFIG);
	set_lktos_effect("firewall");

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "5", "reserv");
}


#if defined(APP_QUAGGA)
CGI_BOOL setBasicRoutingCfg(json_object *request, FILE *conn_fp)
{
	int num=0;
	
	char *setType = webs_get_string(request, "setType");
	if (atoi(setType) == 0 || atoi(setType) == 1)
	{
		char *reCnnt = webs_get_string(request, "redistributeConnect");
		char *reStatic = webs_get_string(request, "redistributeStatic");
		char *reKernel = webs_get_string(request, "redistributeKernel");

		if(atoi(setType) == 0)
		{
			Uci_Set_Str(PKG_ROUTER_QUAGGA_CONFIG, "ripd", "reCnnt", reCnnt);
			Uci_Set_Str(PKG_ROUTER_QUAGGA_CONFIG, "ripd", "reStatic", reStatic);
			Uci_Set_Str(PKG_ROUTER_QUAGGA_CONFIG, "ripd", "reKernel", reKernel);
		}
		else
		{
			Uci_Set_Str(PKG_ROUTER_QUAGGA_CONFIG, "ospfd", "reCnnt", reCnnt);
			Uci_Set_Str(PKG_ROUTER_QUAGGA_CONFIG, "ospfd", "reStatic", reStatic);
			Uci_Set_Str(PKG_ROUTER_QUAGGA_CONFIG, "ospfd", "reKernel", reKernel);
		}
	}

	if(atoi(setType) == 2)
	{
		char *routerAs = webs_get_string(request, "routerAs");
		char *routerId = webs_get_string(request, "routerId");

		Uci_Set_Str(PKG_ROUTER_QUAGGA_CONFIG, "bgpd", "router_as", routerAs);
		Uci_Set_Str(PKG_ROUTER_QUAGGA_CONFIG, "bgpd", "router_id", routerId);
	}

	Uci_Commit(PKG_ROUTER_QUAGGA_CONFIG);

	
	if(atoi(setType) == 0){
		Uci_Get_Int(PKG_ROUTER_QUAGGA_CONFIG, "ripd", "num", &num);
		if(num > 0){
			CsDealQuaggaConf(RIPD_CONF);
		}
	}else if(atoi(setType) == 1){
		Uci_Get_Int(PKG_ROUTER_QUAGGA_CONFIG, "ospfd", "num", &num);
		if(num > 0){
			CsDealQuaggaConf(OSPFD_CONF);
		}

	}else if(atoi(setType) == 2){
		Uci_Get_Int(PKG_ROUTER_QUAGGA_CONFIG, "bgpd", "num", &num);
		if(num > 0){
			CsDealQuaggaConf(BGPD_CONF);
		}
	}

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "5", "reserv");
	return CGI_TRUE;
}

CGI_BOOL getRoutingRipCfg(json_object *request, FILE *conn_fp)
{
	int iRulesNum=0, i=0;
	char sRules[1024]={0}, sRule[128]={0};
	char type[8]={0}, addr[16]={0}, buff[32]={0};
	cJSON *root, *connArray, *connEntry;
	
	root = cJSON_CreateObject();

	Uci_Get_Str(PKG_ROUTER_QUAGGA_CONFIG, "ripd", "reCnnt", buff);
	cJSON_AddStringToObject(root,"redistributeConnect", buff);

	memset(buff, 0, sizeof(buff));
	Uci_Get_Str(PKG_ROUTER_QUAGGA_CONFIG, "ripd", "reStatic", buff);
	cJSON_AddStringToObject(root,"redistributeStatic", buff);

	memset(buff, 0, sizeof(buff));
	Uci_Get_Str(PKG_ROUTER_QUAGGA_CONFIG, "ripd", "reKernel", buff);
	cJSON_AddStringToObject(root,"redistributeKernel", buff);
	
	connArray = cJSON_CreateArray();
	cJSON_AddItemToObject(root, "rule", connArray);
	Uci_Get_Int(PKG_ROUTER_QUAGGA_CONFIG, "ripd", "num", &iRulesNum);
	Uci_Get_Str(PKG_ROUTER_QUAGGA_CONFIG,"ripd","rules",sRules);
	
	for(i=0; i<iRulesNum; i++)
	{
		get_nth_val_safe(i, sRules, ' ', sRule, sizeof(sRule));

		if((get_nth_val_safe(0, sRule, ',', type, sizeof(type)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(1, sRule, ',', addr, sizeof(addr)) == -1))
		{
			continue;
		}

		connEntry = cJSON_CreateObject();
		cJSON_AddStringToObject(connEntry,"type", type);
		cJSON_AddStringToObject(connEntry,"address", addr);
		memset(type, 0, sizeof(type));
		memset(addr, 0, sizeof(addr));
		
		cJSON_AddItemToArray(connArray,connEntry);
	}

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}

CGI_BOOL setRoutingRipCfg(json_object *request, FILE *conn_fp)
{
	struct array_list *subnet;
	char tmpBuf[128]={0}, rule[128] = {0}, rules[1024]={0};
	int i = 0, num = 0, count=0;

	//Delete the original rule
	Uci_Get_Int(PKG_ROUTER_QUAGGA_CONFIG, "ripd", "num", &num);
	if(num > 0){
		Uci_Get_Str(PKG_ROUTER_QUAGGA_CONFIG,"ripd","rules",rules);
		for(i=num; i>0; i--){
			memset(tmpBuf, 0, sizeof(tmpBuf));
			get_nth_val_safe((i-1), rules, ' ', tmpBuf, sizeof(tmpBuf));
			Uci_Del_List(PKG_ROUTER_QUAGGA_CONFIG, "ripd", "rules", tmpBuf);
		}	
		num=0;
		Uci_Set_Str(PKG_ROUTER_QUAGGA_CONFIG, "ripd", "num", "0");
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

				char *rulesType = webs_get_string(subnet_x, "type");
				char *address  = webs_get_string(subnet_x, "address");

				if((!rulesType && !strlen(rulesType))||(!address && !strlen(address)))
					continue;

				count++;
				memset(rule, 0, sizeof(rule));
				snprintf(rule, sizeof(rule), "%s,%s", rulesType, address);
				Uci_Add_List(PKG_ROUTER_QUAGGA_CONFIG, "ripd", "rules", rule);
			}

			memset(tmpBuf, 0, sizeof(tmpBuf));
			sprintf(tmpBuf, "%d", count);
			Uci_Set_Str(PKG_ROUTER_QUAGGA_CONFIG, "ripd", "num", tmpBuf);
		}
	}
	
	if(count == 0)
	{
		unlink(QUAGGA_RIPD_CONF);
		unlink("/tmp/rip.log");
	}
	
	Uci_Commit(PKG_ROUTER_QUAGGA_CONFIG);
	set_lktos_effect("router_quagga");
	set_lktos_effect("firewall");

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "5", "reserv");
	return CGI_TRUE;
}

CGI_BOOL getRoutingOspfCfg(json_object *request, FILE *conn_fp)
{
	int iRulesNum=0, i=0;
	char sRules[1024]={0}, sRule[128]={0}, buff[32]={0};
	char type[16]={0}, iface[16]={0}, tmpBuf[64]={0}, network[16]={0}, areaNum[16]={0};
	cJSON *root, *connArray, *connEntry;
	
	root = cJSON_CreateObject();

	Uci_Get_Str(PKG_ROUTER_QUAGGA_CONFIG, "ospfd", "reCnnt", buff);
	cJSON_AddStringToObject(root,"redistributeConnect", buff);

	memset(buff, 0, sizeof(buff));
	Uci_Get_Str(PKG_ROUTER_QUAGGA_CONFIG, "ospfd", "reStatic", buff);
	cJSON_AddStringToObject(root,"redistributeStatic", buff);

	memset(buff, 0, sizeof(buff));
	Uci_Get_Str(PKG_ROUTER_QUAGGA_CONFIG, "ospfd", "reKernel", buff);
	cJSON_AddStringToObject(root,"redistributeKernel", buff);
	
	connArray = cJSON_CreateArray();
	cJSON_AddItemToObject(root, "rule", connArray);
	Uci_Get_Int(PKG_ROUTER_QUAGGA_CONFIG, "ospfd", "num", &iRulesNum);
	Uci_Get_Str(PKG_ROUTER_QUAGGA_CONFIG,"ospfd","rules",sRules);
	
	for(i=0; i<iRulesNum; i++)
	{
		get_nth_val_safe(i, sRules, ' ', sRule, sizeof(sRule));

		if((get_nth_val_safe(0, sRule, ',', type, sizeof(type)) == -1))
		{
			continue;
		}
		
		if(!strcmp(type, "interface")){
			if((get_nth_val_safe(1, sRule, ',', iface, sizeof(iface)) == -1))
			{
				continue;
			}
			if((get_nth_val_safe(2, sRule, ',', tmpBuf, sizeof(tmpBuf)) == -1))
			{
				continue;
			}
			
			connEntry = cJSON_CreateObject();
			cJSON_AddStringToObject(connEntry,"interface", iface);
			if(strlen(tmpBuf) > 5){
				cJSON_AddStringToObject(connEntry,"networkType", tmpBuf);
			}else{
				cJSON_AddStringToObject(connEntry,"cost", tmpBuf);
			}
			memset(iface, 0, sizeof(iface));
			memset(tmpBuf, 0, sizeof(tmpBuf));
		}else{
			if((get_nth_val_safe(1, sRule, ',', network, sizeof(network)) == -1))
			{
				continue;
			}
			if((get_nth_val_safe(2, sRule, ',', areaNum, sizeof(areaNum)) == -1))
			{
				continue;
			}
			
			connEntry = cJSON_CreateObject();
			cJSON_AddStringToObject(connEntry,"address", network);
			cJSON_AddStringToObject(connEntry,"areaNumber", areaNum);
			memset(network, 0, sizeof(network));
			memset(areaNum, 0, sizeof(areaNum));
		}
		
		cJSON_AddStringToObject(connEntry,"type", type);
		memset(type, 0, sizeof(type));
		
		cJSON_AddItemToArray(connArray,connEntry);
	}

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}



CGI_BOOL setRoutingOspfCfg(json_object *request, FILE *conn_fp)
{
	struct array_list *subnet;
	char tmpBuf[128]={0}, rule[128] = {0}, rules[1024]={0};
	int i = 0, num = 0, count=0;
	struct interface_status link_status;
	
	//Delete the original rule
	Uci_Get_Int(PKG_ROUTER_QUAGGA_CONFIG, "ospfd", "num", &num);
	if(num > 0){
		Uci_Get_Str(PKG_ROUTER_QUAGGA_CONFIG,"ospfd","rules",rules);
		for(i=num; i>0; i--){
			memset(tmpBuf, 0, sizeof(tmpBuf));
			get_nth_val_safe((i-1), rules, ' ', tmpBuf, sizeof(tmpBuf));
			Uci_Del_List(PKG_ROUTER_QUAGGA_CONFIG, "ospfd", "rules", tmpBuf);
		}	
		num=0;
		Uci_Set_Str(PKG_ROUTER_QUAGGA_CONFIG, "ospfd", "num", "0");
	}

	get_wan_status(&link_status);
	
	json_object_object_foreach(request, key, val) 
	{
		if (strcmp(key, "rule") == 0) 
		{
			subnet = json_object_get_array(val);

			num = json_object_array_length(val);

			for(i = 0; i < num; i++) 
			{
				struct json_object *subnet_x = (struct json_object *)array_list_get_idx(subnet, i);

				char *rulesType = webs_get_string(subnet_x, "type");
				char *network  = webs_get_string(subnet_x, "address");
				char *area = webs_get_string(subnet_x, "areaNumber");
				char *interface_name  = webs_get_string(subnet_x, "interface");
				char *interface_cost = webs_get_string(subnet_x, "cost");
				char *interface_type  = webs_get_string(subnet_x, "networkType");

				if(!rulesType && !strlen(rulesType))
					continue;

				count++;
				
				memset(rule, 0, sizeof(rule));
				if(!strcmp(rulesType, "interface"))
				{
					if(strlen(interface_cost) > 0 && atoi(interface_cost) > 0)
						snprintf(rule, sizeof(rule), "%s,%s,%s", rulesType, interface_name, interface_cost);
					else
						snprintf(rule, sizeof(rule), "%s,%s,%s", rulesType, interface_name, interface_type);
				}
				else
				{
					snprintf(rule, sizeof(rule), "%s,%s,%s", rulesType, network,area);
				}	
				Uci_Add_List(PKG_ROUTER_QUAGGA_CONFIG, "ospfd", "rules", rule);
			}

			memset(tmpBuf, 0, sizeof(tmpBuf));
			sprintf(tmpBuf, "%d", count);
			Uci_Set_Str(PKG_ROUTER_QUAGGA_CONFIG, "ospfd", "num", tmpBuf);
		}
	}
	
	if(count == 0)
	{
		unlink(QUAGGA_OSPFD_CONF);
		unlink("/tmp/ospf.log");
	}

	Uci_Commit(PKG_ROUTER_QUAGGA_CONFIG);
	set_lktos_effect("router_quagga");
	set_lktos_effect("firewall");

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "5", "reserv");
	return CGI_TRUE;
}


CGI_BOOL getRoutingBgpCfg(json_object *request, FILE *conn_fp)
{
	int iRulesNum=0, i=0, i_flag=0;
	char sRules[1024]={0}, sRule[128]={0};
	char type[16]={0}, network[16]={0}, buff[32]={0};
	char remoteAs[8]={0}, updateSource[8]={0}, logChange[8]={0}, autoSummary[8]={0}, synchron[8]={0};
	cJSON *root, *connArray, *connEntry, *obj;
	

	root = cJSON_CreateObject();

	memset(buff, 0, sizeof(buff));
	Uci_Get_Str(PKG_ROUTER_QUAGGA_CONFIG, "bgpd", "router_as", buff);
	cJSON_AddStringToObject(root, "routerAs", buff);

	memset(buff, 0, sizeof(buff));
	Uci_Get_Str(PKG_ROUTER_QUAGGA_CONFIG, "bgpd", "router_id", buff);
	cJSON_AddStringToObject(root, "routerId", buff);

	memset(buff, 0, sizeof(buff));
	Uci_Get_Str(PKG_ROUTER_QUAGGA_CONFIG, "bgpd", "reCnnt", buff);
	cJSON_AddStringToObject(root,"redistributeConnect", buff);

	memset(buff, 0, sizeof(buff));
	Uci_Get_Str(PKG_ROUTER_QUAGGA_CONFIG, "bgpd", "reStatic", buff);
	cJSON_AddStringToObject(root,"redistributeStatic", buff);

	memset(buff, 0, sizeof(buff));
	Uci_Get_Str(PKG_ROUTER_QUAGGA_CONFIG, "bgpd", "reKernel", buff);
	cJSON_AddStringToObject(root,"redistributeKernel", buff);
	
	connArray = cJSON_CreateArray();
	cJSON_AddItemToObject(root, "rule", connArray);
	Uci_Get_Int(PKG_ROUTER_QUAGGA_CONFIG, "bgpd", "num", &iRulesNum);
	Uci_Get_Str(PKG_ROUTER_QUAGGA_CONFIG,"bgpd","rules",sRules);
	
	for(i=0; i<iRulesNum; i++)
	{
		get_nth_val_safe(i, sRules, ' ', sRule, sizeof(sRule));

		if((get_nth_val_safe(0, sRule, ',', type, sizeof(type)) == -1))
		{
			continue;
		}
		
		if((get_nth_val_safe(1, sRule, ',', network, sizeof(network)) == -1))
		{
			continue;
		}
		
		if(!strcmp(type, "neighbour")){
			if((get_nth_val_safe(2, sRule, ',', remoteAs, sizeof(remoteAs)) == -1))
			{
				continue;
			}
			if((get_nth_val_safe(3, sRule, ',', updateSource, sizeof(updateSource)) == -1))
			{
				continue;
			}

			if((get_nth_val_safe(4, sRule, ',', autoSummary, sizeof(autoSummary)) == -1))
			{
				continue;
			}
			if((get_nth_val_safe(5, sRule, ',', logChange, sizeof(logChange)) == -1))
			{
				continue;
			}
			if((get_nth_val_safe(6, sRule, ',', synchron, sizeof(synchron)) == -1))
			{
				continue;
			}
			
			i_flag=1;
		}

		connEntry = cJSON_CreateObject();
		cJSON_AddStringToObject(connEntry,"type", type);
		cJSON_AddStringToObject(connEntry,"address", network);
		if(i_flag=1){
			i_flag=0;
			cJSON_AddStringToObject(connEntry,"updateSource", updateSource);
			cJSON_AddStringToObject(connEntry,"remoteAs", remoteAs);
			cJSON_AddStringToObject(connEntry,"logChange", logChange);
			cJSON_AddStringToObject(connEntry,"autoSummary", autoSummary);
			cJSON_AddStringToObject(connEntry,"synchronization", synchron);
			
			memset(remoteAs, 0, sizeof(remoteAs));
			memset(updateSource, 0, sizeof(updateSource));
			memset(logChange, 0, sizeof(logChange));
			memset(autoSummary, 0, sizeof(autoSummary));
			memset(synchron, 0, sizeof(synchron));
		}			

		memset(type, 0, sizeof(type));
		memset(network, 0, sizeof(network));
		
		cJSON_AddItemToArray(connArray,connEntry);
	}

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}



CGI_BOOL setRoutingBgpCfg(json_object *request, FILE *conn_fp)
{
	struct array_list *subnet;
	char tmpBuf[128]={0}, rule[128] = {0}, rules[1024]={0};
	int i = 0, num = 0, count=0;

	//Delete the original rule
	Uci_Get_Int(PKG_ROUTER_QUAGGA_CONFIG, "bgpd", "num", &num);
	if(num > 0){
		Uci_Get_Str(PKG_ROUTER_QUAGGA_CONFIG,"bgpd","rules",rules);
		for(i=num; i>0; i--){
			memset(tmpBuf, 0, sizeof(tmpBuf));
			get_nth_val_safe((i-1), rules, ' ', tmpBuf, sizeof(tmpBuf));
			Uci_Del_List(PKG_ROUTER_QUAGGA_CONFIG, "bgpd", "rules", tmpBuf);
		}	
		num=0;
		Uci_Set_Str(PKG_ROUTER_QUAGGA_CONFIG, "bgpd", "num", "0");
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

				char *rulesType = webs_get_string(subnet_x, "type");
				char *address  = webs_get_string(subnet_x, "address");
				char *remoteAsNum = webs_get_string(subnet_x, "remoteAs");
				char *updateSource  = webs_get_string(subnet_x, "updateSource");
				char *auto_summary = webs_get_string(subnet_x, "autoSummary");
				char *log_neighbor_changes  = webs_get_string(subnet_x, "logChange");
				char *synchronization  = webs_get_string(subnet_x, "synchronization");
				dbg("=============remoteAs:%s==========\n",remoteAsNum);
				if((!rulesType && !strlen(rulesType))||(!address && !strlen(address)))
					continue;

				count++;
				
				if(!strcmp(rulesType, "neighbour"))
				{
					snprintf(rule, sizeof(rule), "%s,%s,%s,%s,%s,%s,%s", rulesType, address, \
						remoteAsNum, "", auto_summary, log_neighbor_changes, synchronization);
				}
				else
				{
					snprintf(rule, sizeof(rule), "%s,%s", rulesType, address);
				}
				Uci_Add_List(PKG_ROUTER_QUAGGA_CONFIG, "bgpd", "rules", rule);
			}

			memset(tmpBuf, 0, sizeof(tmpBuf));
			sprintf(tmpBuf, "%d", count);
			Uci_Set_Str(PKG_ROUTER_QUAGGA_CONFIG, "bgpd", "num", tmpBuf);
		}
	}
	
	if(count == 0)
	{
		unlink(QUAGGA_BGPD_CONF);
		unlink("/tmp/bgp.log");
	}

	Uci_Commit(PKG_ROUTER_QUAGGA_CONFIG);
	set_lktos_effect("router_quagga");
	set_lktos_effect("firewall");

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "5", "reserv");
	return CGI_TRUE;
}

#endif




CGI_HANDLE_TABLE firewall_handle_t[] = {
	
	{"getMacFilterRules", getMacFilterRules, 1},
	{"setMacFilterRules", setMacFilterRules, 1},

	{"getUrlFilterRules", getUrlFilterRules, 1},
	{"setUrlFilterRules", setUrlFilterRules, 1},

	{"getIpPortFilterRules", getIpPortFilterRules, 1},
	{"setIpPortFilterRules", setIpPortFilterRules, 1},
	
	{"getDMZCfg", getDmzCfg, 1},
	{"setDMZCfg", setDmzCfg, 1},

	{"setWanPingCfg", setWanPingCfg, 1},
	{"getWanPingCfg", getWanPingCfg, 1},
	
	{"getPortForwardRules", getPortForwardRules, 1},
	{"setPortForwardRules", setPortForwardRules, 1},
	{"delPortForwardRules", delPortForwardRules, 1},

	{"getVpnPassCfg", getVpnPassCfg, 1},
	{"setVpnPassCfg", setVpnPassCfg, 1},

	{"setParentalRules", setParentalRules, 1},
	{"getParentalRules", getParentalRules, 1},
	{"delParentalRules", delParentalRules, 1},

	{"setAccessDeviceCfg", setAccessDeviceCfg, 1},

	{"getRemoteCfg",    getRemoteCfg,    1},
	{"setRemoteCfg",    setRemoteCfg,    1},

	{"getNatRules", getNatRules, 1},
	{"setNatRules", setNatRules, 1},

	{"getQosSetCfg", getQosSetCfg, 1},
	{"setQosSetCfg", setQosSetCfg, 1},
	{"getIpQosLimitCfg", getIpQosLimitCfg, 1},
	{"setIpQosLimitCfg", setIpQosLimitCfg, 1},

	{"getAlgServicesCfg", getAlgServicesCfg, 1},
	{"setAlgServicesCfg", setAlgServicesCfg, 1},
	
#if defined(APP_QUAGGA)
	{"setBasicRoutingCfg", setBasicRoutingCfg, 1},
	
	{"setRoutingRipCfg", setRoutingRipCfg, 1},
	{"getRoutingRipCfg", getRoutingRipCfg, 1},
	
	{"getRoutingOspfCfg", getRoutingOspfCfg, 1},
	{"setRoutingOspfCfg", setRoutingOspfCfg, 1},
	
	{"getRoutingBgpCfg", getRoutingBgpCfg, 1},
	{"setRoutingBgpCfg", setRoutingBgpCfg, 1},
#endif


	{"", NULL, 0}
};

