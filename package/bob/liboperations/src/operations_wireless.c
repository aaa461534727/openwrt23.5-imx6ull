#include "operations_common.h"


/****************************************************************
*																*
*					wireless reload API							*
*																*
*****************************************************************/

OPERATIONS_BOOL CsRealReloadWireless(void)
{
	char mapmode[8] = {0};

	doSystem("%s","cs wifi_basic");
	wificonf_get_by_key(W24G_MH, "mapmode", mapmode, sizeof(mapmode));
	if(atoi(mapmode)==1){
		genBssConfigs();
		doSystem("mapd_cli /tmp/mapd_ctrl renew > /tmp/map_renew.log");
	}

	return OPERATIONS_TRUE;
}

OPERATIONS_BOOL CsRealReloadWps(void)
{
	CsteSystem("cs_wps_exec -s 0 &",0);
	
	return OPERATIONS_TRUE;
}

OPERATIONS_BOOL CsRealReloadAcl(void)
{
	int i;

	int wl_radio,wl_idx, wl_max;

	char acl_idx[8], acl_disabled[8], wlan_ifname[16];

	char cmd_line[4096]={0}, acl_maclist[4096],list_buff[4096];

	char rule[128], macaddr[18];

	datconf_get_by_key(TEMP_STATUS_FILE, "acl_idx", acl_idx, sizeof(acl_idx));

	wl_radio = W24G_RADIO;
	wl_idx   = W24G_IF;
	wl_max   = W24G_G4;

#if BOARD_HAS_5G_RADIO
	if(atoi(acl_idx)==1) { // 0:2.4G; 1:5G;
		wl_radio = W58G_RADIO;
		wl_idx   = W58G_IF;
		wl_max   = W58G_G4;
	}
#endif

	strcpy(wlan_ifname,WL_IF[wl_idx].ifname);
	wificonf_get_by_key(wl_radio, "acl_mode", acl_disabled, sizeof(acl_disabled));
	wificonf_get_by_key(wl_radio, "acl_maclist", list_buff, sizeof(list_buff));

	i=0;
	memset(acl_maclist,0,sizeof(acl_maclist));
	memset(rule,0,sizeof(rule));
	memset(macaddr,0,sizeof(macaddr));
	while(get_nth_val_safe(i, list_buff, ' ', rule, sizeof(rule))==0){
		if((get_nth_val_safe(0, rule, ',', macaddr, sizeof(macaddr)) == -1)){
			i++;
			memset(rule,0,sizeof(rule));
			memset(macaddr,0,sizeof(macaddr));
			continue;
		}

		if(i != 0)
		{
			strcat(acl_maclist,";");
		}

		strcat(acl_maclist,macaddr);
		i++;
		memset(rule,0,sizeof(rule));
		memset(macaddr,0,sizeof(macaddr));
	}

	for(i = wl_idx; i <= wl_max; i++)
	{
		if(i==W24G_MH || i==W58G_MH || is_ssid_disabled(i))
		{
			continue;
		}

		strcpy(wlan_ifname,WL_IF[i].ifname);

		if(0==atoi(acl_disabled)){
			memset(cmd_line,0,sizeof(cmd_line));
			snprintf(cmd_line,sizeof(cmd_line), "iwpriv %s set ACLClearAll=1",wlan_ifname);
			CsteSystem(cmd_line,0);

			memset(cmd_line,0,sizeof(cmd_line));
			snprintf(cmd_line,sizeof(cmd_line),"iwpriv %s set AccessPolicy=0",wlan_ifname);
			CsteSystem(cmd_line,0);
		}else{
			//clear all rules
			memset(cmd_line,0,sizeof(cmd_line));
			snprintf(cmd_line,sizeof(cmd_line),"iwpriv %s set ACLClearAll=1",wlan_ifname);
			CsteSystem(cmd_line,0);

			memset(cmd_line,0,sizeof(cmd_line));
			snprintf(cmd_line,sizeof(cmd_line),"iwpriv %s set AccessPolicy=%s",wlan_ifname,acl_disabled);
			CsteSystem(cmd_line,0);

			if(strlen(acl_maclist)>0){
				memset(cmd_line,0,sizeof(cmd_line));
				snprintf(cmd_line,sizeof(cmd_line),"iwpriv %s set ACLAddEntry=\"%s\"",wlan_ifname,acl_maclist);
				CsteSystem(cmd_line,0);
				//EX: iwpriv rax0 set ACLAddEntry="48:FD:A3:F2:7F:1F"
			}

			memset(cmd_line,0,sizeof(cmd_line));
			snprintf(cmd_line,sizeof(cmd_line),"iwpriv %s set DisConnectAllSta=1",wlan_ifname);
			CsteSystem(cmd_line,0);
		}
	}

	return OPERATIONS_TRUE;
}

