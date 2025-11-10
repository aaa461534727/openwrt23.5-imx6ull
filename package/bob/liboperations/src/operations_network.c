#include "operations_common.h"
#include <sys/sysinfo.h>

int Static_route_loadconfig_set(void)
{
	char strCmdBuf[CMD_STR_LEN] = { 0 };
	char destination[RESULT_STR_LEN] = {0},gateway[RESULT_STR_LEN] = {0},genmask[RESULT_STR_LEN] = {0};
	char metric[SMALL_STR_LEN] = {0},iface[SMALL_STR_LEN]={0}, comment[OPTION_STR_LEN]={0};
	char section[OPTION_STR_LEN]={0};
	int num=0,i=0; 
	struct in_addr ipaddr;
	
	num = get_cmd_val("uci show network | grep route | grep target= |  wc -l");
	
	for(i=0;i<num;i++){
		memset(destination,0,sizeof(destination));
		memset(gateway,0,sizeof(gateway));
		memset(genmask,0,sizeof(genmask));
		memset(iface,0,sizeof(iface));
		memset(metric,0,sizeof(metric));
		snprintf(section,OPTION_STR_LEN,"@route[%d]",i);
		
		Uci_Get_Str(PKG_NETWORK_CONFIG,section,"interface",iface);
		if ( 0 == strlen(iface) )
			continue;
		
		Uci_Get_Str(PKG_NETWORK_CONFIG,section,"metric",metric);
		Uci_Get_Str(PKG_NETWORK_CONFIG,section,"target",destination);
		Uci_Get_Str(PKG_NETWORK_CONFIG,section,"netmask",genmask);
		Uci_Get_Str(PKG_NETWORK_CONFIG,section,"gateway",gateway);
		Uci_Get_Str(PKG_NETWORK_CONFIG,section,"comment",comment);
		
		//���ַ���ת��Ϊin_addr����
		ipaddr.s_addr =  inet_addr(destination)&inet_addr(genmask);
		//��in_addr����ת��Ϊ�ַ���
		strcpy(destination,inet_ntoa(ipaddr));

		if (strlen(metric) == 0)
		{
			XCMD(strCmdBuf, "route add -net %s netmask %s gw %s metric 0", destination , genmask , gateway);
		}
		else
		{
			XCMD(strCmdBuf, "route add -net %s netmask %s gw %s metric %s", destination , genmask , gateway, metric);
		}
	}
	return OPERATIONS_TRUE;
}

int wanup_set_net_server(void)
{
	int wizard_flag;
	int ret;

	struct interface_status status_paremeter;

	ret = check_lan_wan_confliction();
	
	if(ret == 1) {
		CsteSystem("/etc/init.d/dnsmasq restart", 0);
		CsteSystem("/etc/init.d/network restart", 0);
		reset_lan_port();
	}
	dns_genetrate();

	get_wan_status(&status_paremeter);
	Uci_Get_Int(PKG_SYSTEM_CONFIG,"main","wizard_flag",&wizard_flag);
	if(wizard_flag!=1&&status_paremeter.up)
	{
		Uci_Set_Str(PKG_SYSTEM_CONFIG,"main","wizard_flag","1");
		Uci_Commit(PKG_SYSTEM_CONFIG);
	}

#if defined(CONFIG_DDNS_SUPPORT)
	set_lktos_effect("ddns");
#endif

	return OPERATIONS_TRUE;
}

int wanup_set_ipsec_restart()
{
	CsteSystem("/usr/bin/sswan restart", CSTE_PRINT_CMD);

	return OPERATIONS_TRUE;
}
/****************************************************************
*																*
*					network reload API							*
*																*
*****************************************************************/
OPERATIONS_BOOL CsRealReloadNetwork(void)
{
	char lan_change[8]={0};

	CsteSystem("/etc/init.d/xl2tpd stop", CSTE_PRINT_CMD);

	CsteSystem("/etc/init.d/network restart", CSTE_PRINT_CMD);

	CsteSystem("/etc/init.d/dnsmasq restart", CSTE_PRINT_CMD);

	datconf_get_by_key(TEMP_STATUS_FILE, "lan_change", lan_change,sizeof(lan_change));
	if(atoi(lan_change)==1){
		reset_lan_port();
		datconf_set_by_key(TEMP_STATUS_FILE, "lan_change", "0");
	}
	
#if defined(APP_IOT_MQTT)
	set_lktos_effect("iot-mqtt");
#endif

	CsRealReloadIgmpproxy();

	return OPERATIONS_TRUE;
}

OPERATIONS_BOOL CsRealReloadMcm(void)
{
	char ModemPrio[6]={0};

	CsteSystem("/etc/init.d/mcm_init stop", CSTE_PRINT_CMD);

	CsteSystem("/etc/init.d/mcm_init restart", CSTE_PRINT_CMD);

	Uci_Get_Str(PKG_WAN_MODEM_CONFIG,"strategy","prio", ModemPrio);
	
	if( atoi(ModemPrio) == PRIO_ONLY_WIRE )
	{
		datconf_set_by_key(TEMP_MODEM_FILE, "reg_status", "idle");
		datconf_set_by_key(TEMP_MODEM_FILE, "net_type", "");
		datconf_set_by_key(TEMP_MODEM_FILE, "imei",  "");
		datconf_set_by_key(TEMP_MODEM_FILE, "imsi", "");
		datconf_set_by_key(TEMP_MODEM_FILE, "iccid", "");
		datconf_set_by_key(TEMP_MODEM_FILE, "arfcn", "");
		datconf_set_by_key(TEMP_MODEM_FILE, "band", "");			
		datconf_set_by_key(TEMP_MODEM_FILE, "cellid", "");
		datconf_set_by_key(TEMP_MODEM_FILE, "sinr", "");
		datconf_set_by_key(TEMP_MODEM_FILE, "rsrp", "");
		datconf_set_by_key(TEMP_MODEM_FILE, "rsrq", "");
		datconf_set_by_key(TEMP_MODEM_FILE, "rssi", "");
		datconf_set_by_key(TEMP_MODEM_FILE, "pci", "");
		datconf_set_by_key(TEMP_MODEM_FILE, "eci", "");
		datconf_set_by_key(TEMP_MODEM_FILE, "channel", "");
		datconf_set_by_key(TEMP_MODEM_FILE, "signal", "");	

	}

	return OPERATIONS_TRUE;
}

void wanup_set_ipv6_gw(void)
{
	char cmd[256] = {0};
	char result[512] = {0};
	char wan6_gw[128] = {0};
	char wan_iface[16] = {0};
	char wan_proto[16] = {0};
	char web_status[16] = {0};

	Uci_Get_Str(PKG_NETWORK_CONFIG,"wan6","web_status",web_status);
	if(strcmp(web_status, "nat66"))
	{
		return;
	}

	sprintf(cmd,"ip -6 route | grep default");

	get_cmd_result(cmd, result, sizeof(result));

	if(strlen(result) > 0)
	{
		get_nth_val_safe(4,result, ' ', wan6_gw, sizeof(wan6_gw));
		get_nth_val_safe(6,result, ' ', wan_iface, sizeof(wan_iface));
	}
	//route -A inet6 add default gw fe80::20c:43ff:fe4a:213c dev eth1
	sprintf(cmd, "route -A inet6 add default gw %s dev %s", wan6_gw, wan_iface);
	CsteSystem(cmd,0);
	dbg("wanup_set_ipv6_gw: cmd[%s]\n",cmd);
	
}

OPERATIONS_BOOL CsRealFirewall(void)
{
	CsteSystem("cs_firewall", 0);

	return OPERATIONS_TRUE;
}

int wan_policy_set(void)
{

	int modem_prio,link_status, wan_port_link;
	char gw_if[32] = {0}, modem_ifname[32] = {0};
	
	struct interface_status wire_paremeter;
	struct interface_status modem_paremeter;

	memset(&wire_paremeter,0,sizeof(struct interface_status));
	memset(&modem_paremeter,0,sizeof(struct interface_status));

#if defined (ETH_PORT_WAN)
	if(ETH_PORT_WAN > -1 && ETH_PORT_WAN <7) {
		wan_port_link = is_phyport_connected(ETH_PORT_WAN);
	}
	else {
		wan_port_link = 0;
	}
#else
	wan_port_link = 0;
#endif

	get_wire_wan_status(&wire_paremeter);
	get_interface_status(&modem_paremeter,"wan_modem");

	get_gateway_iface(gw_if);

	dbg("===cur gw if[%s]===\n",gw_if);

	Uci_Get_Str(PKG_WAN_MODEM_CONFIG,"strategy","prio", &modem_prio);
	Uci_Get_Str(PKG_NETWORK_CONFIG,"wan_modem","device", modem_ifname);

	if(modem_prio == PRIO_ONLY_WIRE || modem_prio == PRIO_3GPP_ONLY )
	{
		return 0;
	}

	link_status = LINK_STATUS_NO;

	if(modem_prio == PRIO_WIRE_FRIST)	{

		if(wire_paremeter.up && wan_port_link && !strcmp(gw_if, modem_ifname))
			link_status = LINK_STATUS_WIRE;
		else if((!wire_paremeter.up || !wan_port_link)&& modem_paremeter.up && strcmp(gw_if, modem_ifname))
			link_status = LINK_STATUS_MODEM;
	}
	else if(modem_prio == PRIO_3GPP_FRIST) {
		if(modem_paremeter.up && strcmp(gw_if, modem_ifname))
			link_status = LINK_STATUS_MODEM;
		else if(!modem_paremeter.up && wire_paremeter.up && wan_port_link && !strcmp(gw_if, modem_ifname))
			link_status = LINK_STATUS_WIRE;
	}

	if(link_status == LINK_STATUS_WIRE) {
		doSystem("ifup wan");
		dbg("[PRIO TO WIRE].....\n");
	}
	else if(link_status == LINK_STATUS_MODEM) {
		doSystem("ifup wan_modem");
		dbg("[PRIO TO MODEM].....\n");
	}

}

OPERATIONS_BOOL CsRealReloadWandown()
{

	wan_policy_set();

	return OPERATIONS_TRUE;
}

OPERATIONS_BOOL CsRealReloadWanup()
{

	wan_policy_set();

	/* restart firewall */
	CsRealFirewall();

	wanup_set_net_server();

	wanup_set_ipsec_restart();
	
#if defined(CONFIG_CLOUDUPDATE_SUPPORT)
	forced_cloud_upgrade();
#endif

#if defined(CONFIG_USER_IPV6)
	wanup_set_ipv6_gw();
#endif

	return OPERATIONS_TRUE;
}

OPERATIONS_BOOL CsRealWanPortDown(void)
{
	static long down_time=0;
	char old_ip_addr[16]={0}, new_ip_addr[16]={0};
	struct sysinfo info;
	sysinfo(&info);
	
	long new_down_time = info.uptime;
	
	if( (new_down_time-2)<down_time )
	{
		return OPERATIONS_TRUE;
	}
	
	down_time=new_down_time;
	
#if 1 //fix me, it will cause wan down up always
	char opmode_custom[8]={0},wan_proto[16]={0};

	Uci_Get_Str(PKG_SYSTEM_CONFIG, "opmode", "opmode_custom",opmode_custom);
	//Uci_Get_Str(PKG_NETWORK_CONFIG, "wan", "proto", wan_proto);
	
	if(strcmp(opmode_custom,"br")==0 /*(strcmp(opmode_custom,"gw")==0 && strcmp(wan_proto,"dhcp")==0)*/ )
	{
		get_ifname_ipaddr("br-lan",old_ip_addr);
		
		system("killall -SIGUSR2 udhcpc");
		system("killall -SIGUSR1 udhcpc");
		
		sleep(1);
		get_ifname_ipaddr("br-lan",new_ip_addr);
		if( strcmp(old_ip_addr, new_ip_addr)!=0 )
		{
			reset_lan_port();
		}
		
	}else if(strcmp(opmode_custom,"gw")==0){
		system("killall -SIGUSR2 udhcpc");
		system("killall -SIGUSR1 udhcpc");
							
	}
#endif

	return OPERATIONS_TRUE;
}

OPERATIONS_BOOL CsRealWanPortUp(void)
{
	char opmode_custom[8]={0}, wan_proto[16]={0};

	Uci_Get_Str(PKG_SYSTEM_CONFIG, "opmode", "opmode_custom",opmode_custom);
	Uci_Get_Str(PKG_NETWORK_CONFIG, "wan", "proto", wan_proto);

	if(strcmp(opmode_custom,"gw")==0 &&strcmp(wan_proto, "static") == 0)
	{
		struct sysinfo info;
		char wan_up_time[16]={0};

		sysinfo(&info);

		datconf_get_by_key(TEMP_STATUS_FILE, "wan_up_time", wan_up_time,sizeof(wan_up_time));

		if(info.uptime-atoi(wan_up_time)>10)
		{
			doSystem("ifdown wan");
			doSystem("ifup wan");

			snprintf(wan_up_time,sizeof(wan_up_time),"%d",info.uptime);
			datconf_set_by_key(TEMP_STATUS_FILE, "wan_up_time", wan_up_time);
		}
		else
		{
			doSystem("cs_firewall &");
		}
	}

	return OPERATIONS_TRUE;
}

OPERATIONS_BOOL CsRealReloadLanup()
{
	struct interface_status status_paremeter;

	get_wan_status(&status_paremeter);
	if ( 0 == status_paremeter.up )
	{
		//In order to have no network firewall rules
		//FirewallConfigInit(APPLY_RELOAD);
#if defined(CONFIG_CLOUDUPDATE_SUPPORT)
		forced_cloud_upgrade();
#endif
	}
	//else if(OPMODE_BRIDGE_INT == opMode || OPMODE_REPEATER_INT == opMode)
	{
		//FirewallConfigInit(APPLY_RELOAD);
	}
	CsteSystem("/etc/init.d/detect_wanduck restart", CSTE_PRINT_CMD);
	return OPERATIONS_TRUE;
}

OPERATIONS_BOOL CsRealReloadLan(void)
{
	CsteSystem("/etc/init.d/network restart", CSTE_PRINT_CMD);
	
	return OPERATIONS_TRUE;
}

OPERATIONS_BOOL CsRealReloadStaticRoute(void)
{
	Static_route_loadconfig_set();
	
	return OPERATIONS_TRUE;
}

OPERATIONS_BOOL CsRealReloadStaticTunnelRoute(void)
{
	int i, iRulesNum=0;

	char sRules[2048]={0}, sRule[128]={0},strCmdBuf[1024]={0};
	char routeEnabled[8]={0}, tunnelName[32]={0}, ip[32]={0}, virtualIp[32]={0};
	char mask[32]={0},desc[32]={0};

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

		if (atoi(routeEnabled) == 1)
		{
			XCMD(strCmdBuf, "route add -net %s netmask %s gw %s metric 0 dev %s", virtualIp , mask , "0.0.0.0","runnel111");
		}
	}

	return OPERATIONS_TRUE;
}


//------------------------------------------------------------
static void
arpbind_clear(void)
{
	FILE *fp;
	char buffer[256], arp_ip[16], arp_if[32];
	unsigned int arp_flags;
	int unit = 0;
	char strCmdBuf[256]    = { 0 };
	
	fp = fopen("/proc/net/arp", "r");
	if (fp) {
		// skip first line
		fgets(buffer, sizeof(buffer), fp);
		
		while (fgets(buffer, sizeof(buffer), fp)) {
			arp_flags = 0;
			if (sscanf(buffer, "%15s %*s 0x%x %*s %*s %31s", arp_ip, &arp_flags, arp_if) == 3) {

				if ((arp_flags & 0x04) && strcmp(arp_if, LAN_DEV_NAME) == 0)	
					XCMD(strCmdBuf, "arp -i %s -d %s", LAN_DEV_NAME,arp_ip);
			}
		}
		fclose(fp);
	}
}

int arp_bind(void)
{
	int i = 0, arp_enabled = 0, num = 0;
	char section[64]={0}, mac[64] = {0}, ip[64] = {0}, strCmdBuf[256];

	Uci_Get_Int(PKG_DHCP_CONFIG,"lan","arp_enabled",&arp_enabled);

	arpbind_clear();

	if(arp_enabled == 1){
		num = get_cmd_val("uci show dhcp | grep host | grep mac= |  wc -l");

		for(i=0;i<num;i++){

			snprintf(section,OPTION_STR_LEN,"@host[%d]",i);

			Uci_Get_Str(PKG_DHCP_CONFIG, section, "ip", ip);
			Uci_Get_Str(PKG_DHCP_CONFIG, section, "mac", mac);

			XCMD(strCmdBuf, "arp -s %s %s",ip,mac);
		}
	}

	return 0;
}

OPERATIONS_BOOL CsRealReloadDhcp(void)
{
	char reload_arp_bind[8]={0};
	int dhcp_server=0;

	datconf_get_by_key(TEMP_STATUS_FILE, "reload_arp_bind", reload_arp_bind,sizeof(reload_arp_bind));

	Uci_Get_Int(PKG_DHCP_CONFIG, "lan", "ignore", &dhcp_server);

	if(dhcp_server==0){
		arp_bind();
	}

	if(strcmp(reload_arp_bind,"1")!=0)
	{
		/*fix lan ip change dhcp update issue*/
		CsteSystem("/etc/init.d/dnsmasq restart", CSTE_PRINT_CMD);
	}

	datconf_set_by_key(TEMP_STATUS_FILE, "reload_arp_bind", "0");

	//let the PC renew ipaddr
	reset_lan_port();

	//let wireless sta renew ipaddr
	//doSystem("iwpriv %s set DisConnectAllSta=1","ra0");
	doSystem("iwpriv %s set DisConnectAllSta=1","rax0");

	return OPERATIONS_TRUE;
}

OPERATIONS_BOOL CsRealReloadPptpd(void)
{
	CsteSystem("/etc/init.d/pptpd restart", CSTE_PRINT_CMD);
	CsteSystem("cs_firewall", 0);
	return OPERATIONS_TRUE;
}

OPERATIONS_BOOL CsRealReloadL2tpd(void)
{
	CsteSystem("vpn_server xl2tpd", CSTE_PRINT_CMD);
	CsteSystem("/etc/init.d/xl2tpd restart", CSTE_PRINT_CMD);
	CsteSystem("cs_firewall", 0);
	return OPERATIONS_TRUE;
}

OPERATIONS_BOOL CsRealReloadPppuser(void)
{
	int iPptpdEn,iL2tpdEn;
	
	CsteSystem("vpn_server pppuser", CSTE_PRINT_CMD);
	
	Uci_Get_Int(PKG_PPTPD_CONFIG, "pptpd", "enable", &iPptpdEn);
	Uci_Get_Int(PKG_L2TPD_CONFIG, "xl2tpd", "enable", &iL2tpdEn);
	if(iPptpdEn)
		CsRealReloadPptpd();
	return OPERATIONS_TRUE;
}

OPERATIONS_BOOL CsRealReloadIpsecFw(void)
{
	CsteSystem("cs_firewall", 0);
	return OPERATIONS_TRUE;
}

OPERATIONS_BOOL CsRealReloadIpsec(void)
{
	#if 1
	CsteSystem("/usr/bin/sswan restart", CSTE_PRINT_CMD);
	#else
	CsteSystem("/etc/init.d/ipsec restart", CSTE_PRINT_CMD);
	#endif
	return OPERATIONS_TRUE;                         
}

OPERATIONS_BOOL ReloadIpsecGMCfg(void)
{
	CsteSystem("app_ipsec_gm init", 0);

	return OPERATIONS_TRUE;
}

OPERATIONS_BOOL StartIpsecGmCfg(void)
{
	CsteSystem("app_ipsec_gm start", 0);

	return OPERATIONS_TRUE;
}

int dns_genetrate(void)
{
	char lan_dns_server[8] = {0},wanMode[8] = {0}, dns_enable[8] = {0}, wan_interface[8] = {0},buff[128] = {0};
	int peerdns = 0;

	Uci_Get_Int(PKG_NETWORK_CONFIG, "wan", "peerdns", &peerdns);
	Uci_Get_Str(PKG_NETWORK_CONFIG, "lan", "lan_dns_server", lan_dns_server);

	if(strlen(lan_dns_server) < 1  || atoi(lan_dns_server) == 0) {
		CsteSystem("uci -c /etc/config del dhcp.lan.dhcp_option ", CSTE_PRINT_CMD);
		Uci_Commit(PKG_DHCP_CONFIG);
	}

	if(peerdns == 2)
	{
		Uci_Get_Str(PKG_NETWORK_CONFIG, "vpn", "proto",wanMode);
		strcpy(wan_interface,"vpn");
		if(strlen(wanMode) == 0)
		{
			memset(wan_interface,'\0',sizeof(wan_interface));
			strcpy(wan_interface,"wan");
			Uci_Get_Str(PKG_NETWORK_CONFIG, "wan", "proto",wanMode);
		}
		struct interface_status status_paremeter;
		memset(&status_paremeter,0,sizeof(struct interface_status));
		get_interface_status(&status_paremeter,wan_interface);

		if(strlen(status_paremeter.pri_dns_v4) > 0){
			if(strlen(status_paremeter.sec_dns_v4) > 0){
				sprintf(buff, "6,%s,%s", status_paremeter.pri_dns_v4,status_paremeter.sec_dns_v4);
			}else{
				sprintf(buff, "6,%s", status_paremeter.pri_dns_v4);
			}

			Uci_Add_List(PKG_DHCP_CONFIG, "lan", "dhcp_option", buff);
			Uci_Commit(PKG_DHCP_CONFIG);
		}
	}

	Uci_Get_Str(PKG_DHCP_CONFIG, "wan", "dns_enabled", dns_enable);
	if(strlen(dns_enable) > 0 && atoi(dns_enable) == 0) {
		CsteSystem("echo ' ' > /tmp/resolv.conf.d/resolv.conf.auto", 0);
	}
	CsteSystem("/etc/init.d/dnsmasq restart", 0);

	return 0;
}

void newipaddr_genetrate(int i, char *ipaddr, char *dst_ipaddr)
{
	struct in_addr t_ipaddr;
	unsigned long int u_ipaddr;

	if (!inet_aton(ipaddr, &t_ipaddr))
	{
		return ;
	}

	u_ipaddr=t_ipaddr.s_addr;
	if ((u_ipaddr & (1<<i)) == 0)
	{
		u_ipaddr = u_ipaddr+(1<<(24-i));
	}
	else
	{
		u_ipaddr = u_ipaddr-(1<<(24-i));
	}

	t_ipaddr.s_addr=u_ipaddr;

	strcpy(dst_ipaddr, (char *)inet_ntoa(t_ipaddr));
}

void check_static_dhcp_ip(struct in_addr ipaddr_new, struct in_addr netmask_new)
{
	int i = 0, num = 0;

	char static_ip[32] = { 0 };

	char section[OPTION_STR_LEN] = { 0 };

	struct in_addr private_host, tmp_private_host, update;

	num = get_cmd_val("uci show dhcp | grep host | grep mac= |  wc -l");

	for(i = 0; i < num; i++)
	{
		memset(static_ip, 0,sizeof(static_ip));
		snprintf(section,OPTION_STR_LEN,"@host[%d]",i);
		Uci_Get_Str(PKG_DHCP_CONFIG,section,"ip",static_ip);

		private_host.s_addr=inet_addr(static_ip);

		if((ipaddr_new.s_addr & netmask_new.s_addr) != (private_host.s_addr & netmask_new.s_addr))
		{
			update.s_addr = ipaddr_new.s_addr & netmask_new.s_addr;
			tmp_private_host.s_addr  = ~(netmask_new.s_addr) & private_host.s_addr;
			update.s_addr = update.s_addr | tmp_private_host.s_addr;

			Uci_Set_Str(PKG_DHCP_CONFIG, section, "ip", inet_ntoa(update));
		}
	}
	Uci_Commit(PKG_DHCP_CONFIG);
}


int check_lan_wan_confliction()
{
	int i, ret;

	char src_ipaddr[18], dst_ipaddr[18];

	struct in_addr in_wan_ip;
	struct in_addr in_wan_mask;

	struct in_addr in_lan_ip;
	struct in_addr in_lan_mask;

	unsigned long int ul_wan_mask;
	unsigned long int ul_lan_ip;
	unsigned long int ul_lan_mask;
	unsigned long int ul_use_mask;

	struct interface_status wan_status, lan_status;

	memset(&wan_status,0,sizeof(struct interface_status));
	ret = get_wan_status(&wan_status);
	if (ret == LINK_STATUS_MODEM)
	{
		return 0;
	}

	if(strcmp(wan_status.proto,"dhcp")!=0){
		return 0;
	}

	if (!inet_aton(wan_status.ipaddr_v4, &in_wan_ip) || !inet_aton(wan_status.mask_v4, &in_wan_mask))
	{
		return 0;
	}

	memset(&lan_status,0,sizeof(struct interface_status));
	get_interface_status(&lan_status,"lan");
	if (!inet_aton(lan_status.ipaddr_v4, &in_lan_ip) || !inet_aton(lan_status.mask_v4, &in_lan_mask))
	{
		return 0;
	}

	ul_wan_mask = in_wan_mask.s_addr;
	ul_lan_ip   = in_lan_ip.s_addr;
	ul_lan_mask = in_lan_mask.s_addr;

	memcpy(&ul_use_mask, ul_lan_mask>ul_wan_mask?&ul_wan_mask:&ul_lan_mask, sizeof(ul_lan_mask));

	if ((in_wan_ip.s_addr & ul_wan_mask) != (ul_lan_ip & ul_lan_mask)){
		return 0;
	}

	dbg("------  wan ip conflict lan ip  ------\n");

	for (i=0; i<32; i++)
	{
		if ((htonl(ul_use_mask) & (1<<i)) != 0)
		{
			break;
		}
	}

	if ((ul_lan_ip & (1<<i)) == 0)
	{
		ul_lan_ip = ul_lan_ip+(1<<(24-i));
	}
	else
	{
		ul_lan_ip = ul_lan_ip-(1<<(24-i));
	}

	in_lan_ip.s_addr = ul_lan_ip;
	in_lan_mask.s_addr = ul_use_mask;

	memset(src_ipaddr,0,sizeof(src_ipaddr));
	memset(dst_ipaddr,0,sizeof(dst_ipaddr));
	Uci_Get_Str(PKG_DHCP_CONFIG, "lan", "start", src_ipaddr);
	newipaddr_genetrate(i, src_ipaddr, dst_ipaddr);
	Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "start", dst_ipaddr);

	memset(src_ipaddr,0,sizeof(src_ipaddr));
	memset(dst_ipaddr,0,sizeof(dst_ipaddr));
	Uci_Get_Str(PKG_DHCP_CONFIG, "lan", "dhcp_e", src_ipaddr);
	newipaddr_genetrate(i, src_ipaddr, dst_ipaddr);
	Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "dhcp_e", dst_ipaddr);

	Uci_Set_Str(PKG_NETWORK_CONFIG, "lan", "ipaddr",  (char *)inet_ntoa(in_lan_ip));
	Uci_Set_Str(PKG_NETWORK_CONFIG, "lan", "netmask", (char *)inet_ntoa(in_lan_mask));

	check_static_dhcp_ip(in_lan_ip, in_lan_mask);

	Uci_Commit(PKG_DHCP_CONFIG);
	Uci_Commit(PKG_NETWORK_CONFIG);

	return 1;
}

//------------------------------------------------------------
#if defined(CONFIG_DDNS_SUPPORT)
OPERATIONS_BOOL CsRealReloadDdns(void)
{
	CsteSystem("/etc/init.d/yddns restart", CSTE_PRINT_CMD);
	CsteSystem("/etc/init.d/orayddns restart", CSTE_PRINT_CMD);
	CsteSystem("/etc/init.d/noip2 restart", CSTE_PRINT_CMD);

	return OPERATIONS_TRUE;
}
#endif

OPERATIONS_BOOL CsRealReloadUdhcpd(void)
{
	CsteSystem("/etc/init.d/odhcpd restart", CSTE_PRINT_CMD);
	
	return OPERATIONS_TRUE;
}

OPERATIONS_BOOL CsRealReloadUpnpd(void)
{
	CsteSystem("/etc/init.d/miniupnpd restart", CSTE_PRINT_CMD);
	
	return OPERATIONS_TRUE;
}

OPERATIONS_BOOL CsRealReloadIgmpproxy(void)
{	
	int mr_enable,mr_qleave;

	Uci_Get_Int(PKG_NETWORK_CONFIG, "iptv", "mrEnable", &mr_enable);
	Uci_Get_Int(PKG_NETWORK_CONFIG, "iptv", "mrQleave", &mr_qleave);

	if(mr_qleave == 2 || mr_qleave == 3)
		doSystem("echo %d > /proc/sys/net/ipv4/conf/all/force_igmp_version",mr_qleave);
	else
		doSystem("echo 0 > /proc/sys/net/ipv4/conf/all/force_igmp_version");

	if(!mr_enable)
		doSystem("/etc/init.d/igmpproxy stop");
	else 
		doSystem("/etc/init.d/igmpproxy restart");

	return OPERATIONS_TRUE;
}

OPERATIONS_BOOL CsDelayReboot(void)
{
	CsteSystem("reboot -d  5 &", CSTE_PRINT_CMD);

	return OPERATIONS_TRUE;
}

OPERATIONS_BOOL CsReloadSslVpnTun(void)
{
	int enabled=0;
	Uci_Get_Int(PKG_SSLVPN_CONFIG,"ssl","enabled", &enabled);
	if( enabled== 1){
		/* [start]nat66 */
		Uci_Set_Str(PKG_NETWORK_CONFIG, "wan6", "web_status", "nat66");
		Uci_Del_Section(PKG_DHCP_CONFIG,"wan6");
		Uci_Del_Section(PKG_NETWORK_CONFIG,"globals");
		
		Uci_Set_Str(PKG_NETWORK_CONFIG, "wan6", "reqaddress", "try");
		Uci_Set_Str(PKG_NETWORK_CONFIG, "wan6", "reqprefix", "auto");
		Uci_Set_Str(PKG_NETWORK_CONFIG, "wan6", "proto", "dhcpv6");
		Uci_Set_Str(PKG_NETWORK_CONFIG, "lan", "ip6assign", "64");
		
		CsteSystem("uci set network.globals=globals",CSTE_PRINT_CMD);
		Uci_Set_Str(PKG_NETWORK_CONFIG, "globals", "ula_prefix", "auto");
		Uci_Commit(PKG_NETWORK_CONFIG);
		system("sh /rom/etc/uci-defaults/12_network-generate-ula");

		Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "dhcpv6", "server");
		Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "ra", "server");
		Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "ndp", "");
		Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "ra_default", "1");
		Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "ra_management", "1");

		Uci_Set_Str(PKG_DHCP_CONFIG, "wan_modem6", "ignore", "1");
		Uci_Set_Str(PKG_NETWORK_CONFIG, "wan_modem6", "disabled", "0");
		/* [ end ]nat66 */		
	}else{
		/* [start]off ipv6 */
		Uci_Set_Str(PKG_NETWORK_CONFIG, "wan6", "web_status", "off");
		Uci_Del_Section(PKG_DHCP_CONFIG,"wan6");
		Uci_Del_Section(PKG_NETWORK_CONFIG,"globals");
		
		Uci_Set_Str(PKG_NETWORK_CONFIG, "wan6", "reqaddress", "try");
		Uci_Set_Str(PKG_NETWORK_CONFIG, "wan6", "reqprefix", "auto");
		Uci_Set_Str(PKG_NETWORK_CONFIG, "wan6", "proto", "dhcpv6");

		Uci_Set_Str(PKG_NETWORK_CONFIG, "lan", "ip6assign", "");

		Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "dhcpv6", "relay");
		Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "ra", "relay");
		Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "ndp", "relay");
		Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "ra_management", "0");
		Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "ra_default", "1");
		
		Uci_Set_Str(PKG_DHCP_CONFIG, "wan_modem6", "ignore", "0");
		/* [ end ]off ipv6 */

	}
	
	Uci_Commit(PKG_NETWORK_CONFIG);
	Uci_Commit(PKG_DHCP_CONFIG);
	
	set_lktos_effect("network");
	
	return OPERATIONS_TRUE;
}

OPERATIONS_BOOL CsRealReloadOpenvpnc(void)
{
	char server_addr[OPTION_STR_LEN] = {0}, server_domain[OPTION_STR_LEN];

	CsteSystem("/etc/init.d/openvpn stop", CSTE_PRINT_CMD);

	CsteSystem("killall openvpn", CSTE_PRINT_CMD);

	Uci_Get_Str(PKG_OPENVPND_CONFIG,"client","server_domain",server_domain);
	domain_to_ip(server_domain, server_addr);
	Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","server_ip",server_addr);
	Uci_Commit(PKG_OPENVPND_CONFIG);

	CsteSystem("/etc/init.d/openvpn restart", CSTE_PRINT_CMD);
	return OPERATIONS_TRUE;
}

OPERATIONS_BOOL CsRealReloadVxlan(void)
{
	int iRulesNum;
	char enabled[32]={0},cmd[256]={0},Rules[512]={0},Rule[256]={0};
	char vid[16]={0},peer_ip[16]={0},peer_port[16]={0},source_ip[16]={0},interface_t[16]={0};
	char vxlan_name[16]={0},new_name[16]={0};

	Uci_Get_Str(PKG_VXLAN_CONFIG,"vxlan","enabled",enabled);
	Uci_Get_Str(PKG_VXLAN_CONFIG, "vxlan", "rules", Rules);
	Uci_Get_Int(PKG_VXLAN_CONFIG, "vxlan", "num", &iRulesNum);

	if(atoi(enabled) == 1)
	{
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
			
			snprintf(vxlan_name,sizeof(vxlan_name),"vxlan%d",iRulesNum);
			
			Uci_Add_Interface(PKG_NETWORK_CONFIG,vxlan_name,"interface");
			Uci_Set_Str(PKG_NETWORK_CONFIG,vxlan_name,"proto","vxlan");
			Uci_Set_Str(PKG_NETWORK_CONFIG,vxlan_name,"peeraddr",peer_ip);
			Uci_Set_Str(PKG_NETWORK_CONFIG,vxlan_name,"port",peer_port);
			Uci_Set_Str(PKG_NETWORK_CONFIG,vxlan_name,"vid",vid);

			snprintf(vxlan_name,sizeof(vxlan_name),"@vxlan%d",iRulesNum);
			snprintf(new_name,sizeof(new_name),"vx%d",iRulesNum);

			Uci_Add_Interface(PKG_NETWORK_CONFIG,new_name,"interface");
			Uci_Set_Str(PKG_NETWORK_CONFIG,new_name,"proto","static");
			Uci_Set_Str(PKG_NETWORK_CONFIG,new_name,"device",vxlan_name);
			Uci_Set_Str(PKG_NETWORK_CONFIG,new_name,"ipaddr",source_ip);			
			Uci_Set_Str(PKG_NETWORK_CONFIG,new_name,"netmask","255.255.255.0");
			
			Uci_Commit(PKG_NETWORK_CONFIG);
			
			snprintf(cmd,sizeof(cmd),"ifup vxlan%d",iRulesNum);
			
			CsteSystem(cmd, CSTE_PRINT_CMD);
		}
	}
	else
	{
		
		for(int i=0;i<iRulesNum;i++)
		{
			snprintf(cmd,sizeof(cmd),"ifdown vxlan%d",iRulesNum);
			
			CsteSystem(cmd, CSTE_PRINT_CMD);
		}

	}

}

OPERATIONS_BOOL CsRealReloadTunnel(void)
{
	int i,j,num;
	char rules[2048]={0},rule[128]={0},enabled[8]={0},name[16]={0},mode[8]={0};
	char localVirtualIp[32]={0},peerExternIp[32],localExternIp[32]={0};
	char ifname[16]={0},new_name[16]={0},interface_t[16]={0},cmd[32]={0};
	
	char proto_list[3][16]={"gre","ipip","mgre"};


	for(i=0; i<ARRAY_SIZE(proto_list); i++)
	{
		Uci_Get_Int(PKG_TUNNEL_CONFIG, proto_list[i], "num", &num);
		if(num > 0)
		{
			Uci_Get_Str(PKG_TUNNEL_CONFIG,proto_list[i],"rules",rules);
						
			for(j = 0; j < num; j++)
			{
				get_nth_val_safe(j, rules, ' ', rule, sizeof(rule));
				
				if((get_nth_val_safe(0, rule, ',', enabled, sizeof(enabled)) == -1))
				{
					continue;
				}	
				
				if((get_nth_val_safe(1, rule, ',', name, sizeof(name)) == -1))
				{
					continue;
				}

				if((get_nth_val_safe(2, rule, ',', mode, sizeof(mode)) == -1))
				{
						continue;
				}

				
				snprintf(interface_t,sizeof(interface_t),"%s%s",mode,name);

				if(atoi(enabled) == 1)
				{

					if((get_nth_val_safe(3, rule, ',', localVirtualIp, sizeof(localVirtualIp)) == -1))
					{
						continue;
					}

					if((get_nth_val_safe(5, rule, ',', peerExternIp, sizeof(peerExternIp)) == -1))
					{
						continue;
					}
					if((get_nth_val_safe(6, rule, ',', localExternIp, sizeof(localExternIp)) == -1))
					{
						continue;
					}


					Uci_Add_Interface(PKG_NETWORK_CONFIG,interface_t,"interface");
					Uci_Set_Str(PKG_NETWORK_CONFIG,interface_t,"proto",mode);
					Uci_Set_Str(PKG_NETWORK_CONFIG,interface_t,"peeraddr",peerExternIp);
					Uci_Set_Str(PKG_NETWORK_CONFIG,interface_t,"ipaddr",localExternIp);
					Uci_Set_Str(PKG_NETWORK_CONFIG,interface_t,"mtu","1400");	
					
					
					snprintf(ifname,sizeof(ifname),"@%s",interface_t);
					snprintf(new_name,sizeof(new_name),"%s_t",interface_t);
					
					Uci_Add_Interface(PKG_NETWORK_CONFIG,new_name,"interface");
					Uci_Set_Str(PKG_NETWORK_CONFIG,new_name,"proto","static");
					Uci_Set_Str(PKG_NETWORK_CONFIG,new_name,"ifname",ifname);
					Uci_Set_Str(PKG_NETWORK_CONFIG,new_name,"ipaddr",localVirtualIp);
					Uci_Set_Str(PKG_NETWORK_CONFIG,new_name,"netmask","255.255.255.0"); 

					Uci_Commit(PKG_NETWORK_CONFIG);
					
					snprintf(cmd,sizeof(cmd),"ifup %s",interface_t);
			
					CsteSystem(cmd, CSTE_PRINT_CMD);

				}

			}
		}
	}

}


OPERATIONS_BOOL CsRealWireguardConfig(int mode)
{

	set_lktos_effect("firewall");

	if(mode == 1){
		CsteSystem("ifdown wg1", CSTE_PRINT_CMD);
		CsteSystem("ifup wg1", CSTE_PRINT_CMD);
	}else{
		CsteSystem("ifdown wg0", CSTE_PRINT_CMD);
		CsteSystem("ifup wg0", CSTE_PRINT_CMD);
	}

	return OPERATIONS_TRUE;
}



OPERATIONS_BOOL CsRealReloadL2tpSecrets()
{
	int num=0, i=0, enable=0, type=0;
	char section[8]={0}, secret[33]={0}, tmp_buf[128]={0};
	char local_hostname[33]={0}, remote_hostname[33]={0};

	FILE *fp;

	num = get_cmd_val("uci show network | grep vpn | grep server= |  wc -l");
	if(num == 0)
		return;

	fp=fopen(L2TP_SECRETS_FILE, "w");
	if(!fp)
		return;

	fprintf(fp, "# Secrets for authenticating l2tp tunnels\n");
	fprintf(fp, "# us		them		secret\n");

	for(i=0;i<num;i++)
	{
		snprintf(section,sizeof(section)-1,"vpn%d",i);

		Uci_Get_Int(PKG_NETWORK_CONFIG, section, "enable", &enable);
		Uci_Get_Int(PKG_NETWORK_CONFIG, section, "type", &type);
		if(enable == 0 || type != 1)
			continue;

		Uci_Get_Str(PKG_NETWORK_CONFIG, section, "tunnelSecret", secret);
		if(strcmp(secret, "") == 0)
			continue;

		Uci_Get_Str(PKG_NETWORK_CONFIG, section, "tunnelLocalHostname", tmp_buf);
		if(strcmp(tmp_buf, "") == 0)
			strcpy(local_hostname, "*");
		else
			snprintf(local_hostname, sizeof(local_hostname)-1, "%s", tmp_buf);

		memset(tmp_buf, 0, sizeof(tmp_buf));
		Uci_Get_Str(PKG_NETWORK_CONFIG, section, "tunnelRemoteHostname", tmp_buf);
		if(strcmp(tmp_buf, "") == 0)
			strcpy(remote_hostname, "*");
		else
			snprintf(remote_hostname, sizeof(remote_hostname)-1, "%s", tmp_buf);

		memset(tmp_buf, 0, sizeof(tmp_buf));
		sprintf(tmp_buf, "%s %s %s",local_hostname, remote_hostname, secret);
		fprintf(fp, "%s\n", tmp_buf);

		memset(tmp_buf, 0, sizeof(tmp_buf));
		memset(local_hostname, 0, sizeof(local_hostname));
		memset(remote_hostname, 0, sizeof(remote_hostname));
	}

	fclose(fp);

	CsteSystem("/etc/init.d/xl2tpd restart", CSTE_PRINT_CMD);
}

