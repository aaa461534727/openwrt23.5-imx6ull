#include "../defs.h"
#include "../discover.h"
#define ETH_PORT_WAN 4
int uci_del_list_item_all(int title,char *section_name,char *keyword)
{
	int current_num = 0,i = 0,idx = 0,iDelCount = 0, idx_array[FILTER_RULE_NUM_MAX];
	char *value,cmd_buf[128] = {0},name_buf[16] = {0},section[64] = {0};

	snprintf(cmd_buf,sizeof(cmd_buf)-1,"uci show %s | grep %s | grep %s |  wc -l",PKG_ID_TOFILE(title),section_name,keyword);
	current_num = get_cmd_val(cmd_buf);

	for(i = 0; i < FILTER_RULE_NUM_MAX; i++) {
		idx_array[i] = -1;
	}
	
	for (i = 0; i < current_num; i++) {
		idx_array[iDelCount++] = i;
	}
	
	for(i = 0; i < iDelCount; i++) {
		idx = idx_array[i]-i;
		snprintf(section,sizeof(section)-1,"@%s[%d]",section_name,idx);
		cs_uci_force_refresh_context(PKG_NETWORK_CONFIG);
		Uci_Del_Section(title,section);
	}

	return current_num-iDelCount;
}

int uci_del_list_item(int title, char *section_name, char *keyword, json_object *request)
{
	int current_num = 0, i = 0, idx = 0, iDelCount = 0, idx_array[FILTER_RULE_NUM_MAX];
	char *value, cmd_buf[128] = { 0 }, name_buf[16] = { 0 }, section[64] = { 0 };

	snprintf(cmd_buf,sizeof(cmd_buf)-1, "uci show %s | grep %s | grep %s |  wc -l", PKG_ID_TOFILE(title), section_name, keyword);
	current_num = get_cmd_val(cmd_buf);

	for(i = 0; i < FILTER_RULE_NUM_MAX; i++)
	{
		idx_array[i] = -1;
	}

	for(i = 0; i < current_num; i++)
	{
		snprintf(name_buf, sizeof(name_buf)-1, "delRule%d", i);
		value = webs_get_string(request, name_buf);

		if(strcmp(value, "") != 0)
		{
			idx_array[iDelCount++] = atoi(value);
		}
	}

	for(i = 0; i < iDelCount; i++)
	{
		idx = idx_array[i]-i;
		snprintf(section,sizeof(section)-1, "@%s[%d]", section_name,idx);
		cs_uci_force_refresh_context(PKG_NETWORK_CONFIG);
		Uci_Del_Section(title, section);
	}

	return current_num-iDelCount;
}


CGI_BOOL getLanCfg(json_object *request, FILE *conn_fp)
{
	int dhcpignore = 0;
	char opmode[8] = {0},tmpBuf[32] = {0},lan_mode[16]={0},leasetime[16]={0};
	char lan_dns[128] = {0},lan_dns1[32] = {0},lan_dns2[32] = {0};
	struct sockaddr hwaddr;
	cJSON *root;

	struct interface_status status_paremeter;

	root = cJSON_CreateObject();

	get_wan_status(&status_paremeter);

	if(status_paremeter.up) {
		cJSON_AddStringToObject(root, "wanIp",      status_paremeter.ipaddr_v4);
		cJSON_AddStringToObject(root, "wanMask", status_paremeter.mask_v4);
	}
	else {
		cJSON_AddStringToObject(root, "wanIp", "0.0.0.0");
		cJSON_AddStringToObject(root, "wanMask", "0.0.0.0");
	}

	Uci_Get_Str(PKG_SYSTEM_CONFIG, "opmode", "opmode_custom",opmode);

	get_uci2json(root, PKG_NETWORK_CONFIG, "lan", "ipaddr",	 "ip");
	get_uci2json(root, PKG_NETWORK_CONFIG, "lan", "netmask", "mask");
	get_uci2json(root, PKG_DHCP_CONFIG, "lan", "start",	 	 "dhcpStart");
	get_uci2json(root, PKG_DHCP_CONFIG, "lan", "dhcp_e",	 "dhcpEnd");
	
	
	Uci_Get_Str(PKG_DHCP_CONFIG, "lan", "leasetime",leasetime);
	if(strcmp(leasetime,"infinite") == 0)
		cJSON_AddStringToObject(root,"dhcpLease","0");
	else
		cJSON_AddStringToObject(root,"dhcpLease",leasetime);
	

	Uci_Get_Int(PKG_DHCP_CONFIG,"lan","ignore",&dhcpignore);
	if (dhcpignore == 0)
		cJSON_AddStringToObject(root,"dhcpServer","1");
	else
		cJSON_AddStringToObject(root,"dhcpServer","0");

	Uci_Get_Str(PKG_NETWORK_CONFIG, "lan", "dns",lan_dns);
	get_nth_val_safe(0, lan_dns, ' ', lan_dns1, sizeof(lan_dns1));
	get_nth_val_safe(1, lan_dns, ' ', lan_dns2, sizeof(lan_dns2));
	cJSON_AddStringToObject(root, "priDns", lan_dns1);
	cJSON_AddStringToObject(root, "secDns", lan_dns2);


	memset(tmpBuf, '\0', sizeof(tmpBuf));
	getInAddr("br-lan", HW_ADDR_T, (void *)&hwaddr);
	memset(tmpBuf, '\0', sizeof(tmpBuf));
	sprintf(tmpBuf,	"%02X:%02X:%02X:%02X:%02X:%02X", hwaddr.sa_data[0],hwaddr.sa_data[1], \
		hwaddr.sa_data[2],hwaddr.sa_data[3],hwaddr.sa_data[4],hwaddr.sa_data[5]);
	//Uci_Get_Str(PKG_NETWORK_CONFIG, "lan_dev", "macaddr", tmpBuf);
	cJSON_AddStringToObject(root, "mac", tmpBuf);	
	
	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}


CGI_BOOL setLanCfg(json_object *request, FILE *conn_fp)
{
	int limit = 0, leasetime, is_lan_change=0;
	char opmode[8] = { 0 }, tmp_buf[128], lanDns[128] = { 0 };
	char original_lan_ipaddr[18] = { 0 }, original_lan_netmask[18] = { 0 };

	struct in_addr ipaddr_orig,  ipaddr_new;
	struct in_addr netmask_orig, netmask_new;

	char *lanIp  = webs_get_string(request, "ip");
	char *lanNetmask = webs_get_string(request, "mask");

	char *dhcpServer = webs_get_string(request, "dhcpServer");
	char *dhcpStart  = webs_get_string(request, "dhcpStart");
	char *dhcpEnd    = webs_get_string(request, "dhcpEnd");
	char *dhcpLease  = webs_get_string(request, "dhcpLease");
	char *lanDns1    = webs_get_string(request, "priDns");
	char *lanDns2    = webs_get_string(request, "secDns");
		
	Uci_Get_Str(PKG_NETWORK_CONFIG, "lan", "ipaddr",  original_lan_ipaddr);
	Uci_Get_Str(PKG_NETWORK_CONFIG, "lan", "netmask", original_lan_netmask);
	Uci_Set_Str(PKG_NETWORK_CONFIG, "lan", "ipaddr",  lanIp);
	Uci_Set_Str(PKG_NETWORK_CONFIG, "lan", "netmask", lanNetmask);
	Uci_Set_Str(PKG_NETWORK_CONFIG, "usb0", "gateway", lanIp);

	Uci_Get_Str(PKG_SYSTEM_CONFIG, "opmode", "opmode_custom",opmode);

	if(is_ip_valid(lanDns1))
	{
		strcpy(lanDns,lanDns1);

		if(is_ip_valid(lanDns2))
		{
			strcat(lanDns," ");
			strcat(lanDns,lanDns2);
		}
	}
	Uci_Set_Str(PKG_NETWORK_CONFIG, "lan", "dns", lanDns);
		
	if(atoi(dhcpServer) == 0)
	{
		Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "ignore", "1");
	}
	else
	{
		Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "ignore", "0");
	}

	leasetime = atoi(dhcpLease);

	if(leasetime == 0)
	{
		Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "leasetime", "infinite");
	}
	else 
	{
		Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "leasetime", dhcpLease);
	}

	if(is_ip_valid(dhcpStart))
	{
		Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "start",  dhcpStart);
	}
	else
	{
		goto end_label;
	}

	if(is_ip_valid(dhcpEnd))
	{
		Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "dhcp_e", dhcpEnd);
	}
	else
	{
		goto end_label;
	}

	memset(tmp_buf, 0, sizeof(tmp_buf));
	limit = ntohl(inet_addr(dhcpEnd)) - ntohl(inet_addr(dhcpStart)) + 1;

	if(limit > 0)
	{
		sprintf(tmp_buf, "%d", limit);
		Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "limit", tmp_buf);
	}

	ipaddr_orig.s_addr = inet_addr(original_lan_ipaddr);
	netmask_orig.s_addr = inet_addr(original_lan_netmask);

	ipaddr_new.s_addr  = inet_addr(lanIp);
	netmask_new.s_addr = inet_addr(lanNetmask);

	/* Updated the static IP address set on the LAN */
	if((ipaddr_orig.s_addr & netmask_orig.s_addr) != (ipaddr_new.s_addr & netmask_new.s_addr))
	{
		is_lan_change=1;
		datconf_set_by_key(TEMP_STATUS_FILE, "lan_change", "1");
		check_static_dhcp_ip(ipaddr_new, netmask_new);
	}


end_label:

	Uci_Commit(PKG_DHCP_CONFIG);
	Uci_Commit(PKG_NETWORK_CONFIG);
	doSystem("echo disconnect > /sys/class/udc/fe500000.dwc3/soft_connect");
	doSystem("/etc/init.d/network restart");
	sleep(1);
	doSystem("echo connect > /sys/class/udc/fe500000.dwc3/soft_connect");
	if(is_lan_change==1){
		send_cgi_set_respond(conn_fp, TRUE_W, "", lanIp, "30", "reLogin");
	}else{
		send_cgi_set_respond(conn_fp, TRUE_W, "", lanIp, "15", "reLogin");
	}

	return CGI_TRUE;
}

CGI_BOOL getStationMacByIp(json_object *request, FILE *conn_fp)
{
	char ipaddr[16]={0}, macaddr[18]={0};

	cJSON *root;

    root=cJSON_CreateObject();

	datconf_get_by_key(TEMP_STATUS_FILE, "login_ip", ipaddr,sizeof(ipaddr));

	get_sta_mac_byip(ipaddr,macaddr);

	cJSON_AddStringToObject(root,"stationMac",macaddr);

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}

CGI_BOOL getWanCfg(json_object *request, FILE *conn_fp)
{
	cJSON *root;
	char tmp_buf[16]={0}, mac[18]={0};
	char wan_mode[8] = {0}, opmode_custom[8] = {0},vpn_dhcp[8] = {0};

	char wan_section[16] = {0}, wan_dns[OPTION_STR_LEN]={0}, buff1[OPTION_STR_LEN]={0}, buff2[OPTION_STR_LEN]={0};
	
	int ttl_way_support, dns_mode = 0;

	struct interface_status status_paremeter;

	Uci_Get_Str(PKG_SYSTEM_CONFIG, "opmode", "opmode_custom",opmode_custom);

	if(0 == strcmp(opmode_custom, "wisp")){
		strcpy(wan_section,"wwan");
	}else{
		strcpy(wan_section,IFACE_WIRE_WAN);
	}

	root = cJSON_CreateObject();

	Uci_Get_Str(PKG_NETWORK_CONFIG, wan_section, "proto", wan_mode);
	
	cJSON_AddNumberToObject(root, "wanMode", get_wan_mode(wan_mode));

	get_uci2json(root, PKG_SYSTEM_CONFIG, "main", "hostname","hostName");

	//status
	get_wan_status(&status_paremeter);
	if((0 == strcmp(opmode_custom, "gw") && is_phyport_connected(ETH_PORT_WAN)) || 0 == strcmp(opmode_custom, "wisp") ) {
		if(status_paremeter.up) {
			cJSON_AddStringToObject(root, "wanConnStatus", "connected");
		} else {
			cJSON_AddStringToObject(root, "wanConnStatus", "disconnected");
		}
	}

	//static
	get_uci2json(root, PKG_NETWORK_CONFIG, wan_section, "ipaddr",  "staticIp");
	get_uci2json(root, PKG_NETWORK_CONFIG, wan_section, "netmask", "staticMask");
	get_uci2json(root, PKG_NETWORK_CONFIG, wan_section, "gateway", "staticGw");

	Uci_Get_Str(PKG_NETWORK_CONFIG, wan_section, "mtu", tmp_buf);
	if(strlen(tmp_buf) <= 0)
		cJSON_AddStringToObject(root, "dhcpMtu", "1500");
	else
		cJSON_AddStringToObject(root, "dhcpMtu", tmp_buf);
	
	get_uci2json(root, PKG_NETWORK_CONFIG, wan_section, "smtu",	 "staticMtu");

	//pppoe
	if(0 == strcmp(wan_mode, "pppoe")) {
		get_uci2json(root, PKG_NETWORK_CONFIG, wan_section, "username","pppoeUser");
		get_uci2json(root, PKG_NETWORK_CONFIG, wan_section, "password","pppoePass");
	}
	get_uci2json(root, PKG_NETWORK_CONFIG, wan_section, "pmtu",		 "pppoeMtu");

	memset(tmp_buf, 0, sizeof(tmp_buf));
	Uci_Get_Str(PKG_NETWORK_CONFIG, wan_section, "peerdns", tmp_buf);
	if(strlen(tmp_buf) <= 0)
	{
		cJSON_AddStringToObject(root, "dnsMode", "0");
	}
	else
	{
		dns_mode = atoi(tmp_buf);
		if(dns_mode == 0) { //Manual
			cJSON_AddStringToObject(root, "dnsMode", "1");
		} else if(dns_mode == 1) { //auto
			cJSON_AddStringToObject(root, "dnsMode", "0");
		} else {
			cJSON_AddStringToObject(root, "dnsMode", "2");
		}
	}
	
	if(dns_mode == 0)
	{
		Uci_Get_Str(PKG_NETWORK_CONFIG, wan_section, "dns",wan_dns);

		get_nth_val_safe(0, wan_dns, ' ', buff1, sizeof(buff1));
		get_nth_val_safe(1, wan_dns, ' ', buff2, sizeof(buff2));

		cJSON_AddStringToObject(root, "priDns", buff1);
		if(strlen(buff2) > 0)
			cJSON_AddStringToObject(root, "secDns", buff2);
		else
			cJSON_AddStringToObject(root, "secDns", "");
	}
	else
	{
		if(strlen(status_paremeter.pri_dns_v4) > 0){
			cJSON_AddStringToObject(root, "priDns", status_paremeter.pri_dns_v4);
			cJSON_AddStringToObject(root, "secDns", status_paremeter.sec_dns_v4);
		}else{
			cJSON_AddStringToObject(root, "priDns", "");
			cJSON_AddStringToObject(root, "secDns", "");
		}
	}

	memset(tmp_buf, 0, sizeof(tmp_buf));
	Uci_Get_Str(PKG_NETWORK_CONFIG, wan_section, "device", tmp_buf);
	get_ifname_macaddr(tmp_buf,  mac);
	cJSON_AddStringToObject(root, "wanDefMac", mac);
	cJSON_AddStringToObject(root, "macCloneMac", mac);
		
	get_num_uci2json(root, PKG_NETWORK_CONFIG, IFACE_WIRE_WAN, "mac_clone", "macCloneEnabled");
	//get_uci2json(root, PKG_NETWORK_CONFIG,     IFACE_WIRE_WAN, "macaddr",    "macCloneMac");

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}


CGI_BOOL setManualDialCfg(json_object *request, FILE *conn_fp)
{

	char proto[32]={0};
	char *dialStatus = webs_get_string(request, "dialStatus");

	Uci_Get_Str(PKG_NETWORK_CONFIG, "wan", "proto", proto);

	if(strcmp(proto,"pppoe") == 0)
	{
		if(atoi(dialStatus) == 0) 
		{
			doSystem("ifdown wan");
		} 
		else if(atoi(dialStatus) == 1) 
		{
			doSystem("ifup wan");
		}
	}

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "10", "reserv");
	
	return CGI_TRUE;
}

CGI_BOOL setWanCfg(json_object *request, FILE *conn_fp)
{
	int  wan_mode, switch_opmode;

	char *ptr, *opmode_custom;

	char *dns_mode, *pri_dns, *sec_dns, *hostname, *mtu, *mppe, *mppc;
	char *ip, *mask, *gw;
	char *user, *pass, *server_ip, *server_domain, *domain_flag, *is_static_mode;
	char *spectype, *servicename, *acname;

	char  wan_section[16],dnsbuf[64] = {0},opmode[16] = {0};
	char tmp_buf[24]={0};

	ptr=webs_get_string(request, "wanMode");
	wan_mode = atoi(ptr);

	opmode_custom = webs_get_string(request, "opmode");
	if(strlen(opmode_custom)==0){
		Uci_Get_Str(PKG_SYSTEM_CONFIG, "opmode", "opmode_custom",opmode);
		if(0 == strcmp(opmode, "gw")){
			strcpy(wan_section,"wan");
		}else{
			strcpy(wan_section,"wan_modem");
		}
	}
	else{
		if(0 == strcmp(opmode_custom, "wisp")){
			strcpy(wan_section,"wwan");
		}else{
			strcpy(wan_section, IFACE_WIRE_WAN);
		}
	}

	if(wan_mode == DHCP_DISABLED) {
		ip   = webs_get_string(request, "staticIp");
		mask = webs_get_string(request, "staticMask");
		gw   = webs_get_string(request, "staticGw");
		mtu  = webs_get_string(request, "staticMtu");

		Uci_Set_Str(PKG_NETWORK_CONFIG, wan_section, "proto", "static");
		Uci_Set_Str(PKG_NETWORK_CONFIG, wan_section, "proto_backup", "static");
		Uci_Set_Str(PKG_NETWORK_CONFIG, "vpn", "proto", "");

		if(is_ip_valid(ip)){
			Uci_Set_Str(PKG_NETWORK_CONFIG, wan_section, "ipaddr", ip);
		}
		if(is_netmask_valid(mask)){
			Uci_Set_Str(PKG_NETWORK_CONFIG, wan_section, "netmask", mask);
		}
		if(is_ip_valid(gw)){
			Uci_Set_Str(PKG_NETWORK_CONFIG, wan_section, "gateway", gw);
		}
		if(atoi(mtu)>=576 && atoi(mtu)<=1500){
			Uci_Set_Str(PKG_NETWORK_CONFIG, wan_section, "smtu", mtu);
			Uci_Set_Str(PKG_NETWORK_CONFIG, wan_section, "mtu", mtu);
		}
		Uci_Set_Str(PKG_NETWORK_CONFIG, "wan", "ttl_way", "0");
	} 
	else if(wan_mode == PPPOE) 
	{
		user        = webs_get_string(request, "pppoeUser");
		pass        = webs_get_string(request, "pppoePass");
		mtu         = webs_get_string(request, "pppoeMtu");

		Uci_Set_Str(PKG_NETWORK_CONFIG, wan_section, "proto", "pppoe");
		Uci_Set_Str(PKG_NETWORK_CONFIG, wan_section, "proto_backup", "pppoe");
		Uci_Set_Str(PKG_NETWORK_CONFIG, "vpn", "proto", "");

		if(atoi(mtu)>=576 && atoi(mtu)<=1492){
			Uci_Set_Str(PKG_NETWORK_CONFIG, wan_section, "pmtu", mtu);
		}
		Uci_Set_Str(PKG_NETWORK_CONFIG, wan_section, "mtu", "1500");

		Uci_Set_Str(PKG_NETWORK_CONFIG, wan_section, "username", user);
		Uci_Set_Str(PKG_NETWORK_CONFIG, wan_section, "password", pass);
		Uci_Set_Str(PKG_NETWORK_CONFIG, "wan", "ttl_way", "1");
	}
	else 
	{
		mtu      = webs_get_string(request, "dhcpMtu");

		Uci_Set_Str(PKG_NETWORK_CONFIG, wan_section, "proto", "dhcp");
		Uci_Set_Str(PKG_NETWORK_CONFIG, wan_section, "proto_backup", "dhcp");
		Uci_Set_Str(PKG_NETWORK_CONFIG, "vpn", "proto", "");

		if(atoi(mtu)>=576 && atoi(mtu)<=1500){
			Uci_Set_Str(PKG_NETWORK_CONFIG, wan_section, "dmtu", mtu);
			Uci_Set_Str(PKG_NETWORK_CONFIG, wan_section, "mtu", mtu);
		}
		Uci_Set_Str(PKG_NETWORK_CONFIG, "wan", "ttl_way", "0");
	}

	dns_mode = webs_get_string(request, "dnsMode");
	if(atoi(dns_mode) == 1) {//1-Manual
		pri_dns   = webs_get_string(request, "priDns");
		sec_dns   = webs_get_string(request, "secDns");

		if(is_ip_valid(pri_dns)){
			strcpy(dnsbuf,pri_dns);
			if(is_ip_valid(sec_dns)){
				strcat(dnsbuf," ");
				strcat(dnsbuf,sec_dns);
			}
		}
		Uci_Set_Str(PKG_NETWORK_CONFIG, wan_section, "peerdns", "0");
		Uci_Set_Str(PKG_NETWORK_CONFIG, wan_section, "dns", dnsbuf);
	}
	else if(!strcmp(dns_mode, "0")) {//0-auto
		Uci_Set_Str(PKG_NETWORK_CONFIG, wan_section, "peerdns", "1");
		Uci_Set_Str(PKG_NETWORK_CONFIG, wan_section, "dns", "");
	}
	else if(!strcmp(dns_mode, "2")) {//2-Penetrate
		Uci_Set_Str(PKG_NETWORK_CONFIG, wan_section, "peerdns", "2");
		Uci_Set_Str(PKG_NETWORK_CONFIG, wan_section, "dns", "");
	}

	ptr = webs_get_string(request, "macCloneEnabled");
	if(atoi(ptr)) {
		Uci_Set_Str(PKG_NETWORK_CONFIG, IFACE_WIRE_WAN, "mac_clone", "1");
		ptr = webs_get_string(request, "macCloneMac");
		if(is_mac_valid(ptr)){
			Uci_Set_Str(PKG_NETWORK_CONFIG, IFACE_WIRE_WAN, "macaddr", ptr);
		}
	}
	else {
		Uci_Set_Str(PKG_NETWORK_CONFIG, IFACE_WIRE_WAN, "mac_clone", "0");
		Uci_Get_Str(PKG_NETWORK_CONFIG, IFACE_WIRE_WAN, "defmacaddr", tmp_buf);		
		if(strcmp(tmp_buf, "") == 0){
			get_cmd_result("cs mac r wan  |awk '{print $2}'", tmp_buf, sizeof(tmp_buf));
			if(!is_mac_valid(tmp_buf)){
				memset(tmp_buf, 0, sizeof(tmp_buf));
			}
		}
		
		Uci_Set_Str(PKG_NETWORK_CONFIG, IFACE_WIRE_WAN, "macaddr", tmp_buf);
	}

	

	Uci_Commit(PKG_SYSTEM_CONFIG);

	Uci_Commit(PKG_NETWORK_CONFIG);

	set_lktos_effect("network");

	if(wan_mode == PPPOE || wan_mode == PPTP || wan_mode == L2TP) 		
		send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "25", "reLogin");
	else
		send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "15", "reLogin");

	return CGI_TRUE;
}

CGI_BOOL getRouteTableInfo(json_object *request, FILE *conn_fp)
{
	cJSON *connArray,*connEntry = NULL;;
	connArray = cJSON_CreateArray();
	const char *respond = NULL;
	char buff[256];
	int  nl = 0 ;
	struct in_addr dest;
	struct in_addr gw;
	struct in_addr mask;
	int flgs, ref, use, metric;
	unsigned long int d, g, m;
	char sdest[16], sgw[16];
	FILE *fp;
	
	int iRulesNum = 0, idx = 0;
	char paramName[OPTION_STR_LEN]={0}, tmpBuf[TEMP_STR_LEN]={0},portRange[TEMP_STR_LEN]={0};;
	char *ptr;
	
	/* route */
	if (!(fp = fopen("/proc/net/route", "r"))) return 0;
	while (fgets(buff, sizeof(buff), fp) != NULL) {
			if (nl) {
					int ifl = 0;
					connEntry = cJSON_CreateObject();
	
					while (buff[ifl] != ' ' && buff[ifl] != '\t' && buff[ifl] != '\0')
							ifl++;
	
					buff[ifl] = 0;	/* interface */
	
					if (sscanf(buff + ifl + 1, "%lx%lx%d%d%d%d%lx",
							   &d, &g, &flgs, &ref, &use, &metric, &m) != 7) {
							//error_msg_and_die( "Unsuported kernel route format\n");
							//continue;
					}
	
					dest.s_addr = d;
					gw.s_addr		= g;
					mask.s_addr = m;
					strcpy(sdest, (dest.s_addr == 0 ? "default" : inet_ntoa(dest)));
					strcpy(sgw, (gw.s_addr == 0 ? "*" : inet_ntoa(gw)));
	
					cJSON_AddNumberToObject(connEntry, "idx", nl);
					cJSON_AddStringToObject(connEntry, "routeType", "0");//fixme :"0"静态路由；"1"策略路由
					cJSON_AddStringToObject(connEntry, "interface", buff);
					cJSON_AddStringToObject(connEntry, "network", sdest);
					cJSON_AddStringToObject(connEntry, "subnetMask", inet_ntoa(mask));
					cJSON_AddStringToObject(connEntry, "gateway", sgw);
					cJSON_AddNumberToObject(connEntry, "metric", metric);
					cJSON_AddItemToArray(connArray, connEntry);
			}
	
			nl++;
	}
	
	
	
	send_cgi_json_respond(conn_fp, connArray);
	return CGI_TRUE;
}

CGI_BOOL getStaticRoute(json_object *request, FILE *conn_fp)
{
	char *output =NULL;
	char section[OPTION_STR_LEN]={0},iface[SMALL_STR_LEN]={0},index[OPTION_STR_LEN]={0};
	char responseStr[2048]={0}, tmpBuf[32]={0};
	int num=0,i=0; 

	cJSON *root,*connArray, *item;

	root = cJSON_CreateObject();
	connArray = cJSON_CreateArray();
	cJSON_AddItemToObject(root, "rule", connArray);

	cJSON_AddStringToObject(root, "interface", "LAN,WAN");

	doSystem("ip route > /tmp/ipRoute");

	f_read("/tmp/ipRoute", responseStr,sizeof(responseStr));
	cJSON_AddStringToObject(root, "ipRouteLog", responseStr);
	
	//get_uci2json(root,PKG_CSFW_CONFIG,"staticroute","enable","enable");

	num = get_cmd_val("uci show network | grep route | grep target= |  wc -l");
	int old_tactics_route=0;
	Uci_Get_Int(PKG_WAN_MODEM_CONFIG, "main", "tactics_route", &old_tactics_route);
	if(old_tactics_route==1)
		num--;
	
	for(i=0;i<num;i++)
	{
		memset(iface,0,sizeof(iface));
		snprintf(section,OPTION_STR_LEN,"@route[%d]",i);

		Uci_Get_Str(PKG_NETWORK_CONFIG,section,"interface",iface);
		if ( 0 == strlen(iface) )
			continue;

		item = cJSON_CreateObject();
		
		memset(tmpBuf, 0, sizeof(tmpBuf));
		if(strcmp(iface, "lan") == 0)
			strcpy(tmpBuf, "LAN");
		else
			strcpy(tmpBuf, "WAN");
		cJSON_AddStringToObject(item, "iface", tmpBuf);	
		
				get_uci2json(item,PKG_NETWORK_CONFIG,section,"metric","metric");
		get_uci2json(item,PKG_NETWORK_CONFIG,section,"target","ip");
		get_uci2json(item,PKG_NETWORK_CONFIG,section,"netmask","mask");
		get_uci2json(item,PKG_NETWORK_CONFIG,section,"gateway","gw");
		get_uci2json(item,PKG_NETWORK_CONFIG,section,"comment","desc");

		snprintf(index,OPTION_STR_LEN,"%d",i+1);
		cJSON_AddStringToObject(item, "idx", index);

		cJSON_AddItemToArray(connArray,item);
	}

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}

CGI_BOOL setStaticRoute(json_object *request, FILE *conn_fp)
{
	int num=0,i = 0,addEffect = 0;
	char *ip, *gw, *mask, *metric, *iface, *desc;
	char tmpBuf[32]={0};
	char section[OPTION_STR_LEN] = {0};
	struct array_list *subArry;
	
	addEffect = atoi(webs_get_string(request, "addEffect"));
	num = get_cmd_val("uci show network | grep route | grep target= |  wc -l");

	if(num > 0){
		uci_del_list_item_all(PKG_NETWORK_CONFIG,"route","target=");
	}

	num=0;
	json_object_object_foreach(request, key, val) {
		if (strcmp(key, "subnet") == 0) {

			subArry = json_object_get_array(val);
			num = json_object_array_length(val);
						
			for(i = 0; i < num; i++) {
				struct json_object *object_x = (struct json_object *)array_list_get_idx(subArry, i);

				ip=webs_get_string(object_x, "ip");
				gw=webs_get_string(object_x, "gw");
				mask=webs_get_string(object_x, "mask");
				metric=webs_get_string(object_x, "metric");
				iface=webs_get_string(object_x, "iface");
				desc=webs_get_string(object_x, "desc");
				
				Uci_Add_Section(PKG_NETWORK_CONFIG,"route");
				memset(section,0,sizeof(section));
				snprintf(section,sizeof(section)-1,"@route[%d]",i);

				if(strcmp(iface, "LAN") == 0)
					strcpy(tmpBuf, "lan");
				else if(strcmp(iface, "WAN") == 0)
					strcpy(tmpBuf, "wan");
				else
					strcpy(tmpBuf, IFACE_3GPP_WAN);
				Uci_Set_Str(PKG_NETWORK_CONFIG,section,"interface",tmpBuf);
				
				Uci_Set_Str(PKG_NETWORK_CONFIG,section,"target",ip);
				Uci_Set_Str(PKG_NETWORK_CONFIG,section,"gateway",gw);
				Uci_Set_Str(PKG_NETWORK_CONFIG,section,"metric",metric);
				Uci_Set_Str(PKG_NETWORK_CONFIG,section,"netmask",mask);
				Uci_Set_Str(PKG_NETWORK_CONFIG,section,"comment",desc);
				
			}
			break;
		}
	}	

	Uci_Commit(PKG_NETWORK_CONFIG);
	set_lktos_effect("network");
	set_lktos_effect("static_route");
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "30", "reserv");

	return CGI_TRUE;
}

CGI_BOOL delStaticRoute(json_object *request, FILE *conn_fp)
{
	uci_del_list_item(PKG_NETWORK_CONFIG,"route","target=",request);
	Uci_Commit(PKG_NETWORK_CONFIG);
	set_lktos_effect("network");

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "30", "reserv");

	return 0;
}

#if defined(USE_IPV6)
static int get_prefix6_len(struct sockaddr_in6 *mask6)
{
	int i, j, prefix = 0;
	unsigned char *netmask = (unsigned char *) &(mask6)->sin6_addr;

	for (i = 0; i < 16; i++, prefix += 8)
		if (netmask[i] != 0xff)
			break;

	if (i != 16 && netmask[i])
		for (j = 7; j > 0; j--, prefix++)
			if ((netmask[i] & (1 << j)) == 0)
				break;

	return prefix;
}

char *get_ifaddr6(const char *ifname, int linklocal, char *p_addr6s)
{
	char *ret = NULL;
	int prefix;
	struct ifaddrs *ifap, *ife;
	const struct sockaddr_in6 *addr6;
	char addr6s_new[INET6_ADDRSTRLEN] = {0};

	if (getifaddrs(&ifap) < 0)
		return NULL;

	for (ife = ifap; ife; ife = ife->ifa_next)
	{
		if (strcmp(ifname, ife->ifa_name) != 0)
			continue;
		if (ife->ifa_addr == NULL)
			continue;
		if (ife->ifa_addr->sa_family == AF_INET6)
		{
			addr6 = (const struct sockaddr_in6 *)ife->ifa_addr;
			if (IN6_IS_ADDR_LINKLOCAL(&addr6->sin6_addr) ^ linklocal)
				continue;
			if (inet_ntop(ife->ifa_addr->sa_family, &addr6->sin6_addr, addr6s_new, INET6_ADDRSTRLEN) != NULL) {
				prefix = get_prefix6_len((struct sockaddr_in6 *)ife->ifa_netmask);
				if (prefix > 0 && prefix < 128)
					sprintf(p_addr6s, "%s/%d", addr6s_new, prefix);
				ret = p_addr6s;
				break;
			}
		}
	}
	freeifaddrs(ifap);
	return ret;
}

static void get_ipv6_status(cJSON *root, char *ifname)
{
	cJSON *rootObj;
	char tmpBuf[128]={0}, protoV6[8]={0}, p_json[LONGLONG_BUFF_LEN];
	char wan6GlobalIp[128], wan6Gw[128];
	char *wan6dns = NULL;
	int ret=0, i;
	char if_str[32]={0};

	sprintf(if_str, "network.interface.%s", ifname);
	
	Uci_Get_Str(PKG_NETWORK_CONFIG, ifname, "proto", tmpBuf);
	if(strcmp(tmpBuf, "pppoe") == 0)
		cJSON_AddStringToObject(root, "ipv6WanLinkType",  "ppp");
	else
		cJSON_AddStringToObject(root, "ipv6WanLinkType",  "dhcp6");

	Uci_Get_Str(PKG_NETWORK_CONFIG, ifname, "proto", protoV6);
	cJSON_AddStringToObject(root, "ipv6WanOriginType", protoV6);

	memset(p_json,0,sizeof(p_json));
	ret = cs_ubus_cli_call(if_str, "status",p_json);

	if(strcmp(protoV6, "static") == 0){
		memset(tmpBuf, 0, sizeof(tmpBuf));
		get_ifaddr6(WAN_IFNAME, 0, tmpBuf);
		cJSON_AddStringToObject(root, "ipv6WanGlobalAddree", tmpBuf);
	}else if(strcmp(protoV6, "dhcpv6") == 0){
		if(!ret){
			rootObj = cJSON_Parse(p_json);
			if(rootObj){
				cJSON *ipv6Obj = cJSON_GetObjectItem(rootObj, "ipv6-address");
				cJSON *ipv6dnsObj = cJSON_GetObjectItem(rootObj, "dns-server");
				if(ipv6Obj) {
					int arrayLen=cJSON_GetArraySize(ipv6Obj);
					if(arrayLen>0){
						i = arrayLen-1;
						cJSON *tmpObj = cJSON_GetArrayItem(ipv6Obj,i);
						memset(wan6GlobalIp, 0, sizeof(wan6GlobalIp));
						get_cjson_string(tmpObj, "address", wan6GlobalIp, sizeof(wan6GlobalIp));	
					}
				} 						
				if(ipv6dnsObj) {
					int arrayLen=cJSON_GetArraySize(ipv6dnsObj);
					for(i=0; i<arrayLen; i++){
						cJSON *tmpObj = cJSON_GetArrayItem(ipv6dnsObj,i);
						wan6dns = tmpObj->valuestring?:"::";
					}
				}
			}
			cJSON_AddStringToObject(root, "ipv6Wan4gGlobalAddree", wan6GlobalIp?wan6GlobalIp:"");
			cJSON_AddStringToObject(root,"ipv6Wan4gDns", wan6dns?wan6dns:"");
		}

	}

	if(!ret){
		if(rootObj) {
			cJSON *ipv6routeObj = cJSON_GetObjectItem(rootObj, "route");
			if(ipv6routeObj) {
				int arrayLen=cJSON_GetArraySize(ipv6routeObj);
				if(arrayLen > 0){
					i=arrayLen-1;
					cJSON *tmpObj = cJSON_GetArrayItem(ipv6routeObj,i);
					memset(wan6Gw, 0, sizeof(wan6Gw));
					get_cjson_string(tmpObj, "nexthop", wan6Gw, sizeof(wan6Gw));
				}
			}
			cJSON_Delete(rootObj);
		}
		cJSON_AddStringToObject(root, "ipv6WanGw", wan6Gw?wan6Gw:"");
	}
	
}

CGI_BOOL getIPv6Status(json_object *request, FILE *conn_fp)
{
	cJSON *root;
	int intVal=0;
	char tmpBuf[128]={0};

	int ret = 0;
	char data_json[2048]={0},modem_dns[256]={0};
	char ipv6Dns[256]={0},ipv6Dns_1[256]={0},modem_gw[256]={0},ipv6_gw[128]={0};
	cJSON*data_root;

	root = cJSON_CreateObject();

	//4G
	Uci_Get_Int(PKG_NETWORK_CONFIG, "wan60", "disabled", &intVal);
	if(intVal){
		cJSON_AddStringToObject(root, "ipv6Wan4gGlobalAddree", "");
		cJSON_AddStringToObject(root, "ipv6Wan4gLinkAddree", "");
		cJSON_AddStringToObject(root, "ipv6WanGlobalAddree", "");
		cJSON_AddStringToObject(root, "ipv6WanLinkAddree", "");
		cJSON_AddStringToObject(root, "ipv6WanLinkType",  "off");
		cJSON_AddStringToObject(root, "ipv6WanOriginType", "off");
		
		cJSON_AddStringToObject(root, "ipv6WanGlobalAddree", "");
		cJSON_AddStringToObject(root, "ipv6WanLinkAddree", "");
		cJSON_AddStringToObject(root, "ipv6WanGw", "");
		cJSON_AddStringToObject(root, "ipv6WanDns", "");
		
		cJSON_AddStringToObject(root, "ipv6LanGlobalAddree", "");
		cJSON_AddStringToObject(root, "ipv6LanLinkAddree", "");
		cJSON_AddStringToObject(root, "ipv6LanGw", "");
	}else{
		get_ipv6_status(root, "wan60");
		//wan LinkAddress
		memset(tmpBuf, 0, sizeof(tmpBuf));
		get_ifaddr6(WAN_IFNAME, 1, tmpBuf);
		cJSON_AddStringToObject(root, "ipv6WanLinkAddree", tmpBuf);
		
		memset(tmpBuf, 0, sizeof(tmpBuf));
		get_ifaddr6(LAN_DEV_NAME, 0, tmpBuf);
		cJSON_AddStringToObject(root, "ipv6LanGlobalAddree", tmpBuf);
		memset(tmpBuf, 0, sizeof(tmpBuf));
		get_ifaddr6(LAN_DEV_NAME, 1, tmpBuf);
		cJSON_AddStringToObject(root, "ipv6LanLinkAddree", tmpBuf);
		cJSON_AddStringToObject(root, "ipv6LanGw", tmpBuf);

		//4G LinkAddress
		memset(tmpBuf, 0, sizeof(tmpBuf));
		//get_ifaddr6(MODEM_IF_NAME, 0, tmpBuf);
		cJSON_AddStringToObject(root, "ipv6Wan4gGlobalAddree", tmpBuf);
		
		memset(tmpBuf, 0, sizeof(tmpBuf));
		//get_ifaddr6(MODEM_IF_NAME, 1, tmpBuf);
		cJSON_AddStringToObject(root, "ipv6Wan4gLinkAddree", tmpBuf);
		
		ret = cs_ubus_cli_call("urild", "data_call_list",data_json);
		if(ret != -1){
			data_root = cJSON_Parse(data_json);
			cJSON *data_call_root = cJSON_GetObjectItem(data_root,"data_calls");
			if(data_call_root != NULL){
				int arrayLen=cJSON_GetArraySize(data_call_root);
				if(arrayLen>0){
					cJSON *tmpObj = cJSON_GetArrayItem(data_call_root,0);
					get_cjson_string(tmpObj, "dnses", modem_dns, sizeof(modem_dns));
					get_cjson_string(tmpObj, "gateways", modem_gw, sizeof(modem_gw));
					
					getNthValueSafe(2, modem_dns, ' ', ipv6Dns, sizeof(ipv6Dns));
//					getNthValueSafe(3, modem_dns, ' ', ipv6Dns_1, sizeof(ipv6Dns_1));
//					strcat(ipv6Dns,ipv6Dns_1);
					cJSON_AddStringToObject(root, "ipv6WanDns", ipv6Dns);

					getNthValueSafe(1, modem_gw, ' ', ipv6_gw, sizeof(ipv6_gw));
					cJSON_AddStringToObject(root, "ipv6WanGw",ipv6_gw);
				}
			}
			cJSON_Delete(data_root);
		}
	}
	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}

CGI_BOOL getIpv6Cfg(json_object *request, FILE *conn_fp)
{
	int disable;
	char service[SHORT_STR_LEN] = {0},wanMode[SHORT_STR_LEN] = {0},buff[LIST_STR_LEN] = {0};
	char wanAddrs[TEMP_STR_LEN] = {0},lanAddrs[TEMP_STR_LEN] = {0};
	char wanAddr[OPTION_STR_LEN] = {0}, wanGate[OPTION_STR_LEN] = {0},lanAddr[OPTION_STR_LEN] = {0};
	char wanSize[SHORT_STR_LEN] = {0}, lanSize[SHORT_STR_LEN] = {0};

	char wanDhcp[SHORT_STR_LEN] = {0}, wanPriv[SHORT_STR_LEN] = {0};

	char wanDns[CMD_STR_LEN] = {0};
	char dns1[OPTION_STR_LEN] = {0},dns2[OPTION_STR_LEN] = {0},dns3[OPTION_STR_LEN] = {0};

	char lanRadvFake[SHORT_STR_LEN] = {0}, dhcpV6[SHORT_STR_LEN] = {0}, dhcpV6Type[SHORT_STR_LEN] = {0};
	char lanDns[OPTION_STR_LEN] = {0};

	cJSON *root = cJSON_CreateObject();

	Uci_Get_Int(PKG_NETWORK_CONFIG, "wan60", "disabled", &disable);
	Uci_Get_Str(PKG_NETWORK_CONFIG, "wan60", "proto", service);
	Uci_Get_Str(PKG_NETWORK_CONFIG, "wan",  "proto", wanMode);
	if(disable){
		cJSON_AddStringToObject(root, "service", "off");
	}
	else {
		if(!strcmp(service,"dhcpv6") && !strcmp(wanMode,"pppoe"))
			cJSON_AddStringToObject(root, "service", "pppoe6");
		else if(!strcmp(service,"dhcpv6"))
			cJSON_AddStringToObject(root, "service", "dhcp6");
		else
			cJSON_AddStringToObject(root, "service", "static");
	}
	
	if(!strcmp(service, "static")) { //static
		Uci_Get_Str(PKG_NETWORK_CONFIG, "wan60", "ip6addr", wanAddrs);
		Uci_Get_Str(PKG_NETWORK_CONFIG, "wan60", "ip6gw", wanGate);
		Uci_Get_Str(PKG_NETWORK_CONFIG, "wan60", "ip6prefix", lanAddrs);

		if(strlen(wanAddrs) > 0){
			get_nth_val_safe(0, wanAddrs, '/', wanAddr, sizeof(wanAddr));
			get_nth_val_safe(1, wanAddrs, '/', wanSize, sizeof(wanSize));
		}
		if(strlen(lanAddrs) > 0){
			get_nth_val_safe(0, lanAddrs, '/', lanAddr, sizeof(lanAddr));
			get_nth_val_safe(1, lanAddrs, '/', lanSize, sizeof(lanSize));
		}
		
	}
	else if(!strcmp(service, "dhcpv6")) {

		if(0 == strcmp(wanMode, "pppoe"))
		{
			get_uci2json(root, PKG_NETWORK_CONFIG, "wan", "usernames","pppoeUser");
			get_uci2json(root, PKG_NETWORK_CONFIG, "wan", "password","pppoePass");
			get_uci2json(root, PKG_NETWORK_CONFIG, "wan", "service","pppoeServiceName");
			get_uci2json(root, PKG_NETWORK_CONFIG, "wan", "pmtu","pppoeMtu");
		}
	
		Uci_Get_Str(PKG_NETWORK_CONFIG, "wan60", "noslaaconly", wanDhcp);
		Uci_Get_Str(PKG_NETWORK_CONFIG, "wan60", "wanPriv", wanPriv);
		if(strlen(wanDhcp) > 0){
			if(atoi(wanDhcp) == 0)
				cJSON_AddStringToObject(root, "wanDhcp", "1");
			else if(atoi(wanDhcp) == 1)
				cJSON_AddStringToObject(root, "wanDhcp", "0");
		}
		else
			cJSON_AddStringToObject(root, "wanDhcp", "2");
		
		cJSON_AddStringToObject(root, "wanPriv", atoi(wanPriv) == 1?"1":"0");
		
		Uci_Get_Str(PKG_NETWORK_CONFIG, "wan60", "ip6prefix", lanAddrs);
		if(strlen(lanAddrs) > 0) {
			get_nth_val_safe(0, lanAddrs, '/', lanAddr, sizeof(lanAddr));
			get_nth_val_safe(1, lanAddrs, '/', lanSize, sizeof(lanSize));
			cJSON_AddStringToObject(root, "lanAutoFake", "0");
		}
		else {
			cJSON_AddStringToObject(root, "lanAutoFake", "1");
		}
	}
	else
	{
		cJSON_AddStringToObject(root, "lanAutoFake", "1");
		cJSON_AddStringToObject(root, "wanDhcp", "2");
		cJSON_AddStringToObject(root, "wanPriv", "0");
		cJSON_AddStringToObject(root, "lanPriv", "1");
	}

	cJSON_AddStringToObject(root, "wanAddr", wanAddr);
	if(strcmp(wanSize, "") == 0)
		cJSON_AddStringToObject(root, "wanSize", "64");
	else
		cJSON_AddStringToObject(root, "wanSize", wanSize);
	cJSON_AddStringToObject(root, "wanGate", wanGate);
	cJSON_AddStringToObject(root, "lanAddr", lanAddr);
	cJSON_AddStringToObject(root, "lanSize", lanSize);
	cJSON_AddStringToObject(root, "sitMtu", "1280");
	cJSON_AddStringToObject(root, "sitTtl", "64");
	cJSON_AddStringToObject(root, "size6rd", "0");
	
	Uci_Get_Str(PKG_NETWORK_CONFIG, "wan60", "dns", wanDns);
	if(strlen(wanDns) > 0)
	{
		get_nth_val_safe(0, wanDns, ' ', dns1, sizeof(dns1));
		get_nth_val_safe(1, wanDns, ' ', dns2, sizeof(dns2));
		get_nth_val_safe(2, wanDns, ' ', dns3, sizeof(dns3));
		cJSON_AddStringToObject(root, "dnsAutoFake", "0");
	}
	else
		cJSON_AddStringToObject(root, "dnsAutoFake", "1");
	cJSON_AddStringToObject(root, "dns1", dns1);
	cJSON_AddStringToObject(root, "dns2", dns2);
	cJSON_AddStringToObject(root, "dns3", dns3);

	Uci_Get_Str(PKG_DHCP_CONFIG, "lan", "ra_default", lanRadvFake);
	cJSON_AddStringToObject(root, "lanRadvFake", strlen(lanRadvFake)?lanRadvFake:"0");

	Uci_Get_Str(PKG_DHCP_CONFIG, "lan", "dhcpv6", dhcpV6);
	Uci_Get_Str(PKG_DHCP_CONFIG, "lan", "ra_management", dhcpV6Type);
	if(!strcmp(dhcpV6, "server")) {
		snprintf(buff,sizeof(buff)-1,"%d",atoi(dhcpV6Type)+1);
		cJSON_AddStringToObject(root, "lanDhcp", buff);
	}
	else {
		cJSON_AddStringToObject(root, "lanDhcp", "0");
	}

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}

CGI_BOOL setIpv6Cfg(json_object *request, FILE *conn_fp)
{
	char buff[512] = {0};
	
	char *service = webs_get_string(request, "service");
	if(!strcmp(service, "off"))
	{
		Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "ra", "disabled");
		Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "dhcpv6", "disabled");

		Uci_Set_Str(PKG_NETWORK_CONFIG, "wan60", "disabled", "1");
		Uci_Set_Str(PKG_NETWORK_CONFIG, "globals", "ula_prefix", "");

		goto end;
	}
	else
	{
		Uci_Set_Str(PKG_NETWORK_CONFIG, "wan60", "disabled", "");
	}

	if(!strcmp(service, "static")) { //static
		char *wanAddr = webs_get_string(request, "wanAddr");
		char *wanSize = webs_get_string(request, "wanSize");
		char *wanGate = webs_get_string(request, "wanGate");
		char *lanAddr = webs_get_string(request, "lanAddr");
		char *lanSize = webs_get_string(request, "lanSize");

		snprintf(buff,sizeof(buff)-1,"%s/%s", wanAddr, wanSize);
		Uci_Set_Str(PKG_NETWORK_CONFIG, "wan60", "proto", "static");
		Uci_Set_Str(PKG_NETWORK_CONFIG, "wan60", "ip6addr", buff);
		Uci_Set_Str(PKG_NETWORK_CONFIG, "wan60", "ip6gw", wanGate);

		snprintf(buff,sizeof(buff)-1,"%s/%s", lanAddr, lanSize);
		Uci_Set_Str(PKG_NETWORK_CONFIG, "wan60", "ip6prefix", buff);
		Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "dhcpv6", "server");

	} 
	else if(!strcmp(service, "dhcp6")) {
		char *wanDhcp = webs_get_string(request, "wanDhcp");   //0:STATELESS,1:STATEFUL,2:STATELESS&STATEFUL
		char *wanPriv = webs_get_string(request, "wanPriv");   //RFC 4941
		char *intVal = webs_get_string(request, "lanAutoFake");//lan ipv6 0:manual 1:dhcp
		if(atoi(intVal) == 0) {
			char *lanAddr = webs_get_string(request, "lanAddr");
			char *lanSize = webs_get_string(request, "lanSize");

			snprintf(buff,sizeof(buff)-1,"%s/%s", lanAddr, lanSize);
			//Uci_Set_Str(PKG_NETWORK_CONFIG, "lan", "ip6addr", lanIp6Addr);
			//Uci_Set_Str(PKG_NETWORK_CONFIG, "lan", "ip6assign", lanSize);
			Uci_Set_Str(PKG_NETWORK_CONFIG, "wan60", "ip6prefix", buff);
		}
		else{
			Uci_Set_Str(PKG_NETWORK_CONFIG, "wan60", "ip6prefix", "");
		}

		if(atoi(wanDhcp) == 0){
			Uci_Set_Str(PKG_NETWORK_CONFIG, "wan60", "noslaaconly", "1");
			Uci_Set_Str(PKG_NETWORK_CONFIG, "wan60", "wanPriv", wanPriv); //Unknown effect
		}
		else if(atoi(wanDhcp) == 1)
		{
			Uci_Set_Str(PKG_NETWORK_CONFIG, "wan60", "noslaaconly", "0");
		}
		else{
			Uci_Set_Str(PKG_NETWORK_CONFIG, "wan60", "noslaaconly", "");
			Uci_Set_Str(PKG_NETWORK_CONFIG, "wan60", "wanPriv", wanPriv); //Unknown effect
		}

		//Uci_Set_Str(PKG_NETWORK_CONFIG, "wan6", "reqaddress", "try");
		//Uci_Set_Str(PKG_NETWORK_CONFIG, "wan6", "reqprefix", "auto");
		Uci_Set_Str(PKG_NETWORK_CONFIG, "wan60", "ip6addr", "");
		Uci_Set_Str(PKG_NETWORK_CONFIG, "wan60", "ip6gw", "");
		Uci_Set_Str(PKG_NETWORK_CONFIG, "wan60", "proto", "dhcpv6");

	}

	char *dnsAuto = webs_get_string(request, "dnsAutoFake");
	if(atoi(dnsAuto) == 0) {
		char *dns1 = webs_get_string(request, "dns1");
		char *dns2 = webs_get_string(request, "dns2");
		char *dns3 = webs_get_string(request, "dns3");
		snprintf(buff, sizeof(buff)-1, "%s %s %s", dns1, dns2, dns3);
		Uci_Set_Str(PKG_NETWORK_CONFIG, "wan60", "dns", buff);
	}
	else {
		Uci_Set_Str(PKG_NETWORK_CONFIG, "wan60", "dns", "");
	}

	char *lanRadvFake = webs_get_string(request, "lanRadvFake");//route broadcast
	char *landhcp = webs_get_string(request, "lanDhcp");//dhcp server
	if(atoi(lanRadvFake) == 1) {
		if(atoi(landhcp) != 0) {
			Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "dhcpv6", "server");
			Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "ra", "server");

			if(atoi(landhcp)==1)//STATELESS
				Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "ra_management", "0");
			else if(atoi(landhcp)==2)//STATELESS&STATEFUL
				Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "ra_management", "1");
			else if(atoi(landhcp)==3)//STATEFUL
				Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "ra_management", "2");
			else
				Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "ra_management", "0");
		}
		else {
			Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "dhcpv6", "disabled");
			Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "ra", "disabled");
		}
		Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "ra_default", "1");
	}
	else {
		Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "ra_default", "0");
	}

end:

	Uci_Commit(PKG_NETWORK_CONFIG);
	Uci_Commit(PKG_DHCP_CONFIG);

	set_lktos_effect("network");
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "15", "reLogin");

	return CGI_TRUE;
}
#endif

enum {
	DETECT_DISABLED=0,
	DETECT_DEFAULT,
	DETECT_TCP,
	DETECT_ICMP
};

CGI_BOOL getWanStrategy(json_object *request, FILE *conn_fp)
{
	int prio=0, strategy=0, detect_mode=0, idx=0;
	char tmp_buf[16]={0}, ip_list[64]={0}, port_list[32]={0};
	cJSON *root, *detect_json, *addr_arry,*port_arry;

	root = cJSON_CreateObject();

	//priority
	Uci_Get_Int(PKG_WAN_MODEM_CONFIG,"strategy","prio", &prio);
	if(prio == PRIO_ONLY_WIRE)//2
		strategy = PRIO_ONLY_WIRE;		
	else if ( prio == PRIO_3GPP_ONLY )//1
		strategy = PRIO_3GPP_ONLY;
	else
		strategy = PRIO_WIRE_FRIST;//0

	sprintf(tmp_buf, "%d", strategy);
	cJSON_AddStringToObject(root, "strategy", tmp_buf);

	//router mode
	memset(tmp_buf, 0, sizeof(tmp_buf));
	Uci_Get_Str(PKG_WAN_MODEM_CONFIG, "strategy", "route_mode", tmp_buf);
	cJSON_AddStringToObject(root, "routeMode", tmp_buf);

	detect_json = cJSON_CreateObject();
	cJSON_AddItemToObject(root, "detectNet", detect_json);

	//detect net
	Uci_Get_Int(PKG_WAN_MODEM_CONFIG, "strategy", "detect_net", &detect_mode);		
	sprintf(tmp_buf, "%d", detect_mode);
	cJSON_AddStringToObject(detect_json, "mode", tmp_buf);

	addr_arry = cJSON_CreateArray();
	port_arry = cJSON_CreateArray();
	cJSON_AddItemToObject(detect_json, "addr", addr_arry);
	cJSON_AddItemToObject(detect_json, "port", port_arry);

	Uci_Get_Str(PKG_WAN_MODEM_CONFIG, "strategy", "ip_list", ip_list);
	while(getNthValueSafe(idx++, ip_list, ',', tmp_buf, sizeof(tmp_buf)) != -1){
		cJSON_AddItemToArray(addr_arry, cJSON_CreateString(tmp_buf));
	}

	idx=0;
	memset(tmp_buf, 0, sizeof(tmp_buf));
	Uci_Get_Str(PKG_WAN_MODEM_CONFIG, "strategy", "port_list", port_list);
	while(getNthValueSafe(idx++, port_list, ',', tmp_buf, sizeof(tmp_buf)) != -1){
		cJSON_AddItemToArray(port_arry, cJSON_CreateString(tmp_buf));
	}

	char searchNetMode[32]={0};
	Uci_Get_Str(PKG_WAN_MODEM_CONFIG, "strategy", "searchnetmode",searchNetMode);
	cJSON_AddStringToObject(root, "searchnetmode", searchNetMode);

	Uci_Get_Int(PKG_NETWORK_CONFIG, IFACE_3GPP_WAN, "sim", &strategy);
	if(strategy == 0)
		cJSON_AddStringToObject(root, "disabled", "1");//这里字段使用不合理，由于涉及到UI，这里暂时不改,这里值为1时，UI显示"公专网功能"开关
	else
		cJSON_AddStringToObject(root, "disabled", "0");
	
	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}

CGI_BOOL setWanStrategy(json_object *request, FILE *conn_fp)
{
	json_object  *detect,*json_obj, *json_tmp;
	int i=0, arr_len=0, int_tmp;
	char tmp_buf[128]={0};
	
	char *strategy = webs_get_string(request, "strategy");
	char *route_mode = webs_get_string(request, "routeMode");

	Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "strategy","prio", strategy);
	Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "strategy", "route_mode", route_mode);
	Uci_Set_Str(PKG_CSFW_CONFIG, "firewall", "nat_enable", atoi(route_mode) == 1 ? "0" : "1");
	
	detect = json_object_object_get(request,"detectNet");
	if(detect) {
		int mode = webs_get_int(detect, "mode");

		
		if(mode == DETECT_DISABLED) //disable
			Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "strategy", "detect_net", "0");
		
		else if(mode == DETECT_TCP)//TCP
			Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "strategy", "detect_net", "2");
		else if(mode == 3)//ICMP
			Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "strategy", "detect_net", "3");
		else //Def
			Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "strategy", "detect_net", "1");

		json_obj = json_object_object_get(detect,"addr");
	 	arr_len = json_object_array_length(json_obj);
		memset(tmp_buf, 0, sizeof(tmp_buf));
		for(i = 0; i < arr_len; i++) {
		  json_tmp = json_object_array_get_idx(json_obj, i);
			if(json_tmp) {
				if(strlen(tmp_buf) > 0)
					strcat(tmp_buf, ",");
				strcat(tmp_buf, json_object_get_string(json_tmp));
			}
		}
		Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "strategy", "ip_list", tmp_buf);
		
		json_obj = json_object_object_get(detect,"port");
		arr_len = json_object_array_length(json_obj);
		memset(tmp_buf, 0, sizeof(tmp_buf));
		for(i = 0; i < arr_len; i++) {
			json_tmp = json_object_array_get_idx(json_obj, i);
			if(json_tmp) {
				if(strlen(tmp_buf) > 0)
					strcat(tmp_buf, ",");
				strcat(tmp_buf, json_object_get_string(json_tmp));
			}
		}
		Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "strategy", "port_list", tmp_buf);
	}
	
	char *searchNetMode = webs_get_string(request, "searchnetmode");
	Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "strategy", "searchnetmode",searchNetMode);

	if(atoi(strategy) == PRIO_3GPP_ONLY)
		set_ethernet_port(1);
	else
		set_ethernet_port(0);

	char modem_wname[16]={0};
	int tactics_usb=atoi(webs_get_string(request, "modem_tactics_usb")) ;
	if(tactics_usb==0)
		tactics_usb=1;
	snprintf( tmp_buf, sizeof(tmp_buf), "%d", tactics_usb);
	Uci_Set_Str(PKG_WAN_MODEM_CONFIG, "main", "modem_tactics_usb", tmp_buf);
	Uci_Get_Int(PKG_WAN_MODEM_CONFIG, "main", "modem_num",&int_tmp);
	if( atoi(strategy)== PRIO_ONLY_WIRE )
	{
		for( i=0; i<int_tmp; i++)
		{	
			snprintf(modem_wname, sizeof(modem_wname), "wan_modem%d", i);
			Uci_Get_Str(PKG_WAN_MODEM_CONFIG, "main", modem_wname, tmp_buf);
			Uci_Set_Str(PKG_NETWORK_CONFIG, tmp_buf, "disabled","1");
			Uci_Set_Str(PKG_NETWORK_CONFIG, tmp_buf, "defaultroute","0");
		}
	}else if( atoi(strategy)== PRIO_WIRE_FRIST )
	{
		for( i=0; i<int_tmp; i++)
		{
			Uci_Set_Str(PKG_NETWORK_CONFIG, "wan", "metric","1");
			snprintf(modem_wname, sizeof(modem_wname), "wan_modem%d", i);
			Uci_Get_Str(PKG_WAN_MODEM_CONFIG, "main", modem_wname, tmp_buf);
			Uci_Set_Str(PKG_NETWORK_CONFIG, tmp_buf, "disabled","0");
			Uci_Set_Str(PKG_NETWORK_CONFIG, tmp_buf, "defaultroute","1");
			if( tactics_usb==(i+1) ){
				Uci_Set_Str(PKG_NETWORK_CONFIG, tmp_buf, "metric","2");	
			}else{
				Uci_Set_Str(PKG_NETWORK_CONFIG, tmp_buf, "metric","3");
			}

		}
	}else{
		for( i=0; i<int_tmp; i++)
		{	
			snprintf(modem_wname, sizeof(modem_wname), "wan_modem%d", i);
			Uci_Get_Str(PKG_WAN_MODEM_CONFIG, "main", modem_wname, tmp_buf);
			Uci_Set_Str(PKG_NETWORK_CONFIG, tmp_buf, "disabled","0");
			Uci_Set_Str(PKG_NETWORK_CONFIG, tmp_buf, "defaultroute","1");
			if( tactics_usb==(i+1) ){
				Uci_Set_Str(PKG_NETWORK_CONFIG, tmp_buf, "metric","1");	
			}else{
				Uci_Set_Str(PKG_NETWORK_CONFIG, tmp_buf, "metric","2");
			}
		}
	}

	Uci_Commit(PKG_CSFW_CONFIG);
	Uci_Commit(PKG_WAN_MODEM_CONFIG);
	Uci_Commit(PKG_NETWORK_CONFIG);

	set_lktos_effect("mcm");
	set_lktos_effect("network");
	set_lktos_effect("firewall");
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "15", "reserv");
}


#define TEMP_WG_PRIVATE_KEY "/tmp/wg_pri_key"
void get_peer_status(cJSON *obj, char *pub_key, int mode)
{
	int node_exist=0;
	char buf[256]={0}, result[1024]={0};
	char cmd[32]={0};
	if(mode == 1)
		strcpy(cmd, "wg show wg1");
	else
		strcpy(cmd, "wg show wg0");
	
	FILE *fp = popen(cmd, "r");

	if(fp){
		while(fgets(buf, sizeof(buf), fp) != NULL){
			if(strncmp(buf, "interface", strlen("interface"))==0)
				node_exist=1;
			
			if(strncmp(buf, "peer:", strlen("peer:")) == 0){
				if(node_exist == 2)//到这里目标peer已经读取结束
					break;
				//重置标识
				node_exist=0;
				if(strstr(buf, pub_key) !=NULL){
					//找到目标节点peer
					node_exist=2;
				}
			}

			if(node_exist == 1 || node_exist == 2)
				strcat(result, buf);
		}
		pclose(fp);
	}

	cJSON_AddStringToObject(obj, "wg_show", result);

	return ;
}

CGI_BOOL getPreshareKey(json_object *request, FILE *conn_fp)
{
	char prekey[64]={0};
	
	get_cmd_result("wg genpsk", prekey, sizeof(prekey));

	cJSON *root = cJSON_CreateObject();
	cJSON_AddStringToObject(root, "preKey", prekey);

	send_cgi_json_respond(conn_fp, root);
	
	return CGI_TRUE;
}

CGI_BOOL getWireguardKey(json_object *request, FILE *conn_fp)
{	
	char cmd[32]={0}, private_key[64]={0}, pub_key[64]={0};
	
	cJSON *root = cJSON_CreateObject();

	char *key = webs_get_string(request, "privateKey");

	if(strcmp(key, "") == 0)
		doSystem("wg genkey > %s", TEMP_WG_PRIVATE_KEY);
	else
		f_write_string(TEMP_WG_PRIVATE_KEY, key, 0, 0);

	snprintf(cmd, sizeof(cmd)-1, "wg pubkey < %s", TEMP_WG_PRIVATE_KEY);
	get_cmd_result(cmd, pub_key, sizeof(pub_key));

	f_read(TEMP_WG_PRIVATE_KEY, private_key, 44);
	
	cJSON_AddStringToObject(root, "privateKey", private_key);
	cJSON_AddStringToObject(root, "publicKey", pub_key);
	
	send_cgi_json_respond(conn_fp, root);
	
	return CGI_TRUE;
}

CGI_BOOL getWireguardCfg(json_object *request, FILE *conn_fp)
{
	int disabled=0, i=0;
	char tmp_buf[64]={0}, buf[64]={0};
	char iface[8]={0};
	
	cJSON *root = cJSON_CreateObject();

	int mode = webs_get_int(request, "mode");
	
	if(mode == 1){
		//client
		strcpy(iface, "wg1");
	}else{
		//server
		strcpy(iface, "wg0");
	}
	
	Uci_Get_Int(PKG_NETWORK_CONFIG, iface, "disabled", &disabled);
	
	if(disabled){
		cJSON_AddStringToObject(root, "enable", "0");	
	}else{
		cJSON_AddStringToObject(root, "enable", "1");
	}
	
	char private_key[64]={0}, pub_key[64]={0};
	char address[64]={0}, listen_port[8]={0};
	char section[32]={0}, cmd[64]={0}, route_ips[512]={0};
	int ips_num=0, j=0;
	
	//[interface]
	Uci_Get_Str(PKG_NETWORK_CONFIG, iface, "private_key", private_key);
	cJSON_AddStringToObject(root, "privateKey", private_key);
	if(strlen(private_key) == 44){
		Uci_Get_Str(PKG_NETWORK_CONFIG, iface, "public_key", pub_key);
		if(strlen(pub_key) != 44){
			f_write_string(TEMP_WG_PRIVATE_KEY, private_key, 0, 0);
			snprintf(cmd, sizeof(cmd)-1, "wg pubkey < %s", TEMP_WG_PRIVATE_KEY);
			get_cmd_result(cmd, pub_key, sizeof(pub_key));
		}
		
		cJSON_AddStringToObject(root, "publicKey", pub_key);
	}
	else{
		cJSON_AddStringToObject(root, "publicKey", "");
	}
	
	Uci_Get_Str(PKG_NETWORK_CONFIG, iface, "addresses", address);
	cJSON_AddStringToObject(root, "ip", address);

	memset(listen_port, 0, sizeof(listen_port));
	Uci_Get_Str(PKG_NETWORK_CONFIG, iface, "listen_port", listen_port);
	cJSON_AddStringToObject(root, "listenPort", listen_port);
	
	//[peer]
	cJSON *array = cJSON_CreateArray();

	cJSON_AddItemToObject(root, "peer", array);

	memset(cmd, 0, sizeof(cmd));
	snprintf(cmd, sizeof(cmd), "uci show network | grep wireguard_%s", iface);
	FILE *fp = popen(cmd, "r");
	if(fp)
	{
		while(fgets(buf, sizeof(buf), fp) != NULL){
			
			get_nth_val_safe(0, buf, '=', tmp_buf, sizeof(tmp_buf));
			get_nth_val_safe(1, tmp_buf, '.', section, sizeof(section));

			cJSON *peer = cJSON_CreateObject();
			cJSON_AddItemToArray(array, peer);

			memset(tmp_buf, 0, sizeof(tmp_buf));
			Uci_Get_Str(PKG_NETWORK_CONFIG, section, "private_key", tmp_buf);
			cJSON_AddStringToObject(peer, "priKey", tmp_buf);
			
			memset(pub_key, 0, sizeof(pub_key));
			Uci_Get_Str(PKG_NETWORK_CONFIG, section, "public_key", pub_key);
			cJSON_AddStringToObject(peer, "pubKey", pub_key);

			memset(tmp_buf, 0, sizeof(tmp_buf));
			Uci_Get_Str(PKG_NETWORK_CONFIG, section, "route_allowed_ips", tmp_buf);
			cJSON_AddStringToObject(peer, "route_allow", tmp_buf);

			Uci_Get_Int(PKG_NETWORK_CONFIG, section, "ips_num", &ips_num);
			
			memset(route_ips, 0, sizeof(route_ips));
			Uci_Get_Str(PKG_NETWORK_CONFIG, section, "allowed_ips", route_ips);
			for(j=0; j < strlen(route_ips); j++){
				if(route_ips[j] == ' ')
					route_ips[j]=',';
			}
			cJSON_AddStringToObject(peer, "route_ips", route_ips);

			memset(tmp_buf, 0, sizeof(tmp_buf));
			Uci_Get_Str(PKG_NETWORK_CONFIG, section, "preshared_key", tmp_buf);
			cJSON_AddStringToObject(peer, "preKey", tmp_buf);

			memset(tmp_buf, 0, sizeof(tmp_buf));
			Uci_Get_Str(PKG_NETWORK_CONFIG, section, "endpoint_host", tmp_buf);
			cJSON_AddStringToObject(peer, "host", tmp_buf);

			memset(tmp_buf, 0, sizeof(tmp_buf));
			Uci_Get_Str(PKG_NETWORK_CONFIG, section, "endpoint_port", tmp_buf);
			cJSON_AddStringToObject(peer, "port", tmp_buf);

			memset(tmp_buf, 0, sizeof(tmp_buf));
			Uci_Get_Str(PKG_NETWORK_CONFIG, section, "comment", tmp_buf);
			cJSON_AddStringToObject(peer, "comment", tmp_buf);

			cJSON_AddStringToObject(peer, "section", section);
			
			get_peer_status(peer, pub_key, mode);
		}
		pclose(fp);
	}

	Uci_Get_Str(PKG_DDNS_CONFIG,"wan","enable",tmp_buf);
	if(atoi(tmp_buf) == 0)
		cJSON_AddStringToObject(root, "ddnsEnable", "0");
	else
		cJSON_AddStringToObject(root, "ddnsEnable", "1");
	memset(tmp_buf,0,sizeof(tmp_buf));
	Uci_Get_Str(PKG_DDNS_CONFIG,"wan","domain",tmp_buf);
	cJSON_AddStringToObject(root, "ddnsHost", tmp_buf);

	send_cgi_json_respond(conn_fp, root);
	
	return CGI_TRUE;
}

void set_cli_peer_config(json_object *request)
{
	int num=0, i=0;
	char tmp_buf[64]={0};
	char sRules[512]={0}, rules[64]={0}, section[16]={0};
	struct json_object *obj_peer;

	obj_peer=json_object_object_get(request, "peer");

	char *pub_key = webs_get_string(obj_peer, "pubKey");
	char *pre_key = webs_get_string(obj_peer, "preKey");
	char *host = webs_get_string(obj_peer, "host");
	char *port = webs_get_string(obj_peer, "port");
	char *route_ips = webs_get_string(obj_peer, "route_ips");
	char *route_allow = webs_get_string(obj_peer, "route_allow");
	char *keep_alive = webs_get_string(obj_peer, "keepAlive");
	
	strcpy(section, "cli_peer");
		
	Uci_Set_Str(PKG_NETWORK_CONFIG, section, "public_key", pub_key);
	
	Uci_Set_Str(PKG_NETWORK_CONFIG, section, "preshared_key", pre_key);
	
	Uci_Set_Str(PKG_NETWORK_CONFIG, section, "endpoint_host", host);

	Uci_Set_Str(PKG_NETWORK_CONFIG, section, "endpoint_port", port);

	Uci_Set_Str(PKG_NETWORK_CONFIG, section, "persistent_keepalive", keep_alive);
			
	if(atoi(route_allow) == 0)
		Uci_Set_Str(PKG_NETWORK_CONFIG, section, "route_allowed_ips", "0");
	else
		Uci_Set_Str(PKG_NETWORK_CONFIG, section, "route_allowed_ips", "1");

	Uci_Get_Int(PKG_NETWORK_CONFIG, section, "ips_num", &num);
	
	Uci_Get_Str(PKG_NETWORK_CONFIG, section, "allowed_ips", sRules);
	
	for(i=0; i<num; i++)
	{
		get_nth_val_safe(i, sRules, ' ', rules, sizeof(rules));
		Uci_Del_List(PKG_NETWORK_CONFIG, section, "allowed_ips", rules);
	}

	num=0;
	i=0;
	if(strlen(route_ips) > 0){
		memset(tmp_buf, 0, sizeof(tmp_buf));
		while(get_nth_val_safe(i++, route_ips, ',', tmp_buf, sizeof(tmp_buf)) != -1){
			Uci_Add_List(PKG_NETWORK_CONFIG, section, "allowed_ips", tmp_buf);
			num++;
		}	
		
		memset(tmp_buf, 0, sizeof(tmp_buf));
		sprintf(tmp_buf, "%d", num);
		Uci_Set_Str(PKG_NETWORK_CONFIG, section, "ips_num", tmp_buf);
	}
	
	return ;
}

CGI_BOOL setWireguardCfg(json_object *request, FILE *conn_fp)
{
	char iface[8]={0};
	
	int mode = webs_get_int(request, "mode");
	if(mode == 1){
		//client
		strcpy(iface, "wg1");
		set_cli_peer_config(request);
	}else{
		//server
		strcpy(iface, "wg0");
	}
		
	Uci_Set_Str(PKG_NETWORK_CONFIG, iface, "disabled", "0");

	Uci_Set_Str(PKG_NETWORK_CONFIG, iface, "proto", "wireguard");
	
	char *private_key = webs_get_string(request, "privateKey");
	Uci_Set_Str(PKG_NETWORK_CONFIG, iface, "private_key", private_key);
	
	char *pub_key = webs_get_string(request, "publicKey");
	Uci_Set_Str(PKG_NETWORK_CONFIG, iface, "pubilc_key", pub_key);

	char *listen_port = webs_get_string(request, "listenPort");
	Uci_Set_Str(PKG_NETWORK_CONFIG, iface, "listen_port", listen_port);

	char *ip = webs_get_string(request, "ip");
	Uci_Set_Str(PKG_NETWORK_CONFIG, iface, "addresses", ip);

	Uci_Commit(PKG_NETWORK_CONFIG);

	if(mode == 1)
		set_lktos_effect("wireguard_cli");
	else
		set_lktos_effect("wireguard_ser");
		
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "3", "reserv");

	return CGI_TRUE;
}

/*
	{"comment":"1234","pubKey":"","host":"","port":"","keepAlive":"","route_ips":"","route_allow":"","preKey":"","topicurl":"setWireguardPeerCfg"}: 
*/
CGI_BOOL setWireguardPeerCfg(json_object *request, FILE *conn_fp)
{
	int add_times=0, i=0, num=0;
	char section[16]={0}, tmp_buf[64]={0};
	
	char *action = webs_get_string(request, "action");
	char *pubKey = webs_get_string(request, "pubKey");
	char *comment = webs_get_string(request, "comment");
	char *host = webs_get_string(request, "host");
	char *port = webs_get_string(request, "port");
	char *route_ips =webs_get_string(request, "route_ips");
	char *route_allow = webs_get_string(request, "route_allow");
	char *preKey = webs_get_string(request, "preKey");
	char *priKey = webs_get_string(request, "priKey");
	
	char iface[8]={0};
	
	int mode = webs_get_int(request, "mode");
	if(mode == 1){
		//client
		strcpy(iface, "wg1");
	}else{
		//server
		strcpy(iface, "wg0");
	}
	
	if(strcmp(action, "add") == 0){
		Uci_Get_Int(PKG_NETWORK_CONFIG, "wg0", "add_peer_times", &add_times);
		
		sprintf(section, "peer%d", add_times);
		doSystem("uci set network.%s=\"wireguard_%s\"", section, iface);

		Uci_Set_Str(PKG_NETWORK_CONFIG, section, "private_key", priKey);
		
		Uci_Set_Str(PKG_NETWORK_CONFIG, section, "public_key", pubKey);
		if(strlen(preKey) > 0)
			Uci_Set_Str(PKG_NETWORK_CONFIG, section, "preshared_key", preKey);
		
		if(strlen(host) > 0)
			Uci_Set_Str(PKG_NETWORK_CONFIG, section, "endpoint_host", host);

		if(strlen(port) > 0)
			Uci_Set_Str(PKG_NETWORK_CONFIG, section, "endpoint_port", port);
		
		if(strlen(comment) > 0)
			Uci_Set_Str(PKG_NETWORK_CONFIG, section, "comment", comment);

		if(atoi(route_allow) == 0)
			Uci_Set_Str(PKG_NETWORK_CONFIG, section, "route_allowed_ips", "0");
		else
			Uci_Set_Str(PKG_NETWORK_CONFIG, section, "route_allowed_ips", "1");

		if(strlen(route_ips) > 0){
			memset(tmp_buf, 0, sizeof(tmp_buf));
			while(get_nth_val_safe(i++, route_ips, ',', tmp_buf, sizeof(tmp_buf)) != -1){
				Uci_Add_List(PKG_NETWORK_CONFIG, section, "allowed_ips", tmp_buf);
				num++;
			}

			memset(tmp_buf, 0, sizeof(tmp_buf));
			sprintf(tmp_buf, "%d", num);
			Uci_Set_Str(PKG_NETWORK_CONFIG, section, "ips_num", tmp_buf);
		}
		
		add_times += 1;
		memset(tmp_buf, 0, sizeof(tmp_buf));
		sprintf(tmp_buf, "%d", add_times);
		Uci_Set_Str(PKG_NETWORK_CONFIG, "wg0", "add_peer_times", tmp_buf);
		
	}
	else if(strcmp(action, "modify") == 0){
		char sRules[512]={0}, rules[64]={0};
		
		char *section = webs_get_string(request, "section");
		Uci_Set_Str(PKG_NETWORK_CONFIG, section, "private_key", priKey);
		
		Uci_Set_Str(PKG_NETWORK_CONFIG, section, "public_key", pubKey);
		
		Uci_Set_Str(PKG_NETWORK_CONFIG, section, "preshared_key", preKey);
		
		Uci_Set_Str(PKG_NETWORK_CONFIG, section, "endpoint_host", host);

		Uci_Set_Str(PKG_NETWORK_CONFIG, section, "endpoint_port", port);
		
		Uci_Set_Str(PKG_NETWORK_CONFIG, section, "comment", comment);

		if(atoi(route_allow) == 0)
			Uci_Set_Str(PKG_NETWORK_CONFIG, section, "route_allowed_ips", "0");
		else
			Uci_Set_Str(PKG_NETWORK_CONFIG, section, "route_allowed_ips", "1");

		Uci_Get_Int(PKG_NETWORK_CONFIG, section, "ips_num", &num);
		
		Uci_Get_Str(PKG_NETWORK_CONFIG, section, "allowed_ips", sRules);
		
		for(i=0; i<num; i++)
		{
			get_nth_val_safe(i, sRules, ' ', rules, sizeof(rules));
			Uci_Del_List(PKG_NETWORK_CONFIG, section, "allowed_ips", rules);
		}

		num=0;
		i=0;
		if(strlen(route_ips) > 0){
			memset(tmp_buf, 0, sizeof(tmp_buf));
			while(get_nth_val_safe(i++, route_ips, ',', tmp_buf, sizeof(tmp_buf)) != -1){
				Uci_Add_List(PKG_NETWORK_CONFIG, section, "allowed_ips", tmp_buf);
				num++;
			}	
			
			memset(tmp_buf, 0, sizeof(tmp_buf));
			sprintf(tmp_buf, "%d", num);
			Uci_Set_Str(PKG_NETWORK_CONFIG, section, "ips_num", tmp_buf);
		}
	}
	else if(strcmp(action, "delete") == 0){
		char *section = webs_get_string(request, "section");
		doSystem("uci -q delete network.%s", section);
	}
	else{
		goto err;
	}

	Uci_Commit(PKG_NETWORK_CONFIG);
	
	if(mode == 1)
		set_lktos_effect("wireguard_cli");
	else
		set_lktos_effect("wireguard_ser");

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

	return CGI_TRUE;

err:
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "error");
	return CGI_FALSE;
}

CGI_BOOL setWireguardSwitch(json_object *request, FILE *conn_fp)
{
	char section[8]={0}, proto[16]={0};
	
	int mode = webs_get_int(request, "mode");
	if(mode == 1){
		//client
		strcpy(section, "wg1");
	}else{
		//server
		strcpy(section, "wg0");
	}
	
	int enable = webs_get_int(request, "enable");
	if(enable == 0){
		Uci_Set_Str(PKG_NETWORK_CONFIG, section, "disabled", "1");
	}else{
		Uci_Set_Str(PKG_NETWORK_CONFIG, section, "disabled", "0");
	}

	Uci_Get_Str(PKG_NETWORK_CONFIG, section, "proto", proto);
	
	Uci_Commit(PKG_NETWORK_CONFIG);

	if(strcmp(proto, "wireguard")  == 0){
		if(mode == 1)
			set_lktos_effect("wireguard_cli");
		else
			set_lktos_effect("wireguard_ser");
	}

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "5", "reserv");

	return CGI_TRUE;
}

void get_config_param(char *ptr, char *dst)
{
	int i=0, offset=0;
	int len = strlen(ptr);

	//跳过等号和空格
	for(i=0; i < len; i++){
		if(ptr[i] == '=' || ptr[i] == 0x20){
			offset++;
		}else
			break;
	}
	ptr += offset;
	
	len -= offset;

	//去掉结尾的换行符,如果有
	for(i = len; i >= 0; i--){
		//dbg("[%d]=0x%X\n", i, ptr[i]);
		if(ptr[i] == 0xD || ptr[i] == 0xA || ptr[i] == 0x0){
			ptr[i] = '\0';
		}else
			break;
	}
	
	memcpy(dst, ptr, strlen(ptr));
	
	return ;
}

CGI_BOOL UploadWireguardConfig(json_object *request, FILE *conn_fp)
{
	int flag=0;
	int flash_size = 0;
	long con_len = 0;
	char buf[256]={0}, allow_ips[256]={0};
	char host[64]={0},port[8]={0}, tmp_buf[64]={0};
	
	cJSON *root = NULL, *sub_peer = NULL;
	const char *file_name = webs_get_string(request, "file_name");
	const char *content_length = webs_get_string(request, "content_length");

	root = cJSON_CreateObject();

	if(strlen(file_name) == 0 || f_size(file_name) == 0)
	{
		cJSON_AddStringToObject(root, "uploadERR", "MM_upload_error");
		goto err;
	}

	FILE *fp = fopen(file_name, "r");
	char *ptr;
	
	if(!fp){
		cJSON_AddStringToObject(root, "uploadERR", "MM_openfile_error");
		goto err;
	}
	sub_peer = cJSON_CreateObject();
	cJSON_AddItemToObject(root, "peer", sub_peer);
	
	while(fgets(buf, sizeof(buf), fp) != NULL)
	{
		if(strncmp(buf, "[Interface]", strlen("[Interface]")) == 0)
			flag=1;
		else if(strncmp(buf, "[Peer]", strlen("[Peer]")) == 0 && flag==2)
			break;//暂时只考虑一个节点
		else if(strncmp(buf, "[Peer]", strlen("[Peer]")) == 0)
			flag=2;
		
		if(flag == 1){
			//[Interface]
			if((ptr=strstr(buf, "PrivateKey")) != NULL){
				memset(tmp_buf, 0, sizeof(tmp_buf));
				get_config_param(ptr+strlen("PrivateKey"), tmp_buf);
				cJSON_AddStringToObject(root, "privateKey", tmp_buf);
			}
			else if((ptr = strstr(buf, "Address")) != NULL){
				memset(tmp_buf, 0, sizeof(tmp_buf));
				get_config_param(ptr+strlen("Address"), tmp_buf);
				cJSON_AddStringToObject(root, "ip", tmp_buf);
			}
			else if((ptr = strstr(buf, "listenPort")) != NULL){
				memset(tmp_buf, 0, sizeof(tmp_buf));
				get_config_param(ptr+strlen("listenPort"), tmp_buf);
				cJSON_AddStringToObject(root, "ip", tmp_buf);
			}
			else if((ptr = strstr(buf, "DNS")) != NULL){
				memset(tmp_buf, 0, sizeof(tmp_buf));
				get_config_param(ptr+strlen("DNS"), tmp_buf);
				cJSON_AddStringToObject(root, "dns", tmp_buf);
			}
			else if((ptr = strstr(buf, "MTU")) != NULL){
				memset(tmp_buf, 0, sizeof(tmp_buf));
				get_config_param(ptr+strlen("MTU"), tmp_buf);
				cJSON_AddStringToObject(root, "mtu", tmp_buf);
			}
		}
		else if(flag == 2){
			//[Peer]
			if((ptr = strstr(buf, "PublicKey")) != NULL){
				memset(tmp_buf, 0, sizeof(tmp_buf));
				get_config_param(ptr+strlen("PublicKey"), tmp_buf);
				cJSON_AddStringToObject(sub_peer, "pubKey", tmp_buf);
			}
			else if((ptr = strstr(buf, "PresharedKey")) != NULL){
				memset(tmp_buf, 0, sizeof(tmp_buf));
				get_config_param(ptr+strlen("PresharedKey"), tmp_buf);
				cJSON_AddStringToObject(sub_peer, "preKey", tmp_buf);
			}
			else if((ptr = strstr(buf, "AllowedIPs")) != NULL){
				memset(tmp_buf, 0, sizeof(tmp_buf));
				get_config_param(ptr+strlen("AllowedIPs"), tmp_buf);
				if(strlen(allow_ips) == 0)
					strcpy(allow_ips, tmp_buf);
				else{
					strcat(allow_ips, ",");
					strcat(allow_ips, tmp_buf);
				}
			}
			else if((ptr = strstr(buf, "Endpoint")) != NULL){
				memset(tmp_buf, 0, sizeof(tmp_buf));
				get_config_param(ptr+strlen("Endpoint"), tmp_buf);
				
				get_nth_val_safe(0, tmp_buf, ':', host, sizeof(host));
				get_nth_val_safe(1, tmp_buf, ':', port, sizeof(port));
				cJSON_AddStringToObject(sub_peer, "host", host);
				cJSON_AddStringToObject(sub_peer, "port", port);
			}
			else if((ptr = strstr(buf, "PersistentKeepalive")) != NULL){
				memset(tmp_buf, 0, sizeof(tmp_buf));
				get_config_param(ptr+strlen("PersistentKeepalive"), tmp_buf);
			
				cJSON_AddStringToObject(sub_peer, "keepAlive", tmp_buf);
			}
				
		}
	}

	if(flag == 0){
		cJSON_AddStringToObject(root, "uploadERR", "MM_param_error");
		goto err;
	}
	else if(flag == 2)
		cJSON_AddStringToObject(sub_peer, "route_ips", allow_ips);
	
	cJSON_AddStringToObject(root, "uploadStatus", "1");
	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;

err:
	doSystem("rm -f %s", file_name);

	send_cgi_json_respond(conn_fp, root);

	return CGI_FALSE;
}




CGI_HANDLE_TABLE network_handle_t[]={
	{"getLanCfg",     getLanCfg,    1},
	{"setLanCfg",     setLanCfg,    1},

	{"getWanCfg",     getWanCfg,    1},
	{"setWanCfg",     setWanCfg,    1},
	{"getStationMacByIp", getStationMacByIp, 1},
	{"setManualDialCfg",  setManualDialCfg,  1},
	
	{"getStaticRoute", getStaticRoute, 1},
	{"setStaticRoute", setStaticRoute, 1},
	{"delStaticRoute", delStaticRoute, 1},
	{"getRouteTableInfo", getRouteTableInfo, 1},

#if defined(USE_IPV6)	
	{"getIpv6Cfg",  getIpv6Cfg,    1},
	{"setIpv6Cfg",  setIpv6Cfg,    1},
	{"getIPv6Status", getIPv6Status,		1},
#endif

	{"getWanStrategy", getWanStrategy, 1},
	{"setWanStrategy", setWanStrategy, 1},

	{"getPreshareKey", getPreshareKey, 1},
	{"getWireguardKey", getWireguardKey, 1},
	{"getWireguardCfg", getWireguardCfg, 1},
	{"setWireguardCfg", setWireguardCfg, 1},
	{"setWireguardPeerCfg", setWireguardPeerCfg, 1},
	{"setWireguardSwitch", setWireguardSwitch, 1},
	{"UploadWireguardConfig", UploadWireguardConfig, 1},
	
	{"", NULL, 0},
};
