
void ipt_local_service(void)
{
	/* Accept DHCPv4 */
	ipt_write("-A %s -p udp --sport 67 --dport 68 -j ACCEPT\n", FILTER_SPI_INPUT_CHAIN);
}

void ipt_filter_spi(void)
{
	int is_spi_enabled;

	Uci_Get_Int(PKG_CSFW_CONFIG, "dos", "spi", &is_spi_enabled);		//spi状态防火墙开启
	if(is_spi_enabled==0){
		return ;
	}

	//INPUT CHAIN
	ipt_write(":%s - [0:0]\n",    FILTER_SPI_INPUT_CHAIN);
	ipt_write("-A INPUT -j %s\n", FILTER_SPI_INPUT_CHAIN);

	ipt_write("-A %s -m conntrack --ctstate INVALID -j DROP\n",     FILTER_SPI_INPUT_CHAIN);
	ipt_write("-A %s -i %s -m conntrack --ctstate NEW -j ACCEPT\n", FILTER_SPI_INPUT_CHAIN, LAN_DEV_NAME);
	ipt_write("-A %s -i lo -m conntrack --ctstate NEW -j ACCEPT\n", FILTER_SPI_INPUT_CHAIN);
	ipt_write("-A %s -m conntrack --ctstate RELATED,ESTABLISHED,DNAT -j ACCEPT\n", FILTER_SPI_INPUT_CHAIN);

	ipt_local_service();//放行一些本地service，比如DHCP客户端，远程管理，ftp，ssh等

	ipt_write("-A %s -j DROP\n", FILTER_SPI_INPUT_CHAIN);		//默认DROP其它流量

	//FORWARD CHAIN
	ipt_write(":%s - [0:0]\n",      FILTER_SPI_FORWARD_CHAIN);
	ipt_write("-A FORWARD -j %s\n", FILTER_SPI_FORWARD_CHAIN);

	ipt_write("-A %s -m conntrack --ctstate INVALID -j DROP\n",     FILTER_SPI_FORWARD_CHAIN);
	ipt_write("-A %s -i %s -m conntrack --ctstate NEW -j ACCEPT\n", FILTER_SPI_FORWARD_CHAIN, LAN_DEV_NAME);
	ipt_write("-A %s -i lo -m conntrack --ctstate NEW -j ACCEPT\n", FILTER_SPI_FORWARD_CHAIN);
	ipt_write("-A %s -m conntrack --ctstate RELATED,ESTABLISHED,DNAT -j ACCEPT\n", FILTER_SPI_FORWARD_CHAIN);
	ipt_write("-A %s -j DROP\n", FILTER_SPI_FORWARD_CHAIN);			//默认DROP其它流量

}

void ipt_filter_dos(void)
{
	int portscan_en, synflood_en;
	char wan_if[16]={0};

	Uci_Get_Int(PKG_CSFW_CONFIG, "dos", "portscan", &portscan_en);
	Uci_Get_Int(PKG_CSFW_CONFIG, "dos", "synflood", &synflood_en);

	if(!portscan_en && !synflood_en){
		return ;
	}

	strcpy(wan_if,fw_status.device);

	if(portscan_en)
	{
		/*
		*  Port scan rules
		*/
		ipt_write(":%s - [0:0]\n",      FILTER_PORTSCAN_FORWARD_CHAIN);
		ipt_write("-A FORWARD -j %s\n", FILTER_PORTSCAN_FORWARD_CHAIN);

		// nmap- Xmas
		ipt_write("-A %s -i %s -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP\n", FILTER_PORTSCAN_FORWARD_CHAIN, wan_if);
		// nmap- P
		ipt_write("-A %s -i %s -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP\n", FILTER_PORTSCAN_FORWARD_CHAIN, wan_if);
		//Xmas Tre
		ipt_write("-A %s -i %s -p tcp --tcp-flags ALL ALL -j DROP\n", FILTER_PORTSCAN_FORWARD_CHAIN, wan_if);
		//scan
		ipt_write("-A %s -i %s -p tcp --tcp-flags SYN,ACK,FIN,RST RST  -m limit --limit 1/s --limit-burst 1 -j ACCEPT\n", FILTER_PORTSCAN_FORWARD_CHAIN, wan_if);
		ipt_write("-A %s -i %s -p tcp --tcp-flags SYN,ACK,FIN,RST RST  -j LOG --log-prefix \"DoS: Block Port Scan: \"\n", FILTER_PORTSCAN_FORWARD_CHAIN, wan_if);
		ipt_write("-A %s -i %s -p tcp --tcp-flags SYN,ACK,FIN,RST RST  -j DROP\n", FILTER_PORTSCAN_FORWARD_CHAIN, wan_if);
		ipt_write("-A %s -i %s -p tcp --syn -m limit --limit 1/s --limit-burst 1 -j ACCEPT\n", FILTER_PORTSCAN_FORWARD_CHAIN, wan_if);
		ipt_write("-A %s -i %s -p tcp --syn -j LOG --log-prefix \"DoS: Block Port Scan: \"\n", FILTER_PORTSCAN_FORWARD_CHAIN, wan_if);
		ipt_write("-A %s -i %s -p tcp --syn -j DROP\n", FILTER_PORTSCAN_FORWARD_CHAIN, wan_if);
		// Null
		ipt_write("-A %s -i %s -p tcp --tcp-flags ALL NONE -j DROP\n", FILTER_PORTSCAN_FORWARD_CHAIN, wan_if);
		// SYN/RST
		ipt_write("-A %s -i %s -p tcp --tcp-flags SYN,RST SYN,RST -j DROP\n", FILTER_PORTSCAN_FORWARD_CHAIN, wan_if);
		// SYN/FIN
		ipt_write("-A %s -i %s -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP\n", FILTER_PORTSCAN_FORWARD_CHAIN, wan_if);

		ipt_write(":%s - [0:0]\n",    FILTER_PORTSCAN_INPUT_CHAIN);
		ipt_write("-A INPUT -j %s\n", FILTER_PORTSCAN_INPUT_CHAIN);

		ipt_write("-A %s -i %s -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP\n", FILTER_PORTSCAN_INPUT_CHAIN, wan_if);
		ipt_write("-A %s -i %s -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP\n", FILTER_PORTSCAN_INPUT_CHAIN, wan_if);
		ipt_write("-A %s -i %s -p tcp --tcp-flags ALL ALL -j DROP\n", FILTER_PORTSCAN_INPUT_CHAIN, wan_if);
		//scan
		ipt_write("-A %s -i %s -p tcp --tcp-flags SYN,ACK,FIN,RST RST  -m limit --limit 1/s --limit-burst 1 -j ACCEPT\n", FILTER_PORTSCAN_INPUT_CHAIN, wan_if);
		ipt_write("-A %s -i %s -p tcp --tcp-flags SYN,ACK,FIN,RST RST  -j LOG --log-prefix \"DoS: Block Port Scan: \"\n", FILTER_PORTSCAN_INPUT_CHAIN, wan_if);
		ipt_write("-A %s -i %s -p tcp --tcp-flags SYN,ACK,FIN,RST RST  -j DROP\n", FILTER_PORTSCAN_INPUT_CHAIN, wan_if);
		ipt_write("-A %s -i %s -p tcp --syn -m limit --limit 1/s --limit-burst 1 -j ACCEPT\n", FILTER_PORTSCAN_INPUT_CHAIN, wan_if);
		ipt_write("-A %s -i %s -p tcp --syn -j LOG --log-prefix \"DoS: Block Port Scan: \"\n", FILTER_PORTSCAN_INPUT_CHAIN, wan_if);
		ipt_write("-A %s -i %s -p tcp --syn -j DROP\n", FILTER_PORTSCAN_INPUT_CHAIN, wan_if);

		ipt_write("-A %s -i %s -p tcp --tcp-flags ALL NONE -j DROP\n", FILTER_PORTSCAN_INPUT_CHAIN, wan_if);
		ipt_write("-A %s -i %s -p tcp --tcp-flags SYN,RST SYN,RST -j DROP\n", FILTER_PORTSCAN_INPUT_CHAIN, wan_if);
		ipt_write("-A %s -i %s -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP\n", FILTER_PORTSCAN_INPUT_CHAIN, wan_if);
	}

	if(synflood_en)
	{
		/*
		* SYN flooding fules
		*/
		ipt_write(":%s - [0:0]\n",      FILTER_SYNFLOOD_FORWARD_CHAIN);
		ipt_write("-A FORWARD -j %s\n", FILTER_SYNFLOOD_FORWARD_CHAIN);
		ipt_write("-A %s -i %s -p tcp --syn -m limit --limit 1/s --limit-burst 10 -j ACCEPT\n", FILTER_SYNFLOOD_FORWARD_CHAIN, wan_if);
		ipt_write("-A %s -i %s -p tcp --syn -j LOG --log-prefix \"DoS: Block Syn Flood: \"\n",  FILTER_SYNFLOOD_FORWARD_CHAIN, wan_if);
		ipt_write("-A %s -i %s -p tcp --syn -j DROP\n", FILTER_SYNFLOOD_FORWARD_CHAIN, wan_if);

		ipt_write(":%s - [0:0]\n",    FILTER_SYNFLOOD_INPUT_CHAIN);
		ipt_write("-A INPUT -j %s\n", FILTER_SYNFLOOD_INPUT_CHAIN);
		ipt_write("-A %s -i %s -p tcp --syn -m limit --limit 1/s --limit-burst 10 -j ACCEPT\n", FILTER_SYNFLOOD_INPUT_CHAIN, wan_if);
		ipt_write("-A %s -i %s -p tcp --syn -j LOG --log-prefix \"DoS: Block Syn Flood: \"\n",  FILTER_SYNFLOOD_INPUT_CHAIN, wan_if);
		ipt_write("-A %s -i %s -p tcp --syn -j DROP\n", FILTER_SYNFLOOD_INPUT_CHAIN, wan_if);
	}
}

static void
timematch_conv(char *mstr, const char *nv_date, const char *nv_time)
{
	const char *datestr[7] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
	char time_s[8], time_e[8], time[32], date[32];
	int i, i_time_s, i_time_e, i_full_time, comma = 0;

	if (!nv_date)
		strcpy(date, "1111111");
	else
		strcpy(date, nv_date);

	if (!nv_time)
		strcpy(time, "00002359");
	else
		strcpy(time, nv_time);

	mstr[0] = 0;

	if (strlen(date) != 7 || strlen(time) != 8)
		return;

	if (!strcmp(date, "0000000"))
		return;

	strncpy(time_s, time+0, 4);
	strncpy(time_e, time+4, 4);

	time_s[4] = 0;
	time_e[4] = 0;

	i_time_s = atoi(time_s);
	i_time_e = atoi(time_e);

	i_full_time = ((i_time_s == i_time_e) || (i_time_s == 0 && i_time_e == 2359)) ? 1 : 0;

	/* check anytime */
	if (!strcmp(date, "1111111") && i_full_time)
		return;

	/* check whole day */
	if (i_full_time) {
		sprintf(mstr, " -m time %s", "--kerneltz");
	} else {
		const char *contiguous = "";

		/* check cross-night */
		if (i_time_s > i_time_e)
			contiguous = " --contiguous";

		sprintf(mstr, " -m time --timestart %c%c:%c%c:00 --timestop %c%c:%c%c:00%s %s",
			time[0], time[1], time[2], time[3], time[4], time[5], time[6], time[7],
			contiguous, "--kerneltz");
	}

	/* check everyday */
	if (strcmp(date, "1111111")) {
		strcat(mstr, " --weekdays ");
		for (i=0; i<7; i++) {
			if (date[i] == '1') {
				if (comma)
					strcat(mstr, ",");
				else
					comma = 1;
				strcat(mstr, datestr[i]);
			}
		}
	}
}

void ipt_filter_mac(int is_ipv6)
{
	int i, i_enable, i_drop, i_num;

	char rules[4096], rule[128], action[16] = {0};

	char mac[18], timematch[128], time[64], date[64];

	Uci_Get_Int(PKG_CSFW_CONFIG, "mac", "enable", &i_enable);		//mac过滤是否开启
	Uci_Get_Int(PKG_CSFW_CONFIG, "mac", "drop", &i_drop);			//是否是黑名单模式,0-白名单、1-黑名单

	memset(rules,0,sizeof(rules));
	Uci_Get_Str(PKG_CSFW_CONFIG, "mac", "rules",  rules);

	if(i_enable==0 || strlen(rules)==0){
		return;
	}

	if (i_drop == 0)
	{
		strcpy(action, "ACCEPT");
	}
	else
	{
		strcpy(action, "DROP");
	}

	if(is_ipv6!=1)
	{
		ipt_write(":%s - [0:0]\n",FILTER_MAC_CHAIN);
		ipt_write("-A FORWARD -i %s -j %s\n", LAN_DEV_NAME, FILTER_MAC_CHAIN);
	}
#if defined (USE_IPV6)
	else
	{
		ip6t_write(":%s - [0:0]\n",FILTER_MAC_CHAIN);
		ip6t_write("-A FORWARD -i %s -j %s\n", LAN_DEV_NAME, FILTER_MAC_CHAIN);
	}
#endif

	i=0;
	i_num=0;

	while (get_nth_val_safe(i++, rules, ' ', rule, sizeof(rule)) != -1 )
	{
		if ((get_nth_val_safe(0, rule, ',', mac, sizeof(mac)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(1, rule, ',', time, sizeof(time)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(2, rule, ',', date, sizeof(date)) == -1))
		{
			continue;
		}

		timematch_conv(timematch, date, time);

		if(is_ipv6!=1)
		{
			ipt_write("-i %s -I %s -m mac --mac-source %s%s -j %s\n", \
					LAN_DEV_NAME, FILTER_MAC_CHAIN, mac, timematch, action);
		}
#if defined (USE_IPV6)
		else
		{
			ip6t_write("-i %s -I %s -m mac --mac-source %s%s -j %s\n", \
					LAN_DEV_NAME, FILTER_MAC_CHAIN, mac, timematch, action);
		}
#endif
		i_num++;
	}

	if(i_num > 0 && i_drop == 0) //whitelist mode
	{
		if(is_ipv6!=1)
		{
			ipt_write("-i %s -A %s -j %s\n", LAN_DEV_NAME, FILTER_MAC_CHAIN, "DROP");
		}
#if defined (USE_IPV6)
		else
		{
			ip6t_write("-i %s -A %s -j %s\n", LAN_DEV_NAME, FILTER_MAC_CHAIN, "DROP");
		}
#endif
	}

}

// 解析域名获取所有IP地址
int resolve_hostname(const char *hostname, char ips[][INET_ADDRSTRLEN], int max_ips) {
    struct addrinfo hints, *result, *rp;
    struct sockaddr_in *addr;
    char ip_str[INET_ADDRSTRLEN];
    int count = 0;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    int ret = getaddrinfo(hostname, NULL, &hints, &result);
    if (ret != 0) {
        char cmd[256];
        char output[1024];
        snprintf(cmd, sizeof(cmd), "nslookup %s 2>/dev/null | grep 'Address' | grep -v '#' | awk '{print $2}'", hostname);
        
        FILE *fp = popen(cmd, "r");
        if (fp) {
            while (count < max_ips && fgets(output, sizeof(output), fp)) {
                output[strcspn(output, "\n")] = 0;
                if (strlen(output) > 0) {
                    strncpy(ips[count], output, INET_ADDRSTRLEN - 1);
                    ips[count][INET_ADDRSTRLEN - 1] = '\0';
                    count++;
                }
            }
            pclose(fp);
        }
        return count;
    }
    
    for (rp = result; rp != NULL && count < max_ips; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET) {
            addr = (struct sockaddr_in *)rp->ai_addr;
            if (inet_ntop(AF_INET, &(addr->sin_addr), ip_str, INET_ADDRSTRLEN)) {
                strncpy(ips[count], ip_str, INET_ADDRSTRLEN - 1);
                ips[count][INET_ADDRSTRLEN - 1] = '\0';
                count++;
            }
        }
    }
    
    freeaddrinfo(result);
    return count;
}

void ipt_filter_url(void)
{
	int i,i_enable;
	int j,ip_count;

	char rules[4096], rule[256], action[16] = {0};

	char url[128];

	Uci_Get_Int(PKG_CSFW_CONFIG, "url", "enable", &i_enable);		//url过滤是否开启

	memset(rules,0,sizeof(rules));
	Uci_Get_Str(PKG_CSFW_CONFIG, "url", "rules",  rules);

	if(i_enable==0 || strlen(rules)==0){
		return;
	}

	ipt_write(":%s - [0:0]\n",FILTER_URL_CHAIN);
	ipt_write("-A FORWARD -i %s -j %s\n", LAN_DEV_NAME, FILTER_URL_CHAIN);

	i=0;

	while (get_nth_val_safe(i++, rules, ' ', rule, sizeof(rule)) != -1 )
	{
		if ((get_nth_val_safe(0, rule, ',', url, sizeof(url)) == -1))
		{
			continue;
		}
		char ips[64][16];
		// 解析域名获取所有IP
		ip_count = resolve_hostname(url, ips, 64);
		if (ip_count <= 0) {
			printf("Failed to resolve hostname: %s\n", url);
			return ;
		}
		printf("Resolved %s to %d IPs\n", url, ip_count);
		// 为每个IP添加防火墙规则
    	for (j = 0; j < ip_count; j++) {
			ipt_write("-A %s -d %s -j DROP\n", FILTER_URL_CHAIN, ips[j]);
		}
	}

}

void ipt_filter_wifi_mac(void)
{
	char rules[4096], rule[128],mac[18];
	int  i,i_num,wifi_idx,acl_mode;
	char tmp_buf[128]={0},action[16]={0};

	wifi_idx = W24G_IF;

	while(1){
		wificonf_get_by_key(wifi_idx, "macfilter", tmp_buf, sizeof(tmp_buf));
		if(strcmp(tmp_buf,"allow")==0){
			acl_mode=1;
		}else if(strcmp(tmp_buf,"deny")==0){
			acl_mode=2;
		}else{
			acl_mode=0;
		}

		memset(rules,0,sizeof(rules));
		wificonf_get_by_key(wifi_idx, "maclist", rules, sizeof(rules));

		if(acl_mode==0 || strlen(rules)==0){
			return;
		}

		if (wifi_idx == W58G_IF)
			goto skip_for;

		ipt_write(":%s - [0:0]\n",FILTER_WIFI_MAC_CHAIN);
		ipt_write("-A FORWARD -i %s -j %s\n", LAN_DEV_NAME, FILTER_WIFI_MAC_CHAIN);

		skip_for:
		if (acl_mode == 1)
		{
			strcpy(action, "ACCEPT");
		}
		else if (acl_mode == 2)
		{
			strcpy(action, "DROP");
		}

		i=0;
		i_num=0;

		while (get_nth_val_safe(i++, rules, ' ', rule, sizeof(rule)) != -1 )
		{
			if ((get_nth_val_safe(0, rule, ',', mac, sizeof(mac)) == -1))
			{
				continue;
			}
			ipt_write("-i %s -I %s -m mac --mac-source %s -j %s\n", \
					LAN_DEV_NAME, FILTER_WIFI_MAC_CHAIN, mac, action);
			i_num++;
		}

		if(i_num > 0 && acl_mode == 0) //whitelist mode
		{
			ipt_write("-i %s -A %s -j %s\n", LAN_DEV_NAME, FILTER_WIFI_MAC_CHAIN, action);
		}

		if(wifi_idx == W58G_IF)
			break;
#if BOARD_HAS_5G_RADIO
		wificonf_get_by_key(W58G_RADIO, "maclist_num", tmp_buf, sizeof(tmp_buf));
		if (atoi(tmp_buf) != 0)
			wifi_idx = W58G_IF;
		else
			break;
#else
		break;
#endif
	}
}



void ipt_filter_blacklist(void)
{
	int i;

	char rules[4096], rule[128];

	char mac[18], type[16] = {0}, timematch[128];

	memset(rules,0,sizeof(rules));
	Uci_Get_Str(PKG_CSFW_CONFIG, "accesslist", "rules", rules);

	if(strlen(rules)==0 || strstr(rules,"black")==NULL){
		return;
	}

	ipt_write(":%s - [0:0]\n",FILTER_BLACKLIST_CHAIN);
	ipt_write("-A FORWARD -i %s -j %s\n", LAN_DEV_NAME, FILTER_BLACKLIST_CHAIN);

	i=0;
	timematch_conv(timematch, NULL, NULL);

	while (get_nth_val_safe(i++, rules, ' ', rule, sizeof(rule)) != -1 )
	{
		if((get_nth_val_safe(1, rule, ';', type, sizeof(type)) == -1))
		{
			continue;
		}

		if(strcmp(type,"black")!=0){
			continue;
		}

		if ((get_nth_val_safe(0, rule, ';', mac, sizeof(mac)) == -1))
		{
			continue;
		}

		ipt_write("-i %s -I %s -m mac --mac-source %s%s -j DROP\n", \
				LAN_DEV_NAME, FILTER_BLACKLIST_CHAIN, mac, timematch);
	}
}

void ipt_filter_parental(void)
{
	int i, i_enable, i_drop;

	char rules[4096], rule[128], action[16] = {0}, mac_list[2048];

	char mac[18], timematch[128], week[64], stime[64], etime[64];

	Uci_Get_Int(PKG_PARENTAL_CONFIG, "parental", "enable", &i_enable);

	memset(rules,0,sizeof(rules));
	memset(mac_list,0,sizeof(mac_list));
	Uci_Get_Str(PKG_PARENTAL_CONFIG, "parental", "rules",  rules);

	if(i_enable==0 || strlen(rules)==0){
		return;
	}

	ipt_write(":%s - [0:0]\n",FILTER_PARENTAL_CHAIN);
	ipt_write("-A FORWARD -i %s -j %s\n", LAN_DEV_NAME, FILTER_PARENTAL_CHAIN);

	i=0;
	while (get_nth_val_safe(i++, rules, ' ', rule, sizeof(rule)) != -1 )
	{
		if ((get_nth_val_safe(0, rule, ';', mac, sizeof(mac)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(2, rule, ';', week, sizeof(week)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(3, rule, ';', stime, sizeof(stime)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(4, rule, ';', etime, sizeof(etime)) == -1))
		{
			continue;
		}

		if (atoi(week) == 0){
			sprintf(week,"%s", "7,1,2,3,4,5,6");
		}

		ipt_write("-I %s -m mac --mac-source %s -m time --weekdays %s --timestart %s --timestop %s -j ACCEPT\n",
						FILTER_PARENTAL_CHAIN, mac, week,stime, etime);

		if(strlen(mac_list)==0){
			strcpy(mac_list,mac);
			ipt_write("-A %s -m mac --mac-source %s -j DROP\n", FILTER_PARENTAL_CHAIN, mac);
		}else if(strstr(mac_list,mac)==NULL){
			strcat(mac_list,";");
			strcat(mac_list,mac);
			ipt_write("-A %s -m mac --mac-source %s -j DROP\n", FILTER_PARENTAL_CHAIN, mac);
		}
	}
}

void filter_ipport_rule(char *write_rule, int len, char *mac,
	char *from_ip1, char *from_ip2, int from_port, int to_port,
	char *to_ip1, char *to_ip2, int d_from_port, int d_to_port,
	int i_proto, int i_action, char *week, char *time)
{
	int  i, i_rc = 0;
	char *p_pos;
	char action[OPTION_STR_LEN] = { 0 }, timematch[TEMP_STR_LEN]   = { 0 };

	p_pos = write_rule;

	switch (i_action)
	{
		case ACTION_DROP:			// 0 == ENABLE--DROP mode
		{
			strcpy(action, "-j DROP");
			break;
		}
		case ACTION_ACCEPT:			// 1 == ENABLE--ACCEPT mode
		{
			strcpy(action, "-j ACCEPT");
			break;
		}
	}

	i_rc = snprintf(p_pos, len-i_rc, "-A %s ", FILTER_IPPORT_CHAIN);
	p_pos = p_pos + i_rc;

	// write source ip
	if(strcmp(from_ip1, "0.0.0.0"))
	{
		i_rc = snprintf(p_pos, len-i_rc, "-s %s ", from_ip1);
		p_pos = p_pos + i_rc;
	}

	// write dest ip
	if(strcmp(to_ip1, "0.0.0.0"))
	{
		i_rc = snprintf(p_pos, len-i_rc, "-d %s ", to_ip1);
		p_pos = p_pos + i_rc;
	}

	// write protocol type
	if (i_proto == PROTO_NONE)
	{
		i_rc = snprintf(p_pos, len-i_rc, " ");
		p_pos = p_pos +i_rc;
	}
	else if (i_proto == PROTO_ICMP)
	{
		i_rc = snprintf(p_pos,  len-i_rc, "-p icmp ");
		p_pos = p_pos + i_rc;
	}
	else
	{
		if (i_proto == PROTO_TCP)
		{
			i_rc = snprintf(p_pos, len-i_rc, "-p tcp ");
		}
		else if (i_proto == PROTO_UDP)
		{
			i_rc = snprintf(p_pos, len-i_rc, "-p udp ");
		}
		p_pos = p_pos + i_rc;

		// write source port
		if (from_port)
		{
			if (to_port)
			{
				i_rc = snprintf(p_pos, len-i_rc, "--sport %d:%d ", from_port, to_port);
			}
			else
			{
				i_rc = snprintf(p_pos, len-i_rc, "--sport %d ", from_port);
			}
			p_pos = p_pos + i_rc;
		}

		// write dest port
		if (d_from_port)
		{
			if (d_to_port)
			{
				i_rc = snprintf(p_pos, len-i_rc, "--dport %d:%d ", d_from_port, d_to_port);
			}
			else
			{
				i_rc = snprintf(p_pos, len-i_rc, "--dport %d ", d_from_port);
			}
			p_pos = p_pos + i_rc;
		}
	}

	timematch_conv(timematch, week, time);

	i_rc = snprintf(p_pos, len-i_rc, "%s", timematch);
	p_pos = p_pos + i_rc;

	i_rc = snprintf(p_pos, len-i_rc, "%s", action);

	return ;
}


void filter_ipport_rule_add_situation(char *write_rule, int len, char *situation_1, char *situation_2)
{
	char situation_1_rule[16], situation_2_rule[16];
	char rule_tmp[128]={0};
	char *p_pos;
	int i_rc=0;

	p_pos = write_rule;

	if(strcmp(situation_1,"WAN") == 0){
		strcpy(situation_1_rule,"-i vap0");
	}else if(strcmp(situation_1,"LAN") == 0){
		strcpy(situation_1_rule,"-i br-lan");
	}else if(strcmp(situation_1,"MODEM") == 0){
		strcpy(situation_1_rule,"-i eth0.2");
	}

	if(strcmp(situation_2,"WAN") == 0){
		strcpy(situation_2_rule,"-o vap0");
	}else if(strcmp(situation_2,"LAN") == 0){
		strcpy(situation_2_rule,"-o br-lan");
	}else if(strcmp(situation_2,"MODEM") == 0){
		strcpy(situation_2_rule,"-o eth0.2");
	}

    sprintf(rule_tmp, "%s", strstr(write_rule,"-A"));

	i_rc = snprintf(p_pos, len-i_rc, "-A %s ", FILTER_IPPORT_CHAIN);
	p_pos = p_pos + i_rc;

	i_rc = snprintf(p_pos, len-i_rc, "%s %s ",situation_1_rule, situation_2_rule);
	p_pos = p_pos + i_rc;

	i_rc = snprintf(p_pos, len-i_rc, "%s", rule_tmp + 3 + strlen(FILTER_IPPORT_CHAIN));
	p_pos = p_pos + i_rc;
}


void ipt_filter_ipport(void)
{
#if 1
	int i=0, i_enable, i_drop=0, i_proto, i_action;
	char rules[4096], rule[128], write_rule[256];
	char s_ipaddr[16],sport_1[8],sport_2[8],d_ipaddr[16],dport_1[8],dport_2[8],situation_1[8],situation_2[8],proto[8];

	char action[OPTION_STR_LEN] = { 0 };

	Uci_Get_Int(PKG_CSFW_CONFIG, "ipport", "drop", &i_drop);
	Uci_Get_Int(PKG_CSFW_CONFIG, "ipport", "enable", &i_enable);

	memset(rules,0,sizeof(rules));
	Uci_Get_Str(PKG_CSFW_CONFIG, "ipport", "rules",  rules);
	Uci_Get_Int(PKG_CSFW_CONFIG, "ipport", "enable", &i_enable);

	if ( i_enable == 0 || strlen(rules) == 0 )
	{
		return ;
	}
	
	Uci_Get_Int(PKG_CSFW_CONFIG, "ipport", "drop", &i_drop);
	if ( i_drop == 0 )
	{
		strcpy(action, "ACCEPT");
	}
	else
	{
		strcpy(action, "DROP");
	}

	ipt_write(":%s - [0:0]\n",      FILTER_IPPORT_CHAIN);
	ipt_write("-A FORWARD -j %s\n", FILTER_IPPORT_CHAIN);

	//rule：ip,sport,eport,dip,dsport,deport,input,output,proto,desc
	while((get_nth_val_safe(i++, rules, ' ', rule, sizeof(rule)) != -1))
	{
		if ((get_nth_val_safe(0, rule, ',', s_ipaddr, sizeof(s_ipaddr)) == -1))
		{
			continue;
		}

		if (!is_ip_valid(s_ipaddr))
		{
			continue;
		}

		if ((get_nth_val_safe(1, rule, ',', sport_1, sizeof(sport_1)) == -1))
		{
			continue;
		}
		else if(atoi(sport_1) > 65535 || atoi(sport_1) < 1)
		{
			continue;
		}

		if ((get_nth_val_safe(2, rule, ',', sport_2, sizeof(sport_2)) == -1))
		{
			continue;
		}
		else if(atoi(sport_2) > 65535 || atoi(sport_2) < 1)
		{
			continue;
		}

		if ((get_nth_val_safe(3, rule, ',', d_ipaddr, sizeof(d_ipaddr)) == -1))
		{
			continue;
		}
		else if (!is_ip_valid(d_ipaddr))
		{
			continue;
		}

		if ((get_nth_val_safe(4, rule, ',', dport_1, sizeof(dport_1)) == -1))
		{
			continue;
		}
		else if(atoi(dport_1) > 65535 || atoi(dport_1) < 1)
		{
			continue;
		}

		if ((get_nth_val_safe(5, rule, ',', dport_2, sizeof(dport_2)) == -1))
		{
			continue;
		}
		else if(atoi(dport_2) > 65535 || atoi(dport_2) < 1)
		{
			continue;
		}

		if ((get_nth_val_safe(6, rule, ',', situation_1, sizeof(situation_1)) == -1))
		{
			continue;
		}

		if ((get_nth_val_safe(7, rule, ',', situation_2, sizeof(situation_2)) == -1))
		{
			continue;
		}
		
		if ((get_nth_val_safe(8, rule, ',', proto, sizeof(proto)) == -1))
		{
			continue;
		}else {
			if(!strcmp(proto, "ALL"))
				i_proto = 3;
			else if (!strcmp(proto, "TCP"))
				i_proto = 1;
			else if (!strcmp(proto, "UDP"))
				i_proto = 2;
		}

		if (i_drop == 0)
		{
			i_action = ACTION_ACCEPT;
		}
		else
		{
			i_action = ACTION_DROP;
		}
		if(!strcmp(proto, "ALL"))
			i_proto = 3;
		else if (!strcmp(proto, "TCP"))
			i_proto = 1;
		else if (!strcmp(proto, "UDP"))
			i_proto = 2;

		switch(i_proto)
		{
			case PROTO_TCP:
			case PROTO_UDP:
			{
				filter_ipport_rule(write_rule, sizeof(write_rule), "", s_ipaddr, "", atoi(sport_1), atoi(sport_2), d_ipaddr, "", atoi(dport_1), atoi(dport_2), i_proto, i_action, "", "");
				filter_ipport_rule_add_situation(write_rule, sizeof(write_rule), situation_1, situation_2);
				ipt_write("%s\n", write_rule);
				filter_ipport_rule(write_rule, sizeof(write_rule), "", d_ipaddr, "", atoi(dport_1), atoi(dport_2), s_ipaddr, "", atoi(sport_1), atoi(sport_2), i_proto, i_action, "", "");
				filter_ipport_rule_add_situation(write_rule, sizeof(write_rule), situation_1, situation_2);
				ipt_write("%s\n", write_rule);
				break;
			}
			case PROTO_TCP_UDP:
			{
				filter_ipport_rule(write_rule, sizeof(write_rule), "", s_ipaddr, "",  atoi(sport_1),  atoi(sport_2), d_ipaddr, "", atoi(dport_1), atoi(dport_2), PROTO_TCP, i_action, "", "");
				filter_ipport_rule_add_situation(write_rule, sizeof(write_rule), situation_1, situation_2);
				ipt_write("%s\n", write_rule);
				
				memset(write_rule, 0, sizeof(write_rule));
				filter_ipport_rule(write_rule, sizeof(write_rule), "", d_ipaddr, "", atoi(dport_1), atoi(dport_2), s_ipaddr, "",  atoi(sport_1),  atoi(sport_2), PROTO_TCP, i_action, "", "");
				filter_ipport_rule_add_situation(write_rule, sizeof(write_rule), situation_1, situation_2);
				ipt_write("%s\n", write_rule);

				memset(write_rule, 0, sizeof(write_rule));
				filter_ipport_rule(write_rule, sizeof(write_rule), "", s_ipaddr, "",  atoi(sport_1),  atoi(sport_2), d_ipaddr, "", atoi(dport_1), atoi(dport_2), PROTO_UDP, i_action, "", "");
				filter_ipport_rule_add_situation(write_rule, sizeof(write_rule), situation_1, situation_2);
				ipt_write("%s\n", write_rule);

				memset(write_rule, 0, sizeof(write_rule));
				filter_ipport_rule(write_rule, sizeof(write_rule), "", d_ipaddr, "", atoi(dport_1), atoi(dport_2), s_ipaddr, "",  atoi(sport_1),  atoi(sport_2), PROTO_UDP, i_action, "", "");
				filter_ipport_rule_add_situation(write_rule, sizeof(write_rule), situation_1, situation_2);
				ipt_write("%s\n", write_rule);
				break;
			}
			default:
			{
				continue;
			}
		}
	}

	if( i_drop == 0 )
	{
		//预留代码
		/* 
		i=0;
		while((get_nth_val_safe(i++, rules, ' ', rule, sizeof(rule)) != -1))
		{
			if ((get_nth_val_safe(3, rule, ',', dip, sizeof(dip)) == -1))
			{
				continue;
			}
			if (!is_ip_valid(dip))
			{
				continue;
			}
			
			get_nth_val_safe(4, rule, ',', dsport, sizeof(dsport));
			get_nth_val_safe(5, rule, ',', deport, sizeof(deport));
			if ( atoi(dsport)<1 || atoi(dsport)> 65535 )
			{
				continue;
			}
			if( atoi(deport)<1 || atoi(deport)> 65535 )
			{
				continue;
			}
			
			if((get_nth_val_safe(8, rule, ',', proto, sizeof(proto)) == -1))
			{
				continue;
			}
			if(!strcmp(proto, "ALL"))
				i_proto = 3;
			else if (!strcmp(proto, "TCP"))
				i_proto = 1;
			else if (!strcmp(proto, "UDP"))
				i_proto = 2;
			
			switch(i_proto)
			{
				case PROTO_TCP:
				{
					ipt_write("-A %s -p tcp -s %s --sport %s:%s -j ACCEPT\n", FILTER_IPPORT_CHAIN, dip, dsport, deport);
					break;
				}
				case PROTO_UDP:
				{
					ipt_write("-A %s -p udp -s %s --sport %s:%s -j ACCEPT\n", FILTER_IPPORT_CHAIN, dip, dsport, deport);
					break;
				}
				case PROTO_TCP_UDP:
				{
					ipt_write("-A %s -p tcp -s %s --sport %s:%s -j ACCEPT\n", FILTER_IPPORT_CHAIN, dip, dsport, deport);
					ipt_write("-A %s -p udp -s %s --sport %s:%s -j ACCEPT\n", FILTER_IPPORT_CHAIN, dip, dsport, deport);
					break;
				}
				default:
				{
					break;
				}
			}
		}
		*/
		ipt_write("-A %s  -j %s\n", FILTER_IPPORT_CHAIN, "DROP");
	}
#endif
}


static int domain_to_hex_string(char *domain, char *restult_domain)
{
	int i = 0;
	char string[128], tmp_domain[256], tmp_buf[128];

	bzero(string, sizeof(string));
	bzero(tmp_domain, sizeof(tmp_domain));
	bzero(tmp_buf, sizeof(tmp_buf));

	while(get_nth_val_safe(i++, domain, '.', string, sizeof(string)) != -1)
	{
		if(strlen(string) == 0)
			continue;

		if(strlen(tmp_domain))
		{
			sprintf(tmp_buf,"|%02x|%s",(unsigned int)strlen(string),string);
			strcat(tmp_domain,tmp_buf);
		}
		else
		{
			sprintf(tmp_domain,"|%02x|%s",(unsigned int)strlen(string),string);
		}
		bzero(string, sizeof(string));
		bzero(tmp_buf, sizeof(tmp_buf));
	}
	strcpy(restult_domain,tmp_domain);

	return 0;
}

void ipt_filter_dmz(void)
{

#if 1
	int enable=0, num=0, i=0;
	char sRules[4096]={0}, rule[128]={0};
	char sip[16]={0}, port[16]={0}, ifname[16]={0}, wan_if[16]={0}, modem_if[16]={0};	
	
	Uci_Get_Int(PKG_CSFW_CONFIG, "dmz", "enable", &enable);
	Uci_Get_Int(PKG_CSFW_CONFIG, "dmz", "num", &num);
	Uci_Get_Str(PKG_CSFW_CONFIG, "dmz", "rules",  sRules);
	if( !fw_status.up || enable==0 || num==0 || strlen(sRules)==0 )
	{
		return;
	}

	ipt_write(":%s - [0:0]\n", FILTER_DMZ_CHAIN);
	ipt_write("-A FORWARD -j %s\n", FILTER_DMZ_CHAIN);

	//ifname,eip,sip,sec
	Uci_Get_Str(PKG_NETWORK_CONFIG, "wan", "device",  wan_if);	
	Uci_Get_Str(PKG_NETWORK_CONFIG, "wan_modem", "device",	modem_if);
	while ( get_nth_val_safe(i++, sRules, ' ', rule, sizeof(rule)) != -1 )
	{
		if(get_nth_val_safe(0, rule, ',', port, sizeof(port))==-1)
		{
			continue;
		}
		if( strcmp(port, "MODEM")==0)
		{
			strcpy(ifname, modem_if);
		}else
		{
			strcpy(ifname, wan_if);
		}
		
		if(get_nth_val_safe(2, rule, ',', sip, sizeof(sip))==-1)
		{
			continue;
		}
		if (!is_ip_valid(sip))
		{
			continue;
		}

		//-A cs_filter_dmz -i eth0.3 -d sip -p ALL -j ACCEP		数据包到达此链时，已经经过nat转换了
		ipt_write("-A %s -i %s -d %s -p ALL -j ACCEPT\n", FILTER_DMZ_CHAIN, fw_status.device, sip);
	}

#else
	int enable=0;

	char rules[4096], rule[128];
	char iface[16],host[24],lan_ipaddr[24];

	Uci_Get_Int(PKG_CSFW_CONFIG, "dmz", "enable", &enable);

	if(!enable){
		return;
	}

	ipt_write(":%s - [0:0]\n", FILTER_DMZ_CHAIN);
	ipt_write("-A FORWARD -j %s\n", FILTER_DMZ_CHAIN);

	Uci_Get_Str(PKG_CSFW_CONFIG, "dmz", "host",  host);
	ipt_write("-A %s -i %s -d %s -p ALL -j ACCEPT\n", FILTER_DMZ_CHAIN, fw_status.device, host);
#endif
	flush_conntrack_table(NULL);
}

void ipt_filter_wanping(void)
{
	int enable=0;

	Uci_Get_Int(PKG_CSFW_CONFIG, "vpn", "wanping", &enable);

	ipt_write(":%s - [0:0]\n", FILTER_WANPING_CHAIN);
	ipt_write("-A INPUT -j %s\n", FILTER_WANPING_CHAIN);

	if (!enable)
	{
		ipt_write("-A %s -i %s -p icmp --icmp-type 8 -j DROP\n",  FILTER_WANPING_CHAIN, fw_status.device);
		ipt_write("-A %s -i %s -p icmp --icmp-type 0 -j ACCEPT\n", FILTER_WANPING_CHAIN, fw_status.device);
	}
	else
	{
		ipt_write("-A %s -i %s -p icmp -j ACCEPT\n", FILTER_WANPING_CHAIN, fw_status.device);
	}

}

void ipt_filter_vpnpass(void)
{
	int l2tp_en=0, pptp_en=0, ipsec_en=0, il2tpd_en=0, iipsec_en=0;
	int sswan_ipsec_en=0;
	
	Uci_Get_Int(PKG_CSFW_CONFIG, "vpn", "l2tp",  &l2tp_en);
	Uci_Get_Int(PKG_CSFW_CONFIG, "vpn", "pptp",  &pptp_en);
	Uci_Get_Int(PKG_CSFW_CONFIG, "vpn", "ipsec", &ipsec_en);
	Uci_Get_Int(PKG_L2TPD_CONFIG, "xl2tpd", "enable", &il2tpd_en);
	Uci_Get_Int(PKG_L2TPD_CONFIG, "xl2tpd", "ipsec_l2tp_enable", &iipsec_en);

	Uci_Get_Int(PKG_IPSEC_CONFIG, "net2net", "enable", &sswan_ipsec_en);
	if(sswan_ipsec_en == 0)
		Uci_Get_Int(PKG_IPSEC_CONFIG, "host2net", "enable", &sswan_ipsec_en);

	ipt_write(":%s - [0:0]\n", FILTER_VPNPASS_CHAIN);
	ipt_write("-A FORWARD -j %s\n", FILTER_VPNPASS_CHAIN);

	ipt_write(":%s - [0:0]\n", FILTER_PPP_INPUT_CHAIN);
	ipt_write("-A INPUT -j %s\n", FILTER_PPP_INPUT_CHAIN);

	ipt_write(":%s - [0:0]\n", FILTER_PPP_FORWARD_CHAIN);
	ipt_write("-I FORWARD -j %s\n", FILTER_PPP_FORWARD_CHAIN);

	ipt_write(":%s - [0:0]\n", FILTER_IPSEC_CHAIN);
	ipt_write("-I INPUT -j %s\n", FILTER_IPSEC_CHAIN);
	
	if(il2tpd_en)
	{	
		ipt_write("-A %s -i ppp+ -j ACCEPT\n", FILTER_PPP_INPUT_CHAIN);
		ipt_write("-A %s -p udp --dport 1701 -j ACCEPT\n", FILTER_PPP_INPUT_CHAIN);

		ipt_write("-A %s -i ppp+ -j ACCEPT\n", FILTER_PPP_FORWARD_CHAIN);
		//ipt_write("-A %s -i ppp+ -j ACCEPT\n", FILTER_PPP_OUTPUT_CHAIN);
	}

	if(iipsec_en == 0 && sswan_ipsec_en == 1){
		ipt_write("-A %s -p 50 -j ACCEPT\n", FILTER_IPSEC_CHAIN);//esp
		ipt_write("-A %s -p 51 -j ACCEPT\n", FILTER_IPSEC_CHAIN);//ah
		ipt_write("-A %s -p udp --sport 500 --dport 500 -j ACCEPT\n", FILTER_IPSEC_CHAIN);
		ipt_write("-A %s -p udp --sport 4500 --dport 4500 -j ACCEPT\n", FILTER_IPSEC_CHAIN);
		
		ipt_write("-A %s -i ipsec0 -j ACCEPT\n", FILTER_IPSEC_CHAIN);
	}
	
	if (ipsec_en)
	{
		ipt_write("-A %s -p 50 -j ACCEPT\n", FILTER_VPNPASS_CHAIN);
		ipt_write("-A %s -p 51 -j ACCEPT\n",   FILTER_VPNPASS_CHAIN);
		ipt_write("-A %s -p 108 -j ACCEPT\n",  FILTER_VPNPASS_CHAIN);
		ipt_write("-A %s -p udp --sport 500 --dport 500 -j ACCEPT\n",  FILTER_VPNPASS_CHAIN);
		ipt_write("-A %s -p udp --sport 4500 --dport 4500 -j ACCEPT\n",FILTER_VPNPASS_CHAIN);

		if(iipsec_en)
		{
			ipt_write("-A %s -p 50 -j ACCEPT\n", FILTER_IPSEC_CHAIN);//esp
			ipt_write("-A %s -p 51 -j ACCEPT\n", FILTER_IPSEC_CHAIN);//ah
			ipt_write("-A %s -p udp --sport 500 --dport 500 -j ACCEPT\n", FILTER_IPSEC_CHAIN);
			ipt_write("-A %s -p udp --sport 4500 --dport 4500 -j ACCEPT\n", FILTER_IPSEC_CHAIN);
			
			ipt_write("-A %s -i ipsec0 -j ACCEPT\n", FILTER_IPSEC_CHAIN);
		}
		
	}
	else
	{
		ipt_write("-A %s -p udp --sport 500 --dport 500 -j DROP\n",  FILTER_VPNPASS_CHAIN);
		ipt_write("-A %s -p udp --sport 4500 --dport 4500 -j DROP\n",FILTER_VPNPASS_CHAIN);
	}

	if (pptp_en)
	{
		ipt_write("-A %s -p 47 -j ACCEPT\n", FILTER_VPNPASS_CHAIN);
		ipt_write("-A %s -p tcp --dport 1723 -j ACCEPT\n", FILTER_VPNPASS_CHAIN);
		ipt_write("-A %s -p tcp --sport 1723 -j ACCEPT\n", FILTER_VPNPASS_CHAIN);
	}
	else
	{
		ipt_write("-A %s -p 47 -j DROP\n", FILTER_VPNPASS_CHAIN);
		ipt_write("-A %s -p tcp --dport 1723 -j DROP\n", FILTER_VPNPASS_CHAIN);
		ipt_write("-A %s -p tcp --sport 1723 -j DROP\n", FILTER_VPNPASS_CHAIN);
	}

	if (l2tp_en)
	{   
		ipt_write("-A %s -p tcp --dport 1701 -j ACCEPT\n", FILTER_VPNPASS_CHAIN);
		ipt_write("-A %s -p udp --dport 1701 -j ACCEPT\n", FILTER_VPNPASS_CHAIN);
	}
	else
	{
		ipt_write("-A %s -p tcp --dport 1701 -j DROP\n", FILTER_VPNPASS_CHAIN);
		ipt_write("-A %s -p udp --dport 1701 -j DROP\n", FILTER_VPNPASS_CHAIN);
	}

}

void ipt_filter_remote_access(void)
{
	int enable=0, port;
	char lanIp[16]={0};

	Uci_Get_Int(PKG_CSFW_CONFIG, "remote", "enable", &enable);

	Uci_Get_Int(PKG_CSFW_CONFIG, "remote", "port", &port);

	ipt_write(":%s - [0:0]\n",    FILTER_REMOTE_ACCESS_CHAIN);
	ipt_write("-A INPUT -j %s\n", FILTER_REMOTE_ACCESS_CHAIN);

	if (enable == 0)
	{
		//deny remote access http
		ipt_write("-A %s -i %s -p tcp --dport 80 -j DROP\n", FILTER_REMOTE_ACCESS_CHAIN, fw_status.device);
	}
	else
	{
		if (port != 80) {
			get_ifname_ipaddr("br-lan", lanIp);
			ipt_write("-I %s -p tcp -d %s --dport %d -j ACCEPT\n", FILTER_REMOTE_ACCESS_CHAIN, lanIp, 80);
			ipt_write("-A %s -i %s -p tcp --dport 80 -j DROP\n", FILTER_REMOTE_ACCESS_CHAIN, fw_status.device);
		}else
			ipt_write("-A %s -i %s -p tcp --dport 80 -j ACCEPT\n", FILTER_REMOTE_ACCESS_CHAIN, fw_status.device);
	}

	//always deny telnet access from wan
	ipt_write("-A %s -i %s -p tcp --dport 23 -j DROP\n",  FILTER_REMOTE_ACCESS_CHAIN, fw_status.device);

}


void ipt_filter_port_forward(void)
{
	int  enable, i=0, num;

	char rules[4096]={0}, rule[256];

	char ipaddr[16], lan_port[8];

	Uci_Get_Int(PKG_CSFW_CONFIG, "portfw", "enable",  &enable);
	Uci_Get_Int(PKG_CSFW_CONFIG, "portfw", "num",  &num);

	if(enable==0 || num==0 || !fw_status.up){
		return ;
	}

	ipt_write(":%s - [0:0]\n", FILTER_PORT_FORWARD_CHAIN);
	ipt_write("-A FORWARD -j %s\n", FILTER_PORT_FORWARD_CHAIN);

	Uci_Get_Str(PKG_CSFW_CONFIG, "portfw", "rules",   rules);

	memset(lan_port,0,sizeof(lan_port));

	while ((get_nth_val_safe(i++, rules, ' ', rule, sizeof(rule)) != -1))
	{
		// get ip address
		if ((get_nth_val_safe(0, rule, ',', ipaddr, sizeof(ipaddr)) == -1))
		{
			continue;
		}

		if (!is_ip_valid(ipaddr))
		{
			continue;
		}

		// get lan port
		if ((get_nth_val_safe(2, rule, ',', lan_port, sizeof(lan_port)) == -1))
		{
			continue;
		}
		if(atoi(lan_port)<1 || atoi(lan_port)>65535){
			continue;
		}

		ipt_write("-A %s -p tcp -i %s --dport %s -j ACCEPT\n", FILTER_PORT_FORWARD_CHAIN, fw_status.device,lan_port);

		ipt_write("-A %s -p udp -i %s --dport %s -j ACCEPT\n", FILTER_PORT_FORWARD_CHAIN, fw_status.device,lan_port);

		ipt_write("-A %s -p 47 -i %s -j ACCEPT\n", FILTER_PORT_FORWARD_CHAIN, fw_status.device);

	}

}

void ipt_filter_guest_wifi(void)
{
	int  flag=0, wl_idx;

	char allow_access[8];

	doSystem("ebtables -F");

	for(wl_idx=W24G_G1;wl_idx<=W58G_G4;wl_idx++)
	{
		if(wl_idx>W24G_G4 && wl_idx<W58G_G1)
		{
			continue;
		}
		wificonf_get_by_key(wl_idx,  "allow_access",	allow_access, sizeof(allow_access));
		if(strcmp(allow_access,"1") != 0){
			doSystem("ebtables -A FORWARD -i %s -o eth0 -j DROP", WL_IF[wl_idx].ifname);
			doSystem("ebtables -A INPUT -p ipv4 -i %s -j mark --set-mark 2 --mark-target CONTINUE", WL_IF[wl_idx].ifname);
			flag = 1;
		}
	}

	if(flag == 0){
		return;
	}

	ipt_write(":%s - [0:0]\n",    FILTER_GUEST_WIFI_CHAIN);
	ipt_write("-I INPUT -j %s\n", FILTER_GUEST_WIFI_CHAIN);
	ipt_write("-I %s -p tcp -m mark --mark 2  -j DROP\n", FILTER_GUEST_WIFI_CHAIN);
}

void ipt_filter_igmp(void)
{
	int mr_enable;

	Uci_Get_Int(PKG_NETWORK_CONFIG, "iptv", "mrEnable", &mr_enable);

	if(!mr_enable){
		return;
	}

	ipt_write(":%s - [0:0]\n", FILTER_IGMP_INPUT_CHAIN);
	ipt_write("-A INPUT -j %s\n", FILTER_IGMP_INPUT_CHAIN);
	ipt_write("-A %s -i %s -p udp -d 224.0.0.0/4 ! --dport 1900 -j ACCEPT\n", FILTER_IGMP_INPUT_CHAIN, fw_status.device);
	ipt_write("-A %s -i %s -d 224.0.0.0/4 -p 2 -j ACCEPT\n", FILTER_IGMP_INPUT_CHAIN, fw_status.device);

	ipt_write(":%s - [0:0]\n", FILTER_IGMP_FORWARD_CHAIN);
	ipt_write("-A FORWARD -j %s\n", FILTER_IGMP_FORWARD_CHAIN);
	ipt_write("-A %s -i %s -d 224.0.0.0/4 -p udp -j ACCEPT\n", FILTER_IGMP_FORWARD_CHAIN, fw_status.device);

}

#if defined(CONFIG_USER_FAST_NAT)
void ipt_filter_hnat(void)
{
	int enable, smart_qos_enable,smart_qos_num;
	char mapmode[8]={0};

	Uci_Get_Int(PKG_CSFW_CONFIG, "firewall",  "hwnat_enable", &enable);
	Uci_Get_Int(PKG_QOS_CONFIG,   "smartqos", "enable", &smart_qos_enable);
	Uci_Get_Int(PKG_QOS_CONFIG,   "iplimit",  "num", &smart_qos_num);
	wificonf_get_by_key(W24G_MH, "mapmode", mapmode, sizeof(mapmode));

	if(enable==0 || atoi(mapmode)==1 || (smart_qos_enable==1 && smart_qos_num>0))
	{
		system("echo 0 > /sys/kernel/debug/hnat/hook_toggle");
	}
	else
	{
		system("echo 1 > /sys/kernel/debug/hnat/hook_toggle");
	}
}
#endif

#if defined(CONFIG_TR069_SUPPORT)
void ipt_filter_tr069_input(void)
{
	int enable, http_port;

	Uci_Get_Int(PKG_ICWMP_CONFIG, "acs", "enable", &enable);

	Uci_Get_Int(PKG_ICWMP_CONFIG, "cpe", "port", &http_port);

	if(enable==0 || (http_port<1 || http_port > 65535)){
		return;
	}

	ipt_write(":%s - [0:0]\n", FILTER_TR069_INPUT_CHAIN);
	ipt_write("-I INPUT -j %s\n", FILTER_TR069_INPUT_CHAIN);

	ipt_write("-A %s -i %s -p tcp --dport %d -j ACCEPT\n", FILTER_TR069_INPUT_CHAIN, fw_status.device, http_port);
}
#endif

void ipt_filter_rules(void)
{
#if defined(CONFIG_TR069_SUPPORT)
	ipt_filter_tr069_input();
#endif

	ipt_filter_mac(0);

	ipt_filter_wifi_mac();

	ipt_filter_blacklist();

	ipt_filter_parental();

	ipt_filter_ipport();

	ipt_filter_dmz();

	ipt_filter_wanping();

	ipt_filter_vpnpass();

	ipt_filter_port_forward();

	ipt_filter_igmp();

	ipt_filter_spi();

	ipt_filter_remote_access();

	ipt_filter_url();

	ipt_filter_dos();

	// ipt_filter_guest_wifi();

#if defined(CONFIG_USER_FAST_NAT)
	ipt_filter_hnat();
#endif
}

#if defined(CONFIG_IPV6_FIREWALL_SUPPORT)
void ip6t_filter_ipport(void)
{
	int i=0, i_enable, i_drop=0, i_proto;
	char rules[4096]={0}, rule[128], write_rule[256];

	char remote_ipaddr[128], loacal_ipaddr[64], remote_pre_len[8];
	char proto[8], port[24];

	memset(rules,0,sizeof(rules));
	Uci_Get_Int(PKG_CSFW_CONFIG, "ipport_ipv6", "enable", &i_enable);
	Uci_Get_Str(PKG_CSFW_CONFIG, "ipport_ipv6", "rules",  rules);

	if (i_enable == 0 || strlen(rules) == 0)
	{
		return ;
	}

	ip6t_write(":%s - [0:0]\n",        FILTER6_IPPORT_INPUT_CHAIN);
	ip6t_write("-A INPUT -j %s\n",     FILTER6_IPPORT_INPUT_CHAIN);

	ip6t_write(":%s - [0:0]\n",        FILTER6_IPPORT_FORWARD_CHAIN);
	ip6t_write("-A FORWARD -j %s\n",   FILTER6_IPPORT_FORWARD_CHAIN);

	while ((get_nth_val_safe(i++, rules, ' ', rule, sizeof(rule)) != -1))
	{
		if ((get_nth_val_safe(0, rule, ',', remote_ipaddr, sizeof(remote_ipaddr)) == -1))
		{
			continue;
		}

		if (!is_ip6_valid(remote_ipaddr))
		{
			continue;
		}

		if ((get_nth_val_safe(1, rule, ',', remote_pre_len, sizeof(remote_pre_len)) == -1))
		{
			continue;
		}

		if ((get_nth_val_safe(2, rule, ',', loacal_ipaddr, sizeof(loacal_ipaddr)) == -1))
		{
			continue;
		}

		if (!is_ip6_valid(loacal_ipaddr))
		{
			continue;
		}

		if ((get_nth_val_safe(3, rule, ',', port, sizeof(port)) == -1))
		{
			continue;
		}
		/*
		if (atoi(port)> 65535 || atoi(port)< 0)
		{
			continue;
		}*/

		if ((get_nth_val_safe(4, rule, ',', proto, sizeof(proto)) == -1))
		{
			continue;
		}
		if(!strcmp(proto, "ALL"))
		{	
			i_proto = 3;
		}
		else if (!strcmp(proto, "TCP"))
		{
			i_proto = 1;
			strcpy(proto,"tcp");
		}
		else if (!strcmp(proto, "UDP"))
		{
			i_proto = 2;
			strcpy(proto,"udp");
		}
		else
		{
			continue;
		}

		switch(i_proto)
		{
			case PROTO_TCP:
			case PROTO_UDP:
			{
				ip6t_write("-A %s -s %s/%s -d %s -p %s --dport %s  -j ACCEPT\n",\
					FILTER6_IPPORT_INPUT_CHAIN, remote_ipaddr, remote_pre_len, loacal_ipaddr, proto, port);

				ip6t_write("-A %s -s %s -d %s/%s -p %s -j ACCEPT\n",\
					FILTER6_IPPORT_FORWARD_CHAIN, loacal_ipaddr, remote_ipaddr, remote_pre_len, proto);
				break;
			}
			case PROTO_TCP_UDP:
			{
				ip6t_write("-A %s -s %s/%s -d %s -p tcp --dport %s  -j ACCEPT\n",\
					FILTER6_IPPORT_INPUT_CHAIN, remote_ipaddr, remote_pre_len, loacal_ipaddr, port);
				ip6t_write("-A %s -s %s/%s -d %s -p udp --dport %s  -j ACCEPT\n",\
					FILTER6_IPPORT_INPUT_CHAIN, remote_ipaddr, remote_pre_len, loacal_ipaddr, port);

				ip6t_write("-A %s -s %s -d %s/%s -p tcp -j ACCEPT\n",\
					FILTER6_IPPORT_FORWARD_CHAIN, loacal_ipaddr, remote_ipaddr, remote_pre_len);
				ip6t_write("-A %s -s %s -d %s/%s -p udp -j ACCEPT\n",\
					FILTER6_IPPORT_FORWARD_CHAIN, loacal_ipaddr, remote_ipaddr, remote_pre_len);
				break;
			}
			default:
			{
				continue;
			}
		}
	}

	//ip6t_write("-A %s -i %s -j %s\n", FILTER6_IPPORT_INPUT_CHAIN, fw_status.device, "DROP");
	//ip6t_write("-A %s -i %s -j %s\n", FILTER6_IPPORT_FORWARD_CHAIN, "br-lan", "DROP");

}

void ip6t_filter_icmpv6(void)
{
	int enable=0;

	Uci_Get_Int(PKG_CSFW_CONFIG, "vpn", "icmpv6", &enable);

	ip6t_write(":%s - [0:0]\n", FILTER6_ICMPV6_CHAIN);
	ip6t_write("-A INPUT -j %s\n", FILTER6_ICMPV6_CHAIN);

	if (!enable)
	{
		ip6t_write("-A %s -i %s -p ipv6-icmp -m icmp6 --icmpv6-type 8 -j DROP\n",   FILTER6_ICMPV6_CHAIN, fw_status.device);
		ip6t_write("-A %s -i %s -p ipv6-icmp -m icmp6 --icmpv6-type 0 -j ACCEPT\n", FILTER6_ICMPV6_CHAIN, fw_status.device);
	}
	else
	{
		ip6t_write("-A %s -i %s -p ipv6-icmp -j ACCEPT\n", FILTER6_ICMPV6_CHAIN, fw_status.device);
	}
}

void ip6t_filter_rules(void)
{
	ipt_filter_mac(1);

	ip6t_filter_ipport();

	ip6t_filter_icmpv6();
}
#endif

