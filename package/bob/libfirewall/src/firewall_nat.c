
#if defined(CONFIG_CRPC_SUPPORT)
void ipt_nat_crpc_rules(void)
{
	char secondipaddr[24]={0}, secondnetmask[24]={0}, lan_ipaddr[24]={0};

	Uci_Get_Str(PKG_NETWORK_CONFIG,"lan","secondipaddr", secondipaddr);
	Uci_Get_Str(PKG_NETWORK_CONFIG,"lan","secondnetmask",secondnetmask);
	get_ifname_ipaddr(LAN_DEV_NAME, lan_ipaddr);
	
	if(!is_ip_valid(secondipaddr) || !is_ip_valid(lan_ipaddr) || !is_netmask_valid(secondnetmask)){
		return;
	}

	ipt_write(":%s - [0:0]\n", NAT_CRPC_FIND_CHAIN);
	ipt_write("-A PREROUTING -i br-lan -j %s\n", NAT_CRPC_FIND_CHAIN);

	ipt_write("-A %s -d %s/%d -j DNAT --to-destination %s\n",\
		NAT_CRPC_FIND_CHAIN,secondipaddr,mask_string2num(secondnetmask),lan_ipaddr);
}
#endif

void ipt_nat_remote_access(void)
{
	int  port, enable;
	char lan_ipaddr[24]={0};

	get_ifname_ipaddr(LAN_DEV_NAME, lan_ipaddr);
	if(!is_ip_valid(lan_ipaddr))
		return;

	Uci_Get_Int(PKG_CSFW_CONFIG, "remote", "port",    &port);

	Uci_Get_Int(PKG_CSFW_CONFIG, "remote", "enable",  &enable);

	if(enable==0){
		return ;
	}

	ipt_write(":%s - [0:0]\n", NAT_REMOTE_ACCESS_CHAIN);
	ipt_write("-A PREROUTING -j %s\n", NAT_REMOTE_ACCESS_CHAIN);

	ipt_write("-A %s -i %s -p tcp --dport %d -j DNAT --to-destination %s:80\n", NAT_REMOTE_ACCESS_CHAIN, fw_status.device, port, lan_ipaddr);

	ipt_write("-A %s -i br-lan -p tcp -d %s --dport %d -j DNAT --to-destination %s:80\n",\
			NAT_REMOTE_ACCESS_CHAIN,fw_status.ipaddr_v4,port, lan_ipaddr);
}


void ipt_nat_port_forward(void)
{
	int  enable, num, i = 0, protocol_flag;
	char protocol[RESULT_STR_LEN] = { 0 };
	char rules[4096] = { 0 }, rule[256] = { 0 };
	char lan_ipaddr[24] = { 0 }, lan_mask[24] = { 0 }, rule_enable[24] = { 0 };
	char ipaddr[16] = { 0 }, wan_port[8] = { 0 }, lan_port[8] = { 0 };

	Uci_Get_Int(PKG_CSFW_CONFIG, "portfw", "enable",  &enable);
	Uci_Get_Int(PKG_CSFW_CONFIG, "portfw", "num",  &num);

	if(enable == 0 || num == 0 || !fw_status.up)
	{
		return ;
	}

	ipt_write(":%s - [0:0]\n", NAT_PORTFW_PRE_CHAIN);
	ipt_write("-A PREROUTING -j %s\n", NAT_PORTFW_PRE_CHAIN);

	ipt_write(":%s - [0:0]\n", NAT_PORTFW_POST_CHAIN);
	ipt_write("-A POSTROUTING -j %s\n", NAT_PORTFW_POST_CHAIN);

	Uci_Get_Str(PKG_CSFW_CONFIG, "portfw", "rules",   rules);

	memset(wan_port,0,sizeof(wan_port));
	memset(lan_port,0,sizeof(lan_port));

	get_ifname_ipaddr(LAN_DEV_NAME, lan_ipaddr);
	get_ifname_mask(LAN_DEV_NAME, lan_mask);

	while((get_nth_val_safe(i++, rules, ' ', rule, sizeof(rule)) != -1))
	{
		/* get ip address */
		if((get_nth_val_safe(0, rule, ',', rule_enable, sizeof(rule_enable)) == -1))
		{
			continue;
		}
		if(atoi(rule_enable) == 0) {
			continue;
		}
		
		if((get_nth_val_safe(1, rule, ',', ipaddr, sizeof(ipaddr)) == -1))
		{
			continue;
		}

		if(!is_ip_valid(ipaddr))
		{
			continue;
		}

		if((get_nth_val_safe(2, rule, ',', protocol, sizeof(protocol)) == -1))
		{
			continue;
		}

		/* get lan port */
		if((get_nth_val_safe(3, rule, ',', lan_port, sizeof(lan_port)) == -1))
		{
			continue;
		}

		if(strcmp(ipaddr, "0.0.0.0") == 0) {
			continue;
		}

		if(atoi(lan_port) < 1 || atoi(lan_port) > 65535)
		{
			continue;
		}

		/* get wan port */
		if((get_nth_val_safe(4, rule, ',', wan_port, sizeof(wan_port)) == -1))
		{
			continue;
		}

		if(atoi(wan_port) < 1 || atoi(wan_port) > 65535)
		{
			continue;
		}

		if(strcmp(protocol, "TCP") == 0)
		{
			protocol_flag = 0; /* tcp */
		}
		else if(strcmp(protocol, "UDP") == 0)
		{
			protocol_flag = 1; /* udp */
		}
		else if(strcmp(protocol, "ALL") == 0)
		{
			protocol_flag = 3; /* all */
		}

		/* PREROUTING */
		if(protocol_flag == 0 || protocol_flag == 3)
		{
			//dbg("protocol is : %s\n", protocol);
			ipt_write("-A %s -p tcp -d %s --dport %s -j DNAT --to %s:%s\n", NAT_PORTFW_PRE_CHAIN, \
			      fw_status.ipaddr_v4,wan_port, ipaddr,lan_port);
		}

		if(protocol_flag == 1 || protocol_flag == 3)
		{
			//dbg("protocol is : %s\n", protocol);
			ipt_write("-A %s -p udp -d %s --dport %s -j DNAT --to %s:%s\n", NAT_PORTFW_PRE_CHAIN, \
			      fw_status.ipaddr_v4,wan_port, ipaddr,lan_port);
		}

		ipt_write("-A %s -p 47 -i %s -d %s -j DNAT --to %s \n", NAT_PORTFW_PRE_CHAIN, fw_status.device, fw_status.ipaddr_v4,ipaddr);

		/* POSTROUTING */
		if(protocol_flag == 0 || protocol_flag == 3)
		{
			//dbg("protocol is : %s\n", protocol);
			ipt_write("-A %s -p tcp -s %s/%d -d %s --dport %s -j SNAT --to %s\n",\
				NAT_PORTFW_POST_CHAIN,lan_ipaddr,mask_string2num(lan_mask), ipaddr, lan_port, fw_status.ipaddr_v4);
		}

		if(protocol_flag == 1 || protocol_flag == 3)
		{
			//dbg("protocol is : %s\n", protocol);
			ipt_write("-A %s -p udp -s %s/%d -d %s --dport %s -j SNAT --to %s\n",\
				NAT_PORTFW_POST_CHAIN,lan_ipaddr,mask_string2num(lan_mask), ipaddr, lan_port, fw_status.ipaddr_v4);
		}

		ipt_write("-A %s -p 47 -s %s/%d -d %s -j SNAT --to %s\n",\
			NAT_PORTFW_POST_CHAIN,lan_ipaddr,mask_string2num(lan_mask), ipaddr, fw_status.ipaddr_v4);
	}
}

enum {
	DNAT=0,
	SNAT
};

void get_portmapp_interface(char *src, char *out)
{
	
	if(strcmp(src, "WAN") == 0){
		Uci_Get_Str(PKG_NETWORK_CONFIG, "wan", "device", out);
	}
	else if(strcmp(src, "modem") == 0){
		Uci_Get_Str(PKG_NETWORK_CONFIG, "wan_modem", "device", out);
	}
	else if(strcmp(src, "sslvpn") == 0){
		f_read_string("/tmp/sslvpn_status", out, sizeof(out));
		str_del_char_bak(out, '\n');
		str_del_char_bak(out, '\r');
	}
}

void ipt_nat_port_mapping(void)
{
	int enable=0, num=0, i=0, j=0, protocol_flag=0;
	char iface[16]={0}, cmd[256]={0};
	char rules[4096] = { 0 }, rule[256] = { 0 };
	char natType[RESULT_STR_LEN]={0};
	char oAddress[OPTION_STR_LEN]={0};
	char addressType[RESULT_STR_LEN]={0};
	char mAddress[RESULT_STR_LEN]={0};
	char mPort[RESULT_STR_LEN]={0},oPort[RESULT_STR_LEN]={0},protocol[RESULT_STR_LEN]={0};
	
	Uci_Get_Int(PKG_CSFW_CONFIG, "rnat", "enable",  &enable);
	Uci_Get_Int(PKG_CSFW_CONFIG, "rnat", "num",  &num);

	if(enable == 0 || num == 0 || !fw_status.up)
	{
		return ;
	}

	ipt_write(":%s - [0:0]\n", NAT_PORTMAPP_PRE_CHAIN);
	ipt_write("-A PREROUTING -j %s\n", NAT_PORTMAPP_PRE_CHAIN);

	ipt_write(":%s - [0:0]\n", NAT_PORTMAPP_POST_CHAIN);
	ipt_write("-A POSTROUTING -j %s\n", NAT_PORTMAPP_POST_CHAIN);

	Uci_Get_Str(PKG_CSFW_CONFIG, "rnat", "rules",   rules);

	while((get_nth_val_safe(i++, rules, ' ', rule, sizeof(rule)) != -1))
	{
		if(strstr(rule, ":") !=NULL)//ipv6 rules
			continue;

		if((get_nth_val_safe(0, rule, ',', addressType, sizeof(addressType)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(1, rule, ',', mAddress, sizeof(mAddress)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(2, rule, ',', mPort, sizeof(mPort)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(3, rule, ',', natType, sizeof(natType)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(4, rule, ',', oAddress, sizeof(oAddress)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(5, rule, ',', oPort, sizeof(oPort)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(6, rule, ',', protocol, sizeof(protocol)) == -1))
		{
			continue;
		}

		if(strcasecmp(protocol, "tcp") == 0)
		{
			protocol_flag = 0; /* tcp */
		}
		else if(strcasecmp(protocol, "udp") == 0)
		{
			protocol_flag = 1; /* udp */
		}
		else if(strcasecmp(protocol, "all") == 0)
		{
			protocol_flag = 3; /* all */
		}

		if(strstr(oPort, "-") != NULL){
			for(j=0; j < strlen(oPort); j++){
				if(oPort[j] == '-'){
					oPort[j]=':';
					break;
				}
			}
		}
		
		if(strcmp(addressType, "interface") == 0){
			if(atoi(natType) == DNAT){
				if(!is_ip_valid(mAddress))
				{
					continue;
				}
				
				get_portmapp_interface(oAddress, iface);
				
				if(protocol_flag == 0 || protocol_flag == 3){
					ipt_write("-A %s -p tcp -i %s --dport %s -j DNAT --to-destination %s:%s\n", NAT_PORTMAPP_PRE_CHAIN, \
			     		 iface,oPort, mAddress, mPort);
				}	

				if(protocol_flag == 1 || protocol_flag){
					ipt_write("-A %s -p udp -i %s --dport %s -j DNAT --to-destination %s:%s\n", NAT_PORTMAPP_PRE_CHAIN, \
			     		 iface, oPort, mAddress, mPort);
				}
					
			}else{
				if(!is_ip_valid(oAddress))
				{
					continue;
				}

				get_portmapp_interface(mAddress, iface);
				
				if(protocol_flag == 0 || protocol_flag == 3){
					ipt_write("-A %s -p tcp -s %s --sport %s -o %s -j MASQUERADE --to-ports %s\n", NAT_PORTMAPP_POST_CHAIN, \
			     		 oAddress, oPort, iface, mPort);
				}	

				if(protocol_flag == 1 || protocol_flag){
					ipt_write("-A %s -p udp -s %s --sport %s -o %s -j MASQUERADE --to-ports %s\n", NAT_PORTMAPP_POST_CHAIN, \
			     		 oAddress, oPort, iface, mPort);
				}
			}
				
		}
		else{
			if(atoi(natType) == DNAT){
				if(!is_ip_valid(mAddress))
				{
					continue;
				}
				
				if(protocol_flag == 0 || protocol_flag == 3){
					ipt_write("-A %s -p tcp -d %s --dport %s -j DNAT --to-destination %s:%s\n", NAT_PORTMAPP_PRE_CHAIN, \
			     		 oAddress, oPort, mAddress, mPort);
				}	

				if(protocol_flag == 1 || protocol_flag){
					ipt_write("-A %s -p udp -d %s --dport %s -j DNAT --to-destination %s:%s\n", NAT_PORTMAPP_PRE_CHAIN, \
			     		 oAddress, oPort, mAddress, mPort);
				}
					
			}else{
				if(!is_ip_valid(oAddress))
				{
					continue;
				}
								
				if(protocol_flag == 0 || protocol_flag == 3){
					ipt_write("-A %s -p tcp -s %s --sport %s -j SNAT --to-source %s:%s\n", NAT_PORTMAPP_POST_CHAIN, \
			     		 oAddress, oPort, mAddress, mPort);
				}	

				if(protocol_flag == 1 || protocol_flag){
					ipt_write("-A %s -p udp -s %s --sport %s -j SNAT --to-source %s:%s\n", NAT_PORTMAPP_POST_CHAIN, \
			     		 oAddress, oPort, mAddress, mPort);
				}
			}
		}
	}

	return ;
}

void ipt_nat_dmz(void)
{

#if 1//工业DMZ
	/*	
		/etc/config/csfw
		config rule 'dmz'
				option wanIdx '1'
				list rules 'WAN,10.0.200.152,192.168.0.222,'
				list rules 'MODEM,10.5.6.7,192.168.0.111,'
				option num '2'
				option enable '1'
	*/	
	
	int  enable, num=0, i=0;
	char sRules[4096]={0}, rule[256]={0};
	char port[8]={0}, destIp[SHORT_STR_LEN]={0}, srcIp[SHORT_STR_LEN]={0};
	char ifname[16]={0}, modem_if[16]={0}, wan_if[16]={0};

	Uci_Get_Int(PKG_CSFW_CONFIG, "dmz", "enable", &enable);
	Uci_Get_Int(PKG_CSFW_CONFIG, "dmz", "num", &num);
	Uci_Get_Str(PKG_CSFW_CONFIG, "dmz", "rules",  sRules);
	if( !fw_status.up || enable==0 || num==0 || strlen(sRules)==0 ){
		return ;
	}
	
	ipt_write(":%s - [0:0]\n", NAT_DMZ_PRE_CHAIN);
	ipt_write("-A PREROUTING -j %s\n", NAT_DMZ_PRE_CHAIN);

	ipt_write(":%s - [0:0]\n", NAT_DMZ_POST_CHAIN);
	ipt_write("-I POSTROUTING -j %s\n", NAT_DMZ_POST_CHAIN);

	Uci_Get_Str(PKG_NETWORK_CONFIG, "wan", "device",  fw_status.device);	
	Uci_Get_Str(PKG_NETWORK_CONFIG, "wan_modem", "device",  modem_if);
	while( get_nth_val_safe(i++, sRules, ' ', rule, sizeof(rule)) != -1 )
	{
		if((get_nth_val_safe(0, rule, ',', port, sizeof(port)) == -1))
		{
			continue;
		}
		if( strcmp(port, "MODEM")==0 )

		{
			strcpy(ifname, modem_if);
		}else{
			strcpy(ifname, wan_if);	
		}
		
		if((get_nth_val_safe(1, rule, ',', destIp, sizeof(destIp)) == -1))
		{
			continue;
		}
		if (!is_ip_valid(destIp))
		{
			continue;
		}

		if((get_nth_val_safe(2, rule, ',', srcIp, sizeof(srcIp)) == -1))
		{
			continue;
		}
		if (!is_ip_valid(srcIp))
		{
			continue;
		}
		
		ipt_write("-A %s -i %s -d %s -j DNAT --to-destination %s\n", NAT_DMZ_PRE_CHAIN, fw_status.device, destIp, srcIp);
		ipt_write("-A %s -s %s -d %s -j ACCEPT\n", NAT_DMZ_POST_CHAIN, srcIp, destIp);
		ipt_write("-A %s -i br-lan -d %s -j SNAT --to %s\n", NAT_DMZ_POST_CHAIN, srcIp, destIp);
	}
#else//家用DMZ

	int  enable;
	char host[24]={0}, lan_ipaddr[24], lan_mask[24];

	Uci_Get_Int(PKG_CSFW_CONFIG, "dmz", "enable",  &enable);
	if(enable==0 || !fw_status.up){
		return ;
	}
	ipt_write(":%s - [0:0]\n", NAT_DMZ_PRE_CHAIN);
	ipt_write("-A PREROUTING -j %s\n", NAT_DMZ_PRE_CHAIN);

	ipt_write(":%s - [0:0]\n", NAT_DMZ_POST_CHAIN);
	ipt_write("-I POSTROUTING -j %s\n", NAT_DMZ_POST_CHAIN);

	get_ifname_ipaddr(LAN_DEV_NAME, lan_ipaddr);
	get_ifname_mask(LAN_DEV_NAME, lan_mask);
	ipt_write("-A %s -s %s -d %s -j ACCEPT\n", NAT_DMZ_POST_CHAIN, lan_ipaddr, host);
	ipt_write("-A %s -i br-lan -d %s/%d -j SNAT --to %s\n",\
			NAT_DMZ_POST_CHAIN,lan_ipaddr,mask_string2num(lan_mask),fw_status.ipaddr_v4);
#endif

}

void ipt_nat_wireguard(void)
{
	int clinet,server;

	Uci_Get_Int(PKG_NETWORK_CONFIG, "wg0", "disabled", &server);
	Uci_Get_Int(PKG_NETWORK_CONFIG, "wg1", "disabled", &clinet);


	if(clinet == 1)
	{
		ipt_write("-A POSTROUTING -o wg1 -j MASQUERADE\n");
	}
	else if(server == 1)
	{
		ipt_write("-A POSTROUTING -o wg0 -j MASQUERADE\n");
	}

}

void ipt_nat_sslvpn(void)
{
	int  enable;
	char mapping_terminal[64]={0},vpn_ip[64]={0},ifname[32]={0};
	
	Uci_Get_Int(PKG_SSLVPN_CONFIG, "ssl", "enabled",  &enable);
	Uci_Get_Str(PKG_SSLVPN_CONFIG, "ssl", "mapping_terminal", mapping_terminal);

	if(enable==0){
		return ;
	}
	
	f_read_string("/tmp/sslvpn_status", ifname, sizeof(ifname));

	str_del_char_bak(ifname, '\n');
	str_del_char_bak(ifname, '\r');
	get_ifname_ipaddr(ifname, vpn_ip);
	

	if(strlen(ifname) && is_ip_valid(vpn_ip)==1)
	{
		//ipt_write("-D POSTROUTING -o tun+ -j MASQUERADE\n");
		ipt_write("-A POSTROUTING -o tun+ -j MASQUERADE\n");
		
		if(is_ip_valid(mapping_terminal)==1){
			//ipt_write("-D PREROUTING -j DNAT -d %s --to-destination %s\n",vpn_ip,mapping_terminal);
			ipt_write("-A PREROUTING -j DNAT -d %s --to-destination %s\n",vpn_ip,mapping_terminal);
		}
	}
}



//---------------------------------------------------------------------------------------------------------
void ipt_nat_rules(void)
{
	char nat_enable[8] = {0};
#if defined(CONFIG_CRPC_SUPPORT)
		//crpc find
		ipt_nat_crpc_rules();
#endif

	if(is_firewall_effect<=0){
		return;
	}
	Uci_Get_Str(PKG_CSFW_CONFIG, "firewall", "nat_enable", nat_enable);

	if(strlen(nat_enable) < 1 || atoi(nat_enable) == 1){
		//ipv4 MASQUERADE
		ipt_write(":%s - [0:0]\n",NAT_MASQUERADE_CHAIN);
		ipt_write("-A POSTROUTING -j %s\n", NAT_MASQUERADE_CHAIN);
		ipt_write("-A %s -o %s -j MASQUERADE\n",  NAT_MASQUERADE_CHAIN, fw_status.device);
	}
	
	ipt_nat_sslvpn();

	ipt_nat_remote_access();

	ipt_nat_port_forward();

	ipt_nat_port_mapping();

	ipt_nat_dmz();


}
//-------------------------------IPV4 END--------------------------------------------------------------------
#if defined (USE_IPV6)
//-------------------------------IPV6 Start------------------------------------------------------------------
int is_ip6_valid(char *str)
{
  struct in6_addr addr;

  if(str==NULL || strlen(str) < 2)
	  return 0;

  if(!strcmp("any/0", str))
	  return 1;

  if(! (inet_pton(AF_INET6 ,str, &addr))){
	  dbg("%s is not a valid IPv6 address.\n", str);
	  return 0;
  }
  return 1;
}

void ipt6_nat_port_mapping(void)
{
	int enable=0, num=0, i=0, j=0, protocol_flag=0;
	char iface[16]={0}, cmd[256]={0};
	char rules[4096] = { 0 }, rule[256] = { 0 };
	char natType[RESULT_STR_LEN]={0};
	char oAddress[OPTION_STR_LEN]={0};
	char addressType[RESULT_STR_LEN]={0};
	char mAddress[RESULT_STR_LEN]={0};
	char mPort[RESULT_STR_LEN]={0},oPort[RESULT_STR_LEN]={0},protocol[RESULT_STR_LEN]={0};
	
	Uci_Get_Int(PKG_CSFW_CONFIG, "rnat", "enable",  &enable);
	Uci_Get_Int(PKG_CSFW_CONFIG, "rnat", "num",  &num);

	if(enable == 0 || num == 0 /* || !fw_status.up */)
	{
		return ;
	}

	ip6t_write(":%s - [0:0]\n", NAT_PORTMAPP_PRE_CHAIN);
	ip6t_write("-A PREROUTING -j %s\n", NAT_PORTMAPP_PRE_CHAIN);

	ip6t_write(":%s - [0:0]\n", NAT_PORTMAPP_POST_CHAIN);
	ip6t_write("-A POSTROUTING -j %s\n", NAT_PORTMAPP_POST_CHAIN);

	Uci_Get_Str(PKG_CSFW_CONFIG, "rnat", "rules",   rules);

	while((get_nth_val_safe(i++, rules, ' ', rule, sizeof(rule)) != -1))
	{
		if(strstr(rule, ":") ==NULL)//ipv4 rules
			continue;
		
		if((get_nth_val_safe(0, rule, ',', protocol, sizeof(protocol)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(1, rule, ',', addressType, sizeof(addressType)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(2, rule, ',', natType, sizeof(natType)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(3, rule, ',', oAddress, sizeof(oAddress)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(4, rule, ',', oPort, sizeof(oPort)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(5, rule, ',', mAddress, sizeof(mAddress)) == -1))
		{
			continue;
		}

		if((get_nth_val_safe(6, rule, ',', mPort, sizeof(mPort)) == -1))
		{
			continue;
		}

		if(strcasecmp(protocol, "TCP") == 0)
		{
			protocol_flag = 0; /* tcp */
		}
		else if(strcasecmp(protocol, "UDP") == 0)
		{
			protocol_flag = 1; /* udp */
		}
		else if(strcasecmp(protocol, "ALL") == 0)
		{
			protocol_flag = 3; /* all */
		}

		if(strstr(oPort, "-") != NULL){
			for(j=0; j < strlen(oPort); j++){
				if(oPort[j] == '-'){
					oPort[j]=':';
					break;
				}
			}
		}
		
		if(strcmp(addressType, "interface") == 0){
			if(atoi(natType) == DNAT){
				if(!is_ip6_valid(mAddress))
				{
					continue;
				}
				
				get_portmapp_interface(oAddress, iface);
				
				if(protocol_flag == 0 || protocol_flag == 3){
					ip6t_write("-A %s -p tcp -i %s --dport %s -j DNAT --to-destination [%s]:%s\n", NAT_PORTMAPP_PRE_CHAIN, \
			     		 "tun0",oPort, mAddress, mPort);
				}	

				if(protocol_flag == 1 || protocol_flag){
					ip6t_write("-A %s -p udp -i %s --dport %s -j DNAT --to-destination [%s]:%s\n", NAT_PORTMAPP_PRE_CHAIN, \
			     		 "tun0", oPort, mAddress, mPort);
				}
					
			}else{
				if(!is_ip6_valid(oAddress))
				{
					continue;
				}

				get_portmapp_interface(mAddress, iface);
				
				if(protocol_flag == 0 || protocol_flag == 3){
					ip6t_write("-A %s -p tcp -s %s --sport %s -o %s -j MASQUERADE --to-ports %s\n", NAT_PORTMAPP_POST_CHAIN, \
			     		 oAddress, oPort, iface, mPort);
				}	

				if(protocol_flag == 1 || protocol_flag){
					ip6t_write("-A %s -p udp -s %s --sport %s -o %s -j MASQUERADE --to-ports %s\n", NAT_PORTMAPP_POST_CHAIN, \
			     		 oAddress, oPort, iface, mPort);
				}
			}
				
		}
		else{
			if(atoi(natType) == DNAT){
				if(!is_ip6_valid(mAddress))
				{
					continue;
				}
				
				if(protocol_flag == 0 || protocol_flag == 3){
					ip6t_write("-A %s -p tcp -d %s --dport %s -j DNAT --to-destination [%s]:%s\n", NAT_PORTMAPP_POST_CHAIN, \
			     		 oAddress, oPort, mAddress, mPort);
				}	

				if(protocol_flag == 1 || protocol_flag){
					ip6t_write("-A %s -p udp -d %s --dport %s -j DNAT --to-destination [%s]:%s\n", NAT_PORTMAPP_POST_CHAIN, \
			     		 oAddress, oPort, mAddress, mPort);
				}
					
			}else{
				if(!is_ip6_valid(oAddress))
				{
					continue;
				}
								
				if(protocol_flag == 0 || protocol_flag == 3){
					ip6t_write("-A %s -p tcp -s %s --sport %s -j SNAT --to-source [%s]:%s\n", NAT_PORTMAPP_POST_CHAIN, \
			     		 oAddress, oPort, mAddress, mPort);
				}	

				if(protocol_flag == 1 || protocol_flag){
					ip6t_write("-A %s -p udp -s %s --sport %s -j SNAT --to-source [%s]:%s\n", NAT_PORTMAPP_POST_CHAIN, \
			     		 oAddress, oPort, mAddress, mPort);
				}
			}
		}
	}

	return ;
}

void ip6_nat_rules(void)
{
	ipt6_nat_port_mapping();
}
#endif