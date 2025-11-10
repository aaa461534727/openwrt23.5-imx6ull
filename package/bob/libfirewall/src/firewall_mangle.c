

void ipt_mangle_smart_qos(void)
{
	int enable	= 0;

	int dpi_mark_num = 1000;				// 1000-49999 identify MARK for dpi application
											// 50000-65535 is the online ip rule MARK

	Uci_Get_Int(PKG_QOS_CONFIG, "smartqos", "enable", &enable);

	if(enable==0){
		return ;
	}

	ipt_write(":%s - [0:0]\n",      MANGLE_SMARTQOS_CHAIN);
	ipt_write(":%s - [0:0]\n",      MANGLE_QOS_INGRESS_CHAIN);
	ipt_write(":%s - [0:0]\n",      MANGLE_QOS_EGRESS_CHAIN);

	ipt_write("-A FORWARD -j %s\n",  MANGLE_SMARTQOS_CHAIN);
	ipt_write("-A %s -i %s -j %s\n", MANGLE_SMARTQOS_CHAIN, fw_status.device, MANGLE_QOS_INGRESS_CHAIN);
	ipt_write("-A %s -o %s -j %s\n", MANGLE_SMARTQOS_CHAIN, fw_status.device, MANGLE_QOS_EGRESS_CHAIN);

	ipt_write("-A %s -m length --length 0:256 -j MARK --set-mark 0x%x/0xffff\n", MANGLE_QOS_INGRESS_CHAIN, dpi_mark_num);
	ipt_write("-A %s -m length --length 0:256 -j MARK --set-mark 0x%x/0xffff\n", MANGLE_QOS_EGRESS_CHAIN,  dpi_mark_num);

	ipt_write("-A %s -m hashspeed --hashspeed-name iprate --wanif %s -j RETURN\n", MANGLE_QOS_INGRESS_CHAIN, fw_status.device);
	ipt_write("-A %s -m hashspeed --hashspeed-name iprate --wanif %s -j RETURN\n", MANGLE_QOS_EGRESS_CHAIN,  fw_status.device);

	ipt_write("-A %s -m length --length 0:128 -j RETURN\n", MANGLE_QOS_INGRESS_CHAIN);
	ipt_write("-A %s -m length --length 0:128 -j RETURN\n", MANGLE_QOS_EGRESS_CHAIN);

	ipt_write("-A %s -j DROP\n", MANGLE_QOS_INGRESS_CHAIN);
	ipt_write("-A %s -j DROP\n", MANGLE_QOS_EGRESS_CHAIN);

}

void ipt_mangle_igmp(void)
{
	int mr_enable,mr_qleave;

	Uci_Get_Int(PKG_NETWORK_CONFIG, "iptv", "mrEnable", &mr_enable);
	Uci_Get_Int(PKG_NETWORK_CONFIG, "iptv", "mrQleave", &mr_qleave);

	if(!mr_enable){
		return;
	}

	if(mr_qleave == 2 || mr_qleave == 3){
		doSystem("echo %d > /proc/sys/net/ipv4/conf/all/force_igmp_version",mr_qleave);
	}
	else{
		doSystem("echo 0 > /proc/sys/net/ipv4/conf/all/force_igmp_version");
	}

	ipt_write(":%s - [0:0]\n", MANGLE_IGMP_CHAIN);
	ipt_write("-A PREROUTING -j %s\n", MANGLE_IGMP_CHAIN);
	ipt_write("-A %s -i %s -d 224.0.0.0/4 -p udp -j TTL --ttl-inc 1\n", MANGLE_IGMP_CHAIN, fw_status.device);

}

void ipt_mangle_ttl(void)
{
	int ttl_way=0;

	Uci_Get_Int(PKG_NETWORK_CONFIG, "wan", "ttl_way", &ttl_way);

	if(ttl_way==0 || strcmp(fw_status.proto,"pppoe")!=0)
		return;

	ipt_write(":%s - [0:0]\n", MANGLE_TTL_CHAIN);
	ipt_write("-A PREROUTING -j %s\n", MANGLE_TTL_CHAIN);
	ipt_write("-A %s -i %s -m ttl --ttl-lt 2 -j TTL --ttl-set 64\n", MANGLE_TTL_CHAIN, fw_status.device);
}

//-j TCPMSS --clamp-mss-to-pmtu
void ipt_mangle_mtu(void)
{
	ipt_write(":%s - [0:0]\n", MANGLE_MTU_CHAIN);
	ipt_write("-A FORWARD -j %s\n", MANGLE_MTU_CHAIN);
	ipt_write("-A %s -p tcp --syn -o %s -j TCPMSS --clamp-mss-to-pmtu\n", MANGLE_MTU_CHAIN, fw_status.device);
}

//---------------------------------------------------------------------------------------------------------
void ipt_mangle_rules(void)
{
	ipt_mangle_smart_qos();

	ipt_mangle_igmp();
	ipt_mangle_ttl();
	ipt_mangle_mtu();
}
