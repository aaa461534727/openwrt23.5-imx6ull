
#include "libfirewall.h"
#include "libfirewall_private.h"

#include "firewall_api.c"
//nat table
#include "firewall_nat.c"
//filter table
#include "firewall_filter.c"
//mangle table
#include "firewall_mangle.c"
//host_filter
#include "host_filter.c"


struct interface_status fw_status;
int is_firewall_effect=0;

#if defined(CONFIG_IPV6_FIREWALL_SUPPORT)
struct interface_status fw_ipv6_status;
int is_ipv6_firewall_effect=0;
#endif

void init_global_param(void)
{
	// get_wan_status(&fw_status);
	fw_status.up=1;
	strcpy(fw_status.proto,"static");
	strcpy(fw_status.device,"vap0");
	get_ifname_ipaddr(fw_status.device, fw_status.ipaddr_v4);
	get_ifname_mask(fw_status.device, fw_status.mask_v4);
	strcpy(fw_status.gateway_v4,"10.0.200.1");
	
	is_firewall_effect=fw_status.up;

#if defined(CONFIG_IPV6_FIREWALL_SUPPORT)
	get_interface_status(&fw_ipv6_status,"wan6");
	is_ipv6_firewall_effect=fw_ipv6_status.up;
#endif

	// set_timezone_to_kernel();
}

//----------------------------------------------------------------------------------------------
static void ipt_raw_table(void)
{
	ipt_write(
		"*raw\n"
		":PREROUTING ACCEPT [0:0]\n"
		":OUTPUT ACCEPT [0:0]\n"
	);

	ipt_write("COMMIT\n");
}

static void ipt_mangle_table(void)
{
	ipt_write(
		"*mangle\n"
		":PREROUTING ACCEPT [0:0]\n"
		":INPUT ACCEPT [0:0]\n"
		":FORWARD ACCEPT [0:0]\n"
		":OUTPUT ACCEPT [0:0]\n"
		":POSTROUTING ACCEPT [0:0]\n"
	);

	if(is_firewall_effect>0){
		ipt_mangle_rules();
	}

	ipt_write("COMMIT\n");
}

static void ipt_nat_table(void)
{
	ipt_write(
		"*nat\n"
		":PREROUTING ACCEPT [0:0]\n"
		":INPUT ACCEPT [0:0]\n"
		":OUTPUT ACCEPT [0:0]\n"
		":POSTROUTING ACCEPT [0:0]\n"
	);

	ipt_nat_rules();

	ipt_write("COMMIT\n");
}

static void ipt_filter_table(void)
{
   //1.设置INPUT FORWARD OUTPUT的默认规则
	ipt_write(
		"*filter\n"
		":INPUT ACCEPT [0:0]\n"
		":FORWARD ACCEPT [0:0]\n"
		":OUTPUT ACCEPT [0:0]\n"
	);

	if(is_firewall_effect>0){
		ipt_filter_rules();
	}

	ipt_write("COMMIT\n");
}

#if defined (USE_IPV6)
static void ip6t_mangle_table(void)
{
	ip6t_write(
		"*mangle\n"
		":PREROUTING ACCEPT [0:0]\n"
		":INPUT ACCEPT [0:0]\n"
		":FORWARD ACCEPT [0:0]\n"
		":OUTPUT ACCEPT [0:0]\n"
		":POSTROUTING ACCEPT [0:0]\n"
	);

	ip6t_write("COMMIT\n");
}

static void ip6t_filter_table(void)
{
	ip6t_write(
		"*filter\n"
		":INPUT ACCEPT [0:0]\n"
		":FORWARD ACCEPT [0:0]\n"
		":OUTPUT ACCEPT [0:0]\n"
	);
#if defined(CONFIG_IPV6_FIREWALL_SUPPORT)
	if(is_ipv6_firewall_effect>0){
		ip6t_filter_rules();
	}
#endif
	ip6t_write("COMMIT\n");
}

static void ip6t_nat_table(void)
{
	char web_status[SHORT_STR_LEN]={0};
	Uci_Get_Str(PKG_NETWORK_CONFIG,"wan6","web_status",web_status);

	ip6t_write(
		"*nat\n"
		":PREROUTING ACCEPT [0:0]\n"
		":INPUT ACCEPT [0:0]\n"
		":OUTPUT ACCEPT [0:0]\n"
		":POSTROUTING ACCEPT [0:0]\n"
	);

	if(strcmp("nat66", web_status) == 0)
	{
		ip6t_write("-A POSTROUTING -j MASQUERADE\n");
		ip6_nat_rules();
	}

	ip6t_write("COMMIT\n");
}
#endif

static int
__start_firewall(void)
{
	if(ipt_fopen() < 0)
		return -1;
#if defined(USE_IPV6)
	if(ip6t_fopen() < 0) {
		ipt_fclose();
		return -2;
	}
#endif

	/* IPv4 Raw rules */
	ipt_raw_table();
	
	/* IPv4 Mangle rules */
	ipt_mangle_table();

	/* IPv4 NAT rules */
	ipt_nat_table();

	/* IPv4 Filter rules */
	ipt_filter_table();

#if defined (USE_IPV6)
	/* IPv6 Mangle rules */
	ip6t_mangle_table();

	ip6t_nat_table();

	/* IPv6 Filter rules */
	ip6t_filter_table();
#endif

	ipt_fclose();
#if defined(USE_IPV6)
	ip6t_fclose();
#endif

	if(ipt_restore() !=0)
		return -3;
#if defined(USE_IPV6)
	if(ip6t_restore() !=0)
		return -4;
#endif
	return 0;
}

int reload_smartqos_module(void)
{
	int enable	= 0;

	Uci_Get_Int(PKG_QOS_CONFIG, "smartqos", "enable", &enable);

	system("iptables -t mangle -F mangle_qos_ingress");
	system("iptables -t mangle -F mangle_qos_egress");

	if(is_module_loaded("xt_hashspeed")){
		system("rmmod xt_hashspeed");
	}

	if(enable==1){
		module_smart_load("xt_hashspeed", NULL);
	}

	return 0;
}

int start_smartqos(void)
{
	int enable	= 0;

	Uci_Get_Int(PKG_QOS_CONFIG, "smartqos", "enable", &enable);

	doSystem("tc qdisc del dev %s root", fw_status.device);

	doSystem("tc qdisc del dev %s root", "ifb0");

	if(f_exists("/proc/1/net/ipt_hashspeed/iprate")){
		doSystem("echo / > /proc/1/net/ipt_hashspeed/iprate");
	}

	doSystem("killall -9 smartqos");

	if(enable==0){
		return 0;
	}

	doSystem("/usr/bin/smartqos &");

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
		return;

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

int start_firewall(void)
{
	int lock, ret;
	char only_restart_url[8]={0};
	char opmode_custom[8]={0}, sta_ipaddr[16]={0};

	datconf_get_by_key(TEMP_STATUS_FILE, "only_restart_url", only_restart_url, sizeof(only_restart_url));

	if(atoi(only_restart_url)){
		//dpi_filter_url();
		datconf_set_by_key(TEMP_STATUS_FILE, "only_restart_url", "0");
		return 0;
	}

	init_global_param();

	reload_smartqos_module();

	lock = file_lock("firewall");

	ret = __start_firewall();
	if(ret == 0) {

#if 0
		module_smart_load("ibms_dpi", NULL);
		dpi_filter_rules();
#endif
		//dpi_filter_url();

		/* enable IPv4 forward */
		set_ipv4_forward(1);

		/* 启用nat透传，帮助pptp和ftp等应用穿透nat */
		set_nfct_helper(1);
	}

	/* 执行自定义的防火墙脚本，可用于特殊情况下补刀 */
	if (f_exists(SCRIPT_FIREWALL))
		doSystem("%s", SCRIPT_FIREWALL);

	file_unlock(lock);

	Uci_Get_Str(PKG_SYSTEM_CONFIG, "opmode", "opmode_custom", opmode_custom);
	if(strcmp(opmode_custom,"gw")==0 || strcmp(opmode_custom,"wisp")==0){
		start_smartqos();
	}

	wanup_set_ipv6_gw();

	//system("/etc/init.d/miniupnpd restart");

#if defined(APP_QUAGGA)
	CsRealReloadRouterQuagga();
#endif


	return ret;
}

int stop_firewall(void)
{
	int lock;

	lock = file_lock("firewall");

#if 0
	dpi_filter_flush();
	module_smart_unload("ibms_dpi", 0);
#endif

	file_unlock(lock);

	return 0;
}
