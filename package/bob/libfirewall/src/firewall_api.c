
//------------------------------------私有函数----------------------------------------
int ipt_fopen(void)
{
	if ((ipt_file = fopen(ipt_fname, "w")) == NULL) {
		notice_set("iptables", "Unable to create iptables restore file");
		return -1;
	}

	return 0;
}

void ipt_write(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vfprintf(ipt_file, format, args);
	va_end(args);
}

void ipt_fclose(void)
{
	if(ipt_file) {
		fclose(ipt_file);
		ipt_file = NULL;
	}
}

int ipt_restore(void)
{
	int ret;
	char s[512];
	char *iptrestore_argv[] = { "iptables-restore", (char *)ipt_fname, NULL };
	
	doSystem("rm -f %s.error", ipt_fname);

	notice_set("iptables", "");
	ret = _eval(iptrestore_argv, ">/var/notice/iptables", 0, NULL);
	if (ret == 0) {
		notice_set("iptables", "");
	} else {
		sprintf(s, "%s.error", ipt_fname);
		rename(ipt_fname, s);
		syslog(LOG_CRIT, "Error while loading rules. See %s file.", s);
	}

	return ret;
}

#if defined(USE_IPV6)
int ip6t_fopen(void)
{
	if ((ip6t_file = fopen(ip6t_fname, "w")) == NULL) {
		notice_set("ip6tables", "Unable to create ip6tables restore file");
		return -1;
	}

	return 0;
}

void ip6t_write(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vfprintf(ip6t_file, format, args);
	va_end(args);
}

void ip6t_fclose(void)
{
	if(ip6t_file) {
		fclose(ip6t_file);
		ip6t_file = NULL;
	}
}

int ip6t_restore(void)
{
	int ret;
	char s[512];
	char *ip6trestore_argv[] = { "ip6tables-restore", (char *)ip6t_fname, NULL };

	notice_set("ip6tables", "");
	ret = _eval(ip6trestore_argv, ">/var/notice/ip6tables", 0, NULL);
	if(ret == 0) {
		notice_set("ip6tables", "");
	} else {
		sprintf(s, "%s.error", ip6t_fname);
		rename(ip6t_fname, s);
		syslog(LOG_CRIT, "Error while loading rules. See %s file.", s);
	}

	return ret;
}
#endif

//-----------------------------------------公有函数---------------------------------------------------------
void set_ipv4_forward(int is_on)
{
	/*
		ip_forward - BOOLEAN
			0 - disabled (default)
			not 0 - enabled

			Forward Packets between interfaces.

			This variable is special, its change resets all configuration
			parameters to their default state (RFC1122 for hosts, RFC1812
			for routers)
	*/
	f_write_string("/proc/sys/net/ipv4/ip_forward", (is_on) ? "1" : "0", 0, 0);
}

void set_nfct_helper(int is_on)
{
	f_write_string("/proc/sys/net/netfilter/nf_conntrack_helper", (is_on) ? "1" : "0", 0, 0);
}

/* 清除某个ip的conntrack缓存 */
void flush_conntrack_table(char *ip)
{
	if (!ip)
		ip = "f"; // flush all table
	f_write_string("/proc/net/nf_conntrack", ip, 0, 0);
}

/* 清除路由表缓存，用于3.6内核之前的版本 */
void flush_route_caches(void)
{
	doSystem("ip route flush cache");
}

/* 清除某个dev的路由表规则 */
void clear_if_route4(char *ifname)
{
	doSystem("ip route flush dev %s scope %s", ifname, "global");
}
