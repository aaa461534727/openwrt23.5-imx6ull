#include <libdatconf.h>

#include <sys/sysinfo.h>

#include "cs_common.h"


#define  ETH_PORT_WAN  4
#define  ETH_PORT_LAN1  1
#define  ETH_PORT_LAN2  2
#define  ETH_PORT_LAN3  3
#define  ETH_PORT_LAN4  4
#define  ETH_PORT_LAN5  5
WLAN_TABLE WL_IF[]={
	{"wifi-device", "radio_2g",        "band",   "2.4G"},
	{"wifi-iface",  "main_2g",         "ifname", "ra0"},
	{"wifi-iface",  "mesh_2g",         "ifname", "ra1"},
	{"wifi-iface",  "guest_2g1",       "ifname", "ra2"},
	{"wifi-iface",  "guest_2g2",       "ifname", "ra3"},
	{"wifi-iface",  "guest_2g3",       "ifname", "ra4"},
	{"wifi-iface",  "guest_2g4",       "ifname", "ra5"},
	{"wifi-device", "radio_5g",        "band",   "5G"},
	{"wifi-iface",  "main_5g",         "ifname", "rax0"},
	{"wifi-iface",  "mesh_5g",         "ifname", "rax1"},
	{"wifi-iface",  "guest_5g1",       "ifname", "rax2"},
	{"wifi-iface",  "guest_5g2",       "ifname", "rax3"},
	{"wifi-iface",  "guest_5g3",       "ifname", "rax4"},
	{"wifi-iface",  "guest_5g4",       "ifname", "rax5"},
	{"wifi-iface",  "apcli",           "ifname", "wlan-sta"},
	{"", 0, NULL, 0},
};

PRODUCT_PARAM_TABLE product_param[]={
	{PKG_PRODUCT_CONFIG, "sysinfo",          "soft_model"},
	{PKG_PRODUCT_CONFIG, "sysinfo",          "hard_model"},
	{PKG_PRODUCT_CONFIG, "custom",           "cloudupdate_domain"},
	{PKG_PRODUCT_CONFIG, "custom",           "telnetd_password"},
	{PKG_PRODUCT_CONFIG, "custom",           "hide_logo"},
	{PKG_PRODUCT_CONFIG, "custom",           "copyright"},
	{PKG_PRODUCT_CONFIG, "custom",           "domainaccess"},
	{PKG_PRODUCT_CONFIG, "custom",           "hostname"},
	{PKG_PRODUCT_CONFIG, "custom",           "web_title"},
	{PKG_PRODUCT_CONFIG, "custom",           "vendor"},
	{PKG_PRODUCT_CONFIG, "custom",           "helpurl_cn"},
	{PKG_PRODUCT_CONFIG, "custom",           "helpurl_en"},
	{PKG_PRODUCT_CONFIG, "custom",           "helpurl_ct"},
	{PKG_PRODUCT_CONFIG, "custom",           "helpurl_ru"},
	{PKG_PRODUCT_CONFIG, "custom",           "helpurl_vi"},
	{PKG_PRODUCT_CONFIG, "custom",           "helpurl_vn"},
	
	//wireless
	{PKG_PRODUCT_CONFIG, "custom",           "fixed_mac"},
	{PKG_PRODUCT_CONFIG, "custom",           "ssid_2g"},
	{PKG_PRODUCT_CONFIG, "custom",           "wlankey_2g"},
	{PKG_PRODUCT_CONFIG, "custom",           "country_2g"},
	{PKG_PRODUCT_CONFIG, "custom",           "htmode_2g"},
	{PKG_PRODUCT_CONFIG, "custom",           "channel_2g"},
	{PKG_PRODUCT_CONFIG, "custom",           "maxsta_2g"},
	{PKG_PRODUCT_CONFIG, "custom",           "ssid_5g"},
	{PKG_PRODUCT_CONFIG, "custom",           "wlankey_5g"},
	{PKG_PRODUCT_CONFIG, "custom",           "country_5g"},
	{PKG_PRODUCT_CONFIG, "custom",           "htmode_5g"},
	{PKG_PRODUCT_CONFIG, "custom",           "channel_5g"},
	{PKG_PRODUCT_CONFIG, "custom",           "maxsta_5g"},
	{PKG_PRODUCT_CONFIG, "custom",           "ssid_tail_5g"},
	//upnp
	{PKG_PRODUCT_CONFIG, "custom",           "manufacturer"},
	{PKG_PRODUCT_CONFIG, "custom",           "model_url"},
	{PKG_PRODUCT_CONFIG, "custom",           "manufacturer_url"},
	{PKG_PRODUCT_CONFIG, "custom",           "manufacturer_name"},

	//network
	{PKG_PRODUCT_CONFIG, "custom",           "lan_ipaddr"},
	{PKG_PRODUCT_CONFIG, "custom",           "dhcp_start"},
	{PKG_PRODUCT_CONFIG, "custom",           "dhcp_end"},
	{PKG_PRODUCT_CONFIG, "custom",           "lan_netmask"},

	{PKG_SYSTEM_CONFIG,  "main",             "username"},
	{PKG_SYSTEM_CONFIG,  "main",             "password"},
	{PKG_SYSTEM_CONFIG,  "main",             "lang_support"},
	{PKG_SYSTEM_CONFIG,  "main",             "lang_type"},
	{PKG_SYSTEM_CONFIG,  "main",             "lang_show_auto"},
	{PKG_SYSTEM_CONFIG,  "main",             "lang_auto_flag"},
	

	{PKG_SYSTEM_CONFIG,  "ntp",              "timezone"},
	{PKG_SYSTEM_CONFIG,  "statistics",       "statistics_model"},
	{PKG_SYSTEM_CONFIG,  "statistics",       "statistics_domain"},

	{PKG_PRODUCT_CONFIG, "ispinfo",          "serial_number"},
	{PKG_PRODUCT_CONFIG, "ispinfo",          "device_key"},
	{PKG_PRODUCT_CONFIG, "ispinfo",          "dm_appkey"},
	{PKG_PRODUCT_CONFIG, "ispinfo",          "dm_pwd"},
	{PKG_PRODUCT_CONFIG, "ispinfo",          "andlink_enabled"},
	{PKG_PRODUCT_CONFIG, "ispinfo",          "andlink_provcode"},
	{PKG_PRODUCT_CONFIG, "ispinfo",          "andlink_vendor"},
	{PKG_PRODUCT_CONFIG, "ispinfo",          "andlink_model"},
	{PKG_PRODUCT_CONFIG, "ispinfo",          "andlink_cmei"},

	{-1, NULL, NULL},
};


typedef struct time_zone_table
{
	char zone[32];
	char desc[128];
} ZONE_TABLE;

ZONE_TABLE zone_name[] = {
	{"UTC+12", "(GMT-12.00)Eniwetok, Kwajalein"},
	{"UTC+11", "(GMT-11.00)Midway Island, Samoa"},
	{"UTC+10", "(GMT-10.00)Hawaii"},
	{"UTC+9", "(GMT-09.00)Alaska"},
	{"UTC+8", "(GMT-08.00)Pacific Time"},
	{"UTC+7", "(GMT-07.00)Arizona"},
	{"UTC+6", "(GMT-06.00)Central Time"},
	{"UTC+5", "(GMT-05.00)Indiana East, Colombia, Eastern Time"},
	{"UTC+4", "(GMT-04.00)Atlantic Time, Brazil West, Bolivia, Venezuela"},
	{"UTC+3", "(GMT-03.00)Guyana, Brazil East, Greenland"},
	{"UTC+2", "(GMT-02.00)Mid-Atlantic"},
	{"UTC+1", "(GMT-01.00)Azores Islands"},
	{"UTC+0", "(GMT-00.00)Gambia, Liberia, Morocco, England, Ireland, Portugal"},
	{"UTC-1", "(GMT+01.00)Czech Republic, Slovak, Spain, Germany, France, Tunisia"},
	{"UTC-2", "(GMT+02.00)Greece, Ukraine, Turkey, South Africa"},
	{"UTC-3", "(GMT+03.00)Iraq, Jordan, Kuwait, Moscow Winter Time"},
	{"UTC-4", "(GMT+04.00)Armenia"},
	{"UTC-5", "(GMT+05.00)Pakistan, Russia"},
	{"UTC-6", "(GMT+06.00)Bangladesh, Russia"},
	{"UTC-7", "(GMT+07.00)Bangkok, Hanoi, Jakarta"},
	{"UTC-8", "(GMT+08.00)Beijing, HongKong, Taibei, Philippines, Singapore"},
	{"UTC-9", "(GMT+09.00)Japan, Korean"},
	{"UTC-10", "(GMT+10.00)Guam, Russia, Australia"},
	{"UTC-11", "(GMT+11.00)Solomon Islands"},
	{"UTC-12", "(GMT+12.00)Fiji, New Zealand"}
};

int CsteSystem(char *command, int printFlag)
{
	int pid = 0, status = 0;

    if( !command )
    {
        printf("CsteSystem: Null Command, Error!");
        return -1;
    }

	pid = fork();
  	if ( pid == -1 )
  	{
		return -1;
	}

  	if ( pid == 0 )
  	{
        char *argv[4];
    	argv[0] = "sh";
    	argv[1] = "-c";
    	argv[2] = command;
    	argv[3] = 0;
    	if (printFlag)
    	{
	        printf("[system]: %s\r\n", command);
        }
    	execv("/bin/sh", argv);
    	exit(127);
	}

  	/* wait for child process return */
  	do
  	{
	  	if ( waitpid(pid, &status, 0) == -1 )
    	{
	    	if ( errno != EINTR )
    		{
            	return -1;
      	    }
	    }
    	else
    	{
	    	return status;
		}
	} while ( 1 );

	return status;
}


/*
 * Returns the process ID.
 *
 * @param	name	pathname used to start the process.  Do not include the
 *                      arguments.
 * @return	pid
 */
pid_t get_pid_by_name(char *name)
{
	pid_t           pid = -1;
	DIR             *dir;
	struct dirent   *next;

	if ((dir = opendir("/proc")) == NULL)
	{
		perror("Cannot open /proc");
		return -1;
	}

	while ((next = readdir(dir)) != NULL)
	{
		FILE *fp;
		char filename[256];
		char buffer[256];

		/* If it isn't a number, we don't want it */
		if (!isdigit(*next->d_name))
			continue;

		sprintf(filename, "/proc/%s/cmdline", next->d_name);
		fp = fopen(filename, "r");
		if (!fp)
		{
			continue;
		}
		buffer[0] = '\0';
		fgets(buffer, 256, fp);
		fclose(fp);

		if (!strcmp(name, buffer))
		{
			pid = strtol(next->d_name, NULL, 0);
			break;
		}
	}
	closedir(dir);
	return pid;
}


void set_lktos_effect(char *action)
{
	 char cmd[CMD_STR_LEN];
	 snprintf(cmd, CMD_STR_LEN, "lktos_reload %s >/dev/null 2>&1", action);
	 system(cmd);
	 return;
}

void logmessage(char *logheader, char *fmt, ...)
{
	va_list args;
	char buf[512];

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	openlog(logheader, 0, 0);
	syslog(0,"%s",buf);
	closelog();
	va_end(args);
}

#define TCP_TMPFILE "/tmp/.tcpcheck.tmp"

int tcpcheck_net(const char *host, int port, int timeout)
{
	FILE *f = NULL;
	char s[TEMP_STR_LEN] = { 0 }; 
	char cmd[CMD_STR_LEN] = { 0 }; 
	int ok = 0;

	if ((NULL == host) || (strlen(host)<7))
		return ok;
	
	sprintf(cmd, "tcpcheck %d %s:%d > %s", timeout, host, port, TCP_TMPFILE);
	system(cmd);
	sleep(1);
	if ((f = fopen(TCP_TMPFILE, "r")) != NULL)
	{
		if ( NULL != fgets(s, sizeof(s), f))
		{
			if (strstr(s, "alive") != NULL)
			{
				ok = 1;
			}
			else if (strstr(s, "timed out") != NULL)
			{
				ok = 0;
			}
			else
			{
				ok = 0;
			}
		}
		fclose(f);
	}
	unlink(TCP_TMPFILE);
	
	return ok;
}

#define PING_TMPFILE "/tmp/.ping_success"
int do_ping_detect(const char *host, char *ifname)
{
	char cmd[CMD_STR_LEN] = {0};

	if ((NULL == host) || (strlen(host)<7))
		goto fail;

	if (ifname == NULL)
	{
		snprintf(cmd, sizeof(cmd), "ping -c 1 -W %d %s > /dev/null && touch %s", 1, host, PING_TMPFILE);
	}
	else
	{
		snprintf(cmd, sizeof(cmd), "ping -c 1 -W %d %s -I %s > /dev/null && touch %s", 1, host, ifname, PING_TMPFILE);
	}
	system(cmd);

	if ( access(PING_TMPFILE, F_OK) == 0)
	{
		unlink(PING_TMPFILE);
		return 1;
	}
fail:
	return 0;
}


int get_split_nums(char *value, char delimit)
{
    char *pos = value;
    int count=1;
    if(!pos)
        return 0;
    while( (pos = strchr(pos, delimit)))
	{
        pos = pos+1;
        count++;
    }
    return count;
}


int get_nth_val_safe(int index, char *value, char delimit, char *result, int len)
{
    int i=0, result_len=0;
    char *begin, *end;

    if(!value || !result || !len)
        return -1;

    begin = value;
    end = strchr(begin, delimit);

    while(i<index && end)
	{
        begin = end+1;
        end = strchr(begin, delimit);
        i++;
    }

    //no delimit
    if(!end)
	{
		if(i == index)
		{
			end = begin + strlen(begin);
			result_len = (len-1) < (end-begin) ? (len-1) : (end-begin);
		}
		else
		{
			return -1;
		}
	}
	else
	{
		result_len = (len-1) < (end-begin)? (len-1) : (end-begin);
	}

	memcpy(result, begin, result_len );
	*(result+ result_len ) = '\0';

	return 0;
}


long get_current_uptime_sec(void)
{
    struct sysinfo info;
    sysinfo(&info);
    return info.uptime;
}


int domain_to_ip(const char *domain, char *ip)
{
	char str[32];
	struct hostent *hptr;
	int count = 0;

//	memset(ip, 0, 32);
	if(isalpha(domain[0]))
	{
		while(count<=3)
		{
			if((hptr = gethostbyname(domain)) != NULL)
			{
				sprintf(ip, "%s", inet_ntop(hptr->h_addrtype, hptr->h_addr, str, sizeof(str)));
				return 0;
			}
			else
			{
				dbg(" gethostbyname error for host:%s try again!\n", domain);
				count++;
			}
		}
		//fail
		strncpy(ip, domain, 32);
		return 0;
	}
	else
	{
		strncpy(ip, domain, 32);
		return 0;
	}
}


int get_cmd_result(char *cmd, char *resultbuf, size_t buf_size)
{
	char *pchar = NULL;
	FILE *fp = popen(cmd, "r");
	if(!fp)
	{
		return -1;
	}
	fgets(resultbuf, buf_size, fp);
	pclose(fp); 
	if((pchar = strstr(resultbuf, "\n")))
		*pchar = '\0';

	resultbuf[buf_size-1] = '\0';
	return 0;
}


int get_cmd_val(const char *cmd)
{
    char buf[TEMP_STR_LEN]= {0};
	
    get_cmd_result(cmd, buf, sizeof(buf));

    return atoi(buf);
}

int getInAddr( char *interface, int type, void *pAddr )
{
    struct ifreq ifr;
    int skfd, found=0;
	struct sockaddr_in *addr;
    skfd = socket(AF_INET, SOCK_DGRAM, 0);

    strcpy(ifr.ifr_name, interface);
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0)
	{
    		close( skfd );
		return (0);
	}
    if (type == HW_ADDR_T)
	{
    	if (ioctl(skfd, SIOCGIFHWADDR, &ifr) >= 0)
		{
			memcpy(pAddr, &ifr.ifr_hwaddr, sizeof(struct sockaddr));
			found = 1;
		}
    }
    else if (type == IP_ADDR_T)
	{
		if (ioctl(skfd, SIOCGIFADDR, &ifr) == 0)
		{
			addr = ((struct sockaddr_in *)&ifr.ifr_addr);
			*((struct in_addr *)pAddr) = *((struct in_addr *)&addr->sin_addr);
			found = 1;
		}
    }
    else if (type == NET_MASK_T)
	{
		if (ioctl(skfd, SIOCGIFNETMASK, &ifr) >= 0)
		{
			addr = ((struct sockaddr_in *)&ifr.ifr_addr);
			*((struct in_addr *)pAddr) = *((struct in_addr *)&addr->sin_addr);
			found = 1;
		}
    }
	else 
    {
    	if (ioctl(skfd, SIOCGIFDSTADDR, &ifr) >= 0)
		{
			addr = ((struct sockaddr_in *)&ifr.ifr_addr);
			*((struct in_addr *)pAddr) = *((struct in_addr *)&addr->sin_addr);
			found = 1;
		}
    }
    close( skfd );
    return found;

}


int get_ifname_ipaddr(char *ifname, char *if_addr)
{
	struct ifreq ifr;
	int skfd = 0;

	if((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		dbg("open socket error");
		return -1;
	}
	strncpy(ifr.ifr_name, ifname, IF_NAMESIZE);
	if (ioctl(skfd, SIOCGIFADDR, &ifr) < 0)
	{
		close(skfd);
		return -1;
	}
	strcpy(if_addr, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

	close(skfd);
	return 0;
}

in_addr_t
get_interface_addr4(const char *ifname)
{
	int sockfd;
	struct ifreq ifr;
	in_addr_t ipv4_addr = INADDR_ANY;

	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		return INADDR_ANY;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	/* Get IPv4 address */
	if (ioctl(sockfd, SIOCGIFADDR, &ifr) == 0) {
		struct sockaddr_in *ipv4_inaddr = (struct sockaddr_in *)&ifr.ifr_addr;

		if (ipv4_inaddr->sin_addr.s_addr != INADDR_ANY &&
		    ipv4_inaddr->sin_addr.s_addr != INADDR_NONE)
			ipv4_addr = ipv4_inaddr->sin_addr.s_addr;
	}

	close(sockfd);

	return ipv4_addr;
}

int get_vpnserver_ipaddr(char *ifname, char *if_addr)
{
	struct ifreq ifr;
	int skfd = 0;

	if((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		dbg("open socket error");
		return -1;
	}
	strncpy(ifr.ifr_name, ifname, IF_NAMESIZE);
	if (ioctl(skfd, SIOCGIFDSTADDR, &ifr) < 0)
	{
		close(skfd);
		return -1;
	}
	strcpy(if_addr, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

	close(skfd);
	return 0;
}


int get_ifname_macaddr(char *ifname, char *if_hw)
{
	struct ifreq ifr;
	char *ptr;
	int skfd;

	if((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		return -1;
	}

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if(ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0)
	{
		close(skfd);
		return -1;
	}

	ptr = (char *)&ifr.ifr_addr.sa_data;
	sprintf(if_hw, "%02X:%02X:%02X:%02X:%02X:%02X",
			(ptr[0] & 0377), (ptr[1] & 0377), (ptr[2] & 0377),
			(ptr[3] & 0377), (ptr[4] & 0377), (ptr[5] & 0377));

	close(skfd);
	return 0;
}


int get_ifname_mask(char *ifname, char *if_addr)
{
    struct ifreq ifr;
	int skfd = 0;

	if((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		dbg("open socket error");
		return -1;
	}
	strncpy(ifr.ifr_name, ifname, IF_NAMESIZE);
	if (ioctl(skfd, SIOCGIFNETMASK, &ifr) < 0)
	{
		close(skfd);
		return -1;
	}
	strcpy(if_addr, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

	close(skfd);
	return 0;
}


int get_current_gateway(char  *sgw)
{
	char   buff[256];
	int    nl = 0 ;
	struct in_addr dest;
	struct in_addr gw;
	int    flgs, ref, use, metric;
	unsigned long int d, g, m;
	int    find_default_flag = 0;

	FILE *fp = fopen("/proc/net/route", "r");

	while (fgets(buff, sizeof(buff), fp) != NULL)
	{
		if (nl)
		{
			int ifl = 0;

			while (buff[ifl] != ' ' && buff[ifl] != '\t' && buff[ifl] != '\0')
				ifl++;

			buff[ifl] = 0;  /* interface */

			if (sscanf(buff + ifl + 1, "%lx%lx%X%d%d%d%lx",
				   &d, &g, &flgs, &ref, &use, &metric, &m) != 7) {
				fclose(fp);
				return 0;
			}

			if (flgs & 0x0001)
			{
				dest.s_addr = d;
				gw.s_addr   = g;
				strcpy(sgw, (gw.s_addr == 0 ? "" : inet_ntoa(gw)));

				if (dest.s_addr == 0)
				{
					find_default_flag = 1;
					break;
				}
			}
		}

		nl++;
	}

	fclose(fp);

	if (find_default_flag != 1)
	{
		strcpy(sgw, "");
	}

	return 0;
	
}


int get_current_dns(int dnsIdx, char *dns, int is_ipv6)
{
	FILE *fp;
	char buf[80] = {0}, ns_str[11];
	int idx = 0;

	fp = fopen("/tmp/resolv.conf.d/resolv.conf.auto", "r");

	if (NULL == fp)
	{
		return -1;
	}

	while (fgets(buf, sizeof(buf), fp) != NULL)
	{
		if (strncmp(buf, "nameserver", 10) != 0 || strstr(buf, "127.0.0.1") != NULL)
			continue;

		if(1 == is_ipv6 && strstr(buf, ":") == NULL)
			continue;

		sscanf(buf, "%s %s", ns_str, dns);
		idx++;

		if (idx == dnsIdx)
			break;
	}

	fclose(fp);

	if (idx != dnsIdx)
	{
		strcpy(dns, "");
	}

	return 0;
}

int get_ip_hostname_bymac_in_br(char *pmac, char *ip, char *hostname)
{
	FILE *fp = NULL;
	char line_str[TEMP_STR_LEN] = {0};
	char line_mac[20] = {0}, line_ip[17]={0}, line_hostname[64] = {0};
	int result = 1;

	fp = fopen("/proc/dhcp_hook","r");
	if(fp != NULL) {
		while(fgets(line_str, sizeof(line_str), fp)) {
			memset(line_mac, 0, sizeof(line_mac));
			memset(line_ip, 0, sizeof(line_ip));
			memset(line_hostname, 0, sizeof(line_hostname));
			sscanf(line_str, "%s %s %*d %s", line_mac, line_ip, line_hostname);
			if(strlen(line_mac)>0 && strcasecmp(pmac, line_mac)==0) {
				strcpy(ip, line_ip);
				strcpy(hostname, line_hostname);
				result = 0;
				break;
			}
			memset(line_str, 0, sizeof(line_str));
		}
		fclose(fp);
	}

	return result;
}

int get_sta_ipaddr_bymac(char *pmac, char *ipv4_addr, char *ipv6_addr)
{
	FILE *fp = NULL;

	int  is_get_ip=0;

	char line_str[TEMP_STR_LEN] = {0};

	char mac[RESULT_STR_LEN] = {0}, ip[RESULT_STR_LEN] = {0};

	fp = fopen("/tmp/dhcp.leases","r");
	if(fp!=NULL)
	{
		while(fgets(line_str,sizeof(line_str),fp))
		{
			memset(mac,0,sizeof(mac));
			memset(ip,0,sizeof(ip));
			sscanf(line_str, "%*s %s %s %*s %*s",mac, ip);

			if(strlen(mac)>0 && strlen(ip)>0 && !strcasecmp(pmac,mac))
			{
				strcpy(ipv4_addr,ip);

				//get_sta_ipv6addr(pmac, ipv6_addr);
				//strcpy(ipv6_addr,"");
				is_get_ip=1;
				break;
			}
			memset(line_str,0,sizeof(line_str));
		}
		fclose(fp);
	}

	if(0==is_get_ip)
	{
		strcpy(ipv4_addr,"0.0.0.0");
		strcpy(ipv6_addr,"");
	}
	return 0;
}

int get_sta_hostname_bymac(char *pmac, char *hostname)
{
	FILE *fp = NULL;

	int is_get_dev_name=0;

	char line_str[TEMP_STR_LEN] = {0};

	char mac[RESULT_STR_LEN] = {0},ip[RESULT_STR_LEN] = {0},dev_name[TEMP_STR_LEN]={0};

	//try get hostname from dhcp.leases
	fp = fopen("/tmp/dhcp.leases","r");
	if(fp)
	{
		while(fgets(line_str, sizeof(line_str)-1, fp))
		{
			bzero(mac,sizeof(mac));
			bzero(ip,sizeof(ip));
			bzero(dev_name,sizeof(dev_name));

			sscanf(line_str, "%*s %s %*s %s %*s",mac, dev_name);

			if(0==strcasecmp(mac,pmac) && strlen(dev_name) > 0)
			{
				strcpy(hostname,dev_name);
				is_get_dev_name=1;
				break;
			}

			bzero(line_str,sizeof(line_str));
		}
		fclose(fp);
		fp = NULL;
	}

	if(0==is_get_dev_name || 0 == strcmp(dev_name, "*")){
		strcpy(hostname,pmac);
	}

	return 0;
}

int get_sta_mac_byip(char *ipaddr, char *mac)
{
	char buf[256];
	char ip_entry[32],flags[8], hw_address[32];
	unsigned long i_flags = 0;

    FILE *fp = fopen("/proc/net/arp", "r");
    if(!fp){
        dbg("no proc fs mounted!\n");
        return;
    }
    strcpy(mac, "00:00:00:00:00:00");

	fgets(buf, 256, fp); //header
    while(fgets(buf, 256, fp)){
        sscanf(buf, "%s %*s %s %s", ip_entry, flags, hw_address);

		i_flags = strtoul(flags, 0, 16);
		if ( 0 == i_flags ){
			continue;
		}

        if(!strcmp(ipaddr, ip_entry)){
            strcpy(mac, hw_address);
            break;
        }
    }

    fclose(fp);
    return;
}

int get_ifname_bytes(const char *ifname, unsigned long long *rxb, unsigned long long *txb)
{
	char path[TEMP_STR_LEN] = {0};

	snprintf(path, TEMP_STR_LEN, "/sys/class/net/%s/statistics/tx_bytes", ifname);
	*txb = f_read_long_long(path);

	snprintf(path, TEMP_STR_LEN, "/sys/class/net/%s/statistics/rx_bytes", ifname);
	*rxb = f_read_long_long(path);

	return 0;
}


int get_wanmode_int(char *proto)
{
	int ret = DHCP_DISABLED;

	if(0 == strcmp(proto, "static"))
		ret = DHCP_DISABLED;
	else if(0 == strcmp(proto, "pppoe"))
		ret = PPPOE;
	else if(0 == strcmp(proto, "pptp"))
		ret = PPTP;
	else if(0 == strcmp(proto, "l2tp"))
		ret = L2TP;
	else
		ret = DHCP_CLIENT;

	return ret;
}

int get_wan_ifname(char *ifname)
{
	struct interface_status status_paremeter;
	get_wan_status(&status_paremeter);
	strcpy(ifname, status_paremeter.device);
	return 0;
}

void get_gateway_iface(char *interface)
{
	char   buff[256], iface[16]={0};
	int    nl = 0 ;
	int    find_interface_flag = 0;

	FILE *fp = fopen("/proc/net/route", "r");

	while (fgets(buff, sizeof(buff), fp) != NULL) {
		if (nl) {
			int ifl = 0;

			while (buff[ifl] != ' ' && buff[ifl] != '\t' && buff[ifl] != '\0')
				ifl++;
			
			if(ifl>0)
				ifl++;
			snprintf(iface, ifl, "%s", buff);

			if(strcmp(iface, "br-lan") != 0){
				find_interface_flag=1;
				strcpy(interface, iface);
				break;
			}
		}
		nl++;
	}

	fclose(fp);

	if (find_interface_flag == 1)
		return ;
	else {
		strcpy(interface, "");
		return ;
	}
}

int get_wire_wan_status(struct interface_status *status_paremeter)
{
	char opmode_custom[16] = { 0 };
	char wan_if[16] = { 0 }, vpn_mode[16] = { 0 }, wan_mode[8] = { 0 };

	memset(status_paremeter, 0, sizeof(struct interface_status));

	Uci_Get_Str(PKG_SYSTEM_CONFIG, "opmode", "opmode_custom", opmode_custom);

	if(strcmp(opmode_custom, "gw") == 0)
	{
		Uci_Get_Str(PKG_NETWORK_CONFIG, "vpn", "proto", vpn_mode);

		if(strlen(vpn_mode) == 0)
		{
			strcpy(wan_if, "wan");
		}
		else
		{
			strcpy(wan_if, "vpn");
		}
	}
	else if(strcmp(opmode_custom, "wisp")==0)
	{
		strcpy(wan_if, "wlan");
	}

	if(strlen(wan_if) > 0)
	{
		Uci_Get_Str(PKG_NETWORK_CONFIG, wan_if, "proto",wan_mode);
		if(strcmp(wan_mode, "pppoe") == 0){
			strncpy(status_paremeter->device,"pppoe-wan",sizeof(status_paremeter->device));
		} else if(strcmp(wan_mode, "l2tp") == 0){
			strncpy(status_paremeter->device,"l2tp-vpn",sizeof(status_paremeter->device));
		} else if(strcmp(wan_mode, "pptp") == 0){
			strncpy(status_paremeter->device,"pptp-vpn",sizeof(status_paremeter->device));
		} else {
			strncpy(status_paremeter->device,WAN_IFNAME,sizeof(status_paremeter->device));
		}
		get_interface_status(status_paremeter, wan_if);
	}
	else
	{
		return -1;
	}

	return 1;
}

LINK_STATUS_T get_wan_status(struct interface_status *status_paremeter)
{
	int modem_prio = 0;
	char opmode_custom[16] = { 0 };
	char wan_if[16] = { 0 }, gw_if[16] = { 0 } ,vpn_mode[16] = { 0 }, wan_mode[8] = { 0 };
	char modem_ifname[16] = { 0 };
	memset(status_paremeter, 0, sizeof(struct interface_status));

	Uci_Get_Str(PKG_SYSTEM_CONFIG, "opmode", "opmode_custom", opmode_custom);
	Uci_Get_Int(PKG_NETWORK_CONFIG, "wan", "modem_prio", &modem_prio);
	Uci_Get_Str(PKG_NETWORK_CONFIG, WAN_MODEM_NET_INTERFACE, "device", modem_ifname);

	if(modem_prio == PRIO_3GPP_ONLY)
	{
		strcpy(wan_if, WAN_MODEM_NET_INTERFACE);
		get_interface_status(status_paremeter, wan_if);
	}
	else {
		if(strcmp(opmode_custom, "gw") == 0)
		{
			Uci_Get_Str(PKG_NETWORK_CONFIG, "vpn", "proto", vpn_mode);

			if(strlen(vpn_mode) == 0)
			{
				strcpy(wan_if, WAN_NET_INTERFACE);
			}
			else
			{
				strcpy(wan_if, "vpn");
			}
		}
		else if(strcmp(opmode_custom, "wisp")==0)
		{
			strcpy(wan_if, "wlan");
		}

		if(strlen(wan_if) > 0)
		{
			get_gateway_iface(gw_if);
			if((modem_prio == PRIO_WIRE_FRIST || modem_prio == PRIO_3GPP_FRIST) && 
					strlen(modem_ifname) && !strcmp(gw_if, modem_ifname))
			{
				strcpy(wan_if, WAN_MODEM_NET_INTERFACE);
			}
			else {
				if((!strcmp(wan_if, WAN_NET_INTERFACE) || !strcmp(wan_if,"vpn")) && !is_phyport_connected(ETH_PORT_WAN))
				{
					return LINK_STATUS_NO;
				}
				else 
				{
					Uci_Get_Str(PKG_NETWORK_CONFIG, wan_if, "proto",wan_mode);
					if(strcmp(wan_mode, "pppoe") == 0){
						strncpy(status_paremeter->device,"pppoe-wan",sizeof(status_paremeter->device));
					} else if(strcmp(wan_mode, "l2tp") == 0){
						strncpy(status_paremeter->device,"l2tp-vpn",sizeof(status_paremeter->device));
					} else if(strcmp(wan_mode, "pptp") == 0){
						strncpy(status_paremeter->device,"pptp-vpn",sizeof(status_paremeter->device));
					} else {				
						strncpy(status_paremeter->device,WAN_IFNAME,sizeof(status_paremeter->device));
					}
				}
			}
			get_interface_status(status_paremeter, wan_if);
		}
		else
		{
			return LINK_STATUS_NO;
		}

	}

	if(status_paremeter->up) 
	{
		if(!strcmp(wan_if,"wan_modem"))
			return LINK_STATUS_MODEM;
		else
			return LINK_STATUS_WIRE;
	}

	return LINK_STATUS_NO;

}

int get_cjson_string(cJSON *object, char *key,  char *val, int len)
{
	cJSON	*sp;

	memset(val, '\0', sizeof(len));
	
    assert(key && *key);

	if ((sp = cJSON_GetObjectItem(object, key)) != NULL) {
		if (sp->type==cJSON_String)
		{
			snprintf(val, len, "%s", sp->valuestring);
		}
		else if (sp->type==cJSON_False)
		{
			snprintf(val, len, "%d", 0);
		}
		else if (sp->type==cJSON_True)
		{
			snprintf(val, len, "%d", 1);
		}
		else if (sp->type==cJSON_Number)
		{
			snprintf(val, len, "%d", sp->valueint);
		}
		else
		{
			return -1;
		}
	}
	return 0;
}

//ubus call network.interface.wan/lan status
int get_interface_status(struct interface_status *status_paremeter,char *interface)
{
	int ret, i, len;

	char *ptr;

	char tmp_buf[128] = {0}, p_json[1024*4] = {0};

	unsigned int addr;

	cJSON *j_data, *j_obj, *tmp_obj;

	snprintf(tmp_buf,sizeof(tmp_buf)-1,"network.interface.%s",interface);
	ret = cs_ubus_cli_call(tmp_buf, "status",p_json);

	if(!ret){
		j_data = cJSON_Parse(p_json);
		if(j_data)
		{
			memset(tmp_buf,0,sizeof(tmp_buf));
			get_cjson_string(j_data, "up",  tmp_buf, sizeof(tmp_buf));
			status_paremeter->up = atoi(tmp_buf);

			memset(tmp_buf,0,sizeof(tmp_buf));
			get_cjson_string(j_data, "uptime",  tmp_buf, sizeof(tmp_buf));
			status_paremeter->uptime = atoi(tmp_buf);

			get_cjson_string(j_data, "proto",  status_paremeter->proto, sizeof(status_paremeter->proto));
			get_cjson_string(j_data, "l3_device", status_paremeter->device, sizeof(status_paremeter->device));

			j_obj = cJSON_GetObjectItem(j_data, "ipv4-address");
			if(j_obj)
			{
				if(cJSON_GetArraySize(j_obj)>0) {
					tmp_obj = cJSON_GetArrayItem(j_obj,0);
					get_cjson_string(tmp_obj, "address", status_paremeter->ipaddr_v4, sizeof(status_paremeter->ipaddr_v4));

					memset(tmp_buf,0,sizeof(tmp_buf));
					get_cjson_string(tmp_obj, "mask",  tmp_buf, sizeof(tmp_buf));
					i=atoi(tmp_buf);

					memset(tmp_buf,0,sizeof(tmp_buf));
					addr = LMOVE(0xffffffff,32-i);
					sprintf(tmp_buf,"%u.%u.%u.%u",RMOVE(addr,24),
						RMOVE(addr,16)&0xff,RMOVE(addr,8)&0xff,addr&0xff);
					strcpy(status_paremeter->mask_v4,tmp_buf);
				}
			}

			j_obj = cJSON_GetObjectItem(j_data, "route");
			if(j_obj)
			{
				len = cJSON_GetArraySize(j_obj);
				for(i = 0;i<len;i++) {
					tmp_obj = cJSON_GetArrayItem(j_obj,i);

					memset(tmp_buf,0,sizeof(tmp_buf));
					get_cjson_string(tmp_obj, "target",  tmp_buf, sizeof(tmp_buf));
					if(strlen(tmp_buf)>0 && !strcmp(tmp_buf,"0.0.0.0"))
					{
						memset(tmp_buf,0,sizeof(tmp_buf));
						get_cjson_string(tmp_obj, "nexthop",  tmp_buf, sizeof(tmp_buf));
						strcpy(status_paremeter->gateway_v4,tmp_buf);
						break;
					}
				}
			}

			j_obj = cJSON_GetObjectItem(j_data, "dns-server");
			if(j_obj)
			{
				len=cJSON_GetArraySize(j_obj);
				for(i = 0; i < len; i++){
					tmp_obj = cJSON_GetArrayItem(j_obj,i);
					ptr=tmp_obj->valuestring ? tmp_obj->valuestring : "0.0.0.0";
				
					if( is_ip_valid(ptr=tmp_obj->valuestring)!=1 )
					{
						continue;
					}
					
					if(i==0 || i==2){
						snprintf(status_paremeter->pri_dns_v4,sizeof(status_paremeter->pri_dns_v4),"%s",ptr);
					}else if(i==1 || i==3){
						snprintf(status_paremeter->sec_dns_v4,sizeof(status_paremeter->sec_dns_v4),"%s",ptr);
					}
				}
			}
			cJSON_Delete(j_data);
		}
	}
	return 0;
}

//exp. 24 to "255.255.255.0"
int mask_num2string(int num, char *mask_buf, int buf_len)
{

    int i_num = 0;
    int byte = 0;
    int bit = 0;
    int i, j;

	union mask_s
	{
			char ch[4];
			unsigned long ul;
	}mask;
		
    mask.ul = 0;

    i_num = num;
    if (i_num < 1 || i_num > 32)
    {
        return -1;
    }

    byte = i_num/8;
    bit = i_num%8;

    for (i = 0; i < byte; i++)
    {
        mask.ch[i] = 0xff;
    }
    for (j = 0; j < bit; j++)
    {
        mask.ch[i] |= (1 << (7 - j));
    }

    if (inet_ntop(AF_INET, (void*)&mask.ul, mask_buf, buf_len) < 0)
    {
        return -1;
    }

    return 0;
}

//exp. "255.255.255.0" to 24 
int mask_string2num(char *mask)
{
	int i = 0;
	struct  in_addr addr;

	if(!mask || strlen(mask) < 9) //128.0.0.0
		return i;

	addr.s_addr=inet_addr(mask);
	for(i = 0; i<32; i++)
	{
		if((RMOVE(htonl(addr.s_addr),i) & 1) == 0)
			continue;
		else
			break;
	}
	return 32-i;
}

/*
 * Convert Ethernet address string representation to binary data
 * @param	a	string in xx:xx:xx:xx:xx:xx notation
 * @param	e	binary data
 * @return	TRUE if conversion was successful and FALSE otherwise
 */
int ether_atoe(const char *a, unsigned char *e)
{
	char *c = (char *) a;
	int i = 0;

	memset(e, 0, ETHER_ADDR_LEN);
	for (;;)
	{
		e[i++] = (unsigned char) strtoul(c, &c, 16);
		if (!*c++ || i == ETHER_ADDR_LEN)
			break;
	}
	return (i == ETHER_ADDR_LEN);
}

/*
 * Convert Ethernet address binary data to string representation
 * @param	e	binary data
 * @param	a	string in xx:xx:xx:xx:xx:xx notation
 * @return	a
 */
int ether_etoa(const unsigned char *e, char *a)
{
	char *c = a;
	int i;

	for (i = 0; i < ETHER_ADDR_LEN; i++)
	{
		if (i)
			*c++ = ':';
		c += sprintf(c, "%02X", e[i] & 0xff);
	}
	return 0;
}

#define BURSIZE 2048

int hex2dec(char c)
{
    if ('0' <= c && c <= '9')
    {
        return c - '0';
    }
    else if ('a' <= c && c <= 'f')
    {
        return c - 'a' + 10;
    }
    else if ('A' <= c && c <= 'F')
    {
        return c - 'A' + 10;
    }
    else
    {
        return -1;
    }
}


char dec2hex(short int c)
{
    if (0 <= c && c <= 9)
    {
        return c + '0';
    }
    else if (10 <= c && c <= 15)
    {
        return c + 'A' - 10;
    }
    else
    {
        return -1;
    }
}


void urldecode(char url[], char *result)
{
    int i = 0;
    int len = strlen(url);
    int res_len = 0;
    char res[BURSIZE];
    for (i = 0; i < len; ++i)
    {
        char c = url[i];
        if (c != '%')
        {
            res[res_len++] = c;
        }
        else
        {
            char c1 = url[++i];
            char c0 = url[++i];
            int num = 0;
            num = hex2dec(c1) * 16 + hex2dec(c0);
            res[res_len++] = num;
        }
    }
    res[res_len] = '\0';
    strcpy(result, res);
}


void urlencode(char url[],char *result)
{
    int i = 0;
    int len = strlen(url);
    int res_len = 0;
    char res[BURSIZE];
    for (i = 0; i < len; ++i)
    {
        char c = url[i];
        if (('0' <= c && c <= '9') || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || c == '/' || c == '.')
        {
            res[res_len++] = c;
        }
        else
        {
            int j = (short int)c;
            if (j < 0)
                j += 256;
            int i1, i0;
            i1 = j / 16;
            i0 = j - i1 * 16;
            res[res_len++] = '%';
            res[res_len++] = dec2hex(i1);
            res[res_len++] = dec2hex(i0);
        }
    }
    res[res_len] = '\0';
    strcpy(result, res);
}

int parsing_str(char *str,char *result,int len)
{
	char backslash = 0x5C;
	char space = 0x20;
	char SUB = 0x1A;
	char buf[1024] = {0},buffer[1024] = {0};
	int i,j;
	char ch,sch;
	strncpy(buf,str,len);

	i = 0;j = 0;
	do{
		ch = buf[i++];
		if(ch == backslash){
			sch = buf[i++];
			if(sch == space){
				ch = SUB;
			}else if(sch == backslash){
				ch = sch;
			}else{
				buffer[j++] = ch;
				ch =sch;
			}
		}
		buffer[j++] = ch;
	}while(ch != '\0');

	strncpy(result,buffer,strlen(buffer));
	return 0;
}

int parsing_ssid(char *ssid,int len)
{
	int i,j;
	char ch;
	char ssid_t[64] = {0},buf[64] = {0};
	char space = 0x20;
	strncpy(ssid_t,ssid,len);
	i = 0;j = 0;
	for(i = 0;i<len;i++){
		ch = ssid_t[i];
		if(ch == '\0')
			break;
		if(ch == space){
			buf[j++] = '\\';
			buf[j++] = ch;
		}else{
			buf[j++] = ch;
		}
	}
	memset(ssid,0,len);
	strncpy(ssid,buf,strlen(buf));
	return 0;
}

#if 0
int setBssConfig(int idx,char *band,char *ssid,char *auth,char *encryption,char *passwd,int hidden)
{
	int count = 0;
	char al_mac[32] = {0},radio_band[8] = {0},ssid_t[32] = {0},auth_mode[32] = {0},encry_type[32] = {0};
	char passwd_t[64] = {0},hidden_t[16] = {0},primary_vlan[32] = {0},default_pcp[32] = {0};
	int bh_support,fh_support,vlan_id,idx_i,flag,real_idx = -1;
	FILE *fp;
	char buffer[1024*5] = {0};
	char buf[256]={0},tmp[256]={0},idx_t[16]={0};
	char buf_t[256] = {0};
	char auth_f[32] = {0},encry_f[32] = {0},hidden_f[32] = {0},passwd_f[64] = {0};

	if(ssid == NULL || auth == NULL || encryption == NULL ||!( hidden == 0||hidden == 1)){
		printf("error");
		return -1;
	}

	fp = fopen("/etc/map/wts_bss_info_config", "r");
	if(!fp){
		return -1;
	}
	flag= 1;
	while(fgets(buf,256,fp)){
		if(strstr(buf,"ucc_bss_info") && count == 0)
		{
			strcat(buffer,buf);
			memset(buf,0,sizeof(buf));
			continue;
		}
		memset(buf_t,0,sizeof(buf_t));
		parsing_str(buf,buf_t,strlen(buf));
		sscanf(buf_t,"%d,%s%s%s%s%s%s%d%d%s%d%s%s",
				&idx_i,al_mac,radio_band,ssid_t,auth_mode,encry_type,passwd_t,&bh_support,&fh_support,hidden_t,&vlan_id,primary_vlan,default_pcp);
		if(flag){
			if(strcmp(radio_band,band) == 0){/*8x--2G,11x--5LG,12x--5HG*/
				real_idx = idx_i + idx;
				flag = 0;
			}
		}

		if(idx_i == real_idx){
			//printf("[%d][%s][%s][%s][%s][%s][%s][%d][%d][%s][%d][%s][%s]\n",
			//	idx_i,al_mac,radio_band,ssid_t,auth_mode,encry_type,passwd_t,bh_support,fh_support,hidden_t,vlan_id,primary_vlan,default_pcp);

			if(strcmp(auth,"WPA2") == 0 && strcmp(encryption,"AES") == 0){
				strcpy(auth_f,"0x0020");/*WPA2*/
				strcpy(encry_f,"0x0008");/*AES*/
				strcpy(passwd_f,passwd);
			}else if(strcmp(auth,"WPA2WPA3") == 0 && strcmp(encryption,"AES") == 0){
				strcpy(auth_f,"0x0060");/*WPA2WPA3*/
				strcpy(encry_f,"0x0008");/*AES*/
				strcpy(passwd_f,passwd);
			}
			else if(strcmp(auth,"OPEN") == 0 && strcmp(encryption,"WEP") == 0){
				strcpy(auth_f,"0x0001");/*OPEN*/
				strcpy(encry_f,"0x0002");/*WEP*/
				strcpy(passwd_f,passwd);
			}else if(strcmp(auth,"SHARED") == 0 && strcmp(encryption,"WEP") == 0){
				strcpy(auth_f,"0x0004");/*SHARED*/
				strcpy(encry_f,"0x0002");/*WEP*/
				strcpy(passwd_f,passwd);
			}else if(strcmp(auth,"WPA") == 0 && strcmp(encryption,"TKIP") == 0){
				strcpy(auth_f,"0x0002");/*WPA*/
				strcpy(encry_f,"0x0004");/*TKIP*/
				strcpy(passwd_f,passwd);
			}else if(strcmp(auth,"WPA2") == 0 && strcmp(encryption,"TKIPAES") == 0){
				strcpy(auth_f,"0x0020");/*WPA2*/
				strcpy(encry_f,"0x000c");/*TKIPAES*/
				strcpy(passwd_f,passwd);
			}else if(strcmp(auth,"WPAWPA2") == 0 && strcmp(encryption,"AES") == 0){
				strcpy(auth_f,"0x0022");/*WPAWPA2*/
				strcpy(encry_f,"0x0008");/*AES*/
				strcpy(passwd_f,passwd);
			}else if(strcmp(auth,"WPAWPA2") == 0 && strcmp(encryption,"TKIPAES") == 0){
				strcpy(auth_f,"0x0020");/*WPAWPA2*/
				strcpy(encry_f,"0x000c");/*TKIPAES*/
				strcpy(passwd_f,passwd);
			}else if(strcmp(auth,"WPA3") == 0 && strcmp(encryption,"AES") == 0){
				strcpy(auth_f,"0x0040");/*WPA3*/
				strcpy(encry_f,"0x0008");/*AES*/
				strcpy(passwd_f,passwd);
			}
			else{
				strcpy(auth_f,"0x0001");/*OPEN*/
				strcpy(encry_f,"0x0001");/*NONE*/
				strcpy(passwd_f,passwd_t);
			}

			if(hidden == 1){
				strcpy(hidden_f,"hidden-Y");
			}else{
				strcpy(hidden_f,"hidden-N");
			}
			sprintf(tmp,"%d,%s %s %s %s %s %s %d %d %s %d %s %s",
				idx_i,al_mac,radio_band,ssid,auth_f,encry_f,passwd_f,bh_support,fh_support,hidden_f,vlan_id,primary_vlan,default_pcp);
			strcat(buffer,tmp);
			strcat(buffer,"\n");
		}
		else{
			strcat(buffer,buf);
		}
		count++;
		memset(tmp,0,sizeof(tmp));
		memset(buf,0,sizeof(buf));
	}
	fclose(fp);
	f_write_string("/etc/map/wts_bss_info_config", buffer, 0, 0);
	return 0;
}
#endif


static int bss_info_line_idx = 1;
static int getBssConfigLine(int inf_idx, char *line, const char *radio, int bh, int fh)
{
	int auth, encry, i, j=0, ssid_len;
	char disabled[5] = {0}, ssid[33] = {0}, escaped_ssid[65]={0}, encrytype[16] = {0},auth_mode[16] = {0},wap_psk[64] = {0},hssid[9] = {0};

	wificonf_get_by_key(inf_idx, "disabled", disabled, sizeof(disabled));
	if(strcmp(disabled, "1")==0){
		return 0;
	}
	wificonf_get_by_key(inf_idx, "authmode", auth_mode, sizeof(auth_mode));
	wificonf_get_by_key(inf_idx, "encryption", encrytype, sizeof(encrytype));
	wificonf_get_by_key(inf_idx, "key", wap_psk, sizeof(wap_psk));
	wificonf_get_by_key(inf_idx, "hidden", hssid, sizeof(hssid));
	wificonf_get_by_key(inf_idx,"ssid",ssid,sizeof(ssid));

	ssid_len = strlen(ssid);
	for(i=0; i<ssid_len; i++){
		if(' ' == ssid[i] || '\\'==ssid[i]){
			escaped_ssid[j++] = '\\';
		}
		escaped_ssid[j++] = ssid[i];
	}
	if(!strcmp(auth_mode, "OPEN")) {
		auth = AUTHMODE_OPEN;
	} else if(!strcmp(auth_mode, "WPAPSK")){
		auth = AUTHMODE_WPA;
	} else if(!strcmp(auth_mode, "WPA2PSK")){
		auth = AUTHMODE_WPA2;
	} else if(!strcmp(auth_mode, "WPAPSKWPA2PSK")) {
		auth = AUTHMODE_WPA_WPA2;
	} else if(!strcmp(auth_mode, "WPA3PSK")) {
		auth = AUTHMODE_WPA3_SAE;
	}else if(!strcmp(auth_mode, "WPA2PSKWPA3PSK")){
		auth = AUTHMODE_WPA3_TRANSITION;
	} else{
		auth = AUTHMODE_WPA3_TRANSITION;
	}
	if(!strcmp(encrytype, "AES")){
		encry = ENCTYTYPE_AES;
	} else if(!strcmp(encrytype, "TKIP")){
		encry= ENCTYTYPE_TKIP;
	} else if(!strcmp(encrytype, "TKIPAES")){
		encry= ENCTYTYPE_TKIP_AES;
	} else if(!strcmp(encrytype, "NONE")){
		encry = ENCTYTYPE_NONE;
	}else {
		encry = ENCTYTYPE_NONE;
	}
	if(strcmp(hssid, "0")==0){
		strcpy(hssid, "hidden-N");
	}else{
		strcpy(hssid, "hidden-Y");
	}

	if(strlen(wap_psk)==0){
		snprintf(line , BSS_LINE_MAX_LENGTH, "%d,ff:ff:ff:ff:ff:ff %s %s 0x%04X 0x%04X 999999999 %d %d %s 4095 N/A N/A\n",
				bss_info_line_idx, radio, escaped_ssid, auth, encry, bh, fh, hssid);
	}else{
		snprintf(line, BSS_LINE_MAX_LENGTH, "%d,ff:ff:ff:ff:ff:ff %s %s 0x%04X 0x%04X %s %d %d %s 4095 N/A N/A\n",
				bss_info_line_idx, radio, escaped_ssid, auth, encry, wap_psk, bh, fh, hssid);
	}
	
	line[BSS_LINE_MAX_LENGTH-1] = '\0';
	bss_info_line_idx++;

	return 1;
}

int genBssConfigs()
{
	char bss_info_config_line[BSS_LINE_MAX_LENGTH] = {0};
	FILE *f = fopen(BSS_CONF_FILE, "w+");

	if(!f){
		return 1;
	}
	fputs("#ucc_bss_info\n", f);
	bss_info_line_idx = 1;
	if(getBssConfigLine(W24G_IF, bss_info_config_line, "8x", 0, 1)){
		fputs(bss_info_config_line, f);
	}
	if(getBssConfigLine(W24G_MH, bss_info_config_line, "8x", 1, 0)){
		fputs(bss_info_config_line, f);
	}
	if(getBssConfigLine(W24G_G1, bss_info_config_line, "8x", 0, 1)){
		fputs(bss_info_config_line, f);
	}
	if(getBssConfigLine(W24G_G2, bss_info_config_line, "8x", 0, 1)){
		fputs(bss_info_config_line, f);
	}
	if(getBssConfigLine(W24G_G3, bss_info_config_line, "8x", 0, 1)){
		fputs(bss_info_config_line, f);
	}
	if(getBssConfigLine(W24G_G4, bss_info_config_line, "8x", 0, 1)){
		fputs(bss_info_config_line, f);
	}

	if(getBssConfigLine(W58G_IF, bss_info_config_line, "11x", 0, 1)){
		fputs(bss_info_config_line, f);
	}
	if(getBssConfigLine(W58G_MH, bss_info_config_line, "11x", 1, 0)){
		fputs(bss_info_config_line, f);
	}
	if(getBssConfigLine(W58G_G1, bss_info_config_line, "11x", 0, 1)){
		fputs(bss_info_config_line, f);
	}
	if(getBssConfigLine(W58G_G2, bss_info_config_line, "11x", 0, 1)){
		fputs(bss_info_config_line, f);
	}
	if(getBssConfigLine(W58G_G3, bss_info_config_line, "11x", 0, 1)){
		fputs(bss_info_config_line, f);
	}
	if(getBssConfigLine(W58G_G4, bss_info_config_line, "11x", 0, 1)){
		fputs(bss_info_config_line, f);
	}

	if(getBssConfigLine(W58G_IF, bss_info_config_line, "12x", 0, 1)){
		fputs(bss_info_config_line, f);
	}
	if(getBssConfigLine(W58G_MH, bss_info_config_line, "12x", 1, 0)){
		fputs(bss_info_config_line, f);
	}
	if(getBssConfigLine(W58G_G1, bss_info_config_line, "12x", 0, 1)){
		fputs(bss_info_config_line, f);
	}
	if(getBssConfigLine(W58G_G2, bss_info_config_line, "12x", 0, 1)){
		fputs(bss_info_config_line, f);
	}
	if(getBssConfigLine(W58G_G3, bss_info_config_line, "12x", 0, 1)){
		fputs(bss_info_config_line, f);
	}
	if(getBssConfigLine(W58G_G4, bss_info_config_line, "12x", 0, 1)){
		fputs(bss_info_config_line, f);
	}
	fclose(f);

	return 0;
}

int setMapRole(int mode_new)
{
	char cmd[64] = {0},old_proto[8] = {0},protodef[8]={0},opmode[8] = {0};
	char ssid[33] = {0},encrytype[16] = {0},auth_mode[16] = {0},wap_psk[64] = {0},hssid[4] = {0};
	char mesh_bh_ssid[32] = {0}, mac_str[20] = {0};
	int reload_network = 0;
	int bss_info_lin_idx = 1;
	int switch_br=0;


	dbg("setMapRole:%d\n", mode_new);
	Uci_Get_Str(PKG_SYSTEM_CONFIG,"opmode","opmode_custom", opmode);
	if(strcmp(opmode, "br")!=0 && strcmp(opmode, "gw")!=0){
		return 1;
	}

	system("uci -q delete network.@device[0].ports");
	Uci_Del_Section(PKG_NETWORK_CONFIG,"@switch_vlan[1]");

	Uci_Get_Str(PKG_NETWORK_CONFIG, "lan", "proto", old_proto);
	if(mode_new >= 0){

		sprintf(cmd,"echo -n ''>%s",MAPD_USER_CONF_FILE);
        CsteSystem(cmd, 0);

		wificonf_set_by_key(W24G_MH,"mapmode","1");
		wificonf_set_by_key(W58G_MH,"mapmode","1");

		wificonf_set_by_key(W24G_MH,"disabled","0");
		wificonf_set_by_key(W58G_MH,"disabled","0");

		wificonf_set_by_key(W24G_MH, "hidden", "1");
		wificonf_set_by_key(W58G_MH, "hidden", "1");

		Uci_Set_Str(PKG_WIRELESS_CONFIG,"schedule","enable","0");
		Uci_Commit(PKG_WIRELESS_CONFIG);

		datconf_set_by_key(MAPD_USER_CONF_FILE, "ScanThreshold2g",    "-65");
		datconf_set_by_key(MAPD_USER_CONF_FILE, "ScanThreshold5g",    "-70");
		datconf_set_by_key(MAPD_USER_CONF_FILE, "ScanThreshold6g",    "-70");

		if(mode_new == DEV_CONTROLLER)
		{
			strcpy(mesh_bh_ssid, "WiFi-MESH-BH");//xx:xx:xx:xx:xx:xx
			if(0 == get_ifname_macaddr(WL_IF[W24G_IF].ifname, mac_str) && strlen(mac_str)==17){
				sprintf(mesh_bh_ssid, "WiFi-MESH-BH-%c%c%c%c%c%c", mac_str[9], mac_str[10], mac_str[12], mac_str[13], mac_str[15], mac_str[16]);
				sprintf(wap_psk, "%cM%cE%cS%cH%c%c", mac_str[9], mac_str[10], mac_str[12], mac_str[13], mac_str[15], mac_str[16]);
			}
			wificonf_set_by_key(W24G_MH, "devicerole", "1");
			wificonf_set_by_key(W58G_MH, "devicerole", "1");

			wificonf_set_by_key(W24G_MH, "ssid", mesh_bh_ssid);
			wificonf_set_by_key(W58G_MH, "ssid", mesh_bh_ssid);
			wificonf_set_by_key(W24G_MH, "authmode", "WPAPSKWPA2PSK");
			wificonf_set_by_key(W58G_MH, "authmode", "WPAPSKWPA2PSK");
			wificonf_set_by_key(W24G_MH, "encryption", "AES");
			wificonf_set_by_key(W58G_MH, "encryption", "AES");
			wificonf_set_by_key(W24G_MH, "key", wap_psk);
			wificonf_set_by_key(W58G_MH, "key", wap_psk);


			datconf_set_by_key(MAPD_1905D_CONF_FILE, "map_agent", "0");
			datconf_set_by_key(MAPD_1905D_CONF_FILE, "map_root",  "1");
			datconf_set_by_key(MAPD_1905D_CONF_FILE, "map_ver",  "R2");

			datconf_set_by_key(MAPD_USER_CONF_FILE, "DeviceRole", "1");
			datconf_set_by_key(MAPD_USER_CONF_FILE, "MapMode",    "1");
			if(strcmp(opmode, "br")==0){
				switch_br=1;
				datconf_set_by_key(MAPD_USER_CONF_FILE, "mode",    "2");
			}else{
				datconf_set_by_key(MAPD_USER_CONF_FILE, "mode",    "1");
			}
			datconf_set_by_key(MAPD_USER_CONF_FILE, "DhcpCtl",    "0");

			datconf_set_by_key(MAPD_DEF_CONF_FILE, "LastMapMode",    "1");
			datconf_set_by_key(DPP_CFG_FILE, "allowed_role",    "2");
		} 
		else 
		{
			switch_br=1;
			wificonf_set_by_key(W24G_MH, "devicerole", "2");
			wificonf_set_by_key(W58G_MH, "devicerole", "2");

			datconf_set_by_key(MAPD_1905D_CONF_FILE, "map_agent", "1");
			datconf_set_by_key(MAPD_1905D_CONF_FILE, "map_root",  "0");
			datconf_set_by_key(MAPD_1905D_CONF_FILE, "map_ver",  "R2");

			datconf_set_by_key(MAPD_USER_CONF_FILE, "MapMode",    "1");
			datconf_set_by_key(MAPD_USER_CONF_FILE, "DeviceRole",    "2");
			datconf_set_by_key(MAPD_USER_CONF_FILE, "mode",    "2");
			datconf_set_by_key(MAPD_DEF_CONF_FILE, "LastMapMode",    "1");
			datconf_set_by_key(DPP_CFG_FILE, "allowed_role",    "1");

			datconf_set_by_key(MAPD_USER_CONF_FILE, "DhcpCtl",    "1");
		}
		genBssConfigs();
	}
	else
	{
		if(strcmp(opmode, "br")==0)
		{
			switch_br=1;
		}
		wificonf_set_by_key(W24G_MH,"mapmode","0");
		wificonf_set_by_key(W58G_MH,"mapmode","0");
		wificonf_set_by_key(W24G_MH,"disabled","1");
		wificonf_set_by_key(W58G_MH,"disabled","1");
		datconf_set_by_key(MAPD_USER_CONF_FILE, "MapMode",    "0");

		sprintf(cmd,"rm -f %s",MESH_INFO_FILE);
		CsteSystem(cmd, 0);
		sprintf(cmd,"echo -n ''>%s",MAPD_USER_CONF_FILE);
		CsteSystem(cmd, 0);
	}

	if(switch_br)
	{
		set_ethernet_port(1);
	}
	else
	{
		set_ethernet_port(0);
	}

	if(strcmp(opmode,"br")==0)
	{	
		if(strcmp(old_proto,"dhcp")!=0) {
			reload_network = 1;
			Uci_Set_Str(PKG_NETWORK_CONFIG, "lan", "proto", "dhcp");
		}
		Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "ignore", "1");
	}
	else
	{
		if(strcmp(old_proto,"static")!=0) 
		{
			Uci_Set_Str(PKG_NETWORK_CONFIG, "lan", "proto", "static");
			reload_network = 1;
		}
		Uci_Set_Str(PKG_DHCP_CONFIG, "lan", "ignore", "0");
	}

	Uci_Commit(PKG_DHCP_CONFIG);
	if(reload_network){
		Uci_Commit(PKG_NETWORK_CONFIG);
	}
	Uci_Commit(PKG_WIRELESS_CONFIG);

	set_lktos_effect("network");

	return 0;
}

#if defined(CONFIG_BOARD_MTK)
#include "mapd_interface_ctrl.h"

static int map_start_mesh(void)
{
	const char *ifmed = "1";

	mapd_interface_trigger_onboarding(NULL, ifmed); /* ifmed: 1 - Wireless and 0 - Ethernet */

	return 1;
}

int get_mesh_master_wps_status()
{
	struct mapd_interface_ctrl *ctrl = NULL;
	char conStatus[2] = {0};
	int ret,fhbss_status=0,bhsta_status=0;

	ctrl = mapd_interface_ctrl_open(MAPD_CTRL_FILE);
	if(!ctrl){
		dbg("mapd_interface_ctrl_open Failed!\n");
		return 0;
	}

	ret = mapd_interface_get_conn_status(ctrl, &fhbss_status, &bhsta_status);
	if(ret == -1){
		dbg("Command Failed!\n");
	}
	else if(ret == -2){
		dbg("Command Timed-out!!\n");
	}

	mapd_interface_ctrl_close(ctrl);

	return fhbss_status;
}


int get_mesh_current_device_role(int *role)
{
	struct mapd_interface_ctrl *ctrl = NULL;
	int devRole;
	int ret, res=1;

	*role = 0;
	//cause choke
	//if(is_ssid_disabled(W24G_IF) || is_ssid_disabled(W58G_IF))
	//	return 0;

	ctrl = mapd_interface_ctrl_open(MAPD_CTRL_FILE);
	if(!ctrl){
		return 0;
	}
	ret = mapd_interface_get_role(ctrl,&devRole);
	if(ret == -1){
		res = 0;
		goto exitfunc;
	}
	else if(ret == -2){
		res = 0;
		goto exitfunc;
	}
	else{
		*role = devRole;
	}
exitfunc:
	mapd_interface_ctrl_close(ctrl);

	return res;
}


int get_mesh_status(char *status, int len)
{
	struct mapd_interface_ctrl *ctrl = NULL;
	char conStatus[2] = {0};
	int ret = 0;

	if(len>0){
		status[0] = '\0';
	}
	ctrl = mapd_interface_ctrl_open(MAPD_CTRL_FILE);
	if(!ctrl){
		dbg("mapd_interface_ctrl_open Failed!\n");
		return -1;
	}

	ret = mapd_interface_bh_ConnectionStatus(ctrl, conStatus);
	if(ret == -1){
		dbg("Command Failed!\n");
	}
	else if(ret == -2){
		dbg("Command Timed-out!!\n");
	}
	else{/*command success*/
		if((int)conStatus[0] == 1){
			if(len>9){
				strncpy(status,"connected",len);
			}
			ret = 1;
		}
		else{
			if(len>13){
				strncpy(status,"disconnected",len);
			}
			ret = 2;
		}
	}
	mapd_interface_ctrl_close(ctrl);

	return ret;
}

int get_mesh_topo(char *buf, int buf_len)
{
	struct mapd_interface_ctrl *ctrl = NULL;
	int ret;

	memset(buf, 0, buf_len);
	ctrl = mapd_interface_ctrl_open(MAPD_CTRL_FILE);
	if(!ctrl){
		dbg("mapd_interface_ctrl_open Failed!\n");
		return -1;
	}

	ret = mapd_interface_get_topology(ctrl, buf, &buf_len, NULL);

	mapd_interface_ctrl_close(ctrl);

	return strlen(buf);
}

int apply_mesh_pre_channel(char *channel)
{
	struct mapd_interface_ctrl *ctrl = NULL;
	int ret;

	ctrl = mapd_interface_ctrl_open(MAPD_CTRL_FILE);
	if(!ctrl){
		return 0;
	}

	ret = mapd_interface_user_preferred_channel(ctrl, channel);
	if(ret == -1){
		dbg("channel %s :Command Failed\n", channel);
	} else if(ret == -2){
		dbg("channel %s :Command Timed-out\n", channel);
	} else{
		dbg("channel %s :apply channel success\n", channel);
	}
	mapd_interface_ctrl_close(ctrl);
	return 1;
}


#else
static int map_start_mesh(void)
{
	return 1;
}

int get_mesh_master_wps_status()
{
	int ret,fhbss_status=0,bhsta_status=0;

	return fhbss_status;
}

int get_mesh_current_device_role(int *role)
{
	int ret, res=1;
	
	return res;

}

int get_mesh_status(char *status, int len)
{
	int ret=0;
	
	return ret;

}

int get_mesh_topo(char *buf, int buf_len)
{
	memset(buf, 0, buf_len);

 	return strlen(buf);
}


int apply_mesh_pre_channel(char *channel)
{
	return 1;

}


#endif
int trigger_map_wps()
{
	int ret = 0,max_count=30, delay=120, check_revert=0;
	int current_role,is_wps_server=0;
	char status[16] = {0}, opmode_custom[16]={0};
	char map_mode_2g[8] = {0},map_mode_5g[8] = {0}, devicerole[8]={0};

	wificonf_get_by_key(W24G_MH,"mapmode",map_mode_2g,sizeof(map_mode_2g));
	wificonf_get_by_key(W58G_MH,"mapmode",map_mode_5g,sizeof(map_mode_5g));

	Uci_Get_Str(PKG_SYSTEM_CONFIG, "opmode", "opmode_custom",opmode_custom);
	if(strcmp(opmode_custom,"rpt")==0 || strcmp(opmode_custom,"wisp")==0)
	{
		return 1;
	}

	datconf_get_by_key(TEMP_STATUS_FILE, "wps_onboarding_trigger_flag", status, sizeof(status));
	if(atoi(status) == 1) {
		return 1;
	}

	if(atoi(map_mode_2g) == 0 || atoi(map_mode_5g) == 0)
	{
		if(is_phyport_connected(ETH_PORT_WAN)==0)
		{
			datconf_set_by_key(TEMP_STATUS_FILE, "wps_onboarding_trigger_flag", "1");

			start_wps_led();

			check_revert=1;
			setMapRole(DEV_AGENT);
			sleep(40);
			delay-=40;
		}
		else
		{
			return 1;
		}
	}
	else
	{
		datconf_set_by_key(TEMP_STATUS_FILE, "wps_onboarding_trigger_flag", "1");

		start_wps_led();
	}

	wificonf_get_by_key(W24G_MH, "devicerole", devicerole, sizeof(devicerole));
	current_role=atoi(devicerole);
	if(current_role == DEV_AUTO){
		get_mesh_current_device_role(&current_role);
	}

	if(current_role == DEV_CONTROLLER || (current_role == DEV_AGENT && get_mesh_status(status, sizeof(status)-1)==1))
	{
		is_wps_server=1;
	}

	while(max_count) {
		if(f_exists(MAPD_CTRL_FILE)) {
			map_start_mesh();
			break;
		} else {
			max_count--;
			sleep(2);
		}
	}

	while(delay>1)
	{
		if(is_wps_server == 1)
		{
			if(get_mesh_master_wps_status()!=1)
			{
				break;
			}
		}
		else if(get_mesh_status(status, sizeof(status)-1)==1)
		{
			ret=1;
			break;
		}
		sleep(1);
		delay--;
	}

	datconf_set_by_key(TEMP_STATUS_FILE, "wps_onboarding_trigger_flag", "0");
	led_system_init();

	if(check_revert==1 && ret==0)
	{
		setMapRole(-1);
	}

	return 0;
}


int get_mesh_agent_count()
{
	char topo_buff[15000];
	int count = 0;
	cJSON *root, *node_array;

	if(get_mesh_topo(topo_buff, 15000)>0){
		root = cJSON_Parse(topo_buff);
		node_array = cJSON_GetObjectItem(root, "topology information");
		count = cJSON_GetArraySize(node_array);
		cJSON_Delete(root);
	}

	return count;
}

int get_mesh_agent_rssi()
{
	char topo_buff[15000];

	char al_mac[18]={0},dev_mac[18]={0}, buff[128]={0};

	int ret = -100, count, i;

	cJSON *root, *node_array, *tmp_obj,*bh_info;

	if(get_mesh_topo(topo_buff, 15000)>0){
		get_ifname_macaddr("ra0", dev_mac);
		root = cJSON_Parse(topo_buff);
		if(!root)
		{
			goto end_label;
		}
		node_array = cJSON_GetObjectItem(root, "topology information");
		if(!node_array)
		{
			goto end_label;
		}

		count = cJSON_GetArraySize(node_array);
		for(i=0;i<count;i++)
		{
			tmp_obj = cJSON_GetArrayItem(node_array,i);
			if(!tmp_obj)
			{
				goto end_label;
			}
			get_cjson_string(tmp_obj, "AL MAC",  al_mac, sizeof(al_mac));
			if(strcasecmp(al_mac,dev_mac)==0)
			{
				bh_info = cJSON_GetObjectItem(tmp_obj, "BH Info");
				if(!bh_info)
				{
					goto end_label;
				}

				tmp_obj = cJSON_GetArrayItem(bh_info,0);
				if(!tmp_obj)
				{
					goto end_label;
				}
				get_cjson_string(tmp_obj, "RSSI",  buff, sizeof(buff));
				ret=atoi(buff);
				break;
			}
		}
		cJSON_Delete(root);
	}
end_label:
	return ret;
}




int get_flash_total_size()
{
	FILE *fp;
	char line[128];
	int flash_size=0;

	if (!(fp = fopen("/proc/mtd", "r")))
		return 16;

	while (fgets(line, sizeof(line), fp))
	{
		if(strstr(line,"flash size")==NULL)
		{
			continue;
		}

		sscanf(line, "flash size: %d %*s", &flash_size);
		break;
	}

	fclose(fp);

	if(flash_size==0){
		flash_size=16;
	}

	return flash_size;
}

int get_apcli_connected(int wl_idx)
{
	char cmd[256] = {0},result[128] ={0}, apcli_if[16]={0};

	wificonf_get_by_key(WLAN_APCLI,"ifname",apcli_if,sizeof(apcli_if));

	sprintf(cmd,"iwconfig %s | grep 'Access Point'", apcli_if);
	get_cmd_result(cmd, result,sizeof(result));

	if(strstr(result, "Access Point:") !=NULL && strstr(result,"Not-Associated")==NULL)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

int get_wps_apcli_connected(char *apcli_if)
{
	char cmd[256] = {0},result[128] ={0};

	sprintf(cmd,"iwconfig %s | grep 'Access Point'", apcli_if);
	get_cmd_result(cmd, result,sizeof(result));

	if(strstr(result, "Access Point:") !=NULL && strstr(result,"Not-Associated")==NULL)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

int get_apcli_signal(char *apcli_if)
{
	char cmd[256] = {0},result[128] ={0}, ifname[20]={0};
	if(!apcli_if){
		if(get_wps_apcli_connected("apcli0")){
			strcpy(ifname, "apcli0");
		}else if(get_wps_apcli_connected("apclix0")){
			strcpy(ifname, "apclix0");
		}else{
			return 0;
		}
	}else{
		strcpy(ifname, apcli_if);
	}

	sprintf(cmd,"iwconfig %s | grep 'Signal level:' | cut -d':' -f2", ifname);
	get_cmd_result(cmd, result,sizeof(result));

	return atoi(result);
}


int get_apcli_connect_ssid(int wl_idx,char *ssid,int len)
{
	char cmd[256] = {0},result[64] ={0};

	sprintf(cmd,"iw %s info | grep ssid | cut -d ' ' -f2",WL_IF[wl_idx].ifname);
	get_cmd_result(cmd, result,sizeof(result));

	strncpy(ssid,result,len);

	return 0;
}

int get_apcli_connect_bssid(const char *ifname,char *bssid,int len)
{
	char cmd[256] = {0},result[64] ={0};
	sprintf(cmd,"iwconfig %s |grep Point|cut -d ' ' -f17",ifname);
	get_cmd_result(cmd, result,sizeof(result));
	strncpy(bssid,result,len);
	return 0;
}

int get_real_ssid(char *ifname, char *ssid, int len)
{
	char cmd[256] = {0},result[64] ={0};
        sprintf(cmd,"iwconfig %s |grep ESSID|awk '{print $4}'|cut -d '\"' -f2",ifname);
        get_cmd_result(cmd, result,sizeof(result));
        strncpy(ssid,result,len);
        return 0;

}

int get_apcli_idx(void)
{
	int ret=0;
	char tmp_buf[24];

	wificonf_get_by_key(WLAN_APCLI,"disabled", tmp_buf, sizeof(tmp_buf));
	if(1 == atoi(tmp_buf)){
		wificonf_get_by_key(WLAN_APCLI,"device", tmp_buf, sizeof(tmp_buf));
		if(strcmp(tmp_buf,WL_IF[W58G_RADIO].section_name )==0){
			ret=1;
		}
	}else{
		ret=2;
	}

	return ret;
}

int get_apcli_enable(int wl_idx)
{
	int ret=0;
	char tmp_buf[24];

	wificonf_get_by_key(WLAN_APCLI,"disabled", tmp_buf, sizeof(tmp_buf));
	if(1 == atoi(tmp_buf)){
		return 0;
	}else{
		wificonf_get_by_key(WLAN_APCLI,"device", tmp_buf, sizeof(tmp_buf));
		if(strcmp(tmp_buf,WL_IF[W58G_RADIO].section_name )==0 && wl_idx == 1){
			ret=1;
		}else if(strcmp(tmp_buf,WL_IF[W24G_RADIO].section_name )==0 && wl_idx == 0){
			ret=1;
		}
	}
	
	return ret;
}

int get_channel(int wl_idx, char *channel)
{
	char cmd[256] = {0},result[64] ={0};
	sprintf(cmd,"iwconfig %s |grep 'Channel' |cut -d ':' -f3",WL_IF[wl_idx].ifname);
	get_cmd_result(cmd, result,sizeof(result));

	sprintf(channel,"%d", atoi(result));

	return 0;
}

int get_wlan_merge(int wl_idx, int wl_odx)
{
	char ssid_i[64],ssid_o[64];
	char key_i[128],key_o[128];
	char encryption_i[24],encryption_o[24];
	char hidden_i[8], hidden_o[8];

	wificonf_get_by_key(wl_idx,  "ssid",   ssid_i, sizeof(ssid_i));
	wificonf_get_by_key(wl_odx,  "ssid",   ssid_o, sizeof(ssid_o));

	wificonf_get_by_key(wl_idx,  "key",   key_i, sizeof(key_i));
	wificonf_get_by_key(wl_odx,  "key",   key_o, sizeof(key_o));

	wificonf_get_by_key(wl_idx,  "encryption",   encryption_i, sizeof(encryption_i));
	wificonf_get_by_key(wl_odx,  "encryption",   encryption_o, sizeof(encryption_o));

	wificonf_get_by_key(wl_idx,  "hidden",   hidden_i, sizeof(hidden_i));
	wificonf_get_by_key(wl_odx,  "hidden",   hidden_o, sizeof(hidden_o));

	if(strcmp(ssid_i,ssid_o)==0 && strcmp(key_i,key_o)==0 \
		&& strcmp(encryption_i,encryption_o)==0 \
		&& strcmp(hidden_i, hidden_o)==0 \
		&&is_ssid_disabled(wl_idx)==is_ssid_disabled(wl_odx))
	{
		return 1;
	}

	return 0;
}

int get_encryption_ui(int wl_idx, char *encryption_ui, char *encryptype_ui)
{
	char authmode[64], encryption[15];

	wificonf_get_by_key(wl_idx, "authmode", authmode, sizeof(authmode));
	wificonf_get_by_key(wl_idx, "encryption", encryption, sizeof(encryption));

	if(!strcmp(authmode,"OPEN") && !strstr(encryption,"WEP")){
		strcpy(encryption_ui,"0");
	}
	else if(!strcmp(authmode,"WPAPSK"))
	{
		strcpy(encryption_ui,"3");
	}
	else if(!strcmp(authmode,"WPA2PSK"))
	{
		strcpy(encryption_ui,"4");
	}
	else if(!strcmp(authmode,"WPAPSKWPA2PSK"))
	{
		strcpy(encryption_ui,"5");
	}
	else if(!strcmp(authmode,"WPA3PSK"))
	{
		strcpy(encryption_ui,"6");
	}
	else if(!strcmp(authmode,"WPA2PSKWPA3PSK"))
	{
		strcpy(encryption_ui,"7");
	}
	else if(!strcmp(authmode,"SHARED"))
	{
		strcpy(encryption_ui,"2");
	}else if( !strcmp(authmode,"OPEN") && strstr(encryption,"WEP") )
	{
		strcpy(encryption_ui,"1");
	}

	if(!strcmp(encryption,"NONE"))
	{
		strcpy(encryptype_ui,"0");
	}
	else if(!strcmp(encryption,"TKIP"))
	{
		strcpy(encryptype_ui,"3");
	}
	else if(!strcmp(encryption,"AES"))
	{
		strcpy(encryptype_ui,"4");
	}
	else if(!strcmp(encryption,"TKIPAES"))
	{
		strcpy(encryptype_ui,"5");
	}
	else if(!strcmp(encryption,"WEP-128"))
	{
		strcpy(encryptype_ui,"2");
	}else if(!strcmp(encryption,"WEP-64"))
	{
		strcpy(encryptype_ui,"1");
	}

	return 0;
}

int wificonf_set_disabled(int radio, int disabled)
{
	int wl_radio = W24G_RADIO;
	int wl_idx   = W24G_IF;
	int wl_guest = W24G_G1;
	int i;

	if(radio!=W24G_RADIO){
		wl_radio = W58G_RADIO;
		wl_idx   = W58G_IF;
		wl_guest = W58G_G1;
	}

	if(disabled == 1) {
		wificonf_set_by_key(wl_radio, "disabled", "1");
		wificonf_set_by_key(wl_idx,	  "disabled", "1");
		for(i=0;i<GUEST_SSID_NUM;i++)
		{
			wificonf_set_by_key(wl_guest+i, "disabled", "1");
		}
	} else {
		wificonf_set_by_key(wl_radio, "disabled", "0");
		wificonf_set_by_key(wl_idx,	  "disabled", "0");
	}

	return 0 ;
}

int get_soft_version(char *soft_version, int len)
{
	char commit_num[16], pre_verion[24];
	
	memset(commit_num,0,sizeof(commit_num));
	memset(pre_verion,0,sizeof(pre_verion));

	Uci_Get_Str(PKG_PRODUCT_CONFIG,"sysinfo","svn_num",commit_num);
	Uci_Get_Str(PKG_PRODUCT_CONFIG,"sysinfo","soft_version",pre_verion);

	snprintf(soft_version, len, "%s.%s", pre_verion, commit_num);

	return 0;
}

void str_del_char_bak(char *a,char c)
{
	int i,j;
	for(i=0,j=0; *(a+i)!='\0'; i++)
	{
		if(*(a+i)==c)
			continue;
		else
		{
		 	*(a+j)=*(a+i);
			j++;
		}
	}
   *(a+j)='\0';
   
}

void mac_del_split(const char *mac_org, char *mac_new)
{
	char *c = (char *) mac_org;
	int i = 0, j = 0;

	for (i = 0; i < 17; i++) 
	{
			if(c[i] != ':') {
					mac_new[j] = c[i];
					j++;
			}
	}

	return ;
}

void add_mac_split(const char *mac_org, char *mac_new)
{
	int i, j;
	mac_new[0] = 0;
	if (strlen(mac_org) == 12)
	{
		for (i = 0, j = 0; i < 12; i++)
		{
			if (i != 0 && (i%2) == 0)
				mac_new[j++] = ':';
			mac_new[j++] = mac_org[i];
		}
		mac_new[j] = 0;	// oleg patch
	}

	if (strcasecmp(mac_new, "FF:FF:FF:FF:FF:FF") == 0 || strcmp(mac_new, "00:00:00:00:00:00") == 0)
		mac_new[0] = 0;

	return ;
}

void str_tolower(char *str)
{
	while(*str != '\0'){
		*str = tolower(*str);
		str++;
	}
}

void str_toupper(char *str)
{
	while(*str != '\0'){
		*str = toupper(*str);
		str++;
	}
}

void str_escape(char *src,char *dec)
{

	char *ptr,tmp[8] = {0};
	ptr = src;
	
	if(!src || !dec)
		return;
	
	while(*ptr)
	{
		memset(tmp,0,sizeof(tmp));
		if(*ptr != '`' && *ptr != '"')
		{
			sprintf(tmp,"%c",*ptr);
		}
		else
		{
			sprintf(tmp,"\\%c",*ptr);
		}
		strcat(dec,tmp);
		ptr++;
	}
}


int datconf_set_by_key(char *path,char *key,char *value)
{
	struct kvc_context *ctx;
	int ret;
	char cmd[256]={0},value_esc[512] = {0};

	ctx = kvc_load_opt(path, DATCONF_LF_FLAGS, dat_nostrip_list);
	if (!ctx)
	{
		return 0;
	}
	str_escape(value,value_esc);

	ret = kvc_set(ctx, key, value_esc);

	if (ret) goto out;
	
	kvc_commit(ctx);
	
out:
	kvc_unload(ctx);
	return 0;
}


int datconf_get_by_key(char *path,char *key,char *value,int len)
{
	char *value_get;
	struct kvc_context *ctx;

	memset(value, 0, len);

	ctx = kvc_load_opt(path, DATCONF_LF_FLAGS, dat_nostrip_list);

	if (!ctx) return 0;

	value_get = kvc_get(ctx, key);

	if (!value_get) goto out;

	snprintf(value, len, "%s", value_get);

out:
	kvc_unload(ctx);

	return 0;
}

int datconf_get_ival(char *path,char *key)
{
	char *value_get;
	int  ret=0;
	struct kvc_context *ctx;

	ctx = kvc_load_opt(path, DATCONF_LF_FLAGS, dat_nostrip_list);

	if (!ctx) return 0;

	value_get = kvc_get(ctx, key);

	if (!value_get) goto out;

	ret=atoi(value_get);

out:
	kvc_unload(ctx);

	return ret;
}

int datconf_set_ival(char *path,char *key, int value)
{
	struct kvc_context *ctx;
	int ret;
	char value_esc[64] = {0};

	ctx = kvc_load_opt(path, DATCONF_LF_FLAGS, dat_nostrip_list);
	if (!ctx)
	{
		return 0;
	}
	sprintf(value_esc, "%d", value);

	ret = kvc_set(ctx, key, value_esc);

	if (ret) goto out;

	kvc_commit(ctx);

out:
	kvc_unload(ctx);
	return 0;
}

int wificonf_set_by_key(int idx, char *key, char *value)
{
	struct uci_context *uci_ctx = NULL;
	struct uci_package *pkg = NULL;
	struct uci_ptr uci_ptr;

	char uci_path[256];
	int ret;

	memset(uci_path,0,sizeof(uci_path));

	if(idx>=WLAN_MAX){
		return -1;
	}

	uci_ctx = uci_alloc_context();

	if(UCI_OK != uci_load(uci_ctx, "/etc/config/wireless", &pkg))
	{
		uci_free_context(uci_ctx);
		return -1;
	}

	snprintf(uci_path, sizeof(uci_path)-1,"wireless.%s.%s", WL_IF[idx].section_name, key);

	if(UCI_OK == uci_lookup_ptr(uci_ctx, &uci_ptr, uci_path, true))
	{
		uci_ptr.value = value;
		ret=uci_set(uci_ctx, &uci_ptr);
		if (ret == UCI_OK){
			ret = uci_save(uci_ctx, uci_ptr.p);
		}
	}

	uci_unload(uci_ctx, pkg);
	uci_free_context(uci_ctx);
	uci_ctx = NULL;

	return 0;
}

int wificonf_get_by_key(int idx, char *key, char *value, int len)
{
	struct uci_context *uci_ctx = NULL;
	struct uci_package *pkg = NULL;
	struct uci_element *e;

	bool sep = false;

	char *p_value = value;

	char uci_path[256]={0};

	struct uci_ptr uci_ptr;

	uci_ctx = uci_alloc_context();

	memset(value,0,len);

	if(idx>=WLAN_MAX){
		return -1;
	}

	if(UCI_OK != uci_load(uci_ctx, "/etc/config/wireless", &pkg))
	{
		strcpy(value,"");
		uci_free_context(uci_ctx);
		return -1;
	}

	snprintf(uci_path, sizeof(uci_path)-1,"wireless.%s.%s",WL_IF[idx].section_name, key);

    uci_lookup_ptr(uci_ctx, &uci_ptr, uci_path, true);
	if (!(uci_ptr.flags & UCI_LOOKUP_COMPLETE)) {
		goto end_label;
	}

	e = uci_ptr.last;
	switch (e->type) {
		case UCI_TYPE_OPTION:
			if (uci_ptr.o->type == UCI_TYPE_STRING) {
				snprintf(value, len, "%s", uci_ptr.o->v.string);
			} else if (uci_ptr.o->type == UCI_TYPE_LIST) {
				*p_value = '\0';
				uci_foreach_element(&(uci_ptr.o->v.list), e) {
					if ((strlen(value) + strlen(e->name) + 2) < len) {
						p_value += sprintf(p_value, "%s%s", sep?" ":"", e->name);
						sep = true;
					}
				}
			} else {
				return 0;
			}
			break;
		default:
			return 0;
	}

end_label:
	uci_unload(uci_ctx, pkg);
	uci_free_context(uci_ctx);
	uci_ctx = NULL;

	return 0;
}


int wificonf_add_by_key(int idx, char *key, char *value)
{
	char uci_path[256]={0}, cmd_line[256]={0};

	snprintf(uci_path, sizeof(uci_path)-1,"wireless.%s.%s", WL_IF[idx].section_name, key);

	memset(cmd_line,0,sizeof(cmd_line));
	snprintf(cmd_line, sizeof(cmd_line), "uci add_list %s=\"%s\"", uci_path,value);

	CsteSystem(cmd_line,0);

	return 0;
}

int wificonf_del_by_key(int idx, char *key, char *value)
{
	char uci_path[256], cmd_line[256]={0};

	snprintf(uci_path, sizeof(uci_path)-1,"wireless.%s.%s", WL_IF[idx].section_name, key);

	if(value && strlen(value)>0){
		snprintf(cmd_line,sizeof(cmd_line),"uci -q del_list %s=\"%s\"",uci_path, value);
	}else{
		snprintf(cmd_line,sizeof(cmd_line),"uci -q delete %s", uci_path);
	}
	system(cmd_line);

	return 0;
}

int get_mem_ratio(void)
{
	int mem_use_percent=0, mem_total=0, mem_use=0;
	char line_buffer[256]={0};

	get_cmd_result("free | grep Mem", line_buffer, sizeof(line_buffer));

	sscanf(line_buffer, "%*s %d %d %*s %*s %*s %*s", &mem_total, &mem_use);

	mem_use_percent=(mem_use*100)/mem_total;

	return mem_use_percent;
}

int get_wan_mode(char *proto)
{
	int ret = DHCP_DISABLED;

	if(0 == strcmp(proto, "static"))
		ret = DHCP_DISABLED;
	else if(0 == strcmp(proto, "pppoe"))
		ret = PPPOE;
	else if(0 == strcmp(proto, "pptp"))
		ret = PPTP;
	else if(0 == strcmp(proto, "l2tp"))
		ret = L2TP;
	else
		ret = DHCP_CLIENT;

	return ret;
}

void get_wan_linktime(unsigned long seconds, char *tmp_buf)
{
	unsigned long sec = seconds;
	unsigned long d, h, m;

	d = sec / 86400;
	sec %= 86400;
	h = sec / 3600;
	sec %= 3600;
	m = sec / 60;
	sec %= 60;
	sprintf(tmp_buf, "%ld;%ld;%ld;%ld", d, h, m, sec);
	return ;
}

void get_sys_uptime(char *tmpBuf)
{
	unsigned long sec, mn, hr, day;

	struct sysinfo info;

	sysinfo(&info);
	sec = (unsigned long) info.uptime ;

	day = sec / 86400;
	//day -= 10957; // day counted from 1970-2000

	sec %= 86400;
	hr = sec / 3600;
	sec %= 3600;
	mn = sec / 60;
	sec %= 60;
	sprintf(tmpBuf, "%ld;%ld;%ld;%ld", day, hr, mn, sec);

	return ;
}


void set_timezone_to_kernel(void)
{
	char time_zone[8]={0}, cmd_line[128]={0},*tz;

	Uci_Get_Str(PKG_SYSTEM_CONFIG, "ntp", "timezone", time_zone);

	if(strlen(time_zone)<4){
		return;
	}

	doSystem("echo %s > /etc/TZ", time_zone);

	if (strstr(time_zone,"-") != NULL) {
		tz = strstr(time_zone,"-");
	}
	else {
		tz = strstr(time_zone,"+");
	}

	//sscanf(time_zone,"UTC%d", &tz);

	snprintf(cmd_line, sizeof(cmd_line), "echo 'tz=%d' > /proc/mtd", atoi(tz));

	system(cmd_line);
}

int poweroff_lan_port(void)
{
	char opmode_custom[8]={0};
	int i;

	Uci_Get_Str(PKG_SYSTEM_CONFIG, "opmode", "opmode_custom",opmode_custom);

	for(i=0;i<5;i++){
		if(i==ETH_PORT_WAN && strcmp(opmode_custom,"gw")==0){
			continue;
		}
		//reset phy port switch mt7531
		doSystem("switch phy cl22 w %d 0 0x800", i);
	}

	return 0;
}

int reset_lan_port(void)
{
	char opmode_custom[8]={0};
	int i;

	Uci_Get_Str(PKG_SYSTEM_CONFIG, "opmode", "opmode_custom",opmode_custom);

	for(i=0;i<5;i++){
		if(i==ETH_PORT_WAN && strcmp(opmode_custom,"gw")==0){
			continue;
		}
		//reset phy port switch mt7531
		doSystem("switch phy cl22 w %d 0 0x8000", i);
	}

	return 0;
}

//for wx039
int iwpriv_set(char *iface, const char *key, const char *val)
{
	char iwpriv_cmd[128]={0};

	snprintf(iwpriv_cmd,sizeof(iwpriv_cmd)-1,"iwpriv %s set %s='%s'", iface, key, val);
	CsteSystem(iwpriv_cmd,0);

	return 0;
}

int wifi_iwpriv_ioctl_set_cmd(const char *ifname,const char* pkey_word,const char* pvalue)
{
    struct iwreq wrq;
	char all_arg[128] = {0};
	int s,status=0;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket");
		status=1;
		goto exit;
	}

	memcpy(all_arg,pkey_word,strlen(pkey_word));
	strncat(all_arg, "=", strlen("="));
	strncat(all_arg, pvalue, strlen(pvalue));
	strncpy(wrq.ifr_ifrn.ifrn_name, ifname, IFNAMSIZ);
	wrq.u.data.pointer = all_arg;
	wrq.u.data.length = strlen(all_arg);
	wrq.u.data.flags = 0;

	if (ioctl(s, 0x8BE2, &wrq) < 0) {
		dbg("ERROR:ioctl %s %s cmd \n", ifname, pkey_word);
		status=1;
		goto exit;
	}

exit:
	close(s);
	return status?-1:0;
}

int get_fixed_mac(char *wlan_if,int count, char *buffmac)
{
	char cmd[128] = {0}, buff[8] = {0}, tmp[32] = {0};
	unsigned char tmpmac[6] = {0};
	int i;
	sprintf(cmd, "cs mac r %s  |awk '{print $2}'", wlan_if);
	FILE *fp = popen(cmd, "r");
	if(!fp) {
		return -1;
	}
	if(fgets(tmp, sizeof(tmp)-1, fp) != NULL){
		sscanf(tmp,"%02x:%02x:%02x:%02x:%02x:%02x",&tmpmac[0],&tmpmac[1],&tmpmac[2],&tmpmac[3],&tmpmac[4],&tmpmac[5]);
		for(i=12-count;i<12;i++){
			memset(buff,0,sizeof(buff));
			if(i%2)
			sprintf(buff, "%01X",(tmpmac[i/2] & 0xf));
			else
			sprintf(buff, "%01X",(tmpmac[i/2] & 0xf0)>>4);
			if(i==0)
				strcpy(buffmac,buff);
			else
				strcat(buffmac,buff);
		}

	}
	pclose(fp);

	return 0;
}


void switchMacFormat(char *srcMac,char *destMac)
{
	int i=0,j=0,len=0;
	len=strlen(srcMac);
	for(i=0;i<len;i++){
		if(*(srcMac+i)=='-' || *(srcMac+i)==':' || *(srcMac+i)=='.' || *(srcMac+i)=='\r' || *(srcMac+i)=='\n')
			continue;
		*(destMac+j)=toupper(*(srcMac+i));
		j++;
	}
	*(destMac+j)='\0';
}


#if defined(CONFIG_AUTO_SERIALNUMBER)
static const char BaseCode[] = "2ABC3DEF4GHJ5KLM6NPQ7RST8UVW9XYZ";

int fixed_auto_sn()
{
	char cmd_line[128],buff[16],code[9], value[64] = {0}, model[64] = {0};
	int mac[6],i=0;
	
	Uci_Get_Str(PKG_PRODUCT_CONFIG, "ispinfo", "serial_number", value);
	Uci_Get_Str(PKG_PRODUCT_CONFIG, "sysinfo", "soft_model", model);
	if(strstr(value, model)) {
		return 0;
	}

	memset(cmd_line,0,sizeof(cmd_line));
	memset(buff,0,sizeof(buff));
	memset(code,0,sizeof(code));

	get_fixed_mac("lan",6, buff);
	sscanf(buff,"%1x%1x%1x%1x%1x%1x",&mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]);
	for(i=0; i<6; i++){
		code[i] = BaseCode[mac[i]];
	}
	code[6] = BaseCode[mac[0]+mac[1]];
	code[7] = BaseCode[mac[2]+mac[3]];

	memset(value,0,sizeof(value));
	sprintf(value,"%s%s",model,code);
	Uci_Set_Str(PKG_PRODUCT_CONFIG, "ispinfo", "serial_number", value);
	Uci_Commit(PKG_PRODUCT_CONFIG);

	return 1;
	
}
#endif


void get_time_zone_info(char *tz, char *args, char *zonename) 
{
	char tz_1[8] = {0}, tz_2[8] = {0}, tmp_zonename[128] = {0};
	const size_t len = 20;
	int i=0;

#if defined(CONFIG_TIME_ZONE_CUSTOM)
	if(strcmp(args, "ZoneName") == 0) {
		for(i=0; i< 24; i++) {
			if(strcmp(tz, zone_name[i].zone) == 0) {
				sprintf(tmp_zonename, "%s", zone_name[i].desc);
				break;
			}
		}
	}else if(strcmp(args, "TZ") == 0) {
		if(strstr(tz, "+")) {
			get_nth_val_safe(1, tz, '+', tz_2, sizeof(tz_2));
			if(atoi(tz_2) < 10)
				sprintf(tmp_zonename, "-0%s.00", tz_2);
			else 
				sprintf(tmp_zonename, "-%s.00", tz_2);
		}else if(strstr(tz, "-")) {
			get_nth_val_safe(1, tz, '-', tz_2, sizeof(tz_2));
			if(atoi(tz_2) < 10)
				sprintf(tmp_zonename, "+0%s.00", tz_2);
			else 
				sprintf(tmp_zonename, "+%s.00", tz_2);
		}
	}
	
#else
	if(strstr(tz, "+")) {
		get_nth_val_safe(0, tz, '+', tz_1, sizeof(tz_1));
		get_nth_val_safe(1, tz, '+', tz_2, sizeof(tz_2));
		sprintf(tmp_zonename, "%s-%s", tz_1, tz_2);
	}else if(strstr(tz, "-")) {
		get_nth_val_safe(0, tz, '-', tz_1, sizeof(tz_1));
		get_nth_val_safe(1, tz, '-', tz_2, sizeof(tz_2));
		sprintf(tmp_zonename, "%s+%s", tz_1, tz_2);
	}else {
		sprintf(tmp_zonename, "%s", tz);
	}
#endif

	strcpy(zonename, tmp_zonename);
}

void set_time_zone_info(char *args, char *value, char *zonename)
{
	char tz_1[8] = {0}, tz_2[8] = {0}, tmp_zonename[128] = {0};
	char tmp_value[8] = {0};
	
#if defined(CONFIG_TIME_ZONE_CUSTOM)
	if(strcmp(args, "ZoneName") == 0) {
	}else if(strcmp(args, "TZ") == 0) {
		if(atoi(value) > 0) {
			sprintf(tmp_zonename, "UTC-%d", atoi(value));
		}else if(atoi(value) <=0) {
			sprintf(tmp_zonename, "UTC+%d", atoi(value));
		}
	}
#else
	if(strstr(value, "+")) {
		get_nth_val_safe(0, value, '+', tz_1, sizeof(tz_1));
		get_nth_val_safe(1, value, '+', tz_2, sizeof(tz_2));
		sprintf(tmp_zonename, "%s-%s", tz_1, tz_2);
	}else if(strstr(value, "-")) {
		get_nth_val_safe(0, value, '-', tz_1, sizeof(tz_1));
		get_nth_val_safe(1, value, '-', tz_2, sizeof(tz_2));
		sprintf(tmp_zonename, "%s+%s", tz_1, tz_2);
	}
#endif	
	strcpy(zonename, tmp_zonename);
}

void get_time_status(char *enabled, char *sValue)
{
	char tmp_value[16] = {0};
	
#if defined(CONFIG_TIME_ZONE_CUSTOM)
	snprintf(tmp_value, sizeof(tmp_value), "%s", "Synchronized");
#else
	snprintf(tmp_value, sizeof(tmp_value), "%s", (atoi(enabled) ? "true" : "false"));
#endif
	strcpy(sValue, tmp_value);
}


void set_wired_vlan()
{
	int wan_port = ETH_PORT_WAN;
	int lan_port[5] = {
		ETH_PORT_LAN1,
		ETH_PORT_LAN2,
		ETH_PORT_LAN3,
		ETH_PORT_LAN4,
		ETH_PORT_LAN5
	};

	char tmp[64]={0};
	char wan_list[32]={0},lan_list[32]={0};
	char section[32]={0},tmp_buf[32]={0};


	for(int i= 0; i<5; i++)
	{
		if(lan_port[i]>-1 && lan_port[i] != 5 && wan_port != 6)
		{
			snprintf(lan_list + strlen(lan_list), sizeof(lan_list) - strlen(lan_list), "%d ", lan_port[i]);
		}
	}
	
	snprintf(lan_list + strlen(lan_list), sizeof(lan_list) - strlen(lan_list), "5t");

	//LAN SWITCH
	if(strlen(lan_list))
	{
		snprintf(section,sizeof(section)-1,"@switch_vlan[0]");
		memset(tmp_buf, 0, sizeof(tmp_buf));
		Uci_Get_Str(PKG_NETWORK_CONFIG,section, "device", tmp_buf);
		if(strlen(tmp_buf)==0)
		{
			Uci_Add_Section(PKG_NETWORK_CONFIG,"switch_vlan");
		}
		Uci_Set_Str(PKG_NETWORK_CONFIG,section, "device", "switch0");
		Uci_Set_Str(PKG_NETWORK_CONFIG,section, "vlan", "2");
		Uci_Set_Str(PKG_NETWORK_CONFIG,section,"ports",lan_list);
	}

	//WAN SWITCHS
	if(wan_port > -1 && wan_port != 5 && wan_port != 6) 
	{
		snprintf(wan_list , sizeof(wan_list) , "%d ",wan_port);
		strcat(wan_list,"5t");
		memset(tmp_buf, 0, sizeof(tmp_buf));
		snprintf(section,sizeof(section)-1, "@switch_vlan[1]");
		Uci_Get_Str(PKG_NETWORK_CONFIG,section, "device", tmp_buf);
		if(strlen(tmp_buf)==0)
		{
				Uci_Add_Section(PKG_NETWORK_CONFIG,"switch_vlan");
		}
		Uci_Set_Str(PKG_NETWORK_CONFIG,section, "device", "switch0");
		Uci_Set_Str(PKG_NETWORK_CONFIG,section, "vlan", "1");
		Uci_Set_Str(PKG_NETWORK_CONFIG, section, "ports",wan_list);
	}

}

void set_modem_vlan()
{
	int wan_port = ETH_PORT_WAN;
	int lan_port[5] = {
		ETH_PORT_LAN1,
		ETH_PORT_LAN2,
		ETH_PORT_LAN3,
		ETH_PORT_LAN4,
		ETH_PORT_LAN5
	};

	char tmp[64]={0};
	char wan_list[32]={0},lan_list[32]={0};
	char section[32]={0},tmp_buf[32]={0};


	for(int i= 0; i<5; i++)
	{
		if(lan_port[i]>-1 && lan_port[i] != 5 && wan_port != 6)
		{
			snprintf(lan_list + strlen(lan_list), sizeof(lan_list) - strlen(lan_list), "%d ", lan_port[i]);
		}
	}
	
	snprintf(lan_list + strlen(lan_list), sizeof(lan_list) - strlen(lan_list), "%d ", wan_port);
	
	snprintf(lan_list + strlen(lan_list), sizeof(lan_list) - strlen(lan_list), "5t");

	Uci_Get_Str(PKG_NETWORK_CONFIG,"ports", "ports", tmp_buf);

	//LAN SWITCH
	if(strlen(lan_list))
	{
		snprintf(section,sizeof(section)-1,"@switch_vlan[0]");
		Uci_Get_Str(PKG_NETWORK_CONFIG,section, "device", tmp_buf);
		if(strlen(tmp_buf)==0)
		{
			Uci_Add_Section(PKG_NETWORK_CONFIG,"switch_vlan");
		}
		Uci_Set_Str(PKG_NETWORK_CONFIG,section, "device", "switch0");
		Uci_Set_Str(PKG_NETWORK_CONFIG,section, "vlan", "2");
		Uci_Set_Str(PKG_NETWORK_CONFIG,section,"ports",lan_list);
	}

}

void set_ethernet_port(int br_mode)
{
	char tmp_buf[128]={0}, section[32], vlan_tag[8];
	int found_switch = 1, switch_wan = 0, switch_lan = 0, i = 0;


#if defined (ETH_PORT_MAP)

#if	defined(SUPPORT_SWITCH_SWCONFIG)


	char wan_code[8]={0},lan_code[8]={0};

	sscanf(WAN_IFNAME, "eth0.%d", wan_code);
	sscanf(LAN_IFNAME, "eth0.%d", lan_code);

	Uci_Del_Section(PKG_NETWORK_CONFIG, "@switch_vlan[0]");
	Uci_Del_Section(PKG_NETWORK_CONFIG, "@switch_vlan[0]");

	get_cmd_result("swconfig list", tmp_buf, sizeof(tmp_buf));
	if(!strlen(tmp_buf) || !strstr(tmp_buf,"Found: switch"))//no found switch ,disable vlan
	{
		found_switch =  0;
		logmessage("custom_apply","Not found swicth!!!");
	}

	int port_num;
	char *sptr,*ptr,tmp[18] = {0},port_layout[] = ETH_PORT_LAYOUT;
	int wan_port = ETH_PORT_WAN,lan_port[5] = {
		ETH_PORT_LAN1,
		ETH_PORT_LAN2,
		ETH_PORT_LAN3,
		ETH_PORT_LAN4,
		ETH_PORT_LAN5
	};
	char wan_list[32],lan_list[32];

	port_num = 0;
	for(sptr = ptr = port_layout; ptr-sptr < strlen(port_layout); ptr++)
	{
		if(*ptr=='W')
			port_num++;
		else if(*ptr=='L')
			port_num++;
		else
			continue;
	}

	snprintf(tmp,sizeof(tmp),"%d",port_num);
	Uci_Set_Str(PKG_SYSTEM_CONFIG, "main", "port_num", tmp);
	snprintf(tmp,sizeof(tmp),"%d",wan_port);
	Uci_Set_Str(PKG_SYSTEM_CONFIG, "main", "wan_port", tmp);
	Uci_Commit(PKG_SYSTEM_CONFIG);

	if(found_switch) {

		snprintf(section,sizeof(section)-1, "@switch[0]");
		memset(tmp_buf, 0, sizeof(tmp_buf));
		Uci_Get_Str(PKG_NETWORK_CONFIG,section, "name", tmp_buf);
		if(strlen(tmp_buf)==0) {
			Uci_Add_Section(PKG_NETWORK_CONFIG, "switch");
			Uci_Set_Str(PKG_NETWORK_CONFIG,section, "name", "switch0");
			Uci_Set_Str(PKG_NETWORK_CONFIG,section, "reset", "1");
			Uci_Set_Str(PKG_NETWORK_CONFIG,section, "enable_vlan", "1");
		}

		memset(lan_list,0,sizeof(lan_list));
		memset(wan_list,0,sizeof(wan_list));
		if(wan_port > -1 && wan_port != 5) {
			snprintf(wan_list,sizeof(wan_list),"%d",wan_port);
			switch_wan = 1;
		}

		for(i= 0; i<5; i++) {
			if(lan_port[i]>-1) {
				if(!strlen(lan_list)) {
					snprintf(lan_list,sizeof(lan_list),"%d",lan_port[i]);
				}
				else {
					snprintf(tmp,sizeof(tmp)," %d",lan_port[i]);
					strcat(lan_list,tmp);
				}
				switch_lan = 1;
			}
		}

		memset(vlan_tag,0,sizeof(vlan_tag));
		if(switch_lan && switch_wan) {
			if(br_mode) {
				strcat(lan_list, " ");
				strcat(lan_list, strlen(wan_list) ? wan_list : "");
				memset(wan_list, 0, sizeof(wan_list));
				strcpy(vlan_tag, " 5");
			}
			else {
				strcpy(vlan_tag, " 5t");
			}
		}
		else if(switch_lan) {
			strcpy(vlan_tag, " 5");
		}

		//LAN SWITCH
		if(strlen(lan_list)) {
			strcat(lan_list,vlan_tag);
			snprintf(section,sizeof(section)-1, "@switch_vlan[0]");
			memset(tmp_buf, 0, sizeof(tmp_buf));
			Uci_Get_Str(PKG_NETWORK_CONFIG,section, "device", tmp_buf);
			if(strlen(tmp_buf)==0)
			{
				Uci_Add_Section(PKG_NETWORK_CONFIG, "switch_vlan");
			}
			Uci_Set_Str(PKG_NETWORK_CONFIG,section, "device", "switch0");
			Uci_Set_Str(PKG_NETWORK_CONFIG,section, "vlan", lan_code);
			Uci_Set_Str(PKG_NETWORK_CONFIG,section, "ports",lan_list);
		}

		//WAN SWITCHS
		if(strlen(wan_list)) {
			strcat(wan_list,vlan_tag);
			memset(tmp_buf, 0, sizeof(tmp_buf));
			snprintf(section,sizeof(section)-1, "@switch_vlan[1]");
			Uci_Get_Str(PKG_NETWORK_CONFIG,section, "device", tmp_buf);
			if(strlen(tmp_buf)==0)
			{
				Uci_Add_Section(PKG_NETWORK_CONFIG,"switch_vlan");
			}
			Uci_Set_Str(PKG_NETWORK_CONFIG,section, "device", "switch0");
			Uci_Set_Str(PKG_NETWORK_CONFIG,section, "vlan", wan_code);
			Uci_Set_Str(PKG_NETWORK_CONFIG, section, "ports", wan_list);
		}
	}

	if(br_mode) {
		if(!switch_wan) {//switch not support wan, wan bridge to lan
			Uci_Del_List_All(PKG_NETWORK_CONFIG, "@device[0]", "ports");
			Uci_Add_List(PKG_NETWORK_CONFIG, "@device[0]", "ports", LAN_IFNAME);
			Uci_Add_List(PKG_NETWORK_CONFIG, "@device[0]", "ports", WAN_IFNAME);
		}
		else {
			Uci_Del_List_All(PKG_NETWORK_CONFIG, "@device[0]", "ports");
			Uci_Add_List(PKG_NETWORK_CONFIG, "@device[0]", "ports", ETH_IFNAME);
		}
		Uci_Set_Str(PKG_NETWORK_CONFIG, "wan", "device", "");
	}
	else {
		Uci_Del_List_All(PKG_NETWORK_CONFIG, "@device[0]", "ports");
		Uci_Add_List(PKG_NETWORK_CONFIG, "@device[0]", "ports", LAN_IFNAME);
		Uci_Set_Str(PKG_NETWORK_CONFIG, "wan", "device", WAN_IFNAME);
	}
#else
//#FIXED ME
#endif
	Uci_Commit(PKG_NETWORK_CONFIG);
#endif

}

int getOpmodeVal()
{
    int val=1;
    char tmpBuf[8]={0};

    Uci_Get_Str(PKG_SYSTEM_CONFIG,"opmode","opmode_custom",tmpBuf);
    if(strcmp(tmpBuf, "gw") == 0)
    	val=1;
    else if(strcmp(tmpBuf, "br") == 0)
        val=0;
    else if(strcmp(tmpBuf, "rpt") == 0)
        val=2;
    else if(strcmp(tmpBuf, "wisp") == 0)
        val=3;
    else
        val=1;

    return val;
}

#if defined (APP_QUAGGA)
int CsDealQuaggaConf(int setType)
{
	char sRules[2048] = {0}, sRule[128]={0};
	char type[32] = {0}, address[32] = {0};
	char area_num[8] = {0};
	char inface[32] = {0}, buf[32] = {0};
	char wanIp[32] = {0};
	char buff[256] = {0};
	char conf_file[32] = {0};
	char log_file[32] = {0}, updateSource[32] = {0};
	char routerAs[8] = {0}, remoteAs[8] = {0},routerId[32] = {0};
	char logChange[8] = {0},autoSummary[8] = {0},synchron[8] = {0};
	char paramName[32]={0};
	int iRulesNum = 0, i = 0;
	int rConnect = 0,  rStatic = 0, rKernel = 0;
	FILE *fpp = NULL;
	struct interface_status link_status;
		
	if (setType == RIPD_CONF)
	{
		sprintf(conf_file, "%s", QUAGGA_RIPD_CONF);
		strcpy(log_file, "/tmp/rip.log");
	}
	else if (setType == OSPFD_CONF)
	{
		sprintf(conf_file, "%s", QUAGGA_OSPFD_CONF);
		strcpy(log_file, "/tmp/ospf.log");
	}
	else if (setType == BGPD_CONF)
	{
		sprintf(conf_file, "%s", QUAGGA_BGPD_CONF);
		strcpy(log_file, "/tmp/bgp.log");
	}
		
	fpp = fopen(conf_file, "w");
	if(fpp == NULL)
		return -1;

	fwrite("password zebra\n", 1, strlen("password zebra\n"), fpp);
	sprintf(buff, "log file %s\n\n", log_file);
	fwrite(buff, 1, strlen(buff), fpp);

	if (setType == RIPD_CONF)
	{
		fwrite("router rip\n", 1, strlen("router rip\n"), fpp);
		
		Uci_Get_Int(PKG_ROUTER_QUAGGA_CONFIG, "ripd", "reCnnt", &rConnect);
		Uci_Get_Int(PKG_ROUTER_QUAGGA_CONFIG, "ripd", "reStatic", &rStatic);
		Uci_Get_Int(PKG_ROUTER_QUAGGA_CONFIG, "ripd", "reKernel", &rKernel);
		Uci_Get_Int(PKG_ROUTER_QUAGGA_CONFIG, "ripd", "num", &iRulesNum);	
		Uci_Get_Str(PKG_ROUTER_QUAGGA_CONFIG, "ripd", "rules", sRules);
	}
	else if (setType == OSPFD_CONF)
	{
		fwrite("router ospf\n", 1, strlen("router ospf\n"), fpp);

		get_wan_status(&link_status);
		if(strcmp(link_status.ipaddr_v4, "") == 0){
			get_ifname_ipaddr(LAN_DEV_NAME, wanIp);
		}else
			strcpy(wanIp, link_status.ipaddr_v4);

		sprintf(buff, " ospf router-id %s\n", wanIp);
		fwrite(buff, 1, strlen(buff), fpp);

		Uci_Get_Int(PKG_ROUTER_QUAGGA_CONFIG, "ospfd", "reCnnt", &rConnect);
		Uci_Get_Int(PKG_ROUTER_QUAGGA_CONFIG, "ospfd", "reStatic", &rStatic);
		Uci_Get_Int(PKG_ROUTER_QUAGGA_CONFIG, "ospfd", "reKernel", &rKernel);
		Uci_Get_Int(PKG_ROUTER_QUAGGA_CONFIG, "ospfd", "num", &iRulesNum);	
		Uci_Get_Str(PKG_ROUTER_QUAGGA_CONFIG, "ospfd", "rules", sRules);
	}
	else if(setType == BGPD_CONF)
	{
		Uci_Get_Int(PKG_ROUTER_QUAGGA_CONFIG, "bgpd", "num", &iRulesNum);
		Uci_Get_Str(PKG_ROUTER_QUAGGA_CONFIG, "bgpd", "router_as", routerAs);
		Uci_Get_Str(PKG_ROUTER_QUAGGA_CONFIG, "bgpd", "router_id", routerId);
		Uci_Get_Str(PKG_ROUTER_QUAGGA_CONFIG, "bgpd", "rules", sRules);
	}
		
	if(rConnect == 1)
		fwrite(" redistribute connected\n", 1, strlen(" redistribute connected\n"), fpp);
	if(rStatic == 1)
		fwrite(" redistribute static\n", 1, strlen(" redistribute static\n"), fpp);
	if(rKernel == 1)
		fwrite(" redistribute kernel\n", 1, strlen(" redistribute kernel\n"), fpp);

	if (iRulesNum == 0)
	{
		fclose(fpp);
		return 0;
	}	

	for(i=0;i < iRulesNum; i++)
	{
		bzero(type, sizeof(type));
		bzero(address, sizeof(address));
		bzero(buff, sizeof(buff));
		bzero(sRule, sizeof(sRule));

		get_nth_val_safe(i, sRules, ' ', sRule, sizeof(sRule));
		
		if (setType == RIPD_CONF)
		{
			get_nth_val_safe(0, sRule, ',', type, sizeof(type));
			get_nth_val_safe(1, sRule, ',', address, sizeof(address));

			if(!strcmp(type, "neighbour"))
				sprintf(buff, " neighbor %s\n", address);
			else
				sprintf(buff, " %s %s\n", type, address);
			fwrite(buff, 1, strlen(buff), fpp);
		}
		else if (setType == OSPFD_CONF)
		{
			bzero(area_num, sizeof(area_num));
			bzero(inface, sizeof(inface));
			bzero(buf, sizeof(buf));
			
			get_nth_val_safe(0, sRule, ',', type, sizeof(type));
			if(!strcmp(type, "network"))
			{
				get_nth_val_safe(1, sRule, ',', address, sizeof(address));
				get_nth_val_safe(2, sRule, ',', area_num, sizeof(area_num));
				sprintf(buff, " %s %s area %s\n", type, address, area_num);
				fwrite(buff, 1, strlen(buff), fpp);	
			}
			else if(!strcmp(type, "neighbour"))
			{
				get_nth_val_safe(1, sRule, ',', address, sizeof(address));
				sprintf(buff, " neighbor %s\n", address);
				fwrite(buff, 1, strlen(buff), fpp);
			}
			else
			{
				get_nth_val_safe(1, sRule, ',', inface, sizeof(inface));
				if(strcmp(inface, "lan") == 0){
					sprintf(buf, "%s", LAN_DEV_NAME);
				}else if(strcmp(inface, "modem") == 0){
					sprintf(buf, "%s", link_status.device);
				}else{
					sprintf(buf, "%s", WAN_IFNAME);
				}
					
				sprintf(buff, " %s %s\n", type, buf); // li: interface eth2.2
				fwrite(buff, 1, strlen(buff), fpp);
				
				memset(buf, 0, sizeof(buf));
				get_nth_val_safe(2, sRule, ',', buf, sizeof(buf));
				if(strlen(buf) > 5) // cost:1-65535, network_type: broadcsat|point-to-point....
				{
					sprintf(buff, " ospf network %s\n", buf);
				}
				else
				{
					sprintf(buff, " ospf cost %s\n", buf);
				}
				fwrite(buff, 1, strlen(buff), fpp);
			}	
		}
		else if (setType == BGPD_CONF)
		{
			sprintf(buff, "router bgp %s\n", routerAs);
			fwrite(buff, 1, strlen(buff), fpp);

			memset(buff, 0, sizeof(buff));
			sprintf(buff, " bgp router-id %s\n", routerId);
			fwrite(buff, 1, strlen(buff), fpp);
			
			get_nth_val_safe(0, sRule, ',', type, sizeof(type));
			get_nth_val_safe(1, sRule, ',', address, sizeof(address));
			if(!strcmp(type, "neighbour"))
			{
				get_nth_val_safe(2, sRule, ',', remoteAs, sizeof(remoteAs));
				get_nth_val_safe(3, sRule, ',', updateSource, sizeof(updateSource));
				get_nth_val_safe(4, sRule, ',', logChange, sizeof(logChange));
				get_nth_val_safe(5, sRule, ',', autoSummary, sizeof(autoSummary));
				get_nth_val_safe(6, sRule, ',', synchron, sizeof(synchron));
				sprintf(buff, " neighbor %s remote-as %s\n",address, remoteAs);
				fwrite(buff, 1, strlen(buff), fpp);
				if(strlen(updateSource) > 0)
				{
					sprintf(buff, " neighbor %s update-source %s\n",address, updateSource);
					fwrite(buff, 1, strlen(buff), fpp);
				}
				if(atoi(logChange) == 1)
					fwrite(" bgp log-neighbor-changes\n", 1, strlen(" bgp log-neighbor-changes\n"), fpp);
				if(atoi(autoSummary) == 0)
					fwrite(" no auto-summary\n", 1, strlen(" no auto-summary\n"), fpp);
				if(atoi(synchron) == 0)
					fwrite(" no synchronization\n", 1, strlen(" no synchronization\n"), fpp);
			}
			else
			{
				sprintf(buff, " %s %s\n", type, address);
				fwrite(buff, 1, strlen(buff), fpp);
			}
			fwrite("!\n", 1, strlen("!\n"), fpp);
		}
	}
	fwrite("!\n", 1, strlen("!\n"), fpp);
	fclose(fpp);
	return 0;
}

void CsRealReloadRouterQuagga(void)
{
	int rip_num=0, ospf_num=0, bgp_num=0;

	Uci_Get_Int(PKG_ROUTER_QUAGGA_CONFIG, "ripd", "num", &rip_num);
	Uci_Get_Int(PKG_ROUTER_QUAGGA_CONFIG, "ospfd", "num", &ospf_num);
	Uci_Get_Int(PKG_ROUTER_QUAGGA_CONFIG, "bgpd", "num", &bgp_num);

	if(!rip_num)
		unlink(QUAGGA_RIPD_CONF);

	if(!ospf_num)
		unlink(QUAGGA_OSPFD_CONF);

	if(!bgp_num)
		unlink(QUAGGA_BGPD_CONF);

	CsteSystem("/usr/sbin/quagga.init stop", CSTE_PRINT_CMD);
	
	if(rip_num == 0 && ospf_num == 0 && bgp_num == 0){
		return ;
	}

	if(rip_num)
		CsDealQuaggaConf(RIPD_CONF);

	if(ospf_num)
		CsDealQuaggaConf(OSPFD_CONF);

	if(bgp_num)
		CsDealQuaggaConf(BGPD_CONF);

	CsteSystem("/usr/sbin/quagga.init start", CSTE_PRINT_CMD);
	
	return ;
}

#endif

int netmask_to_bits(char *mask)
{
	int i=0, count=0, value=0;
	char buf[8]={0};

	while(get_nth_val_safe(i++, mask, '.', buf, sizeof(buf)) != -1){
		value=atoi(buf);
		while (value) {
	        count += value & 1;
	        value >>= 1;
	    }
	}

	return count;
}

int get_ip_network_num(char *ip, char *netmask)
{
	char buf[8]={0};
	int ip_arry[4]={0}, mask_arry[4]={0}, NSID_arr[4]={0};
	int i=0;

	if(strcmp(ip, "") == 0 || strcmp(netmask, "") == 0)
		return -1;
	if(strstr(ip, ".") == NULL || strstr(netmask, ".") == NULL)
		return -1;
	
	while(get_nth_val_safe(i++, ip, '.', buf, sizeof(buf)) != -1){
		ip_arry[i-1]=atoi(buf);
	}

	i=0;
	memset(buf, 0, sizeof(buf));
	while(get_nth_val_safe(i++, netmask, '.', buf, sizeof(buf)) != -1){
		mask_arry[i-1]=atoi(buf);
	}

	for(i = 0; i < 4; i++)
    {
        NSID_arr[i] = ip_arry[i] & mask_arry[i];
    }
	
	sprintf(netmask, "%d.%d.%d.%d", NSID_arr[0], NSID_arr[1], NSID_arr[2], NSID_arr[3]);

	return 1;
}

int getNthValueSafe(int index, char *value, char delimit, char *result, int len)
{
    int i=0, result_len=0;
    char *begin, *end;

    if(!value || !result || !len)
        return -1;

    begin = value;
    end = strchr(begin, delimit);

    while(i<index && end){
        begin = end+1;
        end = strchr(begin, delimit);
        i++;
    }

    //no delimit
    if(!end){
		if(i == index){
			end = begin + strlen(begin);
			result_len = (len-1) < (end-begin) ? (len-1) : (end-begin);
		}else
			return -1;
	}else
		result_len = (len-1) < (end-begin)? (len-1) : (end-begin);

	memcpy(result, begin, result_len );
	*(result+ result_len ) = '\0';

	return 0;
}

int getIfMac(char *ifname, char *if_hw)
{
	struct ifreq ifr;
	char *ptr;
	int skfd;

	if((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		//error(E_L, E_LOG, T("getIfMac: open socket error"));
		return -1;
	}

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	if(ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0) {
		close(skfd);
		//error(E_L, E_LOG, T("getIfMac: ioctl SIOCGIFHWADDR error for %s"), ifname);
		return -1;
	}

	ptr = (char *)&ifr.ifr_addr.sa_data;
	sprintf(if_hw, "%02X:%02X:%02X:%02X:%02X:%02X",
			(ptr[0] & 0377), (ptr[1] & 0377), (ptr[2] & 0377),
			(ptr[3] & 0377), (ptr[4] & 0377), (ptr[5] & 0377));

	close(skfd);
	return 0;
}

int getIfIp(char *ifname, char *if_addr)
{
	struct ifreq ifr;
	int skfd = 0;

	if((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("lktFirewallConfig getIfIp: open socket error");
		return -1;
	}
	strncpy(ifr.ifr_name, ifname, IF_NAMESIZE);
	if (ioctl(skfd, SIOCGIFADDR, &ifr) < 0) {
		close(skfd);
		return -1;
	}
	strcpy(if_addr, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

	close(skfd);
	return 0;
}

/*
src1="key : val \n"
src2="key : val,"
*/
void get_sub_value(char *val, const char *src, int size, char delimit, char end )
{
	//printf("src=%s. end=%c.\n", src, end);
	char *s1 = val;
	char *s2 = src;

	if ( src == NULL || val == NULL ) goto noval;

	if ( strchr(src, delimit) == NULL )
		goto noval;

	memset(val, 0, size);

	while (*s2 != delimit)
		s2++;

	s2++;

	while (*s2 == ' ')
		s2++;

	while (*s2 != '\0' && *s2 != end) {
		*s1 = *s2;
		s1++;
		s2++;
	}

noval:
	*s1 = '\0';

	//printf("val=%s.\n", val);
	return;
}

int getCmdStr(const char *cmd, char *strVal, int len)
{
	char *p;
	int ret = 0;

	FILE *fp = popen(cmd, "r");
	if(!fp) 
		return -1;

	if(fgets(strVal, len, fp) != NULL){
		if(p=strstr(strVal, "\n"))
			p[0]='\0';
	}else{
		*strVal = '\0';
		ret = -1;
	}
	pclose(fp);

	return ret;
}

int getIfMask(char *ifname, char *if_addr)
{
    struct ifreq ifr;
	int skfd = 0;

	if((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("lktFirewallConfig getIfIp: open socket error");
		return -1;
	}
	strncpy(ifr.ifr_name, ifname, IF_NAMESIZE);
	if (ioctl(skfd, SIOCGIFNETMASK, &ifr) < 0) {
		close(skfd);
		return -1;
	}
	strcpy(if_addr, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

	close(skfd);
	return 0;
}


#define MAX_LINE_LEN 1024
#define FILENAME "/etc/firewall.user"
int append_iptables_rule_to_file(const char *zone_name, int enable, const char *rule) {
    FILE *fp;
    char **lines = NULL;
    int line_count = 0;
    int var_index = -1;
    int if_start = -1;
    int if_end = -1;
    char if_start_pattern[MAX_LINE_LEN];
    char var_line[MAX_LINE_LEN];
    int i, j;
    bool found_var = false;
    bool found_if = false;

    // 构造匹配字符串
    snprintf(if_start_pattern, sizeof(if_start_pattern), "if [ \"$%s\" -eq 1 ]; then", zone_name);
    snprintf(var_line, sizeof(var_line), "%s=%d", zone_name, enable);

    // 1. 读取文件内容
    fp = fopen(FILENAME, "r");
    if (fp) {
        char buffer[MAX_LINE_LEN];
        while (fgets(buffer, sizeof(buffer), fp) != NULL) {
            // 移除Windows风格的换行符（\r\n）和Linux换行符（\n）
            size_t len = strlen(buffer);
            if (len > 0 && buffer[len-1] == '\n') {
                buffer[len-1] = '\0';
                if (len > 1 && buffer[len-2] == '\r') {
                    buffer[len-2] = '\0';
                }
            }
            
            lines = realloc(lines, (line_count + 1) * sizeof(char *));
            if (!lines) {
                fclose(fp);
                return -1;
            }
            lines[line_count] = strdup(buffer);
            if (!lines[line_count]) {
                fclose(fp);
                return -1;
            }
            line_count++;
        }
        fclose(fp);
    }

    // 2. 查找变量定义位置
    char var_search[MAX_LINE_LEN];
    snprintf(var_search, sizeof(var_search), "%s=", zone_name);
    for (i = 0; i < line_count; i++) {
        if (strstr(lines[i], var_search)) {
            var_index = i;
            found_var = true;
            break;
        }
    }

    // 3. 查找对应的if区块
    for (i = 0; i < line_count; i++) {
        if (strstr(lines[i], if_start_pattern)) {
            if_start = i;
            found_if = true;
            
            // 查找匹配的fi
            int nest_level = 1;
            for (j = i + 1; j < line_count; j++) {
                if (strstr(lines[j], "if [")) nest_level++;
                if (strstr(lines[j], "fi")) {
                    nest_level--;
                    if (nest_level == 0) {
                        if_end = j;
                        break;
                    }
                }
            }
            break;
        }
    }

    // 4. 处理变量定义
    if (found_var) {
        free(lines[var_index]);
        lines[var_index] = strdup(var_line);
        if (!lines[var_index]) return -1;
    } else {
        // 在文件末尾添加变量定义
        lines = realloc(lines, (line_count + 1) * sizeof(char *));
        if (!lines) return -1;
        
        lines[line_count] = strdup(var_line);
        if (!lines[line_count]) return -1;
        
        var_index = line_count;
        line_count++;
    }

    // 5. 处理规则区块
    if (enable) {
        if (found_if) {
            // 清空现有区块内容
            char **new_lines = malloc((line_count - (if_end - if_start - 1)) * sizeof(char *));
            if (!new_lines) return -1;
            
            int new_index = 0;
            
            // 复制区块之前的内容
            for (i = 0; i <= if_start; i++) {
                new_lines[new_index] = strdup(lines[i]);
                if (!new_lines[new_index]) return -1;
                new_index++;
            }
            
            // 添加新规则
            if (rule && rule[0] != '\0') {
                char *rule_copy = strdup(rule);
                if (!rule_copy) return -1;
                
                char *rule_line = strtok(rule_copy, "\n");
                while (rule_line != NULL) {
                    // 移除Windows风格的换行符
                    char *clean_rule = rule_line;
                    size_t len = strlen(clean_rule);
                    if (len > 0 && clean_rule[len-1] == '\r') {
                        clean_rule[len-1] = '\0';
                    }
                    
                    new_lines = realloc(new_lines, (new_index + 1) * sizeof(char *));
                    if (!new_lines) {
                        free(rule_copy);
                        return -1;
                    }
                    new_lines[new_index] = strdup(clean_rule);
                    if (!new_lines[new_index]) {
                        free(rule_copy);
                        return -1;
                    }
                    new_index++;
                    rule_line = strtok(NULL, "\n");
                }
                free(rule_copy);
            } else {
                // 如果规则为空，添加空命令(:)保持语法正确
                new_lines = realloc(new_lines, (new_index + 1) * sizeof(char *));
                if (!new_lines) return -1;
                new_lines[new_index] = strdup("    :");
                if (!new_lines[new_index]) return -1;
                new_index++;
            }
            
            // 添加区块结束标记
            new_lines = realloc(new_lines, (new_index + 1) * sizeof(char *));
            if (!new_lines) return -1;
            new_lines[new_index] = strdup("fi");
            if (!new_lines[new_index]) return -1;
            new_index++;
            
            // 复制区块之后的内容
            for (i = if_end + 1; i < line_count; i++) {
                new_lines = realloc(new_lines, (new_index + 1) * sizeof(char *));
                if (!new_lines) return -1;
                new_lines[new_index] = strdup(lines[i]);
                if (!new_lines[new_index]) return -1;
                new_index++;
            }
            
            // 释放旧内存并更新行信息
            for (i = 0; i < line_count; i++) free(lines[i]);
            free(lines);
            lines = new_lines;
            line_count = new_index;
        } else {
            // 创建新的if区块
            int insert_pos = var_index + 1;
            char **new_lines = malloc((line_count + 10) * sizeof(char *)); // 额外空间
            if (!new_lines) return -1;
            
            int new_index = 0;
            
            // 复制插入点之前的内容
            for (i = 0; i < insert_pos; i++) {
                new_lines[new_index] = strdup(lines[i]);
                if (!new_lines[new_index]) return -1;
                new_index++;
            }
            
            // 添加if开始标记
            new_lines[new_index] = strdup(if_start_pattern);
            if (!new_lines[new_index]) return -1;
            new_index++;
            
            // 添加规则
            if (rule && rule[0] != '\0') {
                char *rule_copy = strdup(rule);
                if (!rule_copy) return -1;
                
                char *rule_line = strtok(rule_copy, "\n");
                while (rule_line != NULL) {
                    // 移除Windows风格的换行符
                    char *clean_rule = rule_line;
                    size_t len = strlen(clean_rule);
                    if (len > 0 && clean_rule[len-1] == '\r') {
                        clean_rule[len-1] = '\0';
                    }
                    
                    new_lines[new_index] = strdup(clean_rule);
                    if (!new_lines[new_index]) {
                        free(rule_copy);
                        return -1;
                    }
                    new_index++;
                    rule_line = strtok(NULL, "\n");
                }
                free(rule_copy);
            } else {
                // 如果规则为空，添加空命令(:)保持语法正确
                new_lines[new_index] = strdup("    :");
                if (!new_lines[new_index]) return -1;
                new_index++;
            }
            
            // 添加if结束标记
            new_lines[new_index] = strdup("fi");
            if (!new_lines[new_index]) return -1;
            new_index++;
            
            // 复制剩余内容
            for (i = insert_pos; i < line_count; i++) {
                new_lines[new_index] = strdup(lines[i]);
                if (!new_lines[new_index]) return -1;
                new_index++;
            }
            
            // 释放旧内存并更新行信息
            for (i = 0; i < line_count; i++) free(lines[i]);
            free(lines);
            lines = new_lines;
            line_count = new_index;
        }
    } else if (found_if) {
        // 清空现有区块内容
        char **new_lines = malloc((line_count - (if_end - if_start - 1) + 1) * sizeof(char *));
        if (!new_lines) return -1;
        
        int new_index = 0;
        
        // 复制区块之前的内容
        for (i = 0; i <= if_start; i++) {
            new_lines[new_index] = strdup(lines[i]);
            if (!new_lines[new_index]) return -1;
            new_index++;
        }
        
        // 修复语法错误：添加空命令(:)保持语法正确
        new_lines = realloc(new_lines, (new_index + 1) * sizeof(char *));
        if (!new_lines) return -1;
        new_lines[new_index] = strdup("    :"); // 添加空命令
        if (!new_lines[new_index]) return -1;
        new_index++;
        
        // 添加空的fi结束标记
        new_lines = realloc(new_lines, (new_index + 1) * sizeof(char *));
        if (!new_lines) return -1;
        new_lines[new_index] = strdup("fi");
        if (!new_lines[new_index]) return -1;
        new_index++;
        
        // 复制区块之后的内容
        for (i = if_end + 1; i < line_count; i++) {
            new_lines = realloc(new_lines, (new_index + 1) * sizeof(char *));
            if (!new_lines) return -1;
            new_lines[new_index] = strdup(lines[i]);
            if (!new_lines[new_index]) return -1;
            new_index++;
        }
        
        // 释放旧内存并更新行信息
        for (i = 0; i < line_count; i++) free(lines[i]);
        free(lines);
        lines = new_lines;
        line_count = new_index;
    }

    // 6. 写回文件 (确保使用Linux换行符)
    fp = fopen(FILENAME, "wb"); // 使用二进制模式防止Windows转换
    if (!fp) {
        for (i = 0; i < line_count; i++) free(lines[i]);
        free(lines);
        return -1;
    }
    
    for (i = 0; i < line_count; i++) {
        fprintf(fp, "%s\n", lines[i]); // 使用\n作为换行符
        free(lines[i]);
    }
    free(lines);
    fclose(fp);
    
    return 0;
}
