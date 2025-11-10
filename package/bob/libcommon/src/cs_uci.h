#ifndef __CS_UCI_H__
#define __CS_UCI_H__

#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>  
#include <stdio.h>  
#include <uci.h>
#include <pthread.h>

#define MAX_UCI_STRLEN			70
#define MAX_UCI_VALUE_LEN		4096//1024->4096 for static dhcp list

/* Default UCI context timeout */
/* 5 secs */
#define DEFAULT_CTX_TIMEOUT     			5
/* 2 sec, the context will be reused if the last access if within this timeout. (To avoid changing view, when getting a large table) */
#define DEFAULT_CTX_LASTACCESS_TIMEOUT     	2

#define DEFAULT_UCI_STATUS_PATH							"/tmp/cste/"
#define UCI_CUSTOM_INFO_PATH							"/mnt/"
#define DEFAULT_UCI_CONFIG_PATH							"/etc/config"
#define ETC_PATH								        "/etc"
#define ROM_ETC_PATH									"/rom/etc/config"


#define PKG_SYSTEM_STATUS_FILE         					"system_status"
#define PKG_NETWORK_STATUS_FILE         				"network_status"
#define PKG_WIRELESS_STATUS_FILE         				"wireless_status"
#define PKG_MODEM_STATUS_FILE         					"modem_status"
#define PKG_IBMS_STATUS_FILE         					"ibms_status"
#define PKG_PRODUCT_CUSTOM_FILE   						"product"    /*in /useradate directory*/
/*  /etc/config dir */
#define PKG_DHCP_CONFIG_FILE           					"dhcp"
#define PKG_DROPBEAR_CONFIG_FILE       					"dropbear"
#define PKG_FSTAB_CONFIG_FILE          					"fstab"
#define PKG_NETWORK_CONFIG_FILE        					"network"
#define PKG_SYSTEM_CONFIG_FILE         					"system"
#define PKG_TTY_CONFIG_FILE         					"tty"
#define PKG_CSFW_CONFIG_FILE           					"csfw"
#define PKG_TIMER_CONFIG_FILE           				"timertask"
#define PKG_PRODUCT_CONFIG_FILE        					"product"  /*in /etc directory*/
#define PKG_WIRELESS_CONFIG_FILE       					"wireless"
#define PKG_QOS_CONFIG_FILE            					"qos"
#define PKG_WEBR_CONFIG_FILE            				"webr"
#define PKG_DDNS_CONFIG_FILE        					"ddns"
#define PKG_CRON_CONFIG_FILE           					"cron"
#define PKG_CLOUDUPDATE_CONFIG_FILE						"cloudupdate"
#define PKG_SHADOWSOCKS_CONFIG_FILE						"shadowsocks-libev"
#define PKG_PPTPD_CONFIG_FILE							"pptpd"
#define PKG_L2TPD_CONFIG_FILE							"xl2tpd"
#define PKG_OPENVPND_CONFIG_FILE						"openvpn"
#define PKG_PPP_USER_CONFIG_FILE						"ppp_user"
#define PKG_PRODUCT_ROM_FILE							"product"
#define PKG_PORTAL_CONFIG_FILE							"portalos"
#define PKG_VENDOR_INFO_FILE							"cs_vendor"
#define PKG_SMS_CONFIG_FILE								"sms_config"
#define PKG_IPSEC_CONFIG_FILE         					"ipsec"
#define PKG_IPSEC_GM_CONFIG_FILE						"ipsec_gm"
#define PKG_WIFIDOG_CONFIG_FILE         				"wifidog"
#define PKG_PORTALAUTH_CONFIG_FILE         				"portalauth"

#define PKG_CLOUDAC_CONFIG_FILE         				"cste_thinap"

#define PKG_IPTV_CONFIG_FILE							"iptv"
#define PKG_UPNPD_CONFIG_FILE							"upnpd"
#define PKG_PARENTAL_CONFIG_FILE						"parental"
#define PKG_EASYCWMP_CONFIG_FILE						"easycwmp"
#define PKG_ANDLINK_CONFIG_FILE						    "andlink"
#define PKG_CMCC_DM_CONFIG_FILE						    "cmcc_dm"
#define PKG_ICWMP_CONFIG_FILE							"cwmp"
#define PKG_STUN_CONFIG_FILE						    "stun"
#define PKG_SCH_CONFIG_FILE							    "cs_sch"
#define PKG_WANDUCK_CONFIG_FILE							"detect_wanduck"
#define PKG_TRAFFIC_CONFIG_FILE							"traffic"
#define PKG_UDPXY_CONFIG_FILE							"udpxy"
#define PKG_MESH_INFO_CONFIG_FILE						"meshinfo"
#define PKG_ROCKSPACE_CONFIG_FILE					    "rockspace_iot"
#define PKG_CSTE_SUB_CONFIG_FILE					    "cste_sub"
#define PKG_SAMBA_CONFIG_FILE                           "samba"
#define PKG_DTU_CONFIG_FILE								"dtu"
#define PKG_VRRPD_CONFIG_FILE							"cs_vrrpd"
#define PKG_SNMP_CONFIG_FILE                            "snmpd"
#define PKG_WAN_MODEM_CONFIG_FILE						"modem"
#define PKG_EOIP_CONFIG_FILE							"eoip"
#define PKG_TUNNEL_CONFIG_FILE							"tunnel"
#define PKG_GPSD_CONFIG_FILE							"gpsd"
#define PKG_SSLVPN_CONFIG_FILE							"sslvpn"
#define PKG_IOT_CONFIG_FILE                             "iot"
#define PKG_AILING_CONFIG_FILE  						"ailing"
#define PKG_ROUTER_QUAGGA_CONFIG_FILE					"quagga"
#define PKG_VXLAN_CONFIG_FILE                           "vxlan"
#define PKG_SLB_CONFIG_FILE                             "slb"
#define PKG_FIREWALL_CONFIG_FILE                        "firewall"

typedef enum
{
	PKG_UNDEFINE = 0,
	PKG_SYSTEM_STATUS,	
	PKG_NETWORK_STATUS,
	PKG_WIRELESS_STATUS,
	PKG_MODEM_STATUS,
	PKG_IBMS_STATUS,
	PKG_PRODUCT_CUSTOM,
	PKG_DHCP_CONFIG,
	PKG_DROPBEAR_CONFIG,
	PKG_FSTAB_CONFIG,
	PKG_NETWORK_CONFIG,
	PKG_ROUTER_QUAGGA_CONFIG,
	PKG_SYSTEM_CONFIG,
	PKG_TTY_CONFIG,
	PKG_CSFW_CONFIG,
	PKG_TIMER_CONFIG,
	PKG_PRODUCT_CONFIG, /*for product in /etc directory*/
	PKG_WIRELESS_CONFIG,
	PKG_QOS_CONFIG,
	PKG_WEBR_CONFIG,
	PKG_DDNS_CONFIG,
	PKG_CRON_CONFIG,
	PKG_CLOUDUPDATE_CONFIG,
	PKG_SHADOWSOCKS_CONFIG,
	PKG_PPTPD_CONFIG,
	PKG_L2TPD_CONFIG,
	PKG_OPENVPND_CONFIG,
	PKG_PPP_USER_CONFIG,
	PKG_PRODUCT_ROM,
	PKG_PORTAL_CONFIG,
	PKG_VENDOR_INFO,
	PKG_SMS_CONFIG,
	PKG_IPSEC_CONFIG,
	PKG_IPSEC_GM_CONFIG,
	PKG_WIFIDOG_CONFIG,
	PKG_PORTALAUTH_CONFIG,
	PKG_CLOUDAC_CONFIG,
	PKG_IPTV_CONFIG,
	PKG_UPNPD_CONFIG,
	PKG_PARENTAL_CONFIG,
	PKG_EASYCWMP_CONFIG,
	PKG_ANDLINK_CONFIG,
	PKG_CMCC_DM_CONFIG,
	PKG_ICWMP_CONFIG,
	PKG_STUN_CONFIG,
	PKG_SCH_CONFIG,
	PKG_WANDUCK_CONFIG,
	PKG_TRAFFIC_CONFIG,
	PKG_UDPXY_CONFIG,
	PKG_MESH_INFO_CONFIG,
	PKG_ROCKSPACE_CONFIG,
	PKG_CSTE_SUB_CONFIG,
	PKG_SAMBA_CONFIG,
	PKG_SNMP_CONFIG,
	PKG_DTU_CONFIG,
	PKG_VRRPD_CONFIG,
	PKG_WAN_MODEM_CONFIG,
	PKG_EOIP_CONFIG,
	PKG_TUNNEL_CONFIG,
	PKG_GPSD_CONFIG,
	PKG_SSLVPN_CONFIG,
	PKG_IOT_CONFIG,	
	PKG_AILING_CONFIG,
	PKG_VXLAN_CONFIG,
    PKG_SLB_CONFIG,
    PKG_FIREWALL_CONFIG,
	PKG_NUM_OF_PKG   /* This definition should be put at last, to count the total number of packages */
}CS_UCI_TITLE;

#define PKG_ID_TOFILE(id) \
 ((id == PKG_SYSTEM_STATUS) ? PKG_SYSTEM_STATUS_FILE : \
  (id == PKG_NETWORK_STATUS)? PKG_NETWORK_STATUS_FILE : \
  (id == PKG_WIRELESS_STATUS)? PKG_WIRELESS_STATUS_FILE : \
  (id == PKG_MODEM_STATUS)? PKG_MODEM_STATUS_FILE : \
  (id == PKG_IBMS_STATUS)? PKG_IBMS_STATUS_FILE : \
  (id == PKG_PRODUCT_CUSTOM)? PKG_PRODUCT_CUSTOM_FILE: \
  (id == PKG_DHCP_CONFIG)? PKG_DHCP_CONFIG_FILE : \
  (id == PKG_DROPBEAR_CONFIG)? PKG_DROPBEAR_CONFIG_FILE : \
  (id == PKG_FSTAB_CONFIG)? PKG_FSTAB_CONFIG_FILE : \
  (id == PKG_NETWORK_CONFIG)? PKG_NETWORK_CONFIG_FILE : \
  (id == PKG_SYSTEM_CONFIG)? PKG_SYSTEM_CONFIG_FILE : \
  (id == PKG_TTY_CONFIG)? PKG_TTY_CONFIG_FILE : \
  (id == PKG_CSFW_CONFIG)? PKG_CSFW_CONFIG_FILE : \
  (id == PKG_TIMER_CONFIG)? PKG_TIMER_CONFIG_FILE : \
  (id == PKG_PRODUCT_CONFIG)? PKG_PRODUCT_CONFIG_FILE : \
  (id == PKG_WIRELESS_CONFIG)? PKG_WIRELESS_CONFIG_FILE : \
  (id == PKG_QOS_CONFIG)? PKG_QOS_CONFIG_FILE : \
  (id == PKG_WEBR_CONFIG)? PKG_WEBR_CONFIG_FILE : \
  (id == PKG_DDNS_CONFIG)? PKG_DDNS_CONFIG_FILE : \
  (id == PKG_CRON_CONFIG)? PKG_CRON_CONFIG_FILE : \
  (id == PKG_CLOUDUPDATE_CONFIG)? PKG_CLOUDUPDATE_CONFIG_FILE : \
  (id == PKG_SHADOWSOCKS_CONFIG)? PKG_SHADOWSOCKS_CONFIG_FILE: \
  (id == PKG_PPTPD_CONFIG)? PKG_PPTPD_CONFIG_FILE: \
  (id == PKG_L2TPD_CONFIG)? PKG_L2TPD_CONFIG_FILE: \
  (id == PKG_OPENVPND_CONFIG)? PKG_OPENVPND_CONFIG_FILE: \
  (id == PKG_PPP_USER_CONFIG)? PKG_PPP_USER_CONFIG_FILE: \
  (id == PKG_PRODUCT_ROM)? PKG_PRODUCT_ROM_FILE: \
  (id == PKG_PORTAL_CONFIG)? PKG_PORTAL_CONFIG_FILE: \
  (id == PKG_VENDOR_INFO)? PKG_VENDOR_INFO_FILE: \
  (id == PKG_SMS_CONFIG)? PKG_SMS_CONFIG_FILE: \
  (id == PKG_IPSEC_CONFIG)? PKG_IPSEC_CONFIG_FILE: \
  (id == PKG_IPSEC_GM_CONFIG)? PKG_IPSEC_GM_CONFIG_FILE: \
  (id == PKG_WIFIDOG_CONFIG)? PKG_WIFIDOG_CONFIG_FILE: \
  (id == PKG_PORTALAUTH_CONFIG)? PKG_PORTALAUTH_CONFIG_FILE: \
  (id == PKG_CLOUDAC_CONFIG)? PKG_CLOUDAC_CONFIG_FILE: \
  (id == PKG_IPTV_CONFIG)? PKG_IPTV_CONFIG_FILE: \
  (id == PKG_UPNPD_CONFIG)? PKG_UPNPD_CONFIG_FILE: \
  (id == PKG_PARENTAL_CONFIG)? PKG_PARENTAL_CONFIG_FILE: \
  (id == PKG_EASYCWMP_CONFIG)? PKG_EASYCWMP_CONFIG_FILE: \
  (id == PKG_ANDLINK_CONFIG)? PKG_ANDLINK_CONFIG_FILE: \
  (id == PKG_CMCC_DM_CONFIG)? PKG_CMCC_DM_CONFIG_FILE: \
  (id == PKG_ICWMP_CONFIG)? PKG_ICWMP_CONFIG_FILE: \
  (id == PKG_STUN_CONFIG)? PKG_STUN_CONFIG_FILE: \
  (id == PKG_SCH_CONFIG)? PKG_SCH_CONFIG_FILE: \
  (id == PKG_WANDUCK_CONFIG)? PKG_WANDUCK_CONFIG_FILE: \
  (id == PKG_TRAFFIC_CONFIG)? PKG_TRAFFIC_CONFIG_FILE: \
  (id == PKG_UDPXY_CONFIG)? PKG_UDPXY_CONFIG_FILE: \
  (id == PKG_MESH_INFO_CONFIG)? PKG_MESH_INFO_CONFIG_FILE: \
  (id == PKG_ROCKSPACE_CONFIG)? PKG_ROCKSPACE_CONFIG_FILE: \
  (id == PKG_CSTE_SUB_CONFIG)? PKG_CSTE_SUB_CONFIG_FILE: \
  (id == PKG_SAMBA_CONFIG)? PKG_SAMBA_CONFIG_FILE: \
  (id == PKG_SNMP_CONFIG)? PKG_SNMP_CONFIG_FILE: \
  (id == PKG_DTU_CONFIG)? PKG_DTU_CONFIG_FILE: \
  (id == PKG_VRRPD_CONFIG)? PKG_VRRPD_CONFIG_FILE: \
  (id == PKG_WAN_MODEM_CONFIG)? PKG_WAN_MODEM_CONFIG_FILE: \
  (id == PKG_EOIP_CONFIG)? PKG_EOIP_CONFIG_FILE: \
  (id == PKG_TUNNEL_CONFIG)? PKG_TUNNEL_CONFIG_FILE: \
  (id == PKG_GPSD_CONFIG)? PKG_GPSD_CONFIG_FILE: \
  (id == PKG_SSLVPN_CONFIG)? PKG_SSLVPN_CONFIG_FILE: \
  (id == PKG_IOT_CONFIG)? PKG_IOT_CONFIG_FILE: \
  (id == PKG_AILING_CONFIG)? PKG_AILING_CONFIG_FILE: \
  (id == PKG_SLB_CONFIG)? PKG_SLB_CONFIG_FILE: \
  (id == PKG_FIREWALL_CONFIG)? PKG_FIREWALL_CONFIG_FILE: \
  (id == PKG_ROUTER_QUAGGA_CONFIG)? PKG_ROUTER_QUAGGA_CONFIG_FILE: \
  (id == PKG_VXLAN_CONFIG)? PKG_VXLAN_CONFIG_FILE: \
	 "Unknown ID")

#define PKG_FILE_PATH(id) \
 ((id == PKG_SYSTEM_STATUS) ? DEFAULT_UCI_STATUS_PATH : \
  (id == PKG_NETWORK_STATUS) ? DEFAULT_UCI_STATUS_PATH : \
  (id == PKG_WIRELESS_STATUS) ? DEFAULT_UCI_STATUS_PATH : \
  (id == PKG_MODEM_STATUS) ? DEFAULT_UCI_STATUS_PATH : \
  (id == PKG_IBMS_STATUS) ? DEFAULT_UCI_STATUS_PATH : \
  (id == PKG_PRODUCT_CUSTOM) ? UCI_CUSTOM_INFO_PATH : \
  (id == PKG_PRODUCT_CONFIG) ? ETC_PATH : \
  (id == PKG_PRODUCT_ROM) ? ROM_ETC_PATH : \
  (id == PKG_VENDOR_INFO) ? UCI_CUSTOM_INFO_PATH : \
  (id == PKG_DTU_CONFIG)? DEFAULT_UCI_CONFIG_PATH: \
  (id == PKG_IOT_CONFIG)? DEFAULT_UCI_CONFIG_PATH: \
  (id == PKG_ROUTER_QUAGGA_CONFIG)? DEFAULT_UCI_CONFIG_PATH: \
 	DEFAULT_UCI_CONFIG_PATH)

#define IS_PKG_CAN_CACHE(id) ((id == PKG_UNDEFINE)? 0 : 1)

struct cs_uci_get_context {
	unsigned char package;
    struct uci_context* get_uci_context;
    pthread_mutex_t get_ctx_lock;
	long ctx_lastupdate;
	long ctx_lastaccess;
};

/* Function declaration */

/* Initialize CMS UCI, including cache */
void cs_uci_init(void);
/* Release all UCI resources */
void cs_uci_release(void);

/* Cleanup the UCI context cacahe */
/* @package UCI package ID, 0 to clean all cache */
/* @clean_useless_only Only clean the context that are useless (both timed out and not being accessed for a timeout period) */
void cs_uci_clean_uci_context_cache(unsigned char package, bool clean_useless_only);

/**
 * Get the UCI context
 * The ctx cache will be  refreshed after timeout (DEFAULT_CTX_TIMEOUT, 5s)
 * @package UCI package ID (defined in cms_uci.h)
 * @path UCI config file location, pass NULL to use default
 */
struct cs_uci_get_context* cms_uci_get_uci_context(unsigned char package, const char* path);

/**
 * Deprecated, please use cms_uci_get_uci_context.
 * Get the UCI context WITHOUT the last access protection
 * The cache will be refreshed regardless of the DEFAULT_CTX_LASTACCESS_TIMEOUT, 
 * so that ctx cache will be  refreshed after timeout (DEFAULT_CTX_TIMEOUT, 5s)
 * @package UCI package ID (defined in cms_uci.h)
 * @path UCI config file location, pass NULL to use default
 */
struct cs_uci_get_context* cms_uci_get_uci_context_nla(unsigned char package, const char* path);

/**
 * Get the UCI context WITH the last access protection, it will be useful, if you need
 * to get the same snapshot in a consecutive api calls (e.g. get association list)
 * The cache will be refreshed only if the cache is timed out (DEFAULT_CTX_TIMEOUT), 
 * and the last cache access time is long than the DEFAULT_CTX_LASTACCESS_TIMEOUT 
 * @package UCI package ID (defined in cms_uci.h)
 * @path UCI config file location, pass NULL to use default
 */
struct cs_uci_get_context* cms_uci_get_uci_context_lap(unsigned char package, const char* path);

/**
 * Get the uci option using the uci string
 * If the uci option is a list, a concatenated string will be returned with the space as the delimiter
 * It is caller's responsibility to ensure the result has enough space to carry result
 * @ctx  		UCI context
 * @uci_str  	UCI option string
 * @result		UCI result value string
 * @return 0, if failed
 */
int cs_uci_get_option(struct cs_uci_get_context *ctx,  char *uci_str, char *result);

int refresh_uci_get_context(struct cs_uci_get_context* get_ctx, long now);

struct cs_uci_get_context* cs_uci_get_uci_context_nla(unsigned char package, const char* path);

void clean_uci_context(struct uci_context* ctx);

int cs_uci_force_refresh_context(unsigned char package);

#endif


