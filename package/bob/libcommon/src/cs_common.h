#ifndef __CS_COMMON_HEADER__
#define __CS_COMMON_HEADER__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <dirent.h>
#include <assert.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <arpa/inet.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <cJSON.h>
#include <sys/wait.h>

#include "cs_uci.h"
#include "cs_uci_fun.h"
#include "cs_firmware.h"

#include "wifi.h"
#include "cs_base64.h"
#include "cs_modem.h"
#include "cs_board.h"


#if defined(CONFIG_CS_COMMON_SSL)
#include "cs_ssl.h"
#endif

#if defined(CONFIG_USER_CSTE_PRINT_CMD)
    #define CSTE_PRINT_CMD       1
#else
    #define CSTE_PRINT_CMD       0
#endif

//#if defined(APP_IOT_MQTT)
#define TEMP_IOT_FILE     "/var/cste/temp_iot_status"
//#endif

//eth name
#if defined(BOARD_ETH_IFNAME)
#define ETH_IFNAME	        BOARD_ETH_IFNAME
#else
#define ETH_IFNAME	        ""
#endif

//wan name
#if defined(BOARD_WAN_IFNAME)
#define WAN_IFNAME	        BOARD_WAN_IFNAME
#else
#define WAN_IFNAME	        ""
#endif

//lan name
#if defined(BOARD_LAN_IFNAME)
#define LAN_IFNAME	        BOARD_LAN_IFNAME
#else
#define LAN_IFNAME	        ""
#endif

#if defined(CONFIG_MULTI_GUEST_SSID_SUPPORT)
#define  GUEST_SSID_NUM 4
#else
#define  GUEST_SSID_NUM 1
#endif

/*platform len macro*/
#define ETHER_ADDR_LEN						6
#define SMALL_STR_LEN                       8
#define SHORT_STR_LEN                       16
#define RESULT_STR_LEN                      32
#define OPTION_STR_LEN                      64
#define TEMP_STR_LEN                        128
#define CMD_STR_LEN                         256
#define LIST_STR_LEN                        512
#define LONG_BUFF_LEN                       1024
#define LONGLONG_BUFF_LEN                   8192

#define FILTER_RULE_NUM_MAX 				16

#define LOG_MAX         	16384
#define LOG_MAX_LINE        256
#define LOG_MAX_NUM         64


#define SOCK_CONNECT_TIMEOUT    3
#define SOCK_RW_TIMEOUT         5

/*接口名称*/
#define LAN_DEV_NAME        	"br-lan"
#define WAN_PPPOE_IFNAME	  	"pppoe-wan"
#define WAN_MODEM_NET_INTERFACE "wan_modem"
#define WAN_NET_INTERFACE 		"wan"

#define MEMRATIO_FILE		"/proc/meminfo"

#define L2TP_SECRETS_FILE 		"/etc/xl2tpd/xl2tp-secrets"


/*定制功能相关*/
#define PRODUCT_FILE       	"/etc/product"
#define CUSTOM_FILE       	"/mnt/product"
#define WEBDIR       		"/mnt/web"
#define CUR_WEB_DIR  		"/web"

/*当前状态临时文件*/
#define TEMP_STATUS_FILE    "/var/cste/temp_status"
#define TEMP_DATAS_FILE     "/var/cste/temp_datas"
#define TEMP_CLIENT_FILE    "/var/cste/client_info"
#define TEMP_STUN_FILE      "/var/cste/temp_stun"
#define TEMP_MODEM_FILE     "/var/cste/modem_status"
#define TEMP_SMS_FILE     	"/tmp/cste/sms_recv_list"

#define CWMP_TEMP_STUN_FILE      "/var/cste/temp_stun"
#define CWMP_TEMP_CWMP_FILE      "/var/cste/temp_cwmp"

/*模组短信保存文件*/
#define ETC_MODEM_SMS_FILE  		"/etc/config/modem_sms"
#define TEMP_IPSEC_GM_CERT_PATH 	"/etc/config/gm_cert"

#define LMOVE(m,n) ((m)<<(n))
#define RMOVE(m,n) ((m)>>(n))

/*无线相关接口*/
#define WLAN_IF_NUM 5
#define MAX_ACL_NUM 10

#if defined(CONFIG_MULTI_GUEST_SSID_SUPPORT)
#define  GUEST_SSID_NUM 4
#else
#define  GUEST_SSID_NUM 1
#endif

typedef struct wlan_if_table
{
	char section_key[24];
	char section_name[24];
	char key[16];
	char ifname[16];
} WLAN_TABLE;

/*-----------------------------------------*/
#define FILTER_RULE_NUM		32

/*-----------------------------------------*/

#define MESH_INFO_FILE					"/tmp/dump.txt"

#define MAPD_CONF_FILE					"/etc/map/mapd_cfg"
#define MAPD_DEF_CONF_FILE				"/etc/map/mapd_default.cfg"
#define MAPD_USER_CONF_FILE 			"/etc/map/mapd_user.cfg"
#define MAPD_1905D_CONF_FILE 			"/etc/map/1905d.cfg"
#define DPP_CFG_FILE 					"/etc/dpp_cfg.txt"


#define MAPD_CTRL_FILE					"/tmp/mapd_ctrl"

#define BSS_CONF_FILE					"/etc/map/wts_bss_info_config"

#if defined(CONFIG_MTK_CHIP_MT7986)
#define W24G_PATH  						"/etc/wireless/mediatek/mt7986.dbdc.b0.dat"
#define W58G_PATH  						"/etc/wireless/mediatek/mt7986.dbdc.b1.dat"
#else
#define W24G_PATH  						"/etc/wireless/mediatek/mt7981.dbdc.b0.dat"
#define W58G_PATH  						"/etc/wireless/mediatek/mt7981.dbdc.b1.dat"
#endif
#define IFACE_3GPP_WAN	"wan_modem"
#define IFACE_WIRE_WAN	"wan"

#define IFACE_FLAG_T                            0x01
#define IP_ADDR_T                               0x02
#define NET_MASK_T                              0x04
#define HW_ADDR_T                               0x08

enum{
    SYSTEM_GW=0,
	SYSTEM_BR,
    SYSTEM_RPT,
    SYSTEM_WISP,
};

enum{
    DEBUG_LOG_CLOSE=0,
    DBUG_LOG_SAVE_ETC,
    DBUG_LOG_UPDATE_SERVER,
    DBUG_LOG_SAVE_UPDATE,
};

typedef enum role{
	DEV_AUTO = 0,
	DEV_CONTROLLER,
	DEV_AGENT,
}DEV_ROLE;

typedef enum
{
	W24G_RADIO,
	W24G_IF,
	W24G_MH,
	W24G_G1,
	W24G_G2,
	W24G_G3,
	W24G_G4,
	W58G_RADIO,
	W58G_IF,
	W58G_MH,
	W58G_G1,
	W58G_G2,
	W58G_G3,
	W58G_G4,
	WLAN_APCLI,
	WLAN_MAX
} WLAN_T;
extern WLAN_TABLE WL_IF[];

typedef struct product_param_table
{
	int  file_id;
	char section[24];
	char key[24];
} PRODUCT_PARAM_TABLE;

extern PRODUCT_PARAM_TABLE product_param[];

struct interface_status
{
	int up;
	int uptime;
	char proto[16];
	char device[16];
	char ipaddr_v4[16];
	char mask_v4[16];
	char gateway_v4[16];
	char pri_dns_v4[16];
	char sec_dns_v4[16];
};

#if defined (APP_QUAGGA)
#define QUAGGA_RIPD_CONF	"/etc/quagga/ripd.conf"
#define QUAGGA_OSPFD_CONF	"/etc/quagga/ospfd.conf"
#define QUAGGA_BGPD_CONF	"/etc/quagga/bgpd.conf"
enum quagga_conf{
	RIPD_CONF= 0, 
	OSPFD_CONF, 
	BGPD_CONF,
};
#endif


typedef enum {
	LINK_STATUS_NO = 0,
	LINK_STATUS_WIRE,
	LINK_STATUS_MODEM
}LINK_STATUS_T;


#define SAFE_CLOSE(fd)	\
	if(fd > 0)			\
	{					\
		close(fd); 		\
		fd = -1; 		\
	}
	
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))


/* Print directly to the console */
#define dbg(fmt, args...) \
    do \
    { \
        FILE *fp = fopen("/dev/console", "w"); \
        if (fp) \
        { \
            fprintf(fp, "[%s:%d] " fmt,__FUNCTION__ , __LINE__, ## args); \
            fclose(fp); \
        } \
        else \
        { \
            fprintf(stderr, fmt, ## args); \
        } \
    }while(0)

#define XCMD( x, fmt, args... ) \
    do \
    { \
	    sprintf( x, fmt, ##args ); \
	    CsteSystem( x, CSTE_PRINT_CMD ); \
    } while(0)

typedef enum
{
	DHCP_DISABLED = 0,
	DHCP_CLIENT = 1,
	DHCP_SERVER = 2,
	PPPOE = 3,
	PPTP = 4,
	DHCP_RELAY = 5,
	L2TP = 6
} DHCP_T;

typedef enum
{
	DDNS_FAIL = 0,
	DDNS_SUCCESS
}DDNS_STATUS;


extern int CsteSystem(char *command, int print);

extern pid_t get_pid_by_name(char *name);
extern void  logmessage(char *logheader, char *fmt, ...);
extern void  set_lktos_effect(char *action);

extern int   tcpcheck_net(const char *host, int port, int timeout);
extern int   do_ping_detect(const char *host, char *ifname);
extern int   domain_to_ip(const char *domain, char *ip);
extern int   get_split_nums(char *value, char delimit);
extern int   get_nth_val_safe(int index, char *value, char delimit, char *result, int len);
extern long  get_current_uptime_sec(void);
extern int   get_cmd_result(char *cmd, char *resultbuf, size_t buf_size);
extern int   get_cmd_val(const char *cmd);

extern int   get_ifname_ipaddr(char *ifname, char *if_addr);
extern int   get_ifname_mask(char *ifname, char *if_addr);
extern int   get_ifname_macaddr(char *ifname, char *if_hw);
extern int   get_vpnserver_ipaddr(char *ifname, char *if_addr);
extern int   get_current_gateway(char  *sgw);
extern int   get_current_dns(int dnsIdx, char *dns, int is_ipv6);
extern int   get_ifname_bytes(const char *ifname, unsigned long long *rxb, unsigned long long *txb);
extern int   get_wan_ifname(char *ifname);
extern void  get_gateway_iface(char *interface);
extern int   get_wire_wan_status(struct interface_status *status_paremeter);
extern LINK_STATUS_T get_wan_status(struct interface_status *status_paremeter);
extern int   get_cjson_string(cJSON *object, char *key,  char *val, int len);
extern int   get_interface_status(struct interface_status *status_paremeter,char *interface);

extern int   get_ip_hostname_bymac_in_br(char *pmac, char *ip, char *hostname);
extern int   get_sta_ipaddr_bymac(char *pmac, char *ipv4_addr, char *ipv6_addr);
extern int   get_sta_hostname_bymac(char *pmac, char *hostname);
extern int   get_sta_mac_byip(char *ipaddr, char *mac);
extern int   get_flash_total_size();

extern void str_tolower(char *str);
extern void str_toupper(char *str);
extern void str_del_char_bak(char *a,char c);
extern void add_mac_split(const char *mac_org, char *mac_new);
extern void mac_del_split(const char *mac_org, char *mac_new);

extern void set_timezone_to_kernel(void);

extern int datconf_set_by_key(char *path,char *key,char *value);
extern int datconf_get_by_key(char *path,char *key,char *value,int len);
extern int datconf_get_ival(char *path,char *key);
extern int datconf_set_ival(char *path,char *key, int value);

extern int wificonf_set_by_key(int idx,char *key,char *value);
extern int wificonf_get_by_key(int idx,char *key,char *value,int len);

extern int wificonf_del_by_key(int idx, char *key, char *value);
extern int wificonf_add_by_key(int idx, char *key, char *value);

extern int wificonf_set_disabled(int radio, int disabled);

extern int mask_num2string(int num, char *mask_buf, int buf_len);
extern int mask_string2num(char *mask);
extern int ether_atoe(const char *a, unsigned char *e);
extern int ether_etoa(const unsigned char *e, char *a);

extern void urldecode(char url[], char *result);
extern void urlencode(char url[], char *result);

extern int get_apcli_connected(int wl_idx);
extern int get_apcli_signal(char *apcli_if);
extern int get_apcli_connect_ssid(int wl_idx,char *ssid,int len);
extern int get_apcli_connect_bssid(const char *ifname,char *bssid,int len);
extern int get_apcli_idx(void);
extern int get_apcli_enable(int wl_idx);
extern int get_wlan_merge(int wl_idx, int wl_odx);

extern int get_channel(int wl_idx, char *channel);
extern int get_encryption_ui(int wl_idx, char *encryption_ui, char *encryptype_ui);
extern int get_soft_version(char *soft_version, int len);
extern int get_fixed_mac(char *wlan_if,int count, char *buffmac);
extern int fixed_auto_sn();



/*-------------------cs_file-----------------------*/
#define FW_CREATE	0
#define FW_APPEND	1
#define FW_NEWLINE	2
#define FW_SILENT	4	/* Don't print error message even write file fail. */

#define ACTION_LOCK_FILE "/var/lock/a_w_l" // action write lock

extern int check_if_dir_empty(const char *dirpath);

extern int  file_lock(const char *tag);
extern void file_unlock(int lockfd);

extern unsigned long f_size(const char *path);
extern int f_exists(const char *file);
extern int d_exists(const char *path);
extern int f_read(const char *file, void *buffer, int max);
extern int f_write(const char *file, const void *buffer, int len, unsigned flags, unsigned cmode);

extern int f_read_int(const char *path);
extern unsigned long long f_read_long_long(char* name);

extern int f_read_string(const char *file, char *buffer, int max);
extern int f_write_string(const char *file, const char *buffer, unsigned flags, unsigned cmode);	
extern int f_read_alloc(const char *path, char **buffer, int max);
extern int f_read_alloc_string(const char *path, char **buffer, int max);
extern int f_read_offset(const char *path, void *buffer, int offset, int max);
extern int f_wait_exists(const char *name, int max);
extern int f_wait_notexists(const char *name, int max);


/*-------------------cs_led-----------------------*/
extern void led_batch_upg_success(void);
extern void led_system_init(void);

#if defined(DUAL_SYS_LED)
extern void led_self_check(void);
#endif

extern void reset_led_blink(void);
extern void set_led_status(int led_status);
extern void schedule_led_control(void);

/*------------------easymesh---------------------*/
#define AUTHMODE_OPEN 0x0001
#define AUTHMODE_WPA 0x0002
#define AUTHMODE_WPA2 0x0020
#define AUTHMODE_WPA_WPA2 0x0022
#define AUTHMODE_WPA3_SAE 0x0040
#define AUTHMODE_WPA3_TRANSITION 0x0060
#define AUTHMODE_DPP 0x0080
#define AUTHMODE_DPP_SAE 0x00C0
#define AUTHMODE_DPP_SAE_PSK 0x00E0

#define ENCTYTYPE_NONE 0x0001
#define ENCTYTYPE_WEP 0x0002
#define ENCTYTYPE_TKIP 0x0004
#define ENCTYTYPE_AES 0x0008
#define ENCTYTYPE_TKIP_AES 0x000C

#define BSS_LINE_MAX_LENGTH 128

int setMapRole(int mode_new);
int trigger_map_wps();
int get_mesh_status(char *status, int len);
int apply_mesh_pre_channel(char *channel);
int get_mesh_topo(char *buf, int buf_len);
int genBssConfigs();
int get_mesh_agent_count();
int get_mesh_agent_rssi();


/*-------------------cs_param_check-----------------------*/
extern  int is_mac_valid(char *str);
extern  int is_ip_valid(char *str);
extern  int is_netmask_valid(char *str);
extern  int is_cmd_string_valid(char *str);

extern  int is_interface_exist(const char *ifname);
extern  int is_interface_up(const char *ifname);
extern  int is_phyport_connected(int portNum);
extern  int is_ssid_disabled(int idx);

extern  int  get_mem_ratio(void);
extern  int  get_wan_mode(char *proto);
extern  void get_sys_uptime(char *str);
extern  void get_wan_linktime(unsigned long seconds, char *tmp_buf);
extern  int  check_lan_wan_confliction();
extern  void check_static_dhcp_ip(struct in_addr ipaddr_new, struct in_addr netmask_new);
extern  int  poweroff_lan_port(void);
extern  int  reset_lan_port(void);

extern void get_time_zone_info(char *tz, char *args,char *zonename);
extern void set_time_zone_info(char *args, char *value, char *zonename);
extern void get_time_status(char *enabled, char *sValue);

#if defined(CONFIG_IPV6_FIREWALL_SUPPORT)
extern  int is_ip6_valid(char *str);
#endif

int getInAddr( char *interface, int type, void *pAddr );


/*--------------------------------------------------------*/
extern int get_client_link_time(char *devmac, char *time);

//*-----------------------cs_common2---------------------------------------*/
extern int doSystem(const char *fmt, ...);
extern void notice_set(const char *path, const char *format, ...);

extern int _eval(char *const argv[], char *path, int timeout, pid_t *ppid);
#define eval(cmd, args...) ({ \
	char *cs_argv[] = { cmd, ## args, NULL }; \
	_eval(cs_argv, NULL, 0, NULL); \
})

extern int _xstart(const char *cmd, ...);
#define xstart(args...)	_xstart(args, NULL)

int is_module_loaded(const char *module_name);
int get_module_refcount(const char *module_name);
int module_smart_load(const char *module_name, const char *module_param);
int module_smart_unload(const char *module_name, int recurse_unload);

//for wx039
int iwpriv_set(char *iface, const char *key, const char *val);
int wifi_iwpriv_ioctl_set_cmd(const char *ifname,const char* pkey_word,const char* pvalue);

void set_ethernet_port(int br_mode);

int getOpmodeVal(void);

#endif /* __CS_COMMON_HEADER__ */

extern void CsRealReloadRouterQuagga(void);
extern int append_iptables_rule_to_file(const char *zone_name, int enable, const char *rule);
