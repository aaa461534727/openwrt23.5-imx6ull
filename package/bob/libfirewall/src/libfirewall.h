
#ifndef _LIB_FIREWALL_H_
#define _LIB_FIREWALL_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <dirent.h>

#include "cs_common.h"
#include "cs_uci.h"
#include "cs_uci_fun.h"

extern struct interface_status fw_status;
extern int is_firewall_effect;

#define ACTION_DROP						0
#define ACTION_ACCEPT					1

#define PROTO_UNKNOWN					0
#define PROTO_TCP						1
#define PROTO_UDP						2
#define PROTO_TCP_UDP					3
#define PROTO_ICMP						4
#define PROTO_NONE						5
#define PROTO_ALL						6 //no support --port

//----------------------mangle---------------------------------
#define MANGLE_SMARTQOS_CHAIN           "mangle_smartqos"
#define MANGLE_QOS_INGRESS_CHAIN        "mangle_qos_ingress"
#define MANGLE_QOS_EGRESS_CHAIN         "mangle_qos_egress"

#define MANGLE_IGMP_CHAIN               "mangle_igmp"

#define MANGLE_TTL_CHAIN             	"mangle_ttl"

#define MANGLE_MTU_CHAIN             	"mangle_mtu_fix"

//----------------------nat------------------------------------
#define NAT_MASQUERADE_CHAIN            "cs_nat_masquerade"

#define NAT_CRPC_FIND_CHAIN             "cs_nat_crpc_find"

#define NAT_REMOTE_ACCESS_CHAIN         "cs_nat_remote_access"

#define NAT_DMZ_PRE_CHAIN               "cs_nat_dmz_pre"
#define NAT_DMZ_POST_CHAIN              "cs_nat_dmz_post"

#define NAT_PORTFW_PRE_CHAIN            "cs_nat_portfw_pre"
#define NAT_PORTFW_POST_CHAIN           "cs_nat_portfw_post"

#define NAT_PORTMAPP_PRE_CHAIN			"cs_nat_portmapp_pre"
#define NAT_PORTMAPP_POST_CHAIN			"cs_nat_portmapp_post"

//----------------------filter------------------------------------
#define FILTER_MAC_CHAIN                "cs_filter_mac"
#define FILTER_WIFI_MAC_CHAIN           "cs_filter_wifi_mac"
#define FILTER_URL_CHAIN                "cs_filter_url"
#define FILTER_IPPORT_CHAIN             "cs_filter_ipport"
#define FILTER_BLACKLIST_CHAIN          "cs_filter_blacklist"
#define FILTER_PARENTAL_CHAIN           "cs_filter_parental"

#define FILTER_DMZ_CHAIN                "cs_filter_dmz"
#define FILTER_WANPING_CHAIN            "cs_filter_wanping"
#define FILTER_VPNPASS_CHAIN            "cs_filter_vpnpass"
#define FILTER_REMOTE_ACCESS_CHAIN      "cs_filter_remote_access"
#define FILTER_PORT_FORWARD_CHAIN       "cs_filter_port_forward"

#define FILTER_SPI_INPUT_CHAIN          "cs_filter_spi_input"
#define FILTER_SPI_FORWARD_CHAIN        "cs_filter_spi_forward"

#define FILTER_PORTSCAN_INPUT_CHAIN     "cs_filter_portscan_input"
#define FILTER_PORTSCAN_FORWARD_CHAIN   "cs_filter_portscan_forward"

#define FILTER_SYNFLOOD_INPUT_CHAIN     "cs_filter_synflood_input"
#define FILTER_SYNFLOOD_FORWARD_CHAIN   "cs_filter_synflood_forward"

#define FILTER_GUEST_WIFI_CHAIN         "cs_filter_guest_wifi"

#define FILTER_IGMP_INPUT_CHAIN         "cs_filter_igmp_input"
#define FILTER_IGMP_FORWARD_CHAIN       "cs_filter_igmp_forward"

#define FILTER_PPP_FORWARD_CHAIN		"cs_filter_ppp_forward"
#define FILTER_PPP_INPUT_CHAIN          "cs_filter_ppp_input"
#define FILTER_PPP_OUTPUT_CHAIN		    "cs_filter_ppp_output"

#define FILTER_IPSEC_CHAIN         		"cs_filter_ipsec_input"
#define FILTER_IPSEC_FW_CHAIN     		"cs_filter_ipsec_forward"

#if defined(CONFIG_IPV6_FIREWALL_SUPPORT)
#define FILTER6_IPPORT_INPUT_CHAIN         "cs_ipport_input"
#define FILTER6_IPPORT_FORWARD_CHAIN       "cs_ipport_forward"

#define FILTER6_ICMPV6_CHAIN            "cs_filter6_icmpv6"
#define NAT6_MASQUERADE_CHAIN           "cs_nat6_masquerade"
#define NAT6_PORTFW_PRE_CHAIN           "cs_nat6_portfw_pre"
#endif

#if defined(CONFIG_TR069_SUPPORT)
#define FILTER_TR069_INPUT_CHAIN         "cs_filter_tr069_input"
#endif

#define FILTER_HNAT_CHAIN       		"cs_filter_hnat"

/* firewall.c */
extern void set_ipv4_forward(int is_on);
extern int start_firewall(void);
extern int stop_firewall(void);
extern void set_nfct_helper(int is_on);

#endif /* _LIB_FIREWALL_H_ */
