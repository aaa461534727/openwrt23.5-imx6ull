/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/file.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netpacket/packet.h>

#include <net/if.h>
#include <net/ethernet.h>

#include "discover.h"

#define cprintf(fmt, args...)                  \
    do                                         \
    {                                          \
        FILE *fp = fopen("/dev/console", "w"); \
        if (fp)                                \
        {                                      \
            fprintf(fp, fmt, ##args);          \
            fclose(fp);                        \
        }                                      \
	}while(0)

//#define DC_DEBUG
#ifdef DC_DEBUG
#define eprintf(fmt, args...) cprintf("[%s](%d)=>" fmt, __FUNCTION__, __LINE__, ##args)
#else
#define eprintf(fmt, args...)
#endif /* DEBUG */

/************************************/
/* Defaults _you_ may want to tweak */
/************************************/

/* the period of time the client is allowed to use that address */
#define LEASE_TIME (60 * 60 * 24 * 10) /* 10 days of seconds */

/* where to find the DHCP server configuration file */
#define DHCPD_CONF_FILE "/etc/udhcpd.conf"

/*****************************************************************/
/* Do not modify below here unless you know what you are doing!! */
/*****************************************************************/

/* DHCP protocol -- see RFC 2131 */
#define SERVER_PORT 67
#define CLIENT_PORT 68

#define DHCP_MAGIC 0x63825363

/* DHCP option codes (partial list) */
#define DHCP_PADDING 0x00
#define DHCP_SUBNET 0x01
#define DHCP_TIME_OFFSET 0x02
#define DHCP_ROUTER 0x03
#define DHCP_TIME_SERVER 0x04
#define DHCP_NAME_SERVER 0x05
#define DHCP_DNS_SERVER 0x06
#define DHCP_LOG_SERVER 0x07
#define DHCP_COOKIE_SERVER 0x08
#define DHCP_LPR_SERVER 0x09
#define DHCP_HOST_NAME 0x0c
#define DHCP_BOOT_SIZE 0x0d
#define DHCP_DOMAIN_NAME 0x0f
#define DHCP_SWAP_SERVER 0x10
#define DHCP_ROOT_PATH 0x11
#define DHCP_IP_TTL 0x17
#define DHCP_MTU 0x1a
#define DHCP_BROADCAST 0x1c
#define DHCP_NTP_SERVER 0x2a
#define DHCP_WINS_SERVER 0x2c
#define DHCP_REQUESTED_IP 0x32
#define DHCP_LEASE_TIME 0x33
#define DHCP_OPTION_OVER 0x34
#define DHCP_MESSAGE_TYPE 0x35
#define DHCP_SERVER_ID 0x36
#define DHCP_PARAM_REQ 0x37
#define DHCP_MESSAGE 0x38
#define DHCP_MAX_SIZE 0x39
#define DHCP_T1 0x3a
#define DHCP_T2 0x3b
#define DHCP_VENDOR 0x3c
#define DHCP_CLIENT_ID 0x3d

#define DHCP_END 0xFF

#define BOOTREQUEST 1
#define BOOTREPLY 2

#define ETH_10MB 1
#define ETH_10MB_LEN 6
#define DHCPDISCOVER 1
#define DHCPOFFER 2
#define DHCPREQUEST 3
#define DHCPDECLINE 4
#define DHCPACK 5
#define DHCPNAK 6
#define DHCPRELEASE 7
#define DHCPINFORM 8

#define BROADCAST_FLAG 0x8000

#define OPTION_FIELD 0
#define FILE_FIELD 1
#define SNAME_FIELD 2

/* miscellaneous defines */
#define MAC_BCAST_ADDR (unsigned char *)"\xff\xff\xff\xff\xff\xff"
#define OPT_CODE 0
#define OPT_LEN 1
#define OPT_DATA 2

#define INIT_SELECTING 0
#define REQUESTING 1
#define BOUND 2
#define RENEWING 3
#define REBINDING 4
#define INIT_REBOOT 5
#define RENEW_REQUESTED 6
#define RELEASED 7
#define DEFAULT_SCRIPT "/usr/share/udhcpc/default.script"
#define VERSION "0.9.8-pre"

struct client_config_t
{
    char foreground;             /* Do not fork */
    char quit_after_lease;       /* Quit after obtaining lease */
    char abort_if_no_lease;      /* Abort if no lease */
    char background_if_no_lease; /* Fork to background if no lease */
    char *interface;             /* The name of the interface to use */
    char *pidfile;               /* Optionally store the process ID */
    char *script;                /* User script to run at dhcp events */
    unsigned char *clientid;     /* Optional client id to use */
    unsigned char *hostname;     /* Optional hostname to use */
    int ifindex;                 /* Index number of the interface to use */
    unsigned char arp[6];        /* Our arp address */
};

#define DEFAULT_IF "eth1" /* WAN interface */

static struct client_config_t client_config = {
    /* Default options. */
    abort_if_no_lease : 0,
    foreground : 0,
    quit_after_lease : 0,
    background_if_no_lease : 0,
    interface : DEFAULT_IF, //2008.08 magic
    pidfile : NULL,
    script : DEFAULT_SCRIPT,
    clientid : NULL,
    hostname : NULL,
    ifindex : 0,
    arp : "\0\0\0\0\0\0", /* appease gcc-3.0 */
};

struct dhcpMessage
{
    u_int8_t op;
    u_int8_t htype;
    u_int8_t hlen;
    u_int8_t hops;
    u_int32_t xid;
    u_int16_t secs;
    u_int16_t flags;
    u_int32_t ciaddr;
    u_int32_t yiaddr;
    u_int32_t siaddr;
    u_int32_t giaddr;
    u_int8_t chaddr[16];
    u_int8_t sname[64];
    u_int8_t file[128];
    u_int32_t cookie;
    u_int8_t options[308]; /* 312 - cookie */
};

struct udp_dhcp_packet
{
    struct iphdr ip;
    struct udphdr udp;
    struct dhcpMessage data;
};

#define TYPE_MASK 0x0F

enum
{
    OPTION_IP = 1,
    OPTION_IP_PAIR,
    OPTION_STRING,
    OPTION_BOOLEAN,
    OPTION_U8,
    OPTION_U16,
    OPTION_S16,
    OPTION_U32,
    OPTION_S32
};

#define OPTION_REQ 0x10  /* have the client request this option */
#define OPTION_LIST 0x20 /* There can be a list of 1 or more of these */

struct dhcp_option
{
    char name[10];
    char flags;
    unsigned char code;
};

static int state;
//static unsigned long requested_ip; /* = 0 */
//static unsigned long server_addr;
//static unsigned long timeout;
//static int packet_num; /* = 0 */
static int cfd;
//static int signal_pipe[2];

#define LISTEN_NONE 0
#define LISTEN_KERNEL 1
#define LISTEN_RAW 2
static int listen_mode;

/* supported options are easily added here */
static struct dhcp_option options[] = {
    /* name[10]     flags                                   code */
    {"subnet", OPTION_IP | OPTION_REQ, 0x01},
    {"timezone", OPTION_S32, 0x02},
    {"router", OPTION_IP | OPTION_LIST | OPTION_REQ, 0x03},
    {"timesvr", OPTION_IP | OPTION_LIST, 0x04},
    {"namesvr", OPTION_IP | OPTION_LIST, 0x05},
    {"dns", OPTION_IP | OPTION_LIST | OPTION_REQ, 0x06},
    {"logsvr", OPTION_IP | OPTION_LIST, 0x07},
    {"cookiesvr", OPTION_IP | OPTION_LIST, 0x08},
    {"lprsvr", OPTION_IP | OPTION_LIST, 0x09},
    {"hostname", OPTION_STRING | OPTION_REQ, 0x0c},
    {"bootsize", OPTION_U16, 0x0d},
    {"domain", OPTION_STRING | OPTION_REQ, 0x0f},
    {"swapsvr", OPTION_IP, 0x10},
    {"rootpath", OPTION_STRING, 0x11},
    {"ipttl", OPTION_U8, 0x17},
    {"mtu", OPTION_U16, 0x1a},
    {"broadcast", OPTION_IP | OPTION_REQ, 0x1c},
    {"ntpsrv", OPTION_IP | OPTION_LIST, 0x2a},
    {"wins", OPTION_IP | OPTION_LIST | OPTION_REQ, 0x2c},
    {"requestip", OPTION_IP, 0x32},
    {"lease", OPTION_U32, 0x33},
    {"dhcptype", OPTION_U8, 0x35},
    {"serverid", OPTION_IP, 0x36},
    {"message", OPTION_STRING, 0x38},
    {"tftp", OPTION_STRING, 0x42},
    {"bootfile", OPTION_STRING, 0x43},
    {"", 0x00, 0x00}};

/* Lengths of the different option types */
static int option_lengths[] = {
    [OPTION_IP] = 4,
    [OPTION_IP_PAIR] = 8,
    [OPTION_BOOLEAN] = 1,
    [OPTION_STRING] = 1,
    [OPTION_U8] = 1,
    [OPTION_U16] = 2,
    [OPTION_S16] = 2,
    [OPTION_U32] = 4,
    [OPTION_S32] = 4};

u_int16_t checksum(void *addr, int count);

int listen_socket(unsigned int ip, int port, char *inf);

int raw_socket(int ifindex);
int raw_packet(struct dhcpMessage *payload, u_int32_t source_ip, int source_port,
               u_int32_t dest_ip, int dest_port, unsigned char *dest_arp, int ifindex);

unsigned char *get_option(struct dhcpMessage *packet, int code);
int get_packet(struct dhcpMessage *packet, int fd);
int get_raw_packet(struct dhcpMessage *payload, int fd);
int end_option(unsigned char *optionptr);

int add_option_string(unsigned char *optionptr, unsigned char *string);

int add_simple_option(unsigned char *optionptr, unsigned char code, u_int32_t data);

void init_header(struct dhcpMessage *packet, char type);

//static void init_packet(struct dhcpMessage *packet, char type);

//static void add_requests(struct dhcpMessage *packet);

int send_dhcp_discover(unsigned long xid);

int read_interface(char *interface, int *ifindex, u_int32_t *addr, unsigned char *arp);

unsigned long random_xid(void);

//static void change_mode(int new_mode);

/**********************************   ppp   *************************************************/

#define BPF_BUFFER_IS_EMPTY 1
#define BPF_BUFFER_HAS_DATA 0

typedef unsigned short UINT16_t;

typedef unsigned int UINT32_t;

/* Ethernet frame types according to RFC 2516 */
#define ETH_PPPOE_DISCOVERY 0x8863
#define ETH_PPPOE_SESSION 0x8864

/* But some brain-dead peers disobey the RFC, so frame types are variables */

static UINT16_t Eth_PPPOE_Discovery = ETH_PPPOE_DISCOVERY;
static UINT16_t Eth_PPPOE_Session = ETH_PPPOE_SESSION;

/* PPPoE codes */
#define CODE_PADI 0x09
#define CODE_PADO 0x07
#define CODE_PADR 0x19
#define CODE_PADS 0x65
#define CODE_PADT 0xA7

/* Extensions from draft-carrel-info-pppoe-ext-00 */
/* I do NOT like PADM or PADN, but they are here for completeness */
#define CODE_PADM 0xD3
#define CODE_PADN 0xD4

#define CODE_SESS 0x00

/* PPPoE Tags */
#define TAG_END_OF_LIST 0x0000
#define TAG_SERVICE_NAME 0x0101
#define TAG_AC_NAME 0x0102
#define TAG_HOST_UNIQ 0x0103
#define TAG_AC_COOKIE 0x0104
#define TAG_VENDOR_SPECIFIC 0x0105
#define TAG_RELAY_SESSION_ID 0x0110
#define TAG_SERVICE_NAME_ERROR 0x0201
#define TAG_AC_SYSTEM_ERROR 0x0202
#define TAG_GENERIC_ERROR 0x0203

/* Extensions from draft-carrel-info-pppoe-ext-00 */
/* I do NOT like these tags one little bit */
#define TAG_HURL 0x111
#define TAG_MOTM 0x112
#define TAG_IP_ROUTE_ADD 0x121
/* Discovery phase states */
#define STATE_SENT_PADI 0
#define STATE_RECEIVED_PADO 1
#define STATE_SENT_PADR 2
#define STATE_SESSION 3
#define STATE_TERMINATED 4

/* How many PADI/PADS attempts? */
#define MAX_PADI_ATTEMPTS 2

/* Initial timeout for PADO/PADS */
#define PADI_TIMEOUT 5
/* States for scanning PPP frames */
#define STATE_WAITFOR_FRAME_ADDR 0
#define STATE_DROP_PROTO 1
#define STATE_BUILDING_PACKET 2

/* Special PPP frame characters */
#define FRAME_ESC 0x7D
#define FRAME_FLAG 0x7E
#define FRAME_ADDR 0xFF
#define FRAME_CTRL 0x03
#define FRAME_ENC 0x20

#define IPV4ALEN 4
#define SMALLBUF 256

/* A PPPoE Packet, including Ethernet headers */
typedef struct PPPoEPacketStruct
{
    struct ethhdr ethHdr; /* Ethernet header */
    //#ifdef PACK_BITFIELDS_REVERSED
    //    unsigned int type:4;        /* PPPoE Type (must be 1) */
    //    unsigned int ver:4;         /* PPPoE Version (must be 1) */
    //#else
    unsigned int ver : 4;  /* PPPoE Version (must be 1) */
    unsigned int type : 4; /* PPPoE Type (must be 1) */
    //#endif
    unsigned int code : 8;               /* PPPoE code */
    unsigned int session : 16;           /* PPPoE session */
    unsigned int length : 16;            /* Payload length */
    unsigned char payload[ETH_DATA_LEN]; /* A bit of room to spare */
} PPPoEPacket;

/* Header size of a PPPoE packet */
#define PPPOE_OVERHEAD 6 /* type, code, session, length */
#define HDR_SIZE (sizeof(struct ethhdr) + PPPOE_OVERHEAD)
#define MAX_PPPOE_PAYLOAD (ETH_DATA_LEN - PPPOE_OVERHEAD)
#define MAX_PPPOE_MTU (MAX_PPPOE_PAYLOAD - 2)

/* PPPoE Tag */

typedef struct PPPoETagStruct
{
    unsigned int type : 16;              /* tag type */
    unsigned int length : 16;            /* Length of payload */
    unsigned char payload[ETH_DATA_LEN]; /* A LOT of room to spare */
} PPPoETag;

/* Header size of a PPPoE tag */
#define TAG_HDR_SIZE 4

/* Chunk to read from stdin */
#define READ_CHUNK 4096

/* Function passed to parsePacket */
typedef void ParseFunc(UINT16_t type, UINT16_t len, unsigned char *data, void *extra);

#define PPPINITFCS16 0xffff /* Initial FCS value */

/* Keep track of the state of a connection -- collect everything in
one spot */

typedef struct PPPoEConnectionStruct
{
    int discoveryState;              /* Where we are in discovery */
    int discoverySocket;             /* Raw socket for discovery frames */
    int sessionSocket;               /* Raw socket for session frames */
    unsigned char myEth[ETH_ALEN];   /* My MAC address */
    unsigned char peerEth[ETH_ALEN]; /* Peer's MAC address */
    UINT16_t session;                /* Session ID */
    char *ifName;                    /* Interface name */
    char *serviceName;               /* Desired service name, if any */
    char *acName;                    /* Desired AC name, if any */
    int synchronous;                 /* Use synchronous PPP */
    int useHostUniq;                 /* Use Host-Uniq tag */
    int printACNames;                /* Just print AC names */
    int skipDiscovery;               /* Skip discovery */
    int noDiscoverySocket;           /* Don't even open discovery socket */
    int killSession;                 /* Kill session and exit */
    FILE *debugFile;                 /* Debug file for dumping packets */
    int numPADOs;                    /* Number of PADO packets received */
    PPPoETag cookie;                 /* We have to send this if we get it */
    PPPoETag relayId;                /* Ditto */
} PPPoEConnection;
/* Structure used to determine acceptable PADO or PADS packet */
struct PacketCriteria
{
    PPPoEConnection *conn;
    int acNameOK;
    int serviceNameOK;
    int seenACName;
    int seenServiceName;
};

#define CHECK_ROOM(cursor, start, len)                         \
    do                                                         \
    {                                                          \
        if (((cursor) - (start)) + (len) > MAX_PPPOE_PAYLOAD)  \
        {                                                      \
            fprintf(stderr, "Would create too-long packet\n"); \
            return;                                            \
        }                                                      \
    } while (0)

/* True if Ethernet address is broadcast or multicast */
#define NOT_UNICAST(e) ((e[0] & 0x01) != 0)
#define BROADCAST(e) ((e[0] & e[1] & e[2] & e[3] & e[4] & e[5]) == 0xFF)
#define NOT_BROADCAST(e) ((e[0] & e[1] & e[2] & e[3] & e[4] & e[5]) != 0xFF)

static char const RCSID[] = "$Id: discover.h $";

char *strDup(char const *str);

#define SET_STRING(var, val) \
    do                       \
    {                        \
        if (var)             \
            free(var);       \
        var = strDup(val);   \
    } while (0);

int openInterface(char const *ifname, UINT16_t type, unsigned char *hwaddr);

void dumpHex(FILE *fp, unsigned char const *buf, int len);

UINT16_t etherType(PPPoEPacket *packet);

//void
//dumpPacket(FILE *fp, PPPoEPacket *packet, char const *dir);

int parsePacket(PPPoEPacket *packet, ParseFunc *func, void *extra);

void parseForHostUniq(UINT16_t type, UINT16_t len, unsigned char *data, void *extra);

int packetIsForMe(PPPoEConnection *conn, PPPoEPacket *packet);

void parsePADOTags(UINT16_t type, UINT16_t len, unsigned char *data, void *extra);

int sendPacket(PPPoEConnection *conn, int sock, PPPoEPacket *pkt, int size);

int receivePacket(int sock, PPPoEPacket *pkt, int *size);

void sendPADI(PPPoEConnection *conn);

void waitForPADO(PPPoEConnection *conn, int timeout);

void discovery(PPPoEConnection *conn);

#define DHCP_DETECT
//#define DHCP_SOCKET

struct ifreq ifr;
/***********************************************************************/
// ppp

char *strDup(char const *str)
{
    char *copy = malloc(strlen(str) + 1);
    if (!copy)
    {
        //rp_fatal("strdup failed");
        fprintf(stderr, "strdup failed\n");
        return (char *)0;
    }
    strcpy(copy, str);
    return copy;
}

int openInterface(char const *ifname, UINT16_t type, unsigned char *hwaddr)
{
    int optval = 1;
    int fd;
    //struct ifreq ifr;
    int domain, stype;

    struct sockaddr sa;

    memset(&sa, 0, sizeof(sa));

    domain = PF_INET;
    stype = SOCK_PACKET;
    /*
    // test
    int n;
    char buf[256];
    if ((n=read(0, buf, sizeof(buf))) <= 0) {
    perror("read");
    return -1;
    } else{
    fprintf(stderr, "read %s\n", buf);
    }
     */
    if ((fd = socket(domain, stype, htons(type))) < 0)
    {
        /* Give a more helpful message for the common error case */
        if (errno == EPERM)
        {
            fprintf(stderr,
                    "Cannot create raw socket -- pppoe must be run as root.\n");
            return -1;
        }
        perror("socket");
        return -1;
    }
    // test
    //fprintf(stderr, "openInterface: socket [%d]\n", fd);

    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)) < 0)
    {
        perror("setsockopt");
        close(fd);
        return -1;
    }

    /* Fill in hardware address */
    if (hwaddr)
    {
        memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
        if (NOT_UNICAST(hwaddr))
        {
            char buffer[256];
            sprintf(buffer,
                    "Interface %.16s has broadcast/multicast MAC address??", ifname);
            //rp_fatal(buffer);
            fprintf(stderr, "%s", buffer);
            return -1;
        }
    }

    /* Sanity check on MTU */
    strcpy(sa.sa_data, ifname);

    /* We're only interested in packets on specified interface */
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    {
        perror("bind ");
        close(fd);
        return -1;
    }

    return fd;
}

void dumpHex(FILE *fp, unsigned char const *buf, int len)
{
    int i;
    int base;

    if (!fp)
        return;

    /* do NOT dump PAP packets */
    if (len >= 2 && buf[0] == 0xC0 && buf[1] == 0x23)
    {
        fprintf(fp, "(PAP Authentication Frame -- Contents not dumped)\n");
        return;
    }

    for (base = 0; base < len; base += 16)
    {
        for (i = base; i < base + 16; i++)
        {
            if (i < len)
            {
                fprintf(fp, "%02x ", (unsigned)buf[i]);
            }
            else
            {
                fprintf(fp, "   ");
            }
        }
        fprintf(fp, "  ");
        for (i = base; i < base + 16; i++)
        {
            if (i < len)
            {
                if (isprint(buf[i]))
                {
                    fprintf(fp, "%c", buf[i]);
                }
                else
                {
                    fprintf(fp, ".");
                }
            }
            else
            {
                break;
            }
        }
        fprintf(fp, "\n");
    }
}

UINT16_t etherType(PPPoEPacket *packet)
{
    UINT16_t type = (UINT16_t)ntohs(packet->ethHdr.h_proto);
    if (type != Eth_PPPOE_Discovery && type != Eth_PPPOE_Session)
    {
        //syslog(LOG_ERR, "Invalid ether type 0x%x", type);
        fprintf(stderr, "Invalid ether type 0x%x\n", type);
    }
    return type;
}

int parsePacket(PPPoEPacket *packet, ParseFunc *func, void *extra)
{
    UINT16_t len = ntohs(packet->length);
    unsigned char *curTag;
    UINT16_t tagType, tagLen;

    fprintf(stderr, "parse packet\n");
    if (packet->ver != 1)
    {
        //syslog(LOG_ERR, "Invalid PPPoE version (%d)", (int) packet->ver);
        return -1;
    }
    if (packet->type != 1)
    {
        //syslog(LOG_ERR, "Invalid PPPoE type (%d)", (int) packet->type);
        return -1;
    }

    /* Do some sanity checks on packet */
    if (len > ETH_DATA_LEN - 6)
    {
        /* 6-byte overhead for PPPoE header */
        //syslog(LOG_ERR, "Invalid PPPoE packet length (%u)", len);
        return -1;
    }

    /* Step through the tags */
    curTag = packet->payload;
    while (curTag - packet->payload < len)
    {
        /* Alignment is not guaranteed, so do this by hand... */
        tagType = (((UINT16_t)curTag[0]) << 8) + (UINT16_t)curTag[1];
        tagLen = (((UINT16_t)curTag[2]) << 8) + (UINT16_t)curTag[3];
        if (tagType == TAG_END_OF_LIST)
        {
            return 0;
        }
        if ((curTag - packet->payload) + tagLen + TAG_HDR_SIZE > len)
        {
            //syslog(LOG_ERR, "Invalid PPPoE tag length (%u)", tagLen);
            return -1;
        }
        func(tagType, tagLen, curTag + TAG_HDR_SIZE, extra);
        //curTag = curTag + TAG_HDR_SIZE + tagLen;
    }
    return 0;
}

void parseForHostUniq(UINT16_t type, UINT16_t len, unsigned char *data, void *extra)
{
    int *val = (int *)extra;
    if (type == TAG_HOST_UNIQ && len == sizeof(pid_t))
    {
        pid_t tmp;
        memcpy(&tmp, data, len);
        if (tmp == getpid())
        {
            *val = 1;
        }
    }
}

int packetIsForMe(PPPoEConnection *conn, PPPoEPacket *packet)
{
    int forMe = 0;

    /* If packet is not directed to our MAC address, forget it */
    if (memcmp(packet->ethHdr.h_dest, conn->myEth, ETH_ALEN))
        return 0;

    /* If we're not using the Host-Unique tag, then accept the packet */
    if (!conn->useHostUniq)
        return 1;

    parsePacket(packet, parseForHostUniq, &forMe);
    return forMe;
}

int sendPacket(PPPoEConnection *conn, int sock, PPPoEPacket *pkt, int size)
{
    struct sockaddr sa;

    if (!conn)
    {
        fprintf(stderr, "relay and server not supported on Linux 2.0 kernels\n");
        return -1;
    }
    strcpy(sa.sa_data, conn->ifName);
    if (sendto(sock, pkt, size, 0, &sa, sizeof(sa)) < 0)
    {
        return -1;
    }
    return 0;
}

int receivePacket(int sock, PPPoEPacket *pkt, int *size)
{
    if ((*size = recv(sock, pkt, sizeof(PPPoEPacket), 0)) < 0)
    {
        return -1;
    }
    return 0;
}

void sendPADI(PPPoEConnection *conn)
{
    PPPoEPacket packet;
    unsigned char *cursor = packet.payload;
    PPPoETag *svc = (PPPoETag *)(&packet.payload);
    UINT16_t namelen = 0;
    UINT16_t plen;

    eprintf("send PADI packet.\n");
    if (conn->serviceName)
    {
        namelen = (UINT16_t)strlen(conn->serviceName);
    }
    plen = TAG_HDR_SIZE + namelen;
    CHECK_ROOM(cursor, packet.payload, plen);

    /* Set destination to Ethernet broadcast address */
    memset(packet.ethHdr.h_dest, 0xFF, ETH_ALEN);
    memcpy(packet.ethHdr.h_source, conn->myEth, ETH_ALEN);

    packet.ethHdr.h_proto = htons(Eth_PPPOE_Discovery);
    packet.ver = 1;
    packet.type = 1;
    packet.code = CODE_PADI;
    packet.session = 0;

    svc->type = TAG_SERVICE_NAME;
    svc->length = htons(namelen);
    CHECK_ROOM(cursor, packet.payload, namelen + TAG_HDR_SIZE);

    if (conn->serviceName)
    {
        memcpy(svc->payload, conn->serviceName, strlen(conn->serviceName));
    }
    cursor += namelen + TAG_HDR_SIZE;

    /* If we're using Host-Uniq, copy it over */
    if (conn->useHostUniq)
    {
        PPPoETag hostUniq;
        pid_t pid = getpid();
        hostUniq.type = htons(TAG_HOST_UNIQ);
        hostUniq.length = htons(sizeof(pid));
        memcpy(hostUniq.payload, &pid, sizeof(pid));
        CHECK_ROOM(cursor, packet.payload, sizeof(pid) + TAG_HDR_SIZE);
        memcpy(cursor, &hostUniq, sizeof(pid) + TAG_HDR_SIZE);
        cursor += sizeof(pid) + TAG_HDR_SIZE;
        plen += sizeof(pid) + TAG_HDR_SIZE;
    }

    packet.length = htons(plen);
    sendPacket(conn, conn->discoverySocket, &packet, (int)(plen + HDR_SIZE));
}

/***********************************************************************/

u_int16_t checksum(void *addr, int count)
{
    /* Compute Internet Checksum for "count" bytes
     *	 beginning at location "addr".
     */
    register int32_t sum = 0;
    u_int16_t *source = (u_int16_t *)addr;

    while (count > 1)
    {
        /*  This is the inner loop */
        sum += *source++;
        count -= 2;
    }

    /*  Add left-over byte, if any */
    if (count > 0)
    {
        /* Make sure that the left-over byte is added correctly both
         * with little and big endian hosts */
        u_int16_t tmp = 0;
        *(unsigned char *)(&tmp) = *(unsigned char *)source;
        sum += tmp;
    }
    /*  Fold 32-bit sum to 16 bits */
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

int listen_socket(unsigned int ip, int port, char *inf)
{
    struct ifreq interface;
    int fd;
    struct sockaddr_in addr;
    int n = 1;

    //DEBUG(LOG_INFO, "Opening listen socket on 0x%08x:%d %s\n", ip, port, inf);
    if ((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
        //DEBUG(LOG_ERR, "socket call failed: %s", strerror(errno));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = ip;

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&n, sizeof(n)) == -1)
    {
        close(fd);
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, (char *)&n, sizeof(n)) == -1)
    {
        close(fd);
        return -1;
    }

    strncpy(interface.ifr_ifrn.ifrn_name, inf, IFNAMSIZ);
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (char *)&interface, sizeof(interface)) < 0)
    {
        close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr)) == -1)
    {
        close(fd);
        return -1;
    }

    return fd;
}

int raw_socket(int ifindex)
{
    int fd;
    struct sockaddr_ll sock;

    if ((fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0)
    {
        return -1;
    }

    sock.sll_family = AF_PACKET;
    sock.sll_protocol = htons(ETH_P_IP);
    sock.sll_ifindex = ifindex;
    if (bind(fd, (struct sockaddr *)&sock, sizeof(sock)) < 0)
    {
        close(fd);
        return -1;
    }

    return fd;
}

/* Constuct a ip/udp header for a packet, and specify the source and dest hardware address */
int raw_packet(struct dhcpMessage *payload, u_int32_t source_ip, int source_port, u_int32_t dest_ip, int dest_port, unsigned char *dest_arp, int ifindex)
{
    int fd;
    int result;
    struct sockaddr_ll dest;
    struct udp_dhcp_packet packet;

    if ((fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0)
    {
        //DEBUG(LOG_ERR, "socket call failed: %s", strerror(errno));
        //fprintf(stderr, "socket call failed: %s\n", strerror(errno));
        return -1;
    }

    memset(&dest, 0, sizeof(dest));
    memset(&packet, 0, sizeof(packet));

    dest.sll_family = AF_PACKET;
    dest.sll_protocol = htons(ETH_P_IP);
    dest.sll_ifindex = ifindex;
    dest.sll_halen = 6;
    memcpy(dest.sll_addr, dest_arp, 6);
    if (bind(fd, (struct sockaddr *)&dest, sizeof(struct sockaddr_ll)) < 0)
    {
        //DEBUG(LOG_ERR, "bind call failed: %s", strerror(errno));
        //fprintf(stderr, "bind call failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    packet.ip.protocol = IPPROTO_UDP;
    packet.ip.saddr = source_ip;
    packet.ip.daddr = dest_ip;
    packet.udp.uh_sport = htons(source_port);
    packet.udp.uh_dport = htons(dest_port);
    packet.udp.uh_ulen = htons(sizeof(packet.udp) + sizeof(struct dhcpMessage)); /*
        cheat on the psuedo-header */
    packet.ip.tot_len = packet.udp.uh_ulen;
    memcpy(&(packet.data), payload, sizeof(struct dhcpMessage));
    packet.udp.uh_sum = checksum(&packet, sizeof(struct udp_dhcp_packet));

    packet.ip.tot_len = htons(sizeof(struct udp_dhcp_packet));
    packet.ip.ihl = sizeof(packet.ip) >> 2;
    packet.ip.version = IPVERSION;
    packet.ip.ttl = IPDEFTTL;
    packet.ip.check = checksum(&(packet.ip), sizeof(packet.ip));

    result = sendto(fd, &packet, sizeof(struct udp_dhcp_packet), 0, (struct sockaddr *)&dest, sizeof(dest));
    if (result <= 0)
    {
        //DEBUG(LOG_ERR, "write on socket failed: %s", strerror(errno));
        //fprintf(stderr, "write on socket failed: %s", strerror(errno));
    }
    close(fd);
    return result;
}

int get_packet(struct dhcpMessage *packet, int fd)
{
    int bytes;
    int i;
    const char broken_vendors[][8] =
        {
            "MSFT 98", ""};
    char unsigned *vendor;

    memset(packet, 0, sizeof(struct dhcpMessage));
    bytes = read(fd, packet, sizeof(struct dhcpMessage));
    if (bytes < 0)
    {
        //DEBUG(LOG_INFO, "couldn't read on listening socket, ignoring");
        return -1;
    }

    if (ntohl(packet->cookie) != DHCP_MAGIC)
    {
        //LOG(LOG_ERR, "received bogus message, ignoring");
        return -2;
    }
    //DEBUG(LOG_INFO, "Received a packet");

    if (packet->op == BOOTREQUEST && (vendor = get_option(packet, DHCP_VENDOR)))
    {
        for (i = 0; broken_vendors[i][0]; i++)
        {
            if (vendor[OPT_LEN - 2] == (unsigned char)strlen(broken_vendors[i]) && !strncmp(vendor, broken_vendors[i], vendor[OPT_LEN - 2]))
            {
                //DEBUG(LOG_INFO, "broken client (%s), forcing broadcast",
                //	broken_vendors[i]);
                packet->flags |= htons(BROADCAST_FLAG);
            }
        }
    }

    return bytes;
}

/* return -1 on errors that are fatal for the socket, -2 for those that aren't */
int get_raw_packet(struct dhcpMessage *payload, int fd)
{
    int bytes;
    struct udp_dhcp_packet packet;
    u_int32_t source, dest;
    u_int16_t check;

    memset(&packet, 0, sizeof(struct udp_dhcp_packet));
    bytes = read(fd, &packet, sizeof(struct udp_dhcp_packet));
    if (bytes < 0)
    {
        //DEBUG(LOG_INFO, "couldn't read on raw listening socket -- ignoring");
        //fprintf(stderr, "couldn't read on raw listening socket -- ignoring");
        usleep(500000); /* possible down interface, looping condition */
        eprintf("--- get_raw_packet: couldn't read on raw listening socket! ---\n");
        return -1;
    }

    if (bytes < (int)(sizeof(struct iphdr) + sizeof(struct udphdr)))
    {
        //DEBUG(LOG_INFO, "message too short, ignoring");
        eprintf("--- get_raw_packet: message too short! ---\n");
        return -2;
    }

    if (bytes < ntohs(packet.ip.tot_len))
    {
        //DEBUG(LOG_INFO, "Truncated packet");
        eprintf("--- get_raw_packet: Truncated packet! ---\n");
        //return -2;
        return -100;
    }

    /* ignore any extra garbage bytes */
    bytes = ntohs(packet.ip.tot_len);

    /* Make sure its the right packet for us, and that it passes sanity checks */
    if (packet.ip.protocol != IPPROTO_UDP || packet.ip.version != IPVERSION ||
        packet.ip.ihl != sizeof(packet.ip) >> 2 || packet.udp.uh_dport != htons(CLIENT_PORT) || bytes > (int)sizeof(struct udp_dhcp_packet) || ntohs(packet.udp.uh_ulen) != (short)(bytes - sizeof(packet.ip)))
    {
        //DEBUG(LOG_INFO, "unrelated/bogus packet");
        eprintf("--- get_raw_packet: unrelated/bogus packet! ---\n");
        return -2;
    }

    /* check IP checksum */
    check = packet.ip.check;
    packet.ip.check = 0;
    if (check != checksum(&(packet.ip), sizeof(packet.ip)))
    {
        //DEBUG(LOG_INFO, "bad IP header checksum, ignoring");
        eprintf("--- get_raw_packet: bad IP header checksum! ---\n");
        return -1;
    }

    /* verify the UDP checksum by replacing the header with a psuedo header */
    source = packet.ip.saddr;
    dest = packet.ip.daddr;
    check = packet.udp.uh_sum;
    packet.udp.uh_sum = 0;
    memset(&packet.ip, 0, sizeof(packet.ip));

    packet.ip.protocol = IPPROTO_UDP;
    packet.ip.saddr = source;
    packet.ip.daddr = dest;
    packet.ip.tot_len = packet.udp.uh_ulen; /* cheat on the psuedo-header */
    if (check && check != checksum(&packet, bytes))
    {
        //DEBUG(LOG_ERR, "packet with bad UDP checksum received, ignoring");
        eprintf("--- get_raw_packet: packet with bad UDP checksum received! ---\n");
        return -2;
    }

    memcpy(payload, &(packet.data), bytes - (sizeof(packet.ip) + sizeof(packet.udp)));

    if (ntohl(payload->cookie) != DHCP_MAGIC)
    {
        //LOG(LOG_ERR, "received bogus message (bad magic) -- ignoring");
        eprintf("--- get_raw_packet: received bogus message! ---\n");
        return -2;
    }
    //DEBUG(LOG_INFO, "oooooh!!! got some!");
    eprintf("--- get_raw_packet: Got some correct message! ---\n");
    return bytes - (sizeof(packet.ip) + sizeof(packet.udp));
}

/* get an option with bounds checking (warning, not aligned). */
unsigned char *get_option(struct dhcpMessage *packet, int code)
{
    int i, length;
    unsigned char *optionptr;
    int over = 0, done = 0, curr = OPTION_FIELD;

    optionptr = packet->options;
    i = 0;
    length = 308;
    while (!done)
    {
        if (i >= length)
        {
            //LOG(LOG_WARNING, "bogus packet, option fields too long.");
            return NULL;
        }
        if (optionptr[i + OPT_CODE] == code)
        {
            if (i + 1 + optionptr[i + OPT_LEN] >= length)
            {
                //LOG(LOG_WARNING, "bogus packet, option fields too long.");
                return NULL;
            }
            return optionptr + i + 2;
        }
        switch (optionptr[i + OPT_CODE])
        {
        case DHCP_PADDING:
            i++;
            break;
        case DHCP_OPTION_OVER:
            if (i + 1 + optionptr[i + OPT_LEN] >= length)
            {
                //LOG(LOG_WARNING, "bogus packet, option fields too long.");
                return NULL;
            }
            over = optionptr[i + 3];
            i += optionptr[OPT_LEN] + 2;
            break;
        case DHCP_END:
            if (curr == OPTION_FIELD && over & FILE_FIELD)
            {
                optionptr = packet->file;
                i = 0;
                length = 128;
                curr = FILE_FIELD;
            }
            else if (curr == FILE_FIELD && over & SNAME_FIELD)
            {
                optionptr = packet->sname;
                i = 0;
                length = 64;
                curr = SNAME_FIELD;
            }
            else
                done = 1;
            break;
        default:
            i += optionptr[OPT_LEN + i] + 2;
        }
    }
    return NULL;
}

/* return the position of the 'end' option (no bounds checking) */
int end_option(unsigned char *optionptr)
{
    int i = 0;

    while (optionptr[i] != DHCP_END)
    {
        if (optionptr[i] == DHCP_PADDING)
            i++;
        else
            i += optionptr[i + OPT_LEN] + 2;
    }
    return i;
}

/* add an option string to the options (an option string contains an option code,
 * length, then data) */
int add_option_string(unsigned char *optionptr, unsigned char *string)
{
    int end = end_option(optionptr);

    /* end position + string length + option code/length + end option */
    if (end + string[OPT_LEN] + 2 + 1 >= 308)
    {
        //fprintf(stderr, "Option 0x%02x did not fit into the packet!\n", string[OPT_CODE]);
        return 0;
    }
    //fprintf(stderr, "adding option 0x%02x\n", string[OPT_CODE]);
    memcpy(optionptr + end, string, string[OPT_LEN] + 2);
    optionptr[end + string[OPT_LEN] + 2] = DHCP_END;
    return string[OPT_LEN] + 2;
}

/* add a one to four byte option to a packet */
int add_simple_option(unsigned char *optionptr, unsigned char code, u_int32_t data)
{
    char length = 0;
    int i;
    unsigned char option[2 + 4];
    unsigned char *u8;
    u_int16_t *u16;
    u_int32_t *u32;
    u_int32_t aligned;
    u8 = (unsigned char *)&aligned;
    u16 = (u_int16_t *)&aligned;
    u32 = &aligned;

    for (i = 0; options[i].code; i++)
        if (options[i].code == code)
        {
            length = option_lengths[options[i].flags & TYPE_MASK];
        }

    if (!length)
    {
        //DEBUG(LOG_ERR, "Could not add option 0x%02x", code);
        return 0;
    }

    option[OPT_CODE] = code;
    option[OPT_LEN] = length;

    switch (length)
    {
    case 1:
        *u8 = data;
        break;
    case 2:
        *u16 = data;
        break;
    case 4:
        *u32 = data;
        break;
    }
    memcpy(option + 2, &aligned, length);
    return add_option_string(optionptr, option);
}

void init_header(struct dhcpMessage *packet, char type)
{
    memset(packet, 0, sizeof(struct dhcpMessage));
    switch (type)
    {
    case DHCPDISCOVER:
    case DHCPREQUEST:
    case DHCPRELEASE:
    case DHCPINFORM:
        packet->op = BOOTREQUEST;
        break;
    case DHCPOFFER:
    case DHCPACK:
    case DHCPNAK:
        packet->op = BOOTREPLY;
    }
    packet->htype = ETH_10MB;
    packet->hlen = ETH_10MB_LEN;
    packet->cookie = htonl(DHCP_MAGIC);
    packet->options[0] = DHCP_END;
    add_simple_option(packet->options, DHCP_MESSAGE_TYPE, type);
}

/* initialize a packet with the proper defaults */
static void init_packet(struct dhcpMessage *packet, char type)
{
    struct vendor
    {
        char vendor, length;
        char str[sizeof("udhcp " VERSION)];
    } vendor_id =
        {
            DHCP_VENDOR, sizeof("udhcp " VERSION) - 1, "udhcp " VERSION};

    init_header(packet, type);
    memcpy(packet->chaddr, client_config.arp, 6);
    add_option_string(packet->options, client_config.clientid);
    add_option_string(packet->options, (unsigned char *)&vendor_id);
}

/* Add a paramater request list for stubborn DHCP servers. Pull the data
 * from the struct in options.c. Don't do bounds checking here because it
 * goes towards the head of the packet. */
static void add_requests(struct dhcpMessage *packet)
{
    int end = end_option(packet->options);
    int i, len = 0;

    packet->options[end + OPT_CODE] = DHCP_PARAM_REQ;
    for (i = 0; options[i].code; i++)
        if (options[i].flags & OPTION_REQ)
            packet->options[end + OPT_DATA + len++] = options[i].code;
    packet->options[end + OPT_LEN] = len;
    packet->options[end + OPT_DATA + len] = DHCP_END;
}

/* Broadcast a DHCP discover packet to the network, with an optionally requested IP */
int send_dhcp_discover(unsigned long xid)
{
    struct dhcpMessage packet;

    eprintf("send dhcp discover packet.\n");
    init_packet(&packet, DHCPDISCOVER);
    packet.xid = xid;

    add_requests(&packet);

    packet.flags = packet.flags | ntohs(0x8000); /*Broadcast*/
    return raw_packet(&packet, INADDR_ANY, CLIENT_PORT, INADDR_BROADCAST,
                      SERVER_PORT, MAC_BCAST_ADDR, client_config.ifindex);
}

int read_interface(char *interface, int *ifindex, u_int32_t *addr, unsigned char *arp)
{
    int fd;
    //struct ifreq ifr;
    struct sockaddr_in *our_ip;

    memset(&ifr, 0, sizeof(struct ifreq));
    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) >= 0)
    {
        ifr.ifr_addr.sa_family = AF_INET;
        strcpy(ifr.ifr_name, interface);

        // test
        //fprintf(stderr, "read interface, socket is %d\n", fd);

        if (addr)
        {
            if (ioctl(fd, SIOCGIFADDR, &ifr) == 0)
            {
                our_ip = (struct sockaddr_in *)&ifr.ifr_addr;
                *addr = our_ip->sin_addr.s_addr;
            }
            else
            {
                close(fd);
                return -1;
            }
        }

        if (ioctl(fd, SIOCGIFINDEX, &ifr) == 0)
        {
            *ifindex = ifr.ifr_ifindex;
        }
        else
        {
            close(fd); // 1104 chk
            return -1;
        }
        if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0)
        {
            memcpy(arp, ifr.ifr_hwaddr.sa_data, 6);
        }
        else
        {
            //fprintf(stderr, "get hardware address failed!: %s", strerror(errno));
            close(fd);
            return -1;
        }
    }
    else
    {
        return -1;
    }
    // test
    //fprintf(stderr, "end read interface [%d]\n", fd);
    close(fd);
    return 0;
}

#include <sys/sysinfo.h>
long get_uptime(void)
{
    struct sysinfo info;
    sysinfo(&info);

    return info.uptime;
}

/* Create a random xid */
unsigned long random_xid(void)
{
    // test
    //fprintf(stderr, "xid\n");

    static int initialized;
    if (!initialized)
    {
        //		int fd;
        unsigned long seed;

        //fd = open("/dev/urandom", 0);
        //if (fd < 0 || read(fd, &seed, sizeof(seed)) < 0) {
        //LOG(LOG_WARNING, "Could not load seed from /dev/urandom: %s",
        //	strerror(errno));
        //		seed = time(0);
        seed = get_uptime();
        //}
        //if (fd >= 0) {
        //	 close(fd);
        //}
        srand(seed);
        initialized++;
    }
    return rand();
}

static void change_mode(int new_mode)
{
    //DEBUG(LOG_INFO, "entering %s listen mode",
    //	new_mode ? (new_mode == 1 ? "kernel" : "raw") : "none");
    //close(cfd);
    cfd = -1;
    listen_mode = new_mode;
}

void closeall(int fd1, int fd2)
{

// test
//fprintf(stderr, "close [%d][%d]\n", fd1, fd2);
#ifdef DHCP_DETECT
    close(fd1);
#endif // DHCP_DETECT
    close(fd2);
}

/*
ret:
	-1: error
	0  : static
	1  : dhcp
	2  : pppoe
*/
int discover_all(char *ifname)
{
    unsigned char *message;
    unsigned long xid = 0;

    fd_set rfds;
    int retval, i_ret = -1;

    struct timeval tv;
    int len;
    struct dhcpMessage packet;
    int max_fd;

    PPPoEConnection conn; // ppp

    PPPoEPacket ppp_packet;
    int ppp_len;

    /* Initialize connection info */
    memset(&conn, 0, sizeof(conn));
    conn.discoverySocket = -1;
    conn.sessionSocket = -1;
    conn.useHostUniq = 1;

    /* Pick a default interface name */
    client_config.interface=NULL;
    if (ifname && strlen(ifname) > 0)
    {
		SET_STRING(conn.ifName, ifname);
		SET_STRING(client_config.interface, ifname);
    }
    else
    {
		SET_STRING(conn.ifName, DEFAULT_IF);
		SET_STRING(client_config.interface, DEFAULT_IF);
    }
    if (read_interface(client_config.interface, &client_config.ifindex, NULL, client_config.arp) < 0)
    {
        //fprintf(stderr, "read interface error!\n");
        i_ret = -1;
        goto done_final;
    }

    if (!client_config.clientid)
    {
        client_config.clientid = malloc(6 + 3);
        client_config.clientid[OPT_CODE] = DHCP_CLIENT_ID;
        client_config.clientid[OPT_LEN] = 7;
        client_config.clientid[OPT_DATA] = 1;
        memcpy(client_config.clientid + 3, client_config.arp, 6);
    }

#ifdef DHCP_DETECT
    xid = random_xid();
    //xid = 10056;
#endif // DHCP_DETECT

    state = INIT_SELECTING;
#ifdef DHCP_SOCKET
    change_mode(LISTEN_KERNEL);
#else
    change_mode(LISTEN_RAW);
#endif

    if (cfd < 0)
    {
        // ppp
        if ((conn.discoverySocket = openInterface(conn.ifName,
                                                  Eth_PPPOE_Discovery, conn.myEth)) < 0)
        {
            //fprintf(stderr, "open interface fail [%d]\n", conn.discoverySocket);
            i_ret = -1;
            goto done_final;
        }

#ifdef DHCP_DETECT
        if (listen_mode == LISTEN_KERNEL)
            cfd = listen_socket(INADDR_ANY, CLIENT_PORT,
                                client_config.interface);
        else
            cfd = raw_socket(client_config.ifindex);

        if (cfd < 0)
        {
            close(conn.discoverySocket);
            //fprintf(stderr, "socket open error\n");
            i_ret = -1;
            goto done_final;
        }
#endif // DHCP_DETECT
    }

#if 1 //DEBUG
    eprintf("--- discover_all: ifname=%s! ---\n", DEFAULT_IF);
    eprintf("--- discover_all: cfd=%d! ---\n", cfd);
    eprintf("--- discover_all: conn.discoverySocket=%d! ---\n", conn.discoverySocket);
#endif

    int count = 0, got_DHCP, got_PPP;
    for (;;)
    {
#ifdef DHCP_DETECT
        got_DHCP = 0;
#endif // DHCP_DETECT
        got_PPP = 0;

        FD_ZERO(&rfds);

        FD_SET(conn.discoverySocket, &rfds); // ppp
#ifdef DHCP_DETECT
        FD_SET(cfd, &rfds); // DHCP
#endif                      // DHCP_DETECT

        sendPADI(&conn);
#ifdef DHCP_DETECT
        //send_dhcp_discover(xid); /* broadcast */
        send_dhcp_discover(xid); /* broadcast */
#endif                           // DHCP_DETECT

        tv.tv_sec = 5;
        tv.tv_usec = 0;
#ifdef DHCP_DETECT
#if 0
        max_fd = cfd;
#else // J++
        max_fd = cfd > conn.discoverySocket ? cfd : conn.discoverySocket;
#endif
#else  // DHCP_DETECT
        max_fd = conn.discoverySocket;
#endif // DHCP_DETECT
        retval = select(max_fd + 1, &rfds, NULL, NULL, &tv);

        if (retval == -1)
        {
            eprintf("--- discover_all: error on select! ---\n");
            fprintf(stderr, "error on select\n");

            if (errno == EINTR)
            /* a signal was caught */
            {
                eprintf("--- discover_all: a signal was caught! ---\n");
                //fprintf(stderr, "a signal was caught!\n");
                sleep(1);
                continue;
            }
            else if (errno == EBADF)
            {
                eprintf("--- discover_all: An invalid file descriptor was given in one of the sets ---\n");
                //fprintf(stderr, "An invalid file descriptor was given in one of the sets\n");
                break;
            }
            else if (errno == EINVAL)
            {
                eprintf("--- discover_all: max_fd + 1 is negative or the value contained within timeout is invalid ---\n");
                //fprintf(stderr, "max_fd + 1 is negative or the value contained within timeout is invalid\n");
                break;
            }
            else if (errno == ENOMEM)
            {
                eprintf("--- discover_all: unable to allocate memory for internal tables ---\n");
                //fprintf(stderr, "unable to allocate memory for internal tables\n");
                break;
            }
            else
            {
                eprintf("--- discover_all: unknown errno: %x ---\n", errno);
                //fprintf(stderr, "unknown errno: %x\n", errno);
                break;
            }
        }
        else if (retval < 0)
        {
            eprintf("--- discover_all: this should not happen! ---\n");
            //fprintf(stderr, "this should not happen\n");
            break;
        }

#ifdef DHCP_DETECT
#if 1 //DEBUG
        eprintf("--- 1: FD_ISSET=%d---\n", FD_ISSET(1, &rfds));
        eprintf("--- 2: FD_ISSET=%d---\n", FD_ISSET(2, &rfds));
        eprintf("--- 3: FD_ISSET=%d---\n", FD_ISSET(3, &rfds));
        eprintf("--- 4: FD_ISSET=%d---\n", FD_ISSET(4, &rfds));
        eprintf("--- 5: FD_ISSET=%d---\n", FD_ISSET(5, &rfds));
        eprintf("--- 6: FD_ISSET=%d---\n", FD_ISSET(6, &rfds));
        eprintf("--- 7: FD_ISSET=%d---\n", FD_ISSET(7, &rfds));
        eprintf("--- 8: FD_ISSET=%d---\n", FD_ISSET(8, &rfds));

        eprintf("--- discover_all: cfd=%d! ---\n", cfd);
        eprintf("--- discover_all: conn.discoverySocket=%d! ---\n", conn.discoverySocket);
#endif

        if (FD_ISSET(cfd, &rfds))
            got_DHCP = 1;
#endif // DHCP_DETECT

		//PPPoE first.
        if (FD_ISSET(conn.discoverySocket, &rfds))
            got_PPP = 1;
        eprintf("--- discover_all: got_DHCP=%d, got_PPP=%d. ---\n", got_DHCP, got_PPP);
        if (retval == 0)
        {
            eprintf("--- discover_all: retval == 0. ---\n");
            //fprintf(stderr, "timeout occur when discover dhcp or pppoe\n");
            i_ret = 0;
            goto done_1;
        }

        if (FD_ISSET(conn.discoverySocket, &rfds))
            got_PPP = 1;

        //else if (retval > 0 && listen_mode != LISTEN_NONE && got_PPP) {
        if (retval > 0 && listen_mode != LISTEN_NONE && got_PPP == 1)
        {
            eprintf("--- discover_all: discovery PPPoE! ---\n");
            receivePacket(conn.discoverySocket, &ppp_packet, &ppp_len);

            if (ppp_packet.code == CODE_PADO)
            {
                eprintf("--- discover_all: Got the PPPoE! ---\n");
                i_ret = 2;
                goto done_1;
            }

            got_PPP = -1;
            eprintf("--- discover_all: end to analyse the PPPoE's packet! ---\n");
        }

#ifdef DHCP_DETECT
        if (retval > 0 && listen_mode != LISTEN_NONE && got_DHCP == 1)
        {
            eprintf("--- discover_all: discovery DHCP! ---\n");
            /* a packet is ready, read it */
            if (listen_mode == LISTEN_KERNEL)
                len = get_packet(&packet, cfd);
            else
                len = get_raw_packet(&packet, cfd);

            if (len == -1 && errno != EINTR)
                goto done_1;

            if ((len < 0) || (packet.xid != xid) || ((message = get_option(&packet, DHCP_MESSAGE_TYPE)) == NULL))
            {
                ++count;
                eprintf("--- discover_all: Got the wrong %d packet when detecting DHCP! ---\n", count);
#if 0 //disable for MAX_PADI_ATTEMPTS try
#ifdef DHCP_SOCKET
                goto done_1;
#else
                if (len !=  - 100)
                    goto done_1;
                else
                    got_DHCP =  -1;
#endif
#else
                if (count > MAX_PADI_ATTEMPTS)
                {
                    i_ret = 0; //static
                    goto done_1;
                }
#endif
            }
            /* Must be a DHCPOFFER to one of our xid's */
            //if (*message == DHCPOFFER) {
            else if (*message == DHCPOFFER)
            {
                eprintf("--- discover_all: Got the DHCP! ---\n");
                i_ret = 1;
                goto done_1;
            }
            else
                got_DHCP = -1;
            eprintf("--- discover_all: end to analyse the DHCP's packet! ---\n");
        }
#endif // DHCP_DETECT

        eprintf("--- Go to next detect loop. ---\n");
    }

done_1:
    FD_ZERO(&rfds);
    closeall(cfd, conn.discoverySocket);
done_final:

	if (ifname && strlen(ifname) > 0)
	{
		free(conn.ifName);
		free(client_config.interface);
	}
	if (!client_config.clientid)
	{
		free(client_config.clientid);
	}

    return i_ret;
}
