
#ifndef CSTE_CGI_HEADER_INCLUDED
#define	CSTE_CGI_HEADER_INCLUDED

#include <json-c/json.h>

#define OPENVPN_CLIENT_DIR 		    "/etc/openvpn/client"
#define OPENVPN_CLIENT_TMP_DIR		"/tmp/openvpn"

#define FILE_DIR_LEN 256

#define SSL_CERT_PATH  "tmp/ssl/cert"

#define SNMP_CONF 			"/etc/snmp/snmpd.conf"

typedef struct {
    int year;
    int month;
    int day;
    int hour;
} utc_to_local;


typedef enum
{
	FALSE_W = 0,
	TRUE_W
}BOOL;

typedef enum
{
	CGI_TRUE,
	CGI_FALSE
} CGI_BOOL;

typedef struct cgi_handle_table
{
	char topicurl[OPTION_STR_LEN];
	CGI_BOOL (*fun)(json_object *request, FILE *conn_fp);

	int need_auth;
} CGI_HANDLE_TABLE;

typedef enum
{
	CGI_NULL = 0,
	CGI_GET,
	CGI_SET,
	CGI_OTHER,
}CGI_TYPE;

enum{
	VPN_MULIT_TYPE_PPTP = 0,
	VPN_MULIT_TYPE_L2TP = 1,	

};

enum{
	VPN_MULTI_SWITCH_OFF = 0,
	VPN_MULTI_SWITCH_ON = 1,
};




#define MAX_TOPIC_NUM 100

extern CGI_HANDLE_TABLE get_handle_t[];
extern CGI_HANDLE_TABLE set_handle_t[];
extern CGI_HANDLE_TABLE other_handle_t[];

extern CGI_HANDLE_TABLE global_handle_t[];
extern CGI_HANDLE_TABLE gloset_handle_t[];
extern CGI_HANDLE_TABLE system_handle_t[];
extern CGI_HANDLE_TABLE network_handle_t[];
extern CGI_HANDLE_TABLE wireless_handle_t[];
extern CGI_HANDLE_TABLE firewall_handle_t[];
extern CGI_HANDLE_TABLE modem_handle_t[];
extern CGI_HANDLE_TABLE vpn_handle_t[];

typedef struct 
{
	const char *topicurl;
	json_object *request_obj;
	CGI_HANDLE_TABLE *p_tab;
	CGI_TYPE cgi_type;
}PersonalData;

extern void free_priv_data(PersonalData *priv_data);
extern PersonalData *json_to_topic(char *input);

extern void add_str_to_json_obj(json_object *json_obj_out, char *object, const char *string);
extern void add_int_to_json_obj(json_object *json_obj_out, char *object, int value);
extern void add_bollean_to_json_obj(json_object *json_obj_out, char *object, json_bool value);
extern const char *json_common_get_string(json_object *js_obj, char *key);
extern const int json_common_get_int(json_object *js_obj, char *key);
extern char *webs_get_string(json_object *js_obj, char *key);
extern int webs_get_int(json_object *js_obj, char *key);

extern void init_handle_table();
extern void send_cgi_set_respond(FILE *conn_fp, json_bool success, char *error, const char *lan_ip, char *wtime, char *reserv);
extern void send_cgi_json_respond(FILE *conn_fp, cJSON *data);

#endif /* CSTE_CGI_HEADER_INCLUDED */
