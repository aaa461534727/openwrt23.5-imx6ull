
#include "defs.h"
#if defined(SESSION_AUTH)

#include <sys/sysinfo.h>
#define LOGIN_TIMEOUT		300

int check_tnt_id(const char *headers)
{
	char *ptr=NULL;
	char session_id[64];

	datconf_get_by_key(TEMP_STATUS_FILE, "session_id", session_id, sizeof(session_id));
	if((ptr=strstr(headers, "TNT_SID="))!=NULL){
		if(strncmp(ptr+strlen("TNT_SID="),session_id, strlen(session_id)) == 0)
			return 1;

		dbg("Cookie:%s\n", ptr);
	}

	return 0;
}

long uptime(void)
{
	struct sysinfo info;
	sysinfo(&info);

	return info.uptime;
}

char *get_session_id(const char *query, char *sid, int len)
{
	get_query_param(query, "token", sid, len);

	return sid;
}

int check_session_id(const char *query)
{
	char sid[64],session_id[64];

	datconf_get_by_key(TEMP_STATUS_FILE, "session_id", session_id, sizeof(session_id));
	if(get_session_id(query, sid, sizeof(sid)) && strcmp(sid, session_id) == 0){
		return 1;
	}

	return 0;
}

int generate_session_id()
{
	int fd;
	unsigned char s[8];

	char sid[32]={0};

	if((fd = open("/dev/urandom", O_RDONLY)) < 0) {
		dbg("fail open /dev/urandom");
		return -1;
	};

	read(fd, s, sizeof(s));
	close(fd);

	sprintf(sid, "%02X%02X%02X%02X%02X%02X%02X%02X", s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]);

	datconf_set_by_key(TEMP_STATUS_FILE, "session_id", sid);
	return 0;
}


int http_login_check(const char *client_ip)
{
	char login_ip[16]={0}, timestamp[64]={0};
	unsigned long login_timestamp;
	
	datconf_get_by_key(TEMP_STATUS_FILE, "login_ip", login_ip, sizeof(login_ip));
	datconf_get_by_key(TEMP_STATUS_FILE, "login_timestamp", timestamp, sizeof(timestamp));
	
	login_timestamp=strtol(timestamp, NULL, 10);

	int is_new_user=0;
	if(client_ip && (strcmp(login_ip, "0.0.0.0") != 0 && strcmp(client_ip, login_ip) != 0))
	{
		is_new_user=1;
	}

	if ((unsigned long)(uptime() - login_timestamp) > LOGIN_TIMEOUT) {
		if(!is_new_user){
			reset_login_data();
			return 2;
		}
	}else if(is_new_user){
		return 1;
	}

	return 0;
}

void update_login_data(const char *client_ip)
{
	char login_timestamp[24]={0};

	if(client_ip) {
		datconf_set_by_key(TEMP_STATUS_FILE, "login_ip", client_ip);
	
		snprintf(login_timestamp,sizeof(login_timestamp),"%ld",uptime());
		datconf_set_by_key(TEMP_STATUS_FILE, "login_timestamp", login_timestamp);
	}
}

void reset_login_data(void)
{
	datconf_set_by_key(TEMP_STATUS_FILE, "login_ip", "0.0.0.0");
	datconf_set_by_key(TEMP_STATUS_FILE, "login_timestamp", "0");
	
	generate_session_id();
}

int check_auth_login(struct conn *c, char *err_msg, int len)
{
	char *client_ip;
	char password[128] = {0};
	int ret =0, login_state=0;

	Uci_Get_Str(PKG_SYSTEM_CONFIG,"main","password",password);
	if(strlen(password) > 0) 
	{
		client_ip = inet_ntoa(* (struct in_addr *) &c->sa.u.sin.sin_addr.s_addr);

		if(strcmp(client_ip,"127.0.0.1") == 0)
		{
			return 0;
		}
		
		if(!check_session_id(c->query)){
			ret = -1;

			snprintf(err_msg,len,"%s","token invalid");

			return ret; 
		}

		login_state = http_login_check(client_ip);

		if(1==login_state){
			ret = -3;

			snprintf(err_msg,len,"%s","Other user is online");

			return ret;
		}
		else if(2==login_state){
			ret = -4;

			snprintf(err_msg,len,"%s","Login timeout");

			return ret;
		}
	}
	
	c->auth_state = 1;
	update_login_data(client_ip);

	return ret;

}

int get_query_param(char *query, char *param_key, char *param_val, int len)
{
	int idx;
	char tmp_buf[256], tmp_key[128], tmp_val[128];

	if(query==NULL){
		return 0;
	}

	idx=0;
	memset(tmp_buf,0,sizeof(tmp_buf));
	while(get_nth_val_safe(idx++, query, '&', tmp_buf, sizeof(tmp_buf))!=-1){
		memset(tmp_key,0,sizeof(tmp_key));
		memset(tmp_val,0,sizeof(tmp_val));

		get_nth_val_safe(0, tmp_buf, '=', tmp_key, sizeof(tmp_key));
		get_nth_val_safe(1, tmp_buf, '=', tmp_val, sizeof(tmp_val));
		if(strcmp(tmp_key,param_key)==0){
			snprintf(param_val,len,"%s",tmp_val);
			break;
		}
		memset(tmp_buf,0,sizeof(tmp_buf));
	}
	return 0;
}
#endif /* SESSION_AUTH */
