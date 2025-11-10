
#include "defs.h"



char syslog_txt[] =
"Content-Disposition: attachment;\r\n"
"filename=syslog.txt"
;
char no_cache_IE[] =
"X-UA-Compatible: IE=edge\r\n"
"Cache-Control: no-store, no-cache, must-revalidate\r\n"
"Pragma: no-cache\r\n"
"Expires: -1"
;

void *memmem(const void *buf, size_t buf_len, const void *byte_line, size_t byte_line_len);



int make_headers(int status, const char *title, const char *extra_header, const char *mime_type, const struct stat *st, char *header_buf)
{
	time_t now;
	char timebuf[64];
	int len = 0;

	now = time(NULL);
	strftime(timebuf, sizeof(timebuf), RFC1123FMT, localtime(&now));

	len += sprintf(header_buf + len, "%s %d %s\r\n", PROTOCOL_VERSION, status, title );
	len += sprintf(header_buf + len, "Server: %s\r\n", SERVICE_NAME);
	len += sprintf(header_buf + len, "Date: %s\r\n", timebuf );
	if (extra_header) {
		len += sprintf(header_buf + len, "%s\r\n", extra_header);
	} else if(st) {
		now += CACHE_AGE_VAL;
		strftime(timebuf, sizeof(timebuf), RFC1123FMT, localtime(&now));
		len += sprintf(header_buf + len, "Cache-Control: max-age=%u\r\n", CACHE_AGE_VAL );
		len += sprintf(header_buf + len, "Expires: %s\r\n", timebuf );
		if(st->st_mtime != 0) {
			now = st->st_mtime;
			strftime(timebuf, sizeof(timebuf), RFC1123FMT, localtime(&now));
			len += sprintf(header_buf + len, "Last-Modified: %s\r\n", timebuf );
		}
		if (st->st_size > 0)
			len += sprintf(header_buf + len, "Content-Length: %lu\r\n", st->st_size );
	}
	if (mime_type)
		len += sprintf(header_buf + len, "Content-Type: %s\r\n", mime_type );
	len += sprintf(header_buf + len, "Connection: close\r\n" );
	len += sprintf(header_buf + len, "\r\n");

	DBG(("%s %d: len=%d", __FUNCTION__, __LINE__, len));
	return len;
}

void send_redirect_async(const char *path, struct conn *c)
{
	char header_buf[2048];
	char extra_header[512];

	snprintf(extra_header, sizeof(extra_header), "Content-Length: 3\r\nLocation: %s\r\n%s", path, no_cache_IE);
	make_headers(302, "Found", extra_header, "text/html", NULL, header_buf);

	io_clear(&c->loc.io);
	c->loc.io.head = _shttpd_snprintf(c->loc.io.buf, c->loc.io.size,
		"%s"
		"302",
		header_buf);
	c->loc.content_len = 3;
	c->status = 302;
	_shttpd_stop_stream(&c->loc);

	DBG(("%s %d: Redirect %s", __FUNCTION__, __LINE__, path));
}

void send_error_async(int status, const char *title, const char *extra_header, const char *text, struct conn *c)
{
	char header_buf[2048];
	char body_buf[512];
	char new_extra_header[1024];
	int header_len = 0, body_len = 0, extra_header_len = 0;

	body_len += sprintf(body_buf + body_len, "<HTML><HEAD><TITLE>%d %s</TITLE></HEAD>\n<BODY BGCOLOR=\"#cc9999\"><H4>%d %s</H4>\n", status, title, status, title);
	body_len += sprintf(body_buf + body_len, "%s\n", text);
	body_len += sprintf(body_buf + body_len, "</BODY></HTML>\n");

	if(extra_header)
		extra_header_len += sprintf(new_extra_header + extra_header_len, "Content-Length: %d\r\n%s", body_len, extra_header);
	else
		extra_header_len += sprintf(new_extra_header + extra_header_len, "Content-Length: %d", body_len);

	header_len += make_headers(status, title, new_extra_header, "text/html", NULL, header_buf);

	io_clear(&c->loc.io);
	c->loc.io.head = _shttpd_snprintf(c->loc.io.buf, c->loc.io.size,
		"%s"
		"%s",
		header_buf, body_buf);
	c->loc.content_len = body_len;
	c->status = status;
	_shttpd_stop_stream(&c->loc);
}

void send_headers_sync(int status, const char *title, const char *extra_header, const char *mime_type, const struct stat *st, FILE *conn_fp)
{
	time_t now;
	char timebuf[64];

	now = time(NULL);
	strftime(timebuf, sizeof(timebuf), RFC1123FMT, localtime(&now));

	fprintf(conn_fp, "%s %d %s\r\n", PROTOCOL_VERSION, status, title);
	fprintf(conn_fp, "Server: %s\r\n", SERVICE_NAME);
	fprintf(conn_fp, "Date: %s\r\n", timebuf);
	if (extra_header) {
		fprintf(conn_fp, "%s\r\n", extra_header);
	} else if (st) {
		now += CACHE_AGE_VAL;
		strftime(timebuf, sizeof(timebuf), RFC1123FMT, localtime(&now));
		fprintf(conn_fp, "Cache-Control: max-age=%u\r\n", CACHE_AGE_VAL);
		fprintf(conn_fp, "Expires: %s\r\n", timebuf );
		if (st->st_mtime != 0) {
			now = st->st_mtime;
			strftime(timebuf, sizeof(timebuf), RFC1123FMT, localtime(&now));
			fprintf(conn_fp, "Last-Modified: %s\r\n", timebuf);
		}
		if (st->st_size > 0)
			fprintf(conn_fp, "Content-Length: %lu\r\n", st->st_size);
	}
	if (mime_type)
		fprintf(conn_fp, "Content-Type: %s\r\n", mime_type);
	fprintf(conn_fp, "Connection: close\r\n");
	fprintf(conn_fp, "\r\n");
}

void send_redirect_sync(const char *path, FILE *conn_fp)
{
	char s[512];

	snprintf(s, sizeof(s), "Location: %s\r\n%s", path, no_cache_IE);
	send_headers_sync(302, "Found", s, "text/html", NULL, conn_fp);
	fprintf(conn_fp, "%s", s);

	DBG(("%s %d: Redirect %s", __FUNCTION__, __LINE__, path));
}

void send_error_sync(int status, const char *title, const char *extra_header, const char *text, FILE *conn_fp)
{
	send_headers_sync(status, title, extra_header, "text/html", NULL, conn_fp );
	fprintf( conn_fp, "<HTML><HEAD><TITLE>%d %s</TITLE></HEAD>\n<BODY BGCOLOR=\"#cc9999\"><H4>%d %s</H4>\n", status, title, status, title );
	fprintf( conn_fp, "%s\n", text );
	fprintf( conn_fp, "</BODY></HTML>\n" );
	fflush( conn_fp );
}

void send_upload_error_sync(FILE *conn_fp)
{
	cJSON *root;
	const char *respond = NULL;

	root=cJSON_CreateObject();
	cJSON_AddStringToObject(root, "upgradeERR","MM_fwupload_error");


	respond= cJSON_Print(root);

	fprintf(conn_fp, "%s", respond);

	cJSON_Delete(root);

	free(respond);
}

struct mime_handler mime_handlers[] = {
	{ "/cgi-bin/cstecgi.cgi",		"application/json",			no_cache_IE,		do_cste,		2 },
	{ "/uploadfile.cgi",			"text/plain",				no_cache_IE,	    do_upload,	    1 },
	{ "**.dat",					    "application/force-download",	            no_cache_IE,		do_file,	    1 },
	{ "**.csr", 					"application/force-download",				no_cache_IE,		do_file,		1 },
	{ "**.pcap",					"application/force-download",	            no_cache_IE,		do_file,	    1 },
	{ "**.web",					    "application/force-download",	            no_cache_IE,		do_file,	    0 },

#if !defined(NO_CGI)
	/* 支持在cgi-bin目录下执行shell */
	{ "/cgi-bin/*",		NULL,		no_cache_IE,	do_cgi_bin,				1 },	//mime_type是shell程序自己决定的
#endif /* !NO_CGI */

	/* Register URI for file upload */
	{ "/show_post",					"text/plain",				no_cache_IE,	register_show_post,	1 },

	/* download syslog */
	{ "syslog.txt",					"application/force-download",	syslog_txt,		do_syslog_file,	1 },
	{ "**.log", 					"application/force-download", "Content-Disposition:attachment;filename=Syslog.tar.gz",  do_syslog_file, 1 },
	/* cached font */
	{ "**.ttf", 					"application/font-sfnt", 		NULL, 			do_file, 		0 },
	{ "**.otf", 					"application/font-sfnt", 		NULL, 			do_file, 		0 },
	{ "**.woff", 					"application/font-woff", 		NULL, 			do_file, 		0 },
	{ "**.woff2", 					"application/font-woff2", 		NULL, 			do_file, 		0 },
	{ "**.eot", 					"application/vnd.ms-fontobject", NULL, 			do_file, 		0 },


	/* cached css and images */
	{ "**.css",						"text/css",						NULL,			do_file,		0 },
	{ "**.png",						"image/png",					NULL,			do_file,		0 },
	{ "**.gif",						"image/gif",					NULL,			do_file,		0 },
	{ "**.jpg|**.jpeg",				"image/jpeg",					NULL,			do_file,		0 },
	{ "**.ico",						"image/x-icon",					NULL,			do_file,		0 },
	{ "**.svg",						"image/svg+xml",				NULL,			do_file,		0 },

	/* cached json */
	{ "**.json",					"text/json",					NULL,			do_file,		0 },

	/* cached txt */
	{ "**.txt",						"text/plain",					NULL,			do_file,		0 },

#if 0
	//todo: used of swrt ui
	/* logout */
	{ "/logout.asp|/formLogoutAll.htm",		"text/html",	 no_cache_IE,	do_logout,		0 },
#endif
	/* no-cached html files with translations */
	{ "**.htm|**.html",				"text/html",	 no_cache_IE,	do_file,		0 },
	
	/* no-cached javascript files with translations */
	{ "**.js",						"text/javascript",				NULL,	do_file,		0 },

	{ NULL, NULL, NULL, do_register, 1 }			//默认都是need_auth
};
	
void
do_fwrite(const char *buffer, int len, FILE *conn_fp)
{
	int n = len;
	int r = 0;

	while (n > 0) {
		r = fwrite(buffer, 1, n, conn_fp);

		if ((r == 0) && (errno != EINTR))
			return -1;

		buffer += r;
		n -= r;
	}

	return r;
}

void
saveSystemSetting_do_file(FILE *conn_fp)
{
	char csid[16]={0}, data[16]={0}, buf[1025];
	char filename[64]={0}, cmd_line[128] = {0}, d_filename[128]={0};
	
	Uci_Get_Str(PKG_PRODUCT_CONFIG, "custom", "csid", csid);
	get_cmd_result("date  '+%Y%m%d'", data, sizeof(data));
	
	snprintf(filename, sizeof(filename), "Config-%s-%s.dat", csid, data);
	
#if 1
	sprintf(d_filename, "/web/%s", filename);

#if defined(CONFIG_CS_COMMON_SSL)
	char input[65536]={0},output[65536]={0}, file_in[64]={0}, file_out[64]={0};
	int len=0;
	snprintf(cmd_line, sizeof(cmd_line), "sysupgrade --create-backup /tmp/%s >/dev/null 2>&1", filename);
	CsteSystem(cmd_line, CSTE_PRINT_CMD);

	sleep(1);
	sprintf(file_in, "/tmp/%s",filename);
	len=f_read(file_in, input, sizeof(input));
	aes_encrypt_pkcs5pading(input, len, csid, (unsigned char *)SSL_IV, \
		output, sizeof(output));
	sprintf(file_out, "/web/%s",filename);
	f_write(file_out, output, strlen(output), 0, 0);
#else
	if(f_exists("/usr/bin/openssl")){
		snprintf(cmd_line, sizeof(cmd_line), "sysupgrade --create-backup /tmp/%s >/dev/null 2>&1", filename);
		CsteSystem(cmd_line, CSTE_PRINT_CMD);

		sleep(1);
		snprintf(cmd_line, sizeof(cmd_line), "openssl des3 -salt -k %s -in /tmp/%s  -out /web/%s", csid, filename, filename);
		CsteSystem(cmd_line, CSTE_PRINT_CMD);
	}else{
		snprintf(cmd_line, sizeof(cmd_line), "sysupgrade --create-backup /web/%s >/dev/null 2>&1", filename);
		CsteSystem(cmd_line, CSTE_PRINT_CMD);
	}
#endif

#else
	sprintf(d_filename, "/tmp/%s", filename);
	doSystem("sysupgrade --create-backup %s",d_filename);
#endif
	fprintf(conn_fp, "HTTP/1.1 200 OK\r\n");
	fprintf(conn_fp, "Pragma: no-cache\r\n");
	fprintf(conn_fp, "Cache-control: no-cache\r\n");
	fprintf(conn_fp, "Content-type: application/octet-stream\r\n");
	fprintf(conn_fp, "Content-Transfer-Encoding: binary\r\n");
	fprintf(conn_fp, "Content-Disposition: inline; filename=\"%s\"\r\n", filename);
	fprintf(conn_fp, "\r\n");
	
#if 1
	int nr;
	FILE *fp;
	memset(buf, '\0', sizeof(buf));
	if ((fp = fopen(d_filename, "r")) != NULL) {
		while ((nr = fread(buf, 1, 1024, fp)) > 0){
			do_fwrite(buf, nr, conn_fp);
		}
		fclose(fp);
	}
#endif

}

/*------------[[sslvpn start]]---------*/
#define STORAGE_SSLVPN_DIR	"/etc/storage/sdfssl"

int write_to_file(const char *path, const char *data) {
    FILE *file = fopen(path, "w+"); 
    if (file == NULL) {
        dbg("Error opening file");
        return -1;
    }

    size_t len = strlen(data);
    size_t bytes_written = fwrite(data, 1, len, file); 
    fclose(file);

    if (bytes_written != len) {
        dbg("Error writing to file");
        return -1;
    }

    return bytes_written;
}

int uploadSslVpnCert(struct post_arg *arg, FILE *conn_fp)
{
	struct conn *c = arg->conn;
	
	int head_offset=0, content_len=0, len=0;
	
	int length=arg->body_buf_len;
	
	char file_name[32]={0}, tmp_buf[64]={0}, head_str[32]={0};
	char *ptr, *p_data;

	int i=0;
	
	get_nth_val_safe(2, c->query, '&', tmp_buf, sizeof(tmp_buf));
	get_nth_val_safe(1, tmp_buf, '=', file_name, sizeof(file_name));


	//dbg("arg->body_buf=%s\n", arg->body_buf);

	
	//dbg("%s\n",file_name);
		
	if((ptr = strstr(arg->body_buf, "Content-Type")) != NULL){
		strncpy(head_str, arg->body_buf, 30);
	
		//去掉http 头
		head_offset = (ptr-arg->body_buf);
		
		if((p_data = strstr(arg->body_buf+head_offset, "\r\n"))!=NULL){
			head_offset = (p_data - arg->body_buf);
			len=length-head_offset;
			for(i=0; i < len; i++){
				if(memcmp(p_data, "\r\n", strlen("\r\n")) == 0){
					p_data += strlen("\r\n");
					head_offset += strlen("\r\n");
				}else{
					break;
				}
			}
		}else{
			dbg("upload err !\n");
			return 0;
		}
		
		//计算http 尾部长度
		if((ptr=strstr(arg->body_buf+head_offset, head_str)) != NULL){
			content_len = ptr - p_data - strlen("\r\n");
		}else{
			content_len = length - head_offset;
		}

		
		if(!d_exists(SSL_CERT_PATH)){
			doSystem("mkdir -p %s",SSL_CERT_PATH);
		}
			
		snprintf(tmp_buf, sizeof(tmp_buf)-1, "%s/%s",SSL_CERT_PATH, file_name);
		
		len = f_write(tmp_buf, p_data, content_len, 0, 0);
		
		
		return len;
		
	}
	
		return 0;
}

/*-------------[[sslvpn end]]----------*/


int uploadOpenVpnCert(struct post_arg *arg, FILE *conn_fp)
{
	struct conn *c = arg->conn;
	
	int head_offset=0, content_len=0, len=0;
	
	int length=arg->body_buf_len;
	
	char file_name[32]={0},  head_str[32]={0};
	char cmd_buf[CMD_STR_LEN] = {0},tmp_buf[TEMP_STR_LEN] = {0};
	char *ptr, *p_data;
	DIR *dir = NULL;
	
	cJSON *root,*opvnObj;
	char  *output;
	FILE *opvnfp = NULL;
	struct dirent *entry; 
	struct stat opvnst;
	struct dirent *opvnent;
	char *opvnname,*buffer;
	char remote_port[OPTION_STR_LEN]={0},tmpBuf[OPTION_STR_LEN]={0};
	char script_security[OPTION_STR_LEN]={0},remote[OPTION_STR_LEN]={0},port[OPTION_STR_LEN]={0},proto[OPTION_STR_LEN]={0};
	char mtu[OPTION_STR_LEN]={0},dev[OPTION_STR_LEN]={0},comp_lzo[OPTION_STR_LEN]={0},cipher[OPTION_STR_LEN]={0},username[OPTION_STR_LEN]={0},password[OPTION_STR_LEN]={0};
	
	int i=0;
	int opvnf;
	get_nth_val_safe(3, c->query, '&', tmp_buf, sizeof(tmp_buf));
	get_nth_val_safe(1, tmp_buf, '=', file_name, sizeof(file_name));

	if((ptr = strstr(arg->body_buf, "Content-Type")) != NULL){
		strncpy(head_str, arg->body_buf, 30);
	
		//去掉http 头
		head_offset = (ptr-arg->body_buf);
		
		if((p_data = strstr(arg->body_buf+head_offset, "\r\n"))!=NULL){
			head_offset = (p_data - arg->body_buf);
			len=length-head_offset;
			for(i=0; i < len; i++){
				if(memcmp(p_data, "\r\n", strlen("\r\n")) == 0){
					p_data += strlen("\r\n");
					head_offset += strlen("\r\n");
				}else{
					break;
				}
			}
		}else{
			dbg("upload err !\n");
			return 0;
		}
		
		//计算http 尾部长度
		if((ptr=strstr(arg->body_buf+head_offset, head_str)) != NULL){
			content_len = ptr - p_data - strlen("\r\n");
		}else{
			content_len = length - head_offset;
		}

		if(!d_exists(OPENVPN_CLIENT_TMP_DIR)){
			doSystem("mkdir -p %s",OPENVPN_CLIENT_TMP_DIR);
		}
		if(strcmp(file_name,"confgz")==0){
			snprintf(tmp_buf, sizeof(tmp_buf)-1, "%s/%s",OPENVPN_CLIENT_TMP_DIR, file_name);
			len = f_write(tmp_buf, p_data, content_len, 0, 0);
			snprintf(cmd_buf,CMD_STR_LEN,"tar -zxf %s -C %s",tmp_buf,OPENVPN_CLIENT_DIR);
			CsteSystem(cmd_buf,CSTE_PRINT_CMD);
			
			if((dir = opendir(OPENVPN_CLIENT_DIR))==NULL) 
			{ 
				goto err;
			} 
			else 
			{ 
				while((opvnent=readdir(dir)) != NULL)
				{
					if(!strstr(opvnent->d_name,".ovpn"))
						continue;
					opvnname = (char *)malloc(sizeof(char)*FILE_DIR_LEN);
					memset(opvnname,'\0',sizeof(char)*FILE_DIR_LEN);
					strcpy(opvnname,OPENVPN_CLIENT_DIR);
					strcat(opvnname,"/");
					strcat(opvnname,opvnent->d_name);
								
					opvnf=stat(opvnname,&opvnst);
					if(opvnf != -1)
					{
						opvnfp = fopen(opvnname, "r+");
						if(!opvnfp){
							free(opvnname);
							continue;
						}
						buffer = (char *)malloc(sizeof(char)*opvnst.st_size+1);
						memset(buffer,'\0',sizeof(char)*opvnst.st_size+1);
						fread(buffer,opvnst.st_size,1,opvnfp);
						fclose(opvnfp);
						opvnObj = cJSON_Parse(buffer);
						if(!opvnObj){
							free(opvnname);
							free(buffer);
							goto err;
						}
						get_cjson_string(opvnObj, "script_security",	script_security, sizeof(script_security));
						get_cjson_string(opvnObj, "remote",	remote, sizeof(remote));
						get_cjson_string(opvnObj, "port",	port, sizeof(port));
						get_cjson_string(opvnObj, "proto",	proto, sizeof(proto));
						get_cjson_string(opvnObj, "dev",	dev, sizeof(dev));
						get_cjson_string(opvnObj, "comp-lzo",	comp_lzo, sizeof(comp_lzo));
						get_cjson_string(opvnObj, "cipher",	cipher, sizeof(cipher));
						get_cjson_string(opvnObj, "mtu",	mtu, sizeof(mtu));
						get_cjson_string(opvnObj, "username",	username, sizeof(username));
						get_cjson_string(opvnObj, "password",	password, sizeof(password));
						
	
						snprintf(remote_port,OPTION_STR_LEN,"%s %s",remote,port);	
						Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","enabled","1");
						Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","remote",remote_port);
						Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","proto",proto);
						Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","dev",dev);				
						Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","comp_lzo",comp_lzo);
						Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","cipher",cipher);
						Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","mtu",mtu);
						Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","script_security",script_security);
						Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","username",username);
						Uci_Set_Str(PKG_OPENVPND_CONFIG,"client","password",password);
						
						Uci_Commit(PKG_OPENVPND_CONFIG);
						free(buffer);
							
						if(strcmp(script_security,"3")==0 || strcmp(script_security,"2")==0){	
							snprintf(cmd_buf,CMD_STR_LEN,"cp -rf %s/%s.crt %s/client.crt",OPENVPN_CLIENT_DIR,username,OPENVPN_CLIENT_DIR);
							CsteSystem(cmd_buf,CSTE_PRINT_CMD);

							snprintf(cmd_buf,CMD_STR_LEN,"cp -rf %s/%s.key %s/client.key",OPENVPN_CLIENT_DIR,username,OPENVPN_CLIENT_DIR);
							CsteSystem(cmd_buf,CSTE_PRINT_CMD);

							snprintf(cmd_buf,CMD_STR_LEN,"rm -rf %s/%s.*",OPENVPN_CLIENT_DIR,username);
							CsteSystem(cmd_buf,CSTE_PRINT_CMD);

							snprintf(cmd_buf,CMD_STR_LEN,"rm -rf %s/*",OPENVPN_CLIENT_TMP_DIR);
							CsteSystem(cmd_buf,CSTE_PRINT_CMD);
						}
						cJSON_Delete(opvnObj);
						set_lktos_effect("openvpnc");
					}
					free(opvnname);
				}
				closedir(dir);
				
				return len;
			} 
		}else {
			if(strcmp(file_name,"ca.crt")==0){
				Uci_Get_Str(PKG_OPENVPND_CONFIG,"client","ca",tmp_buf);
			}else if(strcmp(file_name,"client.crt")==0){
				Uci_Get_Str(PKG_OPENVPND_CONFIG,"client","cert",tmp_buf);
			}else if(strcmp(file_name,"client.key")==0){
				Uci_Get_Str(PKG_OPENVPND_CONFIG,"client","key",tmp_buf);
			}else if(strcmp(file_name,"ta.key")==0){
				snprintf(tmp_buf,TEMP_STR_LEN,OPENVPN_CLIENT_DIR"/ta.key");
			}
			
			snprintf(cmd_buf,CMD_STR_LEN,"rm -rf %s/%s.*",OPENVPN_CLIENT_DIR,username);
			CsteSystem(cmd_buf,CSTE_PRINT_CMD);
			
			len = f_write(tmp_buf, p_data, content_len, 0, 0);
		}			
		return len;
		
	}
err:	
		return 0;
}

//query="/downloadfile.cgi?topic=DownloadWireguardConfig&peer0"
void export_wireguard_config(char *query, FILE *conn_fp)
{
	FILE *fp;
	char section[8]={0}, date[16]={0}, file_name[32]={0};
	char tmp_buf[1024]={0}, ip[64]={0}, listen_port[8]={0};
	char cmd[32]={0}, host[64]={0}, port[8]={0}, file[32]={0};
	
	get_nth_val_safe(1, query, '&', section, sizeof(section));
	get_nth_val_safe(2, query, '&', ip, sizeof(ip));
	get_nth_val_safe(3, query, '&', host, sizeof(host));
	
	get_cmd_result("date '+%Y%m%d'", date, sizeof(date));

	snprintf(file_name, sizeof(file_name), "wg-%s-%s.conf", section, (date+2));

	snprintf(file, sizeof(file)-1, "/tmp/%s", file_name);
	
	fp=fopen(file, "w");

	if(fp){
		fprintf(fp, "[Interface]\n");
		
		memset(tmp_buf, 0, sizeof(tmp_buf));
		Uci_Get_Str(PKG_NETWORK_CONFIG, section, "private_key", tmp_buf);
		if(strlen(tmp_buf) == 44)
			fprintf(fp, "PrivateKey=%s\n", tmp_buf);
		else
			goto err;

		if(strcmp(ip, "") != 0)
			fprintf(fp, "Address=%s\n", ip);

		if(atoi(listen_port) > 0)
			fprintf(fp, "ListenPort=%s\n", listen_port);

		//Peer
		fprintf(fp, "[Peer]\n");

		memset(tmp_buf, 0, sizeof(tmp_buf));
		Uci_Get_Str(PKG_NETWORK_CONFIG, "wg0", "private_key", tmp_buf);
		if(strlen(tmp_buf) != 44)
			goto err;
		
		f_write_string("/tmp/wg_pri_key", tmp_buf, 0, 0);
		snprintf(cmd, sizeof(cmd)-1, "wg pubkey < %s", "/tmp/wg_pri_key");
		
		memset(tmp_buf, 0, sizeof(tmp_buf));
		get_cmd_result(cmd, tmp_buf, sizeof(tmp_buf));
		fprintf(fp, "PublicKey=%s\n", tmp_buf);

		memset(tmp_buf, 0, sizeof(tmp_buf));
		Uci_Get_Str(PKG_NETWORK_CONFIG, section, "preshared_key", tmp_buf);
		if(strcmp(tmp_buf, "") != 0)
			fprintf(fp, "PresharedKey=%s\n", tmp_buf);
		
		memset(tmp_buf, 0, sizeof(tmp_buf));
		Uci_Get_Str(PKG_NETWORK_CONFIG, "wg0", "listen_port", port);
		if(strcmp(host, "") != 0){
			sprintf(tmp_buf, "%s", host);
			fprintf(fp, "Endpoint=%s:%s\n", tmp_buf, port);
		}
#if 1
		memset(ip, 0, sizeof(ip));
		Uci_Get_Str(PKG_NETWORK_CONFIG, "lan", "ipaddr", ip);
		memset(tmp_buf, 0, sizeof(tmp_buf));
		Uci_Get_Str(PKG_NETWORK_CONFIG, "lan", "netmask", tmp_buf);
		int net_len = netmask_to_bits(tmp_buf);
		get_ip_network_num(ip, tmp_buf);
				
		fprintf(fp, "AllowedIPs=%s/%d\n", tmp_buf, net_len);
#else		
		fprintf(fp, "AllowedIPs=0.0.0.0/0\n");
#endif
		
		fclose(fp);
	}
	
	fprintf(conn_fp, "HTTP/1.1 200 OK\r\n");
	fprintf(conn_fp, "Pragma: no-cache\r\n");
	fprintf(conn_fp, "Cache-control: no-cache\r\n");
	fprintf(conn_fp, "Content-type: application/octet-stream\r\n");
	fprintf(conn_fp, "Content-Transfer-Encoding: binary\r\n");
	fprintf(conn_fp, "Content-Disposition: inline; filename=\"%s\"\r\n", file_name);
	fprintf(conn_fp, "\r\n");
	
	int nr;
	FILE *fd;
	memset(tmp_buf, '\0', sizeof(tmp_buf));
	if ((fd = fopen(file, "r")) != NULL) {
		while ((nr = fread(tmp_buf, 1, 1024, fd)) > 0){
			do_fwrite(tmp_buf, nr, conn_fp);
		}
		fclose(fd);
	}

	return ;
	
err:
	
	fclose(fp);
	return ;
}


static void
handle_post_cste_cgi(struct post_arg *arg, FILE *conn_fp)
{
	struct conn *c = arg->conn;
	struct mime_handler *handler = arg->handler;
	PersonalData *priv_data;
	char *client_ip, err_msg[128]={0};
	int ret=0;
	int no_send_headers = 0;
	char tmp_topic[64]={0};
	
	//dbg("xxxx------------%s\n",c->request);
	//dbg("xxxx------------%s\n",c->headers);
	if(c->query && strstr(c->query, "action=upload")){
		getNthValueSafe(1, c->query, '&', tmp_topic, sizeof(tmp_topic));
		
		if(strcmp(tmp_topic, "uploadSslVpnCert") == 0){

			int rel=uploadSslVpnCert(arg,conn_fp);
			
			if(rel > 0){
				send_headers_sync(200, "OK", handler->extra_header, handler->mime_type, NULL, conn_fp);
				send_check_auth_respond(rel, "OK", conn_fp);
			}else{
				send_headers_sync(200, "OK", handler->extra_header, handler->mime_type, NULL, conn_fp);
				send_check_auth_respond(rel, "NOK", conn_fp);
			}
			
			return;
		}else if(strcmp(tmp_topic, "uploadOpenVpnCert") == 0){

			int rel=uploadOpenVpnCert(arg,conn_fp);
			
			if(rel > 0){
				send_headers_sync(200, "OK", handler->extra_header, handler->mime_type, NULL, conn_fp);
				send_check_auth_respond(rel, "OK", conn_fp);
			}else{
				send_headers_sync(200, "OK", handler->extra_header, handler->mime_type, NULL, conn_fp);
				send_check_auth_respond(rel, "NOK", conn_fp);
			}
			
			return;
		}
		
	}
	
	if(c->query && strstr(c->query,"action=DownloadWireguardConfig") != NULL){
		export_wireguard_config(c->query, conn_fp);
		return;
	}
		
	if(c->query && strstr(c->query,"action=ExportSettings") !=NULL){
		saveSystemSetting_do_file(conn_fp);
		
		return;
	}

	if(c->query && strstr(c->query, "action=saveSettingCfg") != NULL){
		saveSystemSetting_do_file(conn_fp);
		return;
	}
	
#if defined(CONFIG_KL_OPNSENSE_DTU)
	 if(c->query && strstr(c->query, "action=setSslVpnCertCfg") != NULL){
		priv_data=do_SaveSslvpnCert("setSslVpnCertCfg");
		no_send_headers = 1;
	}else	
#endif
		priv_data = json_to_topic(arg->body_buf);			//解析post_buf获取topic
	
	if(priv_data == NULL) {

		send_headers_sync(200, "OK", handler->extra_header, handler->mime_type, NULL, conn_fp);

		send_check_auth_respond(0, "{}", conn_fp);
		return;
	}

	if(c->query && strstr(c->query,"t=app") !=NULL){
		char code[128]={0},app_bind[128]={0};
	
		get_query_param(c->query, "p", code, sizeof(code));
		
		Uci_Get_Str(PKG_SYSTEM_CONFIG,"crpc","app_bind",app_bind);
	
		if(strcmp(app_bind,code)==0){
			send_headers_sync(200, "OK", handler->extra_header, handler->mime_type, NULL, conn_fp);
			ret=priv_data->p_tab->fun(priv_data->request_obj, conn_fp);
			goto app;
		}
	
	}
#if defined(SESSION_AUTH)
	if(priv_data->p_tab->need_auth) {
		ret=check_auth_login(c,err_msg,sizeof(err_msg));
	
		if(ret<0){
			free_priv_data(priv_data);

			send_headers_sync(200, "OK", handler->extra_header, handler->mime_type, NULL, conn_fp);

			send_check_auth_respond(ret, err_msg, conn_fp);

			return; 
		}
	}
#endif
	
	if(no_send_headers==0)
		send_headers_sync(200, "OK", handler->extra_header, handler->mime_type, NULL, conn_fp);

	ret=priv_data->p_tab->fun(priv_data->request_obj, conn_fp);

#if defined(SESSION_AUTH)
	if(CGI_TRUE ==ret && strcmp(priv_data->p_tab->topicurl,"loginAuth")==0){
		client_ip = inet_ntoa(* (struct in_addr *) &c->sa.u.sin.sin_addr.s_addr);
		update_login_data(client_ip);
	}
#endif
app:
	free_priv_data(priv_data);
}

void
do_cste(struct conn *c, struct mime_handler *handler)
{
	shttpd_do_post(c, handler, handle_post_cste_cgi);
}


//--------------------------------------
void *memmem(const void *buf, size_t buf_len, const void *byte_line, size_t byte_line_len)
{
    unsigned char *bl = (unsigned char *)byte_line;
    unsigned char *bf = (unsigned char *)buf;
    unsigned char *p  = bf;

    while (byte_line_len <= (buf_len - (p - bf))){
        unsigned int b = *bl & 0xff;
        if ((p = (unsigned char *) memchr(p, b, buf_len - (p - bf))) != NULL){
            if ( (memcmp(p, byte_line, byte_line_len)) == 0)
                return p;
            else
                p++;
        }else{
            break;
        }
    }
    return NULL;
}

#define MEM_SIZE	1024
#define MEM_HALT	512
static int find_str_infile(char *filename, int offset, unsigned char *str, int str_len)
 {
	 int pos = 0, rc;
	 FILE *fp;
	 unsigned char mem[MEM_SIZE];
	 if(str_len > MEM_HALT)
		 return -1;
	 if(offset <0)
		 return -1;

	 fp = fopen(filename, "rb");
	 if(!fp)
		 return -1;
	 rewind(fp);
	 fseek(fp, offset + pos, SEEK_SET);
	 rc = fread(mem, 1, MEM_SIZE, fp);
	 while(rc){
		 unsigned char *mem_offset;
		 mem_offset = (unsigned char*)memmem(mem, rc, str, str_len);
		 if(mem_offset){
			 fclose(fp); //found it
			 return (mem_offset - mem) + pos + offset;
		 }
		 if(rc == MEM_SIZE){
			 pos += MEM_HALT;	 // 8
		 }else{
			 break;
		 }

		 rewind(fp);
		 fseek(fp, offset+pos, SEEK_SET);
		 rc = fread(mem, 1, MEM_SIZE, fp);
	 }

	 fclose(fp);
	 return -1;
 }

 static void *get_mem_infile(char *filename, int offset, int len)
 {
	 void *result;
	 FILE *fp;
	 if( (fp = fopen(filename, "r")) == NULL ){
		 return NULL;
	 }
	 fseek(fp, offset, SEEK_SET);
	 result = malloc(sizeof(unsigned char) * len );
	 if(!result){
		 fclose(fp);
		 return NULL;
	 }
	 if( fread(result, 1, len, fp) != len){
		 fclose(fp);
		 free(result);
		 result=NULL;
		 return NULL;
	 }
	 fclose(fp);
	 return result;
 }

long delete_upload_file_httphead(char *upload_file)
{
	int file_begin, file_end;
	int line_begin, line_end;
	char *boundary; int boundary_len;
	long flle_len;

	line_begin = 0;
	if((line_end = find_str_infile(upload_file, line_begin, "\r\n", 2)) == -1){	
		return -1;
	}
	boundary_len = line_end - line_begin;
	boundary = get_mem_infile(upload_file, line_begin, boundary_len);

	// sth like this..
	// Content-Disposition: form-data; name="filename"; filename="\\192.168.3.171\tftpboot\a.out"
	//
	char *line, *semicolon, *user_filename;
	line_begin = line_end + 2;
	if((line_end = find_str_infile(upload_file, line_begin, "\r\n", 2)) == -1){
		free(boundary);
		return -1;
	}
	line = get_mem_infile(upload_file, line_begin, line_end - line_begin);
	if(strncasecmp(line, "content-disposition: form-data;", strlen("content-disposition: form-data;"))){
		free(boundary);
		free(line);
		return -1;
	}
	semicolon = line + strlen("content-disposition: form-data;") + 1;
	if(! (semicolon = strchr(semicolon, ';'))  ){
		free(boundary);
		free(line);
		return -1;
	}
	user_filename = semicolon + 2;
	if( strncasecmp(user_filename, "filename=", strlen("filename=")) ){
		free(boundary);
		free(line);
		return -1;
	}
	user_filename += strlen("filename=");

	//get_nth_val_safe(1, user_filename, '"', fwName, FILE_DIR_LEN);

	free(line);
	line_begin = line_end + 2;
	if((line_end = find_str_infile(upload_file, line_begin, "\r\n", 2)) == -1){
		free(boundary);
		return -1;
	}

	line_begin = line_end + 2;
	if((line_end = find_str_infile(upload_file, line_begin, "\r\n", 2)) == -1){
		free(boundary);
		return -1;
	}

	file_begin = line_end + 2;
	if( (file_end = find_str_infile(upload_file, file_begin, boundary, boundary_len)) == -1){
		free(boundary);
		return -1;
	}
	file_end -= 2;		// back 2 chars.(\r\n);

	char *buffer = (char *)malloc(file_end-file_begin);
	flle_len= f_read_offset(upload_file, buffer, file_begin, file_end-file_begin);

	remove(upload_file);

	f_write(FNL_UPLOAD_FILE, buffer, flle_len, FW_CREATE, 0);

	free(buffer);
	free(boundary);

	return flle_len;
}

static void
handle_upload_cste_cgi(struct post_arg *arg, FILE *conn_fp)
{
	struct conn *c = arg->conn;
	struct mime_handler *handler = arg->handler;
	PersonalData *priv_data;

	long content_length;
	cJSON *root;
	char tmp_buf[128];
	char token[40]={0}, topic[128]={0};
	char *pdata;

#if 0
	//sprintf(tmp_buf, "mv %s %s", TMP_UPLOAD_FILE, FNL_UPLOAD_FILE);
	//system(tmp_buf);
	rename(TMP_UPLOAD_FILE, FNL_UPLOAD_FILE);
#else
	content_length=delete_upload_file_httphead(TMP_UPLOAD_FILE);
#endif
	root=cJSON_CreateObject();
	cJSON_AddStringToObject(root, "file_name", FNL_UPLOAD_FILE);

	memset(tmp_buf,0,sizeof(tmp_buf));
	snprintf(tmp_buf,sizeof(tmp_buf),"%ld",content_length);
	cJSON_AddStringToObject(root, "content_length", tmp_buf);

	get_query_param(c->query, "topic", topic,sizeof(topic));
	get_query_param(c->query, "token", token,sizeof(token));

	cJSON_AddStringToObject(root, "topicurl", topic);
	cJSON_AddStringToObject(root, "token", token);

	pdata=cJSON_Print(root);

	priv_data = json_to_topic(pdata);

	cJSON_Delete(root);

	free(pdata);

	send_headers_sync(200, "OK", handler->extra_header, handler->mime_type, NULL, conn_fp);
	
	if(priv_data == NULL) {
		send_upload_error_sync(conn_fp);
		return;
	}

	priv_data->p_tab->fun(priv_data->request_obj, conn_fp);

	free_priv_data(priv_data);

}

void
do_upload(struct conn *c, struct mime_handler *handler)
{
	//clear old upload file
	char cmd_line[256]={0};

	snprintf(cmd_line,sizeof(cmd_line),"rm -f %s",TMP_UPLOAD_FILE);

	system(cmd_line);

	shttpd_do_upload(c, handler, handle_upload_cste_cgi);
	
}
//--------------------------------------

#if !defined(NO_CGI)
void
do_cgi_bin(struct conn *c, struct mime_handler *handler)
{
	char path[URI_MAX];

	(void) _shttpd_snprintf(path, sizeof(path), "%s%s", c->ctx->options[OPT_ROOT], c->uri);

	if(c->method != METHOD_POST && c->method != METHOD_GET) {
		_shttpd_send_server_error(c, 501, "Bad method ");
		return;
	}

	if(_shttpd_match_extension(path, c->ctx->options[OPT_CGI_EXTENSIONS])) {			//默认支持.cgi,.php,.pl后缀
		if ((_shttpd_run_cgi(c, path)) == -1) {
			_shttpd_send_server_error(c, 500, "Cannot exec CGI");
		} else {
			_shttpd_do_cgi(c);
		}
	} else {
		_shttpd_send_server_error(c, 404, "Not Found");
	}
}
#endif /* !NO_CGI */

static void
show_post(struct shttpd_arg *arg)
{
	const char	*s, *file_path = "/tmp/uploaded.txt";
	struct state {
		size_t	cl;		/* Content-Length	*/
		size_t	nread;		/* Number of bytes read	*/
		FILE	*fp;
	} *state;

	/* If the connection was broken prematurely, cleanup */
	if (arg->flags & SHTTPD_CONNECTION_ERROR && arg->state) {
		(void) fclose(((struct state *) arg->state)->fp);
		free(arg->state);
	} else if ((s = shttpd_get_header(arg, "Content-Length")) == NULL) {
		shttpd_printf(arg, "HTTP/1.0 411 Length Required\n\n");
		arg->flags |= SHTTPD_END_OF_OUTPUT;
	} else if (arg->state == NULL) {
		/* New request. Allocate a state structure, and open a file */
		arg->state = state = calloc(1, sizeof(*state));
		state->cl = strtoul(s, NULL, 10);
		state->fp = fopen(file_path, "wb+");
		shttpd_printf(arg, "HTTP/1.0 200 OK\n"
			"Content-Type: text/plain\n\n");
	} else {
		state = arg->state;

		/*
		 * Write the POST data to a file. We do not do any URL
		 * decoding here. File will contain form-urlencoded stuff.
		 */
		(void) fwrite(arg->in.buf, arg->in.len, 1, state->fp);
		state->nread += arg->in.len;

		/* Tell SHTTPD we have processed all data */
		arg->in.num_bytes = arg->in.len;

		/* Data stream finished? Close the file, and free the state */
		if (state->nread >= state->cl) {
			shttpd_printf(arg, "Written %d bytes to %s",
			    state->nread, file_path);
			(void) fclose(state->fp);
			free(state);
			arg->flags |= SHTTPD_END_OF_OUTPUT;
		}
	}
}

void
register_show_post(struct conn *c, struct mime_handler *handler)
{
	struct registered_uri *ruri;

	ruri = _shttpd_is_registered_uri(c->ctx, c->uri);
	if(ruri == NULL)
		ruri = shttpd_register_uri(c->ctx, c->uri, &show_post, NULL);

	if(ruri == NULL) {
		_shttpd_send_server_error(c, 500, "Cannot register uri");
		return;
	}

	_shttpd_setup_embedded_stream(c, ruri->callback, ruri->callback_data);

	dump_registered_uri(c->ctx);
}

void
do_syslog_file(struct conn *c, struct mime_handler *handler)
{
	char path[URI_MAX]={0};
	(void) _shttpd_snprintf(path, sizeof(path), "%s%s", c->ctx->options[OPT_ROOT], c->uri);
	doSystem ("rm -f /web/cgi-bin/ExportSyslog.log");

	doSystem("tar -zcvf /var/ExportSyslog.tar.gz /var/log");

	doSystem("mv  /var/ExportSyslog.tar.gz  /web/cgi-bin/ExportSyslog.log");
	
	do_file(c,handler);
}

void
do_file(struct conn *c, struct mime_handler *handler)
{
	char path[URI_MAX];
	struct stat st;
	char header_buf[2048];

	(void) _shttpd_snprintf(path, sizeof(path), "%s%s", c->ctx->options[OPT_ROOT], c->uri);

	if (stat(path, &st) == 0 && !S_ISDIR(st.st_mode)) {
		if (!handler->extra_header && c->ch.ims.v_time && st.st_mtime <= c->ch.ims.v_time) {
			_shttpd_send_server_error(c, 304, "Not Modified");
			return;
		} else if((c->loc.chan.fd = _shttpd_open(path,O_RDONLY | O_BINARY, 0644)) != -1) {
			make_headers(200, "OK", handler->extra_header, handler->mime_type, &st, header_buf);
		} else {
			_shttpd_send_server_error(c, 500, "Internal Error");
			return;
		}
	} else {
		send_error_async(404, "Not Found", NULL, "URL was not found", c);
		return;
	}

	c->loc.io.head = c->loc.headers_len = _shttpd_snprintf(c->loc.io.buf, c->loc.io.size,
		"%s",
		header_buf);

	c->status = 200;
	c->loc.content_len = (big_int_t)st.st_size;
	c->loc.io_class = &_shttpd_io_file;
	c->loc.flags |= FLAG_R | FLAG_ALWAYS_READY;

	if (c->method == METHOD_HEAD)
		_shttpd_stop_stream(&c->loc);

	DBG(("%s %d: path=%s mime_handler->mime_type=%s st.st_size=%lu", __FUNCTION__, __LINE__, path, handler->mime_type, st.st_size));
}

void
do_register(struct conn *c, struct mime_handler *handler)
{
	struct registered_uri *ruri;
	char password[32] = {0};
	char session_id[64]={0};
	char goURL[128]={0};
	
	if ((ruri = _shttpd_is_registered_uri(c->ctx, c->uri)) != NULL) {
		_shttpd_setup_embedded_stream(c, ruri->callback, ruri->callback_data);
		return;
	} else {
		send_redirect_async("/index.html", c);
		return;
	}
}
