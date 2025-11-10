#include "../defs.h"
#include "cs_firmware.h"
#include "cs_common.h"
#include "md5.h"


void getSysUptime(char *tmpBuf)
{
	unsigned long sec, mn, hr, day;
	long uptime = 0;
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
	sprintf(tmpBuf,"%ld;%ld;%ld;%ld",day,hr,mn,sec);

	return ;
}


int getCurrentTime(char *cur_time)
{
	char buf[OPTION_STR_LEN]={0};
	char *p;
	
	FILE *fp = popen("date", "r");
	if(!fp) return 0;
    
    while(fgets(buf, sizeof(buf), fp) != NULL)
	{
        if(p=strstr(buf, "\n"))
        {
            p[0]='\0';
        }
    }
    pclose(fp);
	strcpy(cur_time,buf);
	
 	return 0;
}


int Validity_check(char *tmpbuf)
{
	if(strstr(tmpbuf, ";")|| strstr(tmpbuf, ".sh") || strstr(tmpbuf, "iptables")\
						  || strstr(tmpbuf, "telnetd") || strstr(tmpbuf, "&") || strstr(tmpbuf, "|")\
						  || strstr(tmpbuf, "`") || strstr(tmpbuf, "$")|| \
	strstr(tmpbuf, "\n"))
	{
		return 1;
	}

	return 0;
}

#define SERVER_NAME		"httpd"
#define PROTOCOL		"HTTP/1.0"

static void
send_headers( int status, const char *title, const char *extra_header, const char *mime_type, const struct stat *st, FILE *conn_fp )
{
	time_t now;
	char timebuf[64];

	now = time(NULL);
	strftime( timebuf, sizeof(timebuf), RFC1123FMT, gmtime( &now ) );

	fprintf( conn_fp, "%s %d %s\r\n", PROTOCOL, status, title );
	fprintf( conn_fp, "Server: %s\r\n", SERVER_NAME );
	fprintf( conn_fp, "Date: %s\r\n", timebuf );

	if (extra_header) {
		fprintf( conn_fp, "%s\r\n", extra_header );
	} else if (st) {
		now += CACHE_AGE_VAL;
		strftime( timebuf, sizeof(timebuf), RFC1123FMT, gmtime( &now ) );
		fprintf( conn_fp, "Cache-Control: max-age=%u\r\n", CACHE_AGE_VAL );
		fprintf( conn_fp, "Expires: %s\r\n", timebuf );

		if (st->st_mtime != 0) {
			now = st->st_mtime;
			strftime( timebuf, sizeof(timebuf), RFC1123FMT, gmtime( &now ) );
			fprintf( conn_fp, "Last-Modified: %s\r\n", timebuf );
		}

		if (st->st_size > 0)
			fprintf( conn_fp, "Content-Length: %lu\r\n", st->st_size );
	}

	if (mime_type)
		fprintf( conn_fp, "Content-Type: %s\r\n", mime_type );

	fprintf( conn_fp, "Connection: close\r\n" );
	fprintf( conn_fp, "\r\n" );
}

CGI_BOOL loginAuth(json_object *request, FILE *conn_fp)
{
	int  login_flag=0;
	char admu[256]={0}, admp[256]={0};
	char s[512], redir[128],sid[32];
	char user_encode[33]={0}, pass_encode[33]={0};
	char goURL[128]={0};
	
	cJSON *root;
	
	char *username = webs_get_string(request, "username");
	char *password = webs_get_string(request, "password");

	Uci_Get_Str(PKG_SYSTEM_CONFIG,"main","password",admp);
	Uci_Get_Str(PKG_SYSTEM_CONFIG,"main","username",admu);

	//encode cfg data
	cal_md5_encode(admu, user_encode);
	cal_md5_encode(admp, pass_encode);
	
	if (strcmp(username, user_encode) || strcmp(password, pass_encode)) {
		login_flag = 1;
	}

	if(login_flag==0)
	{
		datconf_get_by_key(TEMP_STATUS_FILE, "session_id", sid, sizeof(sid));

		strcpy(goURL,"home.html");
		
		strcat(goURL,"?token=");
		strcat(goURL, sid);
	}
	root = cJSON_CreateObject();
	cJSON_AddNumberToObject(root, "loginFlag", login_flag);
	cJSON_AddStringToObject(root, "jump_page", goURL);

	send_cgi_json_respond(conn_fp, root);
	return CGI_TRUE;
}


CGI_BOOL logout(json_object *request, FILE *conn_fp)
{
	generate_session_id();

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

	return CGI_TRUE;
}


CGI_BOOL RebootSystem(json_object *request, FILE *conn_fp)
{
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "65", "reserv");

	set_lktos_effect("reboot");

	return CGI_TRUE;
}

CGI_BOOL LoadDefSettings(json_object *request, FILE *conn_fp)
{
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "65", "reserv");

	set_lktos_effect("restore");

	return CGI_TRUE;
}


CGI_BOOL FirmwareUpgrade(json_object *request, FILE *conn_fp)
{
	char tmp_buf[128] = {0};

	cJSON *root=cJSON_CreateObject();

	memset(tmp_buf,0,sizeof(tmp_buf));
	get_soft_version(tmp_buf,sizeof(tmp_buf));
	cJSON_AddStringToObject(root, "fmVersion", tmp_buf);

	memset(tmp_buf,0,sizeof(tmp_buf));
	Uci_Get_Str(PKG_PRODUCT_CONFIG,"sysinfo","build_time",tmp_buf);
	cJSON_AddStringToObject(root,"buildTime",tmp_buf);

	memset(tmp_buf,0,sizeof(tmp_buf));
	Uci_Get_Str(PKG_PRODUCT_CONFIG,"sysinfo","hard_model",tmp_buf);
	cJSON_AddStringToObject(root,"hardModel", tmp_buf);
#if 0
	cJSON_AddNumberToObject(root,"flashSize",get_flash_total_size());
#else
	cJSON_AddNumberToObject(root,"flashSize",64);
#endif
	memset(tmp_buf,0,sizeof(tmp_buf));
	Uci_Get_Str(PKG_NETWORK_CONFIG, "lan", "ipaddr", tmp_buf);
	cJSON_AddStringToObject(root,"lanIp",tmp_buf);

	cJSON_AddStringToObject(root,"upgradeAction","/uploadfile.cgi?topic=UploadFirmwareFile");
	cJSON_AddStringToObject(root,"setUpgradeFW","1");
	cJSON_AddStringToObject(root,"csteVersion","2.0");

#if	CONFIG_CLOUD_UPGRADE
	cJSON_AddStringToObject(root,"cloudFw","1");
#else
	cJSON_AddStringToObject(root,"cloudFw","0");
#endif

	send_cgi_json_respond(conn_fp, root);

    return CGI_TRUE;
}

CGI_BOOL UploadFirmwareFile(json_object *request, FILE *conn_fp)
{
	int flash_size = 0;
	long con_len = 0;
	char err_msg[256], cmd_buf[128] = { 0 };
	cJSON *root = NULL;
	const char *file_name = webs_get_string(request, "file_name");
	const char *content_length = webs_get_string(request, "content_length");

	root = cJSON_CreateObject();
#if 0
	flash_size = get_flash_total_size();
#else
	flash_size = 64;
#endif

	if(flash_size == 0)
	{
		cJSON_AddStringToObject(root, "upgradeERR", "MM_flashsize_error");
		goto err;
	}

	if(strlen(file_name) == 0)
	{
		cJSON_AddStringToObject(root, "upgradeERR", "MM_fwupload_error");
		goto err;
	}
	con_len = strtol(content_length, NULL, 10);
	if(con_len > flash_size*1024*1024 || con_len < 1 )
	{
		cJSON_AddStringToObject(root, "upgradeERR", "MM_cloud_fw2flash1");
		goto err;
	}

#if 1
	if(firmware_check(file_name, 0, con_len, err_msg, NULL) == 0)
	{
		if(strstr(err_msg, "product_name_error"))
		{
			cJSON_AddStringToObject(root, "upgradeERR", "MM_cloud_fw2flash2");
		}
		else if(strstr(err_msg, "product_svn_error"))
		{
			cJSON_AddStringToObject(root, "upgradeERR", "MM_cloud_fw2flash3");
		}
		else
		{
			cJSON_AddStringToObject(root, "upgradeERR", "MM_cloud_fw2flash1");
		}
		goto err;
	}
#endif

	datconf_set_by_key(TEMP_STATUS_FILE, "firmware", "/tmp/cloudupdate.web");
	datconf_set_by_key(TEMP_STATUS_FILE, "ugrade_firmware", file_name);
	cJSON_AddStringToObject(root, "upgradeStatus", "1");
	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;

err:
	memset(cmd_buf, 0, sizeof(cmd_buf));
	sprintf(cmd_buf, "rm -f %s", file_name);
	CsteSystem(cmd_buf, 0);

	send_cgi_json_respond(conn_fp, root);

	return CGI_FALSE;
}

CGI_BOOL SystemSettings(json_object *request, FILE *conn_fp)
{
	char tmp_buf[TEMP_STR_LEN]={0};

	cJSON *root;

	root = cJSON_CreateObject();

	memset(tmp_buf,0,sizeof(tmp_buf));
	Uci_Get_Str(PKG_PRODUCT_CONFIG,"sysinfo","soft_model",tmp_buf);
	cJSON_AddStringToObject(root,"hardModel",tmp_buf);

	cJSON_AddStringToObject(root,"exportAction", "/cgi-bin/cstecgi.cgi?action=saveSettingCfg");
	cJSON_AddStringToObject(root,"importAction", "/uploadfile.cgi?topic=setUploadSetting");

	cJSON_AddNumberToObject(root,"flashSize",get_flash_total_size());

	Uci_Get_Str(PKG_CSFW_CONFIG,"firewall","hnat_enable",tmp_buf);
	cJSON_AddStringToObject(root,"hnat_enable",tmp_buf);

	memset(tmp_buf,0,sizeof(tmp_buf));
	Uci_Get_Str(PKG_NETWORK_CONFIG, "lan", "ipaddr", tmp_buf);
	cJSON_AddStringToObject(root,"lanIp",tmp_buf);

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}


CGI_BOOL saveSystemSetting(json_object *request, FILE *conn_fp)
{
	cJSON *root;
	char cmd_line[128] = { 0 }, cfg_file_name[128] = { 0 }, model[64] = { 0 }, date_str[24] = { 0 }, key[64] = { 0 };

	Uci_Get_Str(PKG_PRODUCT_CONFIG, "sysinfo", "soft_model", model);
	Uci_Get_Str(PKG_PRODUCT_CONFIG, "custom", "csid", key);

	get_cmd_result("date +%Y%m%d", date_str, sizeof(date_str));
	snprintf(cfg_file_name, sizeof(cfg_file_name), "Config-%s-%s.dat", model, date_str);

#if defined(CONFIG_CS_COMMON_SSL)
		char input[30720]={0},output[30720]={0}, file_in[64]={0}, file_out[64]={0};
		int len=0;
		snprintf(cmd_line, sizeof(cmd_line), "sysupgrade --create-backup /tmp/%s >/dev/null 2>&1", cfg_file_name);
		CsteSystem(cmd_line, CSTE_PRINT_CMD);
	
		sleep(1);
		sprintf(file_in, "/tmp/%s",cfg_file_name);
		len=f_read(file_in, input, sizeof(input));
		aes_encrypt_pkcs5pading(input, len, key, (unsigned char *)SSL_IV, \
			output, sizeof(output));
		sprintf(file_out, "/web/%s",cfg_file_name);
		f_write(file_out, output, strlen(output), 0, 0);
#else

	if(f_exists("/usr/bin/openssl")){
		snprintf(cmd_line, sizeof(cmd_line), "sysupgrade --create-backup /tmp/%s >/dev/null 2>&1", cfg_file_name);
		CsteSystem(cmd_line, CSTE_PRINT_CMD);

		sleep(1);
		snprintf(cmd_line, sizeof(cmd_line), "openssl des3 -salt -k %s -in /tmp/%s  -out /web/%s", key, cfg_file_name, cfg_file_name);
		CsteSystem(cmd_line, CSTE_PRINT_CMD);
	}else{
		snprintf(cmd_line, sizeof(cmd_line), "sysupgrade --create-backup /web/%s >/dev/null 2>&1", cfg_file_name);
		CsteSystem(cmd_line, CSTE_PRINT_CMD);
	}
#endif

#if 1
	char s[512];

	snprintf(s, sizeof(s), "Location: /%s\r\n%s", cfg_file_name, no_cache_IE);
	send_headers_sync(302, "Found", s, "text/html", NULL, conn_fp);
	
	fprintf(conn_fp, "%s", s);
#else
	root = cJSON_CreateObject();
	cJSON_AddStringToObject(root, "url", cfg_file_name);

	send_cgi_json_respond(conn_fp, root);
#endif
	return CGI_TRUE;
}

CGI_BOOL getDiagnosisCfg(json_object *request, FILE *conn_fp)
{
	cJSON *root = cJSON_CreateObject();
	char pingLog[LONGLONG_BUFF_LEN] = {0};

	f_read("/tmp/NetworkDiagnose", pingLog,sizeof(pingLog));
	cJSON_AddStringToObject(root, "log", pingLog);

	send_cgi_json_respond(conn_fp, root);
	
	return CGI_TRUE;
}

CGI_BOOL setDiagnosisCfg(json_object *request, FILE *conn_fp)
{
	char cmd[CMD_STR_LEN] = {0}, tmpBuf[CMD_STR_LEN] = {0};;
	int pingNum = 0;

	int type = atoi(webs_get_string(request, "testType"));
	char *ipAddr  = webs_get_string(request,"ip");
	char *num  = webs_get_string(request,"num");

	if(Validity_check(ipAddr) == 0){
		pingNum = atoi(num);
		if(pingNum > 0 && pingNum <= 60) {
			switch(type) {
				case 0:
					sprintf(cmd, "ping -4 -c");
					break;

				case 1:
					sprintf(cmd, "ping -6 -c");
					break;

				case 2:
					sprintf(cmd, "traceroute -4 -q 2 -m");
					break;

				case 3:
					sprintf(cmd, "traceroute6 -q 2 -m");
					break;

				case 4:
					sprintf(cmd, "mtr -r -c");
					break;

				default:
					break;
			}

			if(strlen(cmd) > 0) {
				sprintf(tmpBuf, "%s %d %s &> %s &", cmd, pingNum, ipAddr, "/tmp/NetworkDiagnose");
				doSystem(tmpBuf);
			}
		}
	}
	
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");
	
	return CGI_TRUE;
}

CGI_BOOL clearDiagnosisLog(json_object *request, FILE *conn_fp)
{
	system("killall ping 2> /dev/null");
	system("killall traceroute 2> /dev/null");
	remove("/tmp/NetworkDiagnose");
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");
	
	return CGI_TRUE;
}

CGI_BOOL getSyslogCfg(json_object *request, FILE *conn_fp)
{
    cJSON *root = cJSON_CreateObject();
	
	char port[SMALL_STR_LEN] = {0}, remoteLogEnabled[SMALL_STR_LEN] = {0}, host[SHORT_STR_LEN] = {0};
 	
	
	Uci_Get_Str(PKG_SYSTEM_CONFIG,"syslog", "remote_log_enabled", remoteLogEnabled);
	Uci_Get_Str(PKG_SYSTEM_CONFIG,"syslog", "host", host);	
	Uci_Get_Str(PKG_SYSTEM_CONFIG,"syslog", "port", port);	

	cJSON_AddStringToObject(root,"enabled", remoteLogEnabled);	
	cJSON_AddStringToObject(root,"host", host);
	cJSON_AddStringToObject(root,"port", port);

	send_cgi_json_respond(conn_fp, root);
	
	return CGI_TRUE;
}

int is_flag_exist(const char *flag ,const char *filename) 
{
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        return 0; 
    }

    char line[256]={0};
    int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, flag) != NULL) {
            found = 1;
            break;
        }
    }
    fclose(fp);
    return found;
}


void del_file_line(char *source_file, const char *keyword) 
{
    char line[256]={0};

	FILE *source = fopen(source_file, "r");
    if (source == NULL) 
	{
        perror("Unable to open source file");
        return ;
    }

	FILE *teme = fopen("/etc/teme.conf", "w");
    if (teme == NULL) {
        perror("Unable to open temporary file");
        fclose(source);
        return ;
    }
	
    // 遍历源文件的每一行
    while (fgets(line, sizeof(line), source) != NULL) 
	{
        if (strstr(line, keyword) == NULL) {
            fputs(line, teme);  
        }
    }

	fclose(source);
    fclose(teme);

    remove(source_file);
    rename("/etc/teme.conf", source_file);
}


CGI_BOOL setSyslogCfg(json_object *request, FILE *conn_fp)
{
	char cmd[CMD_STR_LEN] = {0}, server[128]={0};
	char host_ldo[32]={0},port_ldo[32]={0},remoteLogEnabled_ldo[8]={0};

	char *remoteLogEnabled = webs_get_string(request,"enabled");
	char *host = webs_get_string(request,"host");
	char *port = webs_get_string(request, "port");

	Uci_Get_Str(PKG_SYSTEM_CONFIG,"syslog", "remote_log_enabled", remoteLogEnabled_ldo);
	Uci_Get_Str(PKG_SYSTEM_CONFIG,"syslog", "host", host_ldo);	
	Uci_Get_Str(PKG_SYSTEM_CONFIG,"syslog", "port", port_ldo);	

	Uci_Set_Str(PKG_SYSTEM_CONFIG,"syslog","remote_log_enabled",remoteLogEnabled);


	snprintf(server,sizeof(server),"%s:%s",host_ldo,port_ldo);


	if(atoi(remoteLogEnabled) == 0)
	{
		if(is_flag_exist(server,"/etc/rsyslog.conf"))
		{
			del_file_line("/etc/rsyslog.conf",server);

			doSystem("/etc/init.d/rsyslog restart");

			goto end;

		}
	}
	else
	{

		Uci_Set_Str(PKG_SYSTEM_CONFIG,"syslog","host",host);
		Uci_Set_Str(PKG_SYSTEM_CONFIG,"syslog","port",port);
		
		if(is_flag_exist(server,"/etc/rsyslog.conf"))
		{
			del_file_line("/etc/rsyslog.conf",server);
		}
					
		FILE *fp = fopen("/etc/rsyslog.conf", "a+");
   		if (!fp) {
       		return 0;
   		}
		
		fprintf(fp, "kern.*		@%s:%s\n", host,port);
		
		fclose(fp);

		
		doSystem("/etc/init.d/rsyslog restart");
	}

end:

	Uci_Commit(PKG_SYSTEM_CONFIG);

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");
	
	return CGI_TRUE;
}

CGI_BOOL clearSyslog(json_object *request, FILE *conn_fp)
{
	char cmd[64]={0};
	
	char *type = webs_get_string(request, "type");

	if(strcmp(type,"Message") == 0)
	{
		snprintf(cmd,sizeof(cmd),"> /var/log/messages");
	}
	else if(strcmp(type,"Kernel") == 0)
	{
		snprintf(cmd,sizeof(cmd),"> /var/log/kernel");
	}	
	else if(strcmp(type,"Application") == 0)
	{
		snprintf(cmd,sizeof(cmd),"> /var/log/app");
	}
	else if(strcmp(type,"LTE") == 0)
	{
		snprintf(cmd,sizeof(cmd),"> /var/log/modem");
	}

	doSystem(cmd);

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");
	
	return CGI_TRUE;
}

int read_log( char* log_path, char *log_buf)
{
    int fd;
    int n;
    int ret = -1;
    int log_length = 1024 * 256;
    int temp_len = 0;
    struct stat file_stat;

    bzero( log_buf , log_length);    
    if ( ( fd = open( log_path, O_RDONLY ) ) > 0 )
    {
        if ( -1 == stat( log_path, &file_stat ) )
        {
            dbg( "cannot read the log file stat error !" );
            close( fd );
            return ret;
        }

        if( file_stat.st_size > log_length)
        {
            temp_len = file_stat.st_size - log_length;
            lseek( fd, temp_len, SEEK_SET );
        }

        if( 0 < ( n = read( fd, log_buf, log_length ) ) )
        {
            ret = 0;
        }
        if ( n < 0 )
        {
            dbg( "cannot read the log file " );
        }
        close( fd );
    }
    return ret;
}

CGI_BOOL showSyslog(json_object *request, FILE *conn_fp)
{
	char log_buf[1024*256] = {0};
	char cmd[64] = {0};
	
	char *action = webs_get_string(request, "operation");
	char *type = webs_get_string(request, "type");


	if(strcmp(type,"Message") == 0)
	{
		snprintf(cmd,sizeof(cmd),"cat /var/log/messages |tail -n 50");
	}
	else if(strcmp(type,"Kernel") == 0)
	{
		snprintf(cmd,sizeof(cmd),"cat /var/log/kernel |tail -n 50");
	}	
	else if(strcmp(type,"Application") == 0)
	{
		snprintf(cmd,sizeof(cmd),"cat /var/log/app |tail -n 50");
	}
	else if(strcmp(type,"LTE") == 0)
	{
		snprintf(cmd,sizeof(cmd),"cat /var/log/modem |tail -n 50");
	}
	
	FILE *fp = popen(cmd, "r");//last 50

    if (fp == NULL) {
        return CGI_FALSE;
    }

    fread(log_buf, 1, sizeof(log_buf) - 1, fp);

    pclose(fp);
	
    cJSON *root = cJSON_CreateObject();

	cJSON_AddStringToObject(root,"syslog",log_buf);
	cJSON_AddStringToObject(root,"type",type); 	
	
	send_cgi_json_respond(conn_fp, root);
	
	return CGI_TRUE;
}
#if defined(CONFIG_CLOUDUPDATE_SUPPORT)
CGI_BOOL CloudSrvVersionCheck(json_object *request, FILE *conn_fp)
{
	int upgrade_status = UPG_LATEST;

	char tmp_buf[16] = {0};

	datconf_get_by_key(TEMP_STATUS_FILE, "upgrade_status", tmp_buf, sizeof(tmp_buf));
	upgrade_status = atoi(tmp_buf);

	if(upgrade_status!=UPG_CHECKING && upgrade_status!=UPG_FORCE_UPGRADEING)
	{
		Uci_Set_Str(PKG_PRODUCT_CONFIG, "custom", "runner", "1");
		Uci_Commit(PKG_PRODUCT_CONFIG);

		set_lktos_effect("cloud_upgrade_check");
	}

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "65", "reserv");

	return CGI_TRUE;
}

CGI_BOOL getCloudDownloadStatus(json_object *request, FILE *conn_fp)
{
	char tmpBuf[TEMP_STR_LEN]={0};
	char flag[5] = { 0 };
	cJSON *root;

	root = cJSON_CreateObject();
	memset(tmpBuf, 0, sizeof(tmpBuf));

	datconf_get_by_key(TEMP_STATUS_FILE, "ugrade_firmware", tmpBuf, sizeof(tmpBuf));
	datconf_get_by_key(TEMP_STATUS_FILE, "ugrade_reset", flag, sizeof(flag));
	if(!strcmp(tmpBuf,"") && (atoi(flag) == 0))
	{
		cJSON_AddStringToObject(root, "cloudupg_download", "2");
	}
	else
	{
		cJSON_AddStringToObject(root, "cloudupg_download", "1");
	}

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}

CGI_BOOL getCloudSrvCheckStatus(json_object *request, FILE *conn_fp)
{
	cJSON *root;

	char status[RESULT_STR_LEN]={0}, version[RESULT_STR_LEN]={0};
	int upgrade_status = 0;
	root = cJSON_CreateObject();

	datconf_get_by_key(TEMP_STATUS_FILE, "upgrade_status", status, sizeof(status));
	upgrade_status = atoi(status);
	memset(status,0,sizeof(status));

	if(upgrade_status==UPG_UNNET)
	{
		snprintf(status,RESULT_STR_LEN, "%d", UPG_UNNET);
	}
	else if(upgrade_status==UPG_LATEST)
	{
		snprintf(status,RESULT_STR_LEN, "%d", UPG_LATEST);
	}
	else if(upgrade_status==UPG_CHECKING)
	{
		snprintf(status,RESULT_STR_LEN, "%d", UPG_CHECKING);
	}
	else if(upgrade_status==UPG_NEW)
	{
		snprintf(status,RESULT_STR_LEN, "%d", UPG_NEW);
		Uci_Get_Str(PKG_CLOUDUPDATE_CONFIG, "cloudupdate", "version", version);
	}
	else if(upgrade_status==UPG_FORCE_UPGRADEING)
	{
	    snprintf(status,RESULT_STR_LEN, "%d", UPG_LATEST);
	}
	else
	{
	    snprintf(status,RESULT_STR_LEN, "%d", UPG_LATEST);
	}

	cJSON_AddStringToObject(root, "cloudFwStatus", status);
	cJSON_AddStringToObject(root, "newVersion", version);

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}
#endif

CGI_BOOL getUPnPCfg(json_object *request, FILE *conn_fp)
{
	cJSON *root, *list_obj, *rule_obj;
	FILE *fp = NULL;
	char enabled[SMALL_STR_LEN] = {0};
	char line[TEMP_STR_LEN] = {0};
	char proto[SMALL_STR_LEN]={0}, eport[SMALL_STR_LEN]={0}, iport[SMALL_STR_LEN]={0};
	char iaddr[RESULT_STR_LEN]={0}, desc[OPTION_STR_LEN]={0}; 
	char upnp_lease[]="/var/upnp.leases"; //upnpd.config.upnp_lease_file

	root=cJSON_CreateObject();

	Uci_Get_Str(PKG_UPNPD_CONFIG,"config","enabled",enabled);
	cJSON_AddStringToObject(root,"enable",enabled);

	list_obj=cJSON_CreateArray();
	if ((fp = fopen(upnp_lease, "r")) != NULL) 
	{
		/*
		root@none:/tmp# cat /var/upnp.leases 
		TCP:26848:192.168.0.105:26848:0:BitTorrent (TCP)
		UDP:26848:192.168.0.105:26848:0:BitTorrent (UDP)
		*/
		while (fgets(line, TEMP_STR_LEN, fp))
		{
			if(strlen(line) > 0)
			{
				rule_obj = cJSON_CreateObject();				
				sscanf(line,"%[^':']:%[^':']:%[^':']:%[^':']:%*d:%s",proto,eport,iaddr,iport,desc);
				cJSON_AddStringToObject(rule_obj,"proto",proto);
				cJSON_AddStringToObject(rule_obj,"ePort",eport);
				cJSON_AddStringToObject(rule_obj,"ip",iaddr);
				cJSON_AddStringToObject(rule_obj,"iPort",iport);
				cJSON_AddStringToObject(rule_obj,"desc",desc);
				cJSON_AddStringToObject(rule_obj,"status","1");
				cJSON_AddItemToArray(list_obj,rule_obj);
			}

			memset(proto,0,sizeof(proto));
			memset(eport,0,sizeof(eport));
			memset(iaddr,0,sizeof(iaddr));
			memset(iport,0,sizeof(iport));
			memset(desc,0,sizeof(desc));
			memset(line,0,sizeof(line));
		}
		fclose(fp);
	}

	cJSON_AddItemToObject(root,"upnpList",list_obj);
	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}


CGI_BOOL setUPnPCfg(json_object *request, FILE *conn_fp)
{
	char  *enabled = NULL;
	enabled = webs_get_string(request, "enable");

	Uci_Set_Str(PKG_UPNPD_CONFIG,"config","enabled", enabled);
	Uci_Commit(PKG_UPNPD_CONFIG); 
	set_lktos_effect("upnpd");

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "", "reserv");

	return CGI_TRUE;
}


CGI_BOOL getRebootScheCfg(json_object *request, FILE *conn_fp)
{
	char buff[128]={0};
	char mode[RESULT_STR_LEN]={0},recHour[RESULT_STR_LEN]={0};
	cJSON *root = cJSON_CreateObject();

	Uci_Get_Str(PKG_SYSTEM_CONFIG,"ntp","enabled",buff);
	cJSON_AddStringToObject(root,"NTPValid", buff);
	
	memset(buff,'\0', sizeof(buff));
	getSysUptime(buff);
	cJSON_AddStringToObject(root, "sysTime", buff);
	Uci_Get_Str(PKG_SYSTEM_CONFIG,"rebootsch","switch",mode);
	Uci_Get_Str(PKG_SYSTEM_CONFIG,"rebootsch","recHour",recHour);

	get_uci2json(root,PKG_SYSTEM_CONFIG, "rebootsch", "switch", "mode");
	get_uci2json(root,PKG_SYSTEM_CONFIG, "rebootsch", "week", "week");
	get_uci2json(root,PKG_SYSTEM_CONFIG, "rebootsch", "hour", "hour");
	get_uci2json(root,PKG_SYSTEM_CONFIG, "rebootsch", "minute", "minute");
	get_uci2json(root,PKG_SYSTEM_CONFIG, "rebootsch", "recHour", "recHour");

	int iMode,iSche;
	iSche=atoi(recHour);
	iMode=atoi(mode);

	if(iMode==2&&iSche>0)
	{	
		unsigned long sec, mn, hr, day;
		struct sysinfo info;
		sysinfo(&info);
		sec = (unsigned long)info.uptime;
		sec= iSche*3600-sec;
		day = sec / 86400;
		sec %= 86400;
		hr = sec / 3600;
		sec %= 3600;
		mn = sec / 60;
		sec %= 60;
		sprintf(buff,"%ld;%ld;%ld;%ld",day,hr,mn,sec);
	}
	else
	{
		sprintf(buff,"%d;%d;%d;%d",0,0,0,0);
	}

	cJSON_AddStringToObject(root, "recTime", buff);
	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}


CGI_BOOL setRebootScheCfg(json_object *request, FILE *conn_fp)
{
	int i = 1,iSche = 0;
	unsigned long sec;
	long cfgSec;
	struct sysinfo info;
	char buff[CMD_STR_LEN] = {0},weekBuf[TEMP_STR_LEN] = { 0 },cmd[CMD_STR_LEN] = {0};
	char *ptr = NULL;

    char *mode    = webs_get_string(request, "mode");
    char *week    = webs_get_string(request, "week");
    char *hour    = webs_get_string(request, "hour");
    char *minute  = webs_get_string(request, "minute");
	char *recHour = webs_get_string(request, "recHour");

	sysinfo(&info);
	sec = atoi(recHour)*3600;

	Uci_Set_Str(PKG_SYSTEM_CONFIG, "rebootsch", "switch", mode);
	Uci_Set_Str(PKG_SYSTEM_CONFIG, "rebootsch", "week", week);
	Uci_Set_Str(PKG_SYSTEM_CONFIG, "rebootsch", "hour", hour);
	Uci_Set_Str(PKG_SYSTEM_CONFIG, "rebootsch", "minute", minute);
	Uci_Set_Str(PKG_SYSTEM_CONFIG, "rebootsch", "recHour", recHour);
	Uci_Set_Str(PKG_SYSTEM_CONFIG, "rebootsch", "reboot_flag", "0");
	Uci_Commit(PKG_SYSTEM_CONFIG);
	
	if (info.uptime > sec && atoi(mode) == 2)
	{
		CsteSystem("reboot &", CSTE_PRINT_CMD);
		send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");
		return CGI_TRUE;
	}

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

	return CGI_TRUE;
}


CGI_BOOL getPasswordCfg(json_object *request, FILE *conn_fp)
{
	char admuser[TEMP_STR_LEN]={0};
	cJSON *root;
	root=cJSON_CreateObject();
	
	Uci_Get_Str(PKG_SYSTEM_CONFIG, "main", "username", admuser);
	cJSON_AddStringToObject(root, "admuser", admuser);

	send_cgi_json_respond(conn_fp, root);

    return CGI_TRUE;
}


CGI_BOOL setPasswordCfg(json_object *request, FILE *conn_fp)
{
	char *admuser, *admpass,*origPass;
	char current_pass[OPTION_STR_LEN]={0};
	char pass_old[64]={0}, pass_mdy[64]={0};

	admuser = webs_get_string(request, "admuser");
	admpass = webs_get_string(request, "admpass");
	origPass = webs_get_string(request, "origPass");

	base64_decode(admpass, pass_mdy);
	base64_decode(origPass, pass_old);
		
	Uci_Get_Str(PKG_SYSTEM_CONFIG,"main", "password", current_pass);
	
	if(strcmp(pass_old, current_pass) != 0)
	{
		cJSON *root=cJSON_CreateObject();
		cJSON_AddFalseToObject(root, "success");

		send_cgi_json_respond(conn_fp, root);

		return CGI_FALSE;
	}

	Uci_Set_Str(PKG_SYSTEM_CONFIG, "main", "username", admuser);

	Uci_Set_Str(PKG_SYSTEM_CONFIG,"main", "password", pass_mdy);
	//Uci_Set_Str(PKG_SYSTEM_CONFIG,"main","loginPasswordFlag","1");
	Uci_Commit(PKG_SYSTEM_CONFIG);

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

	return CGI_TRUE;
}


CGI_BOOL getNtpCfg(json_object *request, FILE *conn_fp)
{
    char OperationMode[SHORT_STR_LEN]={0};
	char ntpSer1[RESULT_STR_LEN]={0},ntpSer2[RESULT_STR_LEN]={0},ntpSer3[RESULT_STR_LEN]={0};
	char tmpBuf[TEMP_STR_LEN]={0};
    int opmode=0;
    char TZ[RESULT_STR_LEN]={0},ntpServerIp[TEMP_STR_LEN]={0},NTPClientEnabled[SHORT_STR_LEN]={0},Time_mode[RESULT_STR_LEN]={0};
    char NTPHostFlag[RESULT_STR_LEN]={0},languagetype[RESULT_STR_LEN]={0};

	cJSON *root;
	root=cJSON_CreateObject();

	memset(tmpBuf,0,sizeof(tmpBuf));
	getCurrentTime(tmpBuf);
	cJSON_AddStringToObject(root,"currentTime",tmpBuf);
	Uci_Get_Str(PKG_SYSTEM_CONFIG,"ntp","timezone",TZ);
	cJSON_AddStringToObject(root,"tz",TZ);
	Uci_Get_Str(PKG_SYSTEM_CONFIG,"ntp","time_mode",Time_mode);
	cJSON_AddStringToObject(root,"time_mode",Time_mode);

	Uci_Get_Str(PKG_SYSTEM_CONFIG,"ntp","server",ntpServerIp);
	get_nth_val_safe(0, ntpServerIp, ' ', ntpSer1, sizeof(ntpSer1));
	get_nth_val_safe(2, ntpServerIp, ' ', ntpSer2, sizeof(ntpSer2));
	get_nth_val_safe(4, ntpServerIp, ' ', ntpSer3, sizeof(ntpSer3));
	memset(tmpBuf, 0, sizeof(tmpBuf));
	sprintf(tmpBuf, "%s*%s*%s", ntpSer1, ntpSer2, ntpSer3);
	cJSON_AddStringToObject(root,"server", tmpBuf);
	Uci_Get_Str(PKG_SYSTEM_CONFIG,"ntp","enabled",NTPClientEnabled);
	cJSON_AddStringToObject(root,"enable",NTPClientEnabled);

	send_cgi_json_respond(conn_fp, root);

    return CGI_TRUE;
}


CGI_BOOL NTPSyncWithHost(json_object *request, FILE *conn_fp)
{
    char *host_time;
    char cmd[CMD_STR_LEN]={0};

    host_time = webs_get_string(request, "host_time");
	if(1==Validity_check(host_time))
	{
		goto jump_label;
	}
    CsteSystem("/etc/init.d/sysntpd stop", CSTE_PRINT_CMD);
    snprintf(cmd,CMD_STR_LEN,"date -s \"%s\"", host_time);
    CsteSystem(cmd, CSTE_PRINT_CMD);
    //set ntpupdate success
	CsteSystem("echo 1 > /tmp/NTPValid", CSTE_PRINT_CMD);
	Uci_Set_Str(PKG_SYSTEM_CONFIG,"ntp","time_flag","1");
	Uci_Set_Str(PKG_SYSTEM_CONFIG,"ntp","enabled","0");
	Uci_Commit(PKG_SYSTEM_CONFIG);
	CsteSystem("/etc/init.d/sysntpd restart", CSTE_PRINT_CMD);

jump_label:
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

	return CGI_TRUE;
}

void gps_timing()
{
	int timezone=0;
	char zone[32]={0},gpsdata[512]={0},data[256]={0},time[256]={0};
	char gps_date_file[32] = {0};
	char data_time[512]={0};

	json_object *root = NULL;
	
	Uci_Set_Str(PKG_SYSTEM_CONFIG,"ntp","time_zone",zone);

	

	sprintf(gps_date_file,"/tmp/gps_data");

	int ret = f_read_string(gps_date_file, gpsdata, sizeof(gpsdata));

	 if(ret > 0){
		root = json_tokener_parse(gpsdata);
		if(root != NULL) {
			strcpy(data,webs_get_string(root, "date"));
			strcpy(time,webs_get_string(root, "time"));
			json_object_put(root);
		}
	}
	 
	int data_x=0, data_y=0, data_v=0;
    int time_x=0, time_y=0, time_v=0;

   	sscanf(data, "%d-%d-%d", &data_x, &data_y, &data_v);
  	sscanf(time, "%d:%d:%d", &time_x, &time_y, &time_v);
   	sscanf(zone, "UTC%d", &timezone);

   	data_x += 2000;

   	if(timezone == 0) 
	{
        timezone = timezone;
    } 
	else 
	{
        timezone = ~timezone + 1;
    }

	utc_to_local utc_time = {data_x, data_y, data_v, time_x};

  	utc_to_local_time(&utc_time, timezone);
		   
   	sprintf(data_time,"%d-%d-%d %d:%d:%d",utc_time.year,utc_time.month,utc_time.day, 
									   utc_time.hour,time_y,time_v);

   	doSystem("date -s '%s'", data_time);
	
	
}



CGI_BOOL setNtpCfg(json_object *request, FILE *conn_fp)
{
    char *tz, *ntpServer, *ntpClientEnbl,*time_mode, *ntpSync;
	char ntpSer1[32]={0},ntpSer2[32]={0},ntpSer3[32]={0},tmpBuf[128]={0};
	char *host_time;
	char cmd[CMD_STR_LEN]={0};

    tz = webs_get_string(request, "tz");
	ntpServer = webs_get_string(request, "server");
	ntpClientEnbl = webs_get_string(request, "enable");
	time_mode = webs_get_string(request, "time_mode");
	
	Uci_Set_Str(PKG_SYSTEM_CONFIG,"ntp","time_mode",time_mode);

	if (!strcmp(time_mode, "1"))
	{
		host_time = webs_get_string(request, "host_time");
		if(1==Validity_check(host_time))
		{
			goto jump_label;
		}
		jump_host_time:
		snprintf(cmd,CMD_STR_LEN,"date -s \"%s\"", host_time);
		CsteSystem(cmd, CSTE_PRINT_CMD);
		Uci_Set_Str(PKG_SYSTEM_CONFIG, "ntp", "enabled", "0");
	}	
    else if (!strcmp(time_mode, "2"))
	{
		if(1==Validity_check(ntpServer))
		{
			goto jump_label;
		}
		jump_ntp:
		Uci_Set_Str(PKG_SYSTEM_CONFIG, "ntp", "enabled", "1");
		get_nth_val_safe(0, ntpServer, '*', ntpSer1, sizeof(ntpSer1));
		get_nth_val_safe(1, ntpServer, '*', ntpSer2, sizeof(ntpSer2));
		get_nth_val_safe(2, ntpServer, '*', ntpSer3, sizeof(ntpSer3));
		sprintf(tmpBuf, "%s -h %s -h %s", ntpSer1, ntpSer2, ntpSer3);
		Uci_Set_Str(PKG_SYSTEM_CONFIG, "ntp", "server", tmpBuf);
		Uci_Set_Str(PKG_SYSTEM_CONFIG, "ntp", "sync_time", "0");
		
		set_timezone_to_kernel();
	}

	else if (!strcmp(time_mode, "4"))
	{
		jump_gps:
		gps_timing();
	}
	else if (!strcmp(time_mode, "5"))
	{
		if (!Validity_check(ntpServer))
		{
			goto jump_ntp;
		}
		if (!Validity_check(host_time))
		{
			goto jump_host_time;
		}
	}
	Uci_Set_Str(PKG_SYSTEM_CONFIG, "ntp", "timezone", tz);
	Uci_Commit(PKG_SYSTEM_CONFIG);
	CsteSystem("/etc/init.d/sysntpd restart", CSTE_PRINT_CMD);


jump_label:
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");

	return CGI_TRUE;
}

#if defined(CONFIG_CRPC_SUPPORT)
CGI_BOOL getCrpcCfg(json_object *request, FILE *conn_fp)
{
	
	char wechat_url[CMD_STR_LEN] = { 0 }, url[CMD_STR_LEN] = { 0 };
	char csid[SHORT_STR_LEN] = { 0 }, model[SHORT_STR_LEN] = { 0 }, version[SHORT_STR_LEN] = { 0 };
	char cmd[TEMP_STR_LEN] = {0};
	int crpc_enable = 0;
	int countmax = 50; //1sec

	struct interface_status status_paremeter;

	cJSON *root;
	root = cJSON_CreateObject();

	get_wan_status(&status_paremeter);

	if(status_paremeter.up)
	{
		Uci_Get_Str(PKG_PRODUCT_CONFIG,"custom","csid",csid);
		Uci_Get_Str(PKG_PRODUCT_CONFIG,"sysinfo","soft_model",model);
		Uci_Get_Str(PKG_PRODUCT_CONFIG,"sysinfo","soft_version",version);

		snprintf(cmd, TEMP_STR_LEN, "crpc -c %s -m %s -v %s", csid, model, version);
		CsteSystem(cmd, CSTE_PRINT_CMD);
		CsteSystem(cmd, CSTE_PRINT_CMD);
		Uci_Get_Int(PKG_SYSTEM_CONFIG, "crpc", "enable", &crpc_enable);

		if(crpc_enable == 0)
		{ 
			Uci_Set_Str(PKG_SYSTEM_CONFIG, "crpc", "enable", "1");
			Uci_Commit(PKG_SYSTEM_CONFIG);
		}
		
		while(countmax--)
		{
			if(f_exists("/tmp/crpc_url"))
			{
				break;
			}
			usleep(20);
		}
		f_read("/tmp/crpc_url", wechat_url,sizeof(wechat_url));
		urlencode(wechat_url,url);
		memset(wechat_url,0,sizeof(wechat_url));
		snprintf(wechat_url, CMD_STR_LEN, "%s%s", WECHAR_URL_HEAD, url);
		
		cJSON_AddStringToObject(root, "status", "1");
		cJSON_AddStringToObject(root, "url", wechat_url);
	}
	else
	{
		cJSON_AddStringToObject(root, "status", "0");
		cJSON_AddStringToObject(root, "url", "");
	}

	cJSON_AddNumberToObject(root,"newPhoneUi",1);

	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}
#endif

#if defined(APP_IOT_MQTT)
CGI_BOOL getIotMCfg(json_object *request, FILE *conn_fp)
{
	int intVal=0;
	cJSON *root;

	root = cJSON_CreateObject();
	get_uci2json(root, PKG_IOT_CONFIG, "iotm", "enable", "enabled");
	get_uci2json(root, PKG_IOT_CONFIG, "iotm", "server_host", "serverHost");
	get_uci2json(root, PKG_IOT_CONFIG, "iotm", "port", "port");
	
	get_uci2json(root, PKG_IOT_CONFIG, "iotm", "keep_alive", "keepaLive");
	get_uci2json(root, PKG_IOT_CONFIG, "iotm", "bind_code", "bindCode");
	get_uci2json(root, PKG_IOT_CONFIG, "iotm", "warning_interval", "warningInterval");
	get_uci2json(root, PKG_IOT_CONFIG, "iotm", "gps_interval", "gpsInterval");
	get_uci2json(root, PKG_IOT_CONFIG, "iotm", "lte_interval", "lteInterval");
	Uci_Get_Int(PKG_PRODUCT_CONFIG, "custom", "iotm_show_userpass", &intVal);
	if(intVal == 1){
		get_uci2json(root, PKG_IOT_CONFIG, "iotm", "user_name", "userName");
		get_uci2json(root, PKG_IOT_CONFIG, "iotm", "password", "passWord");
	}
	
	send_cgi_json_respond(conn_fp, root);
	return CGI_TRUE;
}
CGI_BOOL setIotMCfg(json_object *request, FILE *conn_fp)
{
	int intVal=0;
	
	char *enable = webs_get_string(request, "enabled");
	char *serverHost = webs_get_string(request, "serverHost");
	char *port = webs_get_string(request, "port");
	char *keepaLive = webs_get_string(request, "keepaLive");
	char *userName = webs_get_string(request, "userName");
	char *passWord = webs_get_string(request, "passWord");
	char *bindCode = webs_get_string(request, "bindCode");
	
	char *warningInterval = webs_get_string(request, "warningInterval");
	char *gpsInterval = webs_get_string(request, "gpsInterval");
	char *lteInterval = webs_get_string(request, "lteInterval");

	Uci_Set_Str(PKG_IOT_CONFIG, "iotm", "enable", enable);
	if(atoi(enable) == 1){
		Uci_Set_Str(PKG_IOT_CONFIG, "iotm", "server_host", serverHost);
		Uci_Set_Str(PKG_IOT_CONFIG, "iotm", "port", port);
		Uci_Set_Str(PKG_IOT_CONFIG, "iotm", "keep_alive", keepaLive);

		Uci_Set_Str(PKG_IOT_CONFIG, "iotm", "bind_code", bindCode);
		Uci_Set_Str(PKG_IOT_CONFIG, "iotm", "warning_interval", warningInterval);
		Uci_Set_Str(PKG_IOT_CONFIG, "iotm", "gps_interval", gpsInterval);
		
		Uci_Set_Str(PKG_IOT_CONFIG, "iotm", "zhuan_lte_interval", lteInterval);
		Uci_Set_Str(PKG_IOT_CONFIG, "iotm", "lte_interval", lteInterval);

		Uci_Get_Int(PKG_PRODUCT_CONFIG, "custom", "iotm_show_userpass", &intVal);
		if(intVal == 1){
			Uci_Set_Str(PKG_IOT_CONFIG, "iotm", "user_name", userName);
			Uci_Set_Str(PKG_IOT_CONFIG, "iotm", "password", passWord);
		}
	
		Uci_Commit(PKG_IOT_CONFIG);
	}
	else{
		datconf_set_by_key(TEMP_IOT_FILE, "iotm_bind_status", "0");
	}
	
	set_lktos_effect("iot-mqtt");
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "15", "reLogin");

	return CGI_TRUE;
}
CGI_BOOL getIotMStateCfg(json_object *request, FILE *conn_fp)
{
	int enable=0, i_connect=0, i_bind=0;
	char status[8]={0};
	cJSON *root;

	root = cJSON_CreateObject();

	Uci_Get_Int(PKG_IOT_CONFIG, "iotm", "enable", &enable);
	datconf_get_by_key(TEMP_IOT_FILE, "iotm_connect_status", status, sizeof(status));
	i_connect = atoi(status);
	if(enable == 1){
		if(i_connect == 3) //CONNECT_ING
			cJSON_AddStringToObject(root, "connStatus", "3");
		else if(i_connect == 2) //CONNECT_SUCCESS
			cJSON_AddStringToObject(root, "connStatus", "2");
		else if(i_connect == 1)//CONNECT_FAIL
			cJSON_AddStringToObject(root, "connStatus", "1");
		else
			cJSON_AddStringToObject(root, "connStatus", "0");//NO_CONNECT

		memset(status, 0, sizeof(status));
		datconf_get_by_key(TEMP_IOT_FILE, "iotm_bind_status", status, sizeof(status));
		i_bind = atoi(status);
		if(i_bind == 3) //NO_BIND
			cJSON_AddStringToObject(root, "bindStatus", "0");
		else if(i_bind == 2) //BIND_SUCCESS
			cJSON_AddStringToObject(root, "bindStatus", "2");
		else if(i_bind == 1)//BIND_FAIL
			cJSON_AddStringToObject(root, "bindStatus", "1");
		else
			cJSON_AddStringToObject(root, "bindStatus", "0");//NO_BIND
			
	}
	else{
		if(i_connect)
			cJSON_AddStringToObject(root, "connStatus", "1");// CONNECT_FAIL
		else
			cJSON_AddStringToObject(root, "connStatus", "0");// NO_CONNECT

		cJSON_AddStringToObject(root, "bindStatus", "0"); //NO_BIND
	}
	
	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}
#endif


CGI_BOOL getAilingCfg(json_object *request, FILE *conn_fp)
{
	int intVal=0;
	cJSON *root;

	root = cJSON_CreateObject();
	get_uci2json(root, PKG_AILING_CONFIG, "iotm", "enable", "enabled");
	get_uci2json(root, PKG_AILING_CONFIG, "iotm", "server_host", "serverHost");
	get_uci2json(root, PKG_AILING_CONFIG, "iotm", "port", "port");
	
	get_uci2json(root, PKG_AILING_CONFIG, "iotm", "keep_alive", "keepaLive");
	get_uci2json(root, PKG_AILING_CONFIG, "iotm", "bind_code", "bindCode");
	get_uci2json(root, PKG_AILING_CONFIG, "iotm", "warning_interval", "warningInterval");
	get_uci2json(root, PKG_AILING_CONFIG, "iotm", "gps_interval", "gpsInterval");
	get_uci2json(root, PKG_AILING_CONFIG, "iotm", "lte_interval", "lteInterval");
	Uci_Get_Int(PKG_PRODUCT_CONFIG, "custom", "iotm_show_userpass", &intVal);
	if(intVal == 1){
		get_uci2json(root, PKG_AILING_CONFIG, "iotm", "user_name", "userName");
		get_uci2json(root, PKG_AILING_CONFIG, "iotm", "password", "passWord");
	}
	
	send_cgi_json_respond(conn_fp, root);
	return CGI_TRUE;
}
CGI_BOOL setAilingCfg(json_object *request, FILE *conn_fp)
{
	int intVal=0;
	
	char *enable = webs_get_string(request, "enabled");
	char *serverHost = webs_get_string(request, "serverHost");
	char *port = webs_get_string(request, "port");
	char *keepaLive = webs_get_string(request, "keepaLive");
	char *userName = webs_get_string(request, "userName");
	char *passWord = webs_get_string(request, "passWord");
	char *bindCode = webs_get_string(request, "bindCode");
	
	char *warningInterval = webs_get_string(request, "warningInterval");
	char *gpsInterval = webs_get_string(request, "gpsInterval");
	char *lteInterval = webs_get_string(request, "lteInterval");

	Uci_Set_Str(PKG_AILING_CONFIG, "iotm", "enable", enable);
	if(atoi(enable) == 1){
		Uci_Set_Str(PKG_AILING_CONFIG, "iotm", "server_host", serverHost);
		Uci_Set_Str(PKG_AILING_CONFIG, "iotm", "port", port);
		Uci_Set_Str(PKG_AILING_CONFIG, "iotm", "keep_alive", keepaLive);

		Uci_Set_Str(PKG_AILING_CONFIG, "iotm", "bind_code", bindCode);
		Uci_Set_Str(PKG_AILING_CONFIG, "iotm", "warning_interval", warningInterval);
		Uci_Set_Str(PKG_AILING_CONFIG, "iotm", "gps_interval", gpsInterval);
		
		Uci_Set_Str(PKG_AILING_CONFIG, "iotm", "zhuan_lte_interval", lteInterval);
		Uci_Set_Str(PKG_AILING_CONFIG, "iotm", "lte_interval", lteInterval);

		Uci_Get_Int(PKG_PRODUCT_CONFIG, "custom", "iotm_show_userpass", &intVal);
		if(intVal == 1){
			Uci_Set_Str(PKG_AILING_CONFIG, "iotm", "user_name", userName);
			Uci_Set_Str(PKG_AILING_CONFIG, "iotm", "password", passWord);
		}
	
		Uci_Commit(PKG_AILING_CONFIG);
	}
	else{
		datconf_set_by_key(TEMP_IOT_FILE, "iotm_bind_status", "0");
	}
	
	set_lktos_effect("ailing-mqtt");
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "15", "reLogin");

	return CGI_TRUE;
}

CGI_BOOL getAilingStaCfg(json_object *request, FILE *conn_fp)
{
	int enable=0, i_connect=0, i_bind=0;
	char status[8]={0};
	cJSON *root;

	root = cJSON_CreateObject();

	Uci_Get_Int(PKG_AILING_CONFIG, "iotm", "enable", &enable);
	datconf_get_by_key(TEMP_IOT_FILE, "iotm_connect_status", status, sizeof(status));
	i_connect = atoi(status);
	if(enable == 1){
		if(i_connect == 3) //CONNECT_ING
			cJSON_AddStringToObject(root, "connStatus", "3");
		else if(i_connect == 2) //CONNECT_SUCCESS
			cJSON_AddStringToObject(root, "connStatus", "2");
		else if(i_connect == 1)//CONNECT_FAIL
			cJSON_AddStringToObject(root, "connStatus", "1");
		else
			cJSON_AddStringToObject(root, "connStatus", "0");//NO_CONNECT

		memset(status, 0, sizeof(status));
		datconf_get_by_key(TEMP_IOT_FILE, "iotm_bind_status", status, sizeof(status));
		i_bind = atoi(status);
		if(i_bind == 3) //NO_BIND
			cJSON_AddStringToObject(root, "bindStatus", "0");
		else if(i_bind == 2) //BIND_SUCCESS
			cJSON_AddStringToObject(root, "bindStatus", "2");
		else if(i_bind == 1)//BIND_FAIL
			cJSON_AddStringToObject(root, "bindStatus", "1");
		else
			cJSON_AddStringToObject(root, "bindStatus", "0");//NO_BIND
			
	}
	else{
		if(i_connect)
			cJSON_AddStringToObject(root, "connStatus", "1");// CONNECT_FAIL
		else
			cJSON_AddStringToObject(root, "connStatus", "0");// NO_CONNECT

		cJSON_AddStringToObject(root, "bindStatus", "0"); //NO_BIND
	}
	
	send_cgi_json_respond(conn_fp, root);

	return CGI_TRUE;
}


CGI_BOOL getSLBApcliScan(json_object *request, FILE *conn_fp)
{
    FILE *fp = NULL;
    char line_str[256] = {0};
    char domain_name[TEMP_STR_LEN] = {0};
    char cell_id[TEMP_STR_LEN] = {0};
    char channel[TEMP_STR_LEN] = {0};
    char rssi[TEMP_STR_LEN] = {0};
    char domain_cnt[TEMP_STR_LEN] = {0};
    char vendor_info_cnt[TEMP_STR_LEN] = {0};
    int scan_num = 0;
    cJSON *root, *scan_entry;

    root = cJSON_CreateArray();
    
    CsteSystem("killall -9 iwpriv", 0);
    doSystem("iwpriv vap0 cfg \"scan 5.2G 5.4G 5.8G\"");
    sleep(3);
    doSystem("iwpriv vap0 cfg \"show_bss\" > /tmp/scan_slbap.txt");

    fp = fopen("/tmp/scan_slbap.txt", "r");
    if (NULL == fp) {
        goto end;
    }

    while (fgets(line_str, sizeof(line_str), fp) != NULL) {
		// 检查BSS扫描数量
        if (strstr(line_str, "BSS SCANED NUM:") != NULL) {
            sscanf(line_str, "BSS SCANED NUM:%d", &scan_num);
            // 如果扫描数量为0或负数，直接跳出循环
            if (scan_num <= 0) {
                break;
            }
            continue;
        }
        
        // 跳过非数据行
        if (strstr(line_str, "DOMAIN_NAME:") == NULL) {
            continue;
        }

        // 解析行：DOMAIN_NAME:gnode_000, CELL_ID:2, CHANNEL:1875, RSSI:-34, DOMAIN_CNT:1, VENDOR_INFO_CNT:0
        sscanf(line_str, "DOMAIN_NAME:%[^,], CELL_ID:%[^,], CHANNEL:%[^,], RSSI:%[^,], DOMAIN_CNT:%[^,], VENDOR_INFO_CNT:%s",
               domain_name, cell_id, channel, rssi, domain_cnt, vendor_info_cnt);
		
		if (domain_name[0] != '\0') {
			scan_entry = cJSON_CreateObject();
			cJSON_AddStringToObject(scan_entry, "encrypt", "SLB");
			cJSON_AddStringToObject(scan_entry, "ssid", domain_name);
			cJSON_AddStringToObject(scan_entry, "cell_id", cell_id);
			cJSON_AddStringToObject(scan_entry, "channel", channel);
			cJSON_AddStringToObject(scan_entry, "signal", rssi);
			cJSON_AddStringToObject(scan_entry, "domain_cnt", domain_cnt);
			cJSON_AddStringToObject(scan_entry, "vendor_info_cnt", vendor_info_cnt);
			cJSON_AddItemToArray(root, scan_entry);
		}
    }

    fclose(fp);

end:
    send_cgi_json_respond(conn_fp, root);
    return CGI_TRUE;
}

CGI_BOOL getSLBstatus(json_object *request, FILE *conn_fp)
{	
    FILE *fp = NULL;
    char line_str[256] = {0};
    char gnode_name[TEMP_STR_LEN] = {0};
    char ConnStatus[TEMP_STR_LEN] = {0};
    char mac[18] = {0};         
    char rssi[8] = {0};          
    char rsrp[8] = {0};         
    char snr[8] = {0};         
    int has_user = 0;
    int found_header = 0;
    
    cJSON *root = cJSON_CreateObject();
    
    doSystem("iwpriv vap0 cfg \"view_users\" > /tmp/slb_status.txt");
    fp = fopen("/tmp/slb_status.txt", "r");
    if (fp != NULL) {
        while (fgets(line_str, sizeof(line_str), fp) != NULL) {
            // 跳过表头行
            if (strstr(line_str, "user_idx") && strstr(line_str, "mac_addr")) {
                found_header = 1;
                continue;
            }
            // 在表头之后处理数据行
            if (found_header) {
                if (strchr(line_str, ':')) {
                    unsigned int idx;
                    if (sscanf(line_str, "%u %17s", &idx, mac) == 2) {
                        has_user = 1;
                        break;
                    }
                }
            }
        }
        fclose(fp);
    }
    // 设置连接状态
    strncpy(ConnStatus, has_user ? "success" : "", sizeof(ConnStatus)-1);
    
    doSystem("iwpriv vap0 cfg \"get_rssi\" > /tmp/slb_dongle_rssi.txt");
    fp = fopen("/tmp/slb_dongle_rssi.txt", "r");
    if (fp != NULL) {
        int data_header_found = 0;
        
        while (fgets(line_str, sizeof(line_str), fp) != NULL) {
            // 定位数据表头
            if (strstr(line_str, "user_idx") && strstr(line_str, "rssi") && 
                strstr(line_str, "rsrp") && strstr(line_str, "snr")) {
                data_header_found = 1;
                continue;
            }
            // 处理数据行
            if (data_header_found) {
                unsigned int idx;
                int rssi_val, rsrp_val, snr_val;
                // 解析四个整数值
                if (sscanf(line_str, "%u %d %d %d", 
                          &idx, &rssi_val, &rsrp_val, &snr_val) == 4) {
                    // 转换数值为字符串
                    snprintf(rssi, sizeof(rssi), "%d", rssi_val);
                    snprintf(rsrp, sizeof(rsrp), "%d", rsrp_val);
                    snprintf(snr, sizeof(snr), "%d", snr_val);
                    break; // 获取成功后退出循环
                }
            }
        }
        fclose(fp);
    }

    Uci_Get_Str(PKG_SLB_CONFIG, "slb_dongle", "gnode_name", gnode_name);
    cJSON_AddStringToObject(root, "rptGnodeName", gnode_name);
    cJSON_AddStringToObject(root, "rptConnStatus", ConnStatus);
    cJSON_AddStringToObject(root, "mac", mac);
    cJSON_AddStringToObject(root, "rssi", rssi);
    cJSON_AddStringToObject(root, "rsrp", rsrp);
    cJSON_AddStringToObject(root, "snr", snr);
    
    send_cgi_json_respond(conn_fp, root);
    return CGI_TRUE;
}

CGI_BOOL setSLBModeCfg(json_object *request, FILE *conn_fp)
{    
    FILE *fp;   
    char gateway[16] = {0};
    char current_lan_ip[16] = {0};
    char new_lan_ip[16] = {0};
    char line[256];
    char line_str[256] = {0};
    int has_user = 0;
    int found_header = 0;
    int max_attempts = 5;
    int attempt = 0;
    int connected = 0;
    char *mode_rpt, *bssid_rpt, *t_channel_rpt, *ssid_rpt, *encrypt_rpt, *password_rpt, *index_rpt,*bw_rpt;
    t_channel_rpt = webs_get_string(request, "t_channel_rpt");
    ssid_rpt = webs_get_string(request, "ssid_rpt");
    encrypt_rpt = webs_get_string(request, "encrypt_rpt");
    bw_rpt = webs_get_string(request, "bw_rpt");
    password_rpt = webs_get_string(request, "password_rpt");
    index_rpt = webs_get_string(request, "index_rpt");
    // dbg("channel_rpt=%s, ssid_rpt=%s, encrypt_rpt=%s, bw_rpt=%s, password_rpt=%s, index_rpt=%s", t_channel_rpt, ssid_rpt, encrypt_rpt, bw_rpt, password_rpt, index_rpt);
    Uci_Set_Str(PKG_SLB_CONFIG, "slb_dongle", "channel", t_channel_rpt);
    Uci_Set_Str(PKG_SLB_CONFIG, "slb_dongle", "pwd", password_rpt);
    Uci_Set_Str(PKG_SLB_CONFIG, "slb_dongle", "bw", bw_rpt);
	Uci_Set_Str(PKG_SLB_CONFIG, "slb_dongle", "gnode_name", ssid_rpt);
    Uci_Commit(PKG_SLB_CONFIG);

	doSystem("killall -9 uspd");
	doSystem("killall -9 udhcpc");
    doSystem("/usr/sbin/first_start_tnode.sh");
    sleep(5);
    // 轮询尝试连接，最多5次
    for (attempt = 0; attempt < max_attempts && !connected; attempt++) {
        doSystem("iwpriv vap0 cfg \"start_join %s\" > /tmp/start_join.txt", index_rpt);
        sleep(3);
		doSystem("iwpriv vap0 cfg \"start_join %s\" > /tmp/start_join.txt", index_rpt);
		sleep(3); // 等待一下让连接稳定
        doSystem("iwpriv vap0 cfg \"view_users\" > /tmp/slb_status.txt");
        fp = fopen("/tmp/slb_status.txt", "r");
        if (NULL == fp) {
            continue; // 文件打开失败，继续下一次尝试
        }
        has_user = 0;
        found_header = 0;
        while (fgets(line_str, sizeof(line_str), fp) != NULL) {
            // 跳过表头行
            if (strstr(line_str, "user_idx") != NULL && strstr(line_str, "mac_addr") != NULL) {
                found_header = 1;
                continue;
            }
            // 在表头之后，检查数据行
            if (found_header) {
                // 检查是否包含数字和冒号（MAC地址特征）
                if (strchr(line_str, ':') != NULL) {
                    // 进一步验证：行中应该包含数字（用户索引）
                    for (int i = 0; line_str[i] != '\0'; i++) {
                        if (isdigit(line_str[i])) {
                            has_user = 1;
                            break;
                        }
                    }
                    if (has_user) break;
                }
            }
        }
        fclose(fp);
        
        if (has_user) {
            connected = 1;
            break; // 连接成功，跳出循环
        }
        
        // 如果还没达到最大尝试次数，等待一下再试
        if (attempt < max_attempts - 1) {
            sleep(2); // 等待2秒再尝试
        }
    }
    
    // 如果连接失败，记录日志但继续执行
    if (!connected) {
        dbg("Warning: Failed to connect after %d attempts", max_attempts);
		goto end;
    }

    doSystem("sysctl -w net.core.rmem_max=2097152");
    doSystem("sysctl -w net.core.wmem_max=2097152");
    doSystem("udhcpc -i vap0 -n -t 2 > /tmp/udhcpc_output.log 2>&1");

    // 从udhcpc输出中提取网关
    fp = fopen("/tmp/udhcpc_output.log", "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "setting default routers")) {
                char *ptr = strrchr(line, ' ');
                if (ptr) {
                    snprintf(gateway, sizeof(gateway), "%s", ptr + 1);
                    // 去除可能的换行符
                    gateway[strcspn(gateway, "\r\n")] = 0;
                }
                break;
            }
        }
        fclose(fp);
    }
    // 获取当前LAN IP
    fp = popen("uci get network.lan.ipaddr 2>/dev/null", "r");
    if (fp) {
        if (fgets(current_lan_ip, sizeof(current_lan_ip), fp)) {
            current_lan_ip[strcspn(current_lan_ip, "\r\n")] = 0;
        }
        pclose(fp);
    }
    
    // 检查是否需要修改IP
    if (strlen(gateway) > 0 && strlen(current_lan_ip) > 0) {
        char gateway_net[16] = {0};
        char current_net[16] = {0};
        // 提取网关和当前IP的前三段
        char *saveptr1, *saveptr2;
        char *gateway_copy = strdup(gateway);
        char *current_copy = strdup(current_lan_ip);
        char *gateway_part1 = strtok_r(gateway_copy, ".", &saveptr1);
        char *gateway_part2 = strtok_r(NULL, ".", &saveptr1);
        char *gateway_part3 = strtok_r(NULL, ".", &saveptr1);
        char *current_part1 = strtok_r(current_copy, ".", &saveptr2);
        char *current_part2 = strtok_r(NULL, ".", &saveptr2);
        char *current_part3 = strtok_r(NULL, ".", &saveptr2);
        char *current_part4 = strtok_r(NULL, ".", &saveptr2);
        
        if (gateway_part1 && gateway_part2 && gateway_part3 &&
            current_part1 && current_part2 && current_part3 && current_part4) {
            
            snprintf(gateway_net, sizeof(gateway_net), "%s.%s.%s", 
                    gateway_part1, gateway_part2, gateway_part3);
            snprintf(current_net, sizeof(current_net), "%s.%s.%s", 
                    current_part1, current_part2, current_part3);
            
            // 检查网段冲突
            if (strcmp(gateway_net, current_net) == 0) {
                // dbg("Gateway conflict detected! Modifying LAN IP...\n");
                // 计算新的IP地址
                int ip_part3 = atoi(current_part3);
                int new_ip_part3 = ip_part3 + 1;
                if (new_ip_part3 > 254) {
                    new_ip_part3 = 2;
                }
                
                snprintf(new_lan_ip, sizeof(new_lan_ip), "%s.%s.%d.%s",
                        current_part1, current_part2, new_ip_part3, current_part4);
                // dbg("Changing LAN IP from %s to %s\n", current_lan_ip, new_lan_ip);
                // 断开USB
                doSystem("echo disconnect > /sys/class/udc/fe500000.dwc3/soft_connect");
                char cmd[256];
                snprintf(cmd, sizeof(cmd), "uci set network.lan.ipaddr=\"%s\"", new_lan_ip);
                doSystem(cmd);
                snprintf(cmd, sizeof(cmd), "uci set network.usb0.gateway=\"%s\"", new_lan_ip);
                doSystem(cmd);
                doSystem("uci commit network");
                // 重启网络
                // dbg("Restarting network...\n");
                doSystem("/etc/init.d/network restart");
                sleep(2);
                // 重新连接USB
                doSystem("echo connect > /sys/class/udc/fe500000.dwc3/soft_connect");
                sleep(5);
            }
        }
        free(gateway_copy);
        free(current_copy);

		doSystem("killall -9 uspd");
		doSystem("killall -9 udhcpc");
        doSystem("/usr/sbin/first_start_tnode.sh");
        doSystem("iwpriv vap0 cfg \"start_join %s\"", index_rpt);
        sleep(2);
        doSystem("iwpriv vap0 cfg \"start_join %s\"", index_rpt);
        doSystem("sysctl -w net.core.rmem_max=2097152");
        doSystem("sysctl -w net.core.wmem_max=2097152");
        doSystem("udhcpc -i vap0 -n -t 2 &");
    }
end:	
    send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");
    return CGI_TRUE;
}

CGI_BOOL getSLBAPCfg(json_object *request, FILE *conn_fp)
{
    FILE *fp = NULL;
    char line_str[256] = {0};
    cJSON *root;
    root = cJSON_CreateObject();
    char mac[TEMP_STR_LEN] = {0};
    char ssid[TEMP_STR_LEN] = {0};
    char channel[TEMP_STR_LEN] = {0};
    char bw[TEMP_STR_LEN] = {0};
	char tfc_bw[TEMP_STR_LEN] = {0};
    char pwd[TEMP_STR_LEN] = {0};
    char ip[TEMP_STR_LEN] = {0};
    char symbol[TEMP_STR_LEN] = {0};
    char cell_id[TEMP_STR_LEN] = {0};
    char cp_type[TEMP_STR_LEN] = {0};
    char sysmsg_period[TEMP_STR_LEN] = {0};
    char s_cfg_idx[TEMP_STR_LEN] = {0};
    char cc_start_pos[TEMP_STR_LEN] = {0};
    char rptConnected[TEMP_STR_LEN] = "0";

    Uci_Get_Str(PKG_SLB_CONFIG, "slb_ap", "mac", mac);
    Uci_Get_Str(PKG_SLB_CONFIG, "slb_ap", "ssid", ssid);
    Uci_Get_Str(PKG_SLB_CONFIG, "slb_ap", "channel", channel);
    Uci_Get_Str(PKG_SLB_CONFIG, "slb_ap", "bw", bw);
	Uci_Get_Str(PKG_SLB_CONFIG, "slb_ap", "tfc_bw", tfc_bw);
    Uci_Get_Str(PKG_SLB_CONFIG, "slb_ap", "pwd", pwd);
    Uci_Get_Str(PKG_SLB_CONFIG, "slb_ap", "ip", ip);
    Uci_Get_Str(PKG_SLB_CONFIG, "slb_ap", "symbol", symbol);
    Uci_Get_Str(PKG_SLB_CONFIG, "slb_ap", "cell_id", cell_id);
    Uci_Get_Str(PKG_SLB_CONFIG, "slb_ap", "cp_type", cp_type);
    Uci_Get_Str(PKG_SLB_CONFIG, "slb_ap", "sysmsg_period", sysmsg_period);
    Uci_Get_Str(PKG_SLB_CONFIG, "slb_ap", "s_cfg_idx", s_cfg_idx);
    Uci_Get_Str(PKG_SLB_CONFIG, "slb_ap", "cc_start_pos", cc_start_pos);

    doSystem("ifconfig > /tmp/slb_ap_status.txt");
    fp = fopen("/tmp/slb_ap_status.txt", "r");
    if (NULL == fp) {
        goto end;
    }
    while (fgets(line_str, sizeof(line_str), fp) != NULL) {
        if (strstr(line_str, "vap0") != NULL) {
            strcpy(rptConnected, "1"); 
            break;
        }
    }

end:
    if (fp != NULL) {
        fclose(fp);
    }

    cJSON_AddStringToObject(root, "mac", mac);
    cJSON_AddStringToObject(root, "ssid", ssid);
    cJSON_AddStringToObject(root, "channel", channel);
    cJSON_AddStringToObject(root, "bw", bw);
	cJSON_AddStringToObject(root, "tfcBw", tfc_bw);
    cJSON_AddStringToObject(root, "pwd", pwd);
    cJSON_AddStringToObject(root, "ip", ip);
    cJSON_AddStringToObject(root, "symbol", symbol);
    cJSON_AddStringToObject(root, "cell_id", cell_id);
    cJSON_AddStringToObject(root, "cp_type", cp_type);
    cJSON_AddStringToObject(root, "sysmsg_period", sysmsg_period);
    cJSON_AddStringToObject(root, "s_cfg_idx", s_cfg_idx);
    cJSON_AddStringToObject(root, "cc_start_pos", cc_start_pos);
    cJSON_AddStringToObject(root, "rptConnected", rptConnected);

    send_cgi_json_respond(conn_fp, root);
    return CGI_TRUE;
}

CGI_BOOL setSLBAPCfg(json_object *request, FILE *conn_fp)
{
	char *ssid, *mac, *channel, *bw, *tfc_bw, *pwd, *ip,*symbol,*cell_id,*cp_type,*sysmsg_period,*s_cfg_idx,*cc_start_pos;
	ssid = webs_get_string(request, "ssid");
	mac = webs_get_string(request, "mac");
	channel = webs_get_string(request, "channel");
	bw = webs_get_string(request, "bw");
	tfc_bw = webs_get_string(request, "tfcBw");
	pwd = webs_get_string(request, "pwd");
	ip = webs_get_string(request, "ip");
	symbol = webs_get_string(request, "symbol");
	cell_id = webs_get_string(request, "cell_id");
	cp_type = webs_get_string(request, "cp_type");
	sysmsg_period = webs_get_string(request, "sysmsg_period");
	s_cfg_idx = webs_get_string(request, "s_cfg_idx");
	cc_start_pos = webs_get_string(request, "cc_start_pos");
	//dbg("ssid=%s, mac=%s, channel=%s, bw=%s, pwd=%s, ip=%s, symbol=%s, cell_id=%s, cp_type=%s, sysmsg_period=%s, s_cfg_idx=%s, cc_start_pos=%s", ssid, mac, channel, bw, pwd, ip, symbol, cell_id, cp_type, sysmsg_period, s_cfg_idx, cc_start_pos);

	Uci_Set_Str(PKG_SLB_CONFIG, "slb_ap", "mac", mac);
	Uci_Set_Str(PKG_SLB_CONFIG, "slb_ap", "ssid", ssid);
	Uci_Set_Str(PKG_SLB_CONFIG, "slb_ap", "channel", channel);
	Uci_Set_Str(PKG_SLB_CONFIG, "slb_ap", "bw", bw);
	Uci_Set_Str(PKG_SLB_CONFIG, "slb_ap", "tfc_bw", tfc_bw);
	Uci_Set_Str(PKG_SLB_CONFIG, "slb_ap", "pwd", pwd);
	Uci_Set_Str(PKG_SLB_CONFIG, "slb_ap", "ip", ip);
	Uci_Set_Str(PKG_SLB_CONFIG, "slb_ap", "symbol", symbol);
	Uci_Set_Str(PKG_SLB_CONFIG, "slb_ap", "cell_id", cell_id);
	Uci_Set_Str(PKG_SLB_CONFIG, "slb_ap", "cp_type", cp_type);
	Uci_Set_Str(PKG_SLB_CONFIG, "slb_ap", "sysmsg_period", sysmsg_period);
	Uci_Set_Str(PKG_SLB_CONFIG, "slb_ap", "s_cfg_idx", s_cfg_idx);
	Uci_Set_Str(PKG_SLB_CONFIG, "slb_ap", "cc_start_pos", cc_start_pos);
	Uci_Commit(PKG_SLB_CONFIG);

	doSystem("killall -9 uspd");
	doSystem("/usr/sbin/first_start_gnode.sh");

	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");
	return CGI_TRUE;
}

CGI_BOOL setSLBAPstop(json_object *request, FILE *conn_fp)
{
	char *ap_enable;
	ap_enable = webs_get_string(request, "ap_enable");
	if (strcmp(ap_enable, "0") == 0) {
		doSystem("killall -9 uspd");
		doSystem("ifconfig vap0 down");
	}
	send_cgi_set_respond(conn_fp, TRUE_W, "", NULL, "0", "reserv");
	return CGI_TRUE;
}

CGI_HANDLE_TABLE system_handle_t[] = {
	{"loginAuth",       loginAuth,       0},
	{"logout",          logout,          1},
	{"RebootSystem",    RebootSystem,    1},
	{"LoadDefSettings", LoadDefSettings, 1},
	{"FirmwareUpgrade", FirmwareUpgrade, 1},
	{"SystemSettings",  SystemSettings,  1},
	{"UploadFirmwareFile",  UploadFirmwareFile,  1},
	{"saveSystemSetting",   saveSystemSetting,   1},

#if defined(CONFIG_CLOUDUPDATE_SUPPORT)
	{"CloudSrvVersionCheck",   CloudSrvVersionCheck,   1},
	{"getCloudDownloadStatus", getCloudDownloadStatus, 1},
	{"getCloudSrvCheckStatus", getCloudSrvCheckStatus, 1},
#endif

	{"getUPnPCfg", 	    getUPnPCfg,      1},
	{"setUPnPCfg", 	    setUPnPCfg,      1},
	{"getRebootScheCfg",  getRebootScheCfg,  1},
	{"setRebootScheCfg",  setRebootScheCfg,  1},
	{"getPasswordCfg",  getPasswordCfg,  1},
	{"setPasswordCfg",  setPasswordCfg,  1},
	{"getNtpCfg",       getNtpCfg,       1},
	{"NTPSyncWithHost", NTPSyncWithHost, 1},
	{"setNtpCfg",	    setNtpCfg,       1},

	{"getDiagnosisCfg",   getDiagnosisCfg,   1},
	{"setDiagnosisCfg",   setDiagnosisCfg,   1},
	{"clearDiagnosisLog", clearDiagnosisLog, 1},
		
	{"getSyslogCfg", 		getSyslogCfg, 		1},
	{"setSyslogCfg",	 	setSyslogCfg, 		1},
	{"clearSyslog",  		clearSyslog, 		1},
	{"showSyslog",   		showSyslog, 		1},

#if defined(CONFIG_CRPC_SUPPORT)
	{"getCrpcCfg",	 		getCrpcCfg,   		0},
	{"getCrpcConfig",     	getCrpcCfg,         0}, //for arpc android APP
#endif

#if defined(APP_IOT_MQTT)	
	{"getIotMCfg", 		getIotMCfg,			1},
	{"setIotMCfg", 		setIotMCfg,			1},
	{"getIotMStateCfg",		getIotMStateCfg,	1},
#endif
	
	{"setAilingCfg",		setAilingCfg,	1},
	{"getAilingCfg",		getAilingCfg,	1},
	{"getAilingStaCfg",		getAilingStaCfg,	1},
	
	{"getSLBApcliScan", getSLBApcliScan, 1},
	{"getSLBstatus", getSLBstatus, 1},
	{"setSLBModeCfg", setSLBModeCfg, 1},
	{"getSLBAPCfg", getSLBAPCfg, 1},
	{"setSLBAPCfg", setSLBAPCfg, 1},
	{"setSLBAPstop", setSLBAPstop, 1},
	{"", NULL, 0},
};
