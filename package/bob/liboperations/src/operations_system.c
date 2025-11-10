#define _GNU_SOURCE         1/* See feature_test_macros(7) */
#include <string.h>
#include "operations_common.h"


#if defined(CONFIG_CLOUDUPDATE_SUPPORT)
int forced_cloud_upgrade(void)
{
	int upgrade_status = UPG_LATEST;

	char skip_cloudupg_check[8]={0};

	datconf_get_by_key(TEMP_STATUS_FILE, "skip_cloudupg_check", skip_cloudupg_check, sizeof(skip_cloudupg_check));

	//only first connet internet need to check cloud upgrade
	if(atoi(skip_cloudupg_check) !=1 && upgrade_status!=UPG_CHECKING && upgrade_status!=UPG_FORCE_UPGRADEING)
	{
		datconf_set_by_key(TEMP_STATUS_FILE, "forced_cloudupg_check", "1");
	}

	return OPERATIONS_TRUE;
}


OPERATIONS_BOOL CsRealReloadAutoFwUpgrade(void)
{
	char cmd_buff[LONG_BUFF_LEN]= {0};

	snprintf(cmd_buff,LONG_BUFF_LEN,"%s &",AUTOUPDATE_SH);
	CsteSystem(cmd_buff, CSTE_PRINT_CMD);

	return OPERATIONS_TRUE;
}


OPERATIONS_BOOL CsRealCloudUpgadeCheck(void)
{
	CsteSystem("/usr/sbin/cloudupdate_check &", CSTE_PRINT_CMD);

	return OPERATIONS_TRUE;
}
#endif

OPERATIONS_BOOL CsRealUploadSettings(void)
{
	int iPid                          =  0;
	char cmd[128]                     = { 0 };
	char tmp_file[128]={0};

	datconf_get_by_key(TEMP_STATUS_FILE, "upload_settings_path", tmp_file,sizeof(tmp_file));

	sprintf(cmd, "tar zxvf %s  -C /", tmp_file);
	if(0 != CsteSystem(cmd, CSTE_PRINT_CMD))
	{
		printf(" invalid gzip magic\n");
		goto err;	
	}

	CsteSystem("reboot ", 0);
	
    return OPERATIONS_TRUE;
	
err:
	unlink(tmp_file);

	return OPERATIONS_FALSE;
}

int download_firmware()
{
	int ret=0,retry=0;

	char cmd[512] = {0}, url[256] = {0}, magicid[64] = {0}, dlmagicid[64] = {0};

	Uci_Get_Str(PKG_CLOUDUPDATE_CONFIG, "cloudupdate", "url", url);
	Uci_Get_Str(PKG_CLOUDUPDATE_CONFIG, "cloudupdate", "magicid", magicid);

	if(strlen(url) < 10)
	{
		return -1;
	}

	datconf_set_by_key(TEMP_STATUS_FILE, "download_status", "1");//downloading

retry_download:

	snprintf(cmd, sizeof(cmd), "wget -O %s  %s", DL_IMAGE_FILE, url);
	CsteSystem(cmd, CSTE_PRINT_CMD);

	snprintf(cmd, sizeof(cmd),"md5sum %s | cut -d ' ' -f1",DL_IMAGE_FILE);
	get_cmd_result(cmd, dlmagicid, sizeof(dlmagicid));

	if(strcmp(magicid, dlmagicid)!=0)
	{
		if(retry<2)
		{
			retry+=1;
			goto retry_download;
		}
		else
		{
			ret=-1;
		}
	}

	return ret;
}


OPERATIONS_BOOL CsRealReloadFwUpgrade(void)
{
	struct stat st ;
	int  vendor_code = 1, flash_size = 0;
	char ugrade_firmware[LIST_STR_LEN] = { 0 }, is_reset[8] = { 0 };
	char cmd_buff[LONG_BUFF_LEN]= {0}, tmpbuf[RESULT_STR_LEN] = {0};
	char role[8] = {0};
	int config_devrole;

	datconf_get_by_key(TEMP_STATUS_FILE, "ugrade_firmware", ugrade_firmware, sizeof(ugrade_firmware));
	datconf_get_by_key(TEMP_STATUS_FILE, "ugrade_reset", is_reset, sizeof(is_reset));

	if(strlen(ugrade_firmware) == 0)
	{
		strcpy(ugrade_firmware, DL_IMAGE_FILE);
		if(download_firmware() == 0)
		{
			datconf_set_by_key(TEMP_STATUS_FILE, "download_status", "2");//success
		}
		else
		{
			datconf_set_by_key(TEMP_STATUS_FILE, "download_status", "3");//fail
		}

		flash_size = get_flash_total_size();

		if(flash_size == 0)
		{
			return OPERATIONS_FALSE;
		}

		stat(ugrade_firmware, &st );
		if(st.st_size > flash_size * 1024 * 1024 || st.st_size < 1)
		{
			return OPERATIONS_FALSE;
		}


		datconf_get_by_key(MAPD_USER_CONF_FILE, "DeviceRole", role, sizeof(role));
		config_devrole = atoi(role);
		if(config_devrole == DEV_AUTO)
		{
			get_mesh_current_device_role(&config_devrole);
			if(config_devrole==0)//when get role fail default show as controller
			{
				config_devrole=DEV_CONTROLLER;
			}
		}
		
		if(config_devrole == DEV_CONTROLLER){
			char upgrade_action[8] = {0};
			datconf_set_by_key(TEMP_STATUS_FILE, "mesh_update", "1");
			datconf_set_by_key(TEMP_STATUS_FILE, "ugrade_firmware", "/tmp/cloudupdate.web");

			datconf_get_by_key(TEMP_STATUS_FILE, "upgrade_action", upgrade_action, sizeof(upgrade_action));
			if(atoi(upgrade_action) ==2)
				datconf_set_by_key(TEMP_STATUS_FILE, "only_up_agent", "2");
			
			//return OPERATIONS_TRUE;
		}

	}

	Uci_Get_Str(PKG_VENDOR_INFO, "sys", "vendor_code", tmpbuf);
	vendor_code = atoi(tmpbuf);
	vendor_code += 1;
	memset(tmpbuf, 0, sizeof(tmpbuf));
	sprintf(tmpbuf, "%d", vendor_code);

	Uci_Set_Str(PKG_VENDOR_INFO, "sys", "vendor_code", tmpbuf);
	Uci_Commit(PKG_VENDOR_INFO);

	switch(atoi(is_reset))
	{
		case 1:  /*do not keep settings*/
			snprintf(cmd_buff,LONG_BUFF_LEN,"/sbin/sysupgrade -n %s",ugrade_firmware);
			break;
		case 2: /*keep network settings*/
			snprintf(cmd_buff,LONG_BUFF_LEN,"/sbin/sysupgrade -N %s",ugrade_firmware);
			break;
		case 0:  /*keep all settings*/
		default:
			snprintf(cmd_buff,LONG_BUFF_LEN,"/sbin/sysupgrade %s",   ugrade_firmware);
			break;
	}

	CsteSystem(cmd_buff, 0);
	
	return OPERATIONS_TRUE;
}

#if defined(CONFIG_USER_NETCWMP)
OPERATIONS_BOOL CsReloadStun(void)
{
	CsteSystem("rm -f /tmp/cste/stun", CSTE_PRINT_CMD);
	CsteSystem("/etc/init.d/stund restart", CSTE_PRINT_CMD);
	
	return OPERATIONS_TRUE;
}
#endif

#if defined(APP_IOT_MQTT)
OPERATIONS_BOOL CsRealReloadIotMqtt(void)
{
    int enable=0;
    Uci_Get_Int(PKG_IOT_CONFIG, "iotm", "enable", &enable);
    CsteSystem("killall -9 iotm", CSTE_PRINT_CMD);

    if(enable)
            CsteSystem("/usr/sbin/iotm &", CSTE_PRINT_CMD);
}
#endif


OPERATIONS_BOOL CsRealReloadAilingMqtt(void)
{
    int enable=0;
    Uci_Get_Int(PKG_AILING_CONFIG, "iotm", "enable", &enable);
    CsteSystem("/etc/init.d/ailing-mqtt stop &", CSTE_PRINT_CMD);

    if(enable)
            CsteSystem("/etc/init.d/ailing-mqtt start &", CSTE_PRINT_CMD);
}



OPERATIONS_BOOL CsRealReloadGnote(void)
{
    CsteSystem("/usr/sbin/first_start_gnode.sh", CSTE_PRINT_CMD);
}


