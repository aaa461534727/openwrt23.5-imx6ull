#include <fcntl.h>
#include <sys/sysinfo.h>


#include "cs_uci.h"
#include "cs_common.h"

#define TMP_LED_SH	"/tmp/tmp_led.sh"

void start_wps_led(void)
{
#if defined(CONFIG_BOARD_IP04499)
	datconf_set_by_key(TEMP_STATUS_FILE, "led_status", "0");
	CsteSystem("echo none  > /sys/class/leds/sys_red/trigger", 0);
	CsteSystem("echo 0	   > /sys/class/leds/sys_red/brightness", 0);

	CsteSystem("echo none > /sys/class/leds/sys_blue/trigger", 0);
	CsteSystem("echo 1 > /sys/class/leds/sys_blue/brightness", 0);
#elif defined(CONFIG_BOARD_IP04509) || defined(CONFIG_BOARD_IP04501)
	CsteSystem("echo none  > /sys/class/leds/mesh_red/trigger", 0);
	CsteSystem("echo 0	   > /sys/class/leds/mesh_red/brightness", 0);

	CsteSystem("echo timer > /sys/class/leds/mesh_blue/trigger", 0);
	CsteSystem("echo 1000  > /sys/class/leds/mesh_blue/delay_on", 0);
	CsteSystem("echo 1000  > /sys/class/leds/mesh_blue/delay_off", 0);
#else
	CsteSystem("echo none > /sys/class/leds/sys/trigger", 0);
	CsteSystem("echo 1 > /sys/class/leds/sys/brightness", 0);
#endif
	return;
}

void stop_wps_led(void)
{

	return;
}

/*系统启动时灯位初始化*/
void led_system_init(void)
{
	int led_status, flash_boot;

	flash_boot = get_cmd_val("cs_ethmac f r");

	Uci_Get_Int(PKG_SYSTEM_CONFIG, "main", "led_status", &led_status);

#if defined(DUAL_SYS_LED)
	if(flash_boot)
	{
		led_self_check();
		return;
	}
#endif
	set_led_status(led_status);
	CsteSystem("/etc/init.d/led restart", 0);
}

/*双色灯在工厂模式下（烧录后未复位前）灯位自检，循环点亮*/
void led_self_check(void)
{
	char cmd[128]={0};
	FILE *fp = NULL;
	fp = fopen(TMP_LED_SH,"w+");

	if(fp)
	{
		fprintf(fp, "%s\n", "#!/bin/sh");

#if defined(CONFIG_BOARD_IP04499)
		fprintf(fp, "%s\n", "echo none > /sys/class/leds/sys_red/trigger");
		fprintf(fp, "%s\n", "echo none > /sys/class/leds/sys_blue/trigger");
		fprintf(fp, "%s\n", "blink=0");
		fprintf(fp, "%s\n", "while [ y=y ]");
		fprintf(fp, "%s\n", "do");
		fprintf(fp, "%s\n", "[ -f /tmp/restore_default ] && break");
		fprintf(fp, "%s\n", "if [ $blink -eq 1 ];then");
		fprintf(fp, "%s\n", "blink=0");
		fprintf(fp, "%s\n", "echo 1       > /sys/class/leds/sys_red/brightness");
		fprintf(fp, "%s\n", "echo 0       > /sys/class/leds/sys_blue/brightness");
		fprintf(fp, "%s\n", "else");
		fprintf(fp, "%s\n", "blink=1");
		fprintf(fp, "%s\n", "echo 0       > /sys/class/leds/sys_red/brightness");
		fprintf(fp, "%s\n", "echo 1       > /sys/class/leds/sys_blue/brightness");
		fprintf(fp, "%s\n", "fi");
		fprintf(fp, "%s\n", "sleep 1");
		fprintf(fp, "%s\n", "done");
#elif defined(CONFIG_BOARD_IP04509) || defined(CONFIG_BOARD_IP04501)
		fprintf(fp, "%s\n", "echo none > /sys/class/leds/sys_blue/trigger");
		fprintf(fp, "%s\n", "echo none > /sys/class/leds/wlan5g/trigger");
		fprintf(fp, "%s\n", "echo none > /sys/class/leds/wlan2g/trigger");
		fprintf(fp, "%s\n", "echo none > /sys/class/leds/usb/trigger");
		fprintf(fp, "%s\n", "echo none > /sys/class/leds/mesh_red/trigger");
		fprintf(fp, "%s\n", "echo none > /sys/class/leds/mesh_blue/trigger");
		fprintf(fp, "%s\n", "blink=0");
		fprintf(fp, "%s\n", "while [ y=y ]");
		fprintf(fp, "%s\n", "do");
		fprintf(fp, "%s\n", "[ -f /tmp/restore_default ] && break");
		fprintf(fp, "%s\n", "if [ $blink -eq 1 ];then");
		fprintf(fp, "%s\n", "blink=0");
		fprintf(fp, "%s\n", "echo 1 	  > /sys/class/leds/mesh_red/brightness");
		fprintf(fp, "%s\n", "echo 0 	  > /sys/class/leds/mesh_blue/brightness");
		fprintf(fp, "%s\n", "echo 0 	  > /sys/class/leds/sys_blue/brightness");
		fprintf(fp, "%s\n", "echo 0 	  > /sys/class/leds/wlan5g/brightness");
		fprintf(fp, "%s\n", "echo 0 	  > /sys/class/leds/wlan2g/brightness");
		fprintf(fp, "%s\n", "echo 0 	  > /sys/class/leds/usb/brightness");
		fprintf(fp, "%s\n", "else");
		fprintf(fp, "%s\n", "blink=1");
		fprintf(fp, "%s\n", "echo 0 	  > /sys/class/leds/mesh_red/brightness");
		fprintf(fp, "%s\n", "echo 1 	  > /sys/class/leds/mesh_blue/brightness");
		fprintf(fp, "%s\n", "echo 1 	  > /sys/class/leds/sys_blue/brightness");
		fprintf(fp, "%s\n", "echo 1 	  > /sys/class/leds/wlan5g/brightness");
		fprintf(fp, "%s\n", "echo 1 	  > /sys/class/leds/wlan2g/brightness");
		fprintf(fp, "%s\n", "echo 1 	  > /sys/class/leds/usb/brightness");
		fprintf(fp, "%s\n", "fi");
		fprintf(fp, "%s\n", "sleep 1");
		fprintf(fp, "%s\n", "done");
#endif
		fclose(fp);
		snprintf(cmd, sizeof(cmd)-1, "chmod 777 %s",TMP_LED_SH);
		system(cmd);
		snprintf(cmd, sizeof(cmd)-1, "%s 1>/dev/null 2>&1 &", TMP_LED_SH);
		system(cmd);
	}
}

void reset_led_blink(void)
{
#if defined(CONFIG_BOARD_IP04499)
	CsteSystem("killall -9 /tmp/tmp_led.sh 1>/dev/null 2>&1", 0);
	CsteSystem("touch /tmp/restore_default", 0);
	CsteSystem("echo none  > /sys/class/leds/sys_red/trigger", 0);
	CsteSystem("echo 0     > /sys/class/leds/sys_red/brightness", 0);

	CsteSystem("echo timer > /sys/class/leds/sys_blue/trigger", 0);
	CsteSystem("echo 100   > /sys/class/leds/sys_blue/delay_on", 0);
	CsteSystem("echo 100   > /sys/class/leds/sys_blue/delay_off", 0);
#elif defined(CONFIG_BOARD_IP04509) || defined(CONFIG_BOARD_IP04501)
	CsteSystem("killall -9 /tmp/tmp_led.sh 1>/dev/null 2>&1", 0);
	CsteSystem("touch /tmp/restore_default", 0);

	CsteSystem("echo timer > /sys/class/leds/sys_blue/trigger", 0);
	CsteSystem("echo 100   > /sys/class/leds/sys_blue/delay_on", 0);
	CsteSystem("echo 100   > /sys/class/leds/sys_blue/delay_off", 0);
#elif defined(CONFIG_BOARD_HW6026)
	CsteSystem("killall -9 /tmp/tmp_led.sh 1>/dev/null 2>&1", 0);
	CsteSystem("touch /tmp/restore_default", 0);

	CsteSystem("echo timer > /sys/class/leds/sys/trigger", 0);
	CsteSystem("echo 100   > /sys/class/leds/sys/delay_on", 0);
	CsteSystem("echo 100   > /sys/class/leds/sys/delay_off", 0);
#else
	CsteSystem("touch /tmp/restore_default", 0);
	CsteSystem("echo timer > /sys/class/leds/sys/trigger", 0);
	CsteSystem("echo 100   > /sys/class/leds/sys/delay_on", 0);
	CsteSystem("echo 100   > /sys/class/leds/sys/delay_off", 0);
#endif
}

void led_batch_upg_success(void)
{
	if(f_exists("/tmp/restore_default"))
	{
		return;
	}

	CsteSystem("touch /tmp/restore_default", 0);

#if defined(CONFIG_BOARD_IP04499)
	CsteSystem("echo none  > /sys/class/leds/sys_blue/trigger", 0);
	CsteSystem("echo none  > /sys/class/leds/sys_red/trigger", 0);
	while(1)
	{
		CsteSystem("echo 1     > /sys/class/leds/sys_blue/brightness", 0);
		CsteSystem("echo 0     > /sys/class/leds/sys_red/brightness", 0);
		usleep(100000);//0.1s
		CsteSystem("echo 0     > /sys/class/leds/sys_blue/brightness", 0);
		CsteSystem("echo 1    > /sys/class/leds/sys_red/brightness", 0);
		usleep(100000);//0.1s
		CsteSystem("echo 1     > /sys/class/leds/sys_blue/brightness", 0);
		CsteSystem("echo 0     > /sys/class/leds/sys_red/brightness", 0);
		usleep(100000);//0.1s
	}
#elif defined(CONFIG_BOARD_IP04509) || defined(CONFIG_BOARD_IP04501)
	CsteSystem("echo none  > /sys/class/leds/mesh_blue/trigger", 0);
	CsteSystem("echo none  > /sys/class/leds/mesh_red/trigger", 0);
	while(1)
	{
		CsteSystem("echo 1     > /sys/class/leds/mesh_blue/brightness", 0);
		CsteSystem("echo 0     > /sys/class/leds/mesh_red/brightness", 0);
		usleep(100000);//0.1s
		CsteSystem("echo 0     > /sys/class/leds/mesh_blue/brightness", 0);
		CsteSystem("echo 1    > /sys/class/leds/mesh_red/brightness", 0);
		usleep(100000);//0.1s
		CsteSystem("echo 1     > /sys/class/leds/mesh_blue/brightness", 0);
		CsteSystem("echo 0     > /sys/class/leds/mesh_red/brightness", 0);
		usleep(100000);//0.1s
	}
#endif

}

void set_led_status(int led_status)
{
	if(led_status == 1)
	{
#if defined(CONFIG_BOARD_IP04499) || defined(CONFIG_BOARD_IP04509) || defined(CONFIG_BOARD_IP04501) || defined(CONFIG_BOARD_HW6026)
		datconf_set_by_key(TEMP_STATUS_FILE, "led_status", "0");
#if defined(CONFIG_BOARD_HW6026)
		CsteSystem("echo timer > /sys/class/leds/sys/trigger", 0);
		CsteSystem("echo 1000  > /sys/class/leds/sys/delay_on", 0);
		CsteSystem("echo 1000  > /sys/class/leds/sys/delay_off", 0);

		CsteSystem("echo 1	> /sys/class/leds/link/brightness", 0);
		CsteSystem("echo 1	> /sys/class/leds/wlan2g/brightness", 0);
		CsteSystem("echo 1	> /sys/class/leds/wlan5g/brightness", 0);
#endif

#if defined(CONFIG_BOARD_IP04509) || defined(CONFIG_BOARD_IP04501)
		CsteSystem("echo timer > /sys/class/leds/sys_blue/trigger", 0);
		CsteSystem("echo 1000  > /sys/class/leds/sys_blue/delay_on", 0);
		CsteSystem("echo 1000  > /sys/class/leds/sys_blue/delay_off", 0);

		CsteSystem("echo none  > /sys/class/leds/mesh_blue/trigger", 0);
		CsteSystem("echo none  > /sys/class/leds/mesh_red/trigger", 0);
		if(get_cmd_val("block info | grep /dev/sd | wc -l")==0)
		{
			CsteSystem("echo 0 > /sys/class/leds/usb/brightness", 0);
		}
		else
		{
			CsteSystem("echo 1 > /sys/class/leds/usb/brightness", 0);
		}
#endif
		/* reset wan port led */
		CsteSystem("/etc/init.d/led restart", 0);

		//CsteSystem("switch reg w 7c00 1462000");
		CsteSystem("switch reg w 7c10 11111111 > /dev/null", 0);
		CsteSystem("switch reg w 7c14 11110110 > /dev/null", 0);
		CsteSystem("switch reg w 7c18 111 > /dev/null", 0);

#elif defined(CONFIG_BOARD_HW7037)
		CsteSystem("echo timer > /sys/class/leds/sys/trigger", 0);
		CsteSystem("echo 1000  > /sys/class/leds/sys/delay_on", 0);
		CsteSystem("echo 1000  > /sys/class/leds/sys/delay_off", 0);

#elif defined(CONFIG_BOARD_HW7036)
		CsteSystem("echo timer > /sys/class/leds/sys/trigger", 0);
		CsteSystem("echo 1000  > /sys/class/leds/sys/delay_on", 0);
		CsteSystem("echo 1000  > /sys/class/leds/sys/delay_off", 0);

		if(f_read_int("/tmp/linkInternet") == 1)
		{
			CsteSystem("echo none  > /sys/class/leds/link/trigger", 0);
			CsteSystem("echo 1	   > /sys/class/leds/link/brightness", 0);
		}

		

#else //defined(CONFIG_BOARD_IP04499)
		CsteSystem("echo timer > /sys/class/leds/sys/trigger", 0);
		CsteSystem("echo 1000  > /sys/class/leds/sys/delay_on", 0);
		CsteSystem("echo 1000  > /sys/class/leds/sys/delay_off", 0);

#endif //defined(CONFIG_BOARD_IP04499)
	}
	else
	{
#if defined(CONFIG_BOARD_IP04499)  || defined(CONFIG_BOARD_IP04509)  || defined(CONFIG_BOARD_IP04501)

#if defined(CONFIG_BOARD_IP04509) || defined(CONFIG_BOARD_IP04501)
		CsteSystem("echo none  > /sys/class/leds/wlan2g/trigger", 0);
		CsteSystem("echo 0 > /sys/class/leds/wlan2g/brightness", 0);

		CsteSystem("echo none  > /sys/class/leds/wlan5g/trigger", 0);
		CsteSystem("echo 0 > /sys/class/leds/wlan5g/brightness", 0);

		CsteSystem("echo none  > /sys/class/leds/usb/trigger", 0);
		CsteSystem("echo 0 > /sys/class/leds/usb/brightness", 0);

		CsteSystem("echo none  > /sys/class/leds/mesh_blue/trigger", 0);
		CsteSystem("echo 0 > /sys/class/leds/mesh_blue/brightness", 0);

		CsteSystem("echo none  > /sys/class/leds/mesh_red/trigger", 0);
		CsteSystem("echo 0 > /sys/class/leds/mesh_red/brightness", 0);
#else
		CsteSystem("echo none  > /sys/class/leds/sys_red/trigger", 0);
		CsteSystem("echo 0     > /sys/class/leds/sys_red/brightness", 0);
#endif
		CsteSystem("echo none  > /sys/class/leds/sys_blue/trigger", 0);
		CsteSystem("echo 0    > /sys/class/leds/sys_blue/brightness", 0);

		/* close wan port led */
		CsteSystem("echo 0 > /sys/class/leds/wan/brightness", 0);

		/* close port0-port4 led */
		CsteSystem("switch reg w 7c00 1462000", 0);
		CsteSystem("switch reg w 7c10 11011111", 0);
		CsteSystem("switch reg w 7c14 10110000", 0);
		CsteSystem("switch reg w 7c18 110", 0);
		CsteSystem("switch reg w 7c04 1462000", 0);

#elif defined(CONFIG_BOARD_HW7037)
		CsteSystem("echo none  > /sys/class/leds/wlan2g/trigger", 0);
		CsteSystem("echo 0 > /sys/class/leds/wlan2g/brightness", 0);

		CsteSystem("echo none  > /sys/class/leds/wlan5g/trigger", 0);
		CsteSystem("echo 0 > /sys/class/leds/wlan5g/brightness", 0);

		CsteSystem("echo none  > /sys/class/leds/sys/trigger", 0);
		CsteSystem("echo 0 > /sys/class/leds/sys/brightness", 0);

		CsteSystem("echo none  > /sys/class/leds/link/trigger", 0);
		CsteSystem("echo 0 > /sys/class/leds/link/brightness", 0);

#elif defined(CONFIG_BOARD_HW6026)
		CsteSystem("echo none  > /sys/class/leds/wlan2g/trigger", 0);
		CsteSystem("echo 0 > /sys/class/leds/wlan2g/brightness", 0);

		CsteSystem("echo none  > /sys/class/leds/wlan5g/trigger", 0);
		CsteSystem("echo 0 > /sys/class/leds/wlan5g/brightness", 0);

		CsteSystem("echo none  > /sys/class/leds/sys/trigger", 0);
		CsteSystem("echo 0 > /sys/class/leds/sys/brightness", 0);

		CsteSystem("echo none  > /sys/class/leds/link/trigger", 0);
		CsteSystem("echo 0 > /sys/class/leds/link/brightness", 0);

		CsteSystem("switch reg w 7c00 1462000", 0);
		CsteSystem("switch reg w 7c10 11011111", 0);
		CsteSystem("switch reg w 7c14 10110000", 0);
		CsteSystem("switch reg w 7c18 110", 0);
		CsteSystem("switch reg w 7c04 1462000", 0);

#elif defined(CONFIG_BOARD_HW7036)
		datconf_set_by_key(TEMP_STATUS_FILE, "led_status", "0");
		datconf_set_by_key(TEMP_STATUS_FILE, "wlan2g_led_status", "0");
		datconf_set_by_key(TEMP_STATUS_FILE, "wlan5g_led_status", "0");

		CsteSystem("echo none  > /sys/class/leds/wlan2g/trigger", 0);
		CsteSystem("echo 0 > /sys/class/leds/wlan2g/brightness", 0);

		CsteSystem("echo none  > /sys/class/leds/wlan5g/trigger", 0);
		CsteSystem("echo 0 > /sys/class/leds/wlan5g/brightness", 0);

		CsteSystem("echo none  > /sys/class/leds/sys/trigger", 0);
		CsteSystem("echo 0 > /sys/class/leds/sys/brightness", 0);

		CsteSystem("echo none  > /sys/class/leds/link/trigger", 0);
		CsteSystem("echo 0 > /sys/class/leds/link/brightness", 0);
#else
		CsteSystem("echo none  > /sys/class/leds/sys/trigger", 0);
		CsteSystem("echo 0 > /sys/class/leds/sys/brightness", 0);
#endif

	}
}

#if defined(CONFIG_BOARD_IP04509) || defined(CONFIG_BOARD_IP04501)
void mesh_led_control(void)
{
	char map_mode[8]={0},devicerole[8]={0},wps_onboarding_trigger_flag[8]={0}, conn_status[16]={0};
	int dev_role=0, ret=0,  agent_rssi=0;

	wificonf_get_by_key(W58G_MH,"mapmode",map_mode,sizeof(map_mode));

	if(atoi(map_mode)!=1)//mesh is off
	{
		if(f_read_int("/sys/class/leds/mesh_blue/brightness")!=0)
		{
			CsteSystem("echo 0     > /sys/class/leds/mesh_blue/brightness", 0);
		}

		if(f_read_int("/sys/class/leds/mesh_red/brightness")!=0)
		{
			CsteSystem("echo 0     > /sys/class/leds/mesh_red/brightness", 0);
		}
	}
	else
	{
		datconf_get_by_key(TEMP_STATUS_FILE, "wps_onboarding_trigger_flag", wps_onboarding_trigger_flag,sizeof(wps_onboarding_trigger_flag));
		if(atoi(wps_onboarding_trigger_flag)==1)
		{
			return;
		}

		wificonf_get_by_key(W58G_MH, "devicerole", devicerole, sizeof(devicerole));

		dev_role=atoi(devicerole);

		if(dev_role==DEV_AUTO)
		{
			get_mesh_current_device_role(&dev_role);
		}

		if(dev_role==DEV_CONTROLLER)
		{
			if(f_read_int("/sys/class/leds/mesh_red/brightness")!=0)
			{
				CsteSystem("echo 0     > /sys/class/leds/mesh_red/brightness", 0);
			}
			ret=get_mesh_agent_count();
			if(ret>1)
			{
				if(f_read_int("/sys/class/leds/mesh_blue/brightness")!=1)
				{
					CsteSystem("echo 1 > /sys/class/leds/mesh_blue/brightness", 0);
				}
			}
			else
			{
				if(f_read_int("/sys/class/leds/mesh_blue/brightness")!=0)
				{
					CsteSystem("echo 0  > /sys/class/leds/mesh_blue/brightness", 0);
				}
			}
		}
		else //DEV_AGENT
		{
			ret=get_mesh_status(conn_status, sizeof(conn_status));
			if(ret!=1)
			{
				if(f_read_int("/sys/class/leds/mesh_red/brightness")!=0)
				{
					CsteSystem("echo 0     > /sys/class/leds/mesh_red/brightness", 0);
				}

				if(f_read_int("/sys/class/leds/mesh_blue/brightness")!=0)
				{
					CsteSystem("echo 0     > /sys/class/leds/mesh_blue/brightness", 0);
				}
			}
			else
			{
#if 0
				agent_rssi=get_mesh_agent_rssi();
				if(agent_rssi>-60)
				{
					if(f_read_int("/sys/class/leds/mesh_red/brightness")!=0)
					{
						CsteSystem("echo 0     > /sys/class/leds/mesh_red/brightness", 0);
					}

					if(f_read_int("/sys/class/leds/mesh_blue/brightness")!=1)
					{
						CsteSystem("echo 1     > /sys/class/leds/mesh_blue/brightness", 0);
					}
				}
				else if(agent_rssi<=-60 && agent_rssi>-75)
				{
					if(f_read_int("/sys/class/leds/mesh_red/brightness")!=1)
					{
						CsteSystem("echo 1     > /sys/class/leds/mesh_red/brightness", 0);
					}

					if(f_read_int("/sys/class/leds/mesh_blue/brightness")!=1)
					{
						CsteSystem("echo 1     > /sys/class/leds/mesh_blue/brightness", 0);
					}
				}
				else
				{
					if(f_read_int("/sys/class/leds/mesh_red/brightness")!=1)
					{
						CsteSystem("echo 1     > /sys/class/leds/mesh_red/brightness", 0);
					}

					if(f_read_int("/sys/class/leds/mesh_blue/brightness")!=0)
					{
						CsteSystem("echo 0     > /sys/class/leds/mesh_blue/brightness", 0);
					}
				}
#endif
				if(f_read_int("/sys/class/leds/mesh_blue/brightness")!=1)
				{
					CsteSystem("echo 1 > /sys/class/leds/mesh_blue/brightness", 0);
				}
			}
		}
	}
}
#endif

//一些状态灯位需要在定时器里进行控制
void schedule_led_control()
{
	int led_status, flash_boot;
	char led_status_buf[8], wps_onboarding_trigger_flag[8]={0};
	char wlan2g_led_status[8],wlan5g_led_status[8], wlan_cmd[64]={0};
	
	flash_boot = get_cmd_val("cs_ethmac f r");

	Uci_Get_Int(PKG_SYSTEM_CONFIG, "main", "led_status", &led_status);

	datconf_get_by_key(TEMP_STATUS_FILE, "wps_onboarding_trigger_flag", wps_onboarding_trigger_flag, sizeof(wps_onboarding_trigger_flag));

	if(flash_boot || led_status==0 || atoi(wps_onboarding_trigger_flag)==1 || f_exists("/tmp/restore_default") || !f_exists("/var/cste/start_ok"))
	{
		return;
	}

#if defined(CONFIG_BOARD_IP04509) || defined(CONFIG_BOARD_IP04501)
	mesh_led_control();
#else

	datconf_get_by_key(TEMP_STATUS_FILE, "led_status", led_status_buf, sizeof(led_status_buf));

	if(f_read_int("/tmp/linkInternet") == 1)
	{
		if(atoi(led_status_buf) == 1)
		{
			goto wifi_leds;
		}

		datconf_set_by_key(TEMP_STATUS_FILE, "led_status", "1");
		
#if defined(CONFIG_BOARD_IP04499)
	CsteSystem("echo none  > /sys/class/leds/sys_red/trigger", 0);
	CsteSystem("echo 0	   > /sys/class/leds/sys_red/brightness", 0);

	CsteSystem("echo timer > /sys/class/leds/sys_blue/trigger", 0);
	CsteSystem("echo 1000  > /sys/class/leds/sys_blue/delay_on", 0);
	CsteSystem("echo 1000  > /sys/class/leds/sys_blue/delay_off", 0);
#elif defined(CONFIG_BOARD_HW7036)
	CsteSystem("echo none  > /sys/class/leds/link/trigger", 0);
	CsteSystem("echo 1	   > /sys/class/leds/link/brightness", 0);	
#else

#endif
	}else{

		if(atoi(led_status_buf) == 2)
		{
			goto wifi_leds;
		}

		datconf_set_by_key(TEMP_STATUS_FILE, "led_status", "2");

#if defined(CONFIG_BOARD_IP04499)
	CsteSystem("echo none  > /sys/class/leds/sys_blue/trigger", 0);
	CsteSystem("echo 0	  > /sys/class/leds/sys_blue/brightness", 0);

	CsteSystem("echo timer > /sys/class/leds/sys_red/trigger", 0);
	CsteSystem("echo 1000  > /sys/class/leds/sys_red/delay_on", 0);
	CsteSystem("echo 1000  > /sys/class/leds/sys_red/delay_off", 0);
#elif defined(CONFIG_BOARD_HW7036)
	CsteSystem("echo none  > /sys/class/leds/link/trigger", 0);
	CsteSystem("echo 0	   > /sys/class/leds/link/brightness", 0);		
#else

#endif
	}
	
#endif


wifi_leds:
#if defined(CONFIG_BOARD_HW7036)
	datconf_get_by_key(TEMP_STATUS_FILE, "wlan2g_led_status", wlan2g_led_status, sizeof(wlan2g_led_status));
	datconf_get_by_key(TEMP_STATUS_FILE, "wlan5g_led_status", wlan5g_led_status, sizeof(wlan5g_led_status));

	if( atoi(wlan2g_led_status)!=(is_ssid_disabled(W24G_IF)+1) )
	{
		datconf_set_ival(TEMP_STATUS_FILE, "wlan2g_led_status", is_ssid_disabled(W24G_IF)+1);

		snprintf(wlan_cmd, sizeof(wlan_cmd), "echo %d > /sys/class/leds/wlan2g/brightness", !is_ssid_disabled(W24G_IF));
		CsteSystem("echo none  > /sys/class/leds/wlan2g/trigger", 0);
		CsteSystem(wlan_cmd, 0);		
	}


	if( atoi(wlan5g_led_status)!=(is_ssid_disabled(W58G_IF)+1) )
	{
		datconf_set_ival(TEMP_STATUS_FILE, "wlan5g_led_status", is_ssid_disabled(W58G_IF)+1);

		snprintf(wlan_cmd, sizeof(wlan_cmd), "echo %d > /sys/class/leds/wlan5g/brightness", !is_ssid_disabled(W58G_IF));
		CsteSystem("echo none  > /sys/class/leds/wlan5g/trigger", 0);
		CsteSystem(wlan_cmd, 0);		
	}
#endif
	return ;
}

#if defined(CONFIG_THINAP_SUPPORT)
void thinap_led_breath()
{
	datconf_set_by_key(TEMP_STATUS_FILE, "led_ac_set", "1");

	CsteSystem("echo none  > /sys/class/leds/sys_white/trigger", 0);
	CsteSystem("echo 0	   > /sys/class/leds/sys_white/brightness", 0);

	CsteSystem("echo timer > /sys/class/leds/sys_blue/trigger", 0);
	CsteSystem("echo 1000  > /sys/class/leds/sys_blue/delay_on", 0);
	CsteSystem("echo 1000  > /sys/class/leds/sys_blue/delay_off", 0);

	return;
}

void thinap_led_always_on()
{
	datconf_set_by_key(TEMP_STATUS_FILE, "led_ac_set", "1");

	CsteSystem("echo none  > /sys/class/leds/sys_white/trigger", 0);
	CsteSystem("echo 0	   > /sys/class/leds/sys_white/brightness", 0);

	CsteSystem("echo none > /sys/class/leds/sys_blue/trigger", 0);
	CsteSystem("echo 1    > /sys/class/leds/sys_blue/brightness", 0);

	return;
}
void thinap_led_shut_down()
{
	datconf_set_by_key(TEMP_STATUS_FILE, "led_ac_set", "1");

	CsteSystem("echo none  > /sys/class/leds/sys_white/trigger", 0);
	CsteSystem("echo 0	   > /sys/class/leds/sys_white/brightness", 0);

	CsteSystem("echo none > /sys/class/leds/sys_blue/trigger", 0);
	CsteSystem("echo 0    > /sys/class/leds/sys_blue/brightness", 0);

	return;
}
#endif


