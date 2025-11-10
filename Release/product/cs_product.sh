#!/bin/sh
LOCALDIR=$(cd "$(dirname "$0")";pwd)
PACKAGESFILES=$LOCALDIR/../../files

SVN_TMP=`git rev-list HEAD --count 2>/dev/null`
PRODUCT_SVN=$(expr ${SVN_TMP} - 51000)
BUILD_TIME=`date "+%b %d %Y %k:%M:%S"`
BUILD_DATE=`date "+%Y-%m-%d"`
SRC_BRANCH=`git branch -vv |grep "*" |awk '{print $2}'`
COMMIT_ID=`git rev-parse --short HEAD`

CONFIG=$LOCALDIR/../../.config
CONFIG_DEFAULT_FLAG=$PACKAGESFILES/etc/config/restoredefault

TARGET_CSID=`cat $CONFIG | grep CONFIG_KL_CSID |  cut -d "=" -f2 | cut -d "\"" -f2`
echo TARGET_CSID=$TARGET_CSID

#default files
rm -rf $PACKAGESFILES
mkdir $PACKAGESFILES

echo "CSID:$TARGET_CSID"
if [ -d Release/def_files/$TARGET_CSID ]; then

cp  -rf Release/def_files/$TARGET_CSID/* files

#mkdir dir
mkdir -p $PACKAGESFILES/lib
mkdir -p $PACKAGESFILES/etc/config

#Load Custom config
if [ -f Release/Nologo ]; then
. $LOCALDIR/def_product/${TARGET_CSID}_Nologo_config
else
. $LOCALDIR/def_product/${TARGET_CSID}_config
fi

#Load compile config
. $CONFIG

#/etc/config/product
PRODUCT_CONFIG=$PACKAGESFILES/etc/product
echo 'config product sysinfo' > $PRODUCT_CONFIG
echo '       option soft_version  '\'${soft_version}${uboot_upg}\' >> $PRODUCT_CONFIG
echo '       option soft_model    '\'${soft_model}\' >> $PRODUCT_CONFIG
echo '       option hard_model    '\'${hard_model}\' >> $PRODUCT_CONFIG
echo '       option hard_version  '\'${hard_version}\' >> $PRODUCT_CONFIG
echo '       option build_time    '\'${BUILD_TIME}\' >> $PRODUCT_CONFIG
echo '       option build_date    '\'${BUILD_DATE}\' >> $PRODUCT_CONFIG
echo '       option svn_num       '\'${PRODUCT_SVN}\' >> $PRODUCT_CONFIG
echo '       option branch        '\'${SRC_BRANCH}\' >> $PRODUCT_CONFIG
echo '       option commitid      '\'${COMMIT_ID}\' >> $PRODUCT_CONFIG
echo '       option flash_type    '\'${flash_type}\' >> $PRODUCT_CONFIG

echo ' ' >> $PRODUCT_CONFIG
echo 'config product custom' >> $PRODUCT_CONFIG
echo '       option csid           '\'${csid}\' >> $PRODUCT_CONFIG
echo '       option hostname       '\'${hostname}\' >> $PRODUCT_CONFIG
echo '       option hide_logo      '\'${HideLogo}\' >> $PRODUCT_CONFIG
#logo
echo '       option web_title              '\'${web_title}\' >> $PRODUCT_CONFIG
echo '       option vendor                 '\'${vendor}\' >> $PRODUCT_CONFIG
echo '       option domainaccess           '\'${domainaccess}\' >> $PRODUCT_CONFIG
echo '       option copyright              '\'${copyright}\' >> $PRODUCT_CONFIG
echo '       option helpurl_cn             '\'${helpurl_cn}\' >> $PRODUCT_CONFIG
echo '       option helpurl_en             '\'${helpurl_en}\' >> $PRODUCT_CONFIG
echo '       option helpurl_ct             '\'${helpurl_ct}\' >> $PRODUCT_CONFIG
echo '       option helpurl_vi             '\'${helpurl_vi}\' >> $PRODUCT_CONFIG
echo '       option helpurl_vn             '\'${helpurl_vn}\' >> $PRODUCT_CONFIG
echo '       option helpurl_ru             '\'${helpurl_ru}\' >> $PRODUCT_CONFIG
echo '       option helpurl_br             '\'${helpurl_br}\' >> $PRODUCT_CONFIG
#upnp
echo '       option model_name             '\'${model_name}\' >> $PRODUCT_CONFIG
echo '       option manufacturer           '\'${manufacturer}\' >> $PRODUCT_CONFIG
echo '       option model_url              '\'${model_url}\' >> $PRODUCT_CONFIG
echo '       option manufacturer_url       '\'${manufacturer_url}\' >> $PRODUCT_CONFIG
echo '       option manufacturer_name      '\'${manufacturer_name}\' >> $PRODUCT_CONFIG
#service
echo '       option cloudupdate_domain      '\'${cloudupdate_domain}\' >> $PRODUCT_CONFIG
#network
echo '       option wan_type_list          '\'${wan_type_list}\' >> $PRODUCT_CONFIG
echo '       option wan_strategy_list       '\'${wan_strategy_list}\' >> $PRODUCT_CONFIG
echo '       option wan_strategy_def       '\'${wan_strategy_def}\' >> $PRODUCT_CONFIG
echo '       option wan_strategy_flash       '\'${wan_strategy_flash}\' >> $PRODUCT_CONFIG
echo '       option wan_type_default       '\'${wan_type_default}\' >> $PRODUCT_CONFIG
echo '       option lan_ipaddr             '\'${lan_ipaddr}\' >> $PRODUCT_CONFIG
echo '       option lan_netmask            '\'${lan_netmask}\' >> $PRODUCT_CONFIG
echo '       option lan_proto              '\'${lan_proto}\' >> $PRODUCT_CONFIG
echo '       option dhcp_start             '\'${dhcpd_start}\' >> $PRODUCT_CONFIG
echo '       option dhcp_end               '\'${dhcpd_end}\' >> $PRODUCT_CONFIG
echo '       option dhcp_leasetime         '\'${dhcpd_leasetime}\' >> $PRODUCT_CONFIG
echo '       option pridns                 '\'${pridns}\' >> $PRODUCT_CONFIG
echo '       option secdns                 '\'${secdns}\' >> $PRODUCT_CONFIG
echo '       option spi_firewall           '\'${spi_firewall}\' >> $PRODUCT_CONFIG
#wifi
echo '       option country_list           '\'${country_list}\' >> $PRODUCT_CONFIG
echo '       option fixed_mac              '\'${fixed_mac}\' >> $PRODUCT_CONFIG
echo '       option ssid_2g                '\'${ssid_2g}\' >> $PRODUCT_CONFIG
echo '       option ssid_tail_2g           '\'${ssid_tail_2g}\' >> $PRODUCT_CONFIG
echo '       option wlankey_2g             '\'${wlankey_2g}\' >> $PRODUCT_CONFIG
echo '       option country_2g             '\'${country_2g}\' >> $PRODUCT_CONFIG
echo '       option hwmode_2g              '\'${hwmode_2g}\' >> $PRODUCT_CONFIG
echo '       option htmode_2g              '\'${htmode_2g}\' >> $PRODUCT_CONFIG
echo '       option channel_2g             '\'${channel_2g}\' >> $PRODUCT_CONFIG
echo '       option maxsta_2g              '\'${maxsta_2g}\' >> $PRODUCT_CONFIG
echo '       option ssid_5g                '\'${ssid_5g}\' >> $PRODUCT_CONFIG
echo '       option ssid_tail_5g           '\'${ssid_tail_5g}\' >> $PRODUCT_CONFIG
echo '       option wlankey_5g             '\'${wlankey_5g}\' >> $PRODUCT_CONFIG
echo '       option country_5g             '\'${country_5g}\' >> $PRODUCT_CONFIG
echo '       option hwmode_5g              '\'${hwmode_5g}\' >> $PRODUCT_CONFIG
echo '       option htmode_5g              '\'${htmode_5g}\' >> $PRODUCT_CONFIG
echo '       option channel_5g             '\'${channel_5g}\' >> $PRODUCT_CONFIG
echo '       option maxsta_5g              '\'${maxsta_5g}\' >> $PRODUCT_CONFIG
echo '       option wifiEncryptSupport     '\'${wifiEncryptSupport}\' >> $PRODUCT_CONFIG
echo '       option wifiRadiusSupport      '\'${wifiRadiusSupport}\' >> $PRODUCT_CONFIG
echo '       option wifiWepSupport         '\'${wifiWepSupport}\' >> $PRODUCT_CONFIG
echo '       option wifiWpa3Support        '\'${wifiWpa3Support}\' >> $PRODUCT_CONFIG
#modem
echo '       option mcm_sms_mode 	   '\'${mcm_sms_mode}\' >> $PRODUCT_CONFIG
echo '       option modem_netcustom_list   '\'${modem_netcustom_list}\' >> $PRODUCT_CONFIG
echo '       option modem_mode '\'${modem_mode}\' >> $PRODUCT_CONFIG

#xxSupport
echo '	     option WiredWanSupport        '\'${WiredWanSupport}\' >> $PRODUCT_CONFIG
echo '	     option DdnsSupport        	   '\'${DdnsSupport}\' >> $PRODUCT_CONFIG
echo '	     option LinkSwtichSupport      '\'${LinkSwtichSupport}\' >> $PRODUCT_CONFIG
echo '	     option DetectNetSupport       '\'${DetectNetSupport}\' >> $PRODUCT_CONFIG
echo '	     option SimChangeSupport       '\'${SimChangeSupport}\' >> $PRODUCT_CONFIG
echo '       option WechatQrSupport        '\'${WechatQrSupport}\' >> $PRODUCT_CONFIG
echo '       option WanDetectSupport       '\'${WanDetectSupport}\' >> $PRODUCT_CONFIG
echo '       option IptvSupport            '\'${IptvSupport}\' >> $PRODUCT_CONFIG
echo '       option WizardIptvSupport      '\'${WizardIptvSupport}\' >> $PRODUCT_CONFIG
echo '       option IptvMulModeSupport     '\'${IptvMulModeSupport}\' >> $PRODUCT_CONFIG
echo '       option IptvWifiVlanSupport    '\'${IptvWifiVlanSupport}\' >> $PRODUCT_CONFIG
echo '       option Ipv6Support            '\'${Ipv6Support}\' >> $PRODUCT_CONFIG
echo '       option Ipv6TunnelSupport      '\'${Ipv6TunnelSupport}\' >> $PRODUCT_CONFIG
echo '       option Ipv6PPPSupport         '\'${Ipv6PPPSupport}\' >> $PRODUCT_CONFIG
echo '       option PptpServerSupport      '\'${PptpServerSupport}\' >> $PRODUCT_CONFIG
echo '       option PptpClientSupport      '\'${PptpClientSupport}\' >> $PRODUCT_CONFIG
echo '       option L2tpServerSupport      '\'${L2tpServerSupport}\' >> $PRODUCT_CONFIG
echo '       option L2tpClientSupport      '\'${L2tpClientSupport}\' >> $PRODUCT_CONFIG
echo '       option SsrServerSupport       '\'${SsrServerSupport}\' >> $PRODUCT_CONFIG
echo '       option PppoeSpecSupport       '\'${PppoeSpecSupport}\' >> $PRODUCT_CONFIG
echo '       option PppoeSpecRussia        '\'${PppoeSpecRussia}\' >> $PRODUCT_CONFIG
echo '       option PppoelcpEchoSupport    '\'${PppoelcpEchoSupport}\' >> $PRODUCT_CONFIG
echo '       option TtlWaySupport          '\'${TtlWaySupport}\' >> $PRODUCT_CONFIG
echo '       option StorageSupport         '\'${StorageSupport}\' >> $PRODUCT_CONFIG
echo '       option FtpSupport             '\'${FtpSupport}\' >> $PRODUCT_CONFIG
echo '       option UpnpSupport            '\'${UpnpSupport}\' >> $PRODUCT_CONFIG
echo '       option TcpdumpPackSupport     '\'${TcpdumpPackSupport}\' >> $PRODUCT_CONFIG
echo '       option DOSSupport             '\'${DOSSupport}\' >> $PRODUCT_CONFIG
echo '       option StaticrouteSupport     '\'${StaticrouteSupport}\' >> $PRODUCT_CONFIG
echo '       option RipSupport     		   '\'${RipSupport}\' >> $PRODUCT_CONFIG
echo '       option OspfSupport     	   '\'${OspfSupport}\' >> $PRODUCT_CONFIG
echo '       option BgpSupport     	   	   '\'${BgpSupport}\' >> $PRODUCT_CONFIG
echo '       option slbDongleSupport       '\'${slbDongleSupport}\' >> $PRODUCT_CONFIG
echo '       option ailingMqttSupport       '\'${ailingMqttSupport}\' >> $PRODUCT_CONFIG
echo '       option slbAPSupport           '\'${slbAPSupport}\' >> $PRODUCT_CONFIG
echo '       option WifiSchSupport         '\'${WifiSchSupport}\' >> $PRODUCT_CONFIG
echo '       option EoipSupport            '\'${EoipSupport}\' >> $PRODUCT_CONFIG
echo '       option GuestWifiSchSupport    '\'${GuestWifiSchSupport}\' >> $PRODUCT_CONFIG
echo '       option multiGuesrWifiSupport   '\'${multiGuesrWifiSupport}\' >> $PRODUCT_CONFIG
echo '       option WpsSupport             '\'${WpsSupport}\' >> $PRODUCT_CONFIG
echo '       option FirewallSchSupport     '\'${FirewallSchSupport}\' >> $PRODUCT_CONFIG
echo '       option IpsecSupport           '\'${IpsecSupport}\' >> $PRODUCT_CONFIG
echo '	     option IpsecKeyPayloadSupport '\'${IpsecKeyPayloadSupport}\' >> $PRODUCT_CONFIG
echo '       option IpsecGmSupport         '\'${IpsecGmSupport}\' >> $PRODUCT_CONFIG
echo '       option IpsecGmv2Support       '\'${IpsecGmv2Support}\' >> $PRODUCT_CONFIG
echo '       option FtpPortSupport         '\'${FtpPortSupport}\' >> $PRODUCT_CONFIG
echo '       option SmartFlowSupport       '\'${SmartFlowSupport}\' >> $PRODUCT_CONFIG
echo '       option loginVerifySupport     '\'${loginVerifySupport}\' >> $PRODUCT_CONFIG
echo '       option GuestWifiMaxStaSupport '\'${GuestWifiMaxStaSupport}\' >> $PRODUCT_CONFIG
echo '       option SsidQosSupport         '\'${SsidQosSupport}\' >> $PRODUCT_CONFIG
echo '       option GuestSsidQosSupport    '\'${GuestSsidQosSupport}\' >> $PRODUCT_CONFIG
echo '       option Tr069Support           '\'${Tr069Support}\' >> $PRODUCT_CONFIG
echo '       option CwmpdSupport           '\'${CwmpdSupport}\' >> $PRODUCT_CONFIG
echo '       option GpsSupport             '\'${GpsSupport}\' >> $PRODUCT_CONFIG
echo '       option DtuSupport       	   '\'${DtuSupport}\' >> $PRODUCT_CONFIG
echo '       option Dtu485Support      	   '\'${Dtu485Support}\' >> $PRODUCT_CONFIG
echo '       option SnmpSupport            '\'${SnmpSupport}\' >> $PRODUCT_CONFIG
echo '       option Option60Support        '\'${Option60Support}\' >> $PRODUCT_CONFIG
echo '       option RemoteLogSupport       '\'${RemoteLogSupport}\' >> $PRODUCT_CONFIG
echo '       option RipRouterSupport       '\'${RipRouterSupport}\' >> $PRODUCT_CONFIG
echo '       option Usb3DisableSupport     '\'${Usb3DisableSupport}\' >> $PRODUCT_CONFIG
echo '       option VersionControlSupport  '\'${VersionControlSupport}\' >> $PRODUCT_CONFIG
echo '       option totoapSupport          '\'${totoapSupport}\' >> $PRODUCT_CONFIG
echo '       option ipv6NatSupport  	   '\'${ipv6NatSupport}\' >> $PRODUCT_CONFIG
echo '       option SmsSupport 	  		   '\'${SmsSupport}\' >> $PRODUCT_CONFIG
echo '       option FotaSupport 	  	   '\'${FotaSupport}\' >> $PRODUCT_CONFIG
echo '       option TunnelSupport 	  	   '\'${TunnelSupport}\' >> $PRODUCT_CONFIG
echo '       option OpenVpnClientSupport   '\'${OpenVpnClientSupport}\' >> $PRODUCT_CONFIG
echo '       option VrrpSupport   		   '\'${VrrpSupport}\' >> $PRODUCT_CONFIG
echo '       option RnatSupport   		   '\'${RnatSupport}\' >> $PRODUCT_CONFIG
echo '       option QosSupport   		   '\'${QosSupport}\' >> $PRODUCT_CONFIG
echo '       option vxlanSupport           '\'${vxlanSupport}\' >> $PRODUCT_CONFIG
echo '       option WireguardSupport  	   '\'${WireguardSupport}\' >> $PRODUCT_CONFIG
echo '       option l2tpSupport            '\'${l2tpSupport}\' >> $PRODUCT_CONFIG
echo '       option pptpSupport       	   '\'${pptpSupport}\' >> $PRODUCT_CONFIG
echo '       option ModemNetcustomSupport  '\'${ModemNetcustomSupport}\' >> $PRODUCT_CONFIG
echo '       option TimeZoneCSTSupport	   '\'${TimeZoneCSTSupport}\' >> $PRODUCT_CONFIG
echo '       option sslVpnSupport          '\'${sslVpnSupport}\' >> $PRODUCT_CONFIG
echo '       option AlgSupport 		   '\'${AlgSupport}\' >> $PRODUCT_CONFIG
echo '       option cid                    '\'${cid}\' >> $PRODUCT_CONFIG
echo '       option runner                 '\'${runner}\' >> $PRODUCT_CONFIG
echo '       option need_fixed             '\'1\' >> $PRODUCT_CONFIG
echo ' ' >> $PRODUCT_CONFIG
echo 'config product ispinfo' >> $PRODUCT_CONFIG
echo '       option  product_class '\'${product_class}\' >> $PRODUCT_CONFIG
echo '       option  serial_number  ' >> $PRODUCT_CONFIG

#/etc/config/system
SYSTEM_CONFIG=$PACKAGESFILES/etc/config/system
echo 'config system main' > $SYSTEM_CONFIG
echo '       option hostname       '\'${hostname}\' >> $SYSTEM_CONFIG
echo '       option username '\'${login_username}\' >> $SYSTEM_CONFIG
echo '       option password '\'${login_password}\' >> $SYSTEM_CONFIG
echo '       option fixed_default  '\'${fixed_default}\' >> $SYSTEM_CONFIG
echo '       option lang_support   '\'${lang_support}\' >> $SYSTEM_CONFIG
echo '       option lang_type      '\'${lang_type}\' >> $SYSTEM_CONFIG
echo '       option lang_show_auto '\'${lang_show_auto}\' >> $SYSTEM_CONFIG
echo '       option lang_auto_flag '\'${lang_auto_flag}\' >> $SYSTEM_CONFIG
echo '       option port_num     '\'${port_num}\' >> $SYSTEM_CONFIG
echo '       option led_status     '\'${led_status}\' >> $SYSTEM_CONFIG
echo '       option last_run_time 0' >> $SYSTEM_CONFIG
echo 'config timeserver ntp' >> $SYSTEM_CONFIG
echo '       option server	'\'${ntp_server}\' >> $SYSTEM_CONFIG
echo '       option timezone     '\'${timezone}\' >> $SYSTEM_CONFIG
echo '       option enabled 1' >> $SYSTEM_CONFIG
echo '       option enable_server 0' >> $SYSTEM_CONFIG
echo '       option daylight 0' >> $SYSTEM_CONFIG
echo '       option sync_time 0' >> $SYSTEM_CONFIG
echo '       option time_flag 0' >> $SYSTEM_CONFIG
echo 'config sys opmode' >> $SYSTEM_CONFIG
echo '       option opmode_support '\'${opmode_support}\' >> $SYSTEM_CONFIG
echo '       option opmode_custom  '\'${opmode_custom}\' >> $SYSTEM_CONFIG
echo '       option tradQos '\'${tradQos}\' >> $SYSTEM_CONFIG
echo '       option wispinface '\'${WISINFACE}\' >> $SYSTEM_CONFIG
echo 'config sys tcpdump' >> $SYSTEM_CONFIG
echo '       option enable '\'${enable}\' >> $SYSTEM_CONFIG
echo '       option ifname  '\'${ifname}\' >> $SYSTEM_CONFIG
echo '       option packsize '\'${packsize}\' >> $SYSTEM_CONFIG
echo '       option interface '\'${interface}\' >> $SYSTEM_CONFIG
echo 'config sys rebootsch' >> $SYSTEM_CONFIG
echo '       option switch 0' >> $SYSTEM_CONFIG
echo '       option week 255' >> $SYSTEM_CONFIG
echo '       option hour 0' >> $SYSTEM_CONFIG
echo '       option minute 0' >> $SYSTEM_CONFIG
echo '       option rechour 0' >> $SYSTEM_CONFIG
echo 'config sys syslog' >> $SYSTEM_CONFIG
echo '       option switch 0' >> $SYSTEM_CONFIG
echo '       option remote_log_enabled 0' >> $SYSTEM_CONFIG
echo '       option host 0' >> $SYSTEM_CONFIG
echo '       option port 514' >> $SYSTEM_CONFIG
echo 'config sys upnp' >> $SYSTEM_CONFIG
echo '       option enable 0' >> $SYSTEM_CONFIG
echo 'config sys telnetd' >> $SYSTEM_CONFIG
echo '       option enable   '${telnetd_enable} >> $SYSTEM_CONFIG
echo '       option password '\'${telnetd_password}\' >> $SYSTEM_CONFIG
echo 'config sys crpc' >> $SYSTEM_CONFIG
echo '       option enable 0' >> $SYSTEM_CONFIG
echo '       option webchar_url_head http://www.carystudio.com/router/wechatmanage/routerurl?url=' >> $SYSTEM_CONFIG
if [ "${TARGET_CSID}" = "C8385R" ]; then
echo '       option url_postfix  d.kit.co.th' >> $SYSTEM_CONFIG
else
echo '       option url_postfix crpc.carystudio.com' >> $SYSTEM_CONFIG
fi
echo 'config sys statistics' >> $SYSTEM_CONFIG
echo '       option statistics_domain       '\'${statistics_domain}\' >> $SYSTEM_CONFIG
echo '       option statistics_port 80      ' >> $SYSTEM_CONFIG
echo '       option statistics_path         '\'/api/server/report.json\' >> $SYSTEM_CONFIG
echo '       option statistics_model        '\'${statistics_model}\' >> $SYSTEM_CONFIG
echo '       option statistics_auth1 0' >> $SYSTEM_CONFIG
echo '       option statistics_auth2 0' >> $SYSTEM_CONFIG
if [ -f "$LOCALDIR/def_product/${TARGET_CSID}_system" ];then
	echo '' >> $SYSTEM_CONFIG
	cat $LOCALDIR/def_product/${TARGET_CSID}_system >> $SYSTEM_CONFIG
else
echo 'config led sys' >> $SYSTEM_CONFIG
echo '       option name '\'WAN\' >> $SYSTEM_CONFIG
echo '       option sysfs '\'wan\' >> $SYSTEM_CONFIG
echo '       option trigger '\'netdev\' >> $SYSTEM_CONFIG
echo '       option mode '\'link tx rx\' >> $SYSTEM_CONFIG
echo '       option dev '\'eth1\' >> $SYSTEM_CONFIG
fi

touch $CONFIG_DEFAULT_FLAG

fi


