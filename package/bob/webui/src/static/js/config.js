function get_token_from_url()
{
    var url = location.href;
    var query = url.split('?');
    var i,param,key,token="";
    if(query.length>1){
        param=query[1].split('&');
        for(i=0;i<param.length;i++){
            key=param[i].split('=');
            if(key[0]=="token"){
                token=key[1];
                break;
            }
        }
    }
    if(token!=""){
        return "?token="+token
    }
    else{
        return "";
    }
}

/**************语言初始化部分**************************/
$.lang = {};
(function(obj){
    function language(lang){
        this.switch = function(lang){
            $.ajax({
                url:'/language/'+lang+'.json',
                async:false,
                dataType:'json',
                type: 'get',
                success:function(data){
                    for(var i in data){
                        $.lang[i] = data[i];
                    }
                }
            });
        }
    }
    language.prototype.switch = function(lang){
        return this.switch(lang);
    };
    obj.language = new language();
})(window);

//注：localStorage函数手机端调用会出错
// language.switch(localStorage.lang ? localStorage.lang : 'cn');
language.switch('cn');

var lang_t = function(lang,arr){
    var msg, lang1, lang2;
    var regex=/\[|\]/g;
    var a=regex.test(lang);
    if(!a){
        lang1 = lang.split('.')[0];
        lang2 = lang.split('.')[1];
    }else{
        lang1 = lang.split('[')[0];
        var d = lang.split('[')[1].replace(/\"/g, "");
        lang2 = d.split(']')[0];
    }
    if($.lang[lang1] == undefined){
        console.warn(lang1 + 'is undefined');
        return 'undefined';
    }
    msg = $.lang[lang1][lang2];
    if(msg == undefined){
        console.warn(lang +' is undefined');
        return 'undefined';
    }
    if(arr != undefined){
        if(typeof(arr) == 'object'){
            for(var i in arr){
                msg = msg.replace(new RegExp("\{["+i+"]\}","g"), arr[i]);
            }
        }else if(arr == 'html'){
            msg = msg.replace('[','<font style="font-weight:bold;"> [').replace(']','] </font>');
        }
    }
    return msg;
}
/**************END**************************/


/**
 * 全局配置选项配置
 *
 * @property  {boolean}  showLogo 是否显示logo
 * @property  {boolean}  showLanguage 是否显示语言切换
 * @property  {boolean}  showHelp  是否显示帮助按钮
 * @property {bootlean}  showLoading 是否显示loading动画
 * @property {String}  defaultLang  默认值显示中文
 * @property {String}  version  固件版本
 *
 * @example
 * globalConfig.showLogo = true // 显示logo
 * globalConfig.showLogo = false // 隐藏logo
 */
var globalConfig = {
    "debug":true,
    "ajaxType":false,
    "showLogo":true,
    "showMenu":true,
    "showHead":true,
    "showBreadcrumb":true,
    "showLanguage":true,
    "showHelp":true,
    "showLoading":false,
    "showCountDown":false,
    "showAutoLang":true,
    "showLanguage":"",
    "wifiSupport":false,
    "specialIotBanApply":false,
    "wifiSupport5gOnly":false,
    "modelType":"gw",
    "defaultLang":"cn",
    "version":"V1.0.1bate",
    "copyRight":"",
    "helpUrl":"http://www.carystudio.com",
    "operationMode":"",
    "cgiUrl":'/cgi-bin/cstecgi.cgi',
    "customTitle":"\u200E",
    "customCompany":"",
    "customHelp":false,
    "langAutoFlag":false,
    "openVpnServerSupport":false,
    "openVpnClientSupport":false,
    "ipv6Support":false,
    "ddnsSupport":false,
	"smsSupport":false,
	"ussdSupport":false,
	"l2tpClientSupport":false,
	"pptpClientSupport":false,
	"qosSupport":false,
	"wechatQrSupport":false,
    "pppoeSpecSupport":false,
    "deviceManageSupport":true,
	"lteTestSupport":false,
    "isPhoneDevice":false,
    "bandLockSupport":false,
	"versionControlSupport":false,
    "actStatusSupport":false,
    "cwmpdSupport":false,
    "modemDualband":false,
    "modemPrioIsDounleMode":false,
    "wanTypeList":"",
    "wanTypeList_DHCP":false,
    "wanTypeList_STATIC":false,
    "wanTypeList_PPPOE":false,
    "wanTypeList_PPTP":false,
    "wanTypeList_L2TP":false,
    "wanTypeList_USBNET":false,
    "manageCloudSupport":false,
    "ipsecCertSupport":false,
    "onlyModemSupport":false,
    "moduleMultiApnSupport":false,
    "opmodeSupport":"gw;br;rpt;wisp",
    "autoLogoutTimeout": 0,
    "simSelectSupport":false
};

var Cstools = {
    msg: null,
    count: null
};
/**
 * 语言切换选项关联配置
 *
 * @example
 *  {
 *  'cn':'简体中文',
 *  'en':'English'
 *  };
 *
 */
var languages = {
    'auto':'自动检测',
    'en':'English',
    'cn':'简体中文',
    'vn':'Tiếng Việt',
    'th':'ตรวจจับโดยอัตโนมัติ'
};

/**
 * 菜单配置
 *
 * @property {string} menu.href 菜单的路径
 * @property {string} menu.icon 菜单的图标类名（样式类名）
 * @property {string} menu.lang 菜单的文字
 * @property {boolean} menu.display 是否显示菜单
 * @property {boolean} menu.sub 是否有自己。如果有直接设置下面的属性
 * @property {boolean} menu.sub.href 二级菜单的路径
 * @property {boolean} menu.sub.lang 二级菜单的语言
 * @property {boolean} menu.sub.display 是否显示二级菜单
 *
 * @example
 *  {
 *      "href": "/index.html",
 *      "icon": "cs-icon icon-sytem",
 *      "lang": "status",
 *      "display":true,
 *      "sub": false
 *  },
 * {
 *      "href": "#",
 *      "icon": "cs-icon icon-internet",
 *      "lang": "network",
 *      "display":true,
 *      "sub": [
 *          {
 *              "href": "/net/wan.html",
 *              "lang": "net_wan",
 *              "display":true
 *          },
 *          {
 *              "href": "/net/lan.html",
 *              "lang": "net_lan",
 *              "display":true
 *          },
 *          {
 *              "href": "/net/static_dhcp.html",
 *              "lang": "net_static_dhcp",
 *              "display":true
 *          }
 *      ]
 *  }
 *
 */
var menu = [
    {
        "id": "1",
        "href": "/home.html",
        "icon": "fa-home",
        "lang": "home",
        "display": true,
        "sub": false
    },{
        "id": "11",
        "href": "/home.html",
        "icon": "fa-home",
        "lang": "home",
        "display": true,
        "sub": false
    },
	{
        "id": "2",
        "href": "#",
        "icon": "fa-sitemap",
        "lang": "net",
        "display": true,
        "sub": [
            {
                "id": "2-1",
                "href": "/net/network.html",
                "icon": "fa-sitemap",
                "lang": "network",
                "display": true
            }, {
                "id": "2-12",
                "href": "/net/network_4g.html",
                "icon": "fa-sitemap",
                "lang": "network_4g",
                "display": true
            },{
                "id": "2-13",
                "href": "/net/network_5g.html",
                "icon": "fa-sitemap",
                "lang": "network_5g",
                "display": true
            },{
                "id": "2-2",
                "href": "/net/internet.html",
                "icon": "fa-internet-explorer",
                "lang": "internet",
                "display":"wiredWanSupport"
            }, {
                "id": "2-10",
                "href": "/net/static_dhcp.html",
                "icon": "fa-random",
                "lang": "static_dhcp",
                "display": "staticDhcpSupport"
            },{
                "id": "2-3",
                "href": "/net/wifi.html",
                "icon": "fa-navicon",
                "lang": "wifi",
                "display": "wifiSupport"
            }, {
                "id": "2-4",
                "href": "/net/modem.html",
                "icon": "fa-navicon",
                "lang": "modem",
                "display": "modemSupport"
            },{
                "id": "2-14",
                "href": "/net/modem_4g.html",
                "icon": "fa-navicon",
                "lang": "modem_4g",
                "display": "modemSupport"
            },{
                "id": "2-15",
                "href": "/net/modem_5g.html",
                "icon": "fa-navicon",
                "lang": "modem_5g",
                "display": "modemSupport"
            },{
                "id": "2-5",
                "href": "/net/link_switch.html",
                "icon": "fa-navicon",
                "lang": "link_switch",
                "display": false
            }, {
                "id": "2-6",
                "href": "/net/link_priority.html",
                "icon": "fa-navicon",
                "lang": "link_priority",
                "display": "linkSwtichSupport"
            }, {
                "id": "2-7",
                "href": "/net/ipv6.html",
                "icon": "fa-navicon",
                "lang": "ipv6",
                "display": "ipv6Support"
            }, {
                "id": "2-8",
                "href": "/net/lte_test.html",
                "icon": "fa-navicon",
                "lang": "lte_test",
                "display": "lteTestSupport"
            }, {
                "id": "2-11",
                "href": "/net/lte_test_1.html",
                "icon": "fa-navicon",
                "lang": "lte_test_1",
                "display": "lteTestSupport"
            }, {
                "id": "2-9",
                "href": "/net/wifi_acl.html",
                "icon": "fa-navicon",
                "lang": "wifi_acl",
                "display": "wifiSupport"
            }, {
                "id": "2-16",
                "href": "/net/wifi_client.html",
                "icon": "fa-navicon",
                "lang": "wifi_client",
                "display": "clientSupport"
            }
        ]
    }, {
        "id": "3",
        "href": "#",
        "icon": "fa-briefcase",
        "lang": "service",
        "display": true,
        "sub": [
            {
                "id": "3-1",
                "href": "/service/icmp_check.html",
                "icon": "fa-joomla",
                "lang": "icmp_check",
                "display": true
            }, {
                "id": "3-2",
                "href": "/service/ddns.html",
                "icon": "fa-joomla",
                "lang": "ddns",
                "display": "ddnsSupport"
            }, {
                "id": "3-3",
                "href": "/service/tty_server.html",
                "icon": "fa-usb",
                "lang": "tty_server",
                "display": "ttyServerSupport"
            }, {
                "id": "3-4",
                "href": "/service/sms.html",
                "icon": "fa-commenting-o",
                "lang": "sms",
                "display": "smsSupport"
            }, {
                "id": "3-5",
                "href": "/service/gps_set.html",
                "icon": "fa-map-marker",
                "lang": "gps_set",
                "display": "gpsSupport"
            }, {
                "id": "3-26",
                "href": "/service/ussd.html",
                "icon": "fa-commenting-o",
                "lang": "ussd",
                "display": "ussdSupport" 
            }, {
                "id": "3-13",
                "href": "/service/gps_set2.html",
                "icon": "fa-map-marker",
                "lang": "gps_set",
                "display": "gpsSupport"
            }, {
                "id": "3-14",
                "href": "/service/gps_set3.html",
                "icon": "fa-usb",
                "lang": "gps_set",
                "display": "gps3Support"
            }, {
                "id": "3-15",
                "href": "/service/power_ctrol.html",
                "icon": "fa-cloud",
                "lang": "power_ctrol",
                "display": "powerCtlSuppor"
            },{
                "id": "3-16",
                "href": "/service/third_system.html",
                "icon": "fa-cloud",
                "lang": "third_system",
                "display": "thirdSystemSupport"
            },{
                "id": "3-17",
                "href": "/service/iot_mqtt.html",
                "icon": "fa-cloud",
                "lang": "iot_mqtt",
                "display": "iotMqttSupport"
            },{
                "id": "3-18",
                "href": "/service/cwmpd.html",
                "icon": "fa-cloud",
                "lang": "cwmpd",
                "display": "cwmpdSupport"
            },{
                "id": "3-22",
                "href": "/service/cwmpd_4g.html",
                "icon": "fa-cloud",
                "lang": "cwmpd_4g",
                "display": "cwmpdSupport"
            },{
                "id": "3-23",
                "href": "/service/cwmpd_5g.html",
                "icon": "fa-cloud",
                "lang": "cwmpd_5g",
                "display": "cwmpdSupport"
            },{
                "id": "3-20",
                "href": "/service/aliyun_mqtt.html",
                "icon": "fa-cloud",
                "lang": "aliyun_mqtt",
                "display": "aliyunMqttSupport"
            },{
                "id": "3-21",
                "href": "/service/webcam.html",
                "icon": "fa-cloud",
                "lang": "webcam",
                "display": "webcamSupport"
            },{
                "id": "3-24",
                "href": "/service/aiot_mqtt.html",
                "icon": "fa-cloud",
                "lang": "aiot_mqtt",
                "display": "aiotSupport"
            },{
                "id": "3-25",
                "href": "/service/onenet_mqtt.html",
                "icon": "fa-cloud",
                "lang": "onenet_mqtt",
                "display": "onenetSupport"
            },{
                "id": "3-6",
                "href": "/service/schedule.html",
                "icon": "fa-history",
                "lang": "schedule",
                "display": false
            }, {
                "id": "3-7",
                "href": "/service/iot.html",
                "icon": "fa-cloud",
                "lang": "iot",
                "display": "iotSupport"
            }, {
                "id": "3-8",
                "href": "/service/snmp.html",
                "icon": "fa-cloud",
                "lang": "snmp",
                "display": "snmpSupport"
            }, {
                "id": "3-9",
                "href": "/service/vrrp.html",
                "icon": "fa-cloud",
                "lang": "vrrp",
                "display": "vrrpSupport"
            }, {
                "id": "3-10",
                "href": "/service/radius.html",
                "icon": "fa-cloud",
                "lang": "radius",
                "display": "radiusSupport"
            }, {
                "id": "3-11",
                "href": "/service/dtu.html",
                "icon": "fa-usb",
                "lang": "dtu",
                "display": "dtuSupport"
            }, {
                "id": "3-12",
                "href": "/service/mqtt.html",
                "icon": "fa-usb",
                "lang": "mqtt",
                "display": "mqttSupport"
            },{
                "id": "3-12",
                "href": "/service/hwnat.html",
                "icon": "fa-usb",
                "lang": "hwnat",
                "display": "hwNatSupport"
            },{
                "id": "3-27",
                "href": "/service/slb_dongle.html",
                "icon": "fa-home",
                "lang": "slb_dongle",
                "display": "slbDongleSupport"
            },
            {
                "id": "3-28",
                "href": "/service/slb_ap.html",
                "icon": "fa-home",
                "lang": "slb_ap",
                "display": "slbAPSupport"
            }
        ]
    }, {
        "id": "4",
        "href": "#",
        "icon": "fa-paper-plane",
        "lang": "vpn",
        "display": "vpnMenuSupport",
        "sub": [
            {
                "id": "4-1",
                "href": "/vpn/vpdn.html",
                "icon": "fa-filter",
                "lang": "vpdn",
                "display": true
            },{
                "id": "4-13",
                "href": "/vpn/vpdn_multi.html",
                "icon": "fa-filter",
                "lang": "vpdn",
                "display": true
            }, {
                "id": "4-2",
                "href": "/vpn/tunnel.html",
                "icon": "fa-external-link",
                "lang": "tunnel",
                "display": "tunnelSupport"
            },
           /* {
                "id": "4-3",
                "href": "/vpn/ipsec.html",
                "icon": "fa-gamepad",
                "lang": "ipsec",
                "display": true
            }, */
			{
				"id": "4-3",
                "href": "/vpn/account.html",
                "icon": "fa-gamepad",
                "lang": "account",
                "display": "openVpnServerSupport"
			},
			{
                "id": "4-4",
                "href": "/vpn/openvpn.html",
                "icon": "fa-gamepad",
                "lang": "openvpn",
                "display": "openVpnClientSupport"
            }, {
                "id": "4-5",
                "href": "/vpn/vpn_detection.html",
                "icon": "fa-gamepad",
                "lang": "vpn_detection",
                "display": "vpnDetectionSupport"
            }, {
                "id": "4-6",
                "href": "/vpn/eoip.html",
                "icon": "fa-gamepad",
                "lang": "eoip",
                "display": "eoipSupport"
            }, {
                "id": "4-7",
                "href": "/vpn/dmvpn.html",
                "icon": "fa-gamepad",
                "lang": "dmvpn",
                "display": "dmvpnSupport"
            }, {
                "id": "4-8",
                "href": "/vpn/cert.html",
                "icon": "fa-gamepad",
                "lang": "cert",
                "display": "certSupport"
            }, {
                "id": "4-9",
                "href": "/vpn/ipsec_net2net.html",
                "icon": "fa-filter",
                "lang": "ipsec_net2net",
                "display": "ipsecSupport"
            }, {
                "id": "4-10",
                "href": "/vpn/ipsec_host2net.html",
                "icon": "fa-filter",
                "lang": "ipsec_host2net",
                "display": "ipsecSupport"
            }, {
                "id": "4-11",
                "href": "/vpn/ipsec_l2tpxauth.html",
                "icon": "fa-filter",
                "lang": "ipsec_l2tpxauth",
                "display": "ipsecSupport"
            }, {
                "id": "4-12",
                "href": "/vpn/tf.html",
                "icon": "fa-filter",
                "lang": "tf",
                "display": "tfSupport"
            },{
                "id": "4-14",
                "href": "/vpn/sslvpn.html",
                "icon": "fa-filter",
                "lang": "sslvpn",
                "display": "sslVpnSupport"
            },{
                "id": "4-15",
                "href": "/vpn/vxlan.html",
                "icon": "fa-filter",
                "lang": "vxlan",
                "display": "vxlanSupport"
            },{
                "id": "4-16",
                "href": "/vpn/wireguard.html",
                "icon": "fa-filter",
                "lang": "wireguard",
                "display": "wireguardSupport"
            },{
                "id": "4-17",
                "href": "/vpn/pptp.html",
                "icon": "fa-filter",
                "lang": "pptp",
                "display": "pptpSupport"
            },{
                "id": "4-18",
                "href": "/vpn/l2tp.html",
                "icon": "fa-filter",
                "lang": "l2tp",
                "display": "l2tpSupport"
            } 
        ]
    },
	{
        "id": "5",
        "href": "#",
        "icon": "fa-briefcase",
        "lang": "nat",
        "display": true,
        "sub": [
            {
                "id": "5-1",
                "href": "/nat/rnat.html",
                "icon": "fa-share-alt",
                "lang": "rnat",
                "display": "rnatSupport"
            }, {
				"id": "5-2",
				"href": "/nat/smart_qos.html",
				"icon": "fa-cubes",
				"lang": "smart_qos",
				"display": "qosSupport"
			}, {
                "id": "5-3",
                "href": "/nat/static_route.html",
                "icon": "fa-reply",
                "lang": "static_route",
                "display": "staticRouteSupport"
            }, {
                "id": "5-4",
                "href": "/nat/policy_route.html",
                "icon": "fa-reply",
                "lang": "policy_route",
                "display": "policyRouteSupport"
            }, {
                "id": "5-5",
                "href": "/nat/rip.html",
                "icon": "fa-gamepad",
                "lang": "rip",
                "display": "ripSupport"
            }, {
                "id": "5-6",
                "href": "/nat/ospf.html",
                "icon": "fa-gamepad",
                "lang": "ospf",
                "display": "ospfSupport"
            }, {
                "id": "5-7",
                "href": "/nat/bgp.html",
                "icon": "fa-gamepad",
                "lang": "bgp",
                "display": "bgpSupport"
            }
        ]
    },
	{
        "id": "6",
        "href": "#",
        "icon": "fa-shield",
        "lang": "firewall",
        "display": "c7335rSupport",
        "sub": [
            {
                "id": "6-1",
                "href": "/firewall/ipf.html",
                "icon": "fa-hourglass-1",
                "lang": "ipf",
                "display": true
            }, {
                "id": "6-2",
                "href": "/firewall/urlf.html",
                "icon": "fa-hourglass-end",
                "lang": "urlf",
                "display": true
            }, {
                "id": "6-3",
                "href": "/firewall/macf.html",
                "icon": "fa-hourglass-2",
                "lang": "macf",
                "display": true
            }, {
                "id": "6-4",
                "href": "/firewall/remote.html",
                "icon": "fa-weixin",
                "lang": "remote",
                "display": false
            }, {
                "id": "6-5",
                "href": "/firewall/dmz.html",
                "icon": "fa-shield",
                "lang": "dmz",
                "display": true
            }, {
                "id": "6-6",
                "href": "/firewall/alg_server.html",
                "icon": "fa-external-link",
                "lang": "alg_server",
                "display": "algSupport"
            }, {
                "id": "6-7",
                "href": "/firewall/security_option.html",
                "icon": "fa-external-link",
                "lang": "security_option",
                "display": true
            }, {
                "id": "6-8",
                "href": "/firewall/remote_access.html",
                "icon": "fa-external-link",
                "lang": "remote_access",
                "display": true
            }, {
                "id": "6-9",
                "href": "/firewall/attack.html",
                "icon": "fa-external-link",
                "lang": "attack",
                "display": "attackSupport"
            }, {
                "id": "6-10",
                "href": "/firewall/port_mirror.html",
                "icon": "fa-external-link",
                "lang": "port_mirror",
                "display": "mirrorPortSupport"
            }
        ]
    }, {
        "id": "7",
        "href": "#",
        "icon": "fa-external-link",
        "lang": "diffnet",
        "display": "diffnetSupport",
        "sub": [
            {
                "id": "7-1",
                "href": "/diffnet/net_strategy.html",
                "icon": "fa-hourglass-1",
                "lang": "net_strategy",
                "display": true
            }, {
                "id": "7-2",
                "href": "/diffnet/node_info.html",
                "icon": "fa-hourglass-2",
                "lang": "node_info",
                "display": "diffnetListSupport"
            }
        ]
    }, {
        "id": "8",
        "href": "#",
        "icon": "fa-cog",
        "lang": "adm",
        "display": true,
        "sub": [
            {
                "id": "8-1",
                "href": "/adm/changepwd.html",
                "icon": "fa-key",
                "lang": "changepwd",
                "display": true
            }, {
                "id": "8-2",
                "href": "/adm/time.html",
                "icon": "fa-clock-o",
                "lang": "time",
                "display": true
			}, {
                "id": "8-3",
                "href": "/adm/diagnosis.html",
                "icon": "fa-desktop",
                "lang": "diagnosis",
                "display": true
            }, {
                "id": "8-4",
                "href": "/adm/firmware.html",
                "icon": "fa-upload",
                "lang": "firmware",
                "display": true
            }, {
                "id": "8-5",
                "href": "/adm/config.html",
                "icon":"fa-cogs",
                "lang": "config",
                "display":true
            }, {
                "id": "8-6",
                "href": "/adm/reboot.html",
                "icon": "fa-power-off",
                "lang": "reboot",
                "display": true
            }, {
                "id": "8-7",
                "href": "/adm/syslog.html",
                "icon": "fa-file-text",
                "lang": "syslog",
                "display": true
            }, {
                "id": "8-8",
                "href": "/adm/remote_log.html",
                "icon": "fa-file-text",
                "lang": "remote_log",
                "display": "remoteLogSupport"
            }, {
                "id": "8-9",
                "href": "/adm/terminal.html",
                "icon": "fa-file-text",
                "lang": "terminal",
                "display": "terminalSupport"
            }, {
                "id": "8-10",
                "href": "/adm/schedule.html",
                "icon": "fa-history",
                "lang": "schedule",
                "display": true
            }, {
                "id": "8-11",
                "href": "/adm/fota.html",
                "icon": "fa-history",
                "lang": "fota",
                "display": "fotaSupport"
            }, {
                "id": "8-13",
                "href": "/adm/find_package.html",
                "icon": "fa-history",
                "lang": "find_package",
                "display": "tcpdumpPackSupport"
            }, {
                "id": "8-12",
                "href": "/adm/debug_log.html",
                "icon": "fa-history",
                "lang": "debug_log",
                "display": "debugLogSupport"
            }, {
                "id": "8-99",
                "href": "out",
                "icon": "fa-sign-out",
                "lang": "logout",
                "display": true
            }
        ]
    },
    {
        "id": "9",
        "href": "/opmode.html",
        "icon": "fa-navicon",
        "lang": "opmode",
        "display": "opmodeSupport",
        "sub": false
    },
    {
        "id": "10",
        "href": "/cloud_man.html",
        "icon": "fa-cloud",
        "lang": "cloud_man",
        "display": "manageCloudSupport",
        "sub": false
    }
];
