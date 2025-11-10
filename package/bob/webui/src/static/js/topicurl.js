//文件上传类
(function(obj){

var xhrOnProgress=function(fun) {
  xhrOnProgress.onprogress = fun;
  return function() {
    var xhr = $.ajaxSettings.xhr();
    if (typeof xhrOnProgress.onprogress !== 'function')
      return xhr;
    if (xhrOnProgress.onprogress && xhr.upload) {
      xhr.upload.onprogress = xhrOnProgress.onprogress;
    }
    return xhr;
  }
}
/**
 * 文件上传列表：
 * @Author   Karen  <Karen@carystudio.com>
 * @DateTime 2018-10-27
 * @property {Object} fileUpload 文件上传 <a href="#fileUpload">点击查看</a>
 * @alias upload
 * @class
 * @example
 * 封装案例：
 * upload.prototype.xxx = function(obj){
 *    return this.upload(obj);
 * };
 * // 把xxx的位置换成对应的主题即可。
 */
function upload(){
    this.upload = function(obj){
        var formFile = new FormData();
        formFile.append("file", obj.data);
        var data = formFile;
        $.ajax({
           url: obj.url,
           data: data,
           type: "Post",
           dataType: "json",
           cache: false,
           processData: false,
           contentType: false,
           xhr:xhrOnProgress(function(e){
              var percent=e.loaded/e.total;
              percent = parseInt( percent * 100);
              if(typeof(obj.progress) == 'function')
                obj.progress(percent);
           }),
           success: function (result) {
                if(typeof(obj.success) == 'function')
                    obj.success(result);
            },
            error:function(result){
                if(typeof(obj.error) == 'function')
                    obj.error(result);
            }
        })
    }
}
/**
 * 文件上传
 * @Author   Karen       <Karen@carystudio.com>
 * @DateTime 2018-10-27
 * @Author   Amy       <amy@carystudio.com>
 * @DateTime 2018-05-03  Add AutoLanguage
 * @param {Object} obj 传参。url：上传路径，data：上传文件信息，progress：上传进度回调函数，success：上传成功回调函数，error：上传错误回调函数
 * @example
 * request:
 * {
 *     obj:{
 *         url:'',
 *         data:{},
 *         progress:function(){},
 *         success:function(){},
 *         error:function(){}
 *     }
 * }
 */
upload.prototype.fileUpload = function(obj){
    return this.upload(obj);
};
obj.upload = new upload();
})(window);

(function(obj){

  function uipostMethods(key, value) {
        return function(posts, callback) {
            this.topicurl = key;
            this.async = null;
            if (value) {
                if (value.debugUrl && globalConfig.debug) {
                    this.url = "/data/"+ value.debugUrl;
                } else {
                    this.url = globalConfig.cgiUrl;
                }
            }
            this.post(posts, callback);
        }
    }
/**
 * 主题函数库列表：
 *
 * @property {Object} getInitConfig 全局配置 <a href="#getInitConfig">点击查看</a>
 * @property {Object} getSysStatusCfg 获取系统状态 <a href="#getSysStatusCfg">点击查看</a>
 * @property {Object} getPluginStatus 获取插件功能状态 <a href="#getPluginStatus">点击查看</a>
 * @property {Object} getNetStateInfo 获取VPN配置 <a href="#getNetStateInfo">点击查看</a>
 * @property {Object} getLanCfg 获取LAN配置 <a href="#getLanCfg">点击查看</a>
 * @property {Object} setLanCfg 保存LAN配置 <a href="#setLanCfg">点击查看</a>
 * @property {Object} getWanCfg 获取WAN配置 <a href="#getWanCfg">点击查看</a>
 * @property {Object} setWanCfg 保存WAN配置 <a href="#setWanCfg">点击查看</a>
 * @property {Object} getModemCfg 获取Modem配置 <a href="#getModemCfg">点击查看</a>
 * @property {Object} setModemCfg 保存Modem配置 <a href="#setModemCfg">点击查看</a>
 * @property {Object} setManualDialCfg 手动拨号 <a href="#setManualDialCfg">点击查看</a>
 * @property {Object} getPasswordCfg 获取登录用户名 <a href="#getPasswordCfg">点击查看</a>
 * @property {Object} setPasswordCfg 保存登录密码 <a href="#setPasswordCfg">点击查看</a>
 * @property {Object} NTPSyncWithHost 同步本地时间 <a href="#NTPSyncWithHost">点击查看</a>
 * @property {Object} getNtpCfg 获取NTP配置 <a href="#getNtpCfg">点击查看</a>
 * @property {Object} setNtpCfg 保存NTP配置 <a href="#setNtpCfg">点击查看</a>
 * @property {Object} getTelnetCfg 获取Telent配置 <a href="#getTelnetCfg">点击查看</a>
 * @property {Object} setTelnetCfg 保存Telent配置 <a href="#setTelnetCfg">点击查看</a>
 * @property {Object} getPowerCtlCfg 获取Telent配置 <a href="#getPowerCtlCfg">点击查看</a>
 * @property {Object} setPowerCtlCfg 保存Telent配置 <a href="#setPowerCtlCfg">点击查看</a>
 * @property {Object} getDdnsStatus 获取DDNS状态 <a href="#getDdnsStatus">点击查看</a>
 * @property {Object} getDdnsCfg 获取DDNS配置 <a href="#getDdnsCfg">点击查看</a>
 * @property {Object} setDdnsCfg 保存DDNS配置 <a href="#setDdnsCfg">点击查看</a>
 * @property {Object} CloudSrvVersionCheck 检测云升级 <a href="#CloudSrvVersionCheck">点击查看</a>
 * @property {Object} FirmwareUpgrade 获取固件配置 <a href="#FirmwareUpgrade">点击查看</a>
 * @property {Object} setUpgradeFW 本地升级 <a href="#setUpgradeFW">点击查看</a>
 * @property {Object} CloudACMunualUpdate 云检测固件升级 <a href="#CloudACMunualUpdate">点击查看</a>
 * @property {Object} LoadDefSettings 恢复出厂 <a href="#LoadDefSettings">点击查看</a>
 * @property {Object} RebootSystem 重启 <a href="#RebootSystem">点击查看</a>
 * @property {Object} SystemSettings 获取系统配置 <a href="#SystemSettings">点击查看</a>
 * @property {Object} setLanguageCfg 保存语言配置 <a href="#setLanguageCfg">点击查看</a>
 * @property {Object} getCloudSrvCheckStatus 获取新平台云升级状态 <a href="#getCloudSrvCheckStatus">点击查看</a>
 * @property {Object} getCrpcConfig 获取微信管理的链接 <a href="#getCrpcConfig">点击查看</a>
 * @property {Object} getSyslogCfg 获取远程日志配置 <a href="#getSyslogCfg">点击查看</a>
 * @property {Object} setSyslogCfg 保存远程日志配置 <a href="#setSyslogCfg">点击查看</a>
 * @property {Object} clearSyslog 清除系统日志 <a href="#clearSyslog">点击查看</a>
 * @property {Object} showSyslog 获取系统日志 <a href="#showSyslog">点击查看</a>
 * @property {Object} getWiFiBasicConfig 获取无线配置 <a href="#getWiFiBasicConfig">点击查看</a>
 * @property {Object} setWiFiBasicConfig 保存无线配置 <a href="#setWiFiBasicConfig">点击查看</a>
 * @property {Object} getWiFiApcliScan 获取扫描AP配置 <a href="#getWiFiApcliScan">点击查看</a>
 * @property {Object} setWiFiRepeaterConfig 保存中继AP配置 <a href="#setWiFiRepeaterConfig">点击查看</a>
 * @property {Object} getVpnClinentLog 获取VPN客户端日志 <a href="#getVpnClinentLog">点击查看</a>
 * @property {Object} setOpMode 保存系统模式配置 <a href="#setOpMode">点击查看</a>
 * @property {Object} getVpnCheckCfg 获取VPN检测配置 <a href="#getVpnCheckCfg">点击查看</a>
 * @property {Object} setVpnCheckCfg 保存VPN检测配置 <a href="#setVpnCheckCfg">点击查看</a>
 * @property {Object} getVpnPassCfg 获取VPN穿透配置 <a href="#getVpnPassCfg">点击查看</a>
 * @property {Object} setVpnPassCfg 保存VPN穿透配置 <a href="#setVpnPassCfg">点击查看</a>
 * @property {Object} getDMZCfg 获取DMZ配置 <a href="#getDMZCfg">点击查看</a>
 * @property {Object} setDMZCfg 保存DMZ配置 <a href="#setDMZCfg">点击查看</a>
 * @property {Object} getArpTable 获取IP/MAC列表 <a href="#getArpTable">点击查看</a>
 * @property {Object} getNatRules 获取NAT配置 <a href="#getNatRules">点击查看</a>
 * @property {Object} setNatRules 保存NAT配置<a href="#setNatRules">点击查看</a>
 * @property {Object} delNatRules 删除NAT规则 <a href="#delNatRules">点击查看</a>
 * @property {Object} getIpPortFilterRules 获取IP端口过滤配置 <a href="#getIpPortFilterRules">点击查看</a>
 * @property {Object} setIpPortFilterRules 保存IP端口过滤配置 <a href="#setIpPortFilterRules">点击查看</a>
 * @property {Object} getUrlFilterRules 获取URL过滤配置 <a href="#getUrlFilterRules">点击查看</a>
 * @property {Object} setUrlFilterRules 保存URL过滤配置 <a href="#setUrlFilterRules">点击查看</a>
 * @property {Object} getRouteTableInfo 获取生效路由配置 <a href="#getRouteTableInfo">点击查看</a>
 * @property {Object} getStaticRoute 获取静态路由配置 <a href="#getStaticRoute">点击查看</a>
 * @property {Object} setStaticRoute 保存静态路由配置 <a href="#addStaticRoute">点击查看</a>
 * @property {Object} getIPv6Status 获取IPv6状态配置 <a href="#getIPv6Status">点击查看</a>
 * @property {Object} getDiagnosisCfg 获取ping诊断日志配置 <a href="#getDiagnosisCfg">点击查看</a>
 * @property {Object} setDiagnosisCfg 保存ping诊断日志配置 <a href="#setDiagnosisCfg">点击查看</a>
 * @property {Object} clearDiagnosisLog 清除ping诊断日志 <a href="#clearDiagnosisLog">点击查看</a>
 * @property {Object} getGpsReportTimeCfg 获取GPS定位配置 <a href="#getGpsReportTimeCfg">点击查看</a>
 * @property {Object} setGpsReportTimeCfg 保存GPS定位配置 <a href="#setGpsReportTimeCfg">点击查看</a>
 * @property {Object} getGpsReportCfg 获取GPS定位(经纬度)配置 <a href="#getGpsReportCfg">点击查看</a>
 * @property {Object} setGpsReportCfg 保存GPS定位(经纬度)配置 <a href="#setGpsReportCfg">点击查看</a>
 * @property {Object} getGps3Status 获取GPS定位(针对ML302)状态 <a href="#getGps3Cfg">点击查看</a>
 * @property {Object} getGps3Cfg 获取GPS定位(针对ML302)配置 <a href="#getGps3Cfg">点击查看</a>
 * @property {Object} setGps3Cfg 保存GPS定位(针对ML302)配置 <a href="#setGps3Cfg">点击查看</a>
 * @property {Object} getTtyServiceCfg 获取串口服务配置 <a href="#getTtyServiceCfg">点击查看</a>
 * @property {Object} setTtyServiceCfg 保存串口服务配置 <a href="#setTtyServiceCfg">点击查看</a>
 * @property {Object} cancelUssd 清除ussd信息 <a href="#cancelUssd">点击查看</a>
 * @property {Object} setUssd 设置USSD命令 <a href="#setUssd">点击查看</a>
 * @property {Object} getSmsCfg 获取SMS配置 <a href="#getSmsCfg">点击查看</a>
 * @property {Object} setSmsCfg 保存SMS配置 <a href="#setSmsCfg">点击查看</a>
 * @property {Object} getIotCfg 获取IOT配置 <a href="#getIotCfg">点击查看</a>
 * @property {Object} setIotCfg 保存IOT配置 <a href="#setIotCfg">点击查看</a>
 * @property {Object} getTunnelCfg 获取Tunnel隧道配置 <a href="#getTunnelCfg">点击查看</a>
 * @property {Object} setTunnelCfg 保存Tunnel隧道配置 <a href="#setTunnelCfg">点击查看</a>
 * @property {Object} getTunnelRouteCfg 获取Tunnel路由配置 <a href="#getTunnelRouteCfg">点击查看</a>
 * @property {Object} setTunnelRouteCfg 保存Tunnel路由配置 <a href="#setTunnelRouteCfg">点击查看</a>
 * @property {Object} getIcmpCheckCfg 获取Icmp检测配置 <a href="#getIcmpCheckCfg">点击查看</a>
 * @property {Object} setIcmpCheckCfg 保存Icmp检测配置 <a href="#setIcmpCheckCfg">点击查看</a>
 * @property {Object} delIcmpCheckCfg 删除Icmp检测规则 <a href="#delIcmpCheckCfg">点击查看</a>
 * @property {Object} getTimedTaskCfg 获取定时任务配置 <a href="#getTimedTaskCfg">点击查看</a>
 * @property {Object} setTimedTaskCfg 保存定时任务配置 <a href="#setTimedTaskCfg">点击查看</a>
 * @property {Object} setActStatus 设置授权设置参数 <a href="#setActStatus">点击查看</a>
 * @property {Object} getEoipCfg 获取EoIP配置 <a href="#getEoipCfg">点击查看</a>
 * @property {Object} setEoipCfg 设置EoIP配置 <a href="#setEoipCfg">点击查看</a>
 * @property {Object} getSnmpCfg 获取SNMP配置 <a href="#getSnmpCfg">点击查看</a>
 * @property {Object} setSnmpCfg 保存SNMP配置 <a href="#setSnmpCfg">点击查看</a>
 * @property {Object} delSnmpCfg 删除SNMP规则 <a href="#delSnmpCfg">点击查看</a>
 * @property {Object} getVrrpCfg 获取VRRP配置 <a href="#getVrrpCfg">点击查看</a>
 * @property {Object} setVrrpCfg 保存VRRP配置 <a href="#setVrrpCfg">点击查看</a>
 * @property {Object} getDmvpnCfg 获取DMVPN配置 <a href="#getDmvpnCfg">点击查看</a>
 * @property {Object} setDmvpnCfg 设置DMVPN配置 <a href="#setDmvpnCfg">点击查看</a>
 * @property {Object} delDmvpnCfg 删除DMVPN规则 <a href="#delDmvpnCfg">点击查看</a>
 * @property {Object} getIpsecStatus 获取IPSec状态 <a href="#getIpsecStatus">点击查看</a>
 * @property {Object} getIpsecHeartCheckCfg 获取心跳检测配置 <a href="#getIpsecHeartCheckCfg">点击查看</a>
 * @property {Object} setIpsechHeartCheckCfg 设置心跳检测配置 <a href="#setIpsechHeartCheckCfg">点击查看</a>
 * @property {Object} getMqttCfg 获取路由器MQTT连接信息 <a href="#getMqttCfg">点击查看</a>
 * @property {Object} setMqttCfg 设置路由器MQTT连接配置 <a href="#setMqttCfg">点击查看</a>
 * @property {Object} getCellInfo 获取基站扫描列表 <a href="#getCellInfo">点击查看</a>
 * @property {Object} lockCell 保存锁定基站设置参数 <a href="#lockCell">点击查看</a>
 * @property {Object} unLockCell 基站解绑 <a href="#unLockCell">点击查看</a>
 * @property {Object} getTfCfg 获取TF卡配置 <a href="#getTfCfg">点击查看</a>
 * @property {Object} setTfCfg 设置TF卡配置 <a href="#setTfCfg">点击查看</a>
 * @property {Object} getStaticDhcpRules 获取静态DHCP列表 <a href="#getStaticDhcpRules">点击查看</a>
 * @property {Object} setStaticDhcpRules 设置静态DHCP规则 <a href="#setStaticDhcpRules">点击查看</a>
 * @property {Object} delStaticDhcpRules 删除静态DHCP规则 <a href="#delStaticDhcpRules">点击查看</a>
 * @property {Object} getThirdSystem 获取第三方系统连接配置 <a href="#getThirdSystem">点击查看</a>
 * @property {Object} getThirdUpdateState 获取第三方系统连接状态信息 <a href="#getThirdUpdateState">点击查看</a>
 * @property {Object} setThirdSystem 设置第三方系统连接配置 <a href="#setThirdSystem">点击查看</a>
 * @alias uiPost
 * @class
 * @example
 * 封装案例：
 * /**
 *  * 这里写上文档注释
 *  * @param {type} varname description
 *  * param 这里定义为request 参数
 *  * @property {type} varname description
 *  * property 这里定义为response
 *  * @property
 *  * @example
 *  * 实际的案例。
 *  * /
 * uiPost.prototype = {
 *      xxx: {  //无任何参数时，值可为null
 *          debugUrl: "xxxx.json"  //本地调试数据路径
 *      }
 *  };
 * // 把xxx的位置换成对应的主题即可。
 */
function uiPost(){
    this.version = '1.0';
    this.author = 'carystudio';
    this.company = 'carystudio';
    this.srcUrl = globalConfig.cgiUrl;
    this.url = globalConfig.cgiUrl;
    this.type = globalConfig.ajaxType?'GET':'POST';
    this.async = null;
    this.topicurl = '';
    this.post = function(data,callback) {
        var temp_data = null;
        if (data && data instanceof Function) {
            callback = data;
            data = null;
        }
        data = data ? data : {};
        data.topicurl = this.topicurl;
        data = JSON.stringify(data);
		data.token = get_token_from_url().split("=")[1];

		if(!data.token) {
            globalConfig.autoLogoutTimeout = 0;
        }

        if(globalConfig.debug)
        if (/^set|^del/.test(this.topicurl)) {
            this.srcUrl = "/data/set_mock.json";
        } else {
            this.srcUrl = this.url;
        }
        var async = true;
        if(this.async != null)
          async = false;

		if (/^(set|del)/.test(data.topicurl)) {
            globalConfig.autoLogoutTimeout = 0;
        }
        $.ajax({
            url: this.srcUrl+get_token_from_url(),
            type: this.type,
            dataType: 'json',
            data: data,
			jsonp: false,
            async: async,
            success:function(_data) {
                temp_data = (_data);
                if(temp_data.errcode!=undefined && temp_data.errcode<0){
                    var local_url=location.href;
					location.href='http://'+local_url.split('/')[2];
                    return 0;
				}
				if (callback && callback instanceof Function) {
                    callback(temp_data,data);
                }
            },
            error:function(_data) {
                if (callback && callback instanceof Function) {
                    callback(_data,'error');
                }
            }
        });
        this.srcUrl = globalConfig.cgiUrl;
    }
}

uiPost.prototype = {
    /**
    * 初始化数据
    * @DateTime 2020-06-28
    * @property {String}	modelType	支持的产品类型，值：ac：旁路ac，ap：ap，cpe：cpe，gw：工业网关，4g：4g路由器（此版已废弃），5g: 5g路由器
    * @property {String}	csid	CSID
    * @property {String}	model	自定义头部信息
    * @property {String}	wifiSupport	是否支持无线。1：是，0：否
    * @property {String}	wifiDualband	是否支持无线双频。1：是，0：否
    * @property {String}	onlyLoadDefSet	是否支持强制惩罚模式。1：是，0：否（暂未使用）
    * @property {String}	operationMode	系统模式。1：网关，0：桥模式，2：中继，3：wisp模式，4：MESH
    * @property {String}	wanStrategy	上网策略
    * @property {String}	hasMobile	（未知）
    * @property {String}	defaultLang	默认语言（此时的语言）。cn：简体中文，ct：繁体中文，en：英文，vi：越南语，ru：俄语
    * @property {String}	showLanguage	是否显示语言。1：是，0：否
    * @property {String}	showAutoLang	是否支持语言自动检测。1：是，0：否
    * @property {String}	langAutoFlag	当前是否为自动检测语言。1：是，0：否
    * @property {String}	showHelp	是否显示帮助链接。1：是，0：否
    * @property {String}	helpUrl	帮助链接
    * @property {String}	webTitle	浏览器标签显示字样
    * @property {String}	cs	页面头部信息
    * @property {String}	copyRight	版权信息
    * @property {String}	activation	是否授权。1：是，0：否
    * @property {String}	neutralVersion	是否为中性版本。1：是，0：否，默认是
    * @property {Object}	data.custom	定制项
    * @property {String}	wanTypeList	支持的上网方式。dhcp、static、pppoe、pptp、l2tp、usbnet
    * @property {String}	versionControlSupport	未知（废弃）
    * @property {String}	opmodeSupport	是否支持系统模式功能。1：是，0：否
    * @property {String}	openVpnServerSupport	是否支持[openVpn服务端]功能。1：是，0：否
    * @property {String}	openVpnClientSupport	是否支持[openVpn客户端]功能。1：是，0：否
    * @property {String}	ipsecSupport	是否支持[IPsec客户端]功能。1：是，0：否
    * @property {String}	ipv6Support	是否支持[IPv6]功能。1：是，0：否
    * @property {String}	staticRouteSupport	是否支持[静态路由]功能。1：是，0：否
    * @property {String}	policyRouteSupport	是否支持[策略路由]功能。1：是，0：否
    * @property {String}	ttyServerSupport	是否支持[串口透传]功能。1：是，0：否
    * @property {String}	dtuSupport	是否支持[DTU]功能。1：是，0：否
    * @property {String}	firewallSupport	是否支持[防火墙]功能。1：是，0：否
    * @property {String}	iotSupport	是否支持[IOT]功能。1：是，0：否
    * @property {String}	lteTestSupport	是否支持[LTE检测]功能。1：是，0：否
    * @property {String}	actStatusSupport	是否支持[授权]功能。1：是，0：否
    * @property {String}	snmpSupport	是否支持[SNMP]功能。1：是，0：否
    * @property {String}	ripSupport	是否支持[RIP]功能。1：是，0：否
    * @property {String}	ospfSupport	是否支持[OSPF]功能。1：是，0：否
    * @property {String}	bgpSupport	是否支持[BGP]功能。1：是，0：否
    * @property {String}	eoipSupport	是否支持[EOIP]功能。1：是，0：否
    * @property {String}	vrrpSupport	是否支持[VRRP]功能。1：是，0：否
    * @property {String}	bandLockSupport	是否支持[频段锁定]设置项。1：是，0：否
    * @property {String}    nssaiSupport 是否支持[网络切片]设置项。1：是，0：否
    * @property {String}	attackSupport	是否支持[Attack]功能。1：是，0：否
    * @property {String}	diffnetListSupport	是否支持[当前节点信息]功能。1：是，0：否
    * @property {String}	diffnetSupport	是否支持[异地组网]功能。1：是，0：否
    * @property {String}	diffnetSwitchSupport	是否支持[虚拟接口模式]设置项。1：是，0：否
    * @property {String}	radiusSupport	是否支持[Radius]功能。1：是，0：否
    * @property {String}	tunnelSupport	是否支持[隧道设置]功能。1：是，0：否
    * @property {String}	certSupport	是否支持[Cert]功能。1：是，0：否
    * @property {String}	dmvpnSupport	是否支持[DMVPN]功能。1：是，0：否
    * @property {String}	rnatSupport	是否支持[NAT]功能。1：是，0：否
    * @property {String}	algSupport	是否支持[ALG服务]功能。1：是，0：否
    * @property {String}	remoteLogSupport	是否支持[远程日志]功能。1：是，0：否
    * @property {String}	vpnDetectionSupport	是否支持[VPN检测]功能。1：是，0：否
    * @property {String}    saSupport    是否支持独立5g设置。1：是，0：否
    * @property {String}    manageCloudSupport    是否支持云端管理。1：是，0：否
    * @return {object}
    * @example
    * request:
    *
    * response:
    * {
    * 	"modelType":"4g",
    * 	"csid":"C735ER",
    * 	"model":"",
    * 	"wifiSupport":"1",
    * 	"wifiDualband":"0",
    * 	"onlyLoadDefSet":"0",
    * 	"operationMode":"1",
    * 	"wanStrategy":"0",
    * 	"hasMobile":"0",
    * 	"defaultLang":"CN",
    * 	"showLanguage":"cn,en",
    * 	"showAutoLang":0,
    * 	"langAutoFlag":0,
    * 	"showHelp":"0",
    * 	"helpUrl":"http://",
    * 	"webTitle":"",
    * 	"cs":"",
    * 	"copyRight":"",
    * 	"activation":"1",
    *   "neutralVersion":"1",
    * 	"custom":{
    * 	"wanTypeList":"dhcp,static,pppoe",
    * 	"versionControlSupport":"1",
    * 	"opmodeSupport":"1",
    * 	"l2tpClientSupport":"1",
    * 	"pptpClientSupport":"1",
    * 	"l2tpServerSupport":"1",
    * 	"pptpServerSupport":"1",
    * 	"openVpnServerSupport":"1",
    * 	"openVpnClientSupport":"1",
    * 	"ipsecSupport":"1",
    * 	"pppoeSpecSupport":"1",
    * 	"iptvSupport":"1",
    * 	"ipv6Support":"1",
    * 	"ddnsSupport":"1",
    * 	"wechatQrSupport":"1",
    * 	"staticRouteSupport":"1",
    * 	"policyRouteSupport":"1",
    * 	"smsSupport":"1",
    * 	"ttyServerSupport":"1",
    * 	"dtuSupport":"1",
    * 	"portalSupport":"1",
    * 	"portalSmsSupport":"1",
    * 	"firewallSupport":"1",
    * 	"cloudAcClientSupport":"1",
    * 	"PortalSupport":"1",
    * 	"qosSupport":"1",
    * 	"bioSupport":"1",
    * 	"iotSupport":"1",
    * 	"macAuthSupport":"1",
    * 	"lteTestSupport":"0",
    * 	"actStatusSupport":"1",
    * 	"snmpSupport":"1",
    * 	"ripSupport":"1",
    * 	"ospfSupport":"1",
    * 	"bgpSupport":"1",
    * 	"eoipSupport":"1",
    * 	"vrrpSupport":"1",
    * 	"bandLockSupport":"1",
   *    "nssaiSupport":"1",
    * 	"attackSupport":"1",
    *    "manageCloudSupport":"1"
    *   }
    * }
    */
    getInitConfig: {
      debugUrl: "init.json"
    },

    getSLBDongleCfg: {
      debugUrl: "slb_dongle.json"
    },
    getSLBApcliScan: {
      debugUrl: "slb_apcli_scan.json"
    },
    getSLBstatus: {
      debugUrl: "slb_status.json"
    },
    getSLBAPCfg: {
      debugUrl: "slb_ap.json"
    },
    /**
    * 获取系统状态
    * @Author Karen
    * @DateTime 2020-06-29
    * @property {String}	autoChannel	自动信道
    * @property {String}	bssid	无线MAC地址
    * @property {String}	buildTime	发布时间
    * @property {String}	channel	信道
    * @property {String}	fmVersion	固件版本
    * @property {String}	hardModel	（废弃）
    * @property {String}	ipv6Enabled	IPv6开关。1：开启，0：关闭
    * @property {String}	ipv6LanGlobalAddree	[ipv6LanGlobalAddree comment]
    * @property {String}	ipv6LanGw	[ipv6LanGw comment]
    * @property {String}	ipv6LanLinkAddree	[ipv6LanLinkAddree comment]
    * @property {String}	ipv6WanDns	[ipv6WanDns comment]
    * @property {String}	ipv6WanGlobalAddree	[ipv6WanGlobalAddree comment]
    * @property {String}	ipv6WanGw	[ipv6WanGw comment]
    * @property {String}	ipv6WanLinkAddree	[ipv6WanLinkAddree comment]
    * @property {String}	ipv6WanLinkType	[ipv6WanLinkType comment]
    * @property {String}	ipv6WanOriginType	[ipv6WanOriginType comment]
    * @property {String}	key	无线密码
    * @property {String}	lanDhcpServer	DHCP服务。0：关闭，1：开启
    * @property {String}	lanIp	LAN IP
    * @property {String}	lanMac	LAN MAC
    * @property {String}	model	[model comment]
    * @property {String}	operationMode	系统模式
    * @property {String}	ssid	SSID
    * @property {String}	wifiDualband	无线频段支持。0:2.4G，1:5G
    * @property {String}	wifiOff	无线开关。0： 开启，1：关闭
    * @return {object}
    * @example
    * request:
    * 	"topicurl":"getSysStatusCfg"
    *
    * response:
    * {
    * 	"autoChannel": 13,
    * 	"bssid": "F4:28:53:00:34:C0",
    * 	"buildTime": "2020-06-22 14:15:01",
    * 	"channel": "0",
    * 	"fmVersion": "V9.3.5cu.5684",
    * 	"hardModel": "EXT383",
    * 	"ipv6Enabled": 1,
    * 	"ipv6LanGlobalAddree": "",
    * 	"ipv6LanGw": "",
    * 	"ipv6LanLinkAddree": "",
    * 	"ipv6WanDns": "",
    * 	"ipv6WanGlobalAddree": "",
    * 	"ipv6WanGw": "",
    * 	"ipv6WanLinkAddree": "",
    * 	"ipv6WanLinkType": "",
    * 	"ipv6WanOriginType": "",
    * 	"key": "1234567890",
    * 	"lanDhcpServer": 1,
    * 	"lanIp": "192.168.1.1",
    * 	"lanMac": "F4:28:53:00:34:C0",
    * 	"model": "C735ER",
    * 	"operationMode": "1",
    * 	"ssid": "EXT383_34C0",
    * 	"wifiDualband": "0",
    * 	"wifiOff": 0
    * }
    */
    getSysStatusCfg: {
      debugUrl: "sysinfo.json"
    },
    /**
     * 获取插件功能状态
     * @Author   Karen       <Karen@carystudio.com>
     * @DateTime 2018-09-29
     * @property {String} portalEnabled   Portal设置开关状态。1：启用，0：禁用
     * @property {String} ddnsEnabled     DDNS开关状态。1：启用，0：禁用
     * @property {String} ttyEnabled      串口透传开关状态。1：启用，0：禁用
     * @property {String} smsEnabled      短信服务开关状态。1：启用，0：禁用
     * @property {String} wechatEnabled   微信管理开关状态。1：启用，0：禁用
     * @property {String} sambaEnabled    SAMBA开关状态。1：启用，0：禁用
     * @property {String} gpsEnabled      GPS开关状态。1：启用，0：禁用
     * @property {String} appFilterEnable   应用过滤开关状态。1：启用，0：禁用
     * @property {String} qosPolicyEnable   智能流控开关状态。1：启用，0：禁用
     * @example
     * request:
     * {
     *    "topicurl":"getPluginStatus"
     * }
     * response:
     * {
     *    "portalEnabled":"1",
     *    "ddnsEnabled":"1",
     *    "ttyEnabled":"1",
     *    "smsEnabled":"1",
     *    "wechatEnabled":"1",
     *    "sambaEnabled":"1",
     *    "gpsEnabled":"1",
     *    "appFilterEnable":"1",
     *    "qosPolicyEnable":"0"
     * }
     */
    getPluginStatus: {
      debugUrl: "pluginStatus.json"
    },
    /**
    * 获取系统设备实时信息
    * @Author Karen
    * @DateTime 2020-06-29
    * @property {String}	timestamp	当前时间戳（暂时没用上，先保留）
    * @property {String}	totalUpTime	总计运行时间
    * @property {String}	upTime	运行时间
    * @property {Array}	 portLinkStatus	网口信息
    * @property {String}	portLinkStatus.port	网口位置（废弃）
    * @property {String}	portLinkStatus.name	网口名称
    * @property {String}	portLinkStatus.link	网口状态。0：断开，1：连接
    * @property {String}	wanMode	上网方式
    * @property {String}	metric	跳跃数
    * @property {String}	wanConnTime	上网时间
    * @property {String}	wanConnStatus	上网状态。connected：连接，其他：未连接
    * @property {String}	wiredWanIp	WAN IP
    * @property {String}	wiredwanMask	WAN 掩码
    * @property {String}	wiredwanGw	WAN 网关
    * @property {String}	priDns	首选DNS
    * @property {String}	secDns	备选DNS
    * @property {String}	wanMac	WAN MAC
    * @property {String}	wanRx	（未用到）
    * @property {String}	wanTx	（未用到）
    * @property {String}	up	上传速率
    * @property {String}	down	下载速率
    * @property {String}	lanRx	（未用到）
    * @property {String}	lanTx	（未用到）
    * @property {String}	wlanRx	（未用到）
    * @property {String}	wlanTx	（未用到）
    * @property {String}	lanUserNum	用户数
    * @property {String}	memRatio	内存占用率
    * @property {String}	cpuRatio	CPU占用率
    * @property {String}	curConnectNum	（未用到）
    * @property {String}	maxconnectNum	（未用到）
    * @return {object}
    * @example
    * request:
    * 	"topicurl":"getNetInfo"
    *
    * response:
    * {
    * 	"timestamp":	"1588092799",
    * 	"totalUpTime":	"0;0;47;30",
    * 	"upTime":	"0;0;47;30",
    * 	"portLinkStatus":	[{
    * 	  "port":	0,
    * 	  "name":	"WAN",
    * 	  "link":	1
    *    }],
    * 	"wanMode":	"1",
    * 	"metric":	"1",
    * 	"wanConnTime":	"0",
    * 	"wanConnStatus":	"disconnected",
    * 	"wiredWanIp":	"0.0.0.0",
    * 	"wiredwanMask":	"0.0.0.0",
    * 	"wiredwanGw":	"0.0.0.0",
    * 	"priDns":	"0.0.0.0",
    * 	"secDns":	"0.0.0.0",
    * 	"wanMac":	"F4:28:55:00:24:25",
    * 	"wanRx":	"306301",
    * 	"wanTx":	"187164",
    * 	"up":	"0",
    * 	"down":	"0",
    * 	"lanRx":	"0",
    * 	"lanTx":	"0",
    * 	"wlanRx":	"0",
    * 	"wlanTx":	"0",
    * 	"lanUserNum":	"1",
    * 	"memRatio":	51,
    * 	"cpuRatio":	0,
    * 	"curConnectNum":	66,
    * 	"maxconnectNum":	16384
    * }
    */
    getNetInfo: {
      debugUrl: "net_info.json"
    },
    /**
     * getNetStateInfo     获取 NET功能 状态
     * @Author   karen       <karen@carystudio.com>
     * @DateTime 2018-7-11
     * @property {String} ssServerEnabled         影梭服务器开关。1：开启，0：关闭
     * @property {String} ssClientEnabled         影梭客户端开关。1：开启，0：关闭
     * @property {String} l2tpClientEnabled       L2tp客户端开关。1：开启，0：关闭
     * @property {String} l2tpServerEnabled       L2tp服务端开关。1：开启，0：关闭
     * @property {String} pptpClientEnabled       Pptp客户端开关。1：开启，0：关闭
     * @property {String} pptpServerEnabled     Pptp服务端开关。1：开启，0：关闭
     * @property {String} openvpnServerEnabled  Openvpn服务端开关。1：开启，0：关闭
     * @property {String} openvpnClientEnabled  Openvpn客户端开关。1：开启，0：关闭
     * @property {String} l2tpClientConnect   L2tp客户端状态。1：已连接，0：连接失败，2：拨号中
     * @property {String} pptpClientConnect   Pptp客户端状态。1：已连接，0：连接失败，2：拨号中
     * @property {String} openvpnClientConnect  Openvpn客户端状态。1：已连接，0：连接失败，2：拨号中
     * @property {String} ipsecEnabled  IPSec关。1：开启，0：关闭
     * @property {String} ipsecConnect  IPSec状态。1：已连接，0：连接失败，2：拨号中
     * @property {String} l2tpClientIp  L2TP客户端连接地址
     * @property {String} ipsecIp       IPSec连接地址
     * @property {String} pptpClientIp  PPTP客户端连接地址
     * @property {String} openvpnClientIp  OPENVPN客户端连接地址
     * @example
     * request:
     * {
     *    "topicurl":"getNetStateInfo"
     * }
     * response:
     * {
     *    "ssServerEnabled":"0",
     *    "ssClientEnabled":"0",
     *    "l2tpClientEnabled":"",
     *    "l2tpClientConnect":"0",
     *    "pptpClientConnect":"0",
     *    "pptpServerEnabled":"0",
     *    "openvpnServerEnabled":"0",
     *    "openvpnClientEnabled":"0",
     *    "openvpnClientConnect":"0",
     *    "ipsecEnabled":"1",
     *    "ipsecConnect":"1",
     *    "l2tpClientIp":"0.1.0.2",
     *    "ipsecIp":"5.5.68.3",
     *    "pptpClientIp":"8.20.36.3",
     *    "openvpnClientIp":"0.0.0.0"
     * }
     */
    getNetStateInfo: {
      debugUrl: "net_state_info.json"
    },
    /**
     * 获取LAN配置
     * @DateTime 2018-06-05
     * @property {String} wanIp       WAN IP
     * @property {String} wanMask     WAN掩码
     * @property {String} ip          LAN IP
     * @property {String} mask        LAN掩码
     * @property {String} dhcpServer      DHCP服务器
     * @property {String} dhcpStart      起始地址
     * @property {String} dhcpEnd      结束地址
     * @property {String} dhcpLease   租约时间
     * @property {String} priDns     首选DNS
     * @property {String} secDns     备选DNS
     * @property {String} mac        MAC
     * @example
     * request:
     * {
     *      "topicurl":"getLanCfg",
     * }
     * response:
     * {
     *   "wanIp":"192.168.1.1",
     *   "wanMask": "255.255.254.0",
     *   "ip":"192.168.66.1",
     *   "mask":"255.255.255.0",
     *   "dhcpServer":"1",
     *   "dhcpStart":"192.168.66.2",
     *   "dhcpEnd":"192.168.66.254",
     *   "dhcpLease":"86400",
     *   "priDns":"192.168.66.1",
     *   "secDns":"",
     *   "mac":"f4:22:55:96:32:63"
     * }
     */
    getLanCfg: {
      debugUrl: "lan.json"
    },
    /**
     * 保存LAN配置
     * @DateTime 2018-06-05
     * @param {String}
     * @example
     * request:
     * {
     *     "priDns":"192.168.66.1",
     *     "secDns":"",
     *     "mac":"f4:22:55:96:32:63",
     *     "ip":"192.168.66.1",
     *     "mask":"255.255.255.0",
     *     "dhcpServer":"1",
     *     "dhcpStart":"192.168.66.2",
     *     "dhcpEnd":"192.168.66.254",
     *     "dhcpLease":"86400",
     *     "topicurl":"setLanCfg"
     * }
     */
    setLanCfg: null,
    /**
    * 获取外网信息配置
    * @Author Karen
    * @DateTime 2020-06-29
    * @property {String}	wanMode	上网方式
    * @property {String}	staticMtu	静态IP MTU
    * @property {String}	dhcpMtu	DHCP MTU
    * @property {String}	pppoeMtu	宽带上网 MTU
    * @property {String}	pppoeSpecType	PPPoe 特殊策略
    * @property {String}	pppoeOpMode	（未知）默认下发0
    * @property {String}	staticIp	静态IP地址
    * @property {String}	staticMask	静态掩码
    * @property {String}	staticGw	静态网关
    * @property {String}	pppoeUser	宽带账号
    * @property {String}	pppoePass	宽带密码
    * @property {String}	wanConnStatus	网络连接状态。connected：已连接，其他：未连接
    * @property {String}	dnsMode	DNS模式。0：自动，1：手动
    * @property {String}	priDns	首选DNS
    * @property {String}	secDns	备选DNS
    * @property {String}	lanIp	LAN IP地址
    * @property {String}	wanDefMac	缺省MAC地址
    * @property {String}	macCloneMac	克隆MAC地址
    * @property {String}	macCloneEnabled	使用克隆MAC。1：是，0：否
    * @property {String}	ipv6Enabled	IPv6开关。1：开，0：关
    * @property {String}	ipv6StaticIp	IPv6 IP地址
    * @property {String}	ipv6StaticGw	IPv6 网关
    * @property {String}	ipv6PriDns	IPv6 首选DNS
    * @property {String}	ipv6SecDns	IPv6 备选DNS
    * @return {object}
    * @example
    * request:
    * 	"topicurl":"getWanCfg"
    *
    * response:
    * {
    * 	"wanMode":"0",
    * 	"staticMtu":"1500",
    * 	"dhcpMtu":"1500",
    * 	"pppoeMtu":"1492",
    * 	"pppoeSpecType":"0",
    * 	"pppoeOpMode":"0",
    * 	"staticIp":"192.168.16.111",
    * 	"staticMask":"255.255.255.0",
    * 	"staticGw":"192.168.16.1",
    * 	"pppoeUser":"123123",
    * 	"pppoePass":"admin",
    * 	"wanConnStatus":"connected",
    * 	"dnsMode":"0",
    * 	"priDns":"192.168.16.1",
    * 	"secDns":"114.114.114.114",
    * 	"lanIp":"192.168.0.253",
    * 	"wanDefMac":"F4:28:54:00:28:37",
    * 	"macCloneMac":"64:28:54:00:28:37",
    * 	"macCloneEnabled":"0",
    * 	"ipv6Enabled":"1",
    * 	"ipv6StaticIp":"2006:d0b0:3000:3001::1/64",
    * 	"ipv6StaticGw":"2001:d0b0:3000:3001::1/64",
    * 	"ipv6PriDns":"2001:d0b0:3000:3001::2",
    * 	"ipv6SecDns":"2001:d0b0:3000:3001::ffff"
    * }
    */
    getWanCfg: {
      debugUrl: "wan.json"
    },
    /**
     * 保存WAN配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-03-28
     * @param {String} wanMode      WAN连接类型
     * @example
     * request:
     *{
     *      wanMode: "1"
     * }
     */
    setWanCfg: null,
    /**
     *  * 获取Modem配置
     * @Author   Felix       <felix@carystudio.com>
     * @Author   Frankie     <frankie@carystudio.com>
     * @DateTime 2020-06-18
     * @property {String} modemModel        模块型号
     * @param {String} dialWay                拨号方式， 0: 自动， 1:dhcp， 2:ppp
     * @property {String} user4g          拨号用户名（option）
     * @property {String} pass4g          拨号密码（option）
     * @property {String} apn           APN（option）
     * @property {String} dialNum         拨号号码（option）
     * @property {String} pinCode         SIM PIN码（option）
     * @property {String} bandLock        频段锁定（默认0：自动，页面可用选择 61(1.4G)，62(1.8G) ）
     * @property {String} sim         SIM卡选择，1：SIM卡1， 2：SIM卡2（当前暂未使用） ///当前未使用，页面隐藏
     *
     * @property {String} chap          ppp拨号，认证 & 加密，CHAP
     * @property {String} pap         ppp拨号，认证 & 加密，PAP
     * @property {String} mschap        ppp拨号，认证 & 加密，MS-CHAP
     * @property {String} ms2chap       ppp拨号，认证 & 加密，MS2-CHAP
     * @property {String} eap         ppp拨号，认证 & 加密，EAP
     *
     * @property {String} noccp         ppp拨号，压缩 & 控制协议，压缩控制协议
     * @property {String} noaccomp        ppp拨号，压缩 & 控制协议，地址/控制压缩
     * @property {String} nopcomp       ppp拨号，压缩 & 控制协议，协议域压缩
     * @property {String} novj          ppp拨号，压缩 & 控制协议，VJ TCP/IP 头部压缩
     * @property {String} novjccomp       ppp拨号，压缩 & 控制协议，连接ID压缩
     *
     * @property {String} keepaliveSwitch             链接保活设置开关： 0：关闭， 1：开启
     * @property {String} keepaliveAddr       链接保活的探测地址
     * @property {String} keepalivePort       链接保活的探测端口
     * @property {String} keepaliveInterval     链接保活的探测间隔，单位s
     *
     * @property {String} debug         ppp拨号，其他，调试
     * @property {String} usepeerdns      ppp拨号，其他，对端DNS
     * @property {String} failure       ppp拨号，其他，LCP重连次数 ，范围（0~512），页面的单位是S，有问题；这个不需要单位
     * @property {String} interval        ppp拨号，其他，LCP间隔时间
     * @property {String} dialMtu       ppp拨号，其他，MTU
     * @property {String} dialMru       ppp拨号，其他，MRU
     * @property {String} localIp       ppp拨号，其他，本地IP
     * @property {String} remoteIp        ppp拨号，其他，远端IP
     *
     * @property {String} nomppe        ppp拨号，专家选项：NOMPPE
     * @property {String} mppe_required     ppp拨号，专家选项：MPPE Required
     * @property {String} mppe_stateless    ppp拨号，专家选项：MPPE Stateless
     * @property {String} nodeflate       ppp拨号，专家选项：Nodeflate
     * @property {String} nobsdcomp       ppp拨号，专家选项：Nobsdcomp
     * @property {String} asyncmap        ppp拨号，专家选项：Default Asyncmap
     * @property {String} saEnable        独立5g开关
     * @example
     * request:
     * {
     *    "topicurl":"getModemCfg",
     * }
     * response:
     * {
     *    "apn":"3gnet"
     * }
     */
    getModemCfg: {
      debugUrl: "modem.json"
    },
     /**
     * 保存Modem配置
     * @Author   Felix       <felix@carystudio.com>
     * @Author   Frankie     <frankie@carystudio.com>
     * @DateTime 2020-06-18
     * @param {String} dialWay        拨号方式， 0: 自动， 1:dhcp， 2:ppp
     * @param {String} user4g         拨号用户名
     * @param {String} pass4g         拨号密码
     * @param {String} apn          APN
     * @param {String} dialNum        拨号号码
     * @param {String} pinCode        SIM PIN码
     * @property {String} bandLock        频段锁定（默认0：自动，页面可用选择 61(1.4G)，62(1.8G) ）
     * @param {String} sim          SIM卡选择，1：SIM卡1， 2：SIM卡2   ////当前暂未使用，页面不用处理
     *
     * @param {String} chap         ppp拨号，认证 & 加密，CHAP
     * @param {String} pap          ppp拨号，认证 & 加密，PAP
     * @param {String} mschap       ppp拨号，认证 & 加密，MS-CHAP
     * @param {String} ms2chap        ppp拨号，认证 & 加密，MS2-CHAP
     * @param {String} eap          ppp拨号，认证 & 加密，EAP
     *
     * @param {String} noccp        ppp拨号，压缩 & 控制协议，压缩控制协议
     * @param {String} noaccomp       ppp拨号，压缩 & 控制协议，地址/控制压缩
     * @param {String} nopcomp        ppp拨号，压缩 & 控制协议，协议域压缩
     * @param {String} novj         ppp拨号，压缩 & 控制协议，VJ TCP/IP 头部压缩
     * @param {String} novjccomp      ppp拨号，压缩 & 控制协议，连接ID压缩
     *
     * @param {String} keepaliveSwitch    链接保活设置开关
     * @param {String} keepaliveAddr      链接保活的探测地址
     * @param {String} keepalivePort      链接保活的探测端口
     * @param {String} keepaliveInterval    链接保活的探测间隔
     *
     * @param {String} debug        ppp拨号，其他，调试
     * @param {String} usepeerdns     ppp拨号，其他，对端DNS
     * @property {String} failure       ppp拨号，其他，LCP重连次数 ，范围（0~512），页面的单位是S，有问题；这个不需要单位
     * @param {String} interval       ppp拨号，其他，LCP间隔时间
     * @param {String} dialMtu        ppp拨号，其他，MTU
     * @param {String} dialMru        ppp拨号，其他，MRU
     * @param {String} localIp        ppp拨号，其他，本地IP
     * @param {String} remoteIp       ppp拨号，其他，远端IP
     *
     * @param {String} nomppe       ppp拨号，专家选项：NOMPPE
     * @param {String} mppe_required    ppp拨号，专家选项：MPPE Required
     * @param {String} mppe_stateless   ppp拨号，专家选项：MPPE Stateless
     * @param {String} nodeflate      ppp拨号，专家选项：Nodeflate
     * @param {String} nobsdcomp      ppp拨号，专家选项：Nobsdcomp
     * @param {String} asyncmap       ppp拨号，专家选项：Default Asyncmap
     *
     * @example
     * request:
     * {
     *    "topicurl":"getModemCfg",
     * }
     * response:
     * {
     *    "apn":"3gnet"
     * }
     */
    setModemCfg: null,
    /**
    * 手动拨号
    * @Author Karen
    * @DateTime 2020-06-29
    * @param {String}	dialStatus	状态。1：连接，0：断开
    * @property {String}	success	应用成功。true：成功，false：失败
    * @property {String}	wtime	需要等待生效的时间
    * @return {object}
    * @example
    * request:
    * {
    * 	"topicurl":"setManualDialCfg",
    * 	"dialStatus":"1"
    * }
    * response:
    * {
    * 	"success": true,
    * 	"wtime": 1
    * }
    */
    setManualDialCfg: null,
    /**
     * 获取登录用户名
     * @Author   Amy       <amy@carystudio.com>
     * @DateTime 2018-06-05
     * @property {String} admuser       管理员的用户名
     * @example
     * request:
     * {
     *      "topicurl":"getPasswordCfg"
     * }
     * response:
     * {
     *      "admuser":"admin",
     * }
     */
    getPasswordCfg: {
      debugUrl: "password.json"
    },
    /**
     * 保存登录密码
     * @Author   Amy       <amy@carystudio.com>
     * @DateTime 2018-06-05
     * @param {String} admuser          管理员的用户名
     * @param {String} admpass          管理员的新密码
     * @param {String} origPass         管理员的原密码
     * @example
     * request:
     * {
     *      "topicurl":"setPasswordCfg",
     *      "admuser":"admin",
     *      "admpass":"admin",
     *      "origPass":"admin"
     * }
     */
    setPasswordCfg: null,
    /**
    * 同步本地时间
    * @Author Karen
    * @DateTime 2020-06-29
    * @param {String}	host_time	当前的时间，格式：yyyy-MM-dd HH:mm:ss
    * @property {String}	success	应用成功。true：成功，false：失败
    * @property {String}	wtime	需要等待生效的时间
    * @return {object}
    * @example
    * request:
    * {
    * 	"topicurl":"NTPSyncWithHost",
    * 	"host_time":"1"
    * }
    * response:
    * {
    * 	"success": true,
    * 	"wtime": 1
    * }
    */
    NTPSyncWithHost: null,
    /**
     * 获取NTP配置
     * @Author   Bob       <Bob_huang@carystudio.com>
     * @DateTime 2017-11-02
     * @property {String} currentTime       当前时间
     * @property {String} tz                时区
     * @property {String} server       ntp服务器。域名间使用*连接
     * @property {String} enable  自动同步ntp：0：不勾选，1：勾选
     * @example
     * request:
     * {
     *      "topicurl":"getNtpCfg"
     * }
     * response:
     * {
     *      "tz":"UTC-8",
     *      "server":"time.nist.gov",
     *      "enable":1,
     *      "currentTime":"Fri Nov 3 00:48:18 GMT 2017"
     * }
     */
    getNtpCfg: {
      debugUrl: "time.json"
    },
    /**
     * 保存NTP配置
     * @Author   Bob       <Bob_huang@carystudio.com>
     * @DateTime 2017-11-03
     * @param {String} tz               时区
     * @param {String} server      ntp服务器。域名间使用*连接
     * @param {String} enable 自动同步ntp：0：不勾选，1：勾选
     * @example
     * request:
     * {
     *       "topicurl":"setNtpCfg",
     *       "tz":"UTC-8",
     *       "server":"time.nist.gov",
     *       "enable":"1"
     * }
     */
    setNtpCfg: null,
    /**
     * 检测云升级信息
     * @Author   karen       <karen@carystudio.com>
     * @DateTime 2017-11-07
     * @property {String} cloudFwStatus    检测云升级。New：已是最新版本，UnNet:没有网络，Update：有可更新版本
     * @property {String} newVersion       新的固件版本
     * @example
     * request:
     * {
     *      "topicurl":"CloudSrvVersionCheck",
     * }
     * response:
     * {
     *      "cloudFwStatus":"New",
     *      "newVersion":"V6.2c.464"
     * }
     */
    CloudSrvVersionCheck: {
      debugUrl: "firmware_info.json"
    },
    /**
     * 获取固件信息
     * @Author   karen       <karen@carystudio.com>
     * @DateTime 2017-11-07
     * @property {String} fmVersion      当前软件版本
     * @property {String} buildTime      当前软件发布时间
     * @property {String} cloudFw        是否支持云升级。0:no， 1:yes
     * @property {String} platform        当前平台
     * @property {String} cloudFwStatus        云状态
     * @property {String} flashSize       flash固件的大小
     * @property {String} hardModel           硬件型号
     * @property {String} lanIp           IP地址
     * @property {String} maxSize          校验文件最大值。单位：kb,以1000位进制数。
     * @property {String} upgradeAction      返回当前升级固件的url，返回完整的URL
     * @property {String} setUpgradeFW      设置升级检测主题。默认：0调用的是CloudACMunualUpdate主题。如果1则调用setUpgradeFW主题
     * @example
     * request:
     * {
     *      "topicurl":"FirmwareUpgrade"
     *
     * }
     * response:
     * {
     *      "fmVersion":"0",
     *      "buildTime":"Oct 17 2017 10:34:08",
     *      "cloudFw":"0",
     *      "platform":"mtk",
     *      "cloudFwStatus":"",
     *      "flashSize":"16",
     *      "hardModel":"CS182R",
     *      "lanIp":"192.168.0.1",
     *      "maxSize":"10000",
     *      "upgradeAction":"/cgi-bin/cstecgi.cgi?action=upload&setUpgradeFW",
     *      "setUpgradeFW":1
     * }
     */
    FirmwareUpgrade: {
      debugUrl: "firmware_info.json"
    },
    /**
     * 本地升级
     * @Author   karen       <karen@carystudio.com>
     * @DateTime 2017-11-07
     * @param {String} FileName             文件名
     * @param {String} ContentLength        内容大小
     * @param {String} cloudFlag            1:云升级  0:本地升级
     * @property {String} upgradeStatus     上传状态。0：上传失败，1：上传成功
     * @property {String} upgradeERR        错误信息
     * @example
     * request:
     * {
     *       "topicurl":"setUpgradeFW",
     *       "FileName":"",
     *       "ContentLength":""
     * }
     * response:
     * {
     *       "upgradeStatus":"1",
     *       "upgradeERR":"MM_FwFileInvalid"
     * }
     */
    setUpgradeFW: null,
    /**
     * 云检测固件升级
     * @Author   amy       <amy@carystudio.com>
     * @DateTime 2017-11-07
     * @property {String} Flags         带配置升级的标志，1：带，0：不带
     * @property {String} FileName      固件名称
     * @example
     * request:
     * {
     *       "topicurl":"CloudACMunualUpdate",
     * }
     * response:
     * {
     *       "Flags":"0",
     *       "FileName":""
     * }
     */
    CloudACMunualUpdate: null,
    /**
     *恢复出厂
     */
    LoadDefSettings: null,
    /**
     *重启
     */
    RebootSystem: null,
    /**
     * 获取系统配置
     * @Author   amy       <amy@carystudio.com>
     * @DateTime 2017-12-16
     * @property {String} operationMode        系统模式。1：网关，0：桥模式，2：中继，3：wisp模式，4：MESH
     * @property {String} hardModel            固件
     * @property {String} meshEnabled          mesh的开关
     * @property {String} exportAction         导出的配置路径。
     * @property {String} importAction         导入的配置路径。
     * @property {String} maxSize              校验文件最大值。单位：kb,以1000位进制数。
     * @example
     * request:
     * {
     *      "topicurl":"SystemSettings"
     * }
     * response:
     * {
     *      "operationMode":0,
     *      "hardModel":"",
     *      "meshEnabled":0,
     *      "exportAction":'/cgi-bin/ExportSettings.sh',
     *      "importAction":'/cgi-bin/cstecgi.cgi?action=upload&setting/setUploadSetting',
     *      "maxSize":"100000"
     * }
     */
    SystemSettings: {
      debugUrl: "config.json"
    },
    /**
     * 保存语言配置
     * @Author   Karen       <Karen@carystudio.com>
     * @DateTime 2018-10-26
     * @param {String} lang               语言：'cn'：中文，'en': 英文
     * @param {String} langFlag           自动检测。值：0：自动，1：手动
     * @example
     * request:
     * {
     *      "topicurl":"setLanguageCfg",
     *      "lang":"cn",
     *      "langFlag":"0"
     * }
     */
    setLanguageCfg: null,
    /**
     * 获取新平台云升级状态
     * @Author   karen       <karen@carystudio.com>
     * @DateTime 2018-08-21
     * @property {String} cloudFwStatus    检测状态。1：没有网络，2：已是最新版本，3：检测中，4：有可更新版本
     * @property {String} newVersion       新的固件版本
     * @example
     * request:
     * {
     *       "topicurl":"getCloudSrvCheckStatus"
     *
     * }
     * response:
     * {
     *       "cloudFwStatus":"4",
     *       "newVersion":"V6.2c.464"
     * }
     */
    getCloudSrvCheckStatus: {
      debugUrl: "firmware_info.json"
    },
    /**
     * 获取微信管理的链接
     * @Author   Yexk       <yexk@carystudio.com>
     * @DateTime 2018-01-20
     * @property {String} static     1 - 网络接入正常，crp服务运行正常，url为生成二维码的链接 0 - crp服务异常
     * @property {String} url        微信URL。前缀：http://www.carystudio.com/router/wechatmanage/routerurl?url=
      后缀：设备远程访问地址http://f42854000666.d.carystudio.com:9080/的urlencode
      其中f42854000666为设备bridge iface的MAC地址去掉':'号的小写，做为设备的ID
     * @example
     * request:
     * {
     *      "topicurl":"getCrpcConfig"
     * }
     * response:
     * {
     *      "status":"1",
     *      "url":"http://www.carystudio.com/router/wechatmanage/routerurl?url=http%3a%2f%2ff42854000666.d.carystudio.com%3a9080%2f"
     * }
     *
     */
    getCrpcConfig: {
      debugUrl: "crpc.json"
    },
    /**
     * 获取远程日志配置
     * @Author   karen       <karen@carystudio.com>
     * @DateTime 2020-03-27
     * @property {String} enabled     日志开关
     * @property {String} host        日志服务器
     * @property {String} port        日志端口
     * @example
     * request:
     * {
     *      "topicurl":"getSyslogCfg"
     * }
     * response:
     * {
     *      "enabled":"0",
     *      "host":"192.168.0.1",
     *      "port":"512"
     * }
     */
    getSyslogCfg: {
      debugUrl: "remote_log.json"
    },
    /**
     * 保存远程日志配置
     * @Author   karen       <karen@carystudio.com>
     * @DateTime 2020-03-27
     * @param {String} enabled     日志开关
     * @param {String} host        日志服务器
     * @param {String} port        日志端口
     * @example
     * request:
     * {
     *      "topicurl":"setSyslogCfg"
     *      "enabled":"0",
     *      "host":"192.168.0.1",
     *      "port":"512"
     * }
     */
    setSyslogCfg: null,
    /**
     * 清除系统日志
     * @Author   karen       <karen@carystudio.com>
     * @DateTime 2020-03-27
     * @param {String} type        日志类型。Kernel：内核，Message：信息，Application：应用
     * @example
     * request:
     * {
     *      "topicurl":"clearSyslog",
     *      "type":"Kernel"
     * }
     */
    clearSyslog: null,
    /**
     * 获取系统日志
     * @Author   karen       <karen@carystudio.com>
     * @DateTime 2020-03-27
     * @param {String} type             日志类型Message、Kernel、Application
     * @property {String} syslog        日志信息
     * @example
     * request:
     * {
     *      "topicurl":"showSyslog",
     *      "type":"Kernel"
     * }
     * response:
     * {
     *      "syslog":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
     * }
     */
    showSyslog: {
      debugUrl: "syslog.json"
    },
    /**
     * 获取客户端列表
     * @Author   Karen       <Karen@carystudio.com>
     * @DateTime 2018-09-12
     * @property {Object} obj       一个对象带表一条信息
     * @property {String} obj.idx   记录条目素引值
     * @property {String} obj.ip    IP地址
     * @property {String} obj.mac   MAC地址
     * @property {String} obj.livetime   连接时间
     * @property {String} obj.ifaceType   连接接口
     * @return   {Array}
     * @example
     * request:
     * {
     *      "topicurl":"getOnlineMsg"
     * }
     * response:
     * [
     *    {
     *        "idx":"0",
     *        "ip":"192.168.0.3",
     *        "mac":"88:51:fb:4a:dc:2c",
     *        "livetime":"",
     *        "ifaceType ":""
     *    }
     * ]
     */
    getOnlineMsg: {
      debugUrl: "dhcpclient.json"
    },
    /**
     * 获取Lte配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2018-03-31
     * @property {String} registStatus      状态, idle:闲置, searching：搜网中，connected：已注册，noSim：SIM卡异常，simPinLock：SIM卡PIN锁定，simPukLock：SIM卡PUK锁定，noModem：模块异常，unReg: 未注册，regHome: 已注册，本地网，regRoaming：已注册，漫游，regDeny：注册被拒绝，regUnknow：未知网络
     * @property {String} wan4gIp           4G/5G IP,
     * @property {String} wan4gConnStatus   connected, disconnected
     * @property {String} signal            4G信号强度
     * @property {String} imei              IMEI : 如450050475635516
     * @property {String} imsi              IMSI : 如4500504756355161234
     * @property {String} phoneNumber       4G卡号码
     * @property {String} model             模块型号
     * @property {String} isp               运营商信息。0：专用网络，1：中国移动；2：中国联通；3：中国电信；4：中国铁通，5：中国卫通
     * @property {String} bandLte           频段
     * @property {String} netType           1:4G/5G,2:3G
     * @property {String} iccid             SIM卡卡号，相当于SIM的身份证, 唯一识别号码，共有20个字符
     * @property {String} cellId      蜂窝小区ID，用于定位
     * @property {String} lac       位置区码（location area code），用于定位
     */
    getLteAllInfo: {
      debugUrl: "lte.json"
    },
    /**
     * 获取无线配置
     * @Author   Bob       <Bob_huang@carystudio.com>
     * @DateTime 2017-11-04
     * @param {String} wifiIdx          无线信息：1:5G 0:2.4G
     * @property {String} wifiOff       状态：0：启用，1：禁用
     * @property {String} channel       信道
     * @property {String} hssid         广播SSID
     * @property {String} bw            频宽
     * @property {String} key           密码
     * @property {String} ssid          SSID
     * @property {String} band          频段
     * @property {String} noForwarding  AP隔离
     * @property {String} wifiDualband  双频标记
     * @property {String} countryBt        是否支持国家码，值：1：支持，0：不支持
     * @property {String} countryCode      国家地区。CN：中国，US：美国，EU：欧洲，MY：马来西亚，JP：日本，OT：其他
     * @property {String} countryCodeList  国家码列表。CN：中国，US：美国，EU：欧洲，OT：其他，IA：印尼 等
     * @property {String} apcliEnable      0:未中继*G； 1:中继*G
     * @property {String} ipAddress        IP地址, station有效
     * @property {String} mask             子网掩码, station有效
     * @property {String} gateway          网关地址, station有效
     * @property {String} dns              DNS, station有效
     * @example
     * request:
     * {
     *      "topicurl":"getWiFiBasicConfig",
     *      "wifiIdx":"0"
     * }
     * response:
     * {
     *      "wifiOff":"0",
     *      "channel":"0",
     *      "operationMode":"2",
     *      "hssid":"0",
     *      "bw":"0",
     *      "wifiSchEnabled":"1",
     *      "key":"12345678",
     *      "ssid":"TOTOLINK_A800R_5G",
     *      "band":"9",
     *      "authMode":"WPAPSKWPA2PSK",
     *      "encrypType":"TKIPAES",
     *      "noForwarding":"0",
     *      "apcliEnabled":"0",
     *      "wifiDualband":"1",
     *      "countryBt":"1",
     *      "countryCode":"CN",
     *      "countryCodeList":"CN,US,EU,JP",
     *      "apcliEnable":"0"，
     *      "ipAddress":"192.168.1.11"，
     *      "mask":"255.255.255.0"，
     *      "gateway":"192.168.1."，
     *      "dns":"192.168.1."
     * }
     */
    getWiFiBasicConfig: {
      debugUrl: "wifi.json"
    },
    /**
     * 设置无线配置
     * @Author   Bob       <Bob_huang@carystudio.com>
     * @DateTime 2017-11-04
     * @param {String} ssid         SSID
     * @param {String} band         频段
     * @param {String} channel      信道
     * @param {String} hssid        广播SSID
     * @param {String} key          密码
     * @param {String} bw           频宽 2.4G: bw=0(频宽自动), bw=1(频宽20Hmz), bw=2(频宽40Hmz)  5G: bw=0(频宽自动), bw=1(频宽20Hmz), bw=2(频宽40Hmz), bw=3(频宽80Hmz)
     * @param {String} noForwarding AP隔离
     * @param {String} addEffect    判断设置的是开关还是配置，值：1：开关。0：配置值
     * @param {String} wifiIdx      无线信息：1:5G 0:2.4G
     * @param {String} countryCode  国家地区。CN：中国，US：美国，EU：欧洲，MY：马来西亚，JP：日本，OT：其他
     * @param {String} wifiType     工作模式 0:ap, 1:station, 2:repeater
     * @example
     * request:
     * {
     *      "topicurl":"setWiFiBasicConfig",
     *      "wifiIdx":"0",
     *      "addEffect":"0",
     *      "ssid":"TOTOLINK_A800R_5G",
     *      "band":"14",
     *      "channel":"149",
     *      "hssid":"0",
     *      "key":"",
     *      "bw":"1",
     *      "noForwarding":"0",
     *      "wscDisabled":"0",
     *      "countryCode":"CN",
     *      "wifiType":"0"
     * }
     */
    setWiFiBasicConfig: null,
    /**
     * 获取扫描AP列表
     * @Author   Felix       <amy@carystudio.com>
     * @DateTime 2017-12-20
     * @property {String} ssid      SSID
     * @property {String} bssid     MAC
     * @property {String} channel   信道
     * @property {String} encrypt   加密方式
     * @property {String} cipher    加密算法
     * @property {String} band      频段
     * @property {String} signal    信号强度
     * @example
     * request:
     * {
     *      "topicurl":"getWiFiApcliScan"
     * }
     * response:
     * [
     *    {
     *       "ssid":"a1",
     *       "bssid":"F4:11:22:33:44:44",
     *       "channel":"11",
     *       "encrypt":"NONE",
     *       "cipher":"",
     *       "band":"B",
     *       "signal":"78"
     *    }
     * ]
     */
    getWiFiApcliScan: {
      debugUrl: "apcliscan.json"
    },
    /**
     * 获取中继状态
     * @Author   Felix       <amy@carystudio.com>
     * @DateTime 2017-12-20
     * @property {String} rptSwitch
     * @property {String} apcliSsid
     * @property {String} rptConnStatus
     * @example
     * request:
     * {
     *      "topicurl":"getWiFiApcliScan"
     * }
     * response:
     * [
     *    {
     *       "rptSwitch":"",
     *       "apcliSsid":"",
     *       "rptConnStatus":""
     *    }
     * ]
     */
    getRptstatus: {
      debugUrl: "rptstatus.json"
    },
    setClientAdvCfg: null,
    
    /**
     * 保存中继AP配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-03-07
     * @param {String} ssid_rpt         SSID
     * @param {String} bssid_rpt        BSSID
     * @param {String} channel_rpt      信道
     * @param {String} encrypt_rpt      加密算法
     * @param {String} cipher_rpt       加密类型
     * @param {String} password_rpt     加密密码
     * @param {String} wifiIdx_rpt      wifi接口, 0:2.4G, 1:5G
     * @example
     * request:
     * {
     *      "topicurl":"setClientModeCfg",
     *      "ssid_rpt":"a1",
     *      "bssid_rpt":"F4:11:22:33:44:44",
     *      "channel_rpt":"11",
     *      "encrypt_rpt":"",
     *      "cipher_rpt":"",
     *      "password_rpt":"12345678",
     *      "wifiIdx_rpt":"0"
     * }
*/
    setClientModeCfg: null,
    /**
     * 保存中继AP配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-03-07
     * @param {String} apcliSsid        SSID
     * @param {String} apcliBssid       BSSID
     * @param {String} apcliChannel     信道
     * @param {String} apcliAuthMode    加密方式
     * @param {String} apcliEncrypType  加密算法
     * @param {String} apcliKey         加密密码
     * @param {String} operationMode    系统模式 3:station, 2:repeater, 1:ap
     * @param {String} apcliKey         加密密码
     * @param {String} wifiType         工作模式 0:ap, 1:station, 2:repeater
     * @param {String} wifiIdx          wifi接口, 0:2.4G, 1:5G
     * @example
     * request:
     * {
     *      "topicurl":"setWiFiRepeaterConfig",
     *      "apcliSsid":"a1",
     *      "apcliBssid":"F4:11:22:33:44:44",
     *      "apcliChannel":"11",
     *      "apcliAuthMode":"NONE",
     *      "apcliEncrypType":"",
     *      "apcliKey":"12345678",
     *      "operationMode":"2",
     *      "wifiType":"1",
     *      "wifiIdx":"0"
     * }
     */
    setWiFiRepeaterConfig: null,
    /**
     * 设置系统模式配置
     * @Author   karen       <karen@carystudio.com>
     * @DateTime 2018-09-07
     * @param {String} operationMode        系统模式, 0：桥，1：网关，2：中继，3：WISP
     * @example
     * request:
     * {
     *      "topicurl":"setOpMode"
     *      "operationMode":"0",
     * }
     */
    setOpMode: null,
    /**
     * 获取VPN检测配置
     * @Author   Karen       <Karen@carystudio.com>
     * @DateTime 2018-09-20
     * @property {String} vpncheckEnable      VPN检测开关
     * @property {String} checkInterval        检测间隔
     * @property {String} reconnectThreshold     重拨VPN阈值
     * @property {String} networkThreshold     重新接入无线网络阈值
     * @property {String} rebootThreshold     重启系统阈值
     * @property {String} flowUprate         上行（发送）阈值
     * @property {String} flowDownrate       下行（接收）阈值
     * @example
     * request:
     * {
     *      "topicurl":"getVpnCheckCfg"
     * }
     * response:
     * {
     *      "vpncheckEnable":"1",
     *      "checkInterval":"120",
     *      "reconnectThreshold":"5",
     *      "networkThreshold":"0",
     *      "rebootThreshold":"0",
     *      "flowEnable":"1",
     *     "flowUprate":"1024",
     *     "flowDownrate":"1024"
     * }
     */
    getVpnCheckCfg: {
      debugUrl: "vpn_check.json"
    },
    /**
     * 保存VPN检测配置
     * @Author   Karen       <Karen@carystudio.com>
     * @DateTime 2018-09-20
     * @param {String} vpncheckEnable      VPN检测开关
     * @param {String} checkInterval        检测间隔
     * @param {String} reconnectThreshold     重拨VPN阈值
     * @param {String} networkThreshold     重新接入无线网络阈值
     * @param {String} rebootThreshold     重启系统阈值
     * @param {String} flowEnable         流量检测开关
     * @param {String} flowUprate         上行（发送）阈值
     * @param {String} flowDownrate       下行（接收）阈值
     * @example
     * request:
     * {
     *      "topicurl":"setVpnCheckCfg"
     *      "vpncheckEnable":"1",
     *      "checkInterval":"120",
     *      "reconnectThreshold":"5",
     *      "networkThreshold":"0",
     *      "rebootThreshold":"0",
     *      "flowEnable":"1",
     *      "flowUprate":"1024",
     *      "flowDownrate":"1024"
     * }
     */
    setVpnCheckCfg: null,
    /**
     * 获取VPN客户端日志
     * @Author   Karen       <Karen@carystudio.com>
     * @DateTime 2018-09-29
     * @param {String} vpnType   VPN类型。l2tp pptp openvpn ipsec
     * @property {String} log   日志信息
     * @example
     * request:
     * {
     *      "topicurl":"getVpnClinentLog",
     *      "vpnType":"l2tp"
     * }
     * response:
     * {
     *      "log":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
     * }
     */
    getVpnClinentLog: {
      debugUrl: "vpn_log.json"
    },
    /**
     * 获取DMZ配置
     * @Author   Jeff       <Jeff@carystudio.com>
     * @DateTime 2017-11-02
     * @property {String} dmzEnabled       DMZ开关, 0：禁用，1：启用
     * @property {String} dmzAddress       DMZ域名地址
     * @property {String} lanIp            局域网IP地址
     * @property {String} lanNetmask       局域网的子网掩码
     * @property {String} stationIp        计算机连接的IP地址
     * @example
     * request:
     * {
     *      "topicurl":"getDMZCfg"
     * }
     * response:
     * {
     *      "dmzEnabled":"1",
     *      "dmzAddress":"192.168.0.8",
     *      "lanIp":"192.168.0.5",
     *      "lanNetmask":"255.255.255.0",
     *      "stationIp":"192.168.0.6"
     * }
     */
    getDMZCfg: {
      debugUrl: "dmz.json"
    },
    /**
     * 保存DMZ配置
     * @Author   Jeff       <Jeff@carystudio.com>
     * @DateTime 2017-11-02
     * @param {String} dmzEnabled      DMZ开关, 0：禁用，1：启用
     * @param {String} dmzAddress      DMZ域名地址
     * @example
     * request:
     * {
     *     "topicurl":"setDMZCfg",
     *     "dmzEnabled":1,
     *     "dmzAddress":"192.168.0.8"
     * }
     */
    setDMZCfg: null,
    /**
     * 获取IP/MAC列表
     * @Author   Yexk       <yexk@carystudio.com>
     * @DateTime 2017-11-07
     * @property {String} enable   原来的意思是是否开启？还是什么？新版本中建议去掉
     * @property {String} obj       一个对象带表一条信息
     * @property {String} obj.idx   信道的标识 0 2.4g  1 5g ？
     * @property {String} obj.ip    IP地址
     * @property {String} obj.mac   MAC地址
     * @example
     * request:
     * {
     *      "topicurl":"getArpTable"
     * }
     * response:
     * [
     *    {
     *        "enable":"1"
     *    },
     *    {
     *        "idx":"0",
     *        "ip":"192.168.0.3",
     *        "mac":"88:51:fb:4a:dc:2c"
     *    }
     * ]
     */
    getArpTable: {
      debugUrl: "dhcpclient.json"
    },
    /**
     * 获取NAT配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-3-02
     * @property {String} enable    开关 0:关闭  1:开启
     * @property {String} interface   可选接口
     * @property {String} idx           规则序号
     * @property {String} protocol      协议 ：tcp、udp、all
     * @property {String} natType       NAT类型:0：DNAT 1：SNAT
     * @property {String} addressType   地址类型：interface、staticIp
     * @property {String} oAddress      源地址
     * @property {String} mAddress      映射地址
     * @property {String} oPort         源端口
     * @property {String} mPort         映射端口
     * @example
     * request:
     * {
     *      "topicurl":"getNatRules"
     * }
     * response:
     * {
     *    "enable": "1",
     *    "interface": "LAN,WAN",
     *    "rule":[
     *      {
     *        "idx":"1",
     *        "natType":"0",
     *        "protocol":"all",
     *        "addressType":"interface",
     *        "oAddress":"br0",
     *        "mAddress":"192.168.6.1",
     *        "oPort":"8888-8890",
     *        "mPort":"7777-7780"
     *     }
     * ]
     * }
     */
    getNatRules: {
      debugUrl: "rnat.json"
    },
    /**
     * 保存NAT配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-3-02
     * @param {String} protocol         协议 ：tcp、udp、all
     * @param {String} natType          NAT类型:0：DNAT 1：SNAT
     * @param {String} addressType      地址类型：interface、staticIp
     * @param {String} oAddress         源地址
     * @param {String} mAddress         映射地址
     * @param {String} oPort            源端口
     * @param {String} mPort            映射端口
     * @example
     * request:
     * {
     *      "topicurl":"setNatRules",
     *      "natType":"1",
     *      "protocol":"tcp",
     *      "addressType":"staticIp", //当natType为0时，此参数为源地址的类型， natType为1时，此参数为映射地址的类型
     *      "oAddress":"192.168.2.22",
     *      "oPort":"8899",
     *      "mAddress":"192.168.3.2",
     *      "mPort":"9999"
     * }
     */
    setNatRules: null,
    /**
     * 删除NAT规则
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-3-02
     * @example
     * request:
     * {
     *      "topicurl":"delNatRules",
     *      "0":{
     *         "idx": "1",
     *         "natType": "0",
     *         "protocol":"ALL",
     *         "addressType":"interface",
     *         "oAddress":"br0",
     *         "mAddress":"192.168.6.1",
     *         "oPort":"8888-8890",
     *         "mPort":"7777-7780",
     *      }
     * }
     */
    delNatRules: null,
    /**
     * 获取VPN穿透配置
     * @Author   Bob       <Bob_huang@carystudio.com>
     * @DateTime 2017-11-06
     * @param {String} topicurl          主题
     * @property {String} wanPingFilter     Ping Access on WAN；0：禁用，1：启用
     * @property {String} l2tpPassThru      L2TP穿透。 0：禁用，1：启用
     * @property {String} pptpPassThru      PPTP穿透。 0：禁用，1：启用
     * @property {String} ipsecPassThru     IPSec穿透。0：禁用，1：启用
     * @example
     * request:
     * {
     *       "topicurl":"getVpnPassCfg"
     * }
     * response:
     * {
     *       "wanPingFilter":1,
     *       "l2tpPassThru":1,
     *       "pptpPassThru":1,
     *       "ipsecPassThru":1
     * }
     */
    getVpnPassCfg: {
      debugUrl: "vpnpass.json"
    },
    /**
     * 保存VPN穿透配置
     * @Author   Bob       <Bob_huang@carystudio.com>
     * @DateTime 2017-11-06
     * @param {String} wanPingFilter    允许从WAN口PING, 0：禁用，1：启用
     * @param {String} l2tpPassThru     L2TP穿透, 0：禁用，1：启用
     * @param {String} pptpPassThru     PPTP穿透, 0：禁用，1：启用
     * @param {String} ipsecPassThru    IPSec穿透, 0：禁用，1：启用
     * @example
     * request:
     * {
     *       "topicurl":"setVpnPassCfg",
     *       "wanPingFilter":"1",
     *       "l2tpPassThru":"1",
     *       "pptpPassThru":"1",
     *       "ipsecPassThru":"1"
     * }
     */
    setVpnPassCfg: null,
    /**
     * 通过ip获得克隆mac
     * @Author   amy       <amy@carystudio.com>
     * @DateTime 2017-11-06
     * @param {String} stationIp     station ip
     * @property {String} stationMac       station mac
     * @example
     * request:
     * {
     *      "stationIp":"192.168.15.200"
     * }
     * response:
     * {
     *      "stationMac":"c8:1f:66:17:ae:b7"
     * }
     */
    getStationMacByIp: {
      debugUrl: "station_mac.json"
    },
    /**
    * 获取IP/端口过滤配置
    * @Author Karen
    * @DateTime 2020-06-29
    * @property {String}	enable	开关。1：开，0：关
    * @property {String}	interface	接口。使用“，”符号相隔
    * @property {String}	lanIp	LAN IP
    * @property {String}	lanNetmask	LAN MASK
    * @property {Array}	rule	规则列表
    * @property {String}	ip	IP
    * @property {String}	proto	协议
    * @property {String}	sPort	源起始端口
    * @property {String}	ePort	源结束端口
    * @property {String}	dsPort	目的起始端口
    * @property {String}	dePort	目的结束端口
    * @property {String}	desc	描述
    * @property {String}	delRuleName	规则名（页面没用到）
    * @property {String}	dip	目的IP地址
    * @property {String}	input	输入协议
    * @property {String}	output	输出协议
    * @return {object}
    * @example
    * request:
    *
    * 	"topicurl":"getIpPortFilterRules"
    * response:
    * {
    * 	"enable":"1",
    * 	"interface":"ALL,LAN1,LAN2,WAN1",
    * 	"lanIp":"192.168.0.1",
    * 	"lanNetmask":"255.255.255.0",
    * 	"rule":[
    *     {
    *     "idx":"1",
    *   	"ip":"192.168.0.8",
    * 	  "proto":"TCP",
    * 	  "sPort":"100",
    * 	  "ePort":"199",
    * 	  "dsPort":"1",
    * 	  "dePort":"44",
    * 	  "desc":"new",
    * 	  "delRuleName":"delRule0",
    * 	  "dip":"0.0.0.0",
    * 	  "input":"ALL",
    * 	  "output":"ALL"
    *     }
    *   ]
    * }
    */
    getIpPortFilterRules: {
      debugUrl: "ipf.json"
    },
    /**
     * 保存IP端口过滤配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-03-22
     * @param {String} addEffect   0:开关设置，1：数据设置
     * @param {Array} subnet   规则列
     * @example
     * request:
     * {
     *      "topicurl":"setIpPortFilterRules",
     *      "addEffect":"1",
     *      "subnet":[]
     * }
     */
    setIpPortFilterRules: null,
    /**
    * 获取MAC过滤配置
    * @Author Karen
    * @DateTime 2020-06-29
    * @property {String}	enable	开关。1：开，0：关
    * @property {String}	rule	规则列表
    * @property {String}	idx	ID
    * @property {String}	mac	MAC地址
    * @property {String}	desc	描述
    * @property {String}	delRuleName	规则名（页面没用到）
    * @return {object}
    * @example
    * request:
    *
    * 	"topicurl":"getMacFilterRules"
    * response:
    * {
    * 	"enable":"1",
    * 	"rule":[
    *   {
    * 	  "idx":"1",
    * 	  "mac":"00:e0:4c:81:96:71",
    * 	  "desc":"a",
    * 	  "delRuleName":"delRule0"
    *   }
    *   ]
    * }
    */
    getMacFilterRules: {
      debugUrl: "macf.json"
    },
    /**
     * 设置MAC过滤配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-03-22
     * @param {String} addEffect   0:开关设置，1：数据设置
     * @param {Array} subnet   规则列
     * @example
     * request:
     * {
     *      "topicurl":"setMacFilterRules",
     *      "addEffect":"1",
     *      "subnet":[]
     * }
     */
    setMacFilterRules: null,
    /**
    * 获取URL过滤配置
    * @Author Karen
    * @DateTime 2020-06-29
    * @property {String}	enable	开关。1：开，0：关
    * @property {Array}	rule	规则列表
    * @property {String}	idx	ID
    * @property {String}	url	URL关键字
    * @property {String}	delRuleName	规则名（页面没用到）
    * @return {object}
    * @example
    * request:
    *
    * 	"topicurl":"getUrlFilterRules"
    * response:
    * {
    * 	"enable":"1",
    * 	"rule":[
    *   {
    * 	  "idx":"1",
    * 	  "url":"baidu",
    * 	  "delRuleName":"delRule0"
    *   }
    *   ]
    * }
    */
    getUrlFilterRules: {
      debugUrl: "urlf.json"
    },
    /**
     * 保存URL过滤配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-03-22
     * @param {String} addEffect   0:开关设置，1：数据设置
     * @param {Array} subnet   规则列
     * @example
     * request:
     * {
     *      "topicurl":"setUrlFilterRules",
     *      "addEffect":"1",
     *      "subnet":[]
     * }
     */
    setUrlFilterRules: null,
    /**
     * 获取Telent配置
     * @Author   Yexk       <yexk@carystudio.com>
     * @DateTime 2018-02-01
     * @property {String} telnet_enabled         开启或者关闭状态，1开启，0关闭
     * @example
     * request:
     * {
     *      "topicurl":"getTelnetCfg"
     * }
     * response:
     * {
     *      "telnet_enabled":'1'
     * }
     */
    getTelnetCfg: null,
    /**
     * 保存Telent配置
     * @Author   Yexk       <yexk@carystudio.com>
     * @DateTime 2018-02-01
     * @param {String} telnet_enabled         开启或者关闭状态，1开启，0关闭
     * @example
     * request:
     * {
     *      "topicurl":"setTelnetCfg",
     *      "telnet_enabled":'1'
     * }
     */
    setTelnetCfg: null,
	/**
     * 获取电源控制配置
     * @Author   vinson       <vinson@carystudio.com>
     * @DateTime 2021-1-11
     * @property {String} powerStatus         开启或者关闭状态，1开启，0关闭
     * @example
     * request:
     * {
     *      "powerStatus":"1"
     * }
     */
    getPowerCtlCfg: {
      debugUrl: "powerCtl.json"
    },
    /**
     * 保存电源控制配置
     * @Author   vinson       <vinson@carystudio.com>
     * @DateTime 2021-1-11
     * @param {String} powerStatus     开启或者关闭状态，1开启，0关闭
     * @example
     * request:
     * {
     *      "powerStatus":"1"
     * }
     */
    setPowerCtlCfg: {
      debugUrl: "powerCtl.json"
    },/**
    * 获取硬件加速配置
    * @Author   vinson       <vinson@carystudio.com>
    * @DateTime 2022-03-29
    * @property {String} hwNatEnable         开启或者关闭状态，1开启，0关闭
    * @example
    * request:
    * {
    *      "hwNatEnable":"1"
    * }
    */
    getHwNatCfg: {
     debugUrl: "hwnat.json"
   },
   /**
    * 保存硬件加速配置
    * @Author   vinson       <vinson@carystudio.com>
    * @DateTime 2022-03-29
    * @param {String} hwNatEnable     开启或者关闭状态，1开启，0关闭
    * @example
    * request:
    * {
    *      "hwNatEnable":"1"
    * }
    */
    setHwNatCfg: null,
    /**
     * 获取DDNS状态
     * @Author   amy       <Amy_wei@carystudio.com>
     * @DateTime 2017-11-03
     * @property {String} ddnsIp          DDNS的公共地址
     * @property {String} ddnsStatus      DDNS的连接状态
     * @example
     * request:
     * {
     *      "topicurl":"getDdnsStatus"
     * }
     * response:
     * {
     *      "ddnsIp":"",
     *      "ddnsStatus":"fail"
     * }
     */
    getDdnsStatus: {
      debugUrl: "ddnsstatus.json"
    },
    /**
     * 获取DDNS配置
     * @Author   Bob       <Bob_huang@carystudio.com>
     * @DateTime 2017-11-03
     * @property {String} topicurl          主题
     * @property {String} ddnsEnabled       DDNS的开关：0：禁用，1：启用
     * @property {String} ddnsProvider      DDNS的供应商， 0：DynDNS, 1：noip, 2：3322.org
     * @property {String} ddnsDomain        DDNS的域名
     * @property {String} ddnsAccount       DDNS的用户名
     * @property {String} ddnsPassword      DDNS的密码
     * @property {String} ddnsDomainList    NO-IP的选择项
     * @example
     * request:
     * {
     *      "topicurl":"getDdnsCfg"
     * }
     * response:
     * {
     *     "ddnsEnabled":0,
     *     "ddnsProvider":2,
     *     "ddnsDomain":"host.dyndns.org",
     *     "ddnsAccount":"",
     *     "ddnsPassword":"",
     *     "ddnsDomainList":"www.noip.com;aaa.com;adsfaf.ddns.net"
     * }
     */
    getDdnsCfg: {
      debugUrl: "ddns.json"
    },
    /**
     * 保存DDNS配置
     * @Author   Bob       <Bob_huang@carystudio.com>
     * @DateTime 2017-11-03
     * @param {String} ddnsEnabled      DDNS的开关：0：禁用，1：启用
     * @param {String} ddnsProvider     DDNS的供应商， 0：DynDNS, 1：noip, 2：3322.org
     * @param {String} ddnsDomain       DDNS的域名
     * @param {String} ddnsAccount      DDNS的用户名
     * @param {String} ddnsPassword     DDNS的密码
     * @example
     * request:
     * {
     *     "topicurl":"setDdnsCfg",
     *     "ddnsEnabled":0,
     *     "ddnsProvider":2,
     *     "ddnsDomain":"host.dyndns.org",
     *     "ddnsAccount":"",
     *     "ddnsPassword":""
     * }
     */
    setDdnsCfg: null,
    /**
    * 获取qos配置
    * @Author Karen
    * @DateTime 2020-06-29
	* @property {String}	speedMax	网口速率, 100:100M，1000:1000M
    * @property {String}	upPercent	上行带宽
    * @property {String}	downPercent	下行带宽
    * @property {String}	totalUp	总上行带宽
    * @property {String}	totalDown	总下行带宽
    * @return {object}
    * @example
    * request:
    *
    * 	"topicurl":"getQosSetCfg"
    * response:
    * {
	*	"speedMax":"1000",
    * 	"upPercent": "30",
    * 	"downPercent": "30",
    * 	"totalUp": "40",
    * 	"totalDown": "200"
    * }
    */
    getQosSetCfg: {
      debugUrl: "qos.json"
    },
    /**
    * 获取流控配置
    * @Author Karen
    * @DateTime 2020-06-29
    * @property {String}	enable	开关。1：开，0：关
    * @property {String}	ip	LAN IP
    * @property {String}	mask	LAN MASK
    * @property {Array}	rule	规则列表
    * @property {String}	ip	IP
    * @property {String}	up	上行速率
    * @property {String}	down	下行速率
    * @property {String}	desc	描述
    * @return {object}
    * @example
    * request:
    *
    * 	"topicurl":"getIpQosLimitCfg"
    * response:
    * {
    * 	"enable": "1",
    * 	"ip": "192.168.1.1",
    * 	"mask": "255.255.255.0",
    * 	"rule": [
    *   {
    * 	  "ip":"",
    * 	  "up":"",
    * 	  "down":"",
    * 	  "desc":""
    *   }
    * ]
    * }
    */
    getIpQosLimitCfg: {
      debugUrl: "qos_limit.json"
    },
    /**
     * 流控设置
     * @param {String} addEffect   0:开关设置，1：数据设置
     * @param {Array} subnet   规则列
     * @example
     * request:
     * {
     *      "topicurl":"setIpQosLimitCfg",
     *      "addEffect":"1",
     *      "enable":"1",（废弃）
     *      "mode":"0",（废弃）
     *      "subnet":[]
     * }
     */
    setIpQosLimitCfg: null,
    /**
     * 设置qos配置
     * @Author   enter       <enter@carystudio.com>
     * @DateTime 2019-6-14
     * @param {String}	addEffect	0:开关设置，1：数据设置
     * @param {String}	enable	开关
     * @param {String}	upPercent	上行带宽
     * @param {String}	downPercent	下行带宽
     * @param {String}	totalUp	总上行带宽
     * @param {String}	totalDown	总下行带宽
     */
    setQosSetCfg: null,
    /**
     * 获取路由信息
     * @Author   Jeff       <Jeff@carystudio.com>
     * @DateTime 2018-8-17
     * @property {String} routeType       路由类型。0：静态路由  1：策略路由
     * @property {String} network         网络地址
     * @property {String} subnetMask      子网掩码
     * @property {String} gateway         网关
     * @property {String} interface       接口
     * @property {String} metric          路由跳数
     * @example
     * request:
     * {
     *      "topicurl":"getRouteTableInfo"
     * }
     * response:
     * [
     *    //静态路由数据组
     *      {
     *        "routeType":"0",
     *        "network":  "10.1.1.3",
     *        "subnetMask": "255.255.255.0",
     *        "gateway":  "0.0.0.0",
     *        "interface":  "eth0",
     *        "metric": "0"
     *      },{
     *    //策略路由数据组
     *       "routeType": "1",
     *       "proto": "all",
     *       "sourceIp": "192.168.1.5",
     *       "destIp": "192.168.1.6",
     *       "interface": "eth2.2",
     *       "portRange": "1-65535",
     *       "dPortRange": "1-65535"
     *     }
     * ]
     */
    getRouteTableInfo: {
      debugUrl: "route_table.json"
    },
    /**
    * 获取静态路由配置
    * @Author Karen
    * @DateTime 2020-06-29
    * @property {String}	interface	接口。接口间使用","符号相隔
    * @property {String}	wanIp	WAN IP
    * @property {String}	lanIp	LAN IP
    * @property {String}	ipRouteLog	日志
    * @property {Array}	rule	规则列表
    * @property {String}	idx	ID
    * @property {String}	ip	目的地址
    * @property {String}	gw	网关
    * @property {String}	mask	子网掩码
    * @property {String}	metric	跃点数
    * @property {String}	iface	接口
    * @property {String}	desc	描述
    * @property {String}	delRuleName	删除标志（页面未使用）
    * @return {object}
    * @example
    * request:
    *
    * 	"topicurl":"getStaticRoute"
    * response:
    * {
    * 	"interface":  "LAN1,LAN2,LAN3,LAN4,WAN",
    * 	"wanIp":"0.0.0.0",
    * 	"lanIp":"192.168.0.253",
    * 	"ipRouteLog":"data:[2020] 01.01",
    * 	"rule":[
    *    {
    * 	  "idx":"1",
    * 	  "ip":   "192.168.16.0",
    * 	  "gw":  "10.20.40.200",
    * 	  "mask":   "255.255.255.0",
    * 	  "metric":   "0",
    * 	  "iface":   "LAN",
    * 	  "desc":   "vpn1",
    * 	  "delRuleName":"delRule0"
    *     }
    *   ]
    * }
    */
    getStaticRoute: {
      debugUrl: "route.json"
    },
    /**
     * 保存静态路由配置
     * @param {String} addEffect   0:开关设置，1：数据设置
     * @param {Array} subnet   规则列
     * @example
     * request:
     * {
     *      "topicurl":"setStaticRoute",
     *      "addEffect":"1",
     *      "subnet":[]
     * }
     */
    setStaticRoute: null,
    /**
     * 获取IPv6状态
     * @Author Karen
     * @DateTime 2020-07-13
     * @property {String}	ipv6WanLinkType	wan 链路类型 dhcp6 static等，设置那里有全部类型
     * @property {String}	ipv6WanOriginType	wan源类型
     * @property {String}	ipv6WanGlobalAddree	wan全球地址
     * @property {String}	ipv6WanLinkAddree	wan链接本地地址
     * @property {String}	ipv6WanGw	默认网关
     * @property {String}	ipv6WanDns	dns服务器
     * @property {String}	ipv6LanGlobalAddree	lan全球地址
     * @property {String}	ipv6LanLinkAddree	lan本地链接地址
     * @property {String}	ipv6LanGw	lan网关
     * @property {String}	ipv6Enabled	 ipv6开关，0关闭，1开启
     * @return {object}
     * @example
     * request:
     * {
     * 	"topicurl":"getIPv6Status"
     * }
     * response:
     * {
     * 	"ipv6WanLinkType": "off",
     * 	"ipv6WanOriginType": "off",
     * 	"ipv6WanGlobalAddree": "",
     * 	"ipv6WanLinkAddree": "",
     * 	"ipv6WanGw": "",
     * 	"ipv6WanDns": "",
     * 	"ipv6LanGlobalAddree": "",
     * 	"ipv6LanLinkAddree": "",
     * 	"ipv6LanGw": "",
     * 	"ipv6Enabled": 0
     * }
     */
    getIPv6Status: {
      debugUrl: "ipv6_status.json"
    },
    /**
     * 获取OpenVPN服务器配置
     * @Author   Amy       <amy@carystudio.com>
     * @DateTime 2018-06-14
     * @property {String} enabled           状态：1 启用，0 禁用
     * @property {String} port             服务器端口
     * @property {String} subnet           VPN网段
     * @property {String} mask             网段掩码
     * @property {String} proto            Tunnel协议
     * @property {String} devType         Tunnel类型
     * @property {String} cipher           加密算法
     * @property {String} compLzo         LZO压缩，值：1：开启，0：关闭
     * @property {String} mtu          MTU
     * @property {String} ca               CA证书
     * @property {String} caKey           CA私钥
     * @property {String} dh               密钥
     * @property {String} cert             服务器证书
     * @property {String} key              服务器私钥
     * @property {String} extraConfig     附加配置
     * @property {String} auth  客户端连接认证方式,值：2：证书认证；3：账号密码认证
     * @property {String} serverName   通用名称
     * @property {String} dayvalid     有效天数
     * @property {String} country      国家
     * @property {String} province     省份
     * @property {String} city         城市
     * @property {String} org          组织
     * @property {String} ou           单位
     * @example
     * request:
     * {
     *       "topicurl":"getOpenVpnServerCfg"
     * }
     * response:
     * {
     *       "enabled": 1,
     *       "port": 1194,
     *       "subnet":"10.7.7.0",
     *       "mask":"255.255.255.0",
     *       "proto":"udp",
     *       "devType":"tun",
     *       "cipher":"BF-CBC",
     *       "compLzo": 1,
     *       "mtu": 1400,
     *       "auth":"2",
     *       "serverName":"Server",
     *       "dayvalid":"3650",
     *       "country":"CN",
     *       "province":"GD",
     *       "city":"SZ",
     *       "org":"CS",
     *       "email":"cs@cs.com",
     *       "ou":"rd",
     *       "ca":"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----",
     *       "caKey":"",
     *       "dh":"",
     *       "cert":"-----BEGIN CERTIFICATE-----",
     *       "key":"-----BEGIN RSA PRIVATE KEY-----",
     *       "extraConfig":"mtu-disc no"
     * }
     */
    getOpenVpnServerCfg: {
      debugUrl: "openvpn_server.json"
    },
    /**
     * 保存OpenVPN服务器配置
     * @Author   Amy       <amy@carystudio.com>
     * @DateTime 2018-06-14
     * @param {String} enabled          状态：1 启用，0 禁用
     * @param {String} port             服务器端口
     * @param {String} subnet           VPN网段
     * @param {String} mask             网段掩码
     * @param {String} proto            Tunnel协议
     * @param {String} devType         Tunnel类型
     * @param {String} cipher           加密算法
     * @param {String} compLzo         LZO压缩，值：1：开启，0：关闭
     * @param {String} mtu          MTU
     * @param {String} ca               CA证书
     * @param {String} caKey           CA私钥
     * @param {String} dh               密钥
     * @param {String} cert             服务器证书
     * @param {String} key              服务器私钥
     * @param {String} extraConfig     附加配置
     * @param {String} auth  客户端连接认证方式,值：2：证书认证；3：账号密码认证
     * @example
     * request:
     * {
     *      "topicurl":"setOpenVpnServerCfg",
     *      "enabled": 1,
     *      "port": 1194,
     *      "subnet":"10.7.7.0",
     *      "mask":"255.255.255.0",
     *      "proto":"udp",
     *      "devType":"tun",
     *      "cipher":"BF-CBC",
     *      "compLzo": 1,
     *      "mtu": 1400,
     *      "auth":"2",
     *      "ca":"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----",
     *      "caKey":"",
     *      "dh":"",
     *      "cert":"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----",
     *      "key":"-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----",
     *      "extraConfig":"mtu-disc no"
     * }
     */
    setOpenVpnServerCfg: null,
    /**
     * 获取openvpn客户端配置
     * @Author   Karen       <Karen@carystudio.com>
     * @DateTime 2018-08-29
     * @property {String} enabled    开关。，1：开启，0：关闭
     * @property {String} address    服务器地址
     * @property {String} port       端口号
     * @property {String} auth     认证方式。2：证书认证，3：账户密码认证
     * @property {String} username   用户名
     * @property {String} password   密码
     * @property {String} proto   通信协议
     * @property {String} devType   Tunnel类型
     * @property {String} cipher   加密算法
     * @property {String} compLzo   LZO压缩
     * @property {String} mtu   MTU
     * @property {String} ca   CA证书
     * @property {String} ta   TA证书
     * @property {String} cert   客户端证书
     * @property {String} certManual   客户端证书导入方式  0:手动输入  1:文件上传
     * @property {String} key   客户端私钥
     * @property {String} extraConfig   附加配置
     * @property {String} clientAddr   IP地址
     * @property {String} openvpnConnect   连接状态
     * @example
     * request:
     * {
     *      "topicurl":"getOpenVpnClientCfg",
     * }
     * response:
     * {
     *      "enabled":"1",
     *      "address":"192.168.2.22",
     *      "port":"8888",
     *      "auth":"2",
     *      "username":"admin",
     *      "password":"admin",
     *      "proto":"tcp",
     *        "devType":"tap",
     *      "cipher":"none",
     *        "compLzo":"1",
     *      "mtu":"1500",
     *      "certManual":"1",
     *        "ca":"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----",
     *      "ta":"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----",
     *      "cert":"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----",
     *      "key":"-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----",
     *      "extraConfig":"push \"route 192.168.10.0 255.255.255.0\"\npush \"route 192.168.20.0 255.255.255.0\"\npush \"route 192.168.30.0 255.255.255.0\"\npush \"route 66.220.18.42 255.255.255.255\"",
     *      "clientAddr":"10.10.10.1"
     * }
     */
    getOpenVpnClientCfg: {
      debugUrl: "openvpn_client.json"
    },
    /**
     * 保存openvpn客户端配置
     * @Author   Karen       <Karen@carystudio.com>
     * @DateTime 2018-08-29
     * @param {String} enabled    开关。，1：开启，0：关闭
     * @param {String} address    服务器地址
     * @param {String} port       端口号
     * @param {String} auth     认证方式。2：证书认证，3：账户密码认证
     * @param {String} username   用户名
     * @param {String} password   密码
     * @param {String} proto   通信协议
     * @param {String} devType   Tunnel类型
     * @param {String} cipher   加密算法
     * @param {String} compLzo   LZO压缩
     * @param {String} mtu   MTU
     * @param {String} ca   CA证书
     * @param {String} ta   TA证书
     * @param {String} cert   客户端证书
     * @param {String} certManual   客户端证书导入方式   0:手动输入  1:文件上传
     * @param {String} key   客户端私钥
     * @param {String} extraConfig   附加配置
     * @example
     * request:
     * {
     *        "topicurl":"setOpenVpnClientCfg",
     *        "enabled":"1",
     *        "address":"192.168.2.22",
     *        "port":"8888",
     *        "auth":"2",
     *        "username":"admin",
     *        "password":"admin",
     *        "proto":"tcp",
     *        "devType":"tap",
     *        "cipher":"none",
     *        "compLzo":"1",
     *        "mtu":"1500",
     *        "ca":"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----",
     *        "ta":"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----",
     *        "cert":"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----",
     *        "key":"-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----",
     *        "extraConfig":"push \"route 192.168.10.0 255.255.255.0\"\npush \"route 192.168.20.0 255.255.255.0\"\npush \"route 192.168.30.0 255.255.255.0\"\npush \"route 66.220.18.42 255.255.255.255\"",
     * }
     */
    setOpenVpnClientCfg: null,
	/**
	 * 获取VPN账号列表
	 * @Author   Carystudio
	 * @DateTime 2019-9-24
	 * @property {String} rule          VPN账号规则
	 * @property {String} idx           规则: 索引值
	 * @property {String} type          规则: 类型, 0:全部, 1:PPPOE 2:PPTP, 3:L2TP,4:OpenVPN
	 * @property {String} user          规则: 账号
	 * @property {String} pass          规则: 密码
	 * @property {String} desc          规则: 描述
	 * @property {String} vpnNet        vpn地址
	 * @property {String} ipaddr        静态IP
	 * @property {String} accessLimit   访问权限  0：禁止，1：允许
	 * @property {array}  subnet        VPN内网子网信息
	 * @property {String} mask        
	 * @example
	 * request:
	 * {
	 *      "topicurl":"getVpnAccountCfg"
	 * }
	 * response:
	 * {
	 *    "vpnNet":"10.0.8.0",
	 *    "rule":[{
	 *      "idx":"1",
	 *      "type":"0",
	 *      "user":"felix",
	 *      "pass":"felix",
	 *      "desc":"toto",
	 *      "ipaddr":"10.0.8.1",
	 *      "accessLimit":"1",
	 *      "subnet":[
	 *        {"ipaddr":"10.0.8.1", "mask":"255.255.255.0"}
	 *      ]
	 *    }]
	 * }
	 */
    getVpnAccountCfg: {
      debugUrl: "account.json"
    },
	/**
	 * 设置VPN账号规则
	 * @Author   Carystudio
	 * @DateTime 2019-9-24
	 * @param {String} mask   
	 * @param {String} subnet   
	 * @param {String} ipaddr    
	 * @param {String} accessLimit    
	 * @param {String} idx    
	 * @param {String} addEffect    辅助, 0:无操作，1:添加, 2:修改 
	 * @param {String} user         规则: 账号
	 * @param {String} pass         规则: 密码
	 * @param {String} type         规则: 类型, 0:全部, 1:PPPOE 2:PPTP, 3:L2TP,4:OpenVPN
	 * @param {String} desc         规则: 描述
	 * @example
	 * request:
	 * {
	 *    "topicurl":"setVpnAccountCfg",
	 *    "mask":"",
	 *    "subnet":"",
	 *    "ipaddr":"",
	 *    "accessLimit":"",
	 *    "idx":"",
	 *    "addEffect":"0",
	 *    "user":"felix",
	 *    "pass":"felix",
	 *    "type":"1",
	 *    "desc":"wwwwww"
	 * }
	 * response:
	 * {
	 *    "success":true,
	 *    "error":null,
	 *    "lan_ip":"192.168.0.1",
	 *    "wtime":0,
	 *    "reserv":"reserv"
	 * }
	 */
	setVpnAccountCfg: null,
	/**
	 * 删除VPN账号规则
	 * @Author   Carystudio
	 * @DateTime 2019-9-24
	 * @param {String} idx     
	 * @example
	 * request:
	 * {
	 *    "topicurl":"delVpnAccountCfg"，
	 *    "idx":""
	 * }
	 * response:
	 * {
	 *    "success":true,
	 *    "error":null,
	 *    "lan_ip":"192.168.0.1",
	 *    "wtime":0,
	 *    "reserv":"reserv"
	 * }
	 */
	delVpnAccountCfg: null,
	/**
	 * 获取用户状态配置
	 * @Author   Carystudio
	 * @DateTime 2019-9-24
	 * @property    {String}   length        
	 * @property    {String}   ip           IP
	 * @property    {String}   name         账号
	 * @property    {String}   deviceIp     设备IP
	 * @property    {String}   type         认证类型 1:PPPOE 2:PPTP, 3:L2TP,4:OpenVPN
	 * @property    {String}   desc         描述
	 * @return      {Array}
	 * @example
	 * request:
	 * {
	 *       "topicurl":"getUserInfo"
	 * }
	 * response:
	 * [
	 *   {
	 *       "ip":   "10.1.1.2",
	 *       "name": "123",
	 *       "devicIp":  "192.168.0.99",
	 *       "type":  "",
	 *       "desc":  "1"
	 *   }
	 * ]
	 */
    getUserInfo: {
      debugUrl: "UserInfo.json"
    },
	/**
	 * 设置远程管理配置
	 * @Author   Carystudio
	 * @DateTime 2019-9-25
	 * @param {String} servername     通用名称
	 * @param {String} dayvalid       有效天数
	 *
	 * @property {String} success     响应状态：true：响应成功，false：响应失败
	 * @property {String} error       错误
	 * @property {String} lan_ip      局域网IP
	 * @property {String} wtime       等待时间
	 * @property {String} reserv      返回页面（参数未知）
	 *
	 * @example
	 * request:
	 * {
	 *   "topicurl":"generateCertCfg",
	 *   "servername":"Server",
	 *   "dayvalid":"3650"
	 * }
	 * response:
	 * {
	 *   "success": true,
	 *   "error":   null,
	 *   "lan_ip":  "192.168.0.5",
	 *   "wtime":   0,
	 *   "reserv":  "reserv"
	 * }
	 */
    generateCert: {
      debugUrl: "generateCert.json"
    },
    /**
     * 设置远程Cert管理配置
     * @Author   Karen       <Karen@carystudio.com>
     * @DateTime 2018-09-13
     * @param {String} serverName   通用名称
     * @param {String} dayvalid     有效天数
     * @param {String} country      国家
     * @param {String} province     省份
     * @param {String} city         城市
     * @param {String} org          组织
     * @param {String} ou           单位
     * @example
     * request:
     * {
     *      "topicurl":"setOpenVpndCertConfig",
     *      "serverName":"Server",
     *      "dayvalid":"3650",
     *      "country":"CN",
     *      "province":"GD",
     *      "city":"SZ",
     *      "org":"CS",
     *      "email":"cs@cs.com",
     *      "ou":"rd"
     * }
     */
    setOpenVpndCertConfig: {
      debugUrl: "openvpn.json"
    },
    /**
     * 获取证书生成状态
     * @Author   Karen       <Karen@carystudio.com>
     * @DateTime 2018-09-13
     * @property {String} certStatus      生成状态。 0：正常，1：正在生成，2：成功，3：失败，4：缺失
     * @example
     * request:
     * {
     *      "topicurl":"getCertStatus"
     * }
     * response:
     * {
     *      "certStatus":"1"
     * }
     */
    getCertStatus: {
      debugUrl: "cert.json"
    },
    /**
     * 获取OpenVPN日志
     * @Author   Amy       <amy@carystudio.com>
     * @DateTime 2018-06-14
     * @property {String} log         日志信息
     * @example
     * request:
     * {
     *       "topicurl":"getOpenVpnLog"
     * }
     * response:
     * {
     *       "log":"Fri Apr 27 18:47:00 2018 OpenVPN 2.3.11 mipsel-openwrt-linux-gnu [SSL (OpenSSL)] [LZO] [EPOLL] [MH] [IPv6] Fri Apr 27 18:47:00 2018 library versions: OpenSSL 1.0.2e 3 Dec 2015, LZO 2.08 Fri Apr 27 18:47:00 2018 NOTE: the current --script-security setting may allow this configuration to call user-defined scripts Fri Apr 27 18:47:00 2018 WARNING: POTENTIALLY DANGEROUS OPTION --client-cert-not-required may accept clients which do not present a certificate Fri Apr 27 18:47:00 2018 WARNING: normally if you use --mssfix and/or --fragment, you should also set --tun-mtu 1500 (currently it is 1400) Fri Apr 27 18:47:00 2018 TUN/TAP device sovpn opened Fri Apr 27 18:47:00 2018 do_ifconfig, tt->ipv6=0, tt->did_ifconfig_ipv6_setup=0 Fri Apr 27 18:47:00 2018 /sbin/ifconfig sovpn 10.7.7.1 pointopoint 10.7.7.2 mtu 1400 Fri Apr 27 18:47:00 2018 UDPv4 link local (bound): [undef] Fri Apr 27 18:47:00 2018 UDPv4 link remote: [undef] Fri Apr 27 18:47:00 2018 Initialization Sequence Completed"
     * }
     */
    getOpenVpnLog: {
      debugUrl: "openvpn_log.json"
    },
    /**
     * 获取ping诊断信息
     * @DateTime 2018-11-2
     * @property {String} log          Ping诊断结果
     * @property {String} status    操作状态。1：执行中，0：空闲
     * @property {String} num       ping包数
     * @return {object}
     * @example
     * request:
     * {
     *      "topicurl":"getDiagnosisCfg"
     * }
     * response:
     * {
     *      "log":"carystudio",
     *      "status":"0",
     *      "num":"4"
     *}
     */
    getDiagnosisCfg: {
      debugUrl: "pinglog.json"
    },
    /**
     * 保存ping诊断配置
     * @DateTime 2018-11-2
     * @return {object}
     * @property {String} ip           ping地址
     * @property {String} num          ping条数
     * @example
     * request:
     * {
     *      "topicurl":"setDiagnosisCfg"
     *      "ip":"192.168.0.44",
     *      "num":"4"
     * }
     */
    setDiagnosisCfg: null,
    /**
     * 清除ping诊断日志
     * @DateTime 2018-11-2
     * @return {object}
     * @example
     * request:
     * {
     *      "topicurl":"clearDiagnosisLog"
     * }
     */
    clearDiagnosisLog: null,
    /**
     * 获取LTE配置
     * @Author   Karen       <Karen@carystudio.com>
     * @DateTime 2019-05-11
     * @property {String}  ltecheckEnable     LTE检测，1开启 0:关闭
     * @property {String} abnormalCheck      异常自检
     * @property {String} checkInterval      检测间隔
     * @property {String} ip1                LTE检测目标地址1
     * @property {String} ip2                LTE检测目标地址2
     * @property {String} ip3                 LTE检测目标地址3
     * @property {String} dataCheckEnable     数据包检测，1开启 0:关闭
     * @property {String} dataSize            数据包大小
     */
    getLteCheckCfg: {
      debugUrl: "lte_check.json"
    },
    /**
     * 保存LTE配置
     * @Author   Karen       <Karen@carystudio.com>
     * @DateTime 2019-05-11
     * @param {String}  ltecheckEnable     LTE检测，1开启 0:关闭
     * @param {String} abnormalCheck      异常自检
     * @param {String} checkInterval      检测间隔
     * @param {String} ip1                LTE检测目标地址1
     * @param {String} ip2                LTE检测目标地址2
     * @param {String} ip3                 LTE检测目标地址3
     * @param {String} dataCheckEnable     数据包检测，1开启 0:关闭
     * @param {String} dataSize            数据包大小
     */
    setLteCheckCfg: null,
    /**
     * 获取串口服务配置
     * @Author   Karen       <Karen@carystudio.com>
     * @DateTime 2018-08-27
     * @property {String} ttyEnable     0：指令模式，1：透传模式
     * @property {String} ttyMode       0：off ,1：client 2：server
     * @property {String} ttyServerIp   服务地址
     * @property {String} ttyProto      0：tcp，1：udp，2：tcp&udp
     * @property {String} ttyTcpPort    tcp端口
     * @property {String} ttyUdpPort    udp端口
     * @property {String} ttyBaudRate   波特率
     * @property {String} ttyParity     奇偶校验。 NONE，ODD，EVEN
     * @property {String} ttyFlowControl   流控制位 NONE，RTS/CTS,XON/XOFF
     * @property {String} ttyDataBit   信息位
     * @property {String} ttyStopBit   停止位
     * @example
     * request:
     * {
     *      "topicurl":"getTtyServiceCfg"
     * }
     * response:
     * {
     *      "ttyEnable":"0",
     *      "ttyMode":"0",
     *      "ttyServerIp":"192.168.1.1",
     *      "ttyProto":"0",
     *      "ttyTcpPort":"555",
     *      "ttyUdpPort":"666",
     *      "ttyBaudRate":"57600",
     *      "ttyParity":"NONE",
     *      "ttyFlowControl":"NONE",
     *      "ttyDataBit":"8",
     *      "ttyStopBit":"1"
     * }
     */
    getTtyServiceCfg: {
      debugUrl: "tty_server.json"
    },
    /**
     * 保存串口服务配置
     * @Author   Karen       <Karen@carystudio.com>
     * @DateTime 2018-08-27
     * @param {String} ttyEnable     0：指令模式，1：透传模式
     * @param {String} ttyMode       0：off ,1：client 2：server
     * @param {String} ttyServerIp   服务地址
     * @param {String} ttyProto      0：tcp，1：udp，2：tcp&udp
     * @param {String} ttyTcpPort    tcp端口
     * @param {String} ttyUdpPort    udp端口
     * @param {String} ttyBaudRate   波特率
     * @param {String} ttyParity     奇偶校验。 NONE，ODD，EVEN
     * @param {String} ttyFlowControl   流控制位 NONE，RTS/CTS,XON/XOFF
     * @param {String} ttyDataBit   信息位
     * @param {String} ttyStopBit   停止位
     * @example
     * request:
     * {
     *      "topicurl":"setTtyServiceCfg",
     *      "ttyEnable":"0",
     *      "ttyMode":"0",
     *      "ttyServerIp":"192.168.1.1",
     *      "ttyProto":"0",
     *      "ttyTcpPort":"555",
     *      "ttyUdpPort":"666",
     *      "ttyBaudRate":"57600",
     *      "ttyParity":"NONE",
     *      "ttyFlowControl":"NONE",
     *      "ttyDataBit":"8",
     *      "ttyStopBit":"1"
     * }
     */
    setTtyServiceCfg: null,
	
    /**
     * 清除ussd信息
     * @Author   iris
     * @DateTime 2024-10-29
     * @example
     * request:
     * {
     *    "topicurl":"cancelUssd"
     * }
     */
    cancelUssd: null,
    /**
     * 设置USSD命令
     * @Author   iris
     * @DateTime 2024-10-29
     * @param {String} ussd  ussd命令内容 
     * @example
     * request:
     * {
     *    "topicurl":"setUssd"
     *    "ussd":""
     * }
     */
    setUssd: null,
    /**
     * 获取SMS配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-03-23
     * @property {String} onlineEnable   短信上线通知开关
     * @property {String} onlineText        上线通知短信内容
     * @property {String} offlineEnable     短信下线通知开关
     * @property {String} offlineText     下线通知短信内容
     * @property {String} rebootEnable     短信重启控制开关
     * @property {String} rebootText     重启指令
     * @property {String} phone0-5     授权控制手机号码
     * @example
     * request:
     * {
     *    "topicurl":"getSmsCfg"
     * }
     * response:
     * {
     *    "onlineEnable":"1"
     *    "onlineText":"holle word!",
     *    "offlineEnable":"1",
     *    "offlineText":"hi carystudio!",
     *    "rebootEnable":"1",
     *    "rebootText":"hi totolink!",
     *    "phone0":"12345678901",
     *    "phone1":"98765432102",
     *    "phone2":"22222222222",
     *    "phone3":"66666666666",
     *    "phone4":"88888888888",
     *    "phone5":"99999999999"
     * }
     */
    getSmsCfg: {
      debugUrl: "sms.json"
    },
    /**
     * 保存SMS配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-03-23
     * @param {String} onlineEnable   短信上线通知开关
     * @param {String} onlineText        上线通知短信内容
     * @param {String} offlineEnable     短信下线通知开关
     * @param {String} offlineText     下线通知短信内容
     * @param {String} rebootEnable     短信重启控制开关
     * @param {String} rebootText     重启指令
     * @param {String} phone0-5     授权控制手机号码
     * @example
     * request:
     * {
     *    "topicurl":"setSmsCfg"
     *    "onlineEnable":"1",
     *    "onlineText":"holle word!",
     *    "offlineEnable":"1",
     *    "offlineText":"hi carystudio!",
     *    "rebootEnable":"1",
     *    "rebootText":"hi totolink!",
     *    "phone0":"12345678901",
     *    "phone1":"98765432102",
     *    "phone2":"22222222222",
     *    "phone3":"66666666666",
     *    "phone4":"88888888888",
     *    "phone5":"99999999999"
     * }
     */
    setSmsCfg: null,
    /**
     * 获取GPS定位配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-03-25
     * @property {String} enabled      	  	  开关: 开启:1; 关闭:0
	 * @property {String} type      	  	  类型: GPS+BeiDou:1;GPS:0
     * @property {String} localPort       	  本地端口
     * @property {String} protocol        	  协议: TCP, UDP
     * @property {String} server   		  	  服务器地址
	 * @property {String} serverPort   		  服务端口
	 * @property {String} packetHeader   	  包头
	 * @property {String} packetTailer   	  包尾
	 * @property {String} gpsReportInterval   GPS数据上报间隔（s）
     * @example
     * request:
     * {
     *     "topicurl":"getGpsReportTimeCfg"
     * }
     * response:
     * {
     *     "enabled":	1,
     *     "localPort":	"33",
     *     "protocol":	"TCP",
	 *     "server":	"10.0.0.2",
	 *     "serverPort":	"44",
	 *     "packetHeader":	"11",
	 *     "packetTailer":	"22",
     *     "gpsReportInterval":	"30"
     * }
     */
    getGpsReportTimeCfg: {
      debugUrl: "gps.json"
    },
    /**
     * 保存GPS定位配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-03-25
     * @param {String} enabled      	  开关: 开启:1; 关闭:0
	 * @param {String} type      	      类型: GPS+BeiDou:1;GPS:0
     * @param {String} localPort          本地端口
     * @param {String} protocol           协议: TCP, UDP
     * @param {String} server   		  服务器地址
	 * @param {String} serverPort   	  服务端口
	 * @param {String} packetHeader   	  包头
	 * @param {String} packetTailer   	  包尾
	 * @param {String} gpsReportInterval  GPS数据上报间隔（
     * @example
     * request:
     * {
     *     "topicurl":"setGpsReportTimeCfg",
	 *     "enabled":	1,
     *     "localPort":	"33",
     *     "protocol":	"TCP",
	 *     "server":	"10.0.0.2",
	 *     "serverPort":	"44",
	 *     "packetHeader":	"11",
	 *     "packetTailer":	"22",
     *     "gpsReportInterval":	"30"
     * }
     */
    setGpsReportTimeCfg: null,
	/**
     * 获取GPS定位(经纬度)配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-03-25
     * @property {String} module      	  支持gps:1; 不支持gps:0
     * @property {String} longitude       经度
     * @property {String} latitude        纬度
     * @property {String} gpsReportTime   GPS数据上报间隔（s）
     * @example
     * request:
     * {
     *     "topicurl":"getGpsReportCfg"
     * }
     * response:
     * {
     *     "module":	"1",
     *     "longitude":	"113.45610",
     *     "latitude":	"22.53154",
     *     "gpsReportTime":	"30"
     * }
     */
    getGpsReportCfg: {
      debugUrl: "gps.json"
    },
    /**
     * 保存GPS定位(经纬度)配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-03-25
	 * @param {String} gpsReportTime  		GPS数据上报间隔（s）
     * @example
     * request:
     * {
     *     "topicurl":"setGpsReportCfg",
	 *     "gpsReportTime":"30"
     * }
     */
    setGpsReportCfg: null,
	/**
     * 获取GPS定位(针对ML302)状态
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-03-25
     * @property {String} satellitesNum   卫星数
	 * @property {String} satellitesClock 卫星时钟
     * @property {String} longitude       经度
     * @property {String} latitude        纬度
     * @example
     * request:
     * {
     *     "topicurl":"getGps3Status"
     * }
     * response:
     * {
     *     "satellitesNum":	"2",
	 *     "satellitesClock":	"22",
     *     "longitude":	"113.45610",
     *     "latitude":	"22.53154"
     * }
     */
	getGps3Status: {
      debugUrl: "gps3_status.json"
    },
	/**
     * 获取GPS定位(针对ML302)配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-03-25
     * @property {String} mode      	  客户端:1; 关闭:0
     * @property {String} bindPort        绑定端口
     * @property {String} server          服务器地址
	 * @property {String} serverPort      服务端口
	 * @property {String} protocol        协议
	 * @property {String} socketTimeout   Socket超时
	 * @property {String} serialTimeout   串口超时
	 * @property {String} packetPayload   有效载荷包
	 * @property {String} heartBestContent    心跳包内容
	 * @property {String} heartBestInterval   心跳包间隔
	 * @property {String} bandRate        频宽率
	 * @property {String} parityBit       奇偶校验位
	 * @property {String} dataBit         数据位
	 * @property {String} stopBit         停止位
     * @property {String} gpsReportInterval   GPS数据上报间隔（s）
     * @example
     * request:
     * {
     *     "topicurl":"getGps3Cfg"
     * }
     * response:
     * {
     *     "mode":	"1",
     *     "bindPort":	"40001",
     *     "server":	"192.168.0.2",
	 *     "serverPort":	"40002",
	 *     "protocol":	"udp",
	 *     "socketTimeout":	"500",
	 *     "serialTimeout":	"500",
	 *     "packetPayload":	"500",
	 *     "heartBestContent":	"router_0001",
	 *     "heartBestInterval":	"1",
	 *     "bandRate":	"9600",
	 *     "parityBit":	"none",
	 *     "dataBit":	"8",
	 *     "stopBit":	"1",
     *     "gpsReportTime":	"30"
     * }
     */
    getGps3Cfg: {
      debugUrl: "gps.json"
    },
    /**
     * 保存GPS定位(针对ML302)配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-03-25
	 * @param {String} mode      	  客户端:1; 关闭:0
     * @param {String} bindPort        绑定端口
     * @param {String} server          服务器地址
	 * @param {String} serverPort      服务端口
	 * @param {String} protocol        协议
	 * @param {String} socketTimeout   Socket超时
	 * @param {String} serialTimeout   串口超时
	 * @param {String} packetPayload   有效载荷包
	 * @param {String} heartBestContent    心跳包内容
	 * @param {String} heartBestInterval   心跳包间隔
	 * @param {String} bandRate        频宽率
	 * @param {String} parityBit       奇偶校验位
	 * @param {String} dataBit         数据位
	 * @param {String} stopBit         停止位
     * @param {String} gpsReportInterval   GPS数据上报间隔（s）
     * @example
     * request:
     * {
     *     "topicurl":"setGps3Cfg",
	 *     "mode":	"1",
     *     "bindPort":	"40001",
     *     "server":	"192.168.0.2",
	 *     "serverPort":	"40002",
	 *     "protocol":	"udp",
	 *     "socketTimeout":	"500",
	 *     "serialTimeout":	"500",
	 *     "packetPayload":	"500",
	 *     "heartBestContent":	"router_0001",
	 *     "heartBestInterval":	"1",
	 *     "bandRate":	"9600",
	 *     "parityBit":	"none",
	 *     "dataBit":	"8",
	 *     "stopBit":	"1",
     *     "gpsReportTime":	"30"
     * }
     */
    setGps3Cfg: null,
    /**
     * 获取IOT配置
     * @Author   Felix       <Felix@carystudio.com>
     * @DateTime 2019-12-7
     * @property {String} hostPath    服务器IP或域名
     * @property {String} port        服务器端口
     * @property {String} enabled       开关状态
     * @property {String} connStatus    连接状态
     * @example
     * request:
     * {
     *     "topicurl":"getIotCfg"
     * }
     * response:
     * {
     *     "hostPath":"iot.crabox-sys.com",
     *     "enabled":"1",
     *     "port":"80",
     *     "connStatus":"1"
     * }
     */
    getIotCfg: {
      debugUrl: "iot.json"
    },
    getAIotCfg: {
      debugUrl: "aiot.json"
    },
    /**
     * 保存IOT配置
     * @Author   Felix       <Felix@carystudio.com>
     * @DateTime 2019-12-7
     * @param {String} hostPath   服务器IP或域名
     * @param {String} port       服务器端口
     * @param {String} enabled      开关状态
     * @example
     * request:
     * {
     *      "topicurl":"setIotCfg",
     *      "enabled":"1",
     *      "hostPath":"iot.crabox-sys.com",
     *      "port":"80"
     * }
     */
    setIotCfg: null,
    setAIotCfg: null,
    /**
     * 获取IOT配置
     * @Author   Felix       <Felix@carystudio.com>
     * @DateTime 2019-12-7
     * @property {String} hostPath    服务器IP或域名
     * @property {String} port        服务器端口
     * @property {String} enabled       开关状态
     * @property {String} connStatus    连接状态
     * @example
     * request:
     * {
     *     "topicurl":"getIotMCfg"
     * }
     * response:
     * {
     *     "hostPath":"iot.crabox-sys.com",
     *     "enabled":"1",
     *     "port":"80",
     *     "connStatus":"1"
     * }
     */
    getIotMCfg: {
      debugUrl: "iot.json"
    },
    getAIotMCfg: {
      debugUrl: "aiot.json"
    },
    /**
     * 保存IOT配置
     * @Author   Felix       <Felix@carystudio.com>
     * @DateTime 2019-12-7
     * @param {String} hostPath   服务器IP或域名
     * @param {String} port       服务器端口
     * @param {String} enabled      开关状态
     * @example
     * request:
     * {
     *      "topicurl":"setIotMCfg",
     *      "enabled":"1",
     *      "hostPath":"iot.crabox-sys.com",
     *      "port":"80"
     * }
     */
    setIotMCfg: null,
    setAIotMCfg: null,
    
    getOnenetIotMCfg: {
      debugUrl: "onenet.json"
    },
    getOnenetIotMStateCfg: {
      debugUrl: "iotSta.json"
    },
    /**
     * 移动物联网开放平台客户端
     * @Author   vinson       <vinson_tan@carystudio.com>
     * @DateTime 201230808
     * @param {String} hostPath   服务器IP或域名
     * @param {String} port       服务器端口
     * @param {String} enabled      开关状态
     * @example
     * request:
     * {
     *      "topicurl":"getOnenetIotMCfg",
     *      "enabled":"1",
     *      "hostPath":"iot.crabox-sys.com",
     *      "port":"80"
     * }
     */
    setOnenetIotMCfg : null,



getAliyunInfo: {
  debugUrl: "aliyun.json"
},
getAliyunStateCfg: {
    debugUrl: "iotSta.json"
},
 setAliyunInfo: null,



    /**
    * 获取Tunnel配置
    * @Author Karen
    * @DateTime 2020-06-29
    * @property {Array}	rule	规则列表
    * @property {String}	idx	序号
    * @property {String}	enabled	开关，1:开启 0: 关闭
    * @property {String}	name	名称
    * @property {String}	mode	类型：ipip 、 gre、 mgre
    * @property {String}	localVirtualIp	本地虚拟IP地址
    * @property {String}	peerVirtualIp	对端虚拟IP地址
    * @property {String}	peerExternIp	对端外部IP
    * @property {String}	interfaceType	接口类型 ：staticIp 、interface
    * @property {String}	localInterface	本地外部接口：modem、eth0, br0
    * @return {object}
    * @example
    * request:
    *
    * 	"topicurl":"getTunnelCfg"
    * response:
    * {
    * 	"rule": [
    *   {
    * 	"idx": 1,
    * 	"enabled": "1",
    * 	"name": "888",
    * 	"mode": "ipip",
    * 	"localVirtualIp": "10.1.1.1",
    * 	"peerVirtualIp": "10.1.1.2",
    * 	"peerExternIp": "192.168.30.211",
    * 	"interfaceType": "interface",
    * 	"localInterface": "eth2.2"
    *   }
    *   ]
    * }
    */
    getTunnelCfg: {
      debugUrl: "tunnel.json"
    },
    /**
     * 保存Tunnel配置
     * @param {String} addEffect   0:开关设置，1：数据设置
     * @param {Array} rule   规则列
     * @example
     * request:
     * {
     *      "topicurl":"setTunnelCfg",
     *      "addEffect":"1",
     *      "rule":[]
     * }
     */
    setTunnelCfg: null,
     /**
    * 获取Tunnel配置
    * @Author Karen
    * @DateTime 2020-06-29
    * @property {Array} rule  规则列表
    * @property {String}  idx 序号
    * @property {String}  routeEnabled 开关，1:开启 0: 关闭
    * @property {String}  tunnelName  名称
    * @property {String}  virtualIp  本地虚拟IP地址
    * @property {String}  ip 对端内网ip
    * @property {String}  mask  子网掩码
    * @property {String}  desc 描述
    * @return {object}
    * @example
    * request:
    *
    *   "topicurl":"getTunnelCfg"
    * response:
    * {
    *   "rule": [
    *   {
    *   "idx": 1,
    *   "routeEnabled": "1",
    *   "tunnelName": "888",
    *   "ip": "192.168.1.2",
    *   "virtualIp": "10.1.1.1",
    *   "mask": "255.255.255.0",
    *   "desc": "10.1.1.2"
    *   }
    *   ]
    * }
    */
    getTunnelRouteCfg: {
      debugUrl: "tunnelroute.json"
    },
    /**
     * 保存Tunnel配置
     * @param {String} addEffect   0:开关设置，1：数据设置
     * @param {Array} rule   规则列
     * @example
     * request:
     * {
     *      "topicurl":"setTunnelRouteCfg",
     *      "addEffect":"1",
     *      "rule":[]
     * }
     */
    setTunnelRouteCfg: null,
    /**
     * 获取ICMP检测配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2019-12-11
     * @property {String} enable            开关，1:开启 0: 关闭
     * @property {String} icmpCheckName     名称
     * @property {String} checkType         检测类型： icmp、domain
     * @property {String} dstAddress      目的地址（icmp时为IP地址，domain时为域名）
     * @property {String} dstBackup         目的备份地址
     * @property {String} interval          检测间隔
     * @property {String} retryTimes        重复次数
     * @property {String} sourceInterface   源网络接口（default、br0、modem、eth0） default后台会根据当前上网方式去设置接口， 其他对应lan， 4g，wan
     * @property {String} timeoutAction     检测失败触发机制（modem-reset、reboot、network） 模块重启，设备重启，网络重启
     * @example
     * request:
     * {
     *      "topicurl":"getIcmpCheckCfg"
     * }
     * response:
     * [
     *      {
     *        "idx":"1",
     *        "enable":"1",
     *        "icmpCheckName":"22",
     *        "checkType":"ipip",
     *        "dstAddress":"114.114.114.114",
     *        "dstBackup":"",
     *        "interval":"20",
     *        "retryTimes":"3",
     *        "sourceInterface":"eth0",
     *        "timeoutAction":"reboot"
     *      }
     * ]
     */
    getIcmpCheckCfg: {
      debugUrl: "icmp_check.json"
    },
    /**
     * 保存ICMP检测配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2019-12-11
     * @param {string} enable            开关，1:开启 0: 关闭
     * @param {string} icmpCheckName     名称
     * @param {string} checkType         检测类型： icmp、domain
     * @param {string} dstAddress        目的地址（icmp时为IP地址，domain时为域名）
     * @param {string} dstBackup         目的备份地址
     * @param {string} interval          检测间隔
     * @param {string} retryTimes        重复次数
     * @param {string} sourceInterface   源网络接口（default、br0、modem、eth0） default后台会根据当前上网方式去设置接口， 其他对应lan， 4g，wan
     * @param {string} timeoutAction     检测失败触发机制（modem-reset、reboot、network） 模块重启，设备重启，网络重启
     * @example
     * request:
     * {
     *      "topicurl":"setIcmpCheckCfg",
     *      "idx":"1",
     *      "enable":"1",
     *      "icmpCheckName":"33",
     *      "checkType":"domain",
     *      "dstAddress":"www.qq.com",
     *      "dstBackup":"",
     *      "interval":"20",
     *      "retryTimes":"3",
     *      "sourceInterface":"modem",
     *      "timeoutAction":"modem-reset"
     * }
     */
    setIcmpCheckCfg: null,
    /**
     * 删除ICMP检测规则
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2019-12-11
     * @param {string}
     * @example
     * request:
     * {
     *      "topicurl":"delIcmpCheckCfg",
     *      "0":{
     *        "idx":"1",
     *        "enable":"1",
     *        "icmpCheckName":"33",
     *        "checkType":"domain",
     *        "dstAddress":"www.qq.com",
     *        "dstBackup":"",
     *        "interval":"20",
     *        "retryTimes":"3",
     *        "sourceInterface":"modem",
     *        "timeoutAction":"modem-reset"
     *      }
     * }
     */
    delIcmpCheckCfg: null,
    /**
     * 获取定时任务配置
     * @Author Karen
     * @DateTime 2020-07-01
     * @property {Array}	rule	规则表
     * @property {String}	idx	ID
     * @property {String}	enabled	开关。1：开，0：关
     * @property {String}	taskName	名称
     * @property {String}	taskMode	定时类型
     * @property {String}	taskAction	类型
     * @property {String}	hourStart	起始时
     * @property {String}	hourEnd	结束时
     * @property {String}	minuteStart	起始分
     * @property {String}	minuteEnd	结束分
     * @property {String}	dayStart	起始日
     * @property {String}	dayEnd	结束日
     * @property {String}	weekStart	起始周
     * @property {String}	weekEnd	结束周
     * @return {object}
     * @example
     * request:
     *
     * {
     * 	"topicurl":"getTimedTaskCfg"
     * }
     * response:
     * {
     *   "rule": [
     *     {
     *       "idx": 1,
     *       "enabled": "1",
     *       "taskName": "ww",
     *       "taskMode": "1",
     *       "taskAction": "reboot",
     *       "hourStart": "4",
     *       "hourEnd": "",
     *       "minuteStart": "30",
     *       "minuteEnd": "",
     *       "dayStart": "5",
     *       "dayEnd": "8",
     *       "weekStart": "",
     *       "weekEnd": ""
     *   }
     *   ]
     * }
     */
    getTimedTaskCfg: {
      debugUrl: "time_task.json"
    },
    /**
     * 设置定时任务
     * @param {String} addEffect   0:开关设置，1：数据设置
     * @param {Array} subnet   规则列
     * @example
     * request:
     * {
     *      "topicurl":"setTimedTaskCfg",
     *      "addEffect":"1",
     *      "subnet":[]
     * }
     */
    setTimedTaskCfg: null,
    /**
     * 设置授权设置参数
     * @Author   Felix       <Felix@carystudio.com>
     * @DateTime 2019-12-11
     * @param {String} accessCode       授权码
     * @example
     * request:
     * {
     *      "topicurl":"setActStatus"
     *      "accessCode":"A242D34ADS21"
     * }
     */
    setActStatus: null,
    /**
    * 获取eoip配置
    * @Author Karen
    * @DateTime 2020-06-29
    * @property {String}	rule	规则列表
    * @property {String}	idx	序号
    * @property {String}	eoipId	ID 1-65535
    * @property {String}	eoipName	名称
    * @property {String}	dstAddress	目的地址
    * @return {object}
    * @example
    * request:
    *
    * 	"topicurl":"getEoipCfg"
    * response:
    * {
    * 	"rule": [
    *   {
    * 	  "idx": 1,
    * 	  "eoipId": "33",
    * 	  "eoipName": "lin",
    * 	  "dstAddress": "192.168.30.21"
    *   }
    *   ]
    * }
    */
    getEoipCfg: {
      debugUrl: "eoip.json"
    },
    /**
     * 设置eoip配置
     * @param {Array} rule   规则列
     * @example
     * request:
     * {
     *      "topicurl":"setEoipCfg",
     *      "addEffect":"1",
     *      "rule":[]
     * }
     */
    setEoipCfg: null,
    /**
     * 获取RIP配置
     * @Author   Jeff       <jeff@carystudio.com>
     * @DateTime 2020-3-2
     * @property   {string}   type       类型
     * @property   {string}   address      地址
     * @property   {string}   redistributeConnect 重新分布直连路由 开启：1， 关闭：0
     * @property   {string}   redistributeStatic  重新分布静态路由 开启：1， 关闭：0
     * @property   {string}   redistributeKernel  重新分布内核     开启：1， 关闭：0
     * @return   {object}
     * @example
     * request:
     * {
     *      "topicurl":"getRoutingRipcfg",
     * }
     * response:
     * [
     *      {
     *        "redistributeConnect":"0",
     *        "redistributeStatic":"0",
     *        "redistributeKernel":"0",
     *      }, {
     *        "idx":"1",            //数量
     *        "type":"network",           //类型
     *        "address":"10.0.0.107/24",    //地址
     *      }
     * ]
     */
    getRoutingRipCfg: {
      debugUrl: "rip.json"
    },
    /**
     * 设置rip配置
     * @Author   Jeff       <jeff@carystudio.com>
     * @DateTime 2020-3-2
     * @param   {string}   type            类型 network/neighbour
     * @param   {string}   address         地址,类型为network时此参数为x.x.x.x/24，neighbour时为ip地址
     * @example
     * request:
     * {
     *       "topicurl":"setRoutingRipCfg",
     *       "type":"network",
     *       "address":"192.168.2.0/24",
     * }
     */
    setRoutingRipCfg: null,
    /**
     * 删除rip配置
     * @Author   Jeff       <jeff@carystudio.com>
     * @DateTime 2020-3-2
     * @param   {string} address
     * @example
     * request:
     * {
     *      "topicurl":"delRoutingRipCfg",
     *      "0":{
     *        "idx":"1",
     *        "type":"network",
     *        "address":"10.0.0.107/24"
     *      }
     * }
     */
    delRoutingRipCfg: null,
    /**
     * 设置rip基本配置
     * @Author   Jeff       <jeff@carystudio.com>
     * @DateTime 2020-3-2
     * @param   {string}   redistributeConnect 重新分布直连路由 开启：1， 关闭：0
     * @param   {string}   redistributeStatic  重新分布静态路由 开启：1， 关闭：0
     * @param   {string}   redistributeKernel  重新分布内核     开启：1， 关闭：0
     * @example
     * request:
     * {
     *       "topicurl":"setBasicRoutingCfg",
     *       "setType":"0", //0:RIP 1:OSPF
     *       "redistributeConnect":"0",
     *       "redistributeStatic":"0",
     *       "redistributeKernel":"0"
     * }
     */
    setBasicRoutingCfg: null,
    /**
    * 获取OSPF配置
    * @Author   Jeff       <jeff@carystudio.com>
    * @DateTime 2020-3-2
    * @property   {string}   redistributeConnect 重新分布直连路由 开启：1， 关闭：0
    * @property   {string}   redistributeStatic  重新分布静态路由 开启：1， 关闭：0
    * @property   {string}   redistributeKernel  重新分布内核     开启：1， 关闭：0
    * @property   {string}   type        类型
    * @property   {string}   address      地址
    * @property   {string}   areaNumber   area值
    * @property   {string}   interface    接口
    * @property   {string}   cost         开销值
    * @property   {string}   networkType  网络类型
    * @example
    * request:
    * {
    *      "topicurl":"getRoutingOspfcfg",
    * }
    * response:
    * [
    *      {
    *        "redistributeConnect":"0",
    *        "redistributeStatic":"0",
    *        "redistributeKernel":"0"
    *      },
    *      {
    *        "idx":"1",
    *        "type":"network",
    *        "address":"10.0.0.107/24",
    *        "areaNumber":"0"
    *      }
    * ]
    */
    getRoutingOspfCfg: {
      debugUrl: "ospf.json"
    },
    /**
     * 设置ospf配置
     * @Author   Jeff       <jeff@carystudio.com>
     * @DateTime 2020-3-2
     * @param   {string}   type            类型 network/neighbour/interface
     * @param   {string}   address         地址,类型为network时此参数为x.x.x.x/24，neighbour时为ip地址
     * @param   {string}   areaNumber      类型为network时设置此参数 0-65535
     * @param   {string}   interface       类型为interface时设置此参数 br0/eth0/modem
     * @param   {string}   cost            类型为interface时设置此参数 1-65535
     * @param   {string}   networkType     类型为interface时设置此参数 broadcast/non-broadcast/point-to-multipoint/point-to-point
     * @example
     * request:
     * {
     *       "topicurl":"setRoutingOspfCfg",
     *       "type":"interface",
     *       "interface":"br0",
     *       "networkType":"non-broadcast"
     * }
     */
    setRoutingOspfCfg: null,
    /**
     * 删除OSPF配置
     * @Author   Jeff       <jeff@carystudio.com>
     * @DateTime 2020-3-2
     * @param   {string} address
     * @example
     * request:
     * {
     *      "topicurl":"delRoutingOspfCfg",
     *      "0":{
     *        "idx":"1",
     *        "type":"network",
     *        "address":"10.0.0.107/24",
     *        "areaNumber":"0"
     *      }
     * }
     */
    delRoutingOspfCfg: null,
    /**
     * 获取SNMP配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-3-2
     * @property   {string}   enabled    SNMP服务  启用：1， 禁用：0
     * @property   {string}   version     SNMP版本 0：SNMPv2c,   1： SNMPv3
     * @property   {string}   serverPort     SNMP端口
     * @property   {string}   community  共同体 最大长度32位
     * @property   {string}   trapIp     Trap IP
     * @property   {string}   trapPort   Trap 端口
     * @property   {string}   interface   源接口  default, br0, eth0, modem
     * @property   {string}   localhost   回环地址标识  启用：1， 禁用：0
     * SNMPv3
     * @property   {string}   mode      模式  AuthPriv, AuthNoPriv, NoAuthNoPriv
     * @property   {string}   username    账号 最大长度32位
     * @property   {string}   password    密码 最大长度32位
     * @property   {string}   hash      Hash  MD5, SHA
     * @property   {string}   encryption  加密  AES, DES
     * @property   {string}   key       加密密码 最大长度32位
     * @return   {object}
     * @example
     * request:
     * {
     *      "topicurl":"getSnmpCfg",
     * }
     * response:
     * [
     *      {
     *        "enabled":"1",
     *        "version":"v2c",
     *        "serverPort":"161",
     *        "community":"public",
     *        "trapIp":"192.168.1.2",
     *        "trapPort":"162",
     *        "interface":"default",
     *        "localhost":"0"
     *     },
     *     {
     *        "idx":  "1",
     *        "mode":  "1",
     *        "username": "test",
     *        "password":  "test",
     *        "hash": "MD5",
     *        "encryption": "AES",
     *        "key":  "1234"
     *     }
     * ]
     */
    getSnmpCfg: {
      debugUrl: "snmp.json"
    },
    /**
     * 设置SNMP配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-3-2
     * @param {String} addEffect       0：设置SNMP开关；1：设置SNMPv2c, 2：设置SNMPv3
     * @param   {string}   serverPort 服务端口 1-65535
     * @param   {string}   version     SNMP版本 0：SNMPv2c,   1： SNMPv3
     * @param   {string}   serverPort      SNMP端口
     * @param   {string}   community  共同体 最大长度32位
     * @param   {string}   trapIp     Trap IP
     * @param   {string}   trapPort   Trap 端口
     * @param   {string}   interface   源接口  default, br0, eth0, modem
     * @param   {string}   localhost   回环地址标识  启用：1， 禁用
     * SNMPv3
     * @param   {string}   mode     模式  0: AuthPriv, 1: AuthNoPriv, 2: NoAuthNoPriv
     * @param   {string}   username     账号 最大长度32位
     * @param   {string}   password     密码 最大长度32位
     * @param   {string}   hash       Hash  MD5, SHA
     * @param   {string}   encryption  加密  AES, DES
     * @param   {string}   key      加密密码 最大长度32
     * @example
     * request:
     * {
     *      "topicurl":"setSnmpCfg",
     *      "version":"1",
     *      "serverPort":"161",
     *      "community":"public",
     *      "trapIp":"192.168.1.2",
     *      "trapPort":"162",
     *      "interface":"default",
     *      "localhost":"0",
     *
     *      "mode": "0",
     *      "username": "test",
     *      "password": "test1234",
     *      "hash": "MD5",
     *      "encryption": "AES",
     *      "key":  "123456"
     * }
     **/
    setSnmpCfg: null,
    /**
     * 删除SNMPv3规则
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-3-02
     * @example
     * request:
     * {
     *      "topicurl":"delSnmpCfg",
     *      "0":{
     *         "idx":"1",
     *         "username":"test",
     *         "password":"test1234",
     *         "hash":"MD5",
     *         "encryption":"AES",
     *         "key":"123456"
     *      }
     * }
     */
    delSnmpCfg: null,
    /**
     * 获取VRRP配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-3-2
     * @property   {string}   enabled       VRRP服务  启用：1， 禁用：0
     * @property   {string}   vrInterface     接口：lan/wan
     * @property   {string}   virtualIp       虚拟IP
     * @property   {string}   virtualId     虚拟ID
     * @property   {string}   priority      优先级
     * @property   {string}   noticeTimers    超时时间
     * @property   {string}   status      状态  启用：1， 禁用：0
     * @return   {object}
     * @example
     * request:
     * {
     *      "topicurl":"getVrrpCfg",
     * }
     * response:
     * {
     *      "enabled":"1",
     *      "vrInterface":"wan",
     *      "virtualIp":"192.168.3.1",
     *      "virtualId":"2",
     *      "priority":"100",
     *      "noticeTimers":"1",
     *      "status":""
     * }
     */
    getVrrpCfg: {
      debugUrl: "vrrp.json"
    },
    /**
     * 设置VRRP配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-3-2
     * @param   {string}   enabled        VRRP服务  启用：1， 禁用：0
     * @param   {string}   vrInterface     接口：lan/wan
     * @param   {string}   virtualIp      虚拟IP
     * @param   {string}   virtualId      虚拟ID
     * @param   {string}   priority       优先级
     * @param   {string}   noticeTimers     超时时间
     * @example
     * request:
     * {
     *      "topicurl":"setVrrpCfg",
     *      "enabled":"1",
     *      "vrInterface":"wan",
     *      "virtualIp":"192.168.3.1",
     *      "virtualId":"2",
     *      "priority":"100",
     *      "noticeTimers":"1"
     * }
     */
    setVrrpCfg: null,
    /**
     * 获取BGP配置
     * @Author   Jeff       <jeff@carystudio.com>
     * @DateTime 2020-3-2
     * @property   {string}   routerAs    路由As号
     * @property   {string}   routerId    路由ID
     * @property   {string}   logChange   高级设置参数：记录并显示邻居建立过程的信息 1：开启 0：关闭
     * @property   {string}   autoSummary 高级设置参数：自动路由汇总功能 1：开启 0：关闭
     * @property   {string}   synchronization 高级设置参数：BGP与IBGP同步功能 1：开启 0：关闭
     * @property   {string}   type    类型 network/neighbour
     * @property   {string}   address 地址,类型为network时此参数为x.x.x.x/24，neighbour时为ip地址
     * @property   {string}   remoteAs    远端As号 1-65535
     * @property   {string}   updateSource    高级设置参数 接口 br0，eth0等，作用是使用设置的接口作为对等体
     * @return   {object}
     * @example
     * request:
     * {
     *      "topicurl":"getRoutingBgpCfg",
     * }
     * response:
     * [
     *      {
     *        "routerAs":"200",
     *        "routerId":"192.168.1.1",
     *      },
     *      {
     *        "idx":  "1",
     *        "type": "network",
     *        "address":  "10.0.0.107/24",
     *        "logChange":"1",
     *        "autoSummary":"0",
     *        "synchronization":"0"
     *      }
     * ]
     */
    getRoutingBgpCfg: {
      debugUrl: "bgp.json"
    },
    /**
     * 设置BGP配置
     * @Author   Jeff       <jeff@carystudio.com>
     * @DateTime 2020-3-2
     * @param   {string}   type            类型 network/neighbour
     * @param   {string}   address         地址,类型为network时此参数为x.x.x.x/24，neighbour时为ip地址
     * @param   {string}   remoteAs        远端As号 1-65535
     * @param   {string}   updateSource    高级设置参数 接口 br0，eth0等，作用是使用设置的接口作为对等体
     * @param   {string}   logChange       高级设置参数：记录并显示邻居建立过程的信息 1：开启 0：关闭
     * @param   {string}   autoSummary     高级设置参数：自动路由汇总功能 1：开启 0：关闭
     * @param   {string}   synchronization 高级设置参数：BGP与IBGP同步功能 1：开启 0：关闭
     * @example
     * request:
     * {
     *       "topicurl":"setRoutingBgpCfg",
     *       "type":"neighbour",
     *       "address":"192.168.2.33",
     *       "remoteAs":"100"
     * }
     */
    setRoutingBgpCfg: null,
    /**
     * 删除BGP配置
     * @Author   Jeff       <jeff@carystudio.com>
     * @DateTime 2020-3-2
     * @param   {string}
     * @example
     * request:
     * {
     *      "topicurl":"delRoutingBgpCfg",
     *      "0":{
     *        "idx":"1",
     *        "type":"network",
     *        "address":"10.0.0.107/24"
     *      }
     * }
     */
    delRoutingBgpCfg: null,
    /**
     * 获取远程访问配置
     * @DateTime 2020-3-2
     * @property   {string}   enable        开关
     * @property   {string}   port      端口
     * @example
     * request:
     * {
     *      "topicurl":"getRemoteCfg",
     * }
     * response:
     * [
     *      {
     *         "enable": "1",
     *         "port": "80"
     *      }
     * ]
     */
    getRemoteCfg: {
      debugUrl: "remote_access.json"
    },
    /**
     * 设置远程访问配置
     * @Author   Jeff       <jeff@carystudio.com>
     * @DateTime 2020-3-2
     * @param   {string}   interfaceType  网络接口类型 wan、wan4g
     * @param   {string}   sshEnable      ssh是否开启  1：开启 0：关闭
     * @param   {string}   cliEnable      cli控制       1：开启 0：关闭
     * @param   {string}   httpEnable     http是否开启  1：开启 0：关闭
     * @param   {string}   httpsEnable    https是否开启 1：开启 0：关闭
     * @example
     * request:
     * {
     *       "topicurl":"setRemoteCfg",
     *       "interfaceType":"wan",
     *       "sshEnable":"1",
     *       "cliEnable":"1",
     *       "httpEnable":"1",
     *       "httpsEnable":"1"
     * }
     */
    setRemoteCfg: null,
    /**
     * 获取LinkSwitch配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-3-2
     * @property   {string}   enabled            开关 1:开启, 0:关闭
     * @property   {string}   linkStatus            状态
     * @property   {string}   mainInterface         接口, WAN
     * @property   {string}   mainServer            服务器, 域名(IP)
     * @property   {string}   mainNormalInterval    正常间隔, 1-65535
     * @property   {string}   mainRetryTimes        重试时间, 1-65535
     * @property   {string}   mainInterfaceBind     接口绑定, none
     * @property   {string}   sim1Interface         接口, SIM1
     * @property   {string}   sim1Server            服务器, 域名(IP)
     * @property   {string}   sim1NormalInterval    正常间隔, 1-65535
     * @property   {string}   sim1RetryTimes        重试时间, 1-65535
     * @property   {string}   sim1InterfaceBind     接口绑定, none
     * @property   {string}   sim2Interface         接口, SIM2
     * @property   {string}   sim2Server            服务器, 域名(IP)
     * @property   {string}   sim2NormalInterval    正常间隔, 1-65535
     * @property   {string}   sim2RetryTimes        重试时间, 1-65535
     * @property   {string}   sim2InterfaceBind     接口绑定, none
     * @return   {object}
     * @example
     * request:
     * {
     *       "topicurl":"getLinkSwitchCfg",
     * }
     * response:
     * {
     *       "enabled": "1",
     *       "linkStatus": "NONE",
     *       "mainInterface":  "WAN",
     *       "mainServer": "192.168.121.11",
     *       "mainNormalInterval": "65535",
     *       "mainRetryTimes": "65535",
     *       "mainInterfaceBind":  "none",
     *       "sim1Interface":  "SIM1",
     *       "sim1Server": "192.168.121.11",
     *       "sim1NormalInterval": "65535",
     *       "sim1RetryTimes": "65535",
     *       "sim1InterfaceBind":  "none",
     *       "sim2Interface":  "SIM2",
     *       "sim2Server": "192.168.121.11",
     *       "sim2NormalInterval": "65535",
     *       "sim2RetryTimes": "65535",
     *       "sim2InterfaceBind":  "none"
     * }
     */
    getLinkSwitchCfg: {
      debugUrl: "link_switch.json"
    },
    /**
     * 设置LinkSwitch配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-3-2
     * @param   {string}   enabled            开关 1:开启, 0:关闭
     * @param   {string}   linkStatus            状态
     * @param   {string}   mainInterface         接口, WAN
     * @param   {string}   mainServerServer      服务器, 域名(IP)
     * @param   {string}   mainNormalInterval    正常间隔, 1-65535
     * @param   {string}   mainRetryTimes        重试时间, 1-65535
     * @param   {string}   mainInterfaceBind     接口绑定, none
     * @param   {string}   sim1Interface         接口, SIM1
     * @param   {string}   sim1Server            服务器, 域名(IP)
     * @param   {string}   sim1NormalInterval    正常间隔, 1-65535
     * @param   {string}   sim1RetryTimes        重试时间, 1-65535
     * @param   {string}   sim1InterfaceBind     接口绑定, none
     * @param   {string}   sim2Interface         接口, SIM2
     * @param   {string}   sim2Server            服务器, 域名(IP)
     * @param   {string}   sim2NormalInterval    正常间隔, 1-65535
     * @param   {string}   sim2RetryTimes        重试时间, 1-65535
     * @param   {string}   sim2InterfaceBind     接口绑定, none
     * request:
     * {
     *       "topicurl":"setLinkSwitchCfg",
     *       "enabled": "1",
     *       "linkStatus": "NONE",
     *       "mainInterface":  "WAN",
     *       "mainServer": "192.168.121.11",
     *       "mainNormalInterval": "65535",
     *       "mainRetryTimes": "65535",
     *       "mainInterfaceBind":  "none",
     *       "sim1Interface":  "SIM1",
     *       "sim1Server": "192.168.121.11",
     *       "sim1NormalInterval": "65535",
     *       "sim1RetryTimes": "65535",
     *       "sim1InterfaceBind":  "none",
     *       "sim2Interface":  "SIM2",
     *       "sim2Server": "192.168.121.11",
     *       "sim2NormalInterval": "65535",
     *       "sim2RetryTimes": "65535",
     *       "sim2InterfaceBind":  "none"
     * }
     */
     setLinkSwitchCfg: null,
     /**
     * 获取链路优先级配置
     * @Author   Jeff       <Jeff@carystudio.com>
     * @DateTime 2020-01-06
     * @property   {string}   strategy (链路优先级)  0:有线优先    1:4G/5G Only   2: 有线 Only
     * @example
     * request:
     * {
     *      "topicurl":"getWanStrategy"
     * }
     * response:
     * {
     *      "strategy":"1"
     * }
     */
     getWanStrategy: {
        debugUrl: "wan_strategy.json"
     },
     /**
     * 配置链路优先级配置
     * @Author   Jeff       <Jeff@carystudio.com>
     * @DateTime 2020-01-06
     * @param   {string}   strategy (链路优先级)  0:有线优先    1:4G/5G Only   2: 有线 Only
     * @example
     * request:
     * {
     *      "topicurl":"setWanStrategy",
     *      "strategy":"1"
     * }
     */
     setWanStrategy: null,
     /**
     * 获取Radius配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-3-2
     * @property   {string}   server          服务器, 域名(IP)
     * @property   {string}   port            端口号
     * @property   {string}   key             密码，最长64位
     * @property   {string}   interface       接口, default, br0, eth0, modem
     * @example
     * request:
     * {
     *      "topicurl":"getRadiusCfg",
     * }
     * response:
     * {
     *      "server": "abc.test.com",
     *      "port":  "112",
     *      "key": "1234567890",
     *      "interface":  "default"
     * }
     */
     getRadiusCfg: {
        debugUrl: "radius.json"
     },
     /**
     * 设置Radius配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-3-2
     * @param   {string}   server          服务器, 域名(IP)
     * @param   {string}   port            端口号
     * @param   {string}   key             密码，最长64位
     * @param   {string}   interface       接口, default, br0, eth0, modem
     * request:
     * {
     *       "topicurl":"setRadiusCfg",
     *       "server": "abc.test.com",
     *       "port": "112",
     *       "key": "1234567890",
     *       "interface":  "default"
     * }
     */
     setRadiusCfg: null,
     /**
     * 获取Attack配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-3-2
     * @property   {string}   ddosEnabled        Ddos攻击开关, 1:开启 0:关闭
     * @property   {string}   portScanEnabled    端口扫描限制开关, 1:开启 0:关闭
     * @example
     * request:
     * {
     *      "topicurl":"getAttackCfg",
     * }
     * response:
     * {
     *      "ddosEnabled":"1",
     *      "portScanEnabled":"1"
     * }
     */
     getAttackCfg: {
        debugUrl: "attack.json"
     },
     /**
     * 设置Attack配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-3-2
     * @param   {string}   ddosEnabled        Ddos攻击开关, 1:开启 0:关闭
     * @param   {string}   portScanEnabled    端口扫描限制开关, 1:开启 0:关闭
     * @example
     * request:
     * {
     *       "topicurl":"setAttackCfg",
     *       "ddosEnabled":"1",
     *       "portScanEnabled":"1"
     * }
     */
     setAttackCfg: null,
     /**
     * 获取DMVPN配置
     * @Author Karen
     * @DateTime 2020-06-30
     * @property {String}	idx	ID
     * @property {String}	enabled	开/关。1：开，0：关
     * @property {String}	name	名称
     * @property {String}	peerExternalIp	对端外部IP
     * @property {String}	localVirtualIp	本地虚拟IP
     * @property {String}	peerVirtualIp	对端虚拟IP
     * @property {String}	tunnelKey	隧道密钥
     * @property {String}	mode	模式。main、aggr
     * @property {String}	encrypt	加密
     * @property {String}	hash	Hash
     * @property {String}	groupName	工作组名
     * @property {String}	ikeLifetime	IKE存活时间
     * @property {String}	preShareKey	预共享密钥
     * @property {String}	selfIdentify	自我识别
     * @property {String}	matchIdentify	匹配识别
     * @property {String}	saAlgorithm	SA算法
     * @property {String}	lifetime	存活时间(120-86400)s
     * @property {String}	pfs	PFS
     * @property {String}	encryptInterface	接口
     * @property {String}	nhrpCiscoSecrets	Nhrp思科的密钥
     * @property {String}	nhrpHoldtime	Nhrp保持时间
     * @return {Array}
     * @example
     * request:
     *
     * {
     * 	"topicurl":"getDmvpnCfg"
     * }
     * response:
     * [
     *   {
     *         "idx":"1",
     *         "enabled":"1",
     *         "name":"0",
     *         "peerExternalIp":"192.168.1.1",
     *         "localVirtualIp":"10.10.10.1",
     *         "peerVirtualIp":"10.10.10.2",
     * 	        "tunnelKey":"43424343",
     * 	        "mode":"main",
     * 	        "encrypt":"des",
     * 	        "hash":"sha1",
     * 	        "groupName":"group768",
     * 	        "ikeLifetime":"86400",
     * 	        "preShareKey":"1111111222",
     * 	        "selfIdentify":"123456",
     * 	        "matchIdentify":"777666",
     * 	        "saAlgorithm":"des-sha1",
     * 	        "lifetime":"430",
     * 	        "pfs":"close",
     * 	        "encryptInterface":"br0",
     * 	        "nhrpCiscoSecrets":"111222333",
     * 	        "nhrpHoldtime":"65535"
     *   }
     * ]
     */
     getDmvpnCfg: {
        debugUrl: "dmvpn.json"
     },
     /**
     * 设置DMVPN配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-3-2
     * @return   {string}   enabled            "1":开启 "0": 关闭
     * @example
     * request:
     * {
     *       "topicurl":"setDmvpnCfg",
     *       {
     *          "enabled":  "1"
     *       },
     *       {
     *          "name": "0",
     *          "peerExternalIp": "192.168.1.1",
     *          "localVirtualIp": "10.10.10.1",
     *          "peerVirtualIp":  "10.10.10.2",
     *          "tunnelKey":  "43424343",
     *          "mode": "main",
     *          "encrypt":  "des",
     *          "hash": "sha1",
     *          "groupName":  "gourp768",
     *          "ikeLifetime":  "86400",
     *          "preShareKey":  "1111111222",
     *          "selfIdentify": "123456",
     *          "matchIdentify":  "777666",
     *          "saAlgorithm":  "des-sha1",
     *          "lifetime": "430",
     *          "pfs":  "close",
     *          "encryptInterface": "br0",
     *          "nhrpCiscoSecrets": "111222333",
     *          "nhrpHoldtime": "65535"
     *       }
     * }
     */
     setDmvpnCfg: null,
     /**
     *删除DMVPN配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-3-2
     * @param   {string}
     * @example
     * request:
     * {
     *      "topicurl":"delDmvpnCfg",
     *      "0":{
     *          "idx":  "1",
     *          "name": "0",
     *          "peerExternalIp": "192.168.1.1",
     *          "localVirtualIp": "10.10.10.1",
     *          "peerVirtualIp":  "10.10.10.2",
     *          "tunnelKey":  "43424343",
     *          "mode": "main",
     *          "encrypt":  "des",
     *          "hash": "sha1",
     *          "groupName":  "gourp768",
     *          "ikeLifetime":  "86400",
     *          "preShareKey":  "1111111222",
     *          "selfIdentify": "123456",
     *          "matchIdentify":  "777666",
     *          "saAlgorithm":  "des-sha1",
     *          "lifetime": "430",
     *          "pfs":  "close",
     *          "encryptInterface": "br0",
     *          "nhrpCiscoSecrets": "111222333",
     *          "nhrpHoldtime": "65535"
     *      }
     * }
     */
     delDmvpnCfg: null,
     /**
      * 获取VPDN配置
      * @Author Karen
      * @DateTime 2020-06-29
      * @param {String}	vpnType	获取配置功能类型。1:L2TP，0：PPTP
      * @property {String}	enablec	开关。1:开启， 0: 关闭
      * @property {String}	connect	连接状态。1：连接，0：未连接
      * @property {String}	serverip	服务器IP地址
      * @property {String}	user	用户名
      * @property {String}	pass	密码
      * @property {String}	defr	默认路由
      * @property {String}	mppe	MPPE数据加密（PPTP）
      * @property {String}	addr	IP地址（显示连接地址）
      * @property {String}	subnet	自定义路由
      * @property {String}	net	自定义IP
      * @property {String}	mask	自定义掩码
      * @return {object}
      * @example
      * request:
      * {
      * 	"topicurl":"getVpdnCfg",
      * 	"vpnType":"0"
      * }
      * response:
      * {
      * 	"enablec": "1",
      * 	"connect": "1",
      * 	"serverip": "192.168.3.3",
      * 	"user": "karen",
      * 	"pass": "123",
      * 	"defr": "1",
      * 	"mppe": "0",
      * 	"addr": "10.10.10.1",
      * 	"subnet": [
      *     {
      * 	    "net": "192.168.0.1",
      * 	    "mask": "255.255.255.0"
      *     }
      *   ]
      * }
      */
     getVpdnCfg: {
      debugUrl: "vpdn.json"
     },
     /**
     * 设置VPDN配置
     * @Author   Felix       <felix@carystudio.com>
     * @DateTime 2020-3-22
     * @return   {string}   enable            开关， "1":开启 "0": 关闭
     * @return   {string}   name              名称
     * @return   {string}   server            服务器地址
     * @return   {string}   proto             类型， pptp, l2tp
     * @return   {string}   userName          用户名
     * @return   {string}   password          密码
     * @example
     * request:
     * {
     *       "topicurl":"setVpdnCfg",
     *       "enable": "1",
     *       "name": "AAA",
     *       "server": "10.10.10.1",
     *       "proto":  "l2tp",
     *       "userName":  "l2tp-user",
     *       "password": "l2tp-pass"
     * }
     */
     setVpdnCfg: null,
     /**
     * 获取DTU配置
     * @Author Karen
     * @DateTime 2020-06-30
     * @property {String}	enable	开/关。1：开，0：关
     * @property {String}	mode	工作模式。client：客户端，server：服务端
     * @property {String}	localPort	本地端口1-65535
     * @property {String}	protocol	协议
     * @property {String}	type	通信方式。232、485
     * @property {String}	serialPacketMaxLength	UDP接收报文最大长度1-65535
     * @property {String}	channelType	通道类型。treble：三中心，..：主备
     * @property {String}	netReceiveTimeout	接收报文超时
     * @property {String}	serialReceiveTimeout	最后包空闲时间
     * @property {String}	encryption	加密方式
     * @property {String}	key	加密秘钥
     * @property {String}	serverIp1	服务器地址
     * @property {String}	serverPort1	服务端口1-65535
     * @property {String}	serverIp2	服务器地址2
     * @property {String}	serverPort2	服务端口2
     * @property {String}	serverIp3	服务器地址3
     * @property {String}	serverPort3	服务端口3
     * @property {String}	reTryInterval	重连间隔1-65535秒
     * @property {String}	reTryCount	重连次数1-65535
     * @property {String}	registMsg	注册包内容
     * @property {String}	heartBeatInterval	心跳间隔
     * @property {String}	heartBeatData	心跳内容
     * @property {String}	rate	波特率
     * @property {String}	parity	奇偶校验
     * @property {String}	dataBit	数据位
     * @property {String}	stopBit	停止位
     * @property {String}	flowControl	流控。none、hardware、sorfware
     * @return {object}
     * @example
     * request:
     *
     * {
     * 	"topicurl":"getDtuCfg"
     * }
     * response:
     * {
     * 	"enable":"1",
     * 	"mode": "client",
     * 	"localPort":"9090",
     * 	"protocol":"udp",
     * 	"type":"rs232",
     * 	"serialPacketMaxLength":"500",
     * 	"channelType": "treble",
     * 	"netReceiveTimeout":"2000",
     * 	"serialReceiveTimeout":"1000",
     * 	"encryption":"aes",
     * 	"key":"123456",
     * 	"serverIp1":"192.168.0.1",
     * 	"serverPort1":"6688",
     * 	"serverIp2":"192.168.0.1",
     * 	"serverPort2":"6688",
     * 	"serverIp3":"192.168.0.1",
     * 	"serverPort3":"6688",
     * 	"reTryInterval":"10",
     * 	"reTryCount":"12",
     * 	"registMsg":"0x12",
     * 	"heartBeatInterval":"15",
     * 	"heartBeatData":"0x64",
     * 	"rate":"115200",
     * 	"parity":"none",
     * 	"dataBit":"8",
     * 	"stopBit":"1",
     * 	"flowControl":"hardware"
     * }
     */
     getDtuCfg: {
      debugUrl: "dtu.json"
     },
     /**
     * 获取DTU配置
     * @Author Karen
     * @DateTime 2020-06-30
     * @property {String}	enable	开/关。1：开，0：关
     * @property {String}	mode	工作模式。client：客户端，server：服务端
     * @property {String}	localPort	本地端口1-65535
     * @property {String}	protocol	协议
     * @property {String}	type	通信方式。232、485
     * @property {String}	serialPacketMaxLength	UDP接收报文最大长度1-65535
     * @property {String}	channelType	通道类型。treble：三中心，..：主备
     * @property {String}	netReceiveTimeout	接收报文超时
     * @property {String}	serialReceiveTimeout	最后包空闲时间
     * @property {String}	encryption	加密方式
     * @property {String}	key	加密秘钥
     * @property {String}	serverIp1	服务器地址
     * @property {String}	serverPort1	服务端口1-65535
     * @property {String}	serverIp2	服务器地址2
     * @property {String}	serverPort2	服务端口2
     * @property {String}	serverIp3	服务器地址3
     * @property {String}	serverPort3	服务端口3
     * @property {String}	reTryInterval	重连间隔1-65535秒
     * @property {String}	reTryCount	重连次数1-65535
     * @property {String}	registMsg	注册包内容
     * @property {String}	heartBeatInterval	心跳间隔
     * @property {String}	heartBeatData	心跳内容
     * @property {String}	rate	波特率
     * @property {String}	parity	奇偶校验
     * @property {String}	dataBit	数据位
     * @property {String}	stopBit	停止位
     * @property {String}	flowControl	流控。none、hardware、sorfware
     * @return {object}
     * @example
     * request:
     *
     * {
     * 	"topicurl":"getDtu485Cfg
"
     * }
     * response:
     * {
     * 	"enable":"1",
     * 	"mode": "client",
     * 	"localPort":"9090",
     * 	"protocol":"udp",
     * 	"type":"rs232",
     * 	"serialPacketMaxLength":"500",
     * 	"channelType": "treble",
     * 	"netReceiveTimeout":"2000",
     * 	"serialReceiveTimeout":"1000",
     * 	"encryption":"aes",
     * 	"key":"123456",
     * 	"serverIp1":"192.168.0.1",
     * 	"serverPort1":"6688",
     * 	"serverIp2":"192.168.0.1",
     * 	"serverPort2":"6688",
     * 	"serverIp3":"192.168.0.1",
     * 	"serverPort3":"6688",
     * 	"reTryInterval":"10",
     * 	"reTryCount":"12",
     * 	"registMsg":"0x12",
     * 	"heartBeatInterval":"15",
     * 	"heartBeatData":"0x64",
     * 	"rate":"115200",
     * 	"parity":"none",
     * 	"dataBit":"8",
     * 	"stopBit":"1",
     * 	"flowControl":"hardware"
     * }
     */
      getDtu485Cfg: {
        debugUrl: "dtu_485.json"
       },
     /**
     *设置DTU配置
     * @DateTime 2020-5-11
     * @param   {string}
     * @example
     * request:
     * {
     *      "topicurl":"setDtuCfg",
     *      "mode": "1",
     *     "localPort":"9090",
     *     "protocol":"udp",
     *     "serialPacketMaxLength":"500",
     *     "channelType": "3",
     *     "netReceiveTimeout":"2000",
     *     "serialReceiveTimeout":"1000",
     *     "encryption":"aes",
     *     "key":"123456",
     *      "serverIp1":"192.168.0.1",
     *      "serverPort1":"6688",
     *      "serverIp2":"192.168.0.1",
     *      "serverPort2":"6688",
     *      "serverIp3":"192.168.0.1",
     *     "serverPort3":"6688",
     *      "reTryInterval":"10",
     *      "registMsg":"0x12",
     *      "heartBeatData":"0x64",
     *      "rate":"112500",
     *      "parity":"none",
     *      "dataBit":"8",
     *      "stopBit":"1"
     * }
     * response:
     * {
     * }
     */
     setDtuCfg: null,
      /**
     *设置DTU配置
     * @DateTime 2020-5-11
     * @param   {string}
     * @example
     * request:
     * {
     *      "topicurl":"setDtu485Cfg",
     *      "mode": "1",
     *     "localPort":"9090",
     *     "protocol":"udp",
     *     "serialPacketMaxLength":"500",
     *     "channelType": "3",
     *     "netReceiveTimeout":"2000",
     *     "serialReceiveTimeout":"1000",
     *     "encryption":"aes",
     *     "key":"123456",
     *      "serverIp1":"192.168.0.1",
     *      "serverPort1":"6688",
     *      "serverIp2":"192.168.0.1",
     *      "serverPort2":"6688",
     *      "serverIp3":"192.168.0.1",
     *     "serverPort3":"6688",
     *      "reTryInterval":"10",
     *      "registMsg":"0x12",
     *      "heartBeatData":"0x64",
     *      "rate":"112500",
     *      "parity":"none",
     *      "dataBit":"8",
     *      "stopBit":"1"
     * }
     * response:
     * {
     * }
     */
     setDtu485Cfg: null,
     /**
     * 获取ALG服务信息
     * @property {String} ftpPassThru     FTP ALG开关 0:禁用 1:启用
     * @property {String} ftpprotf        FTP 端口：每一位数值范围都在 1-65535之间,不允许配置相同的端口,两个端口之间用逗号,隔开; 最多配置8个端口号
     * @property {String} l2tpPassThru    L2TP ALG开关 0:禁用 1:启用
     * @property {String} pptpPassThru    PPTP ALG开关 0:禁用 1:启用
     * @property {String} ipsecPassThru   IPSEC ALG开关 0:禁用 1:启用
     * @property {String} h323PassThru    H 323 ALG开关 0:禁用 1:启用
     * @property {String} rtspPassThru    RSTP ALG开关 0:禁用 1:启用
     * @property {String} sipPassThru     SIP ALG开关 0:禁用 1:启用
     * @example
     * request:
     * {
     *      "topicurl":"getAlgServicesCfg"
     * }
     * response:
     * {
     *      "ftpPassThru":"1",
     *      "ftpprotf":"21,15,56,98,552",
     *      "l2tpPassThru":"1",
     *      "pptpPassThru":"1",
     *      "ipsecPassThru":"1",
     *      "h323PassThru":"1",
     *      "rtspPassThru":"1",
     *      "sipPassThru":"1"
     * }
     */
     getAlgServicesCfg: {
      debugUrl: "vpnpass.json"
     },
     /**
     * 配置ALG服务信息
     * @property {String} ftpPassThru     FTP ALG开关 0:禁用 1:启用
     * @property {String} ftpprotf        FTP 端口：每一位数值范围都在 1-65535之间,不允许配置相同的端口,两个端口之间用逗号,隔开; 最多配置8个端口号
     * @property {String} l2tpPassThru    L2TP ALG开关 0:禁用 1:启用
     * @property {String} pptpPassThru    PPTP ALG开关 0:禁用 1:启用
     * @property {String} ipsecPassThru   IPSEC ALG开关 0:禁用 1:启用
     * @property {String} h323PassThru    H 323 ALG开关 0:禁用 1:启用
     * @property {String} rtspPassThru    RSTP ALG开关 0:禁用 1:启用
     * @property {String} sipPassThru     SIP ALG开关 0:禁用 1:启用
     * @example
     * request:
     * {
     *      "topicurl":"setAlgServicesCfg"
     *      "ftpPassThru":"1",
     *      "ftpprotf":"21,15,56,98,552",
     *      "l2tpPassThru":"1",
     *      "pptpPassThru":"1",
     *      "ipsecPassThru":"1",
     *      "h323PassThru":"1",
     *      "rtspPassThru":"1",
     *      "sipPassThru":"1"
     * }
     * response:
     * {
     *    "success": true,
     *    "error":   null,
     *    "lan_ip":  "192.168.0.253",
     *    "wtime":   0,
     *    "reserv":  "reserv"
     * }
     */
     setAlgServicesCfg: null,
     /**
     * 获取安全选项信息
     * @property {String} wanPingFilter    开关 0:禁用 1:启用
     * @example
     * request:
     * {
     *      "topicurl":"getWanPingCfg"
     * }
     * response:
     * {
     *      "wanPingFilter":"1",
     * }
     */
     getWanPingCfg: {
      debugUrl: "vpnpass.json"
     },
     /**
     * 配置安全选项信息
     * @property {String} wanPingFilter     开关 0:禁用 1:启用
     * @example
     * request:
     * {
     *      "topicurl":"setWanPingCfg"
     *      "wanPingFilter":"1",
     * }
     * response:
     * {
     *    "success": true,
     *    "error":   null,
     *    "lan_ip":  "192.168.0.253",
     *    "wtime":   0,
     *    "reserv":  "reserv"
     * }
     */
     setWanPingCfg: null,
     /**
     * 获取策略路由数据
     * @Author Karen
     * @DateTime 2020-06-30
     * @property {String}	ifaceOption	接口选项。之间使用","符号相隔
     * @property {String}	country	支持国家码（未使用到）
     * @property {Array}	rule	规则表
     * @property {String}	idx	ID
     * @property {String}	ip	源IP地址
     * @property {String}	addr	目标网络地址
     * @property {String}	proto	协议。all：ALL，tcp：TCP，udp：UDP
     * @property {String}	portRange	源端口
     * @property {String}	dPortRange	目的端口
     * @property {String}	iface	接口
     * @property {String}	desc	规则名称
     * @property {String}	delRuleName	删除标记（未使用到）
     * @return {object}
     * @example
     * request:
     *
     * {
     * 	"topicurl":"getPolicyRouteCfg"
     * }
     * response:
     * {
     * 	"ifaceOption":"LAN1,WAN1,WAN2",
     * 	"country":"CN,US,EU,OT,IA",
     * 	"rule":[
     * 		{
     * 			"idx":	"0",
     * 			"ip":	"192.168.1.2",
     * 			"addr":	"192.16.11.1",
     * 			"proto":	"all",
     * 			"portRange":"1-65535",
     * 			"dPortRange":"1-65535",
     * 			"iface":	"1",
     * 			"desc":	"1231321",
     * 			"delRuleName":"delRule0"
     * 		}
     * 	]
     * }
     */
    getPolicyRouteCfg: {
      debugUrl: "policy.json"
    },
    /**
     * 设置策略路由数据
     * @Author Karen
     * @DateTime 2020-06-30
     * @param {String}	addEffect	0:开关设置，1：数据设置
     * @param {Array}	subnet	规则表
     * @property {String}	success	应用成功。true：成功，false：失败
     * @property {String}	wtime	需要等待生效的时间
     * @return {object}
     * @example
     * request:
     * {
     * 	  "topicurl":"setStaticRoute",
     *    "addEffect":"1",
     *    "subnet":[]
     * }
     * response:
     * {
     * 			"success": true,
     * 			"wtime": 1
     * }
     */
    setPolicyRouteCfg: null,
    /**
     * 获取IPsec点对网信息
     * @Author Karen
     * @DateTime 2020-06-30
     * @property {String}	ipsecH2nEnable	开关。1：开，0：关
     * @property {String}	ipsecH2nLeftsubnet	本地子网
     * @property {String}	ipsecH2nKeyexchange	IKE版本。ikev、ikev1、ikev2
     * @property {String}	ipsecH2nPsk	预共享密钥
     * @property {String}	ipsecH2nIkeCipher	IKE密码套件
     * @property {String}	ipsecH2nIkelifetime	IKE有效时间(1-86400)
     * @property {String}	ipsecH2nEspCipher	ESP密码套件
     * @property {String}	ipsecH2nDpdaction	DPD检测。0：none，1：restart，2：hold，3：clear
     * @property {String}	ipsecH2nDpddelay	DPD间隔时间(1~60)
     * @property {String}	ipsecH2nDpdtimeout	DPD超时时间(1~300)
     * @property {String}	ipsecH2nLifetime	数据传输SA有效时间
     * @property {String}	ipsecH2nCompress	IP压缩。0：关，1：开
     * @property {String}	ipsecH2nRekey	密钥重新协商。0：关，1：开
     * @return {object}
     * @example
     * request:
     * {
     * 	"topicurl":"getIpsecHost2NetCfg"
     * }
     * response:
     * {
     * 	  	"ipsecH2nEnable":"1",
     * 	  	"ipsecH2nLeftsubnet":"192.168.55.6/24",
     * 	  	"ipsecH2nKeyexchange":"ikev1",
     * 	  	"ipsecH2nPsk":"12345678",
     * 	  	"ipsecH2nIkeCipher":"aes128-sha1-modp2048",
     * 	  	"ipsecH2nIkelifetime":"3600",
     * 	  	"ipsecH2nEspCipher":"aes128-sha1",
     * 	  	"ipsecH2nDpdaction":"1",
     * 	  	"ipsecH2nDpddelay":"10",
     * 	  	"ipsecH2nDpdtimeout":"300",
     * 	  	"ipsecH2nLifetime":"3600",
     * 	  	"ipsecH2nCompress":"0",
     * 		"ipsecH2nRekey":"0"
     * }
     */
    getIpsecHost2NetCfg: {
      debugUrl: "ipsec_host2net.json"
    },
    /**
     * 设置IPsec点对网
     */
    setIpsecHost2NetCfg: null,
    /**
     * 获取IPsec L2TP/Xauth信息
     * @Author Karen
     * @DateTime 2020-06-30
     * @property {String}	ipsecL2tpEnable	L2TP开关。1：开启，0：关闭
     * @property {String}	ipsecXauthEnable	XAuth开关。1：开启，0：关闭
     * @property {String}	ipsecXauthRightsourceip	客户端地址池
     * @property {String}	ipsecL2tpUserPasswdEnable	XAuth使用L2TP用户密码。1：开启，0：关闭
     * @property {String}	ipsecXauthPasswd	通用密码
     * @property {String}	ipsecPsk	预共享密钥
     * @return {object}
     * @example
     * request:
     * {
     * 	"topicurl":"getIpsecL2tpXauthCfg"
     * }
     * response:
     * {
     * 	  "ipsecL2tpEnable":"1",
     * 		"ipsecXauthEnable":"1",
     * 	  "ipsecXauthRightsourceip":"192.168.0.100/32",
     * 		"ipsecL2tpUserPasswdEnable":"1",
     * 	  "ipsecXauthPasswd":"abc12345678",
     * 		"ipsecPsk":"12345678"
     * }
     */
    getIpsecL2tpXauthCfg: {
      debugUrl: "ipsec_l2tpxauth.json"
    },
    /**
     * 设置IPsec L2TP/Xauth
     */
    setIpsecL2tpXauthCfg: null,
    /**
    * 获取IPsec网对网信息
    * @Author Karen
    * @DateTime 2020-06-30
    * @property {String}	ipsecN2nEnable	IPsec开关。1：开，0：关
    * @property {Array}	subnet	规则表
    * @property {String}	idx	ID
    * @property {String}	ipsecName	名称
    * @property {String}	ipsecAuto	主动连接。0：add，1：start，2：route，3：ignore
    * @property {String}	ipsecAggressive	野蛮模式。1：开，0：关
    * @property {String}	ipsecBindIf	本地接口
    * @property {String}	ipsecLeft	本地地址
    * @property {String}	ipsecLeftid	本地身份标识
    * @property {String}	ipsecLeftsubnet	本地子网
    * @property {String}	ipsecRight	远端地址
    * @property {String}	ipsecRightid	远端身份标识
    * @property {String}	ipsecRightsubnet	远端子网
    * @property {String}	ipsecPsk	预共享密钥
    * @property {String}	ipsecKeyexchange	IKE版本。ikev、ikev1、ikev2
    * @property {String}	ipsecIkelifetime	IKE有效时间(1-86400)
    * @property {String}	ipsecIkeCipher	IKE密码套件
    * @property {String}	ipsecEspCipher	ESP密码套件
    * @property {String}	ipsecDpdaction	DPD检测。0：none，1：restart，2：hold，3：clear
    * @property {String}	ipsecDpddelay	DPD间隔时间(1~60)
    * @property {String}	ipsecDpdtimeout	DPD超时时间(1~300)
    * @property {String}	ipsecLifetime	数据传输SA有效时间(1-86400)
    * @property {String}	ipsecCompress	IP压缩。0：关，1：开
    * @property {String}	ipsecRekey	密钥重新协商。0：关，1：开
    * @property {String}	delRuleName	删除标记位（未使用）
    * @return {object}
    * @example
    * request:
    * {
    * 	"topicurl":"getIpsecNet2NetCfg"
    * }
    * response:
    * {
    * 	   "ipsecN2nEnable":"1",
    * 	   "subnet":[
    *         {
    * 	            "idx":"1",
    * 	            "ipsecName":"test1",
    * 	            "ipsecAuto":"0",
    * 	            "ipsecAggressive":"0",
    * 	            "ipsecBindIf":"WAN1",
    * 	            "ipsecLeft":"192.168.39.1",
    * 	            "ipsecLeftid":"",
    * 	            "ipsecLeftsubnet":"192.168.0.253/24",
    * 	            "ipsecRight":"192.168.16.1",
    * 	            "ipsecRightid":"",
    * 	            "ipsecRightsubnet":"192.168.3.1/24",
    * 	            "ipsecPsk":"12346578",
    * 	            "ipsecKeyexchange":"ikev1",
    * 	            "ipsecIkelifetime":"3600",
    * 	            "ipsecIkeCipher":"aes128-sha1-modp2048",
    * 	            "ipsecEspCipher":"aes128-sha1",
    * 	            "ipsecDpdaction":"0",
    * 	            "ipsecDpddelay":"60",
    * 	            "ipsecDpdtimeout":"3600",
    * 	            "ipsecLifetime":"3600",
    * 	            "ipsecCompress":"1",
    * 		          "ipsecRekey":"1",
    * 	            "delRuleName":"delRule0"
    *         }
    *     ]
    *  }
    */
    getIpsecNet2NetCfg: {
      debugUrl: "ipsec_net2net.json"
    },
    /**
     * 设置IPsec网对网
     */
    setIpsecNet2NetCfg: null,
    /**
     * 删除IPsec网对网规则
     */
    delIpsecNet2NetCfg: null,
    /**
     * 取组网配置信息
     * @DateTime 2020-2-3
     *
     * @property {String} enabled  0 关闭 1 开启
     * @property {String} addFlag      主题设置标准，0 添加, 1 修改
     * @property {String} declareWan    宣告WAN 0 关闭 1 开启
     * @property {String} declareLan    宣告LAN 0 关闭 1 开启
     * @property {String} receiveDeclare    接收宣告 0 关闭 1 开启
     * @property {String} defaultRouteNode   默认路由节点
     * @return   {object}
     * @example
     * request:
     * {
     *     "topicurl":"getNetStrategyCfg"
     * }
     * response:
     * {
     *       "lanIp":"192.168.0.1",
     *       "enabled":"1",
     *       "declareWan":"1",
     *       "declareLan":"1",
     *       "receiveDeclare":"1",
     *       "defaultRouteNode":"192.168.0.5",
     *       "rule":[
     *           {
     *               "idx":"1",
     *               "network":"192.168.0.5/24",
     *               "type":"1",
     *               "nexthop":"WAN",
     *               "comment":"abc"
     *           }
     *       ]
     *   }
     */
    getNetStrategyCfg: {
      debugUrl: "net_strategy.json"
    },
    /**
    *  异地组网刷新
    * @param {String}
    * @example
    * request:
    * {
    *    "topicurl":"setUpdateInfoCfg",
    * }
    */
    setUpdateInfoCfg: null,
    /**
    * 设置组网密码
    * @DateTime 2020-2-3
    * @return   {object}
    * @property {String} password   密码
    * @example
    * request:
    * {
    *     "topicurl":"setNetStrategyPwdCfg",
    *     "password":"12345678"
    * }
    */
    setNetStrategyPwdCfg: null,
    /**
    * 删除组网密码
    * @DateTime 2020-2-3
    * @return   {object}
    * @property {String} idx  索引ID
    * @property {String} password   密码
    * @property {String} devId  设备ID
    * @example
    * request:
    * {
    *     "topicurl":"delNetStrategyPwdCfg",
    *     "idx":"1",
    *     "password":"12345678",
    *     "devId":"saddasd"
    * }
    */
    delNetStrategyPwdCfg: null,
    /**
    * 获取组网密码
    * @DateTime 2020-2-3
    * @return   {object}
    * @property {String} idx  索引ID
    * @property {String} password    密码
    * @property {String} devId  设备ID,
    * @example
    * request:
    * {
    *     "topicurl":"getNetStrategyPwdCfg"
    * }
    * [
    *    {"idx":"1","password":"12345678","devId":"asdadqwesadas"},
    *   {"idx":"2","password":"12345679","devId":"asdadqwesa123"}
    * ]
    */
    getNetStrategyPwdCfg: {
      debugUrl: "net_strategy_pwd.json"
    },
    /**
    * 组网重新连接
    * @DateTime 2020-2-26
    * @return   {object}
    * @example
    * request:
    * {
    *     "topicurl":"setNetStrategyReconnect",
    * }
    */
    setNetStrategyReconnect: null,
    /**
    * 获取组网连接状态
    * @DateTime 2020-2-19
    * @return   {object}
    * @property {String} type  组网连接类型 1:P2P  2：中转
    * @property {String} status    0 离线,  1 正在连接   2 网络ID/密码错误  3 组网失败  4已连接  5已连接，有冲突(有子网冲突时已连接变成黄色，鼠标放上去显示冲突信息)
    * @property {String} warning  警告信息，已连接(有子网冲突时已连接变成黄色，鼠标放上去显示：子网冲突: 192.168.0.0/24),
    * @property {String} connectTime  连接时间， 时间戳（可以取到的话，这个可以后台确认返回什么的时间格式，我这边配合修改）
    * @example
    * request:
    * {
    *     "topicurl":"getNetStrategyStatus"
    * }
    * {
    *   "type":"1",
    *   "status":"0",
    *   "warning":"192.168.0.0/24",
    *   "connectTime":"1581989858"
    * }
    */
    getNetStrategyStatus: {
      debugUrl: "net_connect_status.json"
    },
    /**
    * 设置组网配置信息
    * @DateTime 2020-2-3
    *
    * @property {String} enabled  0 关闭 1 开启
    * @property {String} declareWan    宣告WAN 0 关闭 1 开启
    * @property {String} declareLan    宣告LAN 0 关闭 1 开启
    * @property {String} receiveDeclare    接收宣告 0 关闭 1 开启
    * @property {String} defaultRouteNode   默认路由节点
    * @property {Array} subnet   策略路由
    * @return   {object}
    * @example
    * request:
    * {
    *       "topicurl":"setNetStrategyCfg",
    *       "enabled":"1",
    *       "declareWan":"0",
    *       "declareLan":"0",
    *       "receiveDeclare":"0",
    *       "defaultRouteNode":"192.168.0.5",
    *       "subnet":[
    *           {
    *               "idx":"1",
    *               "network":"192.168.0.5/24",
    *               "type":"1",
    *               "nexthop":"WAN",
    *               "comment":"abc"
    *           }
    *       ]
    *   }
    */
    setNetStrategyCfg: null,
    /**
    * 取当前节点信息
    * @DateTime 2020-2-3
    * @return   {object}
    * @property {String} deviceName  设备名称
    * @property {String} netId      网路ID
    * @property {String} deviceId    设备ID
    * @property {String} mac    MAC地址
    * @property {String} ip    IP地址
    * @property {String} status   状态 0：离线 1:在线 2：自己
    * @example
    * request:
    * {
    *     "topicurl":"getClientsInfo"
    * }
    * response:
    *       [
    *           {
    *               "idx":"1",
    *               "deviceName":"abc1",
    *               "netId":"2CD2FF2E65",
    *               "deviceId":"97f1bd689185df4b",
    *               "mac":"F4:28:53:E1:1D:20",
    *               "ip":"10.10.111.12",
    *               "status":"0"
    *           }
    *       ]
    */
    getClientsInfo: {
      debugUrl: "clients.json"
    },
    /**
    * 设置节点设备名称
    * @DateTime 2020-2-3
    * @property {String} deviceName  设备名称
    * @property {String} deviceId    设备ID
    * @return   {object}
    * @example
    * request:
    * {
    *     "topicurl":"setDeviceNameCfg",
    *     "deviceId":"97f1bd689185df4b",
    *     "deviceName":"abc11"
    * }
    */
    setDeviceNameCfg: null,
    /**
     * getIpv6Cfg     获取Ipv6配置
     * @Author   Karen       <Karen@carystudio.com>
     * @DateTime 2019-7-25
     * @property {String} service         连接类型
     * @property {String} remote6in4      6in4 远程端点
     * @property {String} relay6to4       6to4 泛播
     * @property {String} relay6rd        6RD 边缘中继器
     * @property {String} size6rd         6RD IPv4 掩码长度
     * @property {String} sitMtu          隧道 MTU
     * @property {String} sitTtl          隧道 TTL
     * @property {String} wanAddr         外网地址(6RD IPv6 前缀)
     * @property {String} wanSize         外网前缀长度(6RD 前缀长度)
     * @property {String} wanGate         外网默认网关
     * @property {String} wanDhcp         获取 IPv6 外网地址
     * @property {String} wanPriv         启用隐私扩展
     * @property {String} dhcp6rd         通过 DHCPv4 获取所有的 6RD 设置
     * @property {String} dnsAutoFake     自动获取 IPV6 DNS
     * @property {String} dns1            服务器 1
     * @property {String} dns2            服务器 2
     * @property {String} dns3            服务器 3
     * @property {String} lanAutoFake     通过 DHCP 获取内网 IPv6 地址
     * @property {String} lanAddr         内网地址
     * @property {String} lanSize         内网前缀长度
     * @property {String} lanRadvFake     启用 LAN 路由器广播
     * @property {String} lanDhcp         启用 LAN DHCPv6 服务器
     * @property {String} wanType         联网类型
     * @property {String} lanSflt         DHCP 租期 (秒)
     * @property {String} lanSfpsFake1    内网地址池1
     * @property {String} lanSfpsFake2    内网地址池2
     * @example
     * request:
     * {
     *  "topicurl" : "getIpv6Cfg"
     * }
     * response:
     * {
     *   "service":"dhcp6",
     * "remote6in4":"192.168.2.22",
     * "relay6to4":"192.88.99.1",
     * "relay6rd":"192.168.88.1",
     * "size6rd":"0",
     * "sitMtu":"1280",
     * "sitTtl":"64",
     * "wanAddr":"1111:2222:1111:3333:1111:4444:1111:5555",
     * "wanSize":"64",
     * "wanGate":"1111:2222:1111:3333:1111:4444:1111:5555",
     * "wanDhcp":"0",
     * "wanPriv":"0",
     * "dhcp6rd":"1",
     * "dnsAutoFake":"0",
     * "dns1":"1111:2222:1111:3333:1111:4444:1111:5555",
     * "dns2":"",
     * "dns3":"",
     * "lanAutoFake":"1",
     * "lanAddr":"1111:2222:1111:3333:1111:4444:1111:5555",
     * "lanSize":"48",
     * "lanRadvFake":"1",
     * "lanDhcp":"1",
     * "wanType":"",
     * "lanSflt":"1800",
     * "lanSfpsFake1":"1000",
     * "lanSfpsFake2":"1100"
     * }
     */
    getIpv6Cfg: {
      debugUrl: "ipv6Cfg.json"
    },
    /**
     * setIpv6Cfg     设置Ipv6配置
     * @Author   Karen       <Karen@carystudio.com>
     * @DateTime 2019-7-25
     * @param {String} service         连接类型
     * @param {String} remote6in4      6in4 远程端点
     * @param {String} relay6to4       6to4 泛播
     * @param {String} relay6rd        6RD 边缘中继器
     * @param {String} size6rd         6RD IPv4 掩码长度
     * @param {String} sitMtu          隧道 MTU
     * @param {String} sitTtl          隧道 TTL
     * @param {String} wanAddr         外网地址(6RD IPv6 前缀)
     * @param {String} wanSize         外网前缀长度(6RD 前缀长度)
     * @param {String} wanGate         外网默认网关
     * @param {String} wanDhcp         获取 IPv6 外网地址
     * @param {String} wanPriv         启用隐私扩展
     * @param {String} dhcp6rd         通过 DHCPv4 获取所有的 6RD 设置
     * @param {String} dnsAutoFake     自动获取 IPV6 DNS
     * @param {String} dns1            服务器 1
     * @param {String} dns2            服务器 2
     * @param {String} dns3            服务器 3
     * @param {String} lanAutoFake     通过 DHCP 获取内网 IPv6 地址
     * @param {String} lanAddr         内网地址
     * @param {String} lanSize         内网前缀长度
     * @param {String} lanRadvFake     启用 LAN 路由器广播
     * @param {String} lanDhcp         启用 LAN DHCPv6 服务器
     * @param {String} lanSflt         DHCP 租期 (秒)
     * @param {String} lanSfpsFake1    内网地址池1
     * @param {String} lanSfpsFake2    内网地址池2
     * @example
     * request:
     * {
     *  "topicurl" : "setIpv6Cfg"
     *   "service":"dhcp6",
     * "remote6in4":"192.168.2.22",
     * "relay6to4":"192.88.99.1",
     * "relay6rd":"192.168.88.1",
     * "size6rd":"0",
     * "sitMtu":"1280",
     * "sitTtl":"64",
     * "wanAddr":"1111:2222:1111:3333:1111:4444:1111:5555",
     * "wanSize":"64",
     * "wanGate":"1111:2222:1111:3333:1111:4444:1111:5555",
     * "wanDhcp":"0",
     * "wanPriv":"0",
     * "dhcp6rd":"1",
     * "dnsAutoFake":"0",
     * "dns1":"1111:2222:1111:3333:1111:4444:1111:5555",
     * "dns2":"",
     * "dns3":"",
     * "lanAutoFake":"1",
     * "lanAddr":"1111:2222:1111:3333:1111:4444:1111:5555",
     * "lanSize":"48",
     * "lanRadvFake":"1",
     * "lanDhcp":"1",
     * "lanSflt":"1800",
     * "lanSfpsFake1":"1000",
     * "lanSfpsFake2":"1100"
     * }
     * response:
     * {
     *
     * }
     */
    setIpv6Cfg: null,
    /**
     * 获取定时重启配置
     * @Author   Amy       <amy@carystudio.com>
     * @DateTime 2018-06-05
     * @property {String} mode           重启模式。值：0：禁用，1：指定时间，2：倒计时
     * @property {String} week           周
     * @property {String} hour           小时
     * @property {String} minute         分钟
     * @property {String} recHour        倒计时
     * @property {String} NTPValid       启用自动同步
     * @property {String} sysTime        运行时间
     * @property {String} recTime        重启倒计时
     * @example
     * request:
     * {
     *    	"topicurl":"getRebootScheCfg"
     * }
     * response:
     * {
     *   	"mode":"1",
     *   	"week":"255",
     *   	"hour":"12",
     *   	"minute":"45",
     *   	"sysTime":"0;23;28;12",
     *   	"recTime":"0;1;22;12",
     *   	"NTPValid":"1",
     *   	"recHour":"2"
     * }
     */
    getRebootScheCfg: {
      debugUrl: "schedule.json"
    },
    /**
     * 设置定时重启配置
     * @Author   Amy     <amy@carystudio>
     * @DateTime 2018-06-05
     * @param {String} mode           重启模式。值：0：禁用，1：指定时间，2：倒计时
     * @param {String} week           周
     * @param {String} hour           小时
     * @param {String} minute         分钟
     * @param {String} recHour        倒计时
     * @example
     * request:
     * {
     *   	"topicurl":"setRebootScheCfg"
     *   	"mode":"1",
     *   	"week":"255",
     *   	"hour":"12",
     *   	"minute":"45",
     *   	"recHour":"2"
     * }
     * response:
     * {
     *   	"success":true,
     *   	"error":null,
     *   	"lan_ip":"192.168.0.1",
     *   	"wtime":"0",
     *   	"reserv":"reserv"
     * }
     */
    setRebootScheCfg: null,
	/**
	 * 获取IPSec状态
	 * @property {String} ipsecStatusLog  返回需要显示的日志log
	 * request:
	 * {
	 *      "topicurl":"getIpsecStatus"
	 * }
	 * response:
	 * {
	 *      "ipsecStatusLog":"ipsec statusall\nStatus of IKE charon daemon (weakSwan 5.3.5, Linux 3.4.113, mips):\n  uptime: 11 minutes, since Oct 19 15:11:01 2020\n  malloc: sbrk 172032, mmap 0, used 158720, free 13312\n  worker threads: 11 of 16 idle, 5/0/0/0 working, job queue: 0/0/0/0, scheduled: 2\n  loaded plugins: charon aes des rc2 sha1 sha2 md5 random nonce x509 revocation constraints pubkey pkcs1 pkcs7 pkcs8 pkcs12 pgp dnskey sshkey pem openssl fips-prf xcbc cmac hmac attr kernel-netlink resolve socket-default farp stroke updown eap-identity eap-md5 eap-mschapv2 eap-dynamic eap-tls eap-ttls eap-peap xauth-generic xauth-eap xauth-noauth dhcp\nListening IP addresses:\n  192.168.39.14\n  192.168.0.253\n  10.100.100.1\nConnections:\n         bbb:  192.168.39.14...192.168.39.108  IKEv1\n         bbb:   local:  [192.168.39.14] uses pre-shared key authentication\n         bbb:   remote: [192.168.39.108] uses pre-shared key authentication\n         bbb:   child:  192.168.0.0/24 === 192.168.1.0/24 TUNNEL\nSecurity Associations (1 up, 0 connecting):\n         bbb[1]: ESTABLISHED 11 minutes ago, 192.168.39.14[192.168.39.14]...192.168.39.108[192.168.39.108]\n         bbb[1]: IKEv1 SPIs: a17ccf8cbde09800_i* f4f70f68099b97e6_r, pre-shared key reauthentication in 32 minutes\n         bbb[1]: IKE proposal: AES_CBC_128/HMAC_SHA1_96/PRF_HMAC_SHA1/MODP_2048\n         bbb{1}:  INSTALLED, TUNNEL, reqid 1, ESP SPIs: c16dcede_i c43313d7_o\n         bbb{1}:  AES_CBC_128/HMAC_SHA1_96, 0 bytes_i, 0 bytes_o, rekeying in 32 minutes\n         bbb{1}:   192.168.0.0/24 === 192.168.1.0/24\nip route show table 220\n192.168.1.0/24 via 192.168.39.108 dev vlan2  proto static  src 192.168.0.253 "
 	 * }
	 */
	getIpsecStatus: {
      debugUrl: "ipsec_status.json"
    },
	/**
	 * 获取心跳检测配置
	 * @property {String} heartCheckEnable  	开启心跳检测：1：开启  0：关闭
	 * @property {String} heartCheckIp  		检测目标
	 * @property {String} heartCheckTime  	时间间隔 单位为秒，范围10-300
	 * @property {String} debugAction 		下载日志路径
	 * @property {String} debugOption  		日志选项 可以发空值即可
	 * request:
	 * {
	 *      "topicurl":"getIpsecHeartCheckCfg"
	 * }
	 * response:
	 * {
	 *      "heartCheckEnable":"1",
	 *      "heartCheckIp":"192.168.3.33",
	 *      "heartCheckTime":"300",
	 *      "debugAction":"/cgi-bin/cstecgi.cgi?action=exportInfo&type=ipsec",
	 *      "debugOption":"dmn 4, mgr 4, ike 4"
	 * }
	 */
	getIpsecHeartCheckCfg: {
      debugUrl: "ipsec_heartcheck.json"
    },
	/**
	 * 设置心跳检测配置
	 * @property {String} heartCheckEnable  	开启心跳检测：1：开启  0：关闭
	 * @property {String} heartCheckIp  		检测目标
	 * @property {String} heartCheckTime  	时间间隔 单位为秒，范围10-300
	 * @property {String} debugOption  		日志选项 可以发空值即可
	 * request:
	 * {
	 *      "topicurl":"setIpsechHeartCheckCfg",
	 *      "heartCheckEnable":"1",
	 *      "heartCheckIp":"192.168.3.33",
	 *      "heartCheckTime":"300"
	 *      "debugOption":"dmn 4, mgr 4, ike 4",
	 * }
	 * response:
	 * {
	 *    "success":true,
	 *    "error":null,
	 *    "lan_ip":"192.168.0.1",
	 *    "wtime":"0",
	 *    "reserv":"reserv"
	 * }
	 */
	setIpsechHeartCheckCfg: null,

    getIpsecCertCfg: {
          debugUrl: "getIpsecCertCfg.json"
        },
    setIpsecCertCfg: null,

	/**
	 * 获取路由器MQTT连接信息
	 * @Author   Felix       <Felix@carystudio.com>
	 * @DateTime 2020-09-27
	 * @property {String} interval    上传路由器信息间隔，0-720分钟
	 * @example
	 * request:
	 * {
	 *     	"topicurl":"getMqttCfg"
	 * }
	 * response:
	 * {
	 *   	"interval":"30"
	 * }
	 */
	getMqttCfg: {
		debugUrl: "mqtt.json"
	},
	/**
	 * 设置路由器MQTT连接配置
	 * @Author   Felix       <Felix@carystudio.com>
	 * @DateTime 2020-09-27
	 * @param {String} interval    上传路由器信息间隔，0-720分钟
	 *
	 * @property {String} success     响应状态：true：响应成功，false：响应失败
	 * @property {String} error       错误
	 * @property {String} lan_ip      局域网IP
	 * @property {String} wtime       等待时间
	 * @property {String} reserv      返回页面（参数未知）
	 * @return   {object}
	 * @example
	 * request:
	 * {
	 *     "topicurl":"setMqttCfg",
	 *     "interval":"30"
	 * }
	 * response:
	 * {
	 *   "success": true,
	 *   "error":   null,
	 *   "lan_ip":  "192.168.0.5",
	 *   "wtime":   120,
	 *   "reserv":  "reserv"
	 * }
	 */
   setMqttCfg: null,
   /**
     * 获取TF卡配置信息
     * @Author   Felix       <Felix@carystudio.com>
     * @DateTime 2020-09-27
     * @property {String} port    端口
     * @property {String} ip      IP
     * @example
     * request:
     * {
     *      "topicurl":"getMqttCfg"
     * }
     * response:
     * {
     *      "port":"30"，
     *      "ip":"192.168.0.33"
     * }
     */
    getTfCfg: {
        debugUrl: "tf.json"
    },
    /**
     * 设置TF卡配置
     * @Author   Felix       <Felix@carystudio.com>
     * @DateTime 2020-09-27
     * @param {String} port           端口
     * @param {String} port           IP

     * @property {String} success     响应状态：true：响应成功，false：响应失败
     * @property {String} error       错误
     * @property {String} lan_ip      局域网IP
     * @property {String} wtime       等待时间
     * @property {String} reserv      返回页面（参数未知）
     * @return   {object}
     * @example
     * request:
     * {
     *     "topicurl":"setTfCfg",
     *     "port":"30",
    *      "ip":"30"
     * }
     * response:
     * {
     *   "success": true,
     *   "error":   null,
     *   "lan_ip":  "192.168.0.5",
     *   "wtime":   120,
     *   "reserv":  "reserv"
     * }
     */
   setTfCfg: null,
   /**
 * 获取基站扫描列表
 * @Author   Felix       <Felix@carystudio.com>
 * @DateTime 2020-09-30
 * @property {String} rat       接入技术
 * @property {String} arfcn     频点(ARFCN)
 * @property {String} pci       物理ID(PCI)
 * @example
 * request:
 * {
 *      "topicurl":"getCellInfo"
 * }
 * response:
 * [
 *      {
 *          "rat":  "LTE",
 *          "arfcn":    "180",
 *          "pci":  "31"
 *      }, {
 *          "rat":  "NR",
 *          "arfcn":    "176",
 *          "pci":  "23"
 *      }
 * ]
 */
getCellInfo: {
    debugUrl: "cellinfo.json"
},


/**
 * 获取tr069配置
 * @property {String} enable     tr069使能 0:关闭tr069  1:开启tr069
 * @property {String} acsUrl    URL地址
 * @property {String} acsUsername     账户
 * @property {String} acsPassword     密码
 * @property {String} periodicEnable    心跳通知
 * @property {String} periodicInterval  心跳通知时间(s)
 * @property {String} cpeUsername     账户
 * @property {String} cpePassword     密码
 * @property {String} port      端口
 * request:
 * {
 *      "topicurl" :"getCwmpdCfg"
 * }
 * response:
 * {
 *     "enable": "0",
 *     "acsUrl": "https://192.168.7.51:8443/nariacs/acs",
 *     "acsUsername": "cwmp",
 *     "acsPassword": "cwmp",
 *     "periodicEnable": "1",
 *     "periodicInterval": "120",
 *     "cpeUsername": "admin",
 *     "cpePassword": "admin",
 *     "port": "1008"
 * }
 */
 getCwmpdCfg: {
  debugUrl: "cwmpdCfg.json"
},


/**
 * 设置tr069配置
 * @property {String} enable     tr069使能 0:关闭tr069  1:开启tr069
 * @property {String} acsUrl    URL地址
 * @property {String} acsUsername     账户
 * @property {String} acsPassword     密码
 * @property {String} periodicEnable    心跳通知
 * @property {String} periodicInterval  心跳通知时间(s)
 * @property {String} cpeUsername     账户
 * @property {String} cpePassword     密码
 * @property {String} port      端口
 * @example
 * request:
 * {
 * 	"topicurl":"setCwmpdCfg",
 *     "enable": "1",
 *     "acsUrl": "https://192.168.7.51:8443/nariacs/acs",
 *     "acsUsername": "cwmp",
 *     "acsPassword": "cwmp",
 *     "periodicEnable": "1",
 *     "periodicInterval": "120",
 *     "cpeUsername": "admin",
 *     "cpePassword": "admin",
 *     "port": "1008"
 * }
 * response:
 * {
 *    "success":"true",
 *    "error": null,
 *    "lan_ip":"192.168.0.1",
 *    "wtime":"10",
 *    "reserv":"reserv"
 * }
 */
 setCwmpdCfg: null,


/**
 * 保存锁定基站设置参数
 * @Author   Felix       <Felix@carystudio.com>
 * @DateTime 2020-09-30
 * @param {String} arfcn        频点(ARFCN)
 * @param {String} pci          物理ID(PCI)
 * @example
 * request:
 * {
 *    "topicurl":"lockCell"
 *    "arfcn":"180",
 *    "pci":"31"
 * }
 * response:
 * {
 *    "success":true,
 *    "error":null,
 *    "lan_ip":"192.168.0.1",
 *    "wtime":"0",
 *    "reserv":"reserv"
 * }
 */
lockCell: null,
/**
* 基站解绑
* request:
* {
*      "topicurl":"unLockCell",
* }
* response:
* {
*    "success":true,
*    "error":null,
*    "lan_ip":"192.168.0.1",
*    "wtime":"0",
*    "reserv":"reserv"
* }
*/
unLockCell: null,
   /**
   * 获取Mac认证配置
   * @property {String} authMode    		认证模式。0：禁用，1：白名单，2：黑名单
   * @property {String} rule       	添加的认证规则
   * @example
   * request:
   * {
   *    	"wifiIdx":"0",
   *    	"topicurl":"getWiFiAclAddCfg"
   * }
   * response:
   * {
   *   	"authMode":2,
   *   	"rule":[{"F4:28:56:34:51:44","desc":"111"}]
   * }
   */
    getWiFiAclRules: {
      debugUrl: "acl.json"
    },
   /**
  * 设置Mac认证规则
  * @param {String} authMode    		认证模式。0：禁用，1：白名单，2：黑名单
  * @param {String} addEffect       	添加的状态
  * @example
  * request:
  * {
  *   	"authMode":"2",
  *   	"addEffect":"1",
  *   	"subnet":[]
  * }
  * response:
  * {
  *   	"success":true,
  *   	"error":null,
  *   	"lan_ip":"192.168.0.1",
  *   	"wtime":"0",
  *   	"reserv":"reserv"
  * }
  */
  setWiFiAclRules: null,
  /**
   * 获取系统模式配置
   * @property {String} operationMode         系统模式, 0:桥, 1:网关, 2:中继, 3:WISP
   * @example
   * request:
   * {
   *    "topicurl":"getOpMode"
   * }
   * response:
   * {
   *    "operationMode":"1"
   * }
   */
  getOpMode: {
    debugUrl: "opmode.json"
  },
  /**
   * Debug配置获取
   * @property {String} debugMode       debug模式, 0:关闭 1:日志保存本地 2:日志上报服务器 3:日志保存本地和上报服务器
   * @property {String} lteDial         LTE拨号日志, 0：禁用，1：启用
   * @property {String} lteRsrp         LTERSRP日志, 0：禁用，1：启用
   * @property {String} lteCsq         LTECSQ日志, 0：禁用，1：启用
   * @property {String} lteCheck         LTE检测日志, 0：禁用，1：启用
   * @property {String} wanDial         WAN上下线日志, 0：禁用，1：启用
   * @example
   * request:
   * {
   *      "topicurl":"getDebugLog"
   * }
   * response:
   * {
   *     "debugMode":"1",
   *     "lteDial":"1",
   *     "lteRsrp":"0",
   *     "lteCsq":"1",
   *     "lteRsrp":"0",
   *     "wanDial":"1"
   * }
   */
getDebugLog: {
  debugUrl: "debug.json"
},

/**
 * Debug配置
 * @Author   Bob       <Bob_huang@carystudio.com>
 * @DateTime 2017-11-06
 * @param {String} debugMode        debug模式, 0:关闭 1:日志保存本地 2:日志上报服务器 3:日志保存本地和上报服务器
 * @param {String} lteDial          LTE拨号日志, 0：禁用，1：启用
 * @param {String} lteRsrp          LTERSRP日志, 0：禁用，1：启用
 * @param {String} lteCsq           LTECSQ日志, 0：禁用，1：启用
 * @param {String} lteCheck         LTE检测日志, 0：禁用，1：启用
 * @param {String} wanDial          WAN上下线日志, 0：禁用，1：启用
 * @example
 * request:
 * {
 *       "topicurl":"setVpnPassCfg",
 *       "debugMode":"1",
 *       "lteDial":"1",
 *       "lteRsrp":"0",
 *       "lteRsrp":"0",
 *       "wanDial":"1"
 * }
 */
setDebugLog: null,
  /**
  * 设置系统模式
  * @param {String} operationMode        系统模式, 0：桥，1：网关，2：中继，3：WISP
  * @example
  * request:
  * {
  *    "topicurl":"setOpMode"
  *    "operationMode":"0",
  * }
  * response:
  * {
  *    "success":true,
  *    "error":null,
  *    "lan_ip":"192.168.0.1",
  *    "wtime":"0",
  *    "reserv":"reserv"
  * }
  */
  setOpMode: null,
  /**
   * 获取FOTA配置
   * @property {String} status   fota升级状态：
   * @property {String} url      fota升级固件下载地址，默认：http://carystudio.f3322.net:6666/firm/，页面显示成例如
   * @property {String} modemVersion     模组当前版本
   * @example
   * request:
   * {
   *      "topicurl":"getFotaCfg"
   * }
   * response:
   * {
   *      "status": "fota_update_fail",
   *      "url": "http://carystudio.f3322.net:6666/firm/",
   *      "modemVersion": "11.821.00.04.00"
   * }
   */
  getFotaCfg: {
    debugUrl: "fota.json"
  },
  /*
  * 设置FOTA配置
  * @property {String} url        fota升级固件下载地址，默认：http://carystudio.f3322.net:6666/firm/，页面显示成例如
  * @property {String} fotaStart   开始fota升级
  * @example
  * request:
  * {
  *      "topicurl":"setFotaCfg",
  * }
  * response:
  * {
  *      "url":"http://carystudio.f3322.net:6666/firm/",
  *      "fotaStart":"1"
  * }
  */
  setFotaCfg: null,
  /**
 * 设置VPDN配置
 * @param {String} addEffect        功能总开关,页面暂时不需要显示，默认下发1就行
 * @param {String} type             拨号类型 0:pptp  1:l2tp
 * @param {String} enable           规则开关 0:禁用  1:启用
 * @param {String} serverIp         服务器IP地址
 * @param {String} user             用户名
 * @param {String} pass             密码
 * @param {String} default          默认路由 0:禁用  1:启用
 * @param {String} mppe             MPPE数据加密 0:可选加密  1:不加密  2:需要加密
 * @param {String} dmzIp            虚拟IP映射
 * @param {String} ipMasq           源地址伪装  0:关闭  1:开启
 * @param {String} lanMasq          LAN子网伪装 0:关闭  1:开启
 * @param {String} net              自定义路由ip
 * @param {String} mask             自定义路由子网
 * @example
 * request:
 * {
 *      "topicurl":"setVpnMultiClientCfg",
 *      "addEffect":"1",
 *      "subnet":[{
 *          "type":"0",
 *          "enable":"1",
 *          "serverIp":"192.168.39.4",
 *          "user":"pptp",
 *          "pass":"pptp",
 *          "default":"0",
 *          "mppe":"0",
 *          "dmzIp":"192.168.1.2",
 *          "ipMasq":"0",
 *          "lanMasq":"0",
 *          "netMask":[{
 *              "net":"192.168.33.0",
 *              "mask":"255.255.255.0"
 *          },
 *          {
 *              "net":"192.168.44.0",
 *              "mask":"255.255.255.0"
 *          }]
 *    },
 *    {
 *          "type":"1",
 *          "enable":"1",
 *          "serverIp":"192.168.39.4",
 *          "user":"l2tp",
 *          "pass":"l2tp",
 *          "default":"0",
 *          "dmzIp":"192.168.1.3",
 *          "ipMasq":"0",
 *          "lanMasq":"0",
 *          "netMask":[{
 *              "net":"192.168.55.0",
 *              "mask":"255.255.255.0"
 *          },
 *          {
 *              "net":"192.168.66.0",
 *              "mask":"255.255.255.0"
 *          }]
 *    }]
 * }
 * response:
 * {
 *    "success":true,
 *    "error":null,
 *    "lan_ip":"192.168.0.1",
 *    "wtime":0,
 *    "reserv":"reserv"
 * }
 */
setVpnMultiClientCfg: null,
/**
 * 获取VPDN配置
 * @param {String} addEffect        功能总开关,页面暂时不需要显示，默认下发1就行
 * @param {String} type             拨号类型 0:pptp  1:l2tp
 * @param {String} enable           规则开关 0:禁用  1:启用
 * @param {String} serverIp         服务器IP地址
 * @param {String} user             用户名
 * @param {String} user             用户名
 * @param {String} pass             密码
 * @param {String} default          默认路由 0:禁用  1:启用
 * @param {String} mppe             MPPE数据加密 0:可选加密  1:不加密  2:需要加密
 * @param {String} dmzIp            虚拟IP映射
 * @param {String} ipMasq           源地址伪装  0:关闭  1:开启
 * @param {String} lanMasq          LAN子网伪装 0:关闭  1:开启
 * @param {String} net              自定义路由ip
 * @param {String} mask             自定义路由子网
 * @param {String} addr             IP地址
 * @example
 * request:
 * {
 *      "topicurl":"getVpnMultiClientCfg"
 * }
 * response:
 * {
 *      "addEffect":"1"
 *      "subnet":[{
 *          "type":"0",
 *          "enable":"1",
 *          "serverIp":"192.168.39.4",
 *          "user":"pptp",
            "state":"1",
 *          "pass":"pptp",
 *          "default":"0",
 *          "mppe":"0",
 *          "dmzIp":"192.168.1.2",
 *          "ipMasq":"0",
 *          "lanMasq":"0",
 *          "addr":"10.8.0.1",
 *          "netMask":[{
 *              "net":"192.168.33.0",
 *              "mask":"255.255.255.0"
 *          },
 *          {
 *              "net":"192.168.44.0",
 *              "mask":"255.255.255.0"
 *          }]
 *    },
 *    {
 *          "type":"1",
 *          "enable":"1",
 *          "serverIp":"192.168.39.4",
 *          "user":"l2tp",
 *          "state":"0",
 *          "pass":"l2tp",
 *          "default":"0",
 *          "dmzIp":"192.168.1.3",
 *          "ipMasq":"0",
 *          "lanMasq":"0",
 *          "addr":"10.8.1.1",
 *          "netMask":[{
 *              "net":"192.168.55.0",
 *              "mask":"255.255.255.0"
 *          },
 *          {
 *              "net":"192.168.66.0",
 *              "mask":"255.255.255.0"
 *          }]
 *    }]
 * }
 */
getVpnMultiClientCfg:{
   debugUrl: "vpncli.json"
},
  /**
   * 获取端口镜像配置
   * @property {String} mirrorPortEnable 端口监控开关 0:关闭 1:开启
   * @property {String} lanPort 页面显示可配置的端口 LAN1,LAN2,LAN3
   * @property {String} mirrorMode  模式 1:输出监控 2:输入监控 3:输入输出监控
   * @property {String} monitorDestinatPort 监控端口(只能选择其中一个LAN口) LAN1
   * @property {String} monitorSourcePort	被监控端口 LAN2,LAN3
   *
   * @example
   * request:
   * {
   *      "topicurl" :"getMirrorPort"
   * }
   * response:
   * {
   *     "lanPort": "LAN1,LAN2,LAN3",
   *     "mirrorPortEnable": "1",
   *     "mirrorMode": "1",
   *     "monitorDestinatPort": "LAN1",
   *     "monitorSourcePort": "LAN2,LAN3"
   * }
   */
  getMirrorPort: {
    debugUrl: "mirror.json"
  },
    /**
   * 获取端口镜像配置
   * @property {String} connStatus iot连接状态
   *
   * @example
   * request:
   * {
   *      "topicurl" :"getIotStateCfg"
   * }
   * response:
   * {
   *     "connStatus": "Device bind"
   * }
   */
  getIotStateCfg: {
    debugUrl: "iotSta.json"
  },
  /**
   * 获取端口镜像配置
   * @property {String} connStatus iot连接状态
   *
   * @example
   * request:
   * {
   *      "topicurl" :"getIotMStateCfg"
   * }
   * response:
   * {
   *     "connStatus": "Device bind"
   * }
   */
  getIotMStateCfg: {
    debugUrl: "iotSta.json"
  },
  getAIotMStateCfg: {
    debugUrl: "iotSta.json"
  },

  /**
   * 设置端口镜像配置
   * @property {String} mirrorPortEnable 端口监控开关 0:关闭 1:开启
   * @property {String} lanPort 页面显示可配置的端口 LAN1,LAN2,LAN3
   * @property {String} mirrorMode  模式 1:输出监控 2:输入监控 3:输入输出监控
   * @property {String} monitorDestinatPort 监控端口(只能选择其中一个LAN口) LAN1
   * @property {String} monitorSourcePort	被监控端口 LAN2,LAN3
   * @example
   * request:
   * {
   *     "topicurl":"setMirrorPort",
   *     "mirrorPortEnable":"1",
   * 	    "mirrorMode":"3",
   * 	    "monitorDestinatPort":"LAN1",
   * 	    "monitorSourcePort":"LAN2,LAN3"
   * }
   * response:
   * {
   *    "success":"true",
   *    "error": null,
   *    "lan_ip":"192.168.0.1",
   *    "wtime":"10",
   *    "reserv":"reserv"
   * }
   */
  setMirrorPort: null,
  /**
   * 获取抓包分析
   * @property {String} enable 抓包分析开关 0:关闭 1:开启
   * @property {String} iface 接口 modem、wan、lan、wifi2.4，如支持5G，可选项加上wifi5
   * @property {String} fileSize 文件大小（30-1024KB）
   *
   * @example
   * request:
   * {
   *      "topicurl" :"getTcpdumpPackCfg"
   * }
   * response:
   * {
   *     "enable":"1",
   *     "iface":"LAN",
   *     "fileSize":"50"
   * }
   */
    getTcpdumpPackCfg: {
        debugUrl: "package.json"
    },
    /**
   * 获取抓包状态
   * @property {String} status 抓包状态 start：开始抓包，ing：正在抓包， end：抓包完成， ifaceError：接口尚未准备好
   *
   * @example
   * request:
   * {
   *      "topicurl" :"getTcpdumpPackStatus"
   * }
   * response:
   * {
   *     "status": "end"
   * }
   */
    getTcpdumpPackStatus: {
        debugUrl: "packageStatus.json"
    },
  /**
   * 设置抓包分析
   * @param {String} enable 抓包分析开关 0:关闭 1:开启
   * @param {String} iface 接口 modem、wan、lan、wifi2.4，如支持5G，可选项加上wifi5
   * @param {String} fileSize 文件大小（30-1024KB）
   * @example
   * request:
   * {
   *     "topicurl":"setTcpdumpPackCfg",
   *     "enable":"1",
   *     "iface":"LAN",
   *     "fileSize":"50"
   * }
   * response:
   * {
   *    "success":"true",
   *    "error": null,
   *    "lan_ip":"192.168.0.1",
   *    "wtime":"10",
   *    "reserv":"reserv"
   * }
   */
  setTcpdumpPackCfg: null,

/**
 * 获取静态DHCP列表
 * @Author   Carystudio
 * @DateTime 2019-9-23
 * @property {String} enable      静态DHCP开关, 1:开启, 0:关闭
 * @property {Array}  rule        端口转发规则
 * @property {String} mac         规则: MAC地址
 * @property {String} ip          规则: IP地址
 * @example
 * request:
 * {
 *     "topicurl":"getStaticDhcpRules",
 * }
 * response:
 * {
 *     "enable":"1",
 *     "rule":[
 *        {
 *          "ip":"192.168.0.3",
 *          "mac":"00:e0:4c:81:96:71"
 *        },
 *      ]
 * }
 */
getStaticDhcpRules: {
    debugUrl: "staticdhcp.json"
},

  /**
 * 设置静态DHCP规则
 * @Author   Carystudio
 * @DateTime 2019-9-23
 * @param {String} addEffect    辅助, 0:无操作，1:添加, 2:修改，3：arp状态
 * @param {String} mac          规则: MAC地址
 * @param {String} ip           规则: IP地址
 * @param {String} rule
 * @example
 * request:
 * {
 *    "topicurl":"setStaticDhcpRules",
 *    "addEffect":0,
 *    "mac":"",
 *    "ip":""
 * }
 * response:
 * {
 *    "success":true,
 *    "error":null,
 *    "lan_ip":"192.168.0.1",
 *    "wtime":0,
 *    "reserv":"reserv"
 * }
 */
setStaticDhcpRules : null,

/**
 * 获取第三方系统连接配置
 * @Author   vinson       <vinson@carystudio.com>
 * @DateTime 2021-11-03
 * @property {String} serverHost   服务器地址
 * @property {String} statName   站所名称
 * @property {String} businessName   业务名称 业务类型选项修改如下：1）配电自动化-DTU  2）配电自动化-FTU    3）TUU业务   4）用采业务  5）智辅业务
 * @property {String} businessIP     业务IP
 * @property {String} signal         信号强度
 * @property {String} sinr           信噪比
 * @property {String} latitude_longitude  经纬度
 * @property {String} date          获取时间(后台返回时间戳)
 * @property {String} autoUpdate      是否开启自动上报 1:开启自动上报 0:关闭自动上报
 * @property {String} autoUpdateTime   自动上报时间间隔(单位分钟)
 * request:
 * {
 *      "topicurl" :"getThirdSystem"
 * }
 * response:
 * {
 *      "serverHost": "http://60.205.148.140:802/api/MapApi",
 *      "statName": "Test",
 *      "businessName": "aaa",
 *      "businessIP": "10.8.0.3",
 *      "signal": "-99",
 *      "sinr": "30",
 *      "latitude_longitude": "23.11,112.23",
 *      "date": "1635771443",
 *      "autoUpdate": "1",
 *      "autoUpdateTime": "30"
 * }
 */
 getThirdSystem: {
  debugUrl: "thirdSystem.json"
},

/**
 * 模组升级配置
 * @return   {object}
 * @example
 * response:
 *   {
 *		"enable":"1",
 *		"ip":"192.168.0.2",
 *		"moduleVer":"EC25EFAR06A08M4G"
 *	}
 */
getModuleUpgradeCfg :{
  debugUrl:"module_upgrade.json"
},

getLoginCfg :{
  debugUrl:"login.json"
},

loginAuth: null,
/**
* 设置模组升级配置
*/
setModuleUpgradeCfg: null,
/**
* 获取模组升级状态
* @property {String} status   file_error：升级文件错误,upgrade_error： 升级失败,upgrade_success：升级成功,upgrade_underway：升级中
* @return   {object}
* @example
* response:
*   {
*		"status":"upgrade_success"
*	}
*/
getModuleUpgradeStatus :{
  debugUrl:"module_upgrade.json"
},
/**
 * 获取第三方系统连接状态信息
 * @Author   vinson       <vinson@carystudio.com>
 * @DateTime 2021-11-03
 * @property {String} result  上报状态信息 0:未上报  1:上报中 2:上报失败 3:上报成功
 *
 * @example
 * request:
 * {
 *      "topicurl" :"getThirdUpdateState"
 * }
 * response:
 * {
 *      "result": "3"
 * }
 */
 getThirdUpdateState: {
  debugUrl: "thirdUpdate.json"
},
/**
 * 设置第三方系统连接配置
 * @Author   vinson       <vinson@carystudio.com>
 * @DateTime 2021-11-03
 * @property {String} serverHost         	服务器地址
 * @property {String} statName            	站所名称
 * @property {String} businessName         业务名称 业务类型选项修改如下：1）配电自动化-DTU  2）配电自动化-FTU    3）TUU业务   4）用采业务  5）智辅业务
 * @property {String} businessIP           业务IP
 * @property {String} signal         信号强度
 * @property {String} sinr           信噪比
 * @property {String} latitude_longitude   经纬度
 * @property {String} date           		获取时间(后台返回时间戳)
 * @property {String} autoUpdate         	是否开启自动上报 1:开启自动上报 0:关闭自动上报
 * @property {String} autoUpdateTime       自动上报时间间隔(单位分钟)
 * @example
 * request:
 * {
 *    "topicurl":"setThirdSystem",
 *    "serverHost":"http://60.205.148.140:802/api/MapApi",
 *    "statName":"test",
 *    "businessName":"ss",
 *    "businessIP":"192.168.1.1",
 *    "signal": "-99",
 *    "sinr": "30",
 *    "latitude_longitude":"23.11,112.23,
 *    "date":"16698544",
 *    "autoUpdate":"1",
 *    "autoUpdateTime":"30"
 * }
 * response:
 * {
 *    "success":"true",
 *    "error": null,
 *    "lan_ip":"192.168.0.1",
 *    "wtime":"10",
 *    "reserv":"reserv"
 * }
  */
 setThirdSystem : null,
 /**
 * 获取第三方系统连接状态信息
 * @Author   vinson       <vinson@carystudio.com>
 * @DateTime 2021-11-03
 * @property {String} result  上报状态信息 0:未上报  1:上报中 2:上报失败 3:上报成功
 *
 * @example
 * request:
 * {
 *      "topicurl" :"getDigest"
 * }
 * response:
 * {
 *      "result": "3"
 * }
 */
 getDigest: {
  debugUrl: "digest.json"
},
/**
 * 设置第三方系统连接配置
 * @Author   vinson       <vinson@carystudio.com>
 * @DateTime 2021-11-03
 * @property {String} serverHost            服务器地址
 * @property {String} statName              站所名称
 * @property {String} businessName         业务名称 业务类型选项修改如下：1）配电自动化-DTU  2）配电自动化-FTU    3）TUU业务   4）用采业务  5）智辅业务
 * @property {String} businessIP           业务IP
 * @property {String} signal         信号强度
 * @property {String} sinr           信噪比
 * @property {String} latitude_longitude   经纬度
 * @property {String} date                  获取时间(后台返回时间戳)
 * @property {String} autoUpdate            是否开启自动上报 1:开启自动上报 0:关闭自动上报
 * @property {String} autoUpdateTime       自动上报时间间隔(单位分钟)
 * @example
 * request:
 * {
 *    "topicurl":"setThirdSystem",
 *    "serverHost":"http://60.205.148.140:802/api/MapApi",
 *    "statName":"test",
 *    "businessName":"ss",
 *    "businessIP":"192.168.1.1",
 *    "signal": "-99",
 *    "sinr": "30",
 *    "latitude_longitude":"23.11,112.23,
 *    "date":"16698544",
 *    "autoUpdate":"1",
 *    "autoUpdateTime":"30"
 * }
 * response:
 * {
 *    "success":"true",
 *    "error": null,
 *    "lan_ip":"192.168.0.1",
 *    "wtime":"10",
 *    "reserv":"reserv"
 * }
  */
 setDigest : null,
 setApnCfg : null,

/**
 * 获取小区信息
 * @property {String} currentCell          0:关闭 1:开启
 * @example
 * request:
 * {
*     "topicurl":"getCurrentCell",
*  }
 * response:
 * {
 *      "currentCell":"1"
 * }
 */
getCurrentCell: {
    debugUrl: "cell.json"
},

/**
 * 获取小区信息
 * @property {String} currentCell          0:关闭 1:开启
 * @example
 * request:
 * {
*     "topicurl":"getCurrentCell",
*  }
 * response:
 * {
 *      "currentCell":"1"
 * }
 */

setSslVpnCertCfg: null,
getSslVpnCfg:{
    debugUrl: "sslvpn.json"
},

getSslVpnCertStatus:{
    debugUrl: "sslvpn_status.json"
},

setSslVpnLoad: null,
setSslVpnTunCfg: null,

getSslVpnTunCfg:{
    debugUrl: "tunnel.json"
},

setSubOnOff: null,

getVxlanCfg: {
  debugUrl: "vxlan.json"
},
/**
 * vxlan配置
 * @Author   dana       <dana@carystudio.com>
 * @DateTime 2020-03-28
 * @param {String} interface    接口类型
 * @param {String} vid          标识符
 * @param {String} peer_ip      远端ip
 * @param {String} peer_prot    远端端口
 * @param {String} source_ip    源端ip
 * @example
 * request:
 *{
 *      interface: "wan"
 *      vid: "100"
 *      peer_ip: "192.168.1.1"
 *      peer_prot: "4785"
 *      source_ip: "192.168.1.1"
 * }
 */
setVxlanCfg: null,

getWireguardCfg:{
    debugUrl: "getWireguardCfg.json"
},
getWireguardKey:{
  debugUrl: "getWireguardKey.json"
},
getPreshareKey:{
  debugUrl: "getPreshareKey.json"
},
setWireguardCfg: null,
setWireguardPeerCfg: null,
setWireguardSwitch: null,


getL2tpClientCfg:{
  debugUrl: "getL2tpClientCfg.json"
},
getL2tpServerCfg:{
  debugUrl: "getL2tpServerCfg.json"
},
setL2tpClientCfg: null,
setL2tpServerCfg: null,
setL2tpSimplifyCfg: null,

getPptpClientCfg:{
  debugUrl: "getPptpClientCfg.json"
},
setPptpClientCfg: null,
setSLBModeCfg: null,
setSLBDongleCfg:null,
setSLBAPCfg:null,
setSLBAPstop:null
};

for (var topicurl in uiPost.prototype) {
    uiPost.prototype[topicurl] = uipostMethods(topicurl, uiPost.prototype[topicurl]);
}

obj.uiPost = new uiPost();
})(window);
