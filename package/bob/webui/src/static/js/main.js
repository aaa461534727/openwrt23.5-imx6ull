
function getUserBrowser(){
    var u = navigator.userAgent;
    if (u.indexOf('Mobile') > -1)
        return "mobile";
    else if (u.indexOf('Android') > -1 || u.indexOf('Linux') > -1)
        return "mobile";
    else if (u.indexOf('iPhone') > -1 || u.indexOf('iPod') > -1 || u.indexOf('iPad') > -1)
        return "mobile";
    else
        return "pc";
}

function set_obj_value(data, key, keys, callback) {
    if (data) {
        if (keys instanceof Function) callback = keys;
        if (typeof key === 'object') {
            keys = key;
            key = null;
        }
        if (!(keys instanceof Array)) keys = Object.keys(keys);
        if (key && data[key]) data = data[key];
        var k = 0;
        while (k < keys.length) {
            var _ = keys[k++];
            if (data[_] != undefined) {
                callback(_, data[_]);
            }
        }
    }
}

(function(obj) {
    function opnsenseInit(){
        try{
            var main = new Vue({
                el: '#app',
                template:'\
                    <div :class="useStyle">\
                        <opnsense-header v-if="globalConfig.showHead"></opnsense-header>\
                        <main class="page-content col-sm-9 col-sm-push-3 col-lg-10 col-lg-push-2" v-if="globalConfig.showMenu">\
                            <opnsense-menu></opnsense-menu>\
                            <div class="row">\
                                <opnsense-breadcrumb ></opnsense-breadcrumb>\
                                <section class="page-content-main">\
                                    <div class="container-fluid">\
                                        <opnsense-main></opnsense-main>\
                                    </div>\
                                    </section>\
                                <opnsense-footer></opnsense-footer>\
                           </div>\
                       </main>\
                       <div class="page-content col-sm-12" :style="wifidogStyle" v-else>\
                        <opnsense-main></opnsense-main>\
                       </div>\
                    </div>\
                    ',
                lang: $.lang,
                lang_t: lang_t,
                data:{
                    globalConfig:globalConfig,
                    wifidogStyle: {},
                    useStyle: ''
                },
                created:function(){
                    var _this = this;
                    if (globalConfig.c735irSupport) {
                        this.useStyle = "app-style-1";
                    }else if(globalConfig.uiStyle =='green'){
                        this.useStyle = "app-style-green";
                    }else if(globalConfig.uiStyle =='green_382c'){
                        this.useStyle = "app-style-green-382c";
                    }else if(globalConfig.uiStyle =='blue'){
                        this.useStyle = "app-style-blue";
                    }

                    if(location.pathname == '/wifidogauth/auth.html'){
                        globalConfig.showHead = false;
                        this.wifidogStyle = {'padding-top':0};
                    }
                },
                mounted:function(){

                },
                components:{
                    'opnsense-main':cs_main
                }
            });
            return main;
        }catch(e){
            location.href = '/error.html';
            console.error('请检查好框架代码',e);
        }
    }

    if(location.pathname == '/login.html' || location.pathname == '/login_4g.html' || location.pathname == '/login_5g.html' || location.pathname == '/active.html' || location.pathname == '/telnet.html' || location.pathname == '/changelogin.html' || location.pathname == '/wifidogauth/auth.html'|| location.pathname == '/module_upgrade.html'){
        globalConfig.showMenu = false;
        globalConfig.showBreadcrumb = false;
        globalConfig.deviceManageSupport = false;
    }
    var applang=(navigator.language||navigator.browserLanguage||navigator.userLanguage||navigator.systemLanguage).toLowerCase();
    var lang = localStorage.getItem('lang') || globalConfig.defaultLang;
 //   language.switch(lang);

    var autoFun = function(autolang){
        if(autolang == "ct"){
            languages.auto = "自動檢測";
        }else if(autolang == "cn"){
            languages.auto = "自动检测";
        }else if(autolang == "jp"){
            languages.auto = "自動検出";
        }else if(autolang == "ru"){
            languages.auto = "автоматическое";
        }else if(autolang == "th"){
            languages.auto = "ตรวจจับโดยอัตโนมัติ";
        }else{
            languages.auto = "Auto";
        }
    };
    autoFun(lang);

    /*页面标题logo定制*/
    try {
        var logoUrl = '/style/favicon.ico';
        var img = new Image();
        img.src = logoUrl;
        img.onload = function() {
            var linkTag = $('<link rel="shortcut icon" href="' + logoUrl +'" />');
            $($('head')[0]).append(linkTag);
        }
    } catch(e) {}

    if(getUserBrowser() == 'mobile')
        globalConfig.isPhoneDevice = true;

    uiPost.getInitConfig(function(data){
        if(data.webTitle) globalConfig.customTitle = data.webTitle;
        document.title = globalConfig.customTitle;

        if(data.cs) globalConfig.customCompany = data.cs;
        globalConfig.neutralVersion = data.neutralVersion != undefined ? data.neutralVersion : "1";

        if(data.showHelp == '1') globalConfig.customHelp = true;
        if(data.showGwlink == '1') globalConfig.showGwlink = true;
        if(data.showGwlink2 == '1') globalConfig.showGwlink2 = true;

        globalConfig.wifiSupport = data.wifiSupport == "1";
        globalConfig.wifiSupport5gOnly = data.wifiSupport5gOnly == "1";
        globalConfig.activation = data.activation == "1";
		globalConfig.wifi11axSupport = data.wifi11axSupport == "1";
        globalConfig.urlNetPage =data.url_net_page;
        globalConfig.specialIotBanApply = data.specialIotBanApply == "1";

        if(data.csid == "C7D3B8E"){
            globalConfig.isclientsetSupport = true;
        }else{
            globalConfig.isclientsetSupport = false;
        }
        if(data.custom.wiredWanSupport=="1" || data.custom.wiredWanSupport==undefined){
            globalConfig.wiredWanSupport = true;
        }else if(data.csid == "C7335R"){
            globalConfig.wiredWanSupport = false;
        }else{
            globalConfig.wiredWanSupport = false;
        }

        if(data.custom.modemSupport=="1" || data.custom.modemSupport==undefined){
            globalConfig.modemSupport = true;
        }else{
            globalConfig.modemSupport = false;
        }

        if(data.custom.linkSwtichSupport=="1" || data.custom.linkSwtichSupport==undefined){
            globalConfig.linkSwtichSupport = true;
        }else{
            globalConfig.linkSwtichSupport = false;
        }

        if(data.custom.onlyModemSupport=="1"){
            globalConfig.onlyModemSupport = true;
        }else{
            globalConfig.onlyModemSupport = false;
        }

        if(data.custom.moduleMultiApnSupport=="1"){
            globalConfig.moduleMultiApnSupport = true;
        }else{
            globalConfig.moduleMultiApnSupport = false;
        }

		if(data.custom.debugLogSupport == "1"){
			globalConfig.debugLogSupport = true;
		}else if(data.custom.debugLogSupport == "0"){
			globalConfig.debugLogSupport = false;
		}else{
			globalConfig.debugLogSupport = true;
		}

		if(data.custom.vpnMenuSupport == "1")
			globalConfig.vpnMenuSupport = true;
		else if(data.custom.vpnMenuSupport == "0")
			globalConfig.vpnMenuSupport = false;
		else
			globalConfig.vpnMenuSupport = true;

		if(data.csid == "C7335R")
			globalConfig.tcpdumpPackSupport=false;
		else{
			if(data.custom.tcpdumpPackSupport=="1")
				globalConfig.tcpdumpPackSupport=true;
			else
				globalConfig.tcpdumpPackSupport=false;
		}

        globalConfig.c7335rSupport = data.csid != "C7335R";
        globalConfig.c735irSupport = data.csid == "C735IR";
        globalConfig.uiStyle = data.custom.uiStyle;
	globalConfig.C738jrSupport = data.custom.additionnalFuncSupport;
        globalConfig.modemDualband = data.modemDualband == "1";
        globalConfig.modemPrioIsDounleMode = data.modemPrioIsDounleMode == "1";
        globalConfig.simSelectSupport = data.custom.simSelectSupport == "1";
        
        set_obj_value(data, [
                "model",
                "csid",
                //"wifiMenuDisabled",
                "helpUrl",
		"gwLink",
		"gwLinkTips",
		"gwLink2",
		"gwLink2Tips",
                "copyRight",
                "defaultLang",
                "lanNum",
				"modelType",
                "operationMode"
            ],
            function(key, value) {
                globalConfig[key] = value;
            }
        )

        set_obj_value(data, "custom", [
				"wifiWpa2Wpa3Support",
                "openVpnServerSupport",
                "openVpnClientSupport",
				"l2tpClientSupport",
				"pptpClientSupport",
                "ipv6Support",
                "pppoeSpecSupport",
                "bandLockSupport",
                "nssaiSupport",
                "rtl8111hSupport",
                "saSupport",
                "netcustomSupport",
                "baseStationSupport",
                "lteTestSupport",
                "wechatQrSupport",
                "vpnPassSupport",
                "actStatusSupport",
                "versionControlSupport",
                "attackSupport",
                "opmodeSupport",
                "dtuSupport",
				"mqttSupport",
                "diffnetListSupport",
                "diffnetSupport",
                "diffnetSwitchSupport",
                "radiusSupport",
                "tunnelSupport",
                "certSupport",
                "dmvpnSupport",
                "rnatSupport",
                "algSupport",
                "remoteLogSupport",
                "ttyServerSupport",
                "iotSupport",
                "vpncDmzSupport",
                "snmpSupport",
                "ripSupport",
                "ospfSupport",
                "bgpSupport",
                "eoipSupport",
                "vrrpSupport",
                "ipsecSupport",
                "slbDongleSupport",
                "slbAPSupport",
                "vpnDetectionSupport",
                "policyRouteSupport",
				"ddnsSupport",
				"smsSupport",
				"ussdSupport",
				"qosSupport",
				"qosDefSingleIpSupport",
				"gpsSupport",
				"gps3Support",
                "staticRouteSupport",
                "manageCloudSupport",
                "wanRouteSupport",
                "thirdSystemSupport",
                "tfSupport",
                "sslVpnSupport",
                "vxlanSupport",
                "fotaSupport",
                "mirrorPortSupport",
                "terminalSupport",
                "vpnMultiClientSupport",
                "staticDhcpSupport",
                "newActiveSupport",
                "cellLockSupport",
                "simChangeSupport",
                "iotMqttSupport",
                "aliyunMqttSupport",
                "iotMqttWebShowUserPass",
                "cwmpdSupport",
                "dtuDualband",
                "dtuAliyunMqttSupport",
                "xuJiRouteSupport",
                "webcamSupport",
                "modbusSupport",
                "ipsecCertSupport",
                "detectNetSupport",
                "hwNatSupport",
                "modemAuthSupport",
                "aiotSupport",
                "onenetSupport",
                "modemPpsSupport",
		        "modemRoamSupport",
                "wireguardSupport",
                "timingSupport",
                "lan5gSupport",
                "simSelectSupport",
                "pptpSupport",
                "l2tpSupport",
                "clientSupport",
            ],
            function(key, value) {
                if (key === "opmodeSupport") {
                    globalConfig[key] = (value == "1" || (value != '0' && !!value));
                    globalConfig.opmodeString = value;
                } else if (key === "netcustomSupport") {
                    globalConfig[key] = (value == "1" || (value != '0' && !!value));
                    globalConfig.nettypeString = value;
                } else{
                    globalConfig[key] = value == "1";
                }
            }

        )

        globalConfig.showLanguage = data.showLanguage.split(",");
		globalConfig.powerCtlSuppor = data.custom.powerCtlSuppor == "1";
        globalConfig.showAutoLang = data.showAutoLang == "1";

        if (data.showAutoLang == "1") {
            globalConfig.showLanguage.splice(0, 0, "auto");
        } else {
            data.langAutoFlag = '0';
        }
		var wanTypeList = data.custom.wanTypeList.split(",");
        globalConfig.wanTypeList_DHCP = !!~$.inArray("dhcp", wanTypeList);
        globalConfig.wanTypeList_STATIC = !!~$.inArray("static", wanTypeList);
        globalConfig.wanTypeList_WISP = !!~$.inArray("wisp", wanTypeList);
        globalConfig.wanTypeList_PPPOE = !!~$.inArray("pppoe", wanTypeList);
        globalConfig.wanTypeList_PPTP = !!~$.inArray("pptp", wanTypeList);
        globalConfig.wanTypeList_L2TP = !!~$.inArray("l2tp", wanTypeList);
        globalConfig.wanTypeList_USBNET = !!~$.inArray("usbnet", wanTypeList);

        if(data.langAutoFlag == '1') {
            globalConfig.langAutoFlag = true;
            if(applang == "zh-tw"||applang == "zh-hk"){
                applang = "ct";
            }else if(applang == "zh-cn"||applang == "zh"||applang == "zh-sg"){
                applang = "cn";
            }else if(applang == "en"||applang == "en-us"||applang == "en-gb"){
                applang = "en";
            }else if(applang == "ja"){
                applang = "jp";
            }else if(applang == "th"){
                applang = "th";
            }else if(applang == "be"||applang == "ru"||applang == "ru-md"){
                applang = "ru";
            }

            if ($.inArray(applang, globalConfig.showLanguage) == -1) applang="en";
            localStorage.setItem('lang',applang);
            language.switch(applang);
        } else {
            if (data.defaultLang) {
                localStorage.setItem('lang',data.defaultLang);
                language.switch(data.defaultLang);
                applang = data.defaultLang;
            }
        }
        autoFun(applang);
        if (data.langAutoFlag == "1" && applang != data.defaultLang ) {
            var postVar = {};
            postVar.lang = applang;
            postVar.langAutoFlag = data.langAutoFlag;
            uiPost.setLanguageCfg(postVar, function() {
                uiPost.getInitConfig(function(data) {
                  	globalConfig.helpUrl = data.helpUrl;
                  	globalConfig.gwLink = data.gwLink;
                  	globalConfig.gwLinkTips = data.gwLinkTips;
                  	globalConfig.gwLink2 = data.gwLink2;
                  	globalConfig.gwLink2Tips = data.gwLink2Tips;
                });
            });
        }

        opnsenseInit();
    })

})(window);
