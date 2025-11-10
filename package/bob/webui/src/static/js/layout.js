var _tempLoadFlag_ =null;
// 注册header
Vue.component('opnsense-header', {
  template: '\
    <header class="page-head" :class="useStyle">\
        <nav class="navbar navbar-default">\
          <div class="container-fluid">\
            <div class="navbar-header">\
              <a class="navbar-brand">\
                <div style="font-size:150%;margin-top:-7px;" v-if="globalConfig.c735irSupport">\
                  <span ref="logoimg"></span>\
                </div>\
                <div style="font-size:150%;margin-top:-7px;" v-else>\
                  <span ref="logoimg"></span>\
                  <span v-if="showWord">{{ globalConfig.customCompany }}</span>\
                  <span class="model-phone-show" v-if="globalConfig.model && globalConfig.customCompany">{{" | "}}</span>\
                  <span class="model-phone-show" v-show="globalConfig.model" style="font-size: 17px;">{{ globalConfig.model }}</span>\
                  <!--<span v-if="!globalConfig.versionControlSupport" style="color:#FF0000">{{ lang_t("index.testVersion") }}</span>-->\
                </div>\
              </a>\
              <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navigation" style="float:right;margin-right:10px" v-if="!islogin">\
                <span class="sr-only">Toggle navigation</span>\
                <span class="icon-bar"></span>\
                <span class="icon-bar"></span>\
                <span class="icon-bar"></span>\
              </button>\
              <span class="navbar-langphone" style="display: none;">\
                <form role="search">\
                  <div class="input-group">\
                    <select v-model="currentLangPhone" data-style="btn-default" data-none-selected-text="" @change="langChange(2)" id="lang_select_phone">\
                      <option v-for="(lan,v) in lang" :value="v">{{ lan }}</option>\
                    </select>\
                  </div>\
                </form>\
              </span>\
            </div>\
            <div class="collapse navbar-collapse">\
              <ul class="nav navbar-nav navbar-right" :style="globalConfig.c735irSupport ? \'margin-top: 25px;\':\'\'">\
                <li v-show="globalConfig.actStatusSupport" style="cursor:pointer;">\
                  <a v-if="globalConfig.activation" style="color: #08d40b;cursor: default;">{{ lang_t("index.authorized") }}</a>\
                  <a v-else @click="setActStatus()" style="color: #EA7105;text-decoration-line: underline;">{{ lang_t("index.unauthorized") }}</a>\
                </li>\
                <li>\
                  <form class="navbar-form" role="search">\
                    <div class="input-group">\
                      <div class="input-group-addon"><i class="fa fa-language"></i></div>\
                      <select v-model="currentLang" class="selectpicker" data-style="btn-default" data-none-selected-text="" @change="langChange(1)" id="lang_select" style="width:110px;">\
                        <option v-for="(lan,v) in lang" :value="v">{{ lan }}</option>\
                      </select>\
                    </div>\
                  </form>\
                </li>\
                <li v-show="globalConfig.customHelp" style="cursor:pointer"><a @click="hrefhelp">{{ lang_t("menu.help") }}</a></li>\
                <li v-show="globalConfig.showGwlink" style="cursor:pointer"><a @click="hrefgwlink">{{ globalConfig.gwLinkTips }}</a></li>\
                <li v-show="globalConfig.showGwlink2" style="cursor:pointer"><a @click="hrefgwlink2">{{ globalConfig.gwLink2Tips }}</a></li>\
                <li>\
                <li>\
                  <li style="cursor:pointer" v-if="globalConfig.deviceManageSupport"><a class="dropdown-toggle" data-toggle="dropdown">{{ lang_t("menu.device_manage") }}</a>\
                    <ul class="dropdown-menu">\
                      <li v-if="globalConfig.specialIotBanApply==false"><a @click="reboot">{{ lang_t("menu.reboot") }}</a></li>\
                      <li><a @click="logout">{{ lang_t("menu.logout") }}</a></li>\
                    </ul>\
                  </li>\
                </li>\
              </ul>\
            </div>\
          </div>\
        </nav>\
        <opnsense-messge ref="main_Messge" v-show="header_msg"></opnsense-messge>\
        <countdown-modal ref="main_Countmsg" v-show="header_msg"></countdown-modal>\
        <active-model ref="active_Model" v-show="header_msg"></active-model>\
    </header>\
  ',
  data:function() {
    return {
      globalConfig:globalConfig,
      lang1:$.lang,
	  lang_t:lang_t,
      lang:{},
      languages:languages,
      currentLang:'',
      currentLangPhone:'',
      islogin:false,
      header_msg:false,
      showWord:false,
      useStyle: ''
    }  
  },
  computed:{
	  
  },
  created:function(){
    var _this = this;
    _this.init();
    _this.fileexit();
    if (globalConfig.c735irSupport) {
        this.useStyle = "app-style-1";
    }else if(globalConfig.uiStyle =='green'){
        this.useStyle = "app-style-green";
    }else if(globalConfig.uiStyle =='green_382c'){
        this.useStyle = "app-style-green-382c";
    }else if(globalConfig.uiStyle =='blue'){
        this.useStyle = "app-style-blue";
    }
  },
  mounted:function(){
    Cstools.msg = this.$refs.main_Messge.init;
    Cstools.count = this.$refs.main_Countmsg.init;
  },
  methods:{
    init:function(time){
      var tmpArr = {}, ls = globalConfig.showLanguage;
      if (ls) {
        for (var l = 0;l < ls.length;l++) {
          if (languages[ ls[l] ] != undefined) {
            tmpArr[ ls[l] ] = languages[ ls[l] ];
          }
        }
        if(globalConfig.langAutoFlag && globalConfig.showAutoLang){
          this.currentLang = "auto";
          this.currentLangPhone = "auto";
        }else{
          this.currentLang = localStorage.getItem('lang') ? localStorage.getItem('lang') : 'en';
          this.currentLangPhone = localStorage.getItem('lang') ? localStorage.getItem('lang') : 'en';
        }
      }

      this.lang = tmpArr;
      if(location.pathname == '/login.html' || location.pathname == '/login_4g.html' || location.pathname == '/login_5g.html'){
        this.islogin = true;
      }
    },
    fileexit:function(){
      var _this = this;
      try {
        var img = new Image();
        if(globalConfig.c735irSupport){
          img.src = "/static/images/logo_zx.png";
        }else{
          img.src = '/style/logo.png';
        }

        img.onload = function(){
          _this.$refs.logoimg.appendChild(img);
        };
        img.onerror = function(){
          _this.showWord = true;
        };
      } catch(e) {
        
      }
    },
    hrefhelp:function(){
      window.open(this.globalConfig.helpUrl);
    },
    hrefgwlink:function(){
      window.open(this.globalConfig.gwLink);
    },
    hrefgwlink2:function(){
      window.open(this.globalConfig.gwLink2);
    },
    langChange:function(type){
      var _this = this;
      var lang = '';
      if (type == 1){
        lang = this.currentLang;
      }else {
        lang = this.currentLangPhone;
      }
      var langAutoFlag = '0';
      var postVar = {};
      var applang = (navigator.language||navigator.browserLanguage).toLowerCase();
      if(lang == "auto"){
        if(applang == "zh-tw"||applang == "zh-hk"){
          applang = "ct";
        }else if(applang == "zh-cn"||applang == "zh"||applang == "zh-sg"){
          applang = "cn";
        }else if(applang == "en"||applang == "en-us"||applang == "en-gb"){
          applang = "en";
        }else if(applang == "ja"){
          applang = "jp";       
        }else if(applang == "be"||applang == "ru"||applang == "ru-md"){
          applang = "ru";       
	}else if(applang == "th" || applang == "th-th"){
          applang = "th";       
	}
        var str = this.globalConfig.showLanguage;
        if(str.indexOf(applang) < 0){
          applang = "en";
        }
 
        language.switch(applang);
        langAutoFlag = "1";
      }else{
        language.switch(lang);
        langAutoFlag = "0";
        applang = lang;
      }
      if(this.globalConfig.showLanguage && globalConfig.langAutoFlag && globalConfig.showAutoLang){
        var autoText = "Auto";
        if(applang == "ct"){
          autoText = "自動檢測";
        }else if(applang == "cn"){
          autoText = "自动检测";
        }else if(applang == "jp"){
          autoText = "自動検出";
        }else if(applang == "ru"){
          autoText = "автоматическое";
        }else if(applang == "th"){
          autoText = "ตรวจจับโดยอัตโนมัติ";
        }else if(applang == "vn"){
          autoText = "Phát hiện tự động";
        } 
        var $id = document.getElementById('lang_select');
        if (type == 2){
          $id = document.getElementById('lang_select_phone');
        }
        $id.childNodes[0].childNodes[0].nodeValue = autoText;
      }
      
      localStorage.setItem('lang',applang);
      postVar.lang = applang;
      postVar.langAutoFlag = langAutoFlag;
      uiPost.setLanguageCfg(postVar,function(){
        uiPost.getInitConfig(function(data) {
          _this.globalConfig.helpUrl = data.helpUrl;
        })
      });
    },
    logout:function(){
      var _this = this;
      _this.header_msg = true;
      setTimeout(function(){
        _this.$refs.main_Messge.init({
          content: _this.lang_t('login.msg8'),
          messgetype: 'confirm',
          ok: function(){
            location.href = '/login.html';
          },
          cancel: function(){
            _this.header_msg = false;
            return false;
          }
        });
      },50);
    },
    reboot:function(){
      var _this = this;
      var time;
      this.header_msg = true;
      setTimeout(function(){
        _this.$refs.main_Messge.init({
          content: _this.lang_t('config.msg6'),
          type: 'warn',
          messgetype: 'confirm',
          ok: function(){
		    uiPost.RebootSystem(function(data) {
			  if(data.wtime != undefined && data.wtime != ""){
			    time = data.wtime;
			  }else{
			    time = 100;
			  }
			  Cstools.count(time,'js',function(){
			  parent.location.href='http://'+location.host+'/login.html?time='+new Date().getTime();
			  });
            });
            return false;
          },
          cancel: function(){
            _this.header_msg = false;
            return false;
          }
        });
      },50);
    },
    setActStatus:function () {
      var _this = this;
      if (_this.globalConfig.newActiveSupport){
        parent.location.href='/active.html';
      }else{
        _this.$refs.active_Model.init();
      }
    }
  }
});

// 注册Menu
Vue.component('opnsense-menu', {
  template: '\
    <aside id="navigation" class="page-side col-xs-12 col-sm-3 col-lg-2 hidden-xs">\
	  <div class="row" id="main_box">\
	    <nav class="page-side-nav" style="cursor:pointer;">\
		  <div id="mainmenu" class="panel" style="border:0px">\
		    <div class="panel list-group" style="border:0px">\
			  <div v-for="(menu,v) in menu" :key="menu.lang" v-if="menu.display">\
			    <div v-if="menu.sub">\
				  <a @click="menuChange(menu.id)" :class="[\'list-group-item\',menuId==menu.id ? \'active-menu-title\' : \'\']" data-toggle="collapse" data-parent="#mainmenu"><span :class="[\'fa\', menu.icon,\'__iconspacer\']" style="width:13%;"></span>{{ lang_t("menu."+menu.lang) }}</a>\
				  <div :class="[\'collapse\',menuId==menu.id ? \'in\' : \'\' ]" :id="menu.id">\
				    <a v-for="sub in menu.sub" @click="gohref(sub.href,sub)" v-if="sub.display" :class="[\'list-group-item\',subArr[sub.id] ? \'active\' : \'\']" :style="paddingStyle">\
					  <div style="display: table;width: 100%;">\
					    <div style="display: table-row" :class="[subArr[sub.id] ? \'menusub\' : \'\']">\
						  <div style="display: table-cell">{{ lang_t("menu."+sub.lang) }}</div>\
						  <!--<div style="display: table-cell; text-align:right; vertical-align:middle;"><span :class="[\'fa\', sub.icon,\'fa-fw\']"></span></div>-->\
					    </div>\
					  </div>\
				    </a>\
				  </div>\
			    </div>\
			    <div v-else>\
				  <a @click="gohref(menu.href,menu)" :class="[\'list-group-item\',menuId==menu.id ? \'active-menu-title\' : \'\']" data-toggle="collapse" data-parent="#mainmenu"><span :class="[\'fa\', menu.icon,\'__iconspacer\']" style="width:13%;"></span>{{ lang_t("menu."+menu.lang) }}</a>\
			    </div>\
			  </div>\
			</div>\
		  </div>\
		</nav>\
	  </div>\
    </aside>\
  ',
  data:function() {
    return {
      globalConfig:globalConfig,
      lang: $.lang,
	  lang_t:lang_t,
      menus:menu,
      menuId:'1',
      subArr:[],
      isOut: false,
      paddingStyle:{'padding-left':40+'px'}
    }  
  },
  computed:{
    menu:function(){
      return this.menus;
    }
  },
  created:function(){
    var _this = this;
    _this.menuInit();
  },
  mounted:function(){
    var _this = this;
    this.sizeAuto();
    window.addEventListener("orientationchange", function(event) {
	  _this.sizeAuto();
	}, false);
  },
  methods:{
    sizeAuto:function(){
      var clientWidth = document.body.clientWidth;
      if(clientWidth < 415){
        $('#main_box').css('padding-top',50+'px');
        this.paddingStyle = {'padding-left':60+'px'};
      }
    },
    menuInit:function(){
      /************菜单初始化************/
      var meunid  = []; //定义一级菜单显示
      var subid   = ['2','3','4','5','6','8'];//拥有子菜单的id
      var netid   = ['2-1','2-2','2-10','2-7','2-3','2-9','2-4','2-5','2-6'], //网络设置子菜单显示
          serid   = [/*'3-1',*/'3-2','3-4',"3-26","3-3","3-11",/*'3-5','3-6',*/'3-7','3-8','3-9','3-10','3-12'], //高级应用子菜单显示
		      vpnid   = [/*'4-1'*/,'4-2','4-3','4-4','4-5',/* '4-8', */'4-6','4-7','4-9','4-10'/*,'4-11'*/,'4-12','4-14','4-15','4-16',,'4-17','4-18'], //VPN子菜单显示
		      natid   = ['5-1','5-2','5-3','5-4','5-5','5-6','5-7'], //NAT子菜单显示
          fireid  = ['6-1','6-2','6-3','6-5','6-6','6-7','6-8','6-10'], //防火墙子菜单显示
          sysid   = ['8-1','8-2','8-3','8-13','8-4','8-11','8-5','8-10','8-7','8-12','8-8','8-9','8-99']; //系统管理子菜单显示
          
      var main = [], menuchlid = [];

      meunid = ['1','9','10','2','3','4','5','6',"7","8"];
	   
	  subid['2'] = netid;

	  if(globalConfig.c735irSupport) {
      netid.splice(7,0,'2-11');  
    }else{
      netid.splice(7,0,'2-8'); 
    }
    if(globalConfig.clientSupport) {
		  netid.splice(7,0,'2-16');  
	  }
	  subid['3'] = serid;
	  //if(globalConfig.csid == "C7I432M") {
	  	serid.splice(12,0,'3-13');
	  //}
	  if(globalConfig.gps3Support) {
		serid.splice(12,0,'3-14');  
	  }
	  if (globalConfig.powerCtlSuppor) {
        serid.splice(12,0,'3-15');
      }
     if(globalConfig.thirdSystemSupport){
	  	serid.splice(15,0,'3-16');
     }

     if(globalConfig.cwmpdSupport){
	  	serid.splice(8,0,'3-18');
     }

     if(globalConfig.iotMqttSupport){
	  	serid.splice(6,0,'3-17');
     }
     if(globalConfig.aliyunMqttSupport){
      serid.splice(20,0,'3-20');
     }
     if(globalConfig.webcamSupport){
      serid.splice(21,0,'3-21');
     }
     if(globalConfig.hwNatSupport){
	  	serid.splice(16,0,'3-19');
     }
     if(globalConfig.slbDongleSupport){
      serid.splice(11,0,'3-27');
     }
     if(globalConfig.slbAPSupport){
      serid.splice(11,0,'3-28');
     }     
	  if(globalConfig.l2tpClientSupport || globalConfig.pptpClientSupport ){
      if (globalConfig.vpnMultiClientSupport) {
        vpnid.splice(0,0,'4-13');
      }else{
        vpnid.splice(0,0,'4-1');
      }
		  
	  }

    if(globalConfig.wifiSupport && globalConfig.ipsecSupport){
      vpnid.splice(vpnid.length-1,0,'4-11');
    }

    if(globalConfig.modemDualband && globalConfig.modemPrioIsDounleMode){
      sysid   = ['8-1','8-2','8-3','8-4','8-11','8-5','8-10','8-7','8-12','8-8','8-9','8-99'];
      if(globalConfig.urlNetPage ==2){
        globalConfig.openVpnClientSupport =true;
      }else{
        vpnid = [];
      }
      globalConfig.linkSwtichSupport =false;
    }
    
      subid['4'] = vpnid;
	    subid['5'] = natid;
      subid['6'] = fireid;

      subid['7'] = ["7-1", "7-2"];
      subid['8'] = sysid;

      var rptSuppot = ['1', '2', '8', '9', '2-1', '2-3', '2-9', '2-16'];
      var apSuppot = ['1', '2', '3','8', '9', '2-1','2-3','3-18', '8-1', '8-3','8-4', '8-5','8-10', '8-99'];
      


      var custom_menu = function(temp) {
        if (typeof temp.display === "string") {
          temp.display = globalConfig[temp.display];
        }
        if (globalConfig.operationMode == '2' && temp.display) {
          temp.display = (!!~$.inArray(temp.id, rptSuppot) || (!!~temp.id.indexOf('8-') && !~temp.id.indexOf('8-3') && !~temp.id.indexOf('8-10')));
        }
        if (globalConfig.operationMode == '0' && temp.display) {
          temp.display = (!!~$.inArray(temp.id, apSuppot) );
        }
      };
	 
      var j = n = m = 0;
      for(var i in meunid){
        for(j=0;j<this.menus.length;j++){
          custom_menu(this.menus[j]);
          if(meunid[i] == this.menus[j].id && this.menus[j].display === true){
            var sub = this.menus[j].sub;
            if(sub){
              menuchlid = [];
              var chlidarr = subid[meunid[i]];
              for(n=0;n<chlidarr.length;n++){
                for(m=0;m<sub.length;m++){ 
                  custom_menu(sub[m]);
                  if(chlidarr[n] == sub[m].id && sub[m].display === true){
                    menuchlid.push(sub[m]);
                    break;
                  }
                }
              }
			  
              this.menus[j].sub = menuchlid;
			  if(this.menus[j].sub.length == 0){
				this.menus[j].display = false; 
			  }
			  
            }
            main.push(this.menus[j]);
            break;
          }
        }
      }
      this.menus = main;
      /*********************************/
      var href = location.pathname.substring(0,location.pathname.lastIndexOf('.'));
      href = href.split('/');
      for(var j in this.menus){
        if(href[1] == this.menus[j].lang){
          this.menuId = this.menus[j].id;
          if(this.menus[j].sub){
            for(var m in this.menus[j].sub){
              if(href[2] == this.menus[j].sub[m].lang){
                this.subArr[this.menus[j].sub[m].id] = true;
                break;
              }
              this.subArr[this.menus[j].sub[m].id] = false;
            }
          }
          break;
        }
      }
    },
    menuChange:function(id){
      if(this.menuId == id){
        this.menuId = '';
      }else{
        this.menuId = id;
      }
    },
    gohref:function(href){
      if(href == 'out'){
        var _this = this;
        this.isOut = true;
        setTimeout(function(){
          Cstools.msg({
            content: _this.lang_t('login.msg8'),
            messgetype: 'confirm',
            ok: function(){
              location.href = '/login.html';
            },
            cancel: function(){
              _this.isOut = false;
              return false;
            }
          });
        },50);
      }else if(href == 'gps'){
        if (href.indexOf('token') > -1){
          location.href = 'http://ac.crabox-sys.com'+'?token='+get_token_from_url();
        }else{
          location.href = 'http://ac.crabox-sys.com'+get_token_from_url();
        }
      }else{
        this.isOut = false;
        if (href.indexOf('token') > -1){
            if(href == 'vpn'){
                location.href = this.vpnhref+'?token='+get_token_from_url();
            }else{
                location.href = href+'?token='+get_token_from_url();
            }
        
        }else{
            if(href == 'vpn'){
                location.href = this.vpnhref+get_token_from_url();
            }else{
                location.href = href+get_token_from_url();
            }
        }
        
      }
    }
  }
});

// 注册表头
Vue.component('opnsense-breadcrumb', {
  template: '\
    <header class="page-content-head">\
          <div class="container-fluid">\
            <ul class="list-inline">\
              <h1><i class="fa fa-home" v-if="currentPage==\'home\'&&globalConfig.isPhoneDevice"></i>{{_bc}}</h1>\
            </ul>\
          </div>\
    </header>\
  ',
  props:{
    header_fa: {
      type: String
    },
    header_ch: {
      type: String
    }
  },
  data:function() {
    return {
      globalConfig:globalConfig,
      lang: $.lang,
	  lang_t:lang_t,
      currentPage: ''
    }  
  },
  computed:{
    href:function() {
      return location.pathname.substring(0,location.pathname.lastIndexOf('.'));
    },
    _bc:function() {
      var _bc = [];
      var _s = this.href.split('/');
	  if(_s[2] == 'gps_set2' || _s[2] == 'gps_set3') _s[2] = 'gps_set';
      for (var i = 0; i < _s.length; i++) {
        if (_s[i]) {
          _bc.push(this.lang_t('menu["'+_s[i]+'"]'));
        }
      }
      this.currentPage = _s[1];
      var msg = '';
      if(_bc[0] == _bc[1]){
        _bc.length = 1;
      }
      msg = _bc[0];
      if(_bc.length == 1){
        msg += '';
      }else{
        msg += ' > ' + _bc[1];
      }
      return msg;
    }
  },
  created:function(){
    var href = this.href.split('/');
  }
});

// 注册footer
Vue.component('opnsense-footer', {
  template: '\
    <footer class="page-foot">\
          <div class="container-fluid" >\
            <div v-html="copyright"></div>\
          </div>\
        </footer>\
  ',
  data:function() {
    return {
      globalConfig:globalConfig,
      lang: $.lang,
	  lang_t:lang_t
    }  
  },
  computed:{
    copyright:function(){
      return this.globalConfig.copyRight.replace(/\[date\]/i,(new Date).getFullYear());
    }
  }
});


// 注册激活弹窗
Vue.component('active-model', {
  template: '\
    <div class="modal fade" v-show="showModal" id="csActiveModel" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" aria-hidden="true" data-backdrop="static">\
       <div class="modal-dialog">\
         <div class="modal-content">\
           <div class="modal-header">\
            <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>\
            <h4 class="modal-title">{{ lang_t("index.set_active_code") }}</h4>\
           </div>\
         <div class="modal-body">\
         <table class="table">\
           <tr>\
             <td width="20%">{{ lang_t("index.active_code") }}</td>\
             <td><input type="text" v-model="accessCode" maxlength="32"/></td>\
           </tr>\
         </table>\
         </div>\
         <div class="modal-footer">\
           <table>\
             <tr>\
               <td colspan="2">\
                 <button @click="cancel()" class="btn btn-default all-but">{{ lang_t("common.cancel") }}</button>&nbsp;&nbsp;\
                 <button @click="setActStatus()" class="btn btn-primary all-but">{{ lang_t("common.confirm") }}</button>\
               </td>\
             </tr>\
           </table>\
         </div>\
        </div>\
       </div>\
     </div>\
  ',
  props: {
    showModal:{
      type: Boolean,
      default: false
    }
  },
  data:function() {
    return {
      globalConfig:globalConfig,
      lang: $.lang,
      lang_t:lang_t,
      accessCode: ""
    }
  },
  computed:{

  },
  methods:{
    init:function(){
      $('#csActiveModel').modal('show');
    },
    cancel:function(){
      $('#csActiveModel').modal('hide');
    },
    setActStatus:function() {
      var _this = this;
      uiPost.setActStatus({accessCode: this.accessCode}, function() {
        _this.cancel();
        Cstools.msg({
          content: lang_t('index.accessing'),
          type: 'info',
          messgetype: 'no'
        })
        var cout = 0;
        var inter = setInterval(function() {
          if (cout > 5) {
            errorAlert(lang_t('index.access_fail'));
            clearInterval(inter);
            return ;
          }
          cout++;
          uiPost.getInitConfig(function(data) {
            if (data.activation == "1") {
              Cstools.msg({
                content: lang_t('index.authorized'),
                type: 'success',
                messgetype: 'no',
                time: 1,
                timeout: function() {
                  location.reload();
                }
              })
              clearInterval(inter);
            }
          })
        }, 1000);
      });
    }
  }
});

// 注册提示框
// js调用写法  this.$refs.***.init({ }) ***为组件中ref定义的 如：ref="***"
// html中按钮调用写法：data-toggle="modal" data-target="#modal_Messge"
Vue.component('opnsense-messge', {
  template: '\
    <div  class="modal fade" :id="messge_id" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" aria-hidden="true" data-backdrop="static" @keydown.enter="okclick()">\
      <div class="modal-dialog">\
        <div class="modal-content">\
          <div class="modal-header" style="border-bottom: none;">\
            <!--<button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>-->\
            <h4 class="modal-title">\
              {{ messgeTitle }}\
            </h4>\
          </div>\
          <div class="modal-body" >\
            <p style="white-space:pre-wrap;word-wrap:break-word;word-break:break-all;"><i :class="iconType" :style="{\'font-size\': \'30px\',color:colorType}"></i>&nbsp;&nbsp;&nbsp;{{ messgeContent }}</p>\
          </div>\
          <div class="modal-footer" style="border-top:none;">\
            <button type="button" class="btn btn-default" v-if="messgeMsgtype == \'confirm\'" @click="cancelclick">{{ lang_t(\'common.cancel\') }}</button>\
            <button type="button" class="btn btn-primary"  @click="okclick" v-if="messgeMsgtype != \'no\'">{{ lang_t(\'common.ok\') }}</button>\
          </div>\
        </div>\
      </div>\
    </div>\
  ',
  props:{
    messge_id:{ //自定义组件id
      type: String,
      default: 'modal_Messge'
    },
    title: { //头部描述
      type: String,
      default: ''
    },
    content: { //内容描述
      type: String,
      default: ''
    },
    type:{ //支持info success warn error
      type: String,
      default: 'info'
    },
    msgtype:{ //支持confirm alert no
      type: String,
      default: 'confirm'
    },
    ok:{ //点击确认按钮执行操作
      type: Function, 
      default: function _default (){
        $('#'+this.messge_id).modal('hide');
      }
    },
    cancel:{ //点击取消按钮执行操作
      type: Function,
      default: function _default (){
        $('#'+this.messge_id).modal('hide');
      }
    },
    calltype:{
      default :''
    }
  },
  data:function() {
    return {
      lang: $.lang,
      lang_t:lang_t,
      callType: '',
      init_title: '',
      init_content: '',
      init_type: 'info',
      init_msgtype: 'confirm',
      init_time: 0,
      init_ok :function(){
        $('#'+this.messge_id).modal('hide');
      },
      init_cancel:function(){
        $('#'+this.messge_id).modal('hide');
      },
      defaultFun:function(){
        $('#'+this.messge_id).modal('hide');
      }
    }  
  },
  computed:{
    messgeTitle:function(){
      if(this.callType != 'js')
        return this.title;
      else
        return this.init_title;
    },
    messgeContent:function(){
      if(this.callType != 'js')
        return this.content;
      else
		    return this.init_content;
    },
    messgeType:function(){
      if(this.callType != 'js')
        return this.type;
      else
        return this.init_type;
    },
    messgeMsgtype:function(){
      if(this.callType != 'js')
        return this.msgtype;
      else
        return this.init_msgtype;
    },
    iconType:function(){
      var type = this.messgeType;
      var icon = '';
      if(type == 'info'){
        icon = 'fa fa-info-circle';
      }else if(type == 'success'){
        icon = 'fa fa-check';
      }else if(type == 'warn'){
        icon = 'fa fa-warning';
      }else if(type == 'error'){
        icon = 'fa fa-times-circle';
      }
      return icon;
    },
    colorType:function(){
      var type = this.messgeType;
      var color = '';
      if(type == 'info'){
        color = '#2d8cf0'
      }else if(type == 'success'){
        color = '#00CD00';
      }else if(type == 'warn'){
        if(globalConfig.c735irSupport)
          color = '#67b9b7';
        else if(globalConfig.uiStyle =='green')
          color = '#67b9b7';
		else if(globalConfig.uiStyle =='green_382c')
          color = '#67b9b7';
        else if(globalConfig.uiStyle =='blue')
          color = '#31708f';
        else
          color = '#EA7105';
      }else if(type == 'error'){
        color = '#f00';
      }
      return color;
    }
  },
  methods:{
    init:function(obj){ //都是可选值，非必要，没填写的对象会赋予默认值
      this.callType = 'js';
      var title = obj.title;
      var content = obj.content;
      var type = obj.type;
      // TODO 调整弹框图标（固定）
      type = 'warn';
      var messgetype = obj.messgetype;
      var time = obj.time;//可定义框消失的时间，只在messgetype为'no'的时候有效
      this.init_title = title != undefined ? title : this.lang_t("common.tips_1")+ window.location.host +this.lang_t("common.tips_2");
      this.init_content = content != undefined ? content : '';
      this.init_type = type != undefined ? type : 'info';
      this.init_msgtype = messgetype != undefined ? messgetype : 'confirm';
      if(typeof(obj.ok) == 'function'){//确定按钮执行函数，无此项时默认关闭 返回false也会关闭
        this.init_ok = obj.ok;
      }else{
        this.init_ok = this.defaultFun;
      }
      if(typeof(obj.cancel) == 'function'){//取消按钮执行函数，无此项时默认关闭 返回false也会关闭
        this.init_cancel = obj.cancel;
      }else{
        this.init_cancel = this.defaultFun;
      }

      $('#'+this.messge_id).modal('show');
      if(time != undefined && time != 0){
        if(this.init_msgtype == 'no'){
          var fun = function(){};
          if(typeof(obj.timeout) == 'function')
            fun = obj.timeout;

          this.timeInit(time,fun);
        }
      }
    },
    timeInit:function(_time,timeoutfun){
      var _this = this;
      var time = 0;
      var count_time =1000;
      if (_tempLoadFlag_ ===true) {
        count_time =10;
      }
      var timeout = setInterval(function(){
        if(time >= _time || _tempLoadFlag_ === false){
          _tempLoadFlag_ = null;
          clearInterval(timeout);
          $('#'+_this.messge_id).modal('hide');
          timeoutfun();
        }
        if(_tempLoadFlag_ === true)
          time = 0;
        else
          time++;
      },count_time);
    },
    okclick:function(){
      if(this.callType == 'js'){
        if(this.init_ok(true) == false){
          $('#'+this.messge_id).modal('hide');
        }
      }else{
        if(this.ok(true) == false){
          $('#'+this.messge_id).modal('hide');
        }
      }
      cs.bodyAction(this.messge_id,'modal_info');
    },
    cancelclick:function(){
      if(this.callType == 'js'){
        if(this.init_cancel(false) == false)
          $('#'+this.messge_id).modal('hide');
      }else{
        this.cancel(false);
      }
      cs.bodyAction(this.messge_id,'modal_info');
    }
  }
});

//注册倒计时
var _tempCount_ = null;
Vue.component('countdown-modal', {
  template: '\
   <div class="modal fade" id="count_down" tabindex="-1" role="dialog" aria-labelledby="myModalLabel" aria-hidden="true" data-backdrop="static">\
      <div class="modal-dialog">\
          <div class="modal-content">\
              <div class="modal-header">\
                <h4 class="modal-title" >{{title}}</h4>\
              </div>\
              <div class="modal-body" >\
                <div >\
                 <b>{{progress}}%</b>\
                 <div v-if="globalConfig.c735irSupport"  :style="{width: progress+\'%\',\'background-color\': \'#67b9b7\',\'border-radius\': \'10px\',height:\'20px\',\'line-height\': \'20px\'}"></div>\
                 <div v-else-if="globalConfig.uiStyle ==\'blue\'" :style="{width: progress+\'%\',\'background-color\': \'#31708f\',\'border-radius\': \'10px\',height:\'20px\',\'line-height\': \'20px\'}"></div>\
                 <div v-else-if="globalConfig.uiStyle ==\'green\'" :style="{width: progress+\'%\',\'background-color\': \'#328f8d\',\'border-radius\': \'10px\',height:\'20px\',\'line-height\': \'20px\'}"></div>\
				 <div v-else-if="globalConfig.uiStyle ==\'green_382c\'" :style="{width: progress+\'%\',\'background-color\': \'#b2d234\',\'border-radius\': \'10px\',height:\'20px\',\'line-height\': \'20px\'}"></div>\
				 <div v-else :style="{width: progress+\'%\',\'background-color\': \'#EA7105\',\'border-radius\': \'10px\',height:\'20px\',\'line-height\': \'20px\'}"></div>\
                </div>\
              </div>\
          </div>\
      </div>\
  </div>\
    ',
    props:{
      percent:{
        default : 0
      }
    },
    data:function(){
      return {
        lang: $.lang,
        lang_t:lang_t,
        progress:0,
        callType: ''
      }
    },
    watch:{
      percent:function(){
        if(this.callType != 'js'){
          this.progress = this.percent;
          if(this.progress >= 100){
            $('#count_down').modal('hide');
          }
        }
      }
    },
    computed:{
      title:function(){
        if(this.callType == 'load')
          return this.lang_t('common.uploading');
        if(this.callType  == 'up')
          return this.lang_t('common.upgrading');
        else
          return this.lang_t('common.loading'); 
      }
    },
    methods:{
      init:function(time,type,fun){
        var _this = this;
        this.callType = type;
        this.progress = 0;
        $('#count_down').modal('show');
        var counttime = (parseInt(time)/100)*1000;
        if(_tempCount_ != null){
          counttime = 500;
        }
        var percentTimer = setInterval(function(){
          if (_this.progress>=99) {
            _tempCount_ = null;
            clearInterval(percentTimer);
            $('#count_down').modal('hide');
              if(typeof(fun) != 'function') return false;
              else 
                fun();
          }
          if(_tempCount_ != null)
            _this.progress = _tempCount_;
          else
            _this.progress++;
        },counttime);
      }
    }
});

//注册table弹框
Vue.component('modal-table', {
  template: '<div :id="id" class="modal fade" tabindex="-1" role="dialog" data-backdrop="static">\
  <div class="modal-dialog" :class="{\'modal-lg\':isShowLgModal}" role="document">\
    <div class="modal-content">\
      <div class="modal-header">\
        <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>\
        <h4 class="modal-title">{{modalTitle}}</h4>\
      </div>\
      <div class="modal-body">\
        <div class="row">\
            <div class="col-xs-12" v-show="isShowSearch">\
              <div class="form-group">\
                <input type="text" class="form-control" v-model="searchQuery">\
              </div>\
            </div>\
            <div class="col-xs-12 table-responsive" :style="styleObject">\
                <table class="table table-bordered table-striped table-hover">\
                 <thead>\
                    <tr>\
                      <th class="text-center" v-for="i in table.th">{{i}}</th>\
                    </tr>\
                </thead>\
                <tbody>\
                    <tr align="center" v-for="(item, index) in tableTd" @click="get_current(index)" >\
                      <td v-for="(sub_item,i) in item" v-if="\'idx\'!= i" style="cursor:pointer">{{sub_item}}</td>\
                    </tr>\
                </tbody>\
                </table>\
            </div>\
        </div>\
      </div>\
      <div class="modal-footer" >\
        <button type="button" class="btn btn-primary" data-dismiss="modal">{{lang_t(\'common.close\')}}</button>\
      </div>\
    </div>\
  </div>\
</div>\
',
  props:{
      id: String,
      table: Object,
      modalTitle: String,
      showSearch: Boolean
  },
  data:function(){
    return {
      lang: $.lang,
      lang_t:lang_t,
      searchQuery:'',
      isShowSearch:this.showSearch,
      tableDataOne : null
    }
  },
  computed:{
    isShowLgModal:function(){
      return this.table.th.length>4;
    },
    styleObject:function(){
      var height = this.table.td.length < 10 ? 'auto' : "500px";
      return {
        height:height,
      };
    },
    tableTd:function() {
      var searchQuery = this.searchQuery;
      var data = this.table.td;
      if (searchQuery) {
        data = data.filter(function (row) {
          return Object.keys(row).some(function (key) {
            return String(row[key]).toLowerCase().indexOf(searchQuery) > -1
          })
        })
      }
      return data;
    }
  },
  methods:{
    get_current:function(data){
      this.tableDataOne = this.table.td[data];
      $('#'+this.id).modal('hide');
      this.$emit('oncurrent',this.tableDataOne);
      cs.bodyAction(this.id,'modal_info');
    }
  }
});

//注册排序功能
//data：表格的总数据
//child：例如当有个数组[1,2,3]则child可以不用理会，当[{yy:"nn","uu":22}]时，如果是根据yy的值来排序，则child="yy"
//type: 需要排序的数据类型，目前有num（默认）：数字、ip：地址、time：时间
//排序得到的数据调用方法为
//升序@asc="xx"
//降序@desc="xx"
// xx是在methods里定义的一个函数，如
// xx:function(data){} data为传回的已排序的参数
Vue.component('table-sort', {
  template:'\
    <div class="csui-table-cell">\
      <span><slot></slot></span>\
      <div class="csui-table-sort">\
        <ul>\
          <li style="padding-bottom: 0;margin-bottom:2px;" @click="ascClick"><i class="fa fa-sort-asc" :style="asc"></i></li>\
          <li style="margin-top:1px;padding-bottom: 9px;" @click="descClick"><i class="fa fa-sort-desc" :style="desc"></i></li>\
        </ul>\
        </div>\
    </div>\
  ',
  props:{
      type:{
        default: 'num'
      },
      child:{
        type: String,
        default: ''
      },
      data:{
        type: Array,
        default: function _default(){
          return [];
        }
      }
  },
  data:function(){
    return {
      asc:{},
      desc:{}
    }
  },
  methods:{
    ascClick:function(){
      this.asc  = {color: '#EA7105'};
      this.desc = {color: '#474747'};
      this.sort('asc');
    },
    descClick:function(){
      this.asc  = {color: '#474747'};
      this.desc = {color: '#EA7105'};
      this.sort('desc');
    },
    sort:function(type){
      var _this = this;
      var _s = this.child;
      var sortdata = this.data.sort(function(a,b){
        if(_s != ''){
          return _this.rank(a[_s],b[_s],type);
        }else{
          return _this.rank(a,b,type);
        }
      });
      this.$emit(type,sortdata);
      return sortdata;
    },
    rank: function(a,b,type){
      var str = this.type;
        var n=m=k=l=0;
        if(str == "ip"){
            n = Number(a.split('.')[2]);
            m = Number(b.split('.')[2]);
            k = Number(a.split('.')[3]);
            l = Number(b.split('.')[3]);
        }else if(str == "num"){
            n = Number(a);
            m = Number(b);
        }else if(str == "time"){
            n = a;
            m = b;
        }
        if(type == 'asc'){
            if(n > m){
                return 1;
            }else if(n == m && str == "ip"){
                return k > l ? 1 : -1;
            }else if(n < m){
                return -1;
            }
        }else{
            if(n > m){
                return -1;
            }else if(n == m && str == "ip"){
                return k > l ? -1 : 1;
            }else if(n < m){
                return 1;
            }
        }
    }
  }
});

//注册密码框类型变换
//调用在input内添加v-pass
Vue.directive('pass',{
    bind:function(el){
        $(el).attr('readonly',false);
        $(el).attr("style","background-color: #FFFFFF!important;cursor:text;");
        $(el).attr("autocomplete","new-password");
        if(el.dataset.type == 'pass'){ //针对一直为暗文的输入框
          $(el).on('focus',function(){
            $(this).prop('type', 'password');
          });
        }else{
          $(el).prop('type', 'password');
          $(el).on('blur',function(){
            $(this).prop('type', 'password');
            $(this).attr('readonly',true);
          }).on('focus',function(){
            $(this).prop('type', 'text');
            $(this).attr('readonly',false);
          })
        }
    }
});

//注册曲线图表
Vue.component('my-echarts',{
    template: '<div :id="echart_id" :style="my_style"></div>',
    props:{
        echart_id:{
            type: String,
            default: 'karen_echart'
        },
        leg:{
            type: Array,
            default: function _default(){
                return [''];
            }
        },
        line_color:{
            type: Array,
            default: function _default(){
                return ['#ED7E36'];
            }
        },
        my_style:{
            default: function _default(){
                return {}
            }
        },
        data_num:{
            type: Number,
            default: 30
        },
        unit:{
            default: 'false'
        },
        title:{
            default: ''
        }
    },
    data:function(){
        return {
            echarts_init: {},
            echarts_data: [],
            echarts_config: {},
            echarts_time: [],
            echarts_start: false
        }
    },
    created:function(){
        if(this.leg.length != this.line_color.length){
            console.error("leg的数组长度与lineColor的数组长度必须等同")
        }
    },
    methods:{
        init:function(){
            var _this = this;
            setTimeout(function(){
              _this.echartInit();
            },500);
        },
        echartInit:function(){
            var echartDom = document.getElementById(this.echart_id);
            this.echarts_init = echarts.init(echartDom);
            this.echarts_time   = new Array(this.data_num);
            this.echarts_time.shift();
            this.echarts_time.push(this.timeInit());
            var leg_num = 1;
            if(this.leg.length != 0) leg_num = this.leg.length;
            
            for(var k=0;k<leg_num;k++){
                this.echarts_data[k] = [];
                this.echarts_data[k] = new Array(this.data_num);
                for(var i=0;i<this.data_num;i++){
                  this.echarts_data[k][i] = '0';
                }
            }
            for(i=0;i<this.data_num;i++){
                this.echarts_time[i] = '';
            }
            var config = [];
            for(var j=0;j<leg_num;j++){
                config.push(
                    {
                        name: this.leg[j],
                        type: 'line',
                        smooth: true,
                        showSymbol: false,
                        itemStyle:{
                          normal: {
                                  width: 1,
                                  color: this.line_color[j]
                              }
                        },
                        data: this.echarts_data[j]
                    }
                );
            }

            this.echarts_config = {
                title: {
                    text: this.title
                },
                tooltip: {
                  trigger:'axis'
                },
                xAxis: [{
                    type: 'category',
                    boundaryGap: false,
                    data: this.echarts_time
                }],
                yAxis: [{
                    splitLine: {show: false}
                }],
               
                legend: {
                    type: "plain",
                    data: this.leg
                },
                series: config,
                animation: false
            };
            this.echarts_init.setOption(this.echarts_config, true);
            this.echarts_start = true;
        },
        setData:function(data){
            if(!this.echarts_start) return ;
            var unit = '';
            this.echarts_time.shift();
            this.echarts_time.push(this.timeInit());
            var _data = data;
            if(this.unit == 'true'){
                data = this.flowToUnit(_data).value;
                unit = this.flowToUnit(_data).unit;
            }
            var data_config = [];
            for(var i=0;i<this.echarts_data.length;i++){
                if(data[i] == undefined) data[i] = 0;
                this.echarts_data[i].shift();
                this.echarts_data[i].push(data[i]);
                data_config.push(
                    {data: this.echarts_data[i]}
                );
            }

            this.echarts_init.setOption({
                xAxis: [{
                    data: this.echarts_time
                }],
                tooltip:{formatter:unit},
                series: data_config
            });
        },
        timeInit:function(){
            var date = new Date();
            var h=date.getHours();
            var m=date.getMinutes();
            var s=date.getSeconds();
            if(h < 10){
              h = '0'+h;
            }
            if(m < 10){
              m = '0'+m;
            }
            return h + ':' + m;
        },
        flowToUnit:function(_value){
            var value = 0, _unit = '',_unit_ = [], _flowvalue = [];
            for(var i=0;i<_value.length;i++){
                value = _value[i];
                value = Number(value);
                var unit = 'B', flowvalue = 0;
                if(value < 1024) {
                  flowvalue = value;
                  unit = 'B';
                }else if(1024 < value && value < (1024*1024)){
                  flowvalue = (value / 1024).toFixed(2);
                  unit = 'KB';
                }else if((1024*1024) < value && value < (1024*1024*1024)){
                  flowvalue = (value / (1024*1024)).toFixed(2);
                  unit = 'M';
                }else if((1024*1024*1024) < value ){
                  flowvalue = (value / (1024*1024*1024)).toFixed(2);
                  unit = 'G';
                }
                _unit += '{a'+i+'}:{c'+i+'}'+unit;
                _unit_.push(unit);
                if(i != _value.length-1) _unit += '<br/>';
                _flowvalue[i] = flowvalue;
            }
            return {unit:_unit,value:_flowvalue,_unit:_unit_};
        }
    }
});
