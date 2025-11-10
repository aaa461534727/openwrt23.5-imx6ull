 /*判断IE浏览器的版本*/
function ie_version() {
    var userAgent = navigator.userAgent; //取得浏览器的userAgent字符串
    var isIE = userAgent.indexOf("compatible") > -1 && userAgent.indexOf("MSIE") > -1; //判断是否IE<11浏览器
    var isEdge = userAgent.indexOf("Edge") > -1 && !isIE; //判断是否IE的Edge浏览器
    var isIE11 = userAgent.indexOf('Trident') > -1 && userAgent.indexOf("rv:11.0") > -1;
    if(isIE) {
        var reIE = new RegExp("MSIE (\\d+\\.\\d+);");
        reIE.test(userAgent);
        var fIEVersion = parseFloat(RegExp["$1"]);
        if(fIEVersion == 7) {
            return 7;
        } else if(fIEVersion == 8) {
            return 8;
        } else if(fIEVersion == 9) {
            return 9;
        } else if(fIEVersion == 10) {
            return 10;
        } else {
            return 6;//IE版本<=7
        }
    } else if(isEdge) {
        return 'edge';//edge
    } else if(isIE11) {
        return 11; //IE11
    }else{
        return -1;//不是ie浏览器
    }
}
var boType = ie_version();
if(boType != -1){   //ie浏览器
    if (boType <= 8){
        location.href = "/error.html";
    }
}
function isSafari(){
    return /Safari/.test(navigator.userAgent) && !/Chrome/.test(navigator.userAgent);
}

/**
 * bootstrap风格开关快速定义
 * @param {String} #xxx  ID
 * @param {[type]} fun 回调函数
 */
function addSwitch(id, fun) {
    $(id).on('switchChange.bootstrapSwitch',function(e,data){
        fun(data);
    });
    setLang();
    $(id).bootstrapSwitch('handleWidth', 30);
    $(id).bootstrapSwitch('labelWidth', 30);
    $('#lang_select').change(function(){
        setLang();
    });
    function setLang() {
        $(id).bootstrapSwitch('onText', lang_t('common.on'));
        $(id).bootstrapSwitch('offText', lang_t('common.off'));
    }

    return function(enable) {
        $(id).bootstrapSwitch('state', enable);
    }
}

/*兼容ie11以下的dataset属性*/
if (window.HTMLElement) {
    if (Object.getOwnPropertyNames(HTMLElement.prototype).indexOf('dataset') === -1) {
        Object.defineProperty(HTMLElement.prototype, 'dataset', {
            get: function () {
                var attributes = this.attributes;
                var name = [],
                    value = [];
                var obj = {};
                for (var i = 0; i < attributes.length; i++) {
                    if (attributes[i].nodeName.slice(0, 5) == 'data-') {
                        name.push(attributes[i].nodeName.slice(5));
                        value.push(attributes[i].nodeValue);
                    }
                }
                for (var j = 0; j < name.length; j++) {
                    obj[name[j]] = value[j];
                }
                return obj;
            }
        });
    }
}

/**
 * 快速错误提示
 * @param  {String} data 提示信息
 */
function errorAlert(data){
  Cstools.msg({
    type: 'error',
    messgetype: 'alert',
    title: lang_t('common.tips'),
    content: data
  })
}

/**
 * 判断设置响应后的数据做出响应的动作
 * @param {Object} data 
 */
function apply_callback(data, t, callback) {
    if (data.success) {
        if (t instanceof Function) {
            callback = t;
            t = 1;
        } else {
            t = t || 1;
        }
        if (data.wtime == "0") data.wtime = 1;
        var wtime = parseInt(data.wtime) || t;
        if (wtime > 2) {
            Cstools.count(wtime, 'js', function() {
                if (callback) callback();
                else location.reload();
            })
        } else {
            Cstools.msg({
                content: lang_t('common.success'),
                type: 'success',
                messgetype: 'no',
                time: wtime,
                timeout: function() {
                    if (callback) callback();
                    else location.reload();
                }
            })
        }
    } else {
        if(globalConfig.specialIotBanApply)
            errorAlert(lang_t('common.fail_fire'));
        else
            errorAlert(lang_t('common.fail'));
    }
}

(function(obj){
   
/**
 * 全局的公有函数
 *
 * @property {function} cs.num(str) 判断此字符串是不是数字 <a href="#num">点击查看</a>
 * @property {function} cs.num_range(str,min,max) 判断是否在数字的范围 <a href="#num_range">点击查看</a>
 * @property {function} cs.port(str)  校验端口是否符合规范（数字必须在1~65535之间） <a href="#port">点击查看</a>
 * @property {function} cs.string(str)   校验字符串是否符合（不能包含无效字符） <a href="#string">点击查看</a>
 * @property {function} cs.string_same(s1,s2)   判断两个字符串是否相同 <a href="#string_same">点击查看</a>
 * @property {function} cs.ssid(str)   检测ssid是否符合规则 <a href="#ssid">点击查看</a>
 * @property {function} cs.hex(str)   检验hex字符 <a href="#hex">点击查看</a>
 * @property {function} cs.ascii(str)   检验ascii字符 <a href="#ascii">点击查看</a>
 * @property {function} cs.key(str)   检验密码是否符合 <a href="#key">点击查看</a>
 * @property {function} cs.mac(str)   校验mac地址 <a href="#mac">点击查看</a>
 * @property {function} cs.mask(str)   校验子网掩码地址 <a href="#mask">点击查看</a>
 * @property {function} cs.ip(str)   校验IP地址 <a href="#ip">点击查看</a>
 * @property {function} cs.ip_mark(str)   校验IP掩码地址 <a href="#ip_mark">点击查看</a> 
 * @property {function} cs.ip_mark_any(str)   校验IP掩码地址/any <a href="#ip_mark_any">点击查看</a>  
 * @property {function} cs.ip_subnet(s1,mn,s2)   检验IP子网段 <a href="#ip_subnet">点击查看</a>
 * @property {function} cs.ip_range(s1,s2)   检验IP范围 <a href="#ip_range">点击查看</a>
 * @property {function} cs.ip_same(s1,s2)   检验IP是否相同 <a href="#ip_same">点击查看</a>
 * @property {function} cs.countdown(msg,time,options,callback)   倒计时通用函数 <a href="#countdown">点击查看</a>
 * @property {function} cs.isIpv6(ip,mask)   IPv6地址判断 <a href="#isIpv6">点击查看</a>
 * @property {function} cs.ip_domain(str)   校验IP/域名是否正确 <a href="#ip_domain">点击查看</a>
 * @property {function} cs.domain(str)   校验域名是否正确 <a href="#domain">点击查看</a> 
 * @property {function} cs.ip2int(ip)   IP转成整型 <a href="#ip2int">点击查看</a>
 * @property {function} cs.commentstr(str)   校验字符串是否符合（对全角字符和特殊字符进行划分，不能包含无效字符） <a href="#commentstr">点击查看</a>
 * @property {function} cs.maskOption()   子网掩码选项 <a href="#maskOption">点击查看</a>
 * @property {function} cs.byteLenght(str,len)   字符串长度判断 <a href="#byteLenght">点击查看</a>
 * @property {function} cs.isInArray(arr,value)   判断一个元素是否存在于一个数组中 <a href="#isInArray">点击查看</a>
 * @property {function} cs.bodyAction(id,id1) 防止去掉了滚动样式(只适用于opnsense) <a href="#bodyAction">点击查看</a>
 * @alias cs
 * @class 
 * @example
 * // 比如调用num函数
 * cs.num('ye') // return 0
 * cs.ip('127.0.0.1') // return 99
 */
function cs(){
    this.version = '0.0.1bate';
    this.author = 'carystudio';
    this.company = 'carystudio';
}

/**
 * 菜单定位
 *
 * @Author   karen       <karen@carystudio.com>
 * @DateTime 2028-9-23
 * @param    {String}   idx     索引值
 * @param    {String}   type    href
 * @return   {String}   子菜单名
 */
cs.prototype.localUrl = function(idx, type){
    if(type == 'href'){        
        var href = location.href;
        if(href.indexOf('?') > -1)
            href = href.split('?')[0];
        location.href = href + get_token_from_url() +'?idx=' + idx;
    }else{
        var search = location.search;
        if(search == ""){
            return idx;
        }
        if(search.indexOf('?') >= 0){
            search = search.replace('?','');
            var temp = search.split('=');
            if(temp[0] == 'idx')
                return temp[1];
            else
                return idx;
        }
    }
};
/**
 * 判断此字符串是不是数字
 * 
 * @Author   Felix       <felix_chen@carystudio.com>
 * @DateTime 2017-10-25
 * @param    {String}   str                   字符串
 * @return   {Number} 
 * 0：不能为空。 <br/>
 * 1：无效，必须是数字 <br/>
 * @example
 * cs.num('carystudio'); // return 0
 */
cs.prototype.num = function(str){
	var ret = 99;	
	if(str == undefined || str=="") { ret = 0;  return ret; }//不能为空
	var reg=/^[0-9]*$/;
	if(!reg.test(str)) ret = 1;//无效，必须是数字
	return ret;
};

/**
 * 判断此字符串是不是数字及小数点
 * 
 * @Author   Felix       <felix_chen@carystudio.com>
 * @DateTime 2017-10-25
 * @param    {String}   str                   字符串
 * @return   {Number} 
 * 0：不能为空。 <br/>
 * 1：无效，必须是数字 <br/>
 * @example
 * cs.num('carystudio'); // return 0
 */
cs.prototype.num_ponit = function(str){
    var ret = 99;   
    //if(str == undefined || str=="") { ret = 0;  return ret; }//不能为空
    var reg = /^\d+$|^\d*\.\d+$/g;
    if(!reg.test(str)) ret = 1;//无效，必须是数字
    return ret;
};


/**
 * 判断是否在数字的范围
 * @Author   Felix       <felix_chen@carystudio.com>
 * @DateTime 2017-10-25
 * @param    {String}   str                   数字值
 * @param    {Number}   min                   最小值
 * @param    {Number}   max                   最大值
 * @return   {Number}                         
 * 0： 不能为空 <br>
 * 1：无效，必须是数字 <br>
 * 2：无效，必须是min~max之间的数字 <br>
 * 99：有效 <br>
 */
cs.prototype.num_range = function (str,min,max){
	var ret = 99;		
	if(str == undefined || str=="") { ret = 0;  return ret; }//不能为空
	var reg=/^[0-9]*$/;
	if(!reg.test(str)) ret = 1;//无效，必须是数字
	if((parseInt(str)<min)||(parseInt(str)>max)) ret = 2;//无效，必须是min~max之间的数字
	return ret;
};

/**
 * 判断是否在数字的范围（包含小数）
 * @Author   Felix       <felix_chen@carystudio.com>
 * @DateTime 2017-10-25
 * @param    {String}   str                   数字值
 * @param    {Number}   min                   最小值
 * @param    {Number}   max                   最大值
 * @return   {Number}                         
 * 0： 不能为空 <br>
 * 1：无效，必须是数字 <br>
 * 2：无效，必须是min~max之间的数字 <br>
 * 99：有效 <br>
 */
cs.prototype.num_range2 = function (str,min,max){
	var ret = 99;		
	if(str == undefined || str=="") { ret = 0;  return ret; }//不能为空
    var reg=/^\d+(\.\d+)?$/;
	if(!reg.test(str)) ret = 1;//无效，必须是数字
	if((Number(str)<min)||(Number(str)>max)) ret = 2;//无效，必须是min~max之间的数字
	return ret;
};

/**
 * 校验端口是否符合规范（数字必须在1~65535之间）
 * 
 * @Author   Felix       <felix_chen@carystudio.com>
 * @DateTime 2017-10-25
 * @param    {String}   str                   数字值
 * @return   {Number}                      
 * 0: 不能为空 <br/>
 * 1: 无效，必须是数字 <br/>
 * 2: 无效，必须是1~65535之间的数字 <br/>
 * 99: 有效
 */
cs.prototype.port = function (str){
	var ret = 99;		
	if(str == undefined || str=="") { ret = 0;  return ret; }//不能为空
	var reg=/^[0-9]*$/;
	if(!reg.test(str)) ret = 1;	//无效，必须是数字	
	if(parseInt(str)<1||parseInt(str)>65535) ret = 2;//无效，必须是1~65535之间的数字
	return ret;
};

/**
 * 校验字符串是否符合（不能包含无效字符）
 * 
 * @Author   Felix       <felix_chen@carystudio.com>
 * @DateTime 2017-10-25
 * @param    {String}   str                   字符串
 * @return   {Number}        
 * 0: 不能为空 <br/>
 * 1: 无效，包含了无效的字符 <br/> 
 * 99: 有效             
 * 
 */
cs.prototype.string = function (str,type){
    var ret = 99;       
    if(str == undefined || str=="") { ret = 0;  return ret; }//不能为空
    if(/[\xB7]/.test(str))  ret = 1;//无效，包含了无效的字符
    if(/[^\x00-\xff]/.test(str)) ret = 1;   //无效，包含了无效的字符   
    
    var re1=/[^\x20-\x7D]/;
    var re2;
    if(type == 'portal'){
        re2=/[\x20\x22\x24\x25\x27\x2C\x3B\x3C\x3E\x5C\x60]/;
    }else{
        re2=/[\x20\x22\x24\x25\x27\x2C\x2F\x3B\x3C\x3E\x5C\x60]/;
    }
    if(re1.test(str)||re2.test(str)) ret = 1;//无效，包含了无效的字符
    return ret;
};

cs.prototype.string1 = function (str){
    var ret = 99;
    var reg=/^[a-zA-Z0-9_-]*$/;
    if(str == undefined || str=="") { ret = 0;  return ret; }//不能为空
    if(!reg.test(str)) return 1;
    return ret;
};

cs.prototype.string2 = function (str){
    var ret = 99;
    var reg = /^[a-zA-Z0-9,!_-]*$/;
    if(str == undefined || str=="") { ret = 0;  return ret; }//不能为空
    if(!reg.test(str)) return 1;
    return ret;
};


cs.prototype.valid_name = function (str){
    if(!this.isascii(str)) return 1;

    var bbb = str.replace(/^\s*/,"");
    str = bbb.replace(/\s*$/,"");
    for(var i=0 ; i<str.length; i++){
        var ch = str.charAt(i);
        if(ch == ' ' || ch == '!' || ch == '?' || ch == '\"' || ch == '\\' || ch == '<' || ch == '>') {
            return 2;
        }
    }
    return 99;
};

cs.prototype.isascii = function (str){
    for(var i=0 ; i<str.length; i++){
        var ch = str.charAt(i);
        if(ch < ' ' || ch > '~'){
            return false;
        }
    }
    return true;
};

    /**
 * 判断两个字符串是否相同
 * @Author   Felix       <felix_chen@carystudio.com>
 * @DateTime 2017-12-21
 * @param    {String}   s1
 * @param    {String}   s2
 * @return   {Number}
 * 0: 是 <br/>
 * 1: 否 
 */
cs.prototype.string_same = function (s1,s2){
    if (undefined == s1 || undefined == s2) return 1;
	if (ip1==ip2) return 0;
	return 1;
};

/**
 * 检测ssid是否符合规则
 * 规则：不能超过32个汉字，不能含有特殊字符。
 * 
 * @Author   Felix       <felix_chen@carystudio.com>
 * @DateTime 2017-10-25
 * @param    {String}   str                   SSID字符串
 * @return   {Number}                         
 * 0: 不能为空 <br/>
 * 1: 无效，包含了无效的字符 <br/> 
 * 2: 无效，不能超过32个字符 <br/> 
 * 4: 无线名称(SSID)不能以“空格”开始或结尾
 * 99: 有效   
 */
cs.prototype.ssid = function (str){
    var ret = 99;
    if(str == undefined || str==""){ ret = 0;  return ret; }
    if(str[0] == ' ' || str[str.length-1] == ' '){
        return 4;
    }
    var reg=/[\x22\x24\x25\x27\x2C\x2F\x3B\x3C\x3E\x5C\x60\x7E]/;
    if(reg.test(str)) ret = 1;
    //for chinese
    // 。 ？ ！ ， 、 ； ： “ ” ‘ ' （ ） 《 》 〈 〉 【 】 『 』 「 」 ﹃ ﹄ 〔 〕 … — ～ ﹏ ￥
    var china = /[\u3002\uff1f\uff01\uff0c\u3001\uff1b\uff1a\u201c\u201d\u2018\u2019\uff08\uff09\u300a\u300b\u3008\u3009\u3010\u3011\u300e\u300f\u300c\u300d\ufe43\ufe44\u3014\u3015\u2026\u2014\uff5e\ufe4f\uffe5]/;
    if(china.test(str)) ret = 1;
    
    var strlen = 0;
    for(var i = 0;i < str.length; i++){
        if(str.charCodeAt(i) > 255) strlen += 3;
        else strlen++;
    }
    //if(strlen>29) ret = 3;
    if(strlen>32) ret = 2;
    return ret;
};

/**
 * ???
 * @Author   Felix       <felix_chen@carystudio.com>
 * @DateTime 2017-10-25
 * @param    {String}   str                   字符串
 * @return   {Number}                         返回0失败，1成功
 */
cs.prototype.hex = function (str){
	var reg=/[^A-Fa-f0-9]/;
	if(reg.test(str)) return 0;
	return 1;	
};

/**
 * ???
 * @Author   Felix       <felix_chen@carystudio.com>
 * @DateTime 2017-10-25
 * @param    {String}   str                   字符串
 * @return   {Number}                         返回0失败，1成功
 */
cs.prototype.ascii = function (str){
	var re1=/[^\x20-\x7D]/;
	var re2=/[\x20\x22\x24\x25\x27\x2C\x2F\x3B\x3C\x3E\x5C\x60]/;
	if(re1.test(str)||re2.test(str)) return 0;
	return 1;	
};

/**
 * ???
 * @Author   Felix       <felix_chen@carystudio.com>
 * @DateTime 2017-10-25
 * @param    {String}   str                   字符串
 * @return   {Number}
 * 0: 不能为空 <br/>
 * 1: 无效，不是合法的MAC地址<br/> 
 * 2: 无效，必须是16进制编码的字符<br/> 
 * 3: 无效，不能包括空格<br/> 
 * 99: 有效
 */
cs.prototype.key = function (str){
	var ret = 99;		
	if(str == undefined || str=="") { ret = 0;  return ret; }
    var reg=/[\x20\x21\x22\x24\x25\x26\x27\x2C\x2F\x3B\x3C\x3E\x3F\x5C\x5E\x60\x7C\x7E]/;
    //!^&|?不允许
    if(reg.test(str)){ ret = 1; return ret;}
    reg = /[^\x00-\xff]/;   //双字节
    if(reg.test(str)){ ret = 2; return ret;}
	return ret;
};

/**
 * 校验mac地址
 * 
 * @Author   Felix       <felix_chen@carystudio.com>
 * @DateTime 2017-10-26
 * @param    {String}   str                   传入mac字符串	
 * @return   {Number}
 * 0: 不能为空 <br/>
 * 1: 无效，不是合法的MAC地址<br/> 
 * 2: 无效，不是有效的MAC地址<br/> 
 * 3: 无效，不是有效的MAC地址<br/> 
 * 99: 有效
 */
cs.prototype.mac = function (str){
	var ret = 99;		
	if(undefined == str || str==":::::"){ ret = 0;  return ret; }
	var reg=/[A-Fa-f0-9]{2}:[A-Fa-f0-9]{2}:[A-Fa-f0-9]{2}:[A-Fa-f0-9]{2}:[A-Fa-f0-9]{2}:[A-Fa-f0-9]{2}/;
    if((!reg.test(str)) || str.length >17) ret = 1;	
	if(str=="00:00:00:00:00:00"||str.toUpperCase()=="FF:FF:FF:FF:FF:FF") ret = 2;
	for(var k=0;k<str.length;k++){
		if((str.charAt(1)&0x01)||(str.charAt(1).toUpperCase()=='B')||(str.charAt(1).toUpperCase()=='D')||(str.charAt(1).toUpperCase()=='F'))
			ret = 3;
	}
	return ret;
};

/**
 * 校验子网掩码地址
 * 
 * @Author   Felix       <felix_chen@carystudio.com>
 * @DateTime 2017-10-26
 * @param    {String}   str                   传入mac字符串	
 * @return   {Number}
 * 0: 不能为空 <br/>
 * 1: 无效，不是合法的掩码地址<br/> 
 * 99: 有效
 */
cs.prototype.mask = function(str){
	var ret = 99;		
	if(undefined == str || str=="") { ret = 0;  return ret; }
	var reg=/^(?:(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\.){3}(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))$/;
	if(!reg.test(str)) ret = 1;
	var buf=str.split(".");
    var k=/^(255|254|252|248|240|224|192|128)(\.0){3}?$|^255\.(254|252|248|240|224|192|128|0)(\.0){2}?$|^255\.255\.(254|252|248|240|224|192|128|0)(\.0)?$|^255\.255\.255\.(254|252|248|240|224|192|128|0)$/;
    if (!k.test(str)) ret = 1;
    return ret;
};

/**
 * 校验IP地址
 * 
 * @Author   Felix       <felix_chen@carystudio.com>
 * @DateTime 2017-10-26
 * @param    {String}   str                   传入ip字符串	
 * @return   {Number}
 * 0: 不能为空 <br/>
 * 1: 无效，不是合法的IP地址<br/> 
 * 2: 无效，第1段必须是1~254之间的数字<br/> 
 * 3: 无效，第2、3段必须是0~254之间的数字<br/> 
 * 4: 无效，第4段必须是1~254之间的数字<br/> 
 * 99: 有效
 */
cs.prototype.ip = function (str){
	var ret = 99;
	if(undefined == str || str=="") { ret = 0;  return ret; }
	var reg=/^(?:(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\.){3}(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))$/;
	if(!reg.test(str)) return 1;
	var buf=str.split(".");
	if(buf[0]==0||buf[0]>223) return 2;
	if(buf[1]>255||buf[2]>255) return 3;
	if(buf[3]<1||buf[3]>254) return 4;
	return ret;
};

/**
 * IP合法性，支持特殊网段如0.0.0.0
 * @param {*} ip 
 */
cs.prototype.ip_seg = function (ip){
    var exp = /^(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])$/;
    var reg = ip.match(exp);
    if(reg == null){
        return false; //不合法
    }else {
        return true; //合法
    }
};

/**
 * 特殊IP校验
 * @param {String} str 
 */
cs.prototype.ip2 = function (str){
    var ret = 99;
    if(undefined == str || str=="") { ret = 0;  return ret; }
    var reg=/^(?:(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\.){3}(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))$/;
    if(!reg.test(str)) ret = 1;
    var buf=str.split(".");
    if(buf[0]>254||buf[1]>254||buf[2]>254||buf[3]>254) ret = 2;
    return ret;
};

/**
 * 校验IPv6地址
 *
 * @Author   Jeff       <kejianfu@carystudio.com>
 * @DateTime 2017-10-26
 * @param    {String}   str                   传入ipv6字符串  2001:d0b0:3000:3001::1/64
 * @return   {Number}
 * 0: 不能为空 <br/>
 * 1: 无效，不是合法的IPv6地址<br/>
 * 99: 有效
 */
cs.prototype.ipv6_mask = function (str){
    if(str == ''){
        return 0;
    }
    if(str.indexOf("/") == -1) {
        return 1;
    }
    var exp = /^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$/;
    var addr = str.split("/");
    if(!exp.test(addr[0])) {
        return 1;
    }
    var substr = str.substring(0, 4);
    if(substr == 'FE80' || substr == 'fE80' || substr == 'Fe80' || substr == 'fe80') {
        // alert("IPv6输入的地址是配置全局单播地址时的链接本地地址。");
        return 2;
    }
    if(substr == '::1/') {
        // alert("输入的地址是环回IPv6地址。");
        return 3;
    }
    if(substr == 'FF00' || substr == 'Ff00' || substr == 'fF00' || substr == 'ff00') {
        // alert("IPv6输入的地址是多播IPv6地址。");
        return 4;
    }
    substr = str.substring(0, 3);
    if(substr == '::/') {
        // alert("IPv6输入的地址是未指定的IPv6地址。");
        return 5;
    }
    if(parseInt(addr[1]) > 128 || parseInt(addr[1]) < 1) {
        return 1;
    }
    return 99;
};
cs.prototype.ipv6 = function (str){
    if(str == ''){
        return 0;
    }
    var exp = /^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$/;
    if(!exp.test(str)) {
        return 1;
    }
    var substr = str.substring(0, 4);
    if(substr == 'FE80' || substr == 'fE80' || substr == 'Fe80' || substr == 'fe80') {
        // alert("IPv6输入的地址是配置全局单播地址时的链接本地地址。");
        return 2;
    }
    if(substr == '::1/') {
        // alert("输入的地址是环回IPv6地址。");
        return 3;
    }
    if(substr == 'FF00' || substr == 'Ff00' || substr == 'fF00' || substr == 'ff00') {
        // alert("IPv6输入的地址是多播IPv6地址。");
        return 4;
    }
    substr = str.substring(0, 3);
    if(substr == '::/') {
        // alert("IPv6输入的地址是未指定的IPv6地址。");
        return 5;
    }
    return 99;
};

/**
 *  校验IP掩码地址 
 * 
 * @Author   Felix       <felix_chen@carystudio.com>
 * @DateTime 2020-3-19
 * @param    {String}   str                   传入ip字符串	
 * @return   {Number}
 * 0: 不能为空<br/>
 * 1: 格式无效<br/> 
 * 2: 无效，不是合法的IP地址<br/> 
 * 3: 无效，第1段必须是0~223之间的数字<br/> 
 * 4: 无效，第2、3段必须是1~255之间的数字<br/> 
 * 5: 无效，第4段必须是1~254之间的数字<br/>
 * 6: 无效，必须是数字<br/>
 * 7: 无效，必须是1~32之间的数字<br/>
 * 99: 有效
 */
cs.prototype.ip_mark = function (str){
    var ret = 99;
    if(undefined == str || str=="") { ret = 0;  return ret; }
    if(str.indexOf("/") == -1) return 1;
    var head = str.split("/")[0];
    var end = str.split("/")[1];
    var reg=/^(?:(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\.){3}(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))$/;
    if(!reg.test(head)) return 2;
    var buf=head.split(".");
    if(buf[0]==0 || buf[0] > 223) return 3;
    if(buf[1]>255||buf[2]>255) return 4;
    if(buf[3]>254) return 5;

    var reg=/^[0-9]*$/;
    if(undefined == end || end=="") return 6;//无效，必须是数字
    if(!reg.test(end)) return 6;//无效，必须是数字
    if((parseInt(end)<1)||(parseInt(end)>32)) return 7;//无效，必须是1~32之间的数字

    return ret;
};

/**
 * 子网掩码
 * @param {String} str 
 */
cs.prototype.ip_mark2 = function (str){
    var ret = 99;
    if(undefined == str || str=="") { ret = 0;  return ret; }
    var reg=/^(?:(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\.){3}(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))$/;
    if(!reg.test(str)) ret = 1;
    var buf=str.split(".");
    if(buf[0]>254||buf[1]>254||buf[2]>254||buf[3]>254) ret = 2;
    return ret;
};

/**
 *  校验IP掩码地址/any 
 * 
 * @Author   Felix       <felix_chen@carystudio.com>
 * @DateTime 2020-3-19
 * @param    {String}   str                   传入ip字符串   
 * @return   {Number}
 * 0: 不能为空<br/>
 * 1: 格式无效<br/> 
 * 2: 无效，不是合法的IP地址<br/> 
 * 3: 无效，第1段必须是0~223之间的数字<br/> 
 * 4: 无效，第2、3段必须是1~255之间的数字<br/> 
 * 5: 无效，第4段必须是1~254之间的数字<br/>
 * 6: 无效，必须是数字<br/>
 * 7: 无效，必须是1~32之间的数字<br/>
 * 8: 无效，可以仅是any<br/>
 * 99: 有效
 */
cs.prototype.ip_mark_any = function (str){
    var ret = 99;
    if(undefined == str || str=="") { ret = 0;  return ret; }

    if(str.indexOf("/") > 0){//ip/mark
        if(str.indexOf("/") == -1) return 1;
        var head = str.split("/")[0];
        var end = str.split("/")[1];
        var reg=/^(?:(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\.){3}(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))$/;
        if(!reg.test(head)) return 2;
        var buf=head.split(".");
        if(buf[0]==0) return 3;
        if(buf[1]>255||buf[2]>255) return 4;
        if(buf[3]>254) return 5;

        var reg=/^[0-9]*$/;
        if(undefined == end || end=="") return 6;//无效，必须是数字
        if(!reg.test(end)) return 6;//无效，必须是数字
        if((parseInt(end)<1)||(parseInt(end)>32)) return 7;//无效，必须是1~32之间的数字
    }else if(str=='any'){//any
        return 99;
    }else if(str!='any'){//ip
        if(str.indexOf(".") > 0){
            var reg=/^(?:(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\.){3}(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))$/;
            if(!reg.test(str)) return 1;
            var buf=str.split(".");
            if(buf[0]==0||buf[0]>223) return 2;
            if(buf[1]>255||buf[2]>255) return 3;
            if(buf[3]<1||buf[3]>254) return 4;
        }else{
            return 8;
        }
    }

    return ret;
};

/**
 * ???
 * @Author   Felix       <felix_chen@carystudio.com>
 * @DateTime 2017-10-26
 * @param    {String}   s1                    ???
 * @param    {String}   mn                    ???
 * @param    {String}   s2                    ???
 * @return   {Number}
 * ???
 */
cs.prototype.ip_subnet = function (s1,mn,s2){
	var ip1=s1.split(".");
	var ip2=s2.split(".");
	var ip3=mn.split(".");
	for(var k=0;k<=3;k++){
		if((ip1[k]&ip3[k])!=(ip2[k]&ip3[k])) return 0;
	}
	return 1;
};

/**
 * 判断IP地址1是否大于IP地址2
 * @Author   Felix       <felix_chen@carystudio.com>
 * @DateTime 2017-10-26
 * @param    {String}   s1                    IP地址1
 * @param    {String}   s2                    IP地址2
 * @return   {Number}
 * 0: 是 <br/>
 * 1: 否 
 */
cs.prototype.ip_range = function (s1,s2){
    if (undefined == s1 || undefined == s2) {
        return 1;
    }
    var ip1=s1.split(".")[3];
    var ip2=s2.split(".")[3];
    if (Number(ip1)>Number(ip2)) return 0;
	return 1;
};

/**
 * 判断两个ip地址是否相同
 * @Author   Felix       <felix_chen@carystudio.com>
 * @DateTime 2017-10-26
 * @param    {String}   s1                    IP地址1
 * @param    {String}   s2                    IP地址2
 * @return   {Number}
 * 0: 是 <br/>
 * 1: 否 
 */
cs.prototype.ip_same = function (s1,s2){
    if (undefined == s1 || undefined == s2) {
        return 1;
    }
	var ip1=s1.replace(/\.\d{1,3}$/,".");
	var ip2=s2.replace(/\.\d{1,3}$/,".");
	if (ip1==ip2) return 0;
	return 1;
};

/**
 * IPv6地址判断
 *
 * @Author   Felix       <felix_chen@carystudio.com>
 * @DateTime 2018-06-21
 * @param    {String}   str     传入IPv6地址字符串 
 */
cs.prototype.isIpv6 = function (str){
    var ret = 99;
    if(!( /:/.test(str) &&str.match(/:/g).length<8&&/::/.test(str)
        ?(str.match(/::/g).length==1&&/^::$|^(::)?([\da-f]{1,4}(:|::))*[\da-f]{1,4}(:|::)?$/i.test(str))
        :/^([\da-f]{1,4}:){7}[\da-f]{1,4}$/i.test(str))
        ){ ret = 0;  }
        return ret;
};

/*校验IP/域名是否正确*/
cs.prototype.ip_domain = function (str){
    var ret = 99;
    var exp=/^(?:(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\.){3}(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))$/;
    if(str.match(exp)==null){//域名模式
        var reg =/^[a-zA-Z0-9\.\-\_][a-zA-Z0-9\.\-\_]+$/;
        if(!reg.test(str)) return 1;
        if(str.indexOf('.')==-1) return 1;
    }else{//IP模式  
        var reg=/^(?:(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\.){3}(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))$/;
        if(!reg.test(str)) return 1;
        var buf=str.split(".");
        if(buf[0]==0) return 1;
        if(buf[1]>255||buf[2]>255) return 1;
        if(buf[3]==0||buf[3]>254) return 1;
    }

    return ret;
};

cs.prototype.ip_domain_ipsec = function (str){
    var ret = 99;
    var exp=/^(?:(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\.){3}(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))$/;
    if(str.match(exp)==null){//域名模式
        var reg =/^[a-zA-Z0-9\.\-\_][a-zA-Z0-9\.\-\_]+$/;
        if(!reg.test(str)) return 1;
        if(str.indexOf('.')==-1) return 1;
    }else{//IP模式  
        var reg=/^(?:(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\.){3}(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))$/;
        if(!reg.test(str)) return 1;
        var buf=str.split(".");
        if(buf[0]>255||buf[1]>255||buf[2]>255||buf[3]>254) return 1;//允许0.0.0.0
    }

    return ret;
};

/*校验域名是否正确*/
cs.prototype.domain = function (str){
    var ret = 99;
    var reg =/^[a-zA-Z\.\-\_][a-zA-Z0-9\.\-\_]+$/;
    if(!reg.test(str)) return 1;
    if(str.indexOf('.')==-1) return 1;

    return ret;
};

/**
 * 菜单定位
 *
 * @Author   Karen       <karen@carystudio.com>
 * @DateTime 2018-10-10
 * @param    {String}   name     传入子菜单名
 * @return   {String}   子菜单名
 */
cs.prototype.local = function(name){
    var search = location.search;
    if (!!~search.indexOf('page=')) {
        return search.match(/page=(\d+)/)[1];
    } else {
        return '';
    }
};

/**
 * 菜单定位
 *
 * @Author   karen       <karen@carystudio.com>
 * @DateTime 2028-9-23
 * @param    {String}   idx     索引值
 * @param    {String}   type    href
 * @return   {String}   子菜单名
 */
cs.prototype.localUrl = function(idx, type){
    if(type == 'href'){        
        var href = location.href;
        if(href.indexOf('?') > -1)
            href = href.split('?')[0];
		location.href = href + get_token_from_url() + '&idx=' + idx;
    }else{
        var search = location.search;
        if(search == ""){
            return idx;
        }
        if(search.indexOf('?') >= 0){
            search = search.replace('?','');
            var temp = search.split('=');
            if(temp[0] == 'idx')
                return temp[1];
            else
                return idx;
        }
    }
};
/**
 * 菜单跳转
 *
 * @Author   Karen       <karen@carystudio.com>
 * @DateTime 2018-10-10
 * @param    {String}   name     传入子菜单名
 */
cs.prototype.href = function(name){
    if (!!~location.search.indexOf('page=')) {
        location.search = location.search.replace(/^(?!time=)\d+/,new Date().getTime());
    } else {
        location.search = location.search+'&page='+name;
    }
    //location.href = location.origin+location.pathname+'?'+name;
};
/**
 * IP转成整型
 *
 * @Author   Jeff       <Jeff@carystudio.com>
 * @DateTime 2018-02-26
 * @param    {String}   ip
 * @return   {Number}   IP整形
 */
cs.prototype.ip2int= function (ip){
    var num = 0;
    ip = ip.split(".");
    num = Number(ip[0]) * 256 * 256 * 256 + Number(ip[1]) * 256 * 256 + Number(ip[2]) * 256 + Number(ip[3]);
    num = num >>> 0;
    return num;
};
/**
 * 校验描述字符串是否符合（不能包含无效字符）
 * 
 * @Author   karen       <karen@carystudio.com>
 * @DateTime 2018-01-29
 * @param    {String}   str                   字符串
 * @return   {Number}        
 * 0: 不能为空 <br/>
 * 1: 无效，包含了全角字符 <br/>
 * 2: 无效，不包含空格'"$%,/\<>;特殊字符 <br/>
 * 99: 有效             
 * 
 */
cs.prototype.commentstr = function (str){
    var ret = 99;       
    if(str == undefined || str=="") { ret = 0;  return ret; }//不能为空
    if(/[\xB7]/.test(str))  ret = 1;//无效，包含了无效的字符
    if(/[^\x00-\xff]/.test(str)) ret = 1;   //无效，包含了全角字符    

    var re=/[\x20\x22\x24\x25\x27\x2C\x2F\x3B\x3C\x3E\x5C\x60\x7E]/;
    if(re.test(str)) ret = 2;//无效，不包含空格'"$%,/\<>;特殊字符
    return ret;
};
/**
 * 使用循环的方式判断一个元素是否存在于一个数组中
 * @Author   Amy       <amy@carystudio.com>
 * @DateTime 2018-3-27
 * @param {Object} arr 数组
 * @param {Object} value 元素值
 */
cs.prototype.isInArray= function (arr,value){
    for(var i = 0; i < arr.length; i++){
        if(value === arr[i]){
            return true;
        }
    }
    return false;
};
/**
 * 容量数据单位换算
 * @Author   Yexk       <yexk@carystudio.com>
 * @DateTime 2018-01-17
 * @param    {Number}   bytes                 字节数
 * @return   {String}                         换算后的单位
 * @example
 * console.log(cs.bytesToSize(1024)); // 1KB
 */
cs.prototype.bytesToSize = function(bytes) {
  if (bytes === 0) return '0 B';
    var k = 1000, // or 1024
        sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'],
        i = Math.floor(Math.log(bytes) / Math.log(k));
 
   return (bytes / Math.pow(k, i)).toPrecision(3) + ' ' + sizes[i]; 
};

cs.prototype.bytesToSize1 = function(bytes) {
    if (bytes === 0) return '0 Kb/s';
    var k = 1000, // or 1024
        sizes = ['Kb/s', 'Mb/s', 'Gb/s', 'Tb/s', 'Pb/s', 'Eb/s', 'Zb/s', 'Yb/s'],
        i = Math.floor(Math.log(bytes) / Math.log(k));

    return (bytes / Math.pow(k, i)).toPrecision(3) + ' ' + sizes[i];
};
/**
 * 字符长度计算
 * @Author   Karen       <Karen@carystudio.com>
 * @DateTime 2018-12-21
 * @param    {String}   str                 字符串
 * @param    {Number}   len                 限制长度
 * @return   {String}                       计算结果
 * @example
 * console.log(cs.byteLenght(str,32)); 
 */
cs.prototype.byteLenght = function(str,len){
    if(len == undefined || typeof(len) != 'number') return 0;
    var strlen = 0;
    for(var i = 0;i < str.length; i++){
        if(str.charCodeAt(i) > 255) strlen += 3;
        else strlen++;
    }
    if(strlen > len) return 1;
    return 99;
};
/**
 * 防止去掉了滚动样式(只适用于opnsense)
 * @Author   Karen       <Karen@carystudio.com>
 * @DateTime 2019-02-22
 * @param    {String}   id               关闭模态框的id
 * @param    {String}   id1              打开模态框的id
 * @return   {String}                     
 * @example
 * 
 */
cs.prototype.bodyAction = function(id,id1){
    $('#'+id).on('hidden.bs.modal', function (e) {
        if($('#'+id1).css('display') != 'block'){
           $('body').removeClass('modal-open');
        }else{
          $('body').addClass('modal-open');
        }
    });
};

/**
 * 校验LAN ip 与 WAN ip 是否在相同子网
 * @Author   Felix       <felix_chen@carystudio.com>
 * @DateTime 2017-10-26
 * @param    {String}   s1                    lan ip地址
 * @param    {String}   mk1                   lan 子网掩码
 * @param    {String}   s2                    wan ip地址
 * @param    {String}   mk2                   wan 子网掩码
 * @return   {Number}
 *  0: 不在同一子网 <br/>
 *  1: 在同一子网 <br/>
 */
cs.prototype.ip_subnet2 = function (s1,mk1,s2,mk2){
    var ip1=s1.split(".");
    var ip2=s2.split(".");
    var mask1=mk1.split(".");
    var mask2=mk2.split(".");
    for(var k=0;k<=3;k++){
        if((ip1[k]&mask1[k])!=(ip2[k]&mask2[k])) {
            return 0;
        }
    }
    return 1;
};

cs.prototype.checkRssi = function (str,min,max){
    var ret = 99;

   
    var re=/^(0|-[1-9][0-9]*)$/;
    if(!re.test(str))  ret = 2    
    if(str == undefined || str == '' ) ret = 1;
    if((parseInt(str)<min)||(parseInt(str)>max)) ret = 3;
    return ret;
};

cs.prototype.myCheckIp = function (str){
    var ret = 99;
    if(undefined == str || str=="") { ret = 0;  return ret; }
    var reg=/^(?:(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\.){3}(?:25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))$/;
    if(!reg.test(str)) ret = 1;
    var buf=str.split(".");
    if(buf[0]<1||buf[0]>255) ret = 2;
    if(buf[1]>255||buf[2]>255) ret = 3;
    if(buf[3]<1||buf[3]>254) ret = 4;
    return ret;
};
/*校验域名是否正确*/
cs.prototype.isUrl = function (str_url) {
    var strRegex = '^((https|http|ftp|rtsp|mms)?://)'
        + '?(([0-9a-z_!~*\'().&=+$%-]+: )?[0-9a-z_!~*\'().&=+$%-]+@)?' //ftp的user@
        + '(([0-9]{1,3}.){3}[0-9]{1,3}' // IP形式的URL- 199.194.52.184
        + '|' // 允许IP和DOMAIN（域名）
        + '([0-9a-z_!~*\'()-]+.)*' // 域名- www.
        + '([0-9a-z][0-9a-z-]{0,61})?[0-9a-z].' // 二级域名
        + '[a-z]{2,6})' // first level domain- .com or .museum
        + '(:[0-9]{1,4})?' // 端口- :80
        + '((/?)|' // a slash isn't required if there is no file name
        + '(/[0-9a-z_!~*\'().;?:@&=+$,%#-]+)+/?)$';
    var re=new RegExp(strRegex);
    if (re.test(str_url)) {
        return (true);
    } else {
        return (false);
    }
};


/**
 * 时间戳转时间格式
 * @Author   Jeff       <Jeff@carystudio.com>
 * @DateTime 2018-03-05
 * @param    {String}	时间戳
 * @param    {String}	时间格式	"yyyy-MM-d hh:mm:ss"
 * @return   {String}                         换算后的时间
 * @example
 * console.log(cs.bytesToSize(1024)); // 1KB
 */
cs.prototype.formatDate = function(date, fmt) {
    var data = parseInt(date+'000');
    var d = new Date(data);
    var o = {
        "M+": d.getMonth() + 1, //month
        "d+": d.getDate(),    //day
        "h+": d.getHours(),   //hour
        "m+": d.getMinutes(), //minute
        "s+": d.getSeconds(), //second
        "q+": Math.floor((d.getMonth() + 3) / 3),  //quarter
        "S": d.getMilliseconds() //millisecond
    }
    if (/(y+)/.test(fmt)) {
        fmt = fmt.replace(RegExp.$1,(d.getFullYear() + "").substr(4 - RegExp.$1.length));
    }
    for (var k in o) {
        if (new RegExp("(" + k + ")").test(fmt)) {
            fmt = fmt.replace(RegExp.$1, RegExp.$1.length == 1 ? o[k] : ("00" + o[k]).substr(("" + o[k]).length));
        }
    }
    return fmt;
};

cs.prototype.maskOption = function(){
    return [
          {
            option: "255.255.255.248(29)",
            value: "255.255.255.248",
            long:29
          },{
            option: "255.255.255.240(28)",
            value: "255.255.255.240",
            long:28
          },{
            option: "255.255.255.224(27)",
            value: "255.255.255.224",
            long:27
          },{
            option: "255.255.255.192(26)",
            value: "255.255.255.192",
            long:26
          },{
            option: "255.255.255.128(25)",
            value: "255.255.255.128",
            long:25
          },{
            option: "255.255.255.0(24)",
            value: "255.255.255.0",
            long:24
          },{
            option: "255.255.254.0(23)",
            value: "255.255.254.0",
            long:23
          },{
            option: "255.255.252.0(22)",
            value: "255.255.252.0",
            long:22
          },{
            option: "255.255.248.0(21)",
            value: "255.255.248.0",
            long:21
          },{
            option: "255.255.240.0(20)",
            value: "255.255.240.0",
            long:20
          },{
            option: "255.255.224.0(19)",
            value: "255.255.224.0",
            long:19
          },{
            option: "255.255.192.0(18)",
            value: "255.255.192.0",
            long:18
          },{
            option: "255.255.128.0(17)",
            value: "255.255.128.0",
            long:17
          },{
            option: "255.255.0.0(16)",
            value: "255.255.0.0",
            long:16
          },{
            option: "255.254.0.0(15)",
            value: "255.254.0.0",
            long:15
          },{
            option: "255.252.0.0(14)",
            value: "255.252.0.0",
            long:14
          },{
            option: "255.248.0.0(13)",
            value: "255.248.0.0",
            long:13
          },{
            option: "255.240.0.0(12)",
            value: "255.240.0.0",
            long:12
          },{
            option: "255.224.0.0(11)",
            value: "255.224.0.0",
            long:11
          },{
            option: "255.192.0.0(10)",
            value: "255.192.0.0",
            long:10
          },{
            option: "255.128.0.0(9)",
            value: "255.128.0.0",
            long:9
          },{
            option: "255.0.0.0(8)",
            value: "255.0.0.0",
            long:8
          },{
            option: "254.0.0.0(7)",
            value: "254.0.0.0",
            long:7
          },{
            option: "252.0.0.0(6)",
            value: "252.0.0.0",
            long:6
          },{
            option: "248.0.0.0(5)",
            value: "248.0.0.0",
            long:5
          },{
            option: "240.0.0.0(4)",
            value: "240.0.0.0",
            long:4
          },{
            option: "224.0.0.0(3)",
            value: "224.0.0.0",
            long:3
          },{
            option: "192.0.0.0(2)",
            value: "192.0.0.0",
            long:2
          },{
            option: "128.0.0.0(1)",
            value: "128.0.0.0",
            long:1
          }
      ];
};
obj.cs = new cs();
})(window);

function checkIp(ip) {
  var obj = ip;
  var exp = /^(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])$/;
  var reg = obj.match(exp);
  if(reg == null){
    return false;
  }else {
    return true;
  }
}

function isEqualIPAddress(ip1,ip2,mask1) {
  var res1 = [], res2 = [];
  var addr1 = ip1.split(".");
  var addr2 = ip2.split(".");
  var mask  = mask1.split(".");
  for(var i = 0,ilen = addr1.length; i < ilen ; i += 1){
    res1.push(parseInt(addr1[i]) & parseInt(mask[i]));
    res2.push(parseInt(addr2[i]) & parseInt(mask[i]));
  }
  if(res1.join(".") == res2.join(".")){
    return true;
  }else{
    return false;
  }
}