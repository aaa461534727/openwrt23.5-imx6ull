'use strict';

function isLowIe(){
	var userAgent = navigator.userAgent;
    var isIE = userAgent.indexOf("compatible") > -1 && userAgent.indexOf("MSIE") > -1; //判断是否IE<11浏览器  
    var isEdge = userAgent.indexOf("Edge") > -1 && !isIE;
    var isIE11 = userAgent.indexOf('Trident') > -1 && userAgent.indexOf("rv:11.0") > -1;
    if(isIE) {
        var reIE = new RegExp("MSIE (\\d+\\.\\d+);");
        reIE.test(userAgent);
        var fIEVersion = parseFloat(RegExp["$1"]);
        if(Number(fIEVersion) < 7){
        	return true;
        }  
    }
    return false;
}

if (!document.querySelectorAll) {
    document.querySelectorAll = function (selectors) {
        var style = document.createElement('style'), elements = [], element;
        document.documentElement.firstChild.appendChild(style);
        document._qsa = [];

        style.styleSheet.cssText = selectors + '{x-qsa:expression(document._qsa && document._qsa.push(this))}';
        window.scrollBy(0, 0);
        style.parentNode.removeChild(style);

        while (document._qsa.length) {
            element = document._qsa.shift();
            element.style.removeAttribute('x-qsa');
            elements.push(element);
        }
        document._qsa = null;
        return elements;
    };
}

if (!document.querySelector) {
    document.querySelector = function (selectors) {
        var elements = document.querySelectorAll(selectors);
        return (elements.length) ? elements[0] : null;
    };
}

if(!Function.prototype.bind){
    Function.prototype.bind = function(){
        if(typeof this !== 'function'){
　　　　　　throw new TypeError('Function.prototype.bind - what is trying to be bound is not callable');
　　　　}
        var _this = this;
        var obj = arguments[0];
        var ags = Array.prototype.slice.call(arguments,1);
        return function(){
            _this.apply(obj,ags);
        };
    };
}
(function(obj){

	function kr(){
		this.author = 'Karen';
		this.version = '0.0';
		this.getEle = function(elm){
			return document.getElementById(elm);
		}
	}

	kr.prototype.request = function(param){
		var re_num = 0;
		var activexName=["MSXML2.XMLHTTP","Microsoft.XMLHTTP"];
		function request(param){
			var xml = null;
			if(window.XMLHttpRequest) {
				xml = new XMLHttpRequest();
			}else if(window.ActiveXObject) {
				xml = new ActiveXObject(activexName[re_num]);
			}
			if(xml == null){
				alert('浏览器不支持XML请求');
				return;
			}
			getRequest(param, xml);
		}
		function getRequest(param, xml){
			var httpType = (param.type || 'GET').toUpperCase();
			var dataType = param.dataType || 'json';
			var httpUrl = param.url || '/cgi-bin/cstecgi.cgi';
			var async = param.async!=undefined ? param.async : true;
			var paramData = param.data || {};
			var requestData = JSON.stringify(paramData);
			
			xml.onreadystatechange = function() {
			    if(xml.readyState == 4 && xml.status == 200) {
			    	if(typeof param.success == 'function')
			    		param.success(JSON.parse(xml.responseText));
			    }else if(xml.readyState == 4 && xml.status != 200){
			    	if(isLowIe() && re_num < 1){
			    		re_num++;
			    		request(param);
			    	}
			    	if(typeof param.error == 'function')
			    		param.error('error');
			    }
			};
			xml.open(httpType, httpUrl, async);
			if(httpType == 'POST'){
				xml.setRequestHeader("Content-type", "application/x-www-form-urlencoded"); 
			}
			xml.send(requestData); 
		}
		request(param);
	};

	kr.prototype.elm = function(elm){
		return this.getEle(elm);
	};

	kr.prototype.show = function(elm){
		this.getEle(elm).style.display = 'block';
	};

	kr.prototype.hide = function(elm){
		this.getEle(elm).style.display = 'none';
	};

	kr.prototype.html = function(elm, text){
		this.getEle(elm).innerHTML = text;
	};

	kr.prototype.set = function(elm, value){
		var $el = this.getEle(elm);
		var tar = $el.tagName.toLowerCase();
		if(tar == 'input' || tar == 'select')
			$el.value = value;
	};

	kr.prototype.get = function(elm){
		var $el = this.getEle(elm);
		var tar = $el.tagName.toLowerCase();
		var value = null;
		if(tar == 'input' || tar == 'select')
			value = $el.value;

		return value;
	};

	kr.prototype.urlMsg = function(){
	    if(location.href.indexOf('?') > -1){
	        var firsturl = location.href.split('?');
	        var urlobj ={};
	        var secondurl = firsturl[1].split('&');
	        for(var i=0;i<secondurl.length;i++){
	           var thirdurl = secondurl[i].split('=');
	           urlobj[thirdurl[0]] = thirdurl[1];
	        }
	        return urlobj;
	    }else{
	        return {};
	    }
	};
	
	kr.prototype.addEventListener = function(ele,event,fn){
		//if(event == 'click' || event == 'change'){
			if(ele.addEventListener){
		        ele.addEventListener(event,fn,false);
		    }else{
		        ele.attachEvent('on'+event,fn.bind(ele));
		    }
		//}
	};

	kr.prototype.className = function(ele, name){
		if(typeof name == 'string'){
			ele.className = name;
		}else{
			return ele.className;
		}
	};

	kr.prototype.firstElementChild = function(ele){
		return ele.firstElementChild || ele.firstChild;
	};

	kr.prototype.nextSibling = function(ele){
	 	return ele.nextElementSibling || ele.nextSibling;
    };

    kr.prototype.previousSibling = function(ele){
    	if(ele.previousElementSibling)
    		ele = ele.previousElementSibling;
    	else{
    		ele = ele.previousSibling;
    	}
    	return ele;
    };

	kr.prototype.target = function(e){
		e = e || event;
		return e.target || e.srcElement;
	};

	kr.prototype.querySelectorAll = function(elm, selectors){
    	var elements = [];
    	var $el = elm.children;
    	selectors = selectors.replace(/^./, "");
    	findClass($el);
    	function findClass(el){
    		for(var i=0;i<el.length;i++){
	    		if(selectors == el[i].className)
	    			elements.push(el[i]);
	    		if(el[i].children){
	    			findClass(el[i].children);
	    		}
	    	}
    	}
    	return elements;
    };

	obj.kr = new kr();
})(window)

/*语言处理*/
var $lang = {};
function getLanguage(lang){
	kr.request({
		url:'/language/'+lang+'.json',
        async: false,
        type: 'GET',
        success:function(data){
            $lang = data;
        }
	});
}

var lang_t = function(lang,arr){
    var msg, lang1, lang2;
    var regex=/\[|\]/g;
    var a=regex.test(lang);
    if(a == false){
        lang1 = lang.split('.')[0];
        lang2 = lang.split('.')[1];
    }else{
        lang1 = lang.split('[')[0];
        var d = lang.split('[')[1].replace(/\"/g, "");
        lang2 = d.split(']')[0];
    }
    if($lang[lang1] == undefined){
        //alert(lang +' is undefined');
        return lang1;
    }
    msg = $lang[lang1][lang2];
    if(msg == undefined){
        //alert(lang +' is undefined');
        return lang2;
    }
    if(arr != undefined){
        if(typeof(arr) == 'object'){
            for(var i in arr){
                msg = msg.replace('{'+i+'}',arr[i]);
            }
        }else if(arr == 'html'){
            msg = msg.replace('[','<font style="font-weight:bold;"> [').replace(']','] </font>');
        }
    }
    return msg;
}
/*lang end*/

var _eleObj_={};

var _allEleArr_ = [];
var _globalNodeValue_ = [];//保存变量文本
var _vm_ = {};

function initChild(el, type, value) {
    var $dom = document.getElementById('myui');
    searchChild($dom, '', [], true);
   
}

function langInit(str){
    str = str.replace(/[\"\']/g,"");
    return lang_t(str);
}

function extend (to, _from) {
  for (var key in _from) {
    to[key] = _from[key];
  }
  return to
}

//主入口
function kr$1(options){
	if(typeof options != 'object'){
		alert('warn! value must is object!');
		return
	}
	this._init(options);
}

kr$1.prototype._init = function(options){
	//getLanguage("cn");
	var main_extend = {
		init:function(){},
		mounted: function(){},
		w: lang_t
	};
	_vm_ = extend(main_extend, options);
	if(typeof _vm_.init == 'function'){
		_vm_.init();
	}
	
	window.onload = function(){
		if(typeof _vm_.mounted == 'function'){
 			_vm_.mounted();
 		}
 		
 		initChild("body");
	    document.getElementById('myui').style.display = 'block';
	};
};

function searchChild(el, el_text, arr, isinit){
	var child;
	if(el.childNodes.length > 0){
		for(var j=0;j<el.childNodes.length;j++){
			child = el.childNodes[j];
			if(child.nodeValue){
				if(isinit === true){
					childtovalue(true, el, child);
				}
			}else if(child){
				if(child.tagName != 'SCRIPT')
					searchChild(child, el_text, arr, isinit);
			}
		}
   	}
}

function processText(){
	for(var i in _globalNodeValue_){
        var result = langInit(_globalNodeValue_[i].value);
        _globalNodeValue_[i].elm.nodeValue = _globalNodeValue_[i].nodeVlaue.replace(/\{\{(.+?)\}\}/g, result);
	}
}

function childtovalue(isinit, el, el1, el_text, arr, idx){
	var str = el1.nodeValue;
	str = str.replace(/(^\s*)|(\s*$)/g, "");
	var result;
    if(/\{\{(.+?)\}\}/g.test(str)){
    	var result, child;
        child = /\{\{([^{}]+)\}\}/g.exec(str)[1];
        if(isinit){
        	var temp = /w\(([^*]+)\)/g.exec(child);
	    	
	        if(temp != null && temp != undefined){
	            result = langInit(temp[1]);
	        }else{
	        	result = _vm_[child.trim()];
	        }
	        _globalNodeValue_.push({
	        	nodeVlaue: str,
	        	value: temp[1],
	        	elm: el1
	        });
	        if(result == undefined)
	        	result = str;
	        else
	        	result = str.replace(/\{\{(.+?)\}\}/g, result);
        }
        el1.nodeValue = result;
    }
}
