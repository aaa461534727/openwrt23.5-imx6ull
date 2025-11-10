var showLanguage=[];
var lang_select = '';
var initData;
var languages = {
    'auto':'自动检测',
    'en':'English',
    'cn':'简体中文'
};


(function(){
var postVar = {"topicurl":"getInitConfig"};
kr.request({
    type: "POST",
    async: false,
    data: postVar,
    url: "/cgi-bin/cstecgi.cgi",
    success:function(data){
        initData = data;
        showLanguage = initData.showLanguage.split(",");
        if(data.showAutoLang == '1'){
            showLanguage.splice(0,0,'auto');
        }
        /*获取语言包*/
        var lang = initData.defaultLang;
        if(initData.showAutoLang == '1' && initData.langAutoFlag == '1'){
            lang = getAuto();
        }
        lang_select = '<select id="language" onchange="changeLanguage()">';
        for(var j in languages){
            for(var i=0;i<showLanguage.length;i++){
                if(showLanguage[i] == j){
                    if(initData.showAutoLang == '1' && initData.langAutoFlag == '1'){
                        if('auto' == j){
                            lang_select += '<option value="'+j+'" selected>'+languages[j]+'</option>';
                        }else {
                            lang_select += '<option value="'+j+'">'+languages[j]+'</option>';
                        }
                    }else{
                        if(lang == j){
                            lang_select += '<option value="'+j+'" selected>'+languages[j]+'</option>';
                        }else {
                            lang_select += '<option value="'+j+'">'+languages[j]+'</option>';
                        }
                    }
                    break;
                }
            }
        }
        lang_select += '</select>';
        getLanguage(lang);
    }
});

})(window);
/*多语言设置*/
function changeLanguage() {
    var t = kr.get('language');
    var langAutoFlag = '0';
    if(t == 'auto'){
        t = getAuto();
        langAutoFlag = '1';
    }
    getLanguage(t);
    processText();
    if(location.href.indexOf('wan_ie.html') >= 0)
    	linkType();
    var postVar = {"topicurl":"setLanguageCfg","lang":t,"langAutoFlag":langAutoFlag};
    kr.request({
        type: "POST",
        url: "/cgi-bin/cstecgi.cgi",
        data: postVar
    });
    
}

function getAuto() {
    var applang=(navigator.language||navigator.browserLanguage||navigator.userLanguage||navigator.systemLanguage).toLowerCase();
    var arr = initData.showLanguage;
    var flag = false;
    if(applang == "zh-tw"||applang == "zh-hk"){
        applang = "ct";
    }else if(applang == "zh-cn"||applang == "zh"||applang == "zh-sg"){
        applang = "cn";
    }else if(applang == "en"||applang == "en-us"||applang == "en-gb"){
        applang = "en";
    }else if(applang == "ja"){
        applang = "jp";
    }else if(applang == "be"||applang == "ru"||applang == "ru-md"||applang == "ru-ru"){
        applang = "ru";
    }else if(applang == "th" || applang == "th-th"){
        applang = "th";
    }else if(applang == "vi" || applang == 'vn' || applang == 'vi-vn'){
        for(var i = 0; i < arr.length; i++){
            if('vn' === arr[i]){
                flag = true;
                break;
            }
        }
        if(flag)
            applang = "vn";
        else
            applang = "vi";
    }
    return applang;
}
