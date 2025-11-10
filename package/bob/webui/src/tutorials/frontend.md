# 前端开发说明 : 快速入门

## 模板语法
> 页面渲染数据和数据绑定

### 文本
**语法**：`{{ 对象.属性 }}`
数据绑定最常见的形式就是使用“Mustache”语法 (双大括号) 的文本插值：
```html
    <span>Message: {{ msg }}</span> 
    <!-- 同时这里msg也可以用于简单的表达式 -->
    eg:  {{ ok ? 'YES' : 'NO' }}
```
Mustache 标签将会被替代为对应数据对象上 `msg` 属性的值。无论何时，绑定的数据对象上 `msg` 属性发生了**改变**，插值处的内容都会**更新**。

### 属性
**语法**：`:属性="对象.属性"`
```html
    <div :id="id"></div>
```
这样`:id`对应的属性值就会对应的变化。适合用于任何标签属性：'`class`,`style`,`href`,...'

### form属性（双向数据绑定）
**语法**：`v-model="对象.属性"`
```html
<input type="text" v-model="status">
```
数据`status`对应的属性变化的时候，表单就会做相应的变化。提交时候就拿`status`提交到后台就行。不需要再去取`input`的`value`值。

### 事件
**语法**：`@事件名称="事件处理函数"`
```html
    <p @click="fun1">点击</p>
```
点击`p`标签就会执行对应的函数`fun1`。

# vue组件简单的使用
> 此处仅对我们界面用到的知识进行讲解。详细的内容要移步到官网手册: [点击查看手册](https://cn.vuejs.org/v2/guide/syntax.html)
```JavaScript
Vue.component('cs-main', {
    template: '#main',
    data:function() {
        return {
            lang:$.lang,
            globalConfig:globalConfig
        }
    },
    created:function() {
      this.globalConfig.show_easy_setup = false;
    },
    computed:{
        local_href:function() {
            return location.host;
        }
    },
    methods:{
        submit_save:function() {
            location.href = '/wizard.html';
        }
    },
});
```
> 以上的代码就是登陆一个demo。

## 注册组件component
```
Vue.component('cs-main',option)
```
这里代表注册一个组件，名为：“`cs-main`”,`option`是携带给这个组件的所有参数。
## 组件选项：template
```JavaScript
template:'选择器'
```
指定某一行html元素。通过`id`，`class`，`标签`都可以选择。一般推荐用id选择器。
## 组件选项：data
```JavaScript
data:function() {
    return 数据
},
```
**注意：组件里面的数据必须用funciton(){reutrn  {}}的形式返回。所有需要在模板里面使用的数据必须先定义。**

## 组件选项：created
```JavaScript
    created:function() {
      // ajax请求。页面参数赋值。等等。
    },
```
初始化函数。当页面vue组件加载完成后就会调用这个`created`函数。这里面可以用于处理一些页面的初始化操作。比如获取页面初始化数据。

## 组件选项：computed
```JavaScript
computed:{
    local_href:function() {
        return location.host;
    }
},
```
计算属性：用于监听属性的变化值。同时也可以定义一个新的属性，用于页面的展示。  
计算属性的作用是当属性值改变的时候就会触发一次这个函数，否则就把当前的结果缓存起来供下次使用。  

实际用途：比如后台返回一个状态类型值为`1,2`,但页面需要显示；`开，关`。就可以用计算属性去处理了。

# 组件选项：methods
```JavaScript
methods:{
    submit_save:function() {
        location.href = '/wizard.html';
    }
},    
```
方法：顾名思义就是定义组件内所有需要的方法。

# 组件选项：watch 
用于实时监听所需要的数据。


> 此文档只适用简单的开发。详细的教程还需到官网([https://cn.vuejs.org](https://cn.vuejs.org))去看。 


# 前端开发之接口文档书写的格式
> 主要实现自己在data文件夹吧数据给模拟出来，文档写全。  
参考设备把每个页面把主题封装和数据的东西给补全。这里拿 `wizard.html` 作为案例

## getXXX 获取数据
### 第一步：请求需要的数据。
在 `wizard.html` 里面 `created` 函数发送一个 `getXXX` 主题。把拿到的数据根据需求处理后放到 `data` 里面（页面如果有数据需要调整的就进行调整）。 
eg：
```JavaScript
    // wizard.html 部分代码
    created:function() {
      var _this = this;
      this.globalConfig.show_loading = true; // 显示loading动画。根据实际页面的需求去添加。
      uiPost.getEasyWizardCfg(function(data) {
          data.staticIp = data.staticIp.split('.');
          data.staticMask = data.staticMask.split('.');
          data.staticGw = data.staticGw.split('.');
          data.wanPriDns = data.wanPriDns.split('.');
          data.wanSecDns = data.wanSecDns.split('.');
          _this.data = data; 
      });
    },
```

### 第二步：使用数据（页面和数据绑定上）
> 适配页面。实现数据动态绑定上。

### 第三步：封装函数，写文档（topicurl.js）
在 `topicurl.js` 里面的数据名称需要注意大小写。必现写上所有请求数据和响应数据。并注明可提供的值和值代表的意义。  
**语法**：
```JavaScript
/**
 * 这里写上文档注释
 * @param {[type]} [varname] [description]
 * param 这里定义为request 参数 
 * @property {[type]} [varname] [description]
 * property 这里定义为response
 * @property 
 * @example
 * 实际的案例。
 */
uiPost.prototype.xxx = function(postVar,callback){
   this.topicurl = 'xxx';
   // this.async = false; // 可以省略，默认true。true:异步，false:同步。
   this.url = '/data/wzd.json'; // 实际部署去掉。
   return this.post(postVar,callback);
};
// 把xxx的位置换成对应的主题即可。
```
eg:
```JavaScript
/**
 * getEasyWizardCfg 主题
 * @Author   Yexk       <yexk@carystudio.com>
 * @DateTime 2017-10-27
 * @param    {Object}   postVar         set参数
 * @param    {Function} callback        回调函数
 *
 * @property {String} wanConnMode       连接模式。0：静态IP，1：DHCP，2：PPPOE拨号                  
 * @property {String} staticIp          静态 IP地址      
 * @property {String} staticMask        静态 子网掩码      
 * @property {String} staticGw          静态 网关      
 * @property {String} wanPriDns         首选dns地址      
 * @property {String} wanSecDns         备用dns地址     
 * @property {String} wanConnStatus     连接状态   
 * 
 * @property {String} xxxxx 其他的参数(还有很多参数不知道意思,但是你们要写对咯。)
 * @return   {Object}
 * @example
 * request:
 * {
 *    topicurl:"getEasyWizardCfg"
 * }
 * response:
 * {
 *    "wanConnMode":  1,
 *    "staticIp": "172.1.1.1",
 *    "staticMask":  "255.255.255.0",
 *    "staticGw": "172.1.1.254",
 *    "wanPriDns":  "114.114.114.114",
 *    "wanSecDns":  "0.0.0.0",
 *    "wanConnStatus":  "disconnected",
 * ....
 * }
 */
```
### 第四步：在 `topicurl.js` 主题列表里面写上主题简要说明：  
**语法：**
```JavaScript
/**
 * @property {Object} 主题名称 简述 <a href="#主题名称">点击查看</a> 
 */
```
eg：
```JavaScript
/**
 * @property {Object} setEasyWizardCfg 提交wizrad数据 <a href="#setEasyWizardCfg">点击查看</a> 
 */
```
## setXXX 提交数据
这个一种主题和get差不多。主要多了一步数据封装操作。前面增加一步数据封装和数据校验。
### 第一步：数据封装和校验。
案例:
```JavaScript
提交函数:function() {
    var postVar = {}; // 定义提交变量
    postVar.wifiOff5g = this.data.wifiOff5g;
    postVar.wifiSSID5g = this.data.wifiSSID5g;
    ...
    postVar.wifiAuthMode5g = this.data.wifiAuthMode5g;
    // 做数据校验。所有的校验都在 `common.js` 的函数都封装到 `common.js`。并写上注释。

    uiPost.setxxx(postVar,function(data){
       // 可以对返回的数据进行对应的操作
    });
};
```

