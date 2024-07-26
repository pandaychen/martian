使用日志：

[root@VM-218-158-centos proxy]# ^C
[root@VM-218-158-centos proxy]# ./main   -generate-ca-cert -har   -skip-tls-verify -v=2
2024/06/11 09:37:50 martian: starting proxy on [::]:8080 and api on [::]:8181
start tls
^C2024/06/11 09:41:15 martian: shutting down
[root@VM-218-158-centos proxy]# ./main   -generate-ca-cert -har   -skip-tls-verify -v=2&
[1] 79975
[root@VM-218-158-centos proxy]# 2024/06/11 09:41:17 martian: starting proxy on [::]:8080 and api on [::]:8181
^C
[root@VM-218-158-centos proxy]# start tls
tr^C
[root@VM-218-158-centos proxy]# ./main -h^C
[root@VM-218-158-centos proxy]# ^C
[root@VM-218-158-centos proxy]# connect www.baidu.com:443
2024/06/11 09:41:37 INFO: 
--------------------------------------------------------------------------------
Request to http://www.baidu.com:443
--------------------------------------------------------------------------------
CONNECT http://www.baidu.com:443 HTTP/1.1
Host: www.baidu.com:443
Content-Length: 0
User-Agent: curl/7.29.0
Via: 1.1 martian-6cc603c7aaf92fe4f28a
X-Forwarded-For: 9.x.x.x
X-Forwarded-Host: www.baidu.com:443
X-Forwarded-Proto: http
X-Forwarded-Url: http://www.baidu.com:443


--------------------------------------------------------------------------------

mitm
2024/06/11 09:41:37 INFO: 
--------------------------------------------------------------------------------
Response from http://www.baidu.com:443
--------------------------------------------------------------------------------
HTTP/1.1 200 OK
Content-Length: 0


--------------------------------------------------------------------------------

handler 22
mitm https
2024/06/11 09:41:37 INFO: martian: forcing HTTPS inside secure session
not a connect GET
2024/06/11 09:41:37 INFO: 
--------------------------------------------------------------------------------
Request to https://www.baidu.com/
--------------------------------------------------------------------------------
GET https://www.baidu.com/ HTTP/1.1
Host: www.baidu.com
Content-Length: 0
Accept: */*
User-Agent: curl/7.29.0
Via: 1.1 martian-6cc603c7aaf92fe4f28a
X-Forwarded-For: 9.x.x.x
X-Forwarded-Host: www.baidu.com
X-Forwarded-Proto: https
X-Forwarded-Url: https://www.baidu.com/


--------------------------------------------------------------------------------

2024/06/11 09:41:37 INFO: 
--------------------------------------------------------------------------------
Response from https://www.baidu.com/
--------------------------------------------------------------------------------
HTTP/1.1 200 OK
Content-Length: 2443
Accept-Ranges: bytes
Cache-Control: private, no-cache, no-store, proxy-revalidate, no-transform
Content-Type: text/html
Date: Tue, 11 Jun 2024 01:41:37 GMT
Etag: "588603eb-98b"
Last-Modified: Mon, 23 Jan 2017 13:23:55 GMT
Pragma: no-cache
Server: bfe/1.0.8.18
Set-Cookie: BDORZ=27315; max-age=86400; domain=.baidu.com; path=/

<!DOCTYPE html>
<!--STATUS OK--><html> <head><meta http-equiv=content-type content=text/html;charset=utf-8><meta http-equiv=X-UA-Compatible content=IE=Edge><meta content=always name=referrer><link rel=stylesheet type=text/css href=https://ss1.bdstatic.com/5eN1bjq8AAUYm2zgoY3K/r/www/cache/bdorz/baidu.min.css><title>百度一下，你就知道</title></head> <body link=#0000cc> <div id=wrapper> <div id=head> <div class=head_wrapper> <div class=s_form> <div class=s_form_wrapper> <div id=lg> <img hidefocus=true src=//www.baidu.com/img/bd_logo1.png width=270 height=129> </div> <form id=form name=f action=//www.baidu.com/s class=fm> <input type=hidden name=bdorz_come value=1> <input type=hidden name=ie value=utf-8> <input type=hidden name=f value=8> <input type=hidden name=rsv_bp value=1> <input type=hidden name=rsv_idx value=1> <input type=hidden name=tn value=baidu><span class="bg s_ipt_wr"><input id=kw name=wd class=s_ipt value maxlength=255 autocomplete=off autofocus=autofocus></span><span class="bg s_btn_wr"><input type=submit id=su value=百度一下 class="bg s_btn" autofocus></span> </form> </div> </div> <div id=u1> <a href=http://news.baidu.com name=tj_trnews class=mnav>新闻</a> <a href=https://www.hao123.com name=tj_trhao123 class=mnav>hao123</a> <a href=http://map.baidu.com name=tj_trmap class=mnav>地图</a> <a href=http://v.baidu.com name=tj_trvideo class=mnav>视频</a> <a href=http://tieba.baidu.com name=tj_trtieba class=mnav>贴吧</a> <noscript> <a href=http://www.baidu.com/bdorz/login.gif?login&amp;tpl=mn&amp;u=http%3A%2F%2Fwww.baidu.com%2f%3fbdorz_come%3d1 name=tj_login class=lb>登录</a> </noscript> <script>document.write('<a href="http://www.baidu.com/bdorz/login.gif?login&tpl=mn&u='+ encodeURIComponent(window.location.href+ (window.location.search === "" ? "?" : "&")+ "bdorz_come=1")+ '" name="tj_login" class="lb">登录</a>');
                </script> <a href=//www.baidu.com/more/ name=tj_briicon class=bri style="display: block;">更多产品</a> </div> </div> </div> <div id=ftCon> <div id=ftConw> <p id=lh> <a href=http://home.baidu.com>关于百度</a> <a href=http://ir.baidu.com>About Baidu</a> </p> <p id=cp>&copy;2017&nbsp;Baidu&nbsp;<a href=http://www.baidu.com/duty/>使用百度前必读</a>&nbsp; <a href=http://jianyi.baidu.com/ class=cp-feedback>意见反馈</a>&nbsp;京ICP证030173号&nbsp; <img src=//www.baidu.com/img/gs.gif> </p> </div> </div> </div> </body> </html>

--------------------------------------------------------------------------------