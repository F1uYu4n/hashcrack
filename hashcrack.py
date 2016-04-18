#!/usr/bin/env python
# encoding: utf-8

# __author__ = "F1uYu4n"

import json
import re
import threading
from urllib import unquote

import requests
from requests.exceptions import RequestException

timeout = 60
retry_cnt = 2
common_headers = {u"Accept": u"text/html, application/xhtml+xml, */*", u"Accept-Encoding": u"gzip, deflate",
                  u"User-Agent": u"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
                  u"Accept-Language": u"zh-CN,zh;q=0.8"}


# md5-16, md5-32, sha1, mysql-323, mysql5, and so on...
def cmd5(passwd):
    url = u"http://cmd5.com/"
    try_cnt = 0
    while True:
        try:
            s = requests.Session()
            req = s.get(url, headers=common_headers, timeout=timeout)
            __ = dict(re.findall(r'id="(.*?)" value="(.*?)"', req.text))

            headers = dict(common_headers, **{u"Content-Type": u"application/x-www-form-urlencoded", u"Referer": url})
            data = {u"__EVENTTARGET": __[u"__EVENTTARGET"], u"__EVENTARGUMENT": __[u"__EVENTARGUMENT"],
                    u"__VIEWSTATE": __[u"__VIEWSTATE"],
                    u"__VIEWSTATEGENERATOR": __[u"__VIEWSTATEGENERATOR"],
                    u"ctl00$ContentPlaceHolder1$TextBoxInput": passwd,
                    u"ctl00$ContentPlaceHolder1$InputHashType": u"md5",
                    u"ctl00$ContentPlaceHolder1$Button1": u'\u89e3\u5bc6',
                    u"ctl00$ContentPlaceHolder1$HiddenField1": u"",
                    u"ctl00$ContentPlaceHolder1$HiddenField2": __[u"ctl00_ContentPlaceHolder1_HiddenField2"]}
            req = s.post(url, headers=headers, data=data, timeout=timeout)
            result = re.search(r'<span id="ctl00_ContentPlaceHolder1_LabelAnswer">.+?<br(\s/)*>', req.text).group(0)
            print u"[*] cmd5: %s" % re.sub(ur'(<.*?>)|(\u3002.*)', '', result)
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] cmd5: RequestError"
                break
        except (KeyError, AttributeError), e:
            print u"[-] cmd5: Error: %s" % e
            break


# md5-16, md5-32
def pmd5(passwd):
    url = u"http://pmd5.com/"
    try_cnt = 0
    while True:
        try:
            s = requests.Session()
            req = s.get(url, headers=common_headers, timeout=timeout)
            __ = dict(re.findall(r'id="(__VIEWSTATE|__EVENTVALIDATION)" value="(.*?)"', req.text))

            headers = dict(common_headers, **{u"Content-Type": u"application/x-www-form-urlencoded", u"Referer": url})
            data = {u"__VIEWSTATE": __[u"__VIEWSTATE"], u"__EVENTVALIDATION": __[u"__EVENTVALIDATION"], u"key": passwd,
                    u"jiemi": u"MD5\u89e3\u5bc6"}
            req = s.post(url, headers=headers, data=data, timeout=timeout)
            rsp = req.text
            if rsp.find(u"tip success") > 0:
                print u"[+] pmd5: %s" % re.findall(r'<em>(.*?)</em>', rsp)[1]
            elif rsp.find(u"tip error") > 0:
                print u"[-] pmd5: NotFound"
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] pmd5: RequestError"
                break
        except (KeyError, IndexError), e:
            print u"[-] pmd5: Error: %s" % e
            break


# md5-16, md5-32
def md5comcn(passwd):
    url = u"http://md5.com.cn/"
    try_cnt = 0
    while True:
        try:
            s = requests.Session()
            req = s.get(url, headers=common_headers, timeout=timeout)
            st = dict(re.findall(r'name="(sand|token)" value="(.*?)"', req.text))

            headers = dict(common_headers, **{u"Content-Type": u"application/x-www-form-urlencoded", u"Referer": url})
            data = {u"md": passwd, u"sand": st[u"sand"], u"token": st[u"token"], u"submit": u"MD5 Crack"}
            req = s.post(url + u"md5reverse", headers=headers, data=data, timeout=timeout)
            rsp = req.text
            if rsp.find(u"NotFound") > 0:
                print u"[-] md5comcn: NotFound"
            elif rsp.find(u"Found !") > 0:
                result = re.search(r'<span class="rescn">.*?</span>', rsp).group(0)[20:-7]
                print u"[+] md5comcn: %s" % result
            else:
                result = re.search(r'Result:</label><span class="res green">.*?</span>', rsp).group(0)[39:-7]
                print u"[+] md5comcn: %s" % result
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] md5comcn: RequestError"
                break
        except (KeyError, AttributeError), e:
            print u"[-] md5comcn: Error: %s" % e
            break


# md5-16, md5-32
def xmd5(passwd):
    url = u"http://xmd5.com/"
    try_cnt = 0
    while True:
        try:
            s = requests.Session()
            headers = dict(common_headers, **{u"Content-Type": u"application/x-www-form-urlencoded", u"Referer": url})
            data = {u"UserName": u"625107832@qq.com", u"Password": u"9XQ3NkTvXm2d3Z7p", u"logins": "\xb5\xc7\xc2\xbc"}
            req = s.post(url + u"user/CheckLog.asp", headers=headers, data=data, timeout=timeout)
            checkcode = re.search(r'checkcode2 type=hidden value=".*?">', req.text).group(0)[30:-2]

            params = {u"hash": passwd, u"xmd5": "MD5 \xbd\xe2\xc3\xdc", u"open": u"on", u"checkcode2": checkcode}
            headers = dict(common_headers, **{u"Referer": url})
            req = s.get(url + u"md5/search.asp", params=params, headers=headers, timeout=timeout)
            req.encoding = "gb2312"
            new_url = req.url
            if new_url.find(u"getpass.asp?type=no") > 0:
                print u"[-] xmd5: NotFound"
            elif new_url.find(u"paypass.asp") > 0:
                print u"[+] xmd5: %s" % re.findall(r'href=/user/pay.asp.*>(.*?)</a>', req.text)[0]
            elif new_url.find(u"403.asp") > 0:
                print u"[-] xmd5: checkcode error!"
            else:
                print u"[+] xmd5: %s" % new_url[37:]
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] xmd5: RequestError"
                break
        except IndexError, e:
            print u"[-] xmd5: Error: %s" % e
            break


# md5-16, md5-32, sha1
def navisec(passwd):
    url = u"http://md5.navisec.it/"
    try_cnt = 0
    while True:
        try:
            s = requests.Session()
            req = s.get(url, headers=common_headers, timeout=timeout)
            _token = re.search(r'name="_token" value=".+?">', req.text).group(0)[21:-2]

            headers = dict(common_headers, **{u"Content-Type": u"application/x-www-form-urlencoded", u"Referer": url})
            data = {u"_token": _token, u"hash": passwd}
            req = s.post(url + u"search", headers=headers, data=data, timeout=timeout)
            rsp = req.text
            result = re.search(r'<code>.*?</code>', rsp).group(0)[6:-7]
            num = re.search(ur'\u79ef\u5206\u5269\u4f59\uff1a([-]?\d)+', rsp).group(0)
            if result.find(u'\u672a\u80fd\u89e3\u5bc6') >= 0:
                print u"[-] navisec: %s%s" % (result, num)
            else:
                print u"[+] navisec: %s %s" % (result, num)
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] navisec: RequestError"
                break
        except AttributeError, e:
            print u"[-] navisec: Error: %s" % e
            break


# md5-16, md5-32
def blackbap(passwd):
    url = u"http://cracker.blackbap.org/"
    try_cnt = 0
    while True:
        try:
            params = {u"do": u"search"}
            headers = dict(common_headers, **{u"Content-Type": u"application/x-www-form-urlencoded",
                                              u"X-Requested-With": u"XMLHttpRequest", u"Referer": url})
            data = {u"isajax": 1, u"md5": passwd}
            req = requests.post(url, params=params, headers=headers, data=data, timeout=timeout)
            rsp = req.text
            if rsp.find(u"oktip") > 0:
                print u"[+] blackbap: %s" % re.findall(r'<strong>(.*?)</strong>', rsp)[2]
            else:
                print u"[-] blackbap: NotFound"
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] blackbap: RequestError"
                break
        except IndexError, e:
            print u"[-] blackbap: Error: %s" % e
            break


# md5-16, md5-32, sha1, mysql323, mysql5, discuz
def future_sec(passwd):
    url = u"http://md5.future-sec.com/query.php"
    try_cnt = 0
    while True:
        try:
            headers = dict(common_headers, **{u"Content-Type": u"application/x-www-form-urlencoded", u"Referer": url})
            data = {u"h": passwd, u"t": u"auto"}
            req = requests.post(url, headers=headers, data=data, timeout=timeout)
            rsp = req.text
            if rsp.startswith(u'\u7834\u89e3\u5931\u8d25'):
                print u"[-] future_sec: %s" % rsp.replace(u'<br>', u' ')
            elif rsp.startswith(u'\u7834\u89e3\u6210\u529f'):
                pos = rsp.find(u'\u5bc6\u6587\u7c7b\u578b')
                print u"[+] future_sec: %s" % rsp[pos:].replace(u'<br>', u',')
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] future_sec: RequestError"
                break
        except ValueError, e:
            print u"[-] future_sec: Error: %s" % e
            break


# md5-16, md5-32, sha1, mysql5
def md5lol(passwd, md5type):
    url = u"http://www.md5.lol/md5"
    try_cnt = 0
    while True:
        try:
            s = requests.Session()
            req = s.get(url, headers=common_headers, timeout=timeout)
            csrf_token = re.search(r'name="csrf_token" type="hidden" value=".+?">', req.text).group(0)[39:-2]

            headers = dict(common_headers, **{u"Content-Type": u"application/x-www-form-urlencoded", u"Referer": url})
            data = {u"csrf_token": csrf_token, u"md5": passwd, u"md5type": md5type}
            req = s.post(url, headers=headers, data=data, timeout=timeout)
            result = re.findall(r'<div class="input-group">[\s\S].+?</div>', req.text, re.S)[1][25:-6].strip()[4:-5]
            if result.find(u'\u6210\u529f') > 0:
                print u"[+] md5lol: %s" % result
            elif result.find(u'\u5931\u8d25') > 0:
                print u"[-] md5lol: NotFound"
            else:
                print u"[-] md5lol: %s" % result
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] md5lol: RequestError"
                break
        except (AttributeError, IndexError), e:
            print u"[-] md5lol: Error: %s" % e
            break


# md5-16, md5-32
def pdtools(passwd):
    url = u"http://www.pdtools.net/"
    try_cnt = 0
    while True:
        try:
            s = requests.Session()
            params = {u"method": u"crack", u"type": 1, u"md5": passwd}
            headers = dict(common_headers,
                           **{u"X-Requested-With": u"XMLHttpRequest", u"Referer": url + u"tools/md5Util.jsp"})
            req = s.post(url + u"tools/md5Util.jsp", headers=headers, params=params, timeout=timeout)
            result = req.text.strip()

            headers = dict(common_headers, **{u"Content-Type": u"application/x-www-form-urlencoded",
                                              u"Referer": url + u"tools/md5Util.jsp"})
            data = {u"_VIEWRESOURSE": u"c4c92e61011684fc23405bfd5ebc2b31", u"md5": passwd, u"result": result}
            req = s.post(url + u"tools/md5.jsp", headers=headers, data=data, timeout=timeout)
            res = re.search(r'<textarea.*?name="realtext".*?>.*?</textarea>', req.text, re.S).group(0)
            res = re.sub(r'<.*?>', '', res, 0, re.S)
            if res.find(u'\u9057\u61be') > 0:
                print u"[-] pdtools: NotFound"
            else:
                tmp = re.split(r'\r\n', res)
                print u"[+] pdtools: %s, %s" % (tmp[2], tmp[3])
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] pdtools: RequestError"
                break
        except (AttributeError, IndexError), e:
            print u"[-] pdtools: Error: %s" % e
            break


# md5-32
def md5net(passwd):
    url = u"http://www.md5.net/md5-cracker/"
    try_cnt = 0
    while True:
        try:
            headers = dict(common_headers, **{u"Content-Type": u"application/x-www-form-urlencoded", u"Referer": url})
            cookies = {u"active_template::6734": u"orig_site"}
            data = {u"generator[hash]": passwd, u"generator[submit]": u""}

            req = requests.post(url, headers=headers, cookies=cookies, data=data, timeout=timeout)
            result = re.search(r'<div class="panel-body">.*?</p>', req.text, re.S).group(0)[32:-4]
            print u"[%s] md5net: %s" % (u"-" if result == u"Not found..." else u"+", result)
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] md5net: RequestError"
                break
        except AttributeError, e:
            print u"[-] md5net: Error: %s" % e
            break


# md5-32, sha1, sha256, sha384, sha512
def hashtoolkit(passwd):
    url = u"http://hashtoolkit.com/reverse-hash"
    try_cnt = 0
    while True:
        try:
            params = {u"hash": passwd}
            req = requests.get(url, headers=common_headers, params=params, timeout=timeout)
            rsp = req.text
            if rsp.find(u"No hashes found for") > 0:
                print u"[-] hashtoolkit: NotFound"
            else:
                result = re.findall(r'<td class="res-text">.*?<span.*?>(.*?)</span>', rsp, re.S)[0]
                print u"[+] hashtoolkit: %s" % result
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] hashtoolkit: RequestError"
                break
        except IndexError, e:
            print u"[-] hashtoolkit: Error: %s" % e
            break


# md5-32
def md5db(passwd):
    url = u"http://md5db.net/"
    try_cnt = 0
    while True:
        try:
            req = requests.get(url + u"api/" + passwd, headers=common_headers, timeout=timeout)
            rsp = req.text
            if rsp:
                print u"[+] md5db: %s" % rsp
            else:
                print u"[-] md5db: NotFound"
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] md5db: RequestError"
                break


# md5-16, md5-32, sha1
def wmd5(passwd, action):
    url = u"http://www.wmd5.com/"
    try_cnt = 0
    while True:
        try:
            headers = dict(common_headers, **{u"Content-Type": u"application/x-www-form-urlencoded",
                                              u"X-Requested-With": u"XMLHttpRequest", u"Referer": url})
            data = {u"miwen": passwd, u"action": action}
            req = requests.post(url + u"ajax.php", headers=headers, data=data, timeout=timeout)
            rsp = req.json()
            if rsp[u"status"] == u"success":
                print u"[+] wmd5: %s" % rsp.get(u"md5text", u'\u8be5\u6761\u662f\u4ed8\u8d39\u8bb0\u5f55')
            else:
                print u"[-] wmd5: NotFound"
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] wmd5: RequestError"
                break
        except KeyError, e:
            print u"[-] wmd5: Error: %s" % e
            break


# md5-16, md5-32
def t00ls(passwd):
    url = u"https://www.t00ls.net/md5_decode.html"
    try_cnt = 0
    while True:
        try:
            s = requests.Session()
            req = s.get(url, headers=common_headers, timeout=timeout)
            formhash = re.search(r'name="formhash" value=".*?" />', req.text).group(0)[23:-4]

            headers = dict(common_headers, **{u"Content-Type": u"application/x-www-form-urlencoded",
                                              u"X-Requested-With": u"XMLHttpRequest", u"Referer": url})
            data = {u"querymd5": passwd, u"md5type": u"decode", u"formhash": formhash, u"querymd5submit": u"decode"}
            req = s.post(url, headers=headers, data=data, timeout=timeout)
            rsp = req.json()
            if rsp[u"result"] == u"error" and u'\u5df2\u67e5\u5230' not in rsp[u"msg"]:
                print u"[-] t00ls: %s" % rsp[u"msg"]
            elif rsp[u"result"] == u"success":
                print u"[+] t00ls: %s" % rsp[u"mingwen"]
            else:
                print u"[+] t00ls: %s" % rsp[u"msg"]
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] t00ls: RequestError"
                break
        except (AttributeError, KeyError), e:
            print u"[-] t00ls: Error: %s" % e
            break


# md5-16, md5-32
def hkc5(passwd):
    url = u"http://md5.hkc5.com/"
    try_cnt = 0
    while True:
        try:
            headers = dict(common_headers, **{u"Content-Type": u"application/x-www-form-urlencoded", u"Referer": url})
            data = {u"md5text": passwd, u"look": " \xb2\xe9\xd1\xaf "}
            req = requests.post(url + u"index.asp?action=look", headers=headers, data=data, timeout=timeout)
            req.encoding = "gb2312"
            if u"err" in req.url:
                print u"[-] hkc5: %s" % unquote(str(req.url[35:-1])).decode('gbk')
            else:
                result = re.search(r'name="rr2" value=".*?" >', req.text).group(0)[18:-3].strip()
                print u"[+] hkc5: %s" % result
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] hkc5: RequestError"
                break
        except AttributeError, e:
            print u"[-] hkc5: Error: %s" % e
            break


# md5-32
def nitrxgen(passwd):
    url = u"http://www.nitrxgen.net/md5db/"
    try_cnt = 0
    while True:
        try:
            headers = dict(common_headers, **{u"Content-Type": u"application/x-www-form-urlencoded", u"Referer": url})
            data = {u"input": passwd}
            req = requests.post(url, headers=headers, data=data, timeout=timeout)
            result = re.search(r'<pre.*?>[\s\S].+?</pre>', req.text, re.S).group(0)[33:-6].strip()
            print u"[%s] nitrxgen: %s" % (u"-" if result == u"Result not found." else u"+", result)
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] nitrxgen: RequestError"
                break
        except AttributeError, e:
            print u"[-] nitrxgen: Error: %s" % e
            break


# md5-16, md5-32
def zzblo(passwd):
    url = u"http://tool.zzblo.com/Api/Md5/decrypt"
    try_cnt = 0
    while True:
        try:
            headers = dict(common_headers, **{u"Content-Type": u"application/x-www-form-urlencoded",
                                              u"X-Requested-With": u"XMLHttpRequest", u"Referer": url})
            data = {u"secret": passwd}
            req = requests.post(url, headers=headers, data=data, timeout=timeout)
            rsp = req.json()
            if rsp[u"status"] == 200:
                print u"[+] zzblo: %s" % rsp[u"text"]
            elif rsp[u"mesg"].find(u'\u65e0\u6cd5\u89e3\u5bc6') > 0:
                print u"[-] zzblo: NotFound"
            else:
                print u"[-] zzblo: %s" % rsp[u"mesg"]
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] zzblo: RequestError"
                break
        except KeyError, e:
            print u"[-] zzblo: Error: %s" % e
            break


# md5-32
def myaddr(passwd):
    url = u"http://md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php"
    try_cnt = 0
    while True:
        try:
            headers = dict(common_headers, **{u"Content-Type": u"application/x-www-form-urlencoded", u"Referer": url})
            data = {u"md5": passwd}
            req = requests.post(url, headers=headers, data=data, timeout=timeout)
            result = re.search(r'Hashed string</span>:\s.*?</div>', req.text)
            if result:
                print u"[+] myaddr: %s" % result.group(0)[22:-6]
            else:
                print u"[-] myaddr: %s" % u"NotFound"
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] myaddr: RequestError"
                break
        except AttributeError, e:
            print u"[-] myaddr: Error: %s" % e
            break


# md5-16, md5-32, sha1, mysql323, mysql5, discuz
def chamd5(passwd, type):
    url = u"http://www.chamd5.org/"
    try_cnt = 0
    while True:
        try:
            s = requests.Session()
            headers = dict(common_headers, **{u"Content-Type": u"application/json", u"Referer": url,
                                              u"X-Requested-With": u"XMLHttpRequest"})
            data = {u"email": u"akb0016@126.com", u"pass": u"!Z3jFqDKy8r6v4", u"type": u"login"}
            s.post(url + u"HttpProxyAccess.aspx/ajax_login", headers=headers, data=json.dumps(data),
                   timeout=timeout)

            data = {u"hash": passwd, u"type": type}
            req = s.post(url + u"HttpProxyAccess.aspx/ajax_me1ody", headers=headers, data=json.dumps(data),
                         timeout=timeout)
            rsp = req.json()
            result = re.sub(r'<.*?>', '', json.loads(rsp[u"d"])[u"msg"])
            if result.find(u'\u7834\u89e3\u6210\u529f') > 0:
                print u"[+] chamd5: %s" % re.search(ur'\u660e\u6587:.*?\u7528\u65f6', result).group(0)[:-2].strip()
            elif result.find(u'\u91d1\u5e01\u4e0d\u8db3') >= 0:
                print u"[-] chamd5: %s" % result
            else:
                print u"[-] chamd5: NotFound"
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] chamd5: RequestError"
                break
        except (AttributeError, ValueError), e:
            print u"[-] chamd5: Error: %s" % e
            break


# md5-16, md5-32, sha1, mysql5
def sssie(passwd):
    url = u"http://md5.sssie.com/decode"
    try_cnt = 0
    while True:
        try:
            headers = dict(common_headers, **{u"Content-Type": u"application/x-www-form-urlencoded", u"Referer": url})
            data = {u"type": u"md5", u"password": passwd, u"submit": "md5\xe8\xa7\xa3\xe5\xaf\x86"}
            req = requests.post(url, headers=headers, data=data, timeout=timeout)
            result = re.findall(r'home_index_div_dialog.*?input-group">(.*?)</div>', req.text, re.S)[0].strip()
            print u"[%s] sssie: %s" % (u"+" if result.find(u'\u7834\u89e3\u5931\u8d25') < 0 else u"-", result)
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] sssie: RequestError"
                break
        except IndexError, e:
            print u"[-] sssie: Error: %s" % e
            break


# md5-16, md5-32
def cc90(passwd):
    url = u"http://www.90cc.pw/index.php"
    try_cnt = 0
    while True:
        try:
            headers = dict(common_headers,
                           **{u"X-Requested-With": u"application/x-www-form-urlencoded", u"Referer": url})
            data = {u"q": passwd}
            req = requests.post(url, headers=headers, data=data, timeout=timeout)
            req.encoding = 'utf-8'
            result = re.search(r'<ul>.*</ul>', req.text).group(0)[4:-5]
            if result.find(u'\u89e3\u5bc6\u6210\u529f') > 0:
                print u"[+] 90cc: %s" % re.sub(r'<.*?>', '', result)
            else:
                print u"[-] 90cc: %s" % result
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] 90cc: RequestError"
                break
        except AttributeError, e:
            print u"[-] 90cc: Error: %s" % e
            break


# md5-16, md5-32
def isilic(passwd):
    url = u"http://cracker.isilic.org/"
    try_cnt = 0
    while True:
        try:
            params = {u"do": u"search"}
            headers = dict(common_headers, **{u"Content-Type": u"application/x-www-form-urlencoded",
                                              u"X-Requested-With": u"XMLHttpRequest", u"Referer": url})
            data = {u"isajax": 1, u"md5": passwd}
            req = requests.post(url, params=params, headers=headers, data=data, timeout=timeout)
            req.encoding = "utf-8"
            rsp = req.text
            if rsp.find(u"oktip") > 0:
                print u"[+] isilic: %s" % re.findall(r'<strong>(.*?)</strong>', rsp)[2]
            else:
                print u"[-] isilic: %s" % re.search(r'<p>.+?<a', rsp).group(0)[3:-2]
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] isilic: RequestError"
                break
        except (AttributeError, IndexError), e:
            print u"[-] isilic: Error: %s" % e
            break


# md5-32
def md5decryption(passwd):
    url = u"http://md5decryption.com/"
    try_cnt = 0
    while True:
        try:
            headers = dict(common_headers, **{u"Content-Type": u"application/x-www-form-urlencoded",
                                              u"X-Requested-With": u"XMLHttpRequest", u"Referer": url})
            data = {u"hash": passwd, u"submit": u"Decrypt It!"}
            req = requests.post(url, headers=headers, data=data, timeout=timeout)
            rsp = req.text
            if rsp.find(u"Decrypted Text:") > 0:
                print u"[+] md5decryption: %s" % re.search(r'Decrypted Text: </b>.*?</font>', rsp).group(0)[20:-7]
            else:
                print u"[-] md5decryption: NotFound"
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] md5decryption: RequestError"
                break
        except AttributeError, e:
            print u"[-] md5decryption: Error: %s" % e
            break


# md5-16, md5-32
def syue(passwd):
    url = u"http://md5.syue.com/ShowMD5Info.asp"
    try_cnt = 0
    while True:
        try:
            params = {u"GetType": u"ShowInfo", u"md5_str": passwd}
            headers = dict(common_headers, **{u"X-Requested-With": u"XMLHttpRequest", u"Referer": url})
            req = requests.get(url, params=params, headers=headers, timeout=timeout)
            req.encoding = "gb2312"
            result = re.findall(r'<span.*?>(.*?)</span>', req.text)[0]
            print u"[%s] syue: %s" % (u"-" if u'\u5f88\u62b1\u6b49' in result else u"+", result)
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] syue: RequestError"
                break
        except IndexError, e:
            print u"[-] syue: Error: %s" % e
            break


# md5-32
def md5pass(passwd):
    url = u"http://md5pass.info/"
    try_cnt = 0
    while True:
        try:
            headers = dict(common_headers, **{u"Content-Type": u"application/x-www-form-urlencoded",
                                              u"X-Requested-With": u"XMLHttpRequest", u"Referer": url})
            data = {u"hash": passwd, u"get_pass": u"Get Pass"}
            req = requests.post(url, headers=headers, data=data, timeout=timeout)
            rsp = req.text
            if rsp.find(u"Not found!") > 0:
                print u"[-] md5pass: NotFound"
            else:
                print u"[+] md5pass: %s" % re.search(r"Password - <b>.*?</b>", rsp).group(0)[14:-4]
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] md5pass: RequestError"
                break
        except AttributeError, e:
            print u"[-] md5pass: Error: %s" % e
            break


# md5-32
def gromweb(passwd):
    url = u"http://md5.gromweb.com/"
    try_cnt = 0
    while True:
        try:
            params = {u"md5": passwd}
            req = requests.post(url, headers=common_headers, params=params, timeout=timeout)
            rsp = req.text
            if rsp.find(u"succesfully reversed") > 0:
                print u"[+] gromweb: %s" % re.search(r'<em class="long-content string">.*?</em>', rsp).group(0)[32:-5]
            else:
                print u"[-] gromweb: NotFound"
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] gromweb: RequestError"
                break
        except AttributeError, e:
            print u"[-] gromweb: Error: %s" % e
            break


def crack(passwd):
    threads = [threading.Thread(target=cmd5, args=(passwd,))]
    if len(passwd) == 41 and re.match(r'\*[0-9a-f]{40}|\*[0-9A-F]{40}', passwd):
        threads.append(threading.Thread(target=future_sec, args=(passwd,)))
        threads.append(threading.Thread(target=md5lol, args=(passwd, 4,)))
        threads.append(threading.Thread(target=chamd5, args=(passwd[1:], u"300",)))
        threads.append(threading.Thread(target=sssie, args=(passwd,)))
    elif len(passwd) == 40 and re.match(r'[0-9a-f]{40}|[0-9A-F]{40}', passwd):
        threads.append(threading.Thread(target=navisec, args=(passwd,)))
        threads.append(threading.Thread(target=future_sec, args=(passwd,)))
        threads.append(threading.Thread(target=md5lol, args=(passwd, 2,)))
        threads.append(threading.Thread(target=hashtoolkit, args=(passwd,)))
        threads.append(threading.Thread(target=wmd5, args=(passwd, u"sha1show")))
        threads.append(threading.Thread(target=chamd5, args=(passwd, u"100",)))
        threads.append(threading.Thread(target=chamd5, args=(passwd, u"300",)))
        threads.append(threading.Thread(target=sssie, args=(passwd,)))
    elif len(passwd) == 32 and re.match(r'[0-9a-f]{32}|[0-9A-F]{32}', passwd):
        threads.append(threading.Thread(target=pmd5, args=(passwd,)))
        threads.append(threading.Thread(target=xmd5, args=(passwd,)))
        threads.append(threading.Thread(target=navisec, args=(passwd,)))
        threads.append(threading.Thread(target=md5comcn, args=(passwd,)))
        threads.append(threading.Thread(target=blackbap, args=(passwd,)))
        threads.append(threading.Thread(target=future_sec, args=(passwd,)))
        threads.append(threading.Thread(target=md5lol, args=(passwd, 1,)))
        threads.append(threading.Thread(target=pdtools, args=(passwd,)))
        threads.append(threading.Thread(target=md5net, args=(passwd,)))
        threads.append(threading.Thread(target=hashtoolkit, args=(passwd,)))
        threads.append(threading.Thread(target=md5db, args=(passwd,)))
        threads.append(threading.Thread(target=wmd5, args=(passwd, u"md5show")))
        threads.append(threading.Thread(target=t00ls, args=(passwd,)))
        threads.append(threading.Thread(target=hkc5, args=(passwd,)))
        threads.append(threading.Thread(target=nitrxgen, args=(passwd,)))
        threads.append(threading.Thread(target=zzblo, args=(passwd,)))
        threads.append(threading.Thread(target=myaddr, args=(passwd,)))
        threads.append(threading.Thread(target=chamd5, args=(passwd, u"md5",)))
        threads.append(threading.Thread(target=sssie, args=(passwd,)))
        threads.append(threading.Thread(target=cc90, args=(passwd,)))
        threads.append(threading.Thread(target=isilic, args=(passwd,)))
        threads.append(threading.Thread(target=syue, args=(passwd,)))
        threads.append(threading.Thread(target=md5decryption, args=(passwd,)))
        threads.append(threading.Thread(target=md5pass, args=(passwd,)))
        threads.append(threading.Thread(target=gromweb, args=(passwd,)))
    elif len(passwd) == 16 and re.match(r'[0-9a-f]{16}|[0-9A-F]{16}', passwd):
        threads.append(threading.Thread(target=pmd5, args=(passwd,)))
        threads.append(threading.Thread(target=xmd5, args=(passwd,)))
        threads.append(threading.Thread(target=navisec, args=(passwd,)))
        threads.append(threading.Thread(target=md5comcn, args=(passwd,)))
        threads.append(threading.Thread(target=blackbap, args=(passwd,)))
        threads.append(threading.Thread(target=future_sec, args=(passwd,)))
        threads.append(threading.Thread(target=md5lol, args=(passwd, 1,)))
        threads.append(threading.Thread(target=pdtools, args=(passwd,)))
        threads.append(threading.Thread(target=wmd5, args=(passwd, u"md5show")))
        threads.append(threading.Thread(target=t00ls, args=(passwd,)))
        threads.append(threading.Thread(target=hkc5, args=(passwd,)))
        threads.append(threading.Thread(target=zzblo, args=(passwd,)))
        threads.append(threading.Thread(target=chamd5, args=(passwd, u"md5",)))
        threads.append(threading.Thread(target=chamd5, args=(passwd, u"200",)))
        threads.append(threading.Thread(target=sssie, args=(passwd,)))
        threads.append(threading.Thread(target=cc90, args=(passwd,)))
        threads.append(threading.Thread(target=isilic, args=(passwd,)))
        threads.append(threading.Thread(target=syue, args=(passwd,)))
    elif passwd.find(':') > 0:
        threads.append(threading.Thread(target=chamd5, args=(passwd, u"10",)))
        threads.append(threading.Thread(target=future_sec, args=(passwd,)))
    elif len(passwd) in [64, 96, 128]:
        threads.append(threading.Thread(target=hashtoolkit, args=(passwd,)))

    for t in threads:
        t.start()
    for t in threads:
        t.join()


def main():
    while True:
        try:
            passwd = raw_input(u"Hash(0=exit): ").strip()
            if passwd:
                if passwd == u'0':
                    break
                crack(passwd)
        except (KeyboardInterrupt, ValueError, EOFError):
            break


if __name__ == '__main__':
    main()
