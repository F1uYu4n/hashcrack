#!/usr/bin/env python
# encoding: utf-8

# __author__ = "F1uYu4n"


import HTMLParser
import re
import threading

import requests
from requests.exceptions import RequestException

timeout = 60
retry_cnt = 3
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
            result = re.sub(ur'(<.*?>)|(\u3002.*)', '', result)

            # 未查到或解密进度100%或验证码错误
            if re.search(ur'\u672a\u67e5\u5230|100%', result) or result == u'\u9a8c\u8bc1\u7801\u9519\u8bef':
                print u"[-] cmd5: %s" % result
            else:
                print u"[+] cmd5: %s" % result
            break
        except RequestException, e:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] cmd5: RequestError: %s" % e
                break
        except (KeyError, AttributeError), e:
            print u"[-] cmd5: Error: %s" % e
            break


# md5-16, md5-32, sha1, mysql-323, mysql5
def somd5(passwd):
    url = u"http://www.somd5.com/"
    try_cnt = 0
    while True:
        try:
            s = requests.Session()
            req = s.get(url + u"somd5-md5-js.html", headers=common_headers, timeout=timeout)
            isajax = re.search(r"isajax=(.*)&", req.text).group(0)[7:-1]

            data = {u"isajax": isajax, u"md5": passwd}
            headers = dict(common_headers, **{u"Content-Type": u"application/x-www-form-urlencoded",
                                              u"X-Requested-With": u"XMLHttpRequest", u"Referer": url})
            req = s.post(url + u"somd5-index-md5.html", headers=headers, data=data, timeout=timeout)
            rsp = req.text
            h1 = re.search(r'<h1.*>(.+?)</h1>', rsp)
            if h1:
                print u"[+] somd5: %s" % re.sub(r'<.*?>', '', h1.group(0))
            else:
                p = re.search(r'<p>(.*?)</p>', rsp)
                if p:
                    print u"[-] somd5: %s" % HTMLParser.HTMLParser().unescape(re.sub(r'<.*?>', '', p.group(0)))
                else:
                    print u"[-] somd5: \u4e0d\u6b63\u5e38\u7684MD5\u683c\u5f0f"
            break
        except RequestException, e:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] somd5: RequestError: %s" % e
                break
        except AttributeError, e:
            print u"[-] somd5: Error: %s" % e
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
        except RequestException, e:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] pmd5: RequestError: %s" % e
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
                print u"[+] md5comcn: Found! %s" % result
            else:
                result = re.search(r'Result:</label><span class="res green">.*?</span>', rsp).group(0)[39:-7]
                print u"[+] md5comcn: %s" % result
            break
        except RequestException, e:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] md5comcn: RequestError: %s" % e
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
        except RequestException, e:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] xmd5: RequestError: %s" % e
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
            num = re.search(ur'\u79ef\u5206\u5269\u4f59\uff1a(\d)+', rsp).group(0)
            if result.find(u'\u672a\u80fd\u89e3\u5bc6') >= 0:
                print u"[-] navisec: %s%s" % (result, num)
            else:
                print u"[+] navisec: %s %s" % (result, num)
            break
        except RequestException, e:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] navisec: RequestError: %s" % e
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
                print u"[-] blackbap: %s" % re.search(r'<p>.+?<a', rsp).group(0)[3:-2]
            break
        except RequestException, e:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] blackbap: RequestError: %s" % e
                break
        except (AttributeError, IndexError), e:
            print u"[-] blackbap: Error: %s" % e
            break


# md5-32, sha1, mysql5, and so on...
def leakdb(passwd):
    url = u"http://api.leakdb.abusix.com/"
    try_cnt = 0
    while True:
        params = {u"j": passwd}
        try:
            req = requests.get(url, params=params, headers=common_headers, timeout=timeout)
            rsp = req.json()
            if rsp[u"found"] == u"true":
                print u"[+] leakdb: %s, type: %s" % (rsp[u"hashes"][0][u"plaintext"], rsp[u"type"])
            elif rsp[u"found"] == u"false":
                print u"[-] leakdb: %s" % rsp[u"msg"][:rsp[u"msg"].find(u'.') + 1]
            break
        except RequestException, e:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] leakdb: RequestError: %s" % e
                break
        except (KeyError, IndexError), e:
            print u"[-] leakdb: Error: %s" % e
            break


# md5-32, sha1
def cloudcracker(passwd):
    url = u"http://www.cloudcracker.net/"
    try_cnt = 0
    while True:
        try:
            headers = dict(common_headers, **{u"Content-Type": u"application/x-www-form-urlencoded", u"Referer": url})
            data = {u"inputbox": passwd, u"submit": u"Crack MD5 Hash!"}
            req = requests.post(url + u"index.php", headers=headers, data=data, timeout=timeout)
            result = re.search(r'<div class="result">[\s\S]*?</div>', req.text).group(0)[20:-6].strip()
            if result == u"Sorry, password not found.":
                print u"[-] cloudcracker: %s" % result
            else:
                print u"[+] cloudcracker: %s" % re.search(r'value=".*?"', result).group(0)[7:-1]
            break
        except RequestException, e:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] cloudcracker: RequestError: %s" % e
                break
        except AttributeError, e:
            print u"[-] cloudcracker: Error: %s" % e
            break


# md5-16, md5-32, sha1, mysql323, mysql5
def future_sec(passwd):
    url = u"http://md5.future-sec.com/"
    try_cnt = 0
    while True:
        try:
            headers = dict(common_headers, **{u"Content-Type": u"application/x-www-form-urlencoded", u"Referer": url})
            data = {u"h": passwd, u"t": u"auto"}
            req = requests.post(url + u"query.php", headers=headers, data=data, timeout=timeout)
            rsp = req.text
            if rsp.startswith(u'\u7834\u89e3\u5931\u8d25'):
                print u"[-] future_sec: %s" % rsp.replace(u'<br>', u' ')
            elif rsp.startswith(u'\u7834\u89e3\u6210\u529f'):
                pos = rsp.find(u'\u5bc6\u6587\u7c7b\u578b')
                print u"[+] future_sec: %s" % rsp[pos:].replace(u'<br>', u',')
            break
        except RequestException, e:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] future_sec: RequestError: %s" % e
                break
        except (ValueError, KeyError), e:
            print u"[-] future_sec: Error: %s" % e
            break


# md5-16, md5-32, sha1, mysql5
def md5lol(passwd, md5type):
    url = u"http://www.md5.lol/"
    try_cnt = 0
    while True:
        try:
            s = requests.Session()
            req = s.get(url + u"md5", headers=common_headers, timeout=timeout)
            csrf_token = re.search(r'name="csrf_token" type="hidden" value=".+?">', req.text).group(0)[39:-2]

            headers = dict(common_headers, **{u"Content-Type": u"application/x-www-form-urlencoded", u"Referer": url})
            data = {u"csrf_token": csrf_token, u"md5": passwd, u"md5type": md5type}
            req = s.post(url + u"md5", headers=headers, data=data, timeout=timeout)
            result = re.findall(r'<div class="input-group">[\s\S].+?</div>', req.text, re.S)[1][25:-6].strip()
            if result.find(u'\u6210\u529f') > 0:
                print u"[+] md5lol: %s" % result
            elif result.find(u'\u5931\u8d25') > 0:
                print u"[-] md5lol: NotFound"
            else:
                print u"[-] md5lol: %s" % result
            break
        except RequestException, e:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] md5lol: RequestError: %s" % e
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
            headers = dict(common_headers, **{u"X-Requested-With": u"XMLHttpRequest", u"Referer": url})
            req = s.post(url + u"tools/md5Util.jsp", headers=headers, params=params, timeout=timeout)
            result = req.text.strip()

            headers = dict(common_headers, **{u"Content-Type": u"application/x-www-form-urlencoded", u"Referer": url})
            data = {u"_VIEWRESOURSE": u"c4c92e61011684fc23405bfd5ebc2b31", u"md5": passwd, u"result": result}
            req = s.post(url + u"tools/md5.jsp", headers=headers, data=data, timeout=timeout)
            res = re.search(r'"realtext">[\s\S].*?</textarea>', req.text, re.S).group(0)[11:-11]
            if res.find(u'\u9057\u61be') > 0:
                print u"[-] pdtools: %s" % res
            else:
                tmp = re.split(r'\r\n', res)
                print u"[+] pdtools: %s, %s" % (tmp[2], tmp[3])
            break
        except RequestException, e:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] pdtools: RequestError: %s" % e
                break
        except (AttributeError, IndexError), e:
            print u"[-] pdtools: Error: %s" % e
            break


# md5-32
def md5net(passwd):
    url = u"http://www.md5.net/"
    try_cnt = 0
    while True:
        try:
            headers = dict(common_headers, **{u"Content-Type": u"application/x-www-form-urlencoded", u"Referer": url})
            data = {u"generator[hash]": passwd, u"generator[submit]": u""}
            req = requests.post(url + u"md5-cracker/", headers=headers, data=data, timeout=timeout)
            rsp = req.text
            result = re.search(r'background-color:transparent;margin:0px 0px 10px 0px">.*?</p>', rsp).group(0)[54:-4]
            print u"[%s] md5net: %s" % (u"-" if result == u"Not found..." else u"+", result)
            break
        except RequestException, e:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] md5net: RequestError: %s" % e
                break
        except AttributeError, e:
            print u"[-] md5net: Error: %s" % e
            break


# md5-32, sha1
def hashtoolkit(passwd):
    url = u"http://hashtoolkit.com/"
    try_cnt = 0
    while True:
        try:
            params = {u"hash": passwd}
            req = requests.get(url + u"reverse-hash", headers=common_headers, params=params, timeout=timeout)
            rsp = req.text
            if rsp.find(u"No hashes found for") > 0:
                print u"[-] hashtoolkit: NotFound"
            else:
                result = re.findall(r'<td class="res-text">.*?<span>(.*?)</span>', req.text, re.S)[0]
                print u"[+] hashtoolkit: %s" % result
            break
        except RequestException, e:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] md5net: RequestError: %s" % e
                break
        except AttributeError, e:
            print u"[-] md5net: Error: %s" % e
            break


def crack(passwd):
    threads = [threading.Thread(target=cmd5, args=(passwd,))]
    if len(passwd) == 41 and re.match(r'\*[0-9a-f]{40}|\*[0-9A-F]{40}', passwd):
        threads.append(threading.Thread(target=somd5, args=(passwd,)))
        threads.append(threading.Thread(target=leakdb, args=(passwd,)))
        threads.append(threading.Thread(target=future_sec, args=(passwd,)))
        threads.append(threading.Thread(target=md5lol, args=(passwd, 4,)))
    elif len(passwd) == 40 and re.match(r'[0-9a-f]{40}|[0-9A-F]{40}', passwd):
        threads.append(threading.Thread(target=somd5, args=(passwd,)))
        threads.append(threading.Thread(target=leakdb, args=(passwd,)))
        threads.append(threading.Thread(target=navisec, args=(passwd,)))
        threads.append(threading.Thread(target=cloudcracker, args=(passwd,)))
        threads.append(threading.Thread(target=future_sec, args=(passwd,)))
        threads.append(threading.Thread(target=md5lol, args=(passwd, 2,)))
        threads.append(threading.Thread(target=hashtoolkit, args=(passwd,)))
    elif len(passwd) == 32 and re.match(r'[0-9a-f]{32}|[0-9A-F]{32}', passwd):
        threads.append(threading.Thread(target=somd5, args=(passwd,)))
        threads.append(threading.Thread(target=pmd5, args=(passwd,)))
        threads.append(threading.Thread(target=xmd5, args=(passwd,)))
        threads.append(threading.Thread(target=navisec, args=(passwd,)))
        threads.append(threading.Thread(target=md5comcn, args=(passwd,)))
        threads.append(threading.Thread(target=blackbap, args=(passwd,)))
        threads.append(threading.Thread(target=leakdb, args=(passwd,)))
        threads.append(threading.Thread(target=cloudcracker, args=(passwd,)))
        threads.append(threading.Thread(target=future_sec, args=(passwd,)))
        threads.append(threading.Thread(target=md5lol, args=(passwd, 1,)))
        threads.append(threading.Thread(target=pdtools, args=(passwd,)))
        threads.append(threading.Thread(target=md5net, args=(passwd,)))
        threads.append(threading.Thread(target=hashtoolkit, args=(passwd,)))
    elif len(passwd) == 16 and re.match(r'[0-9a-f]{16}|[0-9A-F]{16}', passwd):
        threads.append(threading.Thread(target=somd5, args=(passwd,)))
        threads.append(threading.Thread(target=pmd5, args=(passwd,)))
        threads.append(threading.Thread(target=xmd5, args=(passwd,)))
        threads.append(threading.Thread(target=navisec, args=(passwd,)))
        threads.append(threading.Thread(target=md5comcn, args=(passwd,)))
        threads.append(threading.Thread(target=blackbap, args=(passwd,)))
        threads.append(threading.Thread(target=future_sec, args=(passwd,)))
        threads.append(threading.Thread(target=md5lol, args=(passwd, 1,)))
        threads.append(threading.Thread(target=pdtools, args=(passwd,)))

    for t in threads:
        t.start()
    for t in threads:
        t.join()


def main():
    while True:
        try:
            passwd = raw_input(u"Hash(0=exit): ")
            if passwd:
                if passwd == u'0':
                    break
                crack(passwd)
        except (KeyboardInterrupt, ValueError, EOFError):
            break


if __name__ == '__main__':
    main()
