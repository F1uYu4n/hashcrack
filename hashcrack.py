#!/usr/bin/env python
# encoding: utf-8

# __author__ = "F1uYu4n"

import json
import re
import threading
import urlparse

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

            headers = dict(common_headers, **{u"Referer": url})
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

            headers = dict(common_headers, **{u"Referer": url})
            data = {u"__VIEWSTATE": __[u"__VIEWSTATE"], u"__EVENTVALIDATION": __[u"__EVENTVALIDATION"],
                    u"key": passwd, u"jiemi": u"MD5\u89e3\u5bc6"}
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
def xmd5(passwd):
    url = u"http://xmd5.com/"
    try_cnt = 0
    while True:
        try:
            s = requests.Session()
            headers = dict(common_headers, **{u"Referer": url})
            data = {u"UserName": u"jevoyf46098@chacuo.net", u"Password": u"eEZT1FaD&$S*!t3!Y2d0",
                    u"logins": "\xb5\xc7\xc2\xbc"}
            req = s.post(urlparse.urljoin(url, u"/user/CheckLog.asp"), headers=headers, data=data, timeout=timeout)
            checkcode = re.search(r'checkcode2 type=hidden value=".*?">', req.text).group(0)[30:-2]

            params = {u"hash": passwd, u"xmd5": "MD5 \xbd\xe2\xc3\xdc", u"open": u"on", u"checkcode2": checkcode}
            headers = dict(common_headers, **{u"Referer": url})
            req = s.get(urlparse.urljoin(url, u"/md5/search.asp"), params=params, headers=headers, timeout=timeout)
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

            headers = dict(common_headers, **{u"Referer": url})
            data = {u"_token": _token, u"hash": passwd}
            req = s.post(urlparse.urljoin(url, u"/search"), headers=headers, data=data, timeout=timeout)
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


# md5-16, md5-32, sha1, mysql323, mysql5, discuz
def future_sec(passwd):
    url = u"http://md5.future-sec.com/query.php"
    try_cnt = 0
    while True:
        try:
            headers = dict(common_headers, **{u"Referer": url})
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


# md5-16, md5-32
def dmd5(passwd, type):
    url = u"http://www.dmd5.com/"
    try_cnt = 0
    while True:
        try:
            s = requests.Session()
            params = {u"method": u"crack", u"type": type, u"md5": passwd}
            headers = dict(common_headers, **{u"X-Requested-With": u"XMLHttpRequest", u"Referer": url})
            req = s.post(urlparse.urljoin(url, u"/md5Util.jsp"), headers=headers, params=params, timeout=timeout)
            result = req.text.strip()

            headers = dict(common_headers, **{u"Referer": url})
            data = {u"_VIEWRESOURSE": u"c4c92e61011684fc23405bfd5ebc2b31", u"md5": passwd, u"result": result}
            req = s.post(urlparse.urljoin(url, u"/md5-decrypter.jsp"), headers=headers, data=data, timeout=timeout)
            rsp = req.text
            if rsp.find(u'\u5f88\u9057\u61be') > 0:
                print u"[-] dmd5: NotFound"
            else:
                res = re.findall(r'<p>(.*?)</p>', rsp)
                print u"[+] dmd5: %s, %s" % (res[2], res[3])
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] dmd5: RequestError"
                break
        except IndexError, e:
            print u"[-] dmd5: Error: %s" % e
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
    url = u"https://md5db.net/"
    try_cnt = 0
    while True:
        try:
            req = requests.get(urlparse.urljoin(url, u"/api/%s" % passwd), headers=common_headers, timeout=timeout)
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
def wmd5(passwd):
    url = u"http://www.wmd5.com/"
    try_cnt = 0
    while True:
        try:
            headers = dict(common_headers, **{u"X-Requested-With": u"XMLHttpRequest", u"Referer": url})
            data = {u"miwen": passwd, u"action": u"md5show"}
            req = requests.post(urlparse.urljoin(url, u"/ajax.php"), headers=headers, data=data, timeout=timeout)
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
        except (KeyError, ValueError), e:
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

            headers = dict(common_headers, **{u"X-Requested-With": u"XMLHttpRequest", u"Referer": url})
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


# md5-32
def nitrxgen(passwd):
    url = u"http://www.nitrxgen.net/md5db/"
    try_cnt = 0
    while True:
        try:
            headers = dict(common_headers, **{u"Referer": url})
            req = requests.get(url + passwd + u".txt", headers=headers, timeout=timeout)
            result = req.text
            if result:
                print u"[+] nitrxgen: %s" % result
            else:
                print u"[-] nitrxgen: NotFound"
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] nitrxgen: RequestError"
                break
        except AttributeError, e:
            print u"[-] nitrxgen: Error: %s" % e
            break


# md5-32
def myaddr(passwd):
    url = u"http://md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php"
    try_cnt = 0
    while True:
        try:
            headers = dict(common_headers, **{u"Referer": url})
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
            data = {u"email": u"drtekj82764@chacuo.net", u"pass": u"!Z3jFqDKy8r6v4", u"type": u"login"}
            s.post(urlparse.urljoin(url, u"/HttpProxyAccess.aspx/ajax_login"), headers=headers, data=json.dumps(data),
                   timeout=timeout)

            data = {u"hash": passwd, u"type": type}
            req = s.post(urlparse.urljoin(url, u"/HttpProxyAccess.aspx/ajax_me1ody"), headers=headers,
                         data=json.dumps(data), timeout=timeout)
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
            headers = dict(common_headers, **{u"X-Requested-With": u"XMLHttpRequest", u"Referer": url})
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


# md5-16, md5-32, sha1, mysql-323, mysql5, and so on...
def l44ll8(passwd):
    url = u"http://www.144118.com/md5c/"
    try_cnt = 0
    while True:
        try:
            headers = dict(common_headers, **{u"X-Requested-With": u"XMLHttpRequest", u"Referer": url})
            params = {u"md5c": passwd}
            req = requests.get(url, headers=headers, params=params, timeout=timeout)
            req.encoding = 'utf-8-sig'
            result = json.loads(req.text.strip()[3:])
            if result[u"result"]:
                print u"[+] l44ll8: %s" % result[u"result"]
            else:
                print u"[-] l44ll8: NotFound"
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] l44ll8: RequestError"
                break
        except (KeyError, ValueError), e:
            print u"[-] l44ll8: Error: %s" % e
            break


# md5-16, md5-32, sha1, mysql-323, mysql5, and so on...
def hashkill(passwd):
    url = u"http://hashkill.com/"
    try_cnt = 0
    while True:
        try:
            s = requests.Session()
            req = s.get(url, headers=common_headers, timeout=timeout)
            lc = re.search(r'name="__lc__" value=".+?"', req.text).group(0)[21:-1]

            headers = dict(common_headers, **{u"Referer": url, u"X-Requested-With": u"XMLHttpRequest"})
            data = {u"action": u"checkAction", u"jyz": u'F'}
            s.post(urlparse.urljoin(url, u"/co.php"), headers=headers, data=data, timeout=timeout)

            data = {u"userinfo": u"", u'h': passwd, u"ht": u'', u"lc": lc, u"ct": 0, u"aj": 0}
            req = s.post(urlparse.urljoin(url, u"/c.php"), headers=headers, data=data, timeout=timeout)
            rsp = req.json()
            if isinstance(rsp[u'd'], dict) and rsp[u'd'][u"status"] == 1:
                text = rsp[u"d"][u"text"][0]
                print u"[+] hashkill: %s, type:%s" % (text[u"plain"], text[u"type"])
            else:
                print u"[-] hashkill: NotFound"
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] hashkill: RequestError"
                break
        except (IndexError, AttributeError, KeyError, TypeError), e:
            print u"[-] hashkill: Error: %s" % e
            break


# md5-32
def md5decryption(passwd):
    url = u"http://md5decryption.com/"
    try_cnt = 0
    while True:
        try:
            headers = dict(common_headers, **{u"X-Requested-With": u"XMLHttpRequest", u"Referer": url})
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


# md5-16, md5-32, sha1, mysql, mysql5, and so on...
def bugbank(passwd):
    url = u"http://www.bugbank.cn/api/md5"
    try_cnt = 0
    while True:
        try:
            headers = dict(common_headers, **{u"X-Requested-With": u"XMLHttpRequest", u"Referer": url})
            data = {u"md5text": passwd, u"hashtype": 0}
            req = requests.post(url, headers=headers, data=data, timeout=timeout)
            result = req.json()
            if u"answer" in result:
                print u"[+] bugbank: %s, type: %s" % (result[u"answer"], result[u"type"])
            else:
                print u"[-] bugbank: %s" % result[u"err_msg"]
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] bugbank: RequestError"
                break
        except KeyError, e:
            print u"[-] bugbank: Error: %s" % e
            break


def crack(passwd):
    threads = [threading.Thread(target=cmd5, args=(passwd,)), threading.Thread(target=l44ll8, args=(passwd,)),
               threading.Thread(target=hashkill, args=(passwd,)), threading.Thread(target=bugbank, args=(passwd,))]
    if len(passwd) == 41 and re.match(r'\*[0-9a-f]{40}|\*[0-9A-F]{40}', passwd):
        # threads.append(threading.Thread(target=future_sec, args=(passwd,)))
        threads.append(threading.Thread(target=chamd5, args=(passwd[1:], u"300",)))
        threads.append(threading.Thread(target=dmd5, args=(passwd[1:], 4,)))
    elif len(passwd) == 40 and re.match(r'[0-9a-f]{40}|[0-9A-F]{40}', passwd):
        threads.append(threading.Thread(target=navisec, args=(passwd,)))
        # threads.append(threading.Thread(target=future_sec, args=(passwd,)))
        threads.append(threading.Thread(target=hashtoolkit, args=(passwd,)))
        threads.append(threading.Thread(target=wmd5, args=(passwd,)))
        threads.append(threading.Thread(target=chamd5, args=(passwd, u"100",)))
        threads.append(threading.Thread(target=chamd5, args=(passwd, u"300",)))
        threads.append(threading.Thread(target=dmd5, args=(passwd, 4,)))
    elif len(passwd) == 32 and re.match(r'[0-9a-f]{32}|[0-9A-F]{32}', passwd):
        threads.append(threading.Thread(target=pmd5, args=(passwd,)))
        threads.append(threading.Thread(target=xmd5, args=(passwd,)))
        threads.append(threading.Thread(target=navisec, args=(passwd,)))
        # threads.append(threading.Thread(target=future_sec, args=(passwd,)))
        threads.append(threading.Thread(target=dmd5, args=(passwd, 1,)))
        threads.append(threading.Thread(target=hashtoolkit, args=(passwd,)))
        threads.append(threading.Thread(target=md5db, args=(passwd,)))
        threads.append(threading.Thread(target=wmd5, args=(passwd,)))
        threads.append(threading.Thread(target=t00ls, args=(passwd,)))
        threads.append(threading.Thread(target=nitrxgen, args=(passwd,)))
        threads.append(threading.Thread(target=myaddr, args=(passwd,)))
        threads.append(threading.Thread(target=chamd5, args=(passwd, u"md5",)))
        threads.append(threading.Thread(target=syue, args=(passwd,)))
        threads.append(threading.Thread(target=md5pass, args=(passwd,)))
        threads.append(threading.Thread(target=gromweb, args=(passwd,)))
        threads.append(threading.Thread(target=md5decryption, args=(passwd,)))
    elif len(passwd) == 16 and re.match(r'[0-9a-f]{16}|[0-9A-F]{16}', passwd):
        threads.append(threading.Thread(target=pmd5, args=(passwd,)))
        threads.append(threading.Thread(target=xmd5, args=(passwd,)))
        threads.append(threading.Thread(target=navisec, args=(passwd,)))
        # threads.append(threading.Thread(target=future_sec, args=(passwd,)))
        threads.append(threading.Thread(target=dmd5, args=(passwd, 1,)))
        threads.append(threading.Thread(target=wmd5, args=(passwd,)))
        threads.append(threading.Thread(target=t00ls, args=(passwd,)))
        threads.append(threading.Thread(target=chamd5, args=(passwd, u"md5",)))
        threads.append(threading.Thread(target=chamd5, args=(passwd, u"200",)))
        threads.append(threading.Thread(target=syue, args=(passwd,)))
    elif passwd.find(':') > 0:
        threads.append(threading.Thread(target=chamd5, args=(passwd, u"10",)))
        # threads.append(threading.Thread(target=future_sec, args=(passwd,)))
        threads.append(threading.Thread(target=dmd5, args=(passwd, 3,)))
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
