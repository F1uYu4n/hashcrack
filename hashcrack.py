#!/usr/bin/env python
# encoding: utf-8

# __author__ = "F1uYu4n"


import json
import re
import threading
from base64 import b64encode
from hashlib import md5

import requests
from Crypto.Cipher import AES
from requests.exceptions import RequestException

timeout = 60
retry_cnt = 2
common_headers = {u"Accept": u"text/html,*/*", u"Accept-Encoding": u"gzip, deflate",
                  u"User-Agent": u"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
                  u"Accept-Language": u"zh-CN,zh;q=0.8,en-US"}


# md5-16, md5-32, sha1, mysql-323, mysql5, ...
def cmd5(passwd):
    url = u"http://cmd5.com/"
    try_cnt = 0
    while True:
        try:
            s = requests.Session()
            req = s.get(url, headers=common_headers, timeout=timeout)
            __ = dict(re.findall(ur'id="(.+?)" value="(.*?)"', req.text))

            headers = dict(common_headers, **{u"Referer": url})
            data = {u"__EVENTTARGET": __[u"__EVENTTARGET"], u"__EVENTARGUMENT": __[u"__EVENTARGUMENT"],
                    u"__VIEWSTATE": __[u"__VIEWSTATE"], u"__VIEWSTATEGENERATOR": __[u"__VIEWSTATEGENERATOR"],
                    u"ctl00$ContentPlaceHolder1$TextBoxInput": passwd,
                    u"ctl00$ContentPlaceHolder1$InputHashType": u"md5",
                    u"ctl00$ContentPlaceHolder1$Button1": u"\u67e5\u8be2",
                    u"ctl00$ContentPlaceHolder1$HiddenField1": u"",
                    u"ctl00$ContentPlaceHolder1$HiddenField2": __[u"ctl00_ContentPlaceHolder1_HiddenField2"]}
            req = s.post(url, headers=headers, data=data, timeout=timeout)
            result = re.findall(ur'<span id="ctl00_ContentPlaceHolder1_LabelAnswer">.+?<br[\s/]*>', req.text)[0]
            print u"[*] cmd5: {0}".format(re.sub(ur"(<.*?>)|(\u3002.*)", u"", result))
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] cmd5: RequestError"
                break
        except (KeyError, IndexError), e:
            print u"[-] cmd5: Error: {0}".format(e)
            break


# md5-16, md5-32
def pmd5(passwd):
    url = u"http://pmd5.com/"
    try_cnt = 0
    while True:
        try:
            s = requests.Session()
            req = s.get(url, headers=common_headers, timeout=timeout)
            __ = dict(re.findall(ur'id="(__[\w]+)" value="(.*?)"', req.text))

            headers = dict(common_headers, **{u"Referer": url})
            data = {u"__VIEWSTATE": __[u"__VIEWSTATE"], u"__EVENTVALIDATION": __[u"__EVENTVALIDATION"],
                    u"__VIEWSTATEGENERATOR": __[u"__VIEWSTATEGENERATOR"],
                    u"key": passwd, u"jiemi": u"MD5\u89e3\u5bc6"}
            req = s.post(url, headers=headers, data=data, timeout=timeout)
            rsp = req.text
            if rsp.find(u"tip success") > 0:
                plain = re.findall(ur"<em>(.+?)</em>", rsp)[1]
                print u"[+] pmd5: {0}".format(plain)
            elif rsp.find(u"tip error") > 0:
                print u"[-] pmd5: NotFound"
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] pmd5: RequestError"
                break
        except (KeyError, IndexError), e:
            print u"[-] pmd5: Error: {0}".format(e)
            break


# md5-16, md5-32
def xmd5(passwd):
    url = u"http://xmd5.com/"
    try_cnt = 0
    while True:
        try:
            s = requests.Session()
            data = {u"UserName": u"jevoyf46098@chacuo.net", u"Password": u"eEZT1FaD&$S*!t3!Y2d0",
                    u"logins": u"\u767b\u5f55"}
            req = s.post(u"{0}user/CheckLog.asp".format(url), headers=common_headers, data=data, timeout=timeout)
            checkcode = re.findall(ur'checkcode2 type=hidden value="(.+?)">', req.text)[0]

            params = {u"hash": passwd, u"xmd5": u"MD5 \u89e3\u5bc6", u"open": u"on", u"checkcode2": checkcode}
            headers = dict(common_headers, **{u"Referer": url})
            req = s.get(u"{0}md5/search.asp".format(url), params=params, headers=headers, timeout=timeout,
                        allow_redirects=False)
            location = req.headers[u"Location"]
            if location == u"getpass.asp?type=no":
                print u"[-] xmd5: NotFound"
            elif location[:16] == u"getpass.asp?info":
                print u"[+] xmd5: {0}".format(location[17:])
            elif location.find(u"403.asp") > 0:
                print u"[-] xmd5: checkcode error!"
            else:
                print u"[+] xmd5: Pay to get plain."
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] xmd5: RequestError"
                break
        except IndexError, e:
            print u"[-] xmd5: Error: {0}".format(e)
            break


# md5-16, md5-32, sha1
def navisec(passwd):
    url = u"http://md5.navisec.it/"
    try_cnt = 0
    while True:
        try:
            s = requests.Session()
            req = s.get(url, headers=common_headers, timeout=timeout)
            _token = re.findall(ur'name="_token" value="(.+?)">', req.text)[0]

            headers = dict(common_headers, **{u"Referer": url})
            data = {u"_token": _token, u"hash": passwd}
            req = s.post(u"{0}search".format(url), headers=headers, data=data, timeout=timeout)
            rsp = req.text
            result = re.findall(ur"<code>(.*?)</code>", rsp)[0]
            num = re.findall(ur"\u79ef\u5206\u5269\u4f59\uff1a[-]?\d+", rsp)[0]
            if result.find(u"\u672a\u80fd\u89e3\u5bc6") >= 0:
                print u"[-] navisec: {0}{1}".format(result, num)
            else:
                print u"[+] navisec: {0} {1}".format(result, num)
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] navisec: RequestError"
                break
        except IndexError, e:
            print u"[-] navisec: Error: {0}".format(e)
            break


# md5-16, md5-32, sha1, mysql5
def dmd5(passwd, type):
    url = u"http://www.dmd5.com/"
    try_cnt = 0
    while True:
        try:
            s = requests.Session()
            data = {u"method": u"crack", u"type": type, u"md5": passwd}
            headers = dict(common_headers, **{u"X-Requested-With": u"XMLHttpRequest", u"Referer": url})
            req = s.post(u"{0}md5Util.jsp".format(url), headers=headers, data=data, timeout=timeout)
            result = req.text.strip()

            headers = dict(common_headers, **{u"Referer": url})
            data = {u"_VIEWRESOURSE": u"c4c92e61011684fc23405bfd5ebc2b31", u"md5": passwd, u"result": result}
            req = s.post(u"{0}md5-decrypter.jsp".format(url), headers=headers, data=data, timeout=timeout)
            rsp = req.text
            if rsp.find(u"\u5f88\u9057\u61be") > 0:
                print u"[-] dmd5: NotFound"
            else:
                res = re.findall(ur"<p>(.+?)</p>", rsp)
                print u"[+] dmd5: {0}, {1}".format(res[2], res[3])
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] dmd5: RequestError"
                break
        except IndexError, e:
            print u"[-] dmd5: Error: {0}".format(e)
            break


# md5-32, sha1, sha256, sha384, sha512
def hashtoolkit(passwd):
    url = u"http://hashtoolkit.com/reverse-hash/"
    try_cnt = 0
    while True:
        try:
            params = {u"hash": passwd}
            req = requests.get(url, headers=common_headers, params=params, timeout=timeout)
            rsp = req.text
            if rsp.find(u"No hashes found for") > 0:
                print u"[-] hashtoolkit: NotFound"
            else:
                plain = re.findall(r'<td class="res-text">.*?<span.*?>(.+?)</span>', rsp, re.S)[0]
                print u"[+] hashtoolkit: {0}".format(plain)
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] hashtoolkit: RequestError"
                break
        except IndexError, e:
            print u"[-] hashtoolkit: Error: {0}".format(e)
            break


# md5-32
def md5db(passwd):
    url = u"https://md5db.net/"
    try_cnt = 0
    while True:
        try:
            req = requests.get(u"{0}api/{1}".format(url, passwd), headers=common_headers, timeout=timeout)
            rsp = req.text
            if rsp:
                print u"[+] md5db: {0}".format(rsp)
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
            req = requests.post(u"{0}ajax.php".format(url), headers=headers, data=data, timeout=timeout)
            rsp = req.json()
            if rsp[u"status"] == u"success":
                result = rsp[u"md5text"] if rsp[u"md5text"] else u"\u8be5\u6761\u662f\u4ed8\u8d39\u8bb0\u5f55"
                print u"[+] wmd5: {0}".format(result)
            else:
                print u"[-] wmd5: NotFound"
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] wmd5: RequestError"
                break
        except (KeyError, ValueError), e:
            print u"[-] wmd5: Error: {0}".format(e)
            break


# md5-16, md5-32
def t00ls(passwd):
    url = u"https://www.t00ls.net/md5_decode.html"
    try_cnt = 0
    while True:
        try:
            s = requests.Session()
            req = s.get(url, headers=common_headers, timeout=timeout)
            formhash = re.findall(r'name="formhash" value="(.+?)" />', req.text)[0]

            headers = dict(common_headers, **{u"X-Requested-With": u"XMLHttpRequest", u"Referer": url})
            data = {u"querymd5": passwd, u"md5type": u"decode", u"formhash": formhash, u"querymd5submit": u"decode"}
            req = s.post(url, headers=headers, data=data, timeout=timeout)
            rsp = req.json()
            if rsp[u"result"] == u"error" and u"\u5df2\u67e5\u5230" not in rsp[u"msg"]:
                print u"[-] t00ls: {0}".format(rsp[u"msg"])
            elif rsp[u"result"] == u"success":
                print u"[+] t00ls: {0}".format(rsp[u"mingwen"])
            else:
                print u"[+] t00ls: {0}".format(rsp[u"msg"])
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] t00ls: RequestError"
                break
        except KeyError, e:
            print u"[-] t00ls: Error: {0}".format(e)
            break


# md5-32
def nitrxgen(passwd):
    url = u"http://www.nitrxgen.net/md5db/"
    try_cnt = 0
    while True:
        try:
            req = requests.get(u"{0}{1}.txt".format(url, passwd), headers=common_headers, timeout=timeout)
            rsp = req.text
            if rsp:
                print u"[+] nitrxgen: {0}".format(rsp)
            else:
                print u"[-] nitrxgen: NotFound"
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] nitrxgen: RequestError"
                break


# md5-32
def myaddr(passwd):
    url = u"http://md5.my-addr.com/md5_decrypt-md5_cracker_online/md5_decoder_tool.php"
    try_cnt = 0
    while True:
        try:
            data = {u"md5": passwd}
            req = requests.post(url, headers=common_headers, data=data, timeout=timeout)
            result = re.findall(r"Hashed string</span>:\s(.+?)</div>", req.text)
            if result:
                print u"[+] myaddr: {0}".format(result[0])
            else:
                print u"[-] myaddr: NotFount"
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] myaddr: RequestError"
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
            data = {u"email": u"nxvcoj84201@chacuo.net", u"pass": u"!Z3jFqDKy8r6v4", u"type": u"login"}
            s.post(u"{0}HttpProxyAccess.aspx/ajax_login".format(url), headers=headers, data=json.dumps(data),
                   timeout=timeout)

            data = {u"hash": passwd, u"type": type}
            req = s.post(u"{0}HttpProxyAccess.aspx/ajax_me1ody".format(url), headers=headers, data=json.dumps(data),
                         timeout=timeout)
            rsp = req.json()
            msg = re.sub(ur"<.+?>", u"", json.loads(rsp[u"d"])[u"msg"])
            if msg.find(u"\u7834\u89e3\u6210\u529f") > 0:
                plain = re.findall(ur"\u660e\u6587:(.+?)\u6570\u636e\u6765\u6e90", msg)[0].strip()
                print u"[+] chamd5: {0}".format(plain)
            elif msg.find(u"\u91d1\u5e01\u4e0d\u8db3") >= 0:
                print u"[-] chamd5: {0}".format(msg)
            else:
                print u"[-] chamd5: NotFound"
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] chamd5: RequestError"
                break
        except (IndexError, ValueError), e:
            print u"[-] chamd5: Error: {0}".format(e)
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
            result = re.findall(r"<span.*?>(.+?)</span>", req.text)
            print u"[{0}] syue: {1}".format(u"-" if u"\u5f88\u62b1\u6b49" in result[0] else u"+", result[0])
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] syue: RequestError"
                break
        except IndexError, e:
            print u"[-] syue: Error: {0}".format(e)
            break


# md5-32
def gromweb(passwd):
    url = u"http://md5.gromweb.com/"
    try_cnt = 0
    while True:
        try:
            params = {u"md5": passwd}
            req = requests.get(url, headers=common_headers, params=params, timeout=timeout)
            rsp = req.text
            if rsp.find(u"succesfully reversed") > 0:
                plain = re.findall(ur'<em class="long-content string">(.*?)</em>', rsp)[0]
                print u"[+] gromweb: {0}".format(plain)
            else:
                print u"[-] gromweb: NotFound"
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] gromweb: RequestError"
                break
        except IndexError, e:
            print u"[-] gromweb: Error: {0}".format(e)
            break


# md5-16, md5-32, sha1, mysql-323, mysql5, ...
def hashkill(passwd):
    url = u"http://hashkill.com/"
    try_cnt = 0
    while True:
        try:
            s = requests.Session()
            req = s.get(url, headers=common_headers, timeout=timeout)
            lc = re.findall(ur'name="__lc__" value="(.+?)"', req.text)[0]

            headers = dict(common_headers, **{u"X-Requested-With": u"XMLHttpRequest", u"Referer": url})
            data = {u"action": u"checkAction", u"jyz": u"F"}
            s.post(u"{0}co.php".format(url), headers=headers, data=data, timeout=timeout)

            data = {u"userinfo": u"", u"h": passwd, u"ht": u"", u"lc": lc, u"ct": 0, u"aj": 0}
            req = s.post(u"{0}c.php".format(url), headers=headers, data=data, timeout=timeout)
            rsp = req.json()
            if isinstance(rsp[u"d"], dict) and rsp[u"d"][u"status"] == 1:
                text = rsp[u"d"][u"text"][0]
                print u"[+] hashkill: {0}, type:{1}".format(text[u"plain"], text[u"type"])
            else:
                print u"[-] hashkill: NotFound"
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] hashkill: RequestError"
                break
        except (IndexError, KeyError, TypeError), e:
            print u"[-] hashkill: Error: e".format(e)
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
                plain = re.findall(ur"Decrypted Text: </b>(.+?)</font>", rsp)[0]
                print u"[+] md5decryption: {0}".format(plain)
            else:
                print u"[-] md5decryption: NotFound"
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] md5decryption: RequestError"
                break
        except IndexError, e:
            print u"[-] md5decryption: Error: {0}".format(e)
            break


# md5-16, md5-32, sha1, mysql-323, mysql5, ...
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
                print u"[+] bugbank: {0}, type: {1}".format(result[u"answer"], result[u"type"])
            else:
                print u"[-] bugbank: {0}".format(result[u"err_msg"])
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] bugbank: RequestError"
                break
        except (KeyError, ValueError), e:
            print u"[-] bugbank: Error: {0}".format(e)
            break


# md5-32, sha1
def hashdatabase(passwd):
    url = u"http://hashdatabase.info/crack"
    try_cnt = 0
    while True:
        try:
            params = {u"hash": passwd}
            req = requests.get(url, headers=common_headers, params=params, timeout=timeout)
            rsp = req.text
            if u"plain text" in rsp:
                plain = re.findall(ur"<td><strong>(.+?)</strong></td>", rsp)[0]
                print u"[+] hashdatabase: {0}".format(plain)
            else:
                print u"[-] hashdatabase: NotFound"
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] hashdatabase: RequestError"
                break
        except IndexError, e:
            print u"[-] hashdatabase: Error: {0}".format(e)
            break


# md5-16, md5-32
def p80(passwd):
    url = u"http://md5.80p.cn/"
    try_cnt = 0
    while True:
        try:
            data = {u"decode": passwd}
            req = requests.post(url, headers=common_headers, data=data, timeout=timeout)
            result = re.findall(ur'<font color="#FF0000">(.*?)</font>', req.text)
            if result:
                print u"[+] p80: {0}".format(result[0])
            else:
                print u"[-] p80: NotFound"
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] p80: RequestError"
                break
        except IndexError, e:
            print u"[-] p80: Error: {0}".format(e)
            break


# md5-32, sha1, sha512
def md5decoder(passwd):
    url = u"http://zh.md5decoder.org/"
    try_cnt = 0
    while True:
        try:
            req = requests.get(u"{0}{1}".format(url, passwd), headers=common_headers, timeout=timeout,
                               allow_redirects=False)
            if req.status_code == 200:
                plain = re.findall(ur"<h2>(.*?)</h2>", req.text)[1]
                print u"[+] md5decoder: {0}".format(plain)
            else:
                print u"[-] md5decoder: NotFound"
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] md5decoder: RequestError"
                break
        except IndexError, e:
            print u"[-] md5decoder: Error: {0}".format(e)
            break


# md5-32
def md5decrypt(passwd):
    url = u"http://www.md5decrypt.org/"
    try_cnt = 0
    while True:
        try:
            s = requests.Session()
            req = s.get(url, headers=common_headers, timeout=timeout)
            jscheck = re.findall(ur"<script>var jscheck='(.*?)';</script>", req.text)[1]
            data = {u"jscheck": jscheck, u"value": b64encode(passwd), u"operation": u"MD5D"}
            req = s.post(u"{0}index/process".format(url), headers=common_headers, data=data, timeout=timeout)
            rsp = req.json()
            if rsp[u"body"]:
                print u"[+] md5decrypt: {0}".format(rsp[u"body"])
            else:
                print u"[-] md5decrypt: {0}".format(rsp[u"error"])
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] md5decrypt: RequestError"
                break
        except IndexError, e:
            print u"[-] md5decrypt: Error: {0}".format(e)
            break


# md5-32, sha1, sha256, sha384, sha512
def md5tr(passwd):
    url = u"http://www.md5tr.com/"
    try_cnt = 0
    while True:
        try:
            s = requests.Session()
            req = s.get(url, headers=common_headers, timeout=timeout)
            __ = dict(re.findall(ur'id="(__[\w]+)" value="(.*?)"', req.text))

            data = {u"__VIEWSTATE": __[u"__VIEWSTATE"], u"__VIEWSTATEGENERATOR": __[u"__VIEWSTATEGENERATOR"],
                    u"__EVENTVALIDATION": __[u"__EVENTVALIDATION"], u"TextBox1": passwd,
                    u"Button1": u"\u015eifreyi+\xc7\xf6z"}
            req = s.post(url, headers=common_headers, data=data, timeout=timeout)
            result = re.findall(ur'<span title="decrypted md5 hash">(.*?)</span>', req.text)
            if result:
                print u"[+] md5tr: {0}".format(result[0])
            else:
                print u"[-] md5tr: NotFound"
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] md5tr: RequestError"
                break
        except IndexError, e:
            print u"[-] md5tr: Error: {0}".format(e)
            break


# md5-32
def tellyou(passwd):
    url = u"http://md5.tellyou.top/"
    try_cnt = 0
    while True:
        try:
            s = requests.Session()
            req = s.get(url, headers=common_headers, timeout=timeout)
            __ = dict(re.findall(ur'id="(__[\w]+)" value="(.*?)"', req.text))

            data = {u"__VIEWSTATE": __[u"__VIEWSTATE"], u"__VIEWSTATEGENERATOR": __[u"__VIEWSTATEGENERATOR"],
                    u"__EVENTVALIDATION": __[u"__EVENTVALIDATION"], u"Textmd5": passwd,
                    u"MD5GET": u"\u6b63\u5728\u5904\u7406"}
            req = s.post(url, headers=common_headers, data=data, timeout=timeout)
            result = re.findall(ur'<span id="[\w]*?" class="MD5TXT\s.*?">.+?</span>', req.text)
            if result:
                plain = re.sub(ur"<.*?>", u"", result[0])
                print u"[{0}] tellyou: {1}".format(u"-" if re.findall(ur"\u6ca1\u627e\u5230", plain) else u"+", plain)
            else:
                print u"[-] tellyou: NotFound"
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] tellyou: RequestError"
                break
        except IndexError, e:
            print u"[-] tellyou: Error: {0}".format(e)
            break


# md5-16, md5-32, sha1, mysql323, mysql5
def somd5(passwd):
    url = u"http://www.somd5.com/"
    try_cnt = 0
    while True:
        try:
            params = {u"hash": passwd, u"t": 0}
            pad = lambda s: s + ((16 - len(s) % 16) % 16) * chr(0)
            key = iv = md5(passwd).hexdigest()[:16]
            cookies = {u"key": b64encode(AES.new(key, AES.MODE_CBC, iv).encrypt(pad(passwd)))}
            req = requests.get(u"{0}ss.php".format(url), headers=common_headers, params=params, cookies=cookies,
                               timeout=timeout)
            result = req.content.decode("utf-8")
            print u"[{0}] somd5: {1}".format(u"-" if re.findall(ur"(\u641e\u4e8b)|(\u672a\u67e5\u5230)") else u"+",
                                             result)
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] somd5: RequestError"
                break


# md5-16, md5-32, sha1, mysql-323, mysql5, ...
def cmd5la(passwd):
    url = u"http://cmd5.la/checkit.php"
    try_cnt = 0
    while True:
        try:
            data = {u"pwd": passwd, u"jiejia": u"jie"}
            req = requests.post(url, headers=common_headers, data=data, timeout=timeout)
            result = re.findall(ur"\u662f:(.+)", req.content.decode("utf-8"))
            if result:
                print u"[+] cmd5la: {0}".format(result[0].strip())
            else:
                print u"[-] cmd5la: NotFound"
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] cmd5la: RequestError"
                break
        except IndexError, e:
            print u"[-] cmd5la: Error: {0}".format(e)
            break


# md5-16, md5-32, sha1, mysql-323, mysql5, ...
def ttmd5(passwd):
    url = u"http://www.ttmd5.com/do.php"
    try_cnt = 0
    while True:
        try:
            s = requests.Session()
            params = {u"c": u"User", u"m": u"doLogin"}
            data = {u"hidUser": u"uplnwkdc@mail.bccto.me", u"hidPassword": u"c927dc915426c2c89de3330c397fadf9"}
            s.post(url, headers=common_headers, params=params, data=data, timeout=timeout)

            params = {u"c": u"Decode", u"m": u"getMD5", u"md5": passwd}
            req = s.get(url, headers=common_headers, params=params, timeout=timeout)
            rsp = req.json()
            if u"plain" in rsp:
                print u"[+] ttmd5: {0}".format(rsp[u"plain"])
            else:
                print u"[-] ttmd5: NotFound"
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] ttmd5: RequestError"
                break
        except IndexError, e:
            print u"[-] ttmd5: Error: {0}".format(e)
            break


def crack(passwd):
    threads = [threading.Thread(target=cmd5, args=(passwd,)), threading.Thread(target=hashkill, args=(passwd,)),
               threading.Thread(target=bugbank, args=(passwd,)), threading.Thread(target=cmd5la, args=(passwd,)),
               threading.Thread(target=ttmd5, args=(passwd,))]
    if len(passwd) == 41 and re.match(r'\*[0-9a-f]{40}|\*[0-9A-F]{40}', passwd):
        threads.append(threading.Thread(target=chamd5, args=(passwd[1:], u"300",)))
        threads.append(threading.Thread(target=dmd5, args=(passwd[1:], 4,)))
        threads.append(threading.Thread(target=somd5, args=(passwd[1:],)))
    elif len(passwd) == 40 and re.match(r'[0-9a-f]{40}|[0-9A-F]{40}', passwd):
        threads.append(threading.Thread(target=navisec, args=(passwd,)))
        threads.append(threading.Thread(target=hashdatabase, args=(passwd,)))
        threads.append(threading.Thread(target=hashtoolkit, args=(passwd,)))
        threads.append(threading.Thread(target=wmd5, args=(passwd,)))
        threads.append(threading.Thread(target=chamd5, args=(passwd, u"100",)))
        threads.append(threading.Thread(target=chamd5, args=(passwd, u"300",)))
        threads.append(threading.Thread(target=dmd5, args=(passwd, 4,)))
        threads.append(threading.Thread(target=md5decoder, args=(passwd,)))
        threads.append(threading.Thread(target=md5tr, args=(passwd,)))
        threads.append(threading.Thread(target=somd5, args=(passwd,)))
    elif len(passwd) == 32 and re.match(r'[0-9a-f]{32}|[0-9A-F]{32}', passwd):
        threads.append(threading.Thread(target=pmd5, args=(passwd,)))
        threads.append(threading.Thread(target=xmd5, args=(passwd,)))
        threads.append(threading.Thread(target=navisec, args=(passwd,)))
        threads.append(threading.Thread(target=hashdatabase, args=(passwd,)))
        threads.append(threading.Thread(target=dmd5, args=(passwd, 1,)))
        threads.append(threading.Thread(target=hashtoolkit, args=(passwd,)))
        threads.append(threading.Thread(target=md5db, args=(passwd,)))
        threads.append(threading.Thread(target=wmd5, args=(passwd,)))
        threads.append(threading.Thread(target=t00ls, args=(passwd,)))
        threads.append(threading.Thread(target=nitrxgen, args=(passwd,)))
        threads.append(threading.Thread(target=myaddr, args=(passwd,)))
        threads.append(threading.Thread(target=chamd5, args=(passwd, u"md5",)))
        threads.append(threading.Thread(target=syue, args=(passwd,)))
        threads.append(threading.Thread(target=gromweb, args=(passwd,)))
        threads.append(threading.Thread(target=md5decryption, args=(passwd,)))
        threads.append(threading.Thread(target=p80, args=(passwd,)))
        threads.append(threading.Thread(target=md5decoder, args=(passwd,)))
        threads.append(threading.Thread(target=md5decrypt, args=(passwd,)))
        threads.append(threading.Thread(target=md5tr, args=(passwd,)))
        threads.append(threading.Thread(target=tellyou, args=(passwd,)))
        threads.append(threading.Thread(target=somd5, args=(passwd,)))
    elif len(passwd) == 16 and re.match(r'[0-9a-f]{16}|[0-9A-F]{16}', passwd):
        threads.append(threading.Thread(target=pmd5, args=(passwd,)))
        threads.append(threading.Thread(target=xmd5, args=(passwd,)))
        threads.append(threading.Thread(target=navisec, args=(passwd,)))
        threads.append(threading.Thread(target=dmd5, args=(passwd, 1,)))
        threads.append(threading.Thread(target=wmd5, args=(passwd,)))
        threads.append(threading.Thread(target=t00ls, args=(passwd,)))
        threads.append(threading.Thread(target=chamd5, args=(passwd, u"md5",)))
        threads.append(threading.Thread(target=chamd5, args=(passwd, u"200",)))
        threads.append(threading.Thread(target=syue, args=(passwd,)))
        threads.append(threading.Thread(target=p80, args=(passwd,)))
        threads.append(threading.Thread(target=somd5, args=(passwd,)))
    elif passwd.find(':') > 0:
        threads.append(threading.Thread(target=chamd5, args=(passwd, u"10",)))
        threads.append(threading.Thread(target=dmd5, args=(passwd, 5,)))
    elif len(passwd) in [64, 96, 128]:
        threads.append(threading.Thread(target=hashtoolkit, args=(passwd,)))
        threads.append(threading.Thread(target=md5decoder, args=(passwd,)))
        threads.append(threading.Thread(target=md5tr, args=(passwd,)))

    for t in threads:
        t.start()
    for t in threads:
        t.join()


def main():
    while True:
        try:
            passwd = raw_input(u"Hash: ").strip()
            if passwd:
                crack(passwd)
        except (KeyboardInterrupt, ValueError, EOFError):
            break


if __name__ == '__main__':
    main()
