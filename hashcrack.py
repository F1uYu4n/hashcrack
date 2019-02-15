#!/usr/bin/env python
# encoding: utf-8

# __author__ = "F1uYu4n"


import json
import os
import re
import threading
from urllib import unquote

import requests
from requests.exceptions import RequestException
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

timeout = 30
retry_cnt = 2
common_headers = {u"User-Agent": u"Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko"}


# md5-16, md5-32, sha1, mysql-323, mysql5, ...
def cmd5(passwd):
    url = u"https://cmd5.com/"
    try_cnt = 0
    while True:
        try:
            s = requests.Session()
            req = s.get(url, headers=common_headers, timeout=timeout, verify=False)
            __ = dict(re.findall(ur'id="(.+?)" value="(.*?)"', req.text))

            headers = dict(common_headers, **{u"Referer": url})
            data = {u"__EVENTTARGET": __[u"__EVENTTARGET"], u"__EVENTARGUMENT": __[u"__EVENTARGUMENT"],
                    u"__VIEWSTATE": __[u"__VIEWSTATE"], u"__VIEWSTATEGENERATOR": __[u"__VIEWSTATEGENERATOR"],
                    u"ctl00$ContentPlaceHolder1$TextBoxInput": passwd,
                    u"ctl00$ContentPlaceHolder1$InputHashType": u"md5",
                    u"ctl00$ContentPlaceHolder1$Button1": u"\u67e5\u8be2",
                    u"ctl00$ContentPlaceHolder1$HiddenFieldAliCode": u"",
                    u"ctl00$ContentPlaceHolder1$HiddenField1": u"",
                    u"ctl00$ContentPlaceHolder1$HiddenField2": __[u"ctl00_ContentPlaceHolder1_HiddenField2"]}
            req = s.post(url, headers=headers, data=data, timeout=timeout, verify=False)
            result = re.findall(ur'<span id="LabelAnswer" class="LabelAnswer".*?>(.+?)<', req.text)[0]
            print u"[*] cmd5: {0}".format(re.sub(ur"\u3002.*", u"", result))
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
    url = u"https://api.pmd5.com/pmd5api/"
    try_cnt = 0
    while True:
        try:
            s = requests.Session()
            req = s.get(u"{0}checkcode".format(url), headers=common_headers, timeout=timeout, verify=False)
            pmd5api = re.findall(ur"koa.sess.pmd5api=([\w=]+)", req.headers[u"Set-Cookie"])
            if pmd5api:
                capcha = json.loads(pmd5api[0].decode("base64"))[u"capcha"]
                params = {u"checkcode": capcha, u"pwd": passwd}
                req = s.get(u"{0}pmd5".format(url), params=params, headers=common_headers, timeout=timeout,
                            verify=False)
                result = req.json()[u"result"].values()
                if result:
                    print u"[+] pmd5: {0}".format(result[0])
                else:
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
    url = u"https://xmd5.com/"
    try_cnt = 0
    while True:
        try:
            s = requests.Session()
            data = {u"UserName": u"jevoyf46098@chacuo.net", u"Password": u"eEZT1FaD&$S*!t3!Y2d0",
                    u"logins": u"\u767b\u5f55"}
            req = s.post(u"{0}user/CheckLog.asp".format(url), headers=common_headers, data=data, timeout=timeout,
                         verify=False)
            checkcode = re.findall(ur'checkcode2 type=hidden value="(.+?)">', req.text)[0]

            params = {u"hash": passwd, u"xmd5": u"MD5 \u89e3\u5bc6", u"open": u"on", u"checkcode2": checkcode}
            headers = dict(common_headers, **{u"Referer": url})
            req = s.get(u"{0}md5/search.asp".format(url), params=params, headers=headers, timeout=timeout,
                        allow_redirects=False, verify=False)
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
    url = u"https://md5.navisec.it/"
    try_cnt = 0
    while True:
        try:
            s = requests.Session()
            req = s.get(url, headers=common_headers, timeout=timeout, verify=False)
            _token = re.findall(ur'name="_token" value="(.+?)">', req.text)[0]

            headers = dict(common_headers, **{u"Referer": url})
            data = {u"_token": _token, u"hash": passwd}
            req = s.post(u"{0}search".format(url), headers=headers, data=data, timeout=timeout, verify=False)
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


# md5-32, sha1, sha256, sha384, sha512
def hashtoolkit(passwd):
    url = u"https://hashtoolkit.com/reverse-hash/"
    try_cnt = 0
    while True:
        try:
            params = {u"hash": passwd}
            req = requests.get(url, headers=common_headers, params=params, timeout=timeout, verify=False)
            rsp = req.text
            if rsp.find(u"No hashes found for") > 0:
                print u"[-] hashtoolkit: NotFound"
            else:
                plain = re.findall(r'<a href="/generate-hash/\?text=(.*?)"', rsp, re.S)[0]
                print u"[+] hashtoolkit: {0}".format(unquote(plain))
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
    url = u"https://www.chamd5.org/"
    try_cnt = 0
    while True:
        try:
            s = requests.Session()
            headers = dict(common_headers, **{u"Content-Type": u"application/json", u"Referer": url,
                                              u"X-Requested-With": u"XMLHttpRequest"})
            data = {u"email": u"jxtepz93152@chacuo.net", u"pass": u"!Z3jFqDKy8r6v4", u"type": u"login"}
            s.post(u"{0}HttpProxyAccess.aspx/ajax_login".format(url), headers=headers, data=json.dumps(data),
                   timeout=timeout, verify=False)

            data = {u"hash": passwd, u"type": type}
            req = s.post(u"{0}HttpProxyAccess.aspx/ajax_me1ody".format(url), headers=headers, data=json.dumps(data),
                         timeout=timeout, verify=False)
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


# md5-32
def gromweb(passwd):
    url = u"https://md5.gromweb.com/"
    try_cnt = 0
    while True:
        try:
            params = {u"md5": passwd}
            req = requests.get(url, headers=common_headers, params=params, timeout=timeout, verify=False)
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


# md5-16, md5-32
def bugbank(passwd):
    url = u"https://www.bugbank.cn/api/md5"
    try_cnt = 0
    while True:
        try:
            headers = dict(common_headers, **{u"X-Requested-With": u"XMLHttpRequest", u"Referer": url})
            data = {u"md5text": passwd, u"hashtype": 0}
            req = requests.post(url, headers=headers, data=data, timeout=timeout, verify=False)
            result = req.json()
            if u"answer" in result:
                if result[u"answer"] != u"error!":
                    print u"[+] bugbank: %s, type: %s" % (result[u"answer"], result[u"type"])
                else:
                    print u"[-] bugbank: error!"
            else:
                print u"[-] bugbank: %s" % result[u"err_msg"]
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] bugbank: RequestError"
                break
        except (KeyError, ValueError), e:
            print u"[-] bugbank: Error: {0}".format(e)
            break


# md5-16, md5-32
def tellyou(passwd):
    url = u"http://md5.tellyou.top/MD5Service.asmx/HelloMd5"
    try_cnt = 0
    while True:
        try:
            params = {u"Ciphertext": passwd}
            headers = dict(common_headers, **{u"X-Forwarded-For": u"192.168.1.1"})
            req = requests.get(url, params=params, headers=headers, timeout=timeout)
            result = re.findall(ur'<string xmlns="http://tempuri.org/">(.*?)</string>', req.text)
            if result:
                print u"[+] tellyou: {0}".format(result[0])
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


# mysql5
def mysql_password(passwd):
    url = u"https://www.mysql-password.com/api/get-password"
    try_cnt = 0
    while True:
        try:
            data = {u"hash": passwd}
            req = requests.post(url, headers=common_headers, data=data, timeout=timeout, verify=False)
            result = req.json()
            if u"error" in result:
                print u"[-] mysql_password: {0}".format(result[u"error"])
            else:
                print u"[+] mysql_password: {0}".format(result[u"password"])
            break
        except RequestException:
            try_cnt += 1
            if try_cnt >= retry_cnt:
                print u"[-] mysql_password: RequestError"
                break
        except IndexError, e:
            print u"[-] mysql_password: Error: {0}".format(e)
            break


def crack(passwd):
    threads = [threading.Thread(target=cmd5, args=(passwd,)), threading.Thread(target=hashtoolkit, args=(passwd,)),
               threading.Thread(target=ttmd5, args=(passwd,))]
    if len(passwd) == 41 and re.match(r'\*[0-9a-f]{40}|\*[0-9A-F]{40}', passwd):
        threads.append(threading.Thread(target=chamd5, args=(passwd[1:], u"300",)))
        threads.append(threading.Thread(target=mysql_password, args=(passwd,)))
    elif len(passwd) == 40 and re.match(r'[0-9a-f]{40}|[0-9A-F]{40}', passwd):
        threads.append(threading.Thread(target=navisec, args=(passwd,)))
        threads.append(threading.Thread(target=chamd5, args=(passwd, u"100",)))
        threads.append(threading.Thread(target=chamd5, args=(passwd, u"300",)))
        threads.append(threading.Thread(target=mysql_password, args=(passwd,)))
    elif len(passwd) == 32 and re.match(r'[0-9a-f]{32}|[0-9A-F]{32}', passwd):
        threads.append(threading.Thread(target=pmd5, args=(passwd,)))
        threads.append(threading.Thread(target=xmd5, args=(passwd,)))
        threads.append(threading.Thread(target=navisec, args=(passwd,)))
        threads.append(threading.Thread(target=nitrxgen, args=(passwd,)))
        threads.append(threading.Thread(target=myaddr, args=(passwd,)))
        threads.append(threading.Thread(target=chamd5, args=(passwd, u"md5",)))
        threads.append(threading.Thread(target=gromweb, args=(passwd,)))
        threads.append(threading.Thread(target=bugbank, args=(passwd,)))
        threads.append(threading.Thread(target=tellyou, args=(passwd,)))
    elif len(passwd) == 16 and re.match(r'[0-9a-f]{16}|[0-9A-F]{16}', passwd):
        threads.append(threading.Thread(target=pmd5, args=(passwd,)))
        threads.append(threading.Thread(target=xmd5, args=(passwd,)))
        threads.append(threading.Thread(target=navisec, args=(passwd,)))
        threads.append(threading.Thread(target=chamd5, args=(passwd, u"md5",)))
        threads.append(threading.Thread(target=chamd5, args=(passwd, u"200",)))
        threads.append(threading.Thread(target=bugbank, args=(passwd,)))
        threads.append(threading.Thread(target=tellyou, args=(passwd,)))
    elif passwd.find(':') > 0:
        threads.append(threading.Thread(target=chamd5, args=(passwd, u"10",)))

    for t in threads:
        t.start()
    for t in threads:
        t.join()


def main():
    while True:
        try:
            passwd = raw_input(u"Hash: ").strip()
            if passwd:
                with open("{0}\\hash.log".format(os.path.split(os.path.realpath(__file__))[0]), 'a+') as f:
                    f.write(passwd + os.linesep)
                crack(passwd)
        except (KeyboardInterrupt, ValueError, EOFError):
            break


if __name__ == '__main__':
    main()
