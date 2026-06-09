#!/usr/bin/env python3
# encoding: utf-8

"""
hashcrack.py - Hash online lookup tool
Queries multiple hash lookup websites simultaneously via multi-threading.

Supported hash types:
  MD5-16, MD5-32, SHA1, MySQL-323, MySQL5, SHA256, SHA384, SHA512, ...

Requirements: Python 3.6+, requests
"""

__author__ = "F1uYu4n"
__version__ = "2.0.0"

import json
import os
import re
import sys
import threading
from urllib.parse import unquote

# Fix Windows console encoding (GBK cannot print some Unicode)
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import requests
from requests.exceptions import RequestException
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ========================= Configuration =========================

TIMEOUT = 30
RETRY_CNT = 2
COMMON_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

# ========================= Helper Functions =========================


def query(site, method, url, session=True, **kwargs):
    """Execute an HTTP request with retry logic.

    Args:
        site:    Site name for error messages
        method:  "get" or "post"
        url:     Target URL
        session: Whether to use a persistent Session
        **kwargs: Passed directly to requests

    Returns:
        Response object on success, None on failure
    """
    kwargs.setdefault("headers", COMMON_HEADERS.copy())
    kwargs.setdefault("timeout", TIMEOUT)
    kwargs.setdefault("verify", False)

    requester = requests.Session() if session else requests

    for attempt in range(RETRY_CNT):
        try:
            if method == "get":
                return requester.get(url, **kwargs)
            return requester.post(url, **kwargs)
        except RequestException as e:
            if attempt == RETRY_CNT - 1:
                print_result(site, None, extra="RequestError", error=True)
                return None

    return None


def print_result(site, plain, extra="", error=False):
    """Print a formatted query result.

    Args:
        site:  Site name
        plain: Decrypted plaintext (None if failed)
        extra: Additional info to append
        error: If True, print as error/not-found message
    """
    if error:
        msg = extra or "NotFound"
        print(f"[-] {site}: {msg}")
    else:
        suffix = f" {extra}" if extra else ""
        print(f"[+] {site}: {plain}{suffix}")


# ========================= Hash Lookup Sources =========================


def cmd5(passwd):
    """cmd5.com - MD5/SHA1/SHA256/MySQL/Discuz/...

    Uses a two-step session approach:
      1. GET the page with hash pre-filled (?str=...)
      2. POST the form from the same session
    This avoids the error-page redirect that happens with a standalone POST.
    """
    url = "https://cmd5.com/default.aspx"
    s = requests.Session()

    # Step 1: Load page with hash pre-filled (initializes session + ViewState)
    resp = s.get(url, headers=COMMON_HEADERS.copy(), timeout=TIMEOUT,
                 verify=False, params={"str": passwd})
    if resp is None:
        print_result("cmd5", None, extra="RequestError", error=True)
        return

    try:
        resp.encoding = "utf-8"
        fields = dict(re.findall(r'id="(.+?)"\s+value="(.*?)"', resp.text))

        # Step 2: POST form from the same session
        data = {
            "__EVENTTARGET": "ctl00$ContentPlaceHolder1$Button1",
            "__EVENTARGUMENT": fields.get("__EVENTARGUMENT", ""),
            "__VIEWSTATE": fields["__VIEWSTATE"],
            "__VIEWSTATEGENERATOR": fields.get("__VIEWSTATEGENERATOR", ""),
            "__VIEWSTATEENCRYPTED": "",
            "ctl00$ContentPlaceHolder1$TextBoxInput": passwd,
            "ctl00$ContentPlaceHolder1$InputHashType": "md5",
            "ctl00$ContentPlaceHolder1$Button1": "\u67e5\u8be2",
            "ctl00$ContentPlaceHolder1$HiddenFieldAliCode": "",
            "ctl00$ContentPlaceHolder1$HiddenField1": "",
            "ctl00$ContentPlaceHolder1$HiddenField2": fields.get(
                "ctl00_ContentPlaceHolder1_HiddenField2", ""
            ),
        }
        post_headers = {
            **COMMON_HEADERS,
            "Referer": f"{url}?str={passwd}",
            "Origin": "https://cmd5.com",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        resp = s.post(url, headers=post_headers, data=data,
                      timeout=TIMEOUT, verify=False)
        if resp is None:
            print_result("cmd5", None, extra="RequestError", error=True)
            return

        resp.encoding = "utf-8"
        result = re.findall(
            r'<span id="LabelAnswer"[^>]*>(.*?)</span>', resp.text, re.S
        )
        if result and result[0].strip():
            text = re.sub(r"\u3002.*", "", result[0].strip())
            print_result("cmd5", text)
        else:
            # Check if it's a paid record (found but not shown)
            if "\u4ed8\u8d39\u8bb0\u5f55" in resp.text:
                print_result("cmd5", None, extra="\u5df2\u67e5\u5230\uff0c\u4f46\u4e3a\u4ed8\u8d39\u8bb0\u5f55", error=True)
            else:
                print_result("cmd5", None, extra="\u672a\u627e\u5230", error=True)
    except (KeyError, IndexError) as e:
        print(f"[-] cmd5: Error: {e}")


def nitrxgen(passwd):
    """nitrxgen.net - MD5-32 only (simple URL-based lookup)"""
    url = f"https://www.nitrxgen.net/md5db/{passwd}.txt"
    resp = query("nitrxgen", "get", url, session=False)
    if resp is None:
        return

    text = resp.text.strip()
    if text:
        print_result("nitrxgen", text)
    else:
        print_result("nitrxgen", None, error=True)


def chamd5(passwd, hash_type):
    """chamd5.org - MD5/SHA1/MySQL5/Discuz/..."""
    url = "https://www.chamd5.org/"
    resp = query("chamd5", "get", url)
    if resp is None:
        return

    try:
        headers = {
            **COMMON_HEADERS,
            "Content-Type": "application/json",
            "Referer": url,
            "X-Requested-With": "XMLHttpRequest",
        }
        login_data = json.dumps(
            {
                "email": "jxtepz93152@chacuo.net",
                "pass": "!Z3jFqDKy8r6v4",
                "type": "login",
            }
        )
        query("chamd5", "post", f"{url}HttpProxyAccess.aspx/ajax_login",
              data=login_data, headers=headers)

        search_data = json.dumps({"hash": passwd, "type": hash_type})
        resp = query("chamd5", "post", f"{url}HttpProxyAccess.aspx/ajax_me1ody",
                     data=search_data, headers=headers)
        if resp is None:
            return

        msg = re.sub(r"<.+?>", "", json.loads(resp.json()["d"])["msg"])

        if "\u7834\u89e3\u6210\u529f" in msg:
            match = re.findall(r"\u660e\u6587:(.+?)\u6570\u636e\u6765\u6e90", msg)
            if match:
                print_result("chamd5", match[0].strip())
        elif "\u91d1\u5e01\u4e0d\u8db3" in msg:
            print_result("chamd5", None, extra=msg, error=True)
        else:
            print_result("chamd5", None, error=True)
    except (IndexError, ValueError, KeyError) as e:
        print(f"[-] chamd5: Error: {e}")


def gromweb(passwd):
    """md5.gromweb.com - MD5-32 only"""
    url = "https://md5.gromweb.com/"
    resp = query("gromweb", "get", url, session=False, params={"md5": passwd})
    if resp is None:
        return

    text = resp.text
    if "successfully reversed" in text:
        match = re.findall(r'href="/\?string=(.+?)"', text)
        if match:
            plain = unquote(match[0])
            print_result("gromweb", plain)
            return
    print_result("gromweb", None, error=True)


def bugbank(passwd):
    """bugbank.cn - MD5-16, MD5-32"""
    url = "https://www.bugbank.cn/api/md5"
    headers = {
        **COMMON_HEADERS,
        "X-Requested-With": "XMLHttpRequest",
        "Referer": url,
    }
    data = {"md5text": passwd, "hashtype": 0}
    resp = query("bugbank", "post", url, headers=headers, data=data)
    if resp is None:
        return

    try:
        result = resp.json()
        if "answer" in result:
            if result["answer"] != "error!":
                print_result("bugbank", result["answer"],
                             extra=f"type: {result.get('type', '?')}")
            else:
                print_result("bugbank", None, extra="error!", error=True)
        else:
            print_result("bugbank", None,
                         extra=result.get("err_msg", "Unknown"), error=True)
    except (KeyError, ValueError) as e:
        print(f"[-] bugbank: Error: {e}")


def ttmd5(passwd):
    """ttmd5.com - MD5-16, MD5-32"""
    url = "http://www.ttmd5.com/do.php"
    resp = query("ttmd5", "get", url, params={"c": "User", "m": "getInfo"})
    if resp is None:
        return

    try:
        # Login first
        login_params = {"c": "User", "m": "doLogin"}
        login_data = {
            "hidUser": "uplnwkdc@mail.bccto.me",
            "hidPassword": "c927dc915426c2c89de3330c397fadf9",
        }
        query("ttmd5", "post", url, params=login_params, data=login_data)

        # Query
        resp = query(
            "ttmd5", "get", url,
            params={"c": "Decode", "m": "getMD5", "md5": passwd},
        )
        if resp is None:
            return

        rsp = resp.json()
        if "plain" in rsp:
            print_result("ttmd5", rsp["plain"])
        else:
            print_result("ttmd5", None, error=True)
    except (IndexError, ValueError) as e:
        print(f"[-] ttmd5: Error: {e}")


# ========================= Orchestration =========================


def crack(passwd):
    """Dispatch hash to appropriate lookup sites based on format.

    Detection logic:
      - 41 chars starting with *: MySQL5
      - 40 hex chars:           SHA1 or MySQL5
      - 32 hex chars:           MD5-32
      - 16 hex chars:           MD5-16
      - Contains ':':            Salted hash
    """
    threads = []

    # Common sites for all hash types
    threads.append(threading.Thread(target=cmd5, args=(passwd,)))

    if len(passwd) == 41 and re.match(r"\*[0-9a-fA-F]{40}", passwd):
        # MySQL5 format: *<40-char SHA1(SHA1(password))>
        threads.append(threading.Thread(target=chamd5, args=(passwd[1:], "300")))

    elif len(passwd) == 40 and re.match(r"[0-9a-fA-F]{40}", passwd):
        # Could be SHA1 or MySQL5
        threads.append(threading.Thread(target=chamd5, args=(passwd, "100")))  # SHA1
        threads.append(threading.Thread(target=chamd5, args=(passwd, "300")))  # MySQL5

    elif len(passwd) == 32 and re.match(r"[0-9a-fA-F]{32}", passwd):
        # MD5-32
        threads.append(threading.Thread(target=nitrxgen, args=(passwd,)))
        threads.append(threading.Thread(target=chamd5, args=(passwd, "md5")))
        threads.append(threading.Thread(target=gromweb, args=(passwd,)))
        threads.append(threading.Thread(target=bugbank, args=(passwd,)))
        threads.append(threading.Thread(target=ttmd5, args=(passwd,)))

    elif len(passwd) == 16 and re.match(r"[0-9a-fA-F]{16}", passwd):
        # MD5-16
        threads.append(threading.Thread(target=chamd5, args=(passwd, "md5")))
        threads.append(threading.Thread(target=chamd5, args=(passwd, "200")))
        threads.append(threading.Thread(target=bugbank, args=(passwd,)))
        threads.append(threading.Thread(target=ttmd5, args=(passwd,)))

    elif ":" in passwd:
        # Salted hash
        threads.append(threading.Thread(target=chamd5, args=(passwd, "10")))

    for t in threads:
        t.start()
    for t in threads:
        t.join()


def main():
    print(f"hashcrack v{__version__} - Hash online lookup tool")
    print(f"Sources: cmd5, nitrxgen, chamd5, gromweb, bugbank, ttmd5")
    print("-" * 50)

    log_dir = os.path.dirname(os.path.realpath(__file__))
    log_path = os.path.join(log_dir, "hash.log")

    while True:
        try:
            passwd = input("Hash: ").strip()
            if not passwd:
                continue
            with open(log_path, "a+") as f:
                f.write(passwd + os.linesep)
            crack(passwd)
        except (KeyboardInterrupt, ValueError, EOFError):
            print("\nBye!")
            break


if __name__ == "__main__":
    main()
