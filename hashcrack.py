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

import os
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
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
MAX_WAIT = 90  # Max seconds to wait for all threads to complete
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
        except RequestException:
            if attempt == RETRY_CNT - 1:
                return None

    return None


def make_result(site, found=False, plain=None, extra=""):
    """Build a standardized result dict.

    Args:
        site:  Source site name
        found: Whether the hash was cracked
        plain: Decrypted plaintext (if found)
        extra: Additional info (error message, hash type, etc.)

    Returns:
        dict with keys: site, found, plain, extra
    """
    return {"site": site, "found": found, "plain": plain, "extra": extra}


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
        return make_result("cmd5", extra="RequestError")

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
            return make_result("cmd5", extra="RequestError")

        resp.encoding = "utf-8"
        result = re.findall(
            r'<span id="LabelAnswer"[^>]*>(.*?)</span>', resp.text, re.S
        )
        if result and result[0].strip():
            text = re.sub(r"\u3002.*", "", result[0].strip())
            return make_result("cmd5", found=True, plain=text)
        else:
            if "\u4ed8\u8d39\u8bb0\u5f55" in resp.text:
                return make_result("cmd5", extra="\u5df2\u67e5\u5230\uff0c\u4f46\u4e3a\u4ed8\u8d39\u8bb0\u5f55")
            else:
                return make_result("cmd5", extra="\u672a\u627e\u5230")
    except (KeyError, IndexError) as e:
        return make_result("cmd5", extra=f"Error: {e}")


def nitrxgen(passwd):
    """nitrxgen.net - MD5-32 only (simple URL-based lookup)"""
    url = f"https://www.nitrxgen.net/md5db/{passwd}.txt"
    resp = query("nitrxgen", "get", url, session=False)
    if resp is None:
        return make_result("nitrxgen", extra="RequestError")

    text = resp.text.strip()
    if text:
        return make_result("nitrxgen", found=True, plain=text)
    return make_result("nitrxgen")


def gromweb(passwd):
    """md5.gromweb.com - MD5-32 only"""
    url = "https://md5.gromweb.com/"
    resp = query("gromweb", "get", url, session=False, params={"md5": passwd})
    if resp is None:
        return make_result("gromweb", extra="RequestError")

    text = resp.text
    if "successfully reversed" in text:
        match = re.findall(r'href="/\?string=(.+?)"', text)
        if match:
            plain = unquote(match[0])
            return make_result("gromweb", found=True, plain=plain)
    return make_result("gromweb")


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
        return make_result("bugbank", extra="RequestError")

    try:
        result = resp.json()
        if "answer" in result:
            if result["answer"] != "error!":
                return make_result("bugbank", found=True, plain=result["answer"],
                                   extra=f"type: {result.get('type', '?')}")
            return make_result("bugbank", extra="error!")
        return make_result("bugbank", extra=result.get("err_msg", "Unknown"))
    except (KeyError, ValueError) as e:
        return make_result("bugbank", extra=f"Error: {e}")


def ttmd5(passwd):
    """ttmd5.com - MD5-16, MD5-32"""
    url = "http://www.ttmd5.com/do.php"
    resp = query("ttmd5", "get", url, params={"c": "User", "m": "getInfo"})
    if resp is None:
        return make_result("ttmd5", extra="RequestError")

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
            return make_result("ttmd5", extra="RequestError")

        rsp = resp.json()
        if "plain" in rsp:
            return make_result("ttmd5", found=True, plain=rsp["plain"])
        return make_result("ttmd5")
    except (IndexError, ValueError) as e:
        return make_result("ttmd5", extra=f"Error: {e}")


# ========================= Orchestration =========================


def crack(passwd):
    """Dispatch hash to appropriate lookup sites based on format.

    Uses ThreadPoolExecutor for concurrent execution.
    Results are printed immediately as each thread finishes.

    Detection logic:
      - 41 chars starting with *: MySQL5
      - 40 hex chars:           SHA1 or MySQL5
      - 32 hex chars:           MD5-32
      - 16 hex chars:           MD5-16
    """
    tasks = []  # list of (func, args)

    if len(passwd) == 41 and re.match(r"\*[0-9a-fA-F]{40}", passwd):
        # MySQL5 format — no dedicated source available currently
        pass

    elif len(passwd) == 40 and re.match(r"[0-9a-fA-F]{40}", passwd):
        # SHA1 — cmd5 handles this
        pass

    elif len(passwd) == 32 and re.match(r"[0-9a-fA-F]{32}", passwd):
        # MD5-32
        tasks.append((cmd5, (passwd,)))
        tasks.append((nitrxgen, (passwd,)))
        tasks.append((gromweb, (passwd,)))
        tasks.append((bugbank, (passwd,)))
        tasks.append((ttmd5, (passwd,)))

    elif len(passwd) == 16 and re.match(r"[0-9a-fA-F]{16}", passwd):
        # MD5-16
        tasks.append((cmd5, (passwd,)))
        tasks.append((bugbank, (passwd,)))
        tasks.append((ttmd5, (passwd,)))

    if not tasks:
        print("  [!] No suitable source for this hash format")
        return False

    # Print lock for thread-safe output
    print_lock = threading.Lock()
    results = {"found": 0, "total": 0}

    def run_and_print(fn, *args):
        """Run a lookup function and print the result immediately."""
        try:
            result = fn(*args)
        except Exception as e:
            result = make_result(fn.__name__, extra=f"Exception: {e}")

        with print_lock:
            results["total"] += 1
            if result and result["found"]:
                results["found"] += 1
                suffix = f" ({result['extra']})" if result["extra"] else ""
                print(f"  [+] {result['site']}: {result['plain']}{suffix}")
            elif result:
                msg = result["extra"] if result["extra"] else "NotFound"
                print(f"  [-] {result['site']}: {msg}")

    # Execute all tasks concurrently, print as each finishes
    with ThreadPoolExecutor(max_workers=len(tasks)) as pool:
        futures = [pool.submit(run_and_print, fn, *args) for fn, args in tasks]

        try:
            for future in as_completed(futures, timeout=MAX_WAIT):
                future.result()  # raise any exception
        except TimeoutError:
            pending = sum(1 for f in futures if not f.done())
            for f in futures:
                f.cancel()
            print(f"  [!] {pending} task(s) timed out (>{MAX_WAIT}s)")

    # Summary
    print(f"  --- {results['found']}/{results['total']} found ---")
    return results["found"] > 0


def main():
    print(f"hashcrack v{__version__} - Hash online lookup tool")
    print(f"Sources: cmd5, nitrxgen, gromweb, bugbank, ttmd5")
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
