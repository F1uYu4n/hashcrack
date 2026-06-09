# hashcrack

Search hashes (MD5, SHA-1, MySQL5...) in different websites. (cmd5, gromweb, bugbank, ttmd5, nitrxgen...)

## Requirements
* Python 3.6+
* requests

```bash
pip install requests
```

## Sources

| Website | Supported Hash Types |
|---------|---------------------|
| https://cmd5.com/ | MD5-16/32, SHA1, SHA256, MySQL, Discuz, ... |
| https://www.nitrxgen.net/ | MD5-32 |
| https://md5.gromweb.com/ | MD5-32 |
| https://www.bugbank.cn/ | MD5-16/32 |
| http://www.ttmd5.com/ | MD5-16/32 |

## Usage

```bash
python hashcrack.py
```

Then enter the hash value when prompted.

## Changelog

### v2.0.0 (2026-06-09)
- Migrated to Python 3
- Updated User-Agent to modern Chrome
- Fixed cmd5.com: use session-based GET+POST to bypass error redirect
- Removed dead websites: pmd5.com, xmd5.com, md5.navisec.it, hashtoolkit.com, md5.my-addr.com, md5.tellyou.top, mysql-password.com
- Removed chamd5.org (too slow / unreliable)
- Refactored to ThreadPoolExecutor with streaming output and timeout control
- Improved error handling and code structure

### v1.0.0
- Initial release with Python 2.7 support

## Feedback
If you know other hash crack websites which have no CAPTCHA or find some bugs, please open an issue.
