# bounty_lite
Bugbounty low hanging fruit testing tool

usage:
```
python.exe .\bounty_lite.py <url>

python bounty_lite.py https://target.com --wordlist /path/to/wordlist.txt

python bounty_lite.py  https://target.com --help
```
|Options |Description|
|---|---|
|--include-subs ||Default|
|--no-include-subs | Don't gather subdomains from crt.sh |
|--wordlist     |         Path to wordlist for JWT secret brute-force [default: None] |
|--install-completion |   Install completion for the current shell.    |  
|--show-completion    |   Show completion for the current shell, to copy it |
|--help  |              Show this message and exit.|