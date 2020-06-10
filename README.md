***bash_profile*** :: Automated reconnaissance wrapper - collecting juicy data & basic security testing (fuzzing)
```bash
# Dependencies
sudomy, httprobe, httpx, gowitness, naabu, dnsprobe, js-beautify, meg, gf, getJS, linkfinder, cf-check, 
unfurl, dalfox, gobuster, nuclei, subjack, retire.js
```
## Output List
### Reconnaissance & Collecting Juicy Data 
```bash
- subdomain.out         -- subdomain list
- subdomain-resolv.out  -- subdomain resolv result
- ipresolv.out          -- ip resolv list from subdomain-resolv.out
- cf-ipresolv.out       -- ipresolv.out Cloudflare scan
- httprobes.out         -- subdomain.out http probes
- httpx.out             -- httprobes.out http status code
- ports-shodan.out      -- Passive port scanning ipresolv.out from shodan
- ports-naabu.out       -- Active port scanning from cf-ipresolv.out
- webanalyzes.out       -- Webanalyzer scan 
- linkfinder.html       -- Discovery endpoint and parameter from JS files
- gowitness.html        -- gowitness screenshoter report
- ./fetch-meg/fetch-custompaths        -- Fetch HTTP response headers & RAW body
- ./URLs/allurls.txt                   -- Fetch url from WebArchive, CommonCrawl, UrlScanIO
- ./URLs/allurls-juicy-httprobes.txt   -- Removing duplicate parameter, junk uri + probing
- ./URLs/params-uniq-live.txt          -- Live (200 OK) unique parameter uri list
- ./gf-juicydata/gf-fileinclusion      -- gf fileinclusion pattern from params-uniq-live.txt
- ./gf-juicydata/gf-redirect           -- gf redirect pattern from params-uniq-live.txt
- ./gf-juicydata/gf-idor               -- gf idor pattern from params-uniq-live.txt
- ./gf-juicydata/gf-sqli               -- gf sqli pattern from params-uniq-live.txt
- ./gf-juicydata/gf-ssrf               -- gf ssrf pattern from params-uniq-live.txt
- ./gf-juicydata/gf-ssti               -- gf ssti pattern from params-uniq-live.txt
- ./juicyfiles/200-allurlsjuicy.out    -- Juicy files (js,json,toml,etc) from allurls.txt
- ./juicyfiles/200-getjscrawling.out   -- Juicy files (js,json,toml,etc) from active crawling ./URLs/allurls-juicy-httprobes.txt
- ./juicyfiles/alljuicyfiles.out       -- Juicy files 200-allurlsjuicy.out + 200-getjscrawling.out
- ./juicyfiles/downloaded-juicyfiles/  -- Downloaded Juicy files
```

### Security Testing [Fuzzing]
```bash
1. Dependencies vulnerability checking (SCA) -- based on CVE/advisories
   --> ./automationtesting/sca-retirejs
2. Sensitive Data Exposure -- Scanning downloaded juicy files 
   --> [none]
3. Subdomain takeover
   --> ./automationtesting/takeover-subjack
4. CRLF Injection > XSS, Cache-Poisoning
   --> ./automationtesting/crlf-vuln
4. Host Header Injection (x-forwarded-host) > Open Redirect
   --> ./automationtesting/hostheaderinjection-vuln
5. CORS Misconfig Scan 
   --> ./automationtesting/cors-vuln
6. Unrestricted PUT method 
   --> ./automationtesting/unrestricted-putMethod
7. Open Redirect (nuclei) > XSS, SSRF
   --> ./automationtesting/cors-vuln
8. Directory Traversal - File inclusion
   --> [none]
9. XSS (Blind, Reflected, DOM)
   --> ./automationtesting/xss-reflected
   --> ./automationtesting/xss-dom[none]
10.SSTI data from webanalyze 
   --> [none]
11.SQLI Fuzzing
   --> [none]
12.Command Injection
   --> [none]
13.Juicy Path & Endpoint Bruteforce
   --> ./automationtesting/gobuster.txt
14.Other -- Custom nuclei Pattern : New CVE&advisores, etc
```
