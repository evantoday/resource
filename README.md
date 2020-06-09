<<<<<<< HEAD
=======
<<<<<<< HEAD
# resource
Automated reconnaissance wrapper - collecting juicy data &amp; basic security testing (fuzzing)
=======
>>>>>>> .
***bash_profile*** :: Automated reconnaissance wrapper - collecting juicy data & basic security testing (fuzzing)
```bash
# Dependencies
sudomy, httprobe, httpx, gowitness, naabu, dnsprobe, js-beautify, meg, gf, getJS, linkfinder, cf-check, 
unfurl, dalfox, gobuster, nuclei, subjack, retire.js
```
## Output List
### Reconnaissance & Collecting Data Stage 
```bash
- subdomain.out         -- subdomain list
- subdomain-resolv.out  -- subdomain resolv result
- ipresolv.out          -- ip resolv list from subdomain-resolv.out
- httprobes.out         -- subdomain.out http probes
- httpx-status.out      -- httprobes.out http status code
- linkfinder.html       -- Discovery endpoint and parameter from JS files
- cf-ipresolv.out       -- ipresolv.out Cloudflare scan
- ports-naabu.out       -- Active port scanning from cf-ipresolv.out
- webanalyzes.out       -- Webanalyzer scan 
- gowitness.html        -- gowitness report
- ./URLs/allurls.txt                   -- Fetch url from WebArchive, CommonCrawl, UrlScanIO
- ./URLs/allurls-juicy.txt             -- Remove duplicate parameter value uri & Delete uri containing extension 
- ./URLs/allurls-juicy-httprobes.txt   -- allurls-juicy.txt probing
- ./URLs/params-uniq-live.txt          -- Live (200 OK) parameter uri list
- ./URLs/fuzz/fuzz-fileinclusion       -- Parameter uri > File inclusion fuzzing
- ./fetch-meg/fetch-custompaths        -- Fetch 'HTTP response headers' & 'RAW body'
- ./gf-juicydata/gf-redirect           -- gf redirect pattern from params-uniq-live.txt
- ./gf-juicydata/gf-idor               -- gf idor pattern from params-uniq-live.txt
- ./gf-juicydata/gf-sqli               -- gf sqli pattern from params-uniq-live.txt
- ./gf-juicydata/gf-ssrf               -- gf ssrf pattern from params-uniq-live.txt
- ./gf-juicydata/gf-ssti               -- gf ssti pattern from params-uniq-live.txt
- ./juicyfiles/juicyfiles-httpx.out    -- Juicy files uri from ./URLs/allurls-juicy.txt + probing
- ./juicyfiles/juicyfiles-200.out      -- Juicy files uri live (200 OK) from ./juicyfiles/juicyfiles-httpx.out 
- ./juicyfiles/downloaded-juicyfiles   -- Downloaded Juicy files
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
10. SSTI data from webanalyze 
   --> [none]
11. SQLI Fuzzing
   --> [none]
12. Juicy Path & Endpoint Bruteforce
   --> ./automationtesting/gobuster.txt
13.Other -- Custom nuclei Pattern : New CVE&advisores, etc
```
<<<<<<< HEAD
=======
>>>>>>> resources
>>>>>>> .
