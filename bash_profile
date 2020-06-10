# Automated reconnaissance wrapper - collecting juicy data & basic security testing (fuzzing)

## Delete junk subdomain - parameter/uri
   ## sed '/.blog.amikom.ac.id/d' subdomain.out > temp && mv temp subdomain.out;
   ## sed '/.blog.amikom.ac.id/d' ./URLs/allurls-temp.txt > temp && mv temp ./URLs/allurls-temp.txt;
   ## sed '/.blog.amikom.ac.id/d' ./URLs/allurls-juicy-httprobes.txt > temp && mv temp ./URLs/allurls-juicy-httprobes.txt;
   ## sed '/.blog.amikom.ac.id/d' ./URLs/params-uniq-live.txt > temp && mv temp ./URLs/params-uniq-live.txt;


# ----------- (1) Reconaissance & Data Collecting ------------ #
automate-recon (){ #> automate-recon target.com

	# Enumerating subdomains + subdomain IP resolv +  collecting open port ip lists from shodan + collecting URLs
	  # Other source : https://chaos.projectdiscovery.io/#/ | fdnsdataset
	  sudomyy -eP -dP -rS -d $1 --no-probe -o $1_sub; 


	# Workdir
	cd $1_sub/Sudomy-Output/$1;
	rm ip_dbasn.txt Subdomain_Resolver.txt Passive_Collecting_URLParamter_Full.txt Passive_Collecting_URLParamter_Uniq.txt;
	mv ip_dbport.txt ports-shodan.out; mv ip_resolver.txt ipresolv.out;  mv pars_subdomain_resolver.txt subdomain-resolv.out; mv subdomain.txt subdomain.out;
	mkdir URLs; mv Passive_Collecting_JuicyURL.txt ./URLs/allurls-temp.txt;


	# Subdomain HTTP Probing & Status Code Checking
	cat subdomain.out | httprobe -c 50 -prefer-https > httprobes.out;
	cat httprobes.out | httpx -status-code -title -threads 100 -timeout 6 -silent > httpx.out;


	# Parsing & processing URL list -- source:: WebArchive,CommonCrawl,UrlScanIO
	  # Removing Click identifier from ./URLs/allurls-temp.txt
	  egrep -iv "\?utm_(source|campaign|content|medium)=|\?fbclid=|\?gclid=|\?dclid=|\?mscklid=|\?zanpid=|\?gclsrc=|\?af_(ios|android)_url=|\?af_force_deeplink=|\?af_web_dp=|\?is_retargeting=|\?af_(dp|esp)=|\&utm_(campaign|source|medium)=" \
	  ./URLs/allurls-temp.txt | sort -u > ./URLs/allurls.txt; rm ./URLs/allurls-temp.txt;

	  # Removing duplicate parameter value & Delete uri containing extension ---> ./URLs/allurls-juicy.txt
	  cat ./URLs/allurls.txt | grep -P "=" | \
	  sed "/\b\(jpg\|JPG\|jpeg\|png\|doc\|PNG\|SVG\|svg\|pdf\|PDF\|ttf\|eot\|cssx\|css\|gif\|GIF\|ico\|woff\|woff2\)\b/d" | \
	  tee output.txt; 
	  for i in $(cat output.txt); do URL="${i}"; LIST=(${URL//[=&]/=FUZZ&}); echo ${LIST} | awk -F '=' -vOFS='=' '{$NF="FUZZ"}1;' \
	  >> OutputParam.txt; done ; sort -u OutputParam.txt > ./URLs/allurls-juicy.txt ; rm OutputParam.txt output.txt;
	  
	  	# Probing allurls-juicy.txt ---> ./URLs/allurls-juicy-httprobes.txt
	  	cp ./URLs/allurls-juicy.txt ./URLs/allurls-juicy-temp.txt;
	  	sed -i -e 's/https\?:\/\///g' ./URLs/allurls-juicy-temp.txt; cat ./URLs/allurls-juicy-temp.txt | httprobe -c 50 -prefer-https | \
	  	tee ./URLs/allurls-juicy-httprobes.txt; rm ./URLs/allurls-juicy-temp.txt allurls-juicy.txt;

	  # Parameter list ---> ./URLs/params-uniq.txt
	  cat ./URLs/allurls-juicy-httprobes.txt | grep -P "=" | grep -v '\?ver=' | tee output.txt; 
	  for i in $(cat output.txt); do URL="${i}"; LIST=(${URL//[=&]/=FUZZ&}); echo ${LIST} | awk -F '=' -vOFS='=' '{$NF="FUZZ"}1;' \
	  >> OutputParam.txt; done ; sort -u OutputParam.txt > ./URLs/params-uniq.txt; rm output.txt OutputParam.txt; 

	  	# + params-uniq.txt check status code 
	  	cat ./URLs/params-uniq.txt | httpx -threads 100 -status-code -silent | tee ./URLs/params-uniq-httpx-temp.txt; 
	  	cat ./URLs/params-uniq-httpx-temp.txt | awk '{print $1}' | tee ./URLs/params-uniq-live.txt; 
	  	rm ./URLs/params-uniq.txt ./URLs/params-uniq-httpx-temp.txt;

	  	# + Query Strings Parameter keys
	  	cat ./URLs/allurls.txt | unfurl keypairs | sort -u | tee ./URLs/onlyquerystrings.txt;

	  # Passing parameters
	  cat ./URLs/allurls.txt | grep "=" | egrep "\.txt|\.jpg|\.JPG|\.png|\.PNG|\.pdf|\.doc" > OutputParam.txt;
	  for i in $(cat OutputParam.txt); do URL="${i}"; LIST=(${URL//[=&]/=FUZZ&}); echo ${LIST} | awk -F '=' -vOFS='=' '{$NF="FUZZ"}1;' \
	  >> OutputParam2.txt; done; sort -u OutputParam2.txt > ./URLs/passingparams.txt; rm OutputParam.txt OutputParam2.txt;

	  
	# Colecting Juicy file : JS, JSON, etc > Downloading
	mkdir juicyfiles; mkdir ./juicyfiles/downloaded-juicyfiles;

	  # Fetch .js,json,etc file from ./URLs/allurls-juicy.txt  
	  cat ./URLs/allurls.txt | egrep "\.js|\.json|\.txt|\.yml|\.toml|\.xml" | httpx -threads 100 -status-code -silent | \
	  grep "200" | cut -d [ -f1 | tee ./juicyfiles/200-allurlsjuicy.out; 

	  # Crawling JS files from given urls/subdomains
	  cat ./URLs/allurls-juicy-httprobes.txt | sort -u | getJS -complete -resolve | grep -vwE "(sidebar)" | \
	  tee ./juicyfiles/200-getjscrawling.out

	  # Downloading juicy files
	  sort -u ./juicyfiles/200-allurlsjuicy.out ./juicyfiles/200-getjscrawling.out > ./juicyfiles/alljuicyfiles.out;
	  cat ./juicyfiles/200.out | parallel -j 20 wget -P ./juicyfiles/downloaded-juicyfiles --no-check-certificate;


	# JS Files processing
	  # Minify, re-indent bookmarklet unpack, deobuscate JS files
	  js-beautify ./juicyfiles/downloaded-juicyfiles/*.js;

	  # Discovery endpoint and parameter from JS files
	  linkfinder -i './juicyfiles/downloaded-juicyfiles/*.js' -o linkfinder.html;


	# Check Cloudflare > Filter > Active Port Scanning
	cat ipresolv.out | cf-check | tee cf-ipresolv.out;


	# Active Port scanning 
	naabu -t 25 -hL cf-ipresolv.out -ports 2000-9000 -retries 2 -verify | tee ports-naabu.out;


	# WebAnalyzer
	webanalyze -apps /root/resource/apps.json -worker 10 -hosts httprobes.out -output csv | tee webanalyzes.out;


	# Taking screenshots
	mkdir screens; 
	gowitness file --source httprobes.out -d ./screens;
	gowitness report generate; mv report-0.html gowitness.html;


	# Fetch paths 'HTTP response headers' & 'RAW body' > Juicy data > gf
	  mkdir fetch-meg;
	  cp httprobes.out hosts;
	  echo '/
/.env
/package.json
/.travis.yml
/.git/config'> ./paths
	  meg --header "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:77.0) Gecko/20100101 Firefox/77.0" -d 3000 -c 50 \
	  paths hosts ./fetch-meg/fetch-custompaths;
	  rm paths hosts;

	  # Filter 200 OK / 403 Forbidden results
	  cat ./fetch-meg/fetch-custompaths/index | grep "403 Forbidden\|200 OK" --color=yes | awk '{print $3$4" "$2}' | \
	  tee ./fetch-meg/200-403-fetch-custompaths.out;

	# Fetch / allurls-juicy-httprobes.txt > http response body > gf
	# meg --header "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:77.0) Gecko/20100101 Firefox/77.0" \
	# -d 3000 -c 50 / ./URLs/allurls-juicy-httpx.txt; 
	# mv ./out fetch-allurls-juicy-httpx; mv ./fetch-allurls-juicy-httpx ./fetch-meg/;


	# Interesting common ::gf pattern:: parameter > Deeping Vulnerable testing
	mkdir ./URLs/gf-juicydata; mkdir ./URLs/gf-juicydata/temp;
	cp ./URLs/params-uniq-live.txt ./URLs/gf-juicydata/temp; cd ./URLs/gf-juicydata/temp;

	# Collecting juicy data from ./URLs/params-uniq-live.txt -- More gf profiles/patterns to maximize utility
	  # --- File inclusion --- 
	  unbuffer gf lfi | sed 's/http/\nhttp/g' | grep ^http | sed 's/\(^http[^ <]*\)\(.*\)/\1/g' | sort -u > ../fuzz-fileinclusion; 

	  # --- Open Redirect ---
	  unbuffer gf redirect | sed 's/http/\nhttp/g' | grep ^http | sed 's/\(^http[^ <]*\)\(.*\)/\1/g' | sort -u > ../fuzz-openredirect;

	  # --- SQL Injection ---
	  unbuffer gf sqli | sed 's/http/\nhttp/g' | grep ^http | sed 's/\(^http[^ <]*\)\(.*\)/\1/g' | sort -u > ../fuzz-sqli;

	  # --- SSRF ---
	  unbuffer gf ssrf | sed 's/http/\nhttp/g' | grep ^http | sed 's/\(^http[^ <]*\)\(.*\)/\1/g' | sort -u > ../fuzz-ssrf;

	  # --- IDOR ---
	  unbuffer gf idor | sed 's/http/\nhttp/g' | grep ^http | sed 's/\(^http[^ <]*\)\(.*\)/\1/g' | sort -u > ../fuzz-idor;

	  # --- SSTI ---
	  unbuffer gf ssti | sed 's/http/\nhttp/g' | grep ^http | sed 's/\(^http[^ <]*\)\(.*\)/\1/g' | sort -u > ../fuzz-ssti;

	cd ../../../; rm -rf ./URLs/gf-juicydata/temp; mv ./URLs/gf-juicydata/ .;
	find ./gf-juicydata -size  0 -print -delete;
}



# ------------------ (2) Security Testing -------------------- #
#> *nuclei -- configurable targeted scanning based on templates 
	#> template: https://github.com/projectdiscovery/nuclei-templates
#> *qsfuzz -- build your own rules to fuzz query strings and easily identify vulnerabilities

automate-testing (){
 
	# Workdir : $1_sub/Sudomy-Output/$1;
	mkdir automationtesting; 


	# Software Composition Analysis (SCA) -- dependencies vulnerability checking (based on CVE/advisories)
	  # -- From downloaded js files ::retire,snyk
	  retire --js --jspath ./juicyfiles/downloaded-juicyfiles/ --exitwith 13 --outputformat text --outputpath ./automationtesting/sca-retirejs;
	  rm -rf node_modules package-lock.json;


	# Sensitive Data Exposure : Scanning juice files
	  # -- gf pattern 
	    # - https://github.com/dxa4481/truffleHogRegexes/blob/master/truffleHogRegexes/regexes.json
	    # - https://github.com/eth0izzle/shhgit/blob/master/config.yaml


	# Subdomain Takeover: Subdomain > CNAME resolv > NXDOMAIN | Pattern matching
	dnsprobe -l subdomain.out -r CNAME -o $1_dnsprobe_cnames -silent; #Filter only CNAME record (subdomains)
	cat $1_dnsprobe_cnames | awk '{print $1}' >> $1_cnames;
	
	time parallel -j 50 --tag host {1} {2} :::: $1_cnames ::: 8.8.8.8 1.1.1.1 8.8.4.4 | tee ./automationtesting/takeover-dnslookup;
	cat takeover-dnslookup | grep "NXDOMAIN" | awk '{print $4$7}' | tee ./automationtesting/takeover-NXDOMAIN; 

	subjack -w $1_cnames -timeout 30 -ssl -o subjack-results -c /root/resource/subjack-fingerprints.json -v 3; 
	cat subjack-results | awk '$0 !~ /Not Vulnerable/' | tee ./automationtesting/takeover-subjack;


	# CRLF Injection > XSS, Cache-Poisoning
	nuclei -t /root/resource/nuclei-templates/vulnerabilities/crlf-injection.yaml -l httprobes.out -c 40 -silent -o ./automationtesting/crlf-vuln;


	# Host Header Injection (x-forwarded-host) > Open Redirect
	nuclei -t /root/resource/nuclei-templates/vulnerabilities/x-forwarded-host-injection.yaml -l httprobes.out -c 40 -silent -o \
	./automationtesting/hostheaderinjection-vuln;


	# CORS Misconfig
	nuclei -t /root/resource/nuclei-templates/security-misconfiguration/basic-cors.yaml -l httprobes.out -c 40 -silent -o ./automationtesting/cors-vuln;


	# Unrestricted PUT method 
	echo "aa" > put.txt;
	cp httprobes.out hosts;
	meg --header "User-Agent: Chrome/70.0.3538.77 Safari/537.36" -d 3000 -c 50 -X PUT /put.txt;
	cat ./out/index | grep "200 OK" | tee ./automationtesting/unrestricted-putMethod;
	rm -rf ./out put.txt hosts;

	# Open Redirect > SSRF
	nuclei -t /root/resource/nuclei-templates/security-misconfiguration/open-redirect.yaml -l httprobes.out -c 40 -silent -o ./automationtesting/cors-vuln

	# Directory Traversal | File inclusion

	# XSS Fuzzing 
	  # [Reflected + Blind]
	  BLIND="https://missme3f.xss.ht"
	  cat ./URLs/params-uniq-live.txt | kxss | tee ./automationtesting/xss-kxss | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | \
	  dalfox -w 50 pipe -b $BLIND -o ./automationtesting/xss-reflected; # dalfox --custom-payload <payloads.txt>

	  # DOM Based


	# SSTI
	  # Engine Identification

	
	# SQLI Fuzzing

	# Command Injection

	# Juicy Path & Endpoint Bruteforce
	cat httprobes.out | parallel -j 10 --bar --shuf gobuster dir -u {} -t 20 \
	-w /root/resource/wordlist/dir/dirsearch.txt -l -e -r -k -q | tee ./automationtesting/gobuster;


	# Other > Custom pattern
		# nuclei -t /root/nuclei-templates/template/ -l httprobes.out -c 40 -silent -o <results>
		# >> New CVE, etc

}
