#!/bin/bash

read -p "[?] E-mail file to parse: " mailFile
clear -x
echo "[*] Gathering E-mail Artifacts"
echo "[*] ##########################"
echo
echo "[*] Sending Address"
echo "[*] --------------------------"
echo
grep ^From $mailFile
echo
echo "[*] Subject Line"
echo "[*] --------------------------"
echo
grep ^Subject $mailFile
echo
echo "[*] Recipients"
echo "[*] --------------------------"
echo
grep ^To $mailFile
echo
echo "[*] Date and Time"
echo "[*] --------------------------"
echo
grep ^Date $mailFile | awk '{sub($1 FS,"")}7'
echo
echo "[*] Sending Server IP"
echo "[*] --------------------------"
echo
srv_IP=$(grep "^Received: from" $mailFile | awk '{print $3,$4}')
#srv_IP_only=$(grep "^Received: from" $mailFile | awk '{print $3,$4}' | cut -d " " -f 2 | sed -re 's,\(\[,,g' | sed -re 's,\]\),,g')
srv_IP_only=$(grep "^Received: from" $mailFile | awk '{print $3,$4}' | cut -d " " -f 2 | sed -re 's,\(\[,,g ; s,\]\),,g')
echo $srv_IP
echo $srv_IP_only
echo
echo "[*] Reverse DNS Lookup"
echo "[*] --------------------------"
echo
dig -x $srv_IP_only | sed '14!d' | awk '{print $5}'
echo
echo "[*] Web links"
echo "[*] --------------------------"
echo
grep -Eo '(http|https)://[^/"].*' $mailFile | sed '/http/G'
vt_urls=$(grep -Eo '(http|https)://[^/"].*' $mailFile)
echo
echo "[*] Attachments"
echo "[*] --------------------------"
echo
VT_API_KEY=$(cat ~/.vt_api)
var1=0
while [ "$var1" = "0" ]
do
read -p "[?] Are there any attachments? (y/n)  " ans
case $ans in
	y|Y|Yes|yes|YES)	var2=0
				while [ "$var2" = "0" ]
				do
					read -p "[?] Enter file: " attachment
					hashval=$(md5sum $attachment)
					echo
					echo $hashval
					echo
					read -P "[?] Upload to VirusTotal? (y/n) " VT
					case $VT in
						y|Y|yes|Yes|YES)	vt_file_upload=$(curl -s --request POST --url 'https://www.virustotal.com/vtapi/v2/file/scan' --form 'apikey=$VT_API_KEY' --form 'file=@$attachment') ;;
						*)			echo "OK" ;;
					esac 
					read -p "[?] Any other attachements? (y/n) " ans2
					case $ans2 in
						n|N|No|no|NO)	echo "[*] Alrighty then. Goodbye :)"
								((var2++)) 
								((var1++))
								;;
						*)		echo "OK" ;;
					esac
				done
				;;
	n|N|no|No|NO)		((var1++)) ;;
	*)			echo "[!] Invalid. Try again" ;;
esac
done
echo
echo "[*] URL Analysis"
echo "[*] --------------------------"
echo
echo "[*] Checking VirusTotal for malicious activity"
for url in $vt_urls
do
	curl -s --request POST --url 'https://www.virustotal.com/vtapi/v2/url/scan' --data apikey=$VT_API_KEY --data url=$url > /tmp/virus_total
	vt_url_id=$( cat /tmp/virus_total | cut -d " " -f 13 | sed 's/"//g ; s/,//')
	vt_url_reports="$vt_url_reports $vt_url_id"
	echo "[*] Uploading url: [[ $url ]] Please wait."
	echo
	sleep 5
done
echo "[*] URL upload(s) complete!"
echo "[*]"
echo "[*] Checking reports"
echo 
for report in $vt_url_reports
do
	curl -s --request GET --url "https://www.virustotal.com/vtapi/v2/url/report?apikey=$VT_API_KEY&resource=$report" > /tmp/virus_total_$report

	vt_report_site=$(cat /tmp/virus_total_$report | sed 's/,//g' | sed 's/,/\n/g' | grep "\"url\"" | awk '{print $2}')
	echo "[*] Report for $vt_report_site"
	echo "[*] "
	cat /tmp/virus_total_$report | sed 's/scans": /scans":\n/ ; s/"}, /"},\n/g ; s/"}}, /"}},\n/g' | grep true | cut -d ":" -f 1,4 | sed 's/"//g ; s/},//g'
done









