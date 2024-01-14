#!/bin/bash

#TODO define an working dir


echo "Start finding subdomains ..."
cat $1 | assetfinder --subs-only > $(pwd)/subdomains-1.txt &
findomain -q -f $1 > $(pwd)/subdomains-2.txt &
subfinder -dL $1 -silent -cs -all| awk -F "," '{print $1}' > $(pwd)/subdomains-3.txt &

wait

cat $(pwd)/subdomains-1.txt $(pwd)/subdomains-2.txt  $(pwd)/subdomains-3.txt > $(pwd)/tmp.txt

uniq -u $(pwd)/tmp.txt > $(pwd)/subdomains.txt
rm $(pwd)/tmp.txt $(pwd)/subdomains-*

#Out of scope
if [ -n $2 ]; then
    mv $(pwd)/subdomains.txt $(pwd)/no-scope-subdomains.txt
    grep -v -i -f "$2" $(pwd)/no-scope-subdomains.txt > $(pwd)/subdomains.txt
fi


echo "Found `wc -l subdomains.txt` unique subdomains"
cat $(pwd)/subdomains.txt | httprobe -c 80 --prefer-https > $(pwd)/urls.txt  
echo "Found `wc -l urls.txt` active domains"

echo "Running aquatone ..."
cat $(pwd)/urls.txt | aquatone -ports large -silent &
#cat $(pwd)/urls.txt  | fff -d 1 -S -o sites  & #aqutone already dump the html

echo "Finding error pages ..."
for line in $(cat $1);do 
shodan search "hostname:$line http.title:error" --fields ip_str >> errors_page.txt &
done;

echo "Finding technologies pages ..."
nuclei -silent -nc -l $(pwd)/urls.txt -t technologies/tech-detect.yaml  > tmp.txt
output=$(cat tmp.txt | sed 's/\[//g; s/\]//g')

declare -A url_array

while IFS= read -r line; do
    first_column=$(echo "$line" | awk '{print $1}')
    url=$(echo "$line" | awk '{print $NF}')

    url_array["$first_column"]+=" $url"
done <<< "$output"

for key in "${!url_array[@]}"; do
    echo "$key${url_array[$key]}" | awk -F "tech-detect:" '{print $2}'  >> tech.txt
done

rm tmp.txt


wait # wait for aqutone

#check if there is some default page to scan. TODO add dir enumeration
cd $(pwd)/html/ 
gf nginx_error    | awk '{print $1}' | awk -F "/" '{print $2}' | sed 's/com__.*/com/' | sed 's/__/\:\/\//g' | sed 's/_/\./g'  >> $(pwd)/../urls_to_scan.txt
gf default_server | awk '{print $1}' | awk -F "/" '{print $2}' | sed 's/com__.*/com/' | sed 's/__/\:\/\//g' | sed 's/_/\./g'  >> $(pwd)/../urls_to_scan.txt
cd -


# Run ffuf on default pages
urls_to_scan="$(pwd)/urls_to_scan.txt"

if [ ! -s "$urls_to_scan" ]; then
    echo "No urls found"
    exit
fi

for line in $(cat "$urls_to_scan"); do
    if [ -z "$3" ]; then
        echo "No wordlist"
        exit
    elif [ -n "$4" ]; then
        ffuf -w "$3" -u "$line/FUZZ" -H "$4" -ac -ach -o "${line:8}.enum"
    else
        ffuf -w "$3" -u "$line/FUZZ" -ac -ach -o "${line:8}.enum"
    fi
done

echo "Done"
exit
