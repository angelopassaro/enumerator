#!/bin/bash
echo "Start finding subdomains ..."
cat $1 | assetfinder --subs-only > $(pwd)/subdomains-1.txt &
findomain -q -f $1 > $(pwd)/subdomains-2.txt &
subfinder -dL $1 -silent -cs -all| awk -F "," '{print $1}' > $(pwd)/subdomains-3.txt &

wait

cat $(pwd)/subdomains-1.txt $(pwd)/subdomains-2.txt  $(pwd)/subdomains-3.txt > $(pwd)/tmp.txt

uniq -u $(pwd)/tmp.txt > $(pwd)/subdomains.txt
rm $(pwd)/tmp.txt $(pwd)/subdomains-*

#Out of scope
if [ -n "$2" ]; then
    echo "Exist"
    mv $(pwd)/subdomains.txt $(pwd)/no-scope-subdomains.txt
    grep -v -i -f "$2" $(pwd)/no-scope-subdomains.txt > $(pwd)/subdomains.txt
fi


echo "Found `wc -l subdomains.txt` unique subdomains"
cat $(pwd)/subdomains.txt | httprobe -c 80 --prefer-https > $(pwd)/urls.txt  
echo "Found `wc -l urls.txt` active domains"

echo "Running aquatone ..."
cat $(pwd)/urls.txt | aquatone -silent &
cat $(pwd)/urls.txt  | fff -d 1 -S -o sites  &

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


wait
echo "Done"
exit
