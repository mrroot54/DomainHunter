#!/bin/bash

# Function to print messages in red
print_red() {
    echo -e "\033[31m$1\033[0m"
}

# Function to print messages in green
print_green() {
    echo -e "\033[32m$1\033[0m"
}

# Function to show usage information
help(){
    echo -e "[Usage]:"
    echo -e "\t$0 <domain>"
}

# Function to get subdomains using multiple sources
getSubdomains(){
    domain=$1

    # Temporary file to store combined results
    temp_file="temp_subdomains.txt"
    output_file="all-subdomains.txt"

    # Check if output file already exists
    if [ -f "$output_file" ]; then
        print_red "$output_file already exists. Remove or rename it before running the script."
        exit 1
    fi

    # Initialize temporary file
    > $temp_file

    # Run each command and append results to the temporary file
    echo "Running assetfinder..."
    if assetfinder -subs-only $domain >> $temp_file; then
        print_green "assetfinder completed successfully."
    else
        print_red "assetfinder failed."
    fi

    echo "Running subfinder..."
    if subfinder -d $domain -silent >> $temp_file; then
        print_green "subfinder completed successfully."
    else
        print_red "subfinder failed."
    fi

    echo "Running subscraper..."
    if subscraper -d $domain; then
        print_green "subscraper completed successfully. Results saved to ./sub_report.txt."
        cat ./sub_report.txt >> $temp_file
    else
        print_red "subscraper failed."
    fi

    echo "Running findomain..."
    if findomain -t $domain -q >> $temp_file; then
        print_green "findomain completed successfully."
    else
        print_red "findomain failed."
    fi

    # New commands for additional subdomain sources
    echo "Running additional subdomain sources..."
    curl -s "https://otx.alienvault.com/api/v1/indicators/domain/$domain/passive_dns" | jq -r ".passive_dns[].hostname" | sort -u >> $temp_file &
    curl -s "https://jldc.me/anubis/subdomains/$domain" | jq -r '.' | cut -d '"' -f2 | cut -d '[' -f1 | cut -d ']' -f1 | grep . | sort -u >> $temp_file &
    curl -s "http://web.archive.org/cdx/search/cdx?url=*.$domain/*&output=text&fl=original&collapse=urlkey" | sort | sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' | sort -u >> $temp_file &
    curl -s "https://certspotter.com/api/v0/certs?domain=$domain" | jq '.[].dns_names[]' 2> /dev/null | sed 's/\"//g' | sed 's/\*\.//g' | grep -w $domain\$ | sort -u >> $temp_file &
    curl -s "https://crt.sh/?q=%.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u >> $temp_file &
    curl -s "https://dns.bufferover.run/dns?q=.$domain" | jq -r .FDNS_A[] 2>/dev/null | cut -d ',' -f2 | grep -o "\w.*$domain" | sort -u >> $temp_file &
    curl -s "https://dns.bufferover.run/dns?q=.$domain" | jq -r .RDNS[] 2>/dev/null | cut -d ',' -f2 | grep -o "\w.*$domain" | sort -u >> $temp_file &
    curl -s "https://tls.bufferover.run/dns?q=.$domain" | jq -r .Results 2>/dev/null | cut -d ',' -f3 | grep -o "\w.*$domain"| sort -u >> $temp_file &
    curl -s "https://api.hackertarget.com/hostsearch/?q=$domain" | cut -d ',' -f1 | sort -u >> $temp_file &
    curl -s "https://rapiddns.io/subdomain/$domain?full=1#result" | grep -oaEi "https?://[^\"\\'> ]+" | grep $domain | sed 's/https\?:\/\///' | cut -d "/" -f3 | sort -u >> $temp_file &
    curl -s "https://riddler.io/search/exportcsv?q=pld:$domain" | grep -o "\w.*$domain" | cut -d ',' -f6 | sort -u >> $temp_file &
    curl -s "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$domain" | jq '.subdomains' | cut -d '"' -f2 | cut -d '[' -f1 | cut -d ']' -f1 | grep . | sort -u >> $temp_file &
    curl -s "https://api.threatminer.org/v2/domain.php?q=$domain&rt=5" | jq -r '.results[]' | sort -u >> $temp_file &
    curl -s "https://urlscan.io/api/v1/search/?q=domain:$domain" | jq -r '.results[].page.domain' | sort -u >> $temp_file &
    curl -s "https://www.virustotal.com/ui/domains/$domain/subdomains?limit=40" | grep '"id":' | cut -d '"' -f4 | sort -u >> $temp_file &
    csrftoken=$(curl -ILs https://dnsdumpster.com | grep csrftoken | cut -d " " -f2 | cut -d "=" -f2 | tr -d ";")
    curl -s --header "Host:dnsdumpster.com" --referer https://dnsdumpster.com --user-agent "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0" --data "csrfmiddlewaretoken=$csrftoken&targetip=$domain" --cookie "csrftoken=$csrftoken; _ga=GA1.2.1737013576.1458811829; _gat=1" https://dnsdumpster.com >> dnsdumpster.html
    if [[ -e dnsdumpster.html && -s dnsdumpster.html ]]; then # file exists and is not zero size
        cat dnsdumpster.html | grep "https://api.hackertarget.com/httpheaders" | grep -o "\w.*$domain" | cut -d "/" -f7 | grep '.' | sort -u >> $temp_file
    fi

    # Wait for background processes to complete
    wait

    # Merge results from temp_file, remove duplicates, and save to the final output file
    echo "Processing results..."
    cat $temp_file | grep -iv "*" | sort -u | grep $domain | tee $output_file

    # Cleanup temporary files
    rm -rf dnsdumpster.html
    rm -rf $temp_file
}

# Main execution
if [[ -z $1 ]]; then
    help
else
    getSubdomains $1
fi
