#!/usr/bin/env bash
#
# - WAF Bypass via DNS History -
# Refactor by _n0m4d_
#

set -u

# --- Colors ---
GREEN='\033[1;32m'
RED='\033[1;31m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- Global Variables ---
DOMAIN=""
OUTFILE=""
CHECK_ALL=0
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"

KNOWN_WAF_RANGES=(
    "173.245.48.0/20" "103.21.244.0/22" "103.22.200.0/22" "103.31.4.0/22"
    "141.101.64.0/18" "108.162.192.0/18" "190.93.240.0/20" "188.114.96.0/20"
    "197.234.240.0/22" "198.41.128.0/17" "162.158.0.0/15" "104.16.0.0/12"
    "172.64.0.0/13" "131.0.72.0/22" "199.83.128.0/21" "198.143.32.0/19"
    "149.126.72.0/21" "103.28.248.0/22" "45.64.64.0/22" "185.11.124.0/22"
    "192.230.64.0/18" "107.154.0.0/16" "45.60.0.0/16" "45.223.0.0/16"
)

# --- Safe Tmp Dir ---
WORKDIR=$(mktemp -d)
trap "rm -rf $WORKDIR" EXIT

# --- Helpers ---

usage() {
    echo -e "${GREEN}Usage: ./bypass-waf.sh -d example.com [-o output.txt]${NC}"
    exit 1
}

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[ OK ]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

check_deps() {
    for cmd in curl jq dig sdiff grepcidr; do
        if ! command -v $cmd &> /dev/null; then
            echo -e "${RED}[ERROR] Dependency Missing: $cmd${NC}"
            echo "Install with: sudo apt install curl jq dnsutils diffutils grepcidr"
            exit 1
        fi
    done
}

# --- Networking ---

is_waf_ip() {
    local ip=$1
    for range in "${KNOWN_WAF_RANGES[@]}"; do
        if echo "$ip" | grepcidr "$range" &>/dev/null; then
            return 0 # WAF
        fi
    done
    return 1 # Not WAF
}

get_subdomains() {
    local domain=$1
    log_info "Searching for subdomains for $domain at crt.sh..."
    
    curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u > "$WORKDIR/subs.txt"
    
    echo "$domain" >> "$WORKDIR/subs.txt"
    
    sort -u "$WORKDIR/subs.txt" -o "$WORKDIR/domains_final.txt"
    local count=$(wc -l < "$WORKDIR/domains_final.txt")
    log_info "Found $count unique domains."
}

get_dns_history() {
    local domain=$1
    log_info "Querying DNS History for $domain..."
    
    # ViewDNS.info (Scrapping basics)
    curl -s -A "$USER_AGENT" "https://viewdns.info/iphistory/?domain=$domain" \
        | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' \
        | sort -u >> "$WORKDIR/ips_raw.txt"

    # SecurityTrails (limited public version)
    curl -s -A "$USER_AGENT" "https://securitytrails.com/domain/$domain/history/a" \
        | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' \
        | sort -u >> "$WORKDIR/ips_raw.txt"

    # Filtering invalid o local IPs
    grep -vE "^127\.|^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^192\.168\." "$WORKDIR/ips_raw.txt" | sort -u > "$WORKDIR/ips_clean.txt"
    
    local count=$(wc -l < "$WORKDIR/ips_clean.txt")
    log_info "Found $count Historical IPs."
}

check_bypass() {
    local domain=$1
    local ip_list="$WORKDIR/ips_clean.txt"
    
    # Get current IP (to ignore)
    local current_ip=$(dig +short "$domain" | head -n 1)
    log_info "Current IP (Frontal/WAF): $current_ip"

    log_info "Downloading original page (Reference)..."
    
    curl -s -k -L --max-time 10 "https://$domain" -o "$WORKDIR/orig_body.html" || \
    curl -s -L --max-time 10 "http://$domain" -o "$WORKDIR/orig_body.html"
    
    if [ ! -s "$WORKDIR/orig_body.html" ]; then
        echo -e "${RED}[ERROR] CRÍTICO: No se pudo conectar a $domain por HTTP ni HTTPS.${NC}"
        echo "Verifica que el Security Group permita tráfico y que la dirección sea correcta."
        return
    fi

    local orig_size=$(wc -c < "$WORKDIR/orig_body.html")
    log_info "Reference Size captured: $orig_size bytes"

    log_info "Testing Historical IPs..."
    
    while read -r ip; do
        if [[ "$ip" == "$current_ip" ]]; then continue; fi
        
        if is_waf_ip "$ip"; then continue; fi

        curl -s -k -m 5 -o "$WORKDIR/test_$ip.html" --resolve "$domain:443:$ip" "https://$domain" || true
        if [ ! -s "$WORKDIR/test_$ip.html" ]; then
             curl -s -m 5 -o "$WORKDIR/test_$ip.html" --resolve "$domain:80:$ip" "http://$domain" || true
        fi
        
        if [ -s "$WORKDIR/test_$ip.html" ]; then
            local test_size=$(wc -c < "$WORKDIR/test_$ip.html")
            
            if [[ "$test_size" -gt 500 ]]; then
                log_success "POSSIBLE BYPASS FOUND: $ip"
                echo "IP: $ip - Response Size: $test_size bytes"
                
                if [ -n "$OUTFILE" ]; then
                    echo "$ip" >> "$OUTFILE"
                fi
                
                local org=$(curl -s "https://ipinfo.io/$ip/org")
                echo "    -> Org: $org"
            fi
        fi
        
        rm -f "$WORKDIR/test_$ip.html"

    done < "$ip_list"
}
# --- Main ---

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -d|--domain)
        DOMAIN="$2"
        shift; shift
        ;;
        -o|--outputfile)
        OUTFILE="$2"
        shift; shift
        ;;
        *)
        shift
        ;;
    esac
done

if [ -z "$DOMAIN" ]; then
    usage
fi

check_deps

echo -e "------------------------------------------------"
echo -e "    Searching Origin for: ${GREEN}$DOMAIN${NC}"
echo -e "------------------------------------------------"

get_subdomains "$DOMAIN"
get_dns_history "$DOMAIN"
check_bypass "$DOMAIN"

echo -e "------------------------------------------------"
echo -e "Done!"



