# WAF Bypass via DNS History
A modernized, refactored, and safer Bash script to detect origin IPs behind Web Application Firewalls (WAF) by analyzing historical DNS records.

> **Note:** This is a heavily refactored version of the classic `bypass-firewalls-by-DNS-history` script, [link here](https://github.com/Elsfa7-110/bypass-firewalls-by-DNS-history). If fixes broken APIs, improves concurrency, handles HTTP/HTTPS fallbacks gracefully, and manages temporary files securely.

# 🚀 How it Works
When a website moves behind a WAF (like Cloudflare, Incapsula, or AWS WAF), the DNS records change to point to the WAF's IP addresses. However, the original server (the "Origin") often keeps its public IP.

This tool:
- **Enumerates Subdomains:** Uses `crt.sh` (Certificate Transparency logs) to find all valid subdomains.
- **Fetches DNS History:** Queries services like ViewDNS and SecurityTrails to find IP addresses previously associated with the domain.
- **Filters Noise:** Removes known WAF ranges (using `grepcidr`) and local IPs.
- **Fingerprints & Compares:**
    - Downloads the current site (via WAF) to get a baseline size.
    - Connects to every historical IP directly (bypassing DNS) .
    - Compares the response size. If a historical IP returns content similar to the live site, it reveals the origin server.

# ✨ Features
- **Smart Fallback:** Automatically switches between HTTP/S if the server doesn't expose port 443.
- **Fast & Safe:** Uses `mktemp` for isolated execution (no `/tmp` collisions) and limits concurrency to avoid resource exhaustion.
- **Modern APIs:** Replaced modern scrappers with `crt.sh` and JSON parsing via `jq`. 
- **WAF Detection:** Built-in list of CIDR ranges for major WAF providers to avoid false positives.

# 🛠️ Prerequisites
This script relies on standard Linux tools. You will likely need to install `grepcidr` and `jq`.

### Debian/Ubuntu/Kali
```Bash
sudo apt update
sudo apt install -y curl jq dnsutils grepcidr
```

### MacOS (Homebrew)
```Bash
brew install jq grepcidr
```
# 💻 Usage
### Basic Scan
Run a scan against a domain and print results to stdout:
```Bash
./bypass-waf.sh -d example.com
```

### Save Results
Save the found origin IPs to a file:
```Bash
./bypass-waf.sh -d example.com -o results.txt
```

# ⚠️ Limitations
- **Cloud Load Balancers (AWS/Azure/GCP):** This technique is less effective against cloud-native DNS. Cloud providers recycle IPs frequently. An old IP in the history likely belongs to a different customer now, or is offline.
- **Hosting Shared IP:** If the target is on shared hosting, accessing the IP directly might return a default "Apache/Nginx" page instead of the specific website, causing the comparison to fail.

# ⚖️ Disclaimer
This tool is for **educational purposes and authorized security testing only.** Do not use this tool on networks or domains you do not own or do not have explicit permission to audit.

---
*Refactored for internal study.*
