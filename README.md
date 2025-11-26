# SubScout 

**Advanced Subdomain Reconnaissance Tool**

SubScout is a powerful, feature-rich subdomain enumeration tool that combines passive reconnaissance, active brute-forcing, DNS resolution, and intelligent anomaly detection to discover and validate subdomains.

## Features

### Passive Enumeration (11+ Sources)

**Free Sources** (No API key required):
- **crt.sh** - Certificate Transparency logs
- **AlienVault OTX** - Open Threat Exchange
- **AnubisDB** - Subdomain database
- **HackerTarget** - DNS reconnaissance
- **ThreatCrowd** - Threat intelligence
- **CertSpotter** - Certificate monitoring
- **URLScan.io** - URL scanning service
- **Chaos** - ProjectDiscovery's dataset
- **BufferOver** - DNS data
- **RapidDNS** - DNS records
- **DNSdumpster** - DNS reconnaissance

**Premium Sources** (API key required):
- **VirusTotal** - Comprehensive threat intelligence
- **SecurityTrails** - DNS history
- **Shodan** - Internet-wide scanning
- **FullHunt** - Attack surface discovery
- **BinaryEdge** - Internet scanning
- **Netlas** - Internet asset discovery

### Active Enumeration
- DNS brute-forcing with custom wordlists
- Wildcard detection and filtering
- Concurrent DNS resolution for speed
- Real-time progress tracking

### DNS Resolution
- Resolve subdomains to IP addresses
- A record lookups
- Configurable DNS servers and timeouts
- Batch resolution with progress tracking

### Smart Anomaly Detection
SubScout includes an intelligent anomaly detector that filters out false positives:

- **Wildcard DNS Detection** - Identifies patterns where 10+ subdomains return identical responses
- **Mass Redirect Detection** - Catches catch-all redirects (5+ subdomains to same target)
- **Legitimate Redirect Filtering** - Allows HTTP→HTTPS and www variant redirects
- **Suspicious Pattern Detection** - Flags 10+ identical error responses (403/404)
- **HTTP Status Code Visibility** - See HTTP responses during anomaly detection (verbose mode)

**Reduced False Negatives**: The enhanced detector is conservative and only flags truly suspicious patterns, not individual legitimate subdomains.

### Wildcard Certificate Handling
- Automatically extracts base domains from wildcard certificates
- Converts `*.example.com` → `example.com`
- Includes base domains in final results for verification

###  Output Formats
- **Plain Text (TXT)** - Simple list format
- **JSON** - Structured data with metadata
- **CSV** - Spreadsheet-compatible format
- All formats support DNS resolution data when `--resolve` is used

## Installation

```bash
# Clone or download the repository
cd SubScout

# Install dependencies
pip install -r requirements.txt
```

## Configuration

### Option 1: Configuration File

Edit `config.yaml` to add your API keys:

```yaml
api_keys:
  virustotal: "your-api-key-here"
  securitytrails: "your-api-key-here"
  shodan: "your-api-key-here"
  fullhunt: "your-api-key-here"
  binaryedge: "your-api-key-here"
  netlas: "your-api-key-here"
```

### Option 2: Environment Variables

```bash
export SUBSCOUT_VIRUSTOTAL="your-api-key"
export SUBSCOUT_SECURITYTRAILS="your-api-key"
export SUBSCOUT_SHODAN="your-api-key"
```

## Usage

### Basic Examples

```bash
# Passive enumeration only (all free sources)
python SubScout.py example.com

# Passive enumeration with verbose output
python SubScout.py example.com -v

# Active brute-forcing with wordlist
python SubScout.py example.com --mode active -w wordlists/default.txt

# Combined passive + active enumeration
python SubScout.py example.com --mode both -w wordlists/default.txt
```

### DNS Resolution

```bash
# Enumerate and resolve subdomains to IPs
python SubScout.py example.com --resolve -v

# Resolve with specific sources
python SubScout.py example.com --sources "crt.sh,virustotal" --resolve
```

### Anomaly Detection

```bash
# Filter anomalous subdomains (wildcards, catch-alls, duplicates)
python SubScout.py example.com --filter-anomalies -v

# Save anomalies to custom file
python SubScout.py example.com --filter-anomalies --anomalies-file suspicious.txt
```

### Output Formats

```bash
# Export to JSON with DNS resolution
python SubScout.py example.com --resolve -o results.json --format json

# Export to CSV
python SubScout.py example.com -o results.csv --format csv

# Export to TXT (default)
python SubScout.py example.com -o results.txt
```

### Advanced Usage

```bash
# Use specific sources only
python SubScout.py example.com --sources "crt.sh,alienvault,anubis"

# Full reconnaissance with all features
python SubScout.py example.com -v --resolve --filter-anomalies -o full_recon.json --format json

# Custom configuration file
python SubScout.py example.com --config custom_config.yaml
```

##  Command-Line Options

```
positional arguments:
  domain                Target domain

options:
  -h, --help            Show this help message and exit
  -m, --mode {passive,active,both}
                        Enumeration mode (default: passive)
  -w, --wordlist WORDLIST
                        Wordlist for active enumeration
  -o, --output OUTPUT   Output file path
  --format {txt,json,csv}
                        Output format (default: txt)
  -v, --verbose         Enable verbose output
  --sources SOURCES     Comma-separated list of sources to use
  --config CONFIG       Config file path (default: config.yaml)
  --filter-anomalies    Filter anomalous subdomains (redirects, duplicates)
  --resolve             Resolve subdomains to IP addresses via DNS
  --anomalies-file ANOMALIES_FILE
                        File to save anomalies
```
## API Keys

To get API keys for premium sources:

- **VirusTotal**: https://www.virustotal.com/gui/my-apikey
- **SecurityTrails**: https://securitytrails.com/app/account/credentials
- **Shodan**: https://account.shodan.io/
- **FullHunt**: https://fullhunt.io/
- **BinaryEdge**: https://app.binaryedge.io/
- **Netlas**: https://app.netlas.io/

## Tips & Best Practices

1. **Start with free sources** - The tool works great without any API keys
2. **Use verbose mode** - See detailed progress and HTTP status codes with `-v`
3. **Filter anomalies** - Use `--filter-anomalies` to remove wildcards and catch-alls
4. **Resolve IPs** - Add `--resolve` to verify which subdomains are actually accessible
5. **Combine features** - Use multiple flags together for comprehensive reconnaissance
6. **Check anomalies file** - Review filtered subdomains to ensure nothing important was removed

## Example Output

### Console Output
```
========================================================
                    SubScout v1.0
        Advanced Subdomain Reconnaissance Tool
========================================================

[*] Target: example.com
[*] Mode: passive
[*] Starting passive enumeration for example.com
[V] Querying crt.sh...
[+] crt.sh: Found 1250 subdomains
[V] Querying alienvault...
[+] alienvault: Found 342 subdomains
[*] Filtering anomalies (redirects and duplicates)...
[V] api.example.com - HTTP 200
[V] www.example.com - HTTP 301
[V]   → Redirects to: https://www.example.com
[!] Detected wildcard pattern: 15 subdomains with 1234 bytes response
[+] Anomalies saved to example.com_anomalies.json
[*] Resolving 450 subdomains...
[+] Resolved 380/450 subdomains

Found 450 unique subdomains:

api.example.com [192.0.2.1]
www.example.com [192.0.2.2]
mail.example.com [192.0.2.3]
...

============================================================
Statistics:
============================================================
  Passive Sources Used: 11
  Active Enumeration: No
  Total Subdomains: 450
  Anomalies Filtered: 120
  Resolved: 380
  Unresolved: 70
============================================================

[+] Exported 450 subdomains to results.txt
```

### JSON Output (with --resolve)
```json
{
  "domain": "example.com",
  "mode": "passive",
  "subdomains": [
    {
      "subdomain": "api.example.com",
      "ips": ["192.0.2.1"]
    },
    {
      "subdomain": "www.example.com",
      "ips": ["192.0.2.2", "192.0.2.3"]
    }
  ],
  "statistics": {
    "Passive Sources Used": 11,
    "Total Subdomains": 450,
    "Resolved": 380
  }
}
```
