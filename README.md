# IP-Triage 🔍

A command-line IP reputation intelligence tool that queries multiple threat intel sources in parallel and aggregates the results. Supports both fanged and defanged IP address formats.

## Sources

| Service | API Needed | What it provides                                                            |
|---|------------|-----------------------------------------------------------------------------|
| [VirusTotal](https://www.virustotal.com) | Yes        | ASN, country, community votes, AV engine analysis, comments                 |
| [AbuseIPDB](https://www.abuseipdb.com) | Yes        | Abuse confidence score, ISP, usage type, Tor exit node status, report count |
| [Cisco Talos](https://talosintelligence.com) | No         | Direct link to reputation center lookup, no API results                     |

## Requirements

- API keys for the sources listed above. They are free accounts
- Python 3.x
- `requests` [library](https://pypi.org/project/requests/) 


```bash
pip install requests
```

## Setup

1. Clone the repo:
   ```bash
   git clone https://github.com/Dump-Log/ip-triage.git
   cd ip-triage
   ```

2. Create accounts for VirusTotal and AbuseIPDB
   - Accounts are free
   - Acquire API keys
   

4. Add your API keys at the top of `ip-triage.py`:
   ```python
   VIRUSTOTAL_API_KEY = "your_virustotal_api_key"
   ABUSEIPDB_API_KEY = "your_abuseipdb_api_key"
   ```

## Usage

```bash
python ip-triage.py <IP address>
```

Both fanged and defanged formats are supported:

```bash
# Fanged
python ip-triage.py 8.8.8.8

# Defanged
python ip-triage.py 8[.]8[.]8[.]8
```

## Example Output

```
python ip-triage.py 8.8.8.8

=== VirusTotal ===
https://www.virustotal.com/gui/ip-address/8.8.8.8
        ASN: 15169
        Country: US
        Votes: {'harmless': 270, 'malicious': 57}
        Analysis: {'malicious': 0, 'suspicious': 0, 'undetected': 36, 'harmless': 55, 'timeout': 0}
        Comments Count: 20

=== AbuseIPDB ===
https://www.abuseipdb.com/check/8.8.8.8
        ConfidenceScore: 0
        Country: US
        ISP: Google LLC
        Usage Type: Content Delivery Network
        Tor: False
        Total Reports: 104
        Reports Count: 0

=== Cisco Talos ===
https://www.talosintelligence.com/reputation_center/lookup?search=8.8.8.8
```

## Future Work
- Expand services to include more
- Implement a threat score
- handle multiple IP's at once

## API Documentation

- [VirusTotal API](https://docs.virustotal.com/reference/ip-info)
- [AbuseIPDB API](https://docs.abuseipdb.com/)

