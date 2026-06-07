# IP-Triage 🔍

A command-line IP reputation intelligence tool that queries multiple threat intel sources in parallel and aggregates the results. Supports both fanged and defanged IP address formats.

## Sources

| Service | API Needed | What it provides                                                            |
|---|------------|-----------------------------------------------------------------------------|
| [VirusTotal](https://www.virustotal.com) | Yes        | ASN, country, community votes, AV engine analysis, comments                 |
| [AbuseIPDB](https://www.abuseipdb.com) | Yes        | Abuse confidence score, ISP, usage type, Tor exit node status, report count |
| [GreyNoise](https://viz.greynoise.io) | Yes         | Direct link to GreyNoise                    |

## Requirements

- API keys for the sources listed above. They are free accounts
- Python 3.x
- install requirements.txt


```bash
pip install -r requirements.txt
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
   
4. Rename env.example to .env
5. Add your API keys .env:
   ```python
   VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
   ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
   GREYNOISE_API_KEY=your_greyNoise_api_key_here
   ```

## Usage

```bash
python ip-triage.py <IP address> <IP address> .... <IP address>
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
python .\ip-triage.py 8.8.8.8 

======================================================
8.8.8.8
======================================================

  [ VirusTotal ]
  ----------------------------------------------------
  https://www.virustotal.com/gui/ip-address/8.8.8.8

  ASN:                 15169
  Country:             US
  Votes:               {'harmless': 274, 'malicious': 57}
  Analysis:            {'malicious': 0, 'suspicious': 0, 'undetected': 36, 'harmless': 55, 'timeout': 0}
  Comments:            20

  [ AbuseIPDB ]
  ----------------------------------------------------
  https://www.abuseipdb.com/check/8.8.8.8

  Confidence Score:    0
  Country:             US
  ISP:                 Google LLC
  Usage Type:          Content Delivery Network
  Tor:                 False
  Total Reports:       125

  [ GreyNoise ]
  ----------------------------------------------------
  https://viz.greynoise.io/ip/8.8.8.8

  Classification:      benign
  Noise:               False
  Riot:                True
  Name:                Google Public DNS
  Last Seen:           2026-06-07
```

## Future Work
- Add additional API's
- Add support to take log files and parse IP's to look up
- Add a CSV feature to preserve results 


## API Documentation

- [VirusTotal API](https://docs.virustotal.com/reference/ip-info)
- [AbuseIPDB API](https://docs.abuseipdb.com/)
- [GreyNoise API](https://docs.greynoise.io/docs/using-the-greynoise-api)

