# IP Intelligence Gatherer
#
# Queries multiple IP reputation services and aggregates results:
# - VirusTotal
# - AbuseIPDB
#
# Input:
#   - Accepts a defanged IP (e.g. 1[.]2[.]3[.]4) or normal IP
#
# Output:
#   - Parsed intelligence results
#   - Direct URLs to each service

# API Documentation:
#   - VirusTotal: https://docs.virustotal.com/reference/ip-info
#   - AbuseIPDB: https://docs.abuseipdb.com/

import sys
import requests
from dotenv import load_dotenv
import os

import ipaddress
from concurrent.futures import ThreadPoolExecutor

# ----------------------------
# API Keys (populate these)
# ----------------------------
load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# exit if an api key is missing
if not VIRUSTOTAL_API_KEY or not ABUSEIPDB_API_KEY:
    print("Error: Check API keys")
    sys.exit(1)

# ----------------------------
# Utility Functions
# ----------------------------
def fang_ip(ip):
    """Convert defanged IP (1[.]2[.]3[.]4) to normal format."""
    return ip.replace("[.]", ".")

# ----------------------------
# Verify IP Format
# ----------------------------
def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# ----------------------------
# VirusTotal Lookup
# ----------------------------
def virus_total(ip):
    """Query VirusTotal API for IP intelligence."""

    result = {}

    try:
        ip_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        comment_url = f"{ip_url}/comments?limit=20"

        headers = {
            "accept": "application/json",
            "x-apikey": VIRUSTOTAL_API_KEY
        }

        # API requests
        ip_response = requests.get(ip_url, headers=headers, timeout=10)
        comment_response = requests.get(comment_url, headers=headers, timeout=10)

        result["url"] = f"https://www.virustotal.com/gui/ip-address/{ip}"

        # Ensure request success
        if ip_response.status_code == 200:
            data = ip_response.json()["data"]["attributes"]

            result["ASN"] = data.get("asn")
            result["Country"] = data.get("country")
            result["Votes"] = data.get("total_votes")
            result["Analysis"] = data.get("last_analysis_stats")

        else:
            result["error"] = f"VirusTotal IP request failed: {ip_response.status_code}"

        # Comments (store only count for simplicity/safety)
        if comment_response.status_code == 200:
            comment_data = comment_response.json()
            result["CommentsCount"] = len(comment_data.get("data", []))
        else:
            result["CommentsCount"] = 0

    except requests.exceptions.RequestException as e:
        result["error"] = f"VirusTotal request error: {e}"

    except Exception as e:
        result["error"] = f"VirusTotal processing error: {e}"

    return result


# ----------------------------
# AbuseIPDB Lookup
# ----------------------------
def abuse_ipdb(ip):
    """Query AbuseIPDB API for IP reputation data."""

    result = {}

    try:
        url = "https://api.abuseipdb.com/api/v2/check"

        headers = {
            "Accept": "application/json",
            "Key": ABUSEIPDB_API_KEY
        }

        params = {
            "ipAddress": ip,
            "maxAgeInDays": "365"
        }

        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=10
        )

        result["url"] = f"https://www.abuseipdb.com/check/{ip}"

        if response.status_code == 200:
            data = response.json()["data"]

            result["ConfidenceScore"] = data.get("abuseConfidenceScore")
            result["isTor"] = data.get("isTor")
            result["ISP"] = data.get("isp")
            result["TotalReports"] = data.get("totalReports")
            result["UsageType"] = data.get("usageType")
            result["Country"] = data.get("countryCode")

        else:
            result["error"] = f"AbuseIPDB request failed: {response.status_code}"

    except requests.exceptions.RequestException as e:
        result["error"] = f"AbuseIPDB request error: {e}"

    except Exception as e:
        result["error"] = f"AbuseIPDB processing error: {e}"

    return result


# ----------------------------
# Output Formatting
# ----------------------------
def print_data(ip, vt, abuse):
    """Print aggregated intelligence results for a single IP."""

    W = 54

    def row(label, value):
        v = value if value is not None else "No results"
        print(f"  {label:<20} {v}")

    # IP header
    print(f"\n{'=' * W}")
    print(f"  TARGET IP: {ip}")
    print(f"{'=' * W}")

    # VirusTotal
    print(f"\n  [ VirusTotal ]")
    print(f"  {'-' * (W - 2)}")
    if "error" in vt:
        print(f"  {vt['error']}")
    else:
        print(f"  {vt.get('url')}")
        print()
        row("ASN:", vt.get("ASN"))
        row("Country:", vt.get("Country"))
        row("Votes:", vt.get("Votes"))
        row("Analysis:", vt.get("Analysis"))
        row("Comments:", vt.get("CommentsCount"))

    # AbuseIPDB
    print(f"\n  [ AbuseIPDB ]")
    print(f"  {'-' * (W - 2)}")
    if "error" in abuse:
        print(f"  {abuse['error']}")
    else:
        print(f"  {abuse.get('url')}")
        print()
        row("Confidence Score:", abuse.get("ConfidenceScore"))
        row("Country:", abuse.get("Country"))
        row("ISP:", abuse.get("ISP"))
        row("Usage Type:", abuse.get("UsageType"))
        row("Tor:", abuse.get("isTor"))
        row("Total Reports:", abuse.get("TotalReports"))

# ----------------------------
# Main Execution
# ----------------------------
if __name__ == "__main__":

    try:
        # Ensure IP argument is provided
        if len(sys.argv) < 2:
            print("Usage: python ipintel.py <ip_address1> < ip_address2>.... <ip_address_N")
            sys.exit(1)

        # Fang and validate all inputs
        ips = []
        for arg in sys.argv[1:]:
            ip = fang_ip(arg)
            try:
                ipaddress.ip_address(ip)
                ips.append(ip)
            except ValueError:
                print(f"Skipping invalid IP: {arg}")

        if not ips:
            print("No valid IPs to look up.")
            sys.exit(1)

        # loops over multiple IP addresses
        for ip in ips:

            # Run API calls concurrently
            with ThreadPoolExecutor(max_workers=3) as executor:
                vt_future = executor.submit(virus_total, ip)
                abuse_future = executor.submit(abuse_ipdb, ip)

                vt_result = vt_future.result()
                abuse_result = abuse_future.result()

            # Print results
            print_data(ip, vt_result, abuse_result)

    except KeyboardInterrupt:
        print("\nExecution interrupted by user.")

    except Exception as e:
        print(f"\nUnexpected error: {e}")