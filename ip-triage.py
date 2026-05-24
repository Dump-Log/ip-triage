# IP Intelligence Gatherer
#
# Queries multiple IP reputation services and aggregates results:
# - VirusTotal
# - AbuseIPDB
# - Cisco Talos
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
from concurrent.futures import ThreadPoolExecutor

# ----------------------------
# API Keys (populate these)
# ----------------------------
VIRUSTOTAL_API_KEY = "your_virustotal_api_key"
ABUSEIPDB_API_KEY = "your_abuseipdb_api_key"


# ----------------------------
# Utility Functions
# ----------------------------
def fang_ip(ip):
    """Convert defanged IP (1[.]2[.]3[.]4) to normal format."""
    return ip.replace("[.]", ".")


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

            # Store only count of reports
            result["ReportsCount"] = len(data.get("reports", []))

        else:
            result["error"] = f"AbuseIPDB request failed: {response.status_code}"

    except requests.exceptions.RequestException as e:
        result["error"] = f"AbuseIPDB request error: {e}"

    except Exception as e:
        result["error"] = f"AbuseIPDB processing error: {e}"

    return result


# ----------------------------
# Cisco Talos Lookup
# ----------------------------
def cisco_gen(ip):
    """Generate Cisco Talos lookup URL."""
    return {
        "url": (
            "https://www.talosintelligence.com/"
            f"reputation_center/lookup?search={ip}"
        )
    }


# ----------------------------
# Output Formatting
# ----------------------------
def print_data(vt, abuse, cisco):
    """Print aggregated intelligence results."""

    print("\n=== VirusTotal ===")

    if "error" in vt:
        print(vt["error"])
    else:
        print(vt.get("url"))
        print("\tASN:", vt.get("ASN"))
        print("\tCountry:", vt.get("Country"))
        print("\tVotes:", vt.get("Votes"))
        print("\tAnalysis:", vt.get("Analysis"))
        print("\tComments Count:", vt.get("CommentsCount"))

    print("\n=== AbuseIPDB ===")

    if "error" in abuse:
        print(abuse["error"])
    else:
        print(abuse.get("url"))
        print("\tConfidenceScore:", abuse.get("ConfidenceScore"))
        print("\tCountry:", abuse.get("Country"))
        print("\tISP:", abuse.get("ISP"))
        print("\tUsage Type:", abuse.get("UsageType"))
        print("\tTor:", abuse.get("isTor"))
        print("\tTotal Reports:", abuse.get("TotalReports"))
        print("\tReports Count:", abuse.get("ReportsCount"))

    print("\n=== Cisco Talos ===")
    print(cisco.get("url"))


# ----------------------------
# Main Execution
# ----------------------------
if __name__ == "__main__":

    try:
        # Ensure IP argument is provided
        if len(sys.argv) < 2:
            print("Usage: python ipintel.py <ip_address>")
            sys.exit(1)

        ip = fang_ip(sys.argv[1])

        # Run API calls concurrently
        with ThreadPoolExecutor(max_workers=3) as executor:
            vt_future = executor.submit(virus_total, ip)
            abuse_future = executor.submit(abuse_ipdb, ip)
            cisco_future = executor.submit(cisco_gen, ip)

            vt_result = vt_future.result()
            abuse_result = abuse_future.result()
            cisco_result = cisco_future.result()

        # Print results
        print_data(vt_result, abuse_result, cisco_result)

    except KeyboardInterrupt:
        print("\nExecution interrupted by user.")

    except Exception as e:
        print(f"\nUnexpected error: {e}")