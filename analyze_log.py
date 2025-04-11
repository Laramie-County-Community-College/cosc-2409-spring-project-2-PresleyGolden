import re
import os

def analyze_log_file(filename="access.log"):
    """Analyzes a log file and extracts information."""

    try:
        with open(filename, "r") as f:
            log_lines = f.readlines()
    except FileNotFoundError:
        print(f"Error: Log file '{filename}' not found.")
        return

    error_count = 0
    unique_ips = set()
    url_counts = {}

    for line in log_lines:
        timestamp, ip, url, status_code = extract_log_data(line)
        if timestamp is None:
            continue  # Skip lines that don't match

        unique_ips.add(ip)

        if url in url_counts:
            url_counts[url] += 1
        else:
            url_counts[url] = 1

        if int(status_code) >= 400:
            error_count += 1

    # Print summary
    print(f"\nTotal Errors (4xx and 5xx): {error_count}")
    print(f"Unique IP Addresses: {len(unique_ips)}")

    if url_counts:
        print("URL Access Counts:")
        for url, count in url_counts.items():
            print(f"    {url}: {count}")
    else:
        print("No valid URL entries found in the log.")


def extract_log_data(line):
    """Extracts timestamp, IP address, URL, and status code from a valid log line."""
    match = re.search(
        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - "
        r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - "
        r"\"GET (.+) HTTP/1.1\" (\d+)", line)
    if match:
        timestamp, ip, url, status_code = match.groups()
        return timestamp, ip, url.strip(), status_code
    else:
        return None, None, None, None


# Analyze the log file
analyze_log_file()