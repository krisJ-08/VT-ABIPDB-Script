import requests
import csv
import time
import os
import logging
from dotenv import load_dotenv
import pycountry
from tqdm import tqdm
from queue import Queue
import threading

# Setup logging
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# Load environment variables
load_dotenv()

# Get API keys
VT_API_KEYS = os.getenv('VT_API_KEYS', '').split(',')
VT_API_KEYS = [key.strip() for key in VT_API_KEYS if key.strip()]
AIPDB_API_KEY = os.getenv('AIPDB_API')

# File names
INPUT_FILE = 'ips-input.txt'
OUTPUT_FILE = 'ips-output.csv'

# Constants
VT_API_URL = 'https://www.virustotal.com/api/v3/ip_addresses/{}'
ABUSEIPDB_API_URL = 'https://api.abuseipdb.com/api/v2/check'
MIN_VT_INTERVAL = 15  # seconds
ABUSEIPDB_DELAY = 1.5  # seconds

print("=" * 60)
print(f"[INFO] Loaded {len(VT_API_KEYS)} VirusTotal API key(s).")
if len(VT_API_KEYS) < 10:
    print(f"[WARNING] Only {len(VT_API_KEYS)} API key(s). This may slow down processing large volumes.")
print("=" * 60)

if not VT_API_KEYS:
    logging.error("VirusTotal API keys not found. Exiting.")
    exit(1)

if not AIPDB_API_KEY:
    logging.warning("AbuseIPDB API key not found. AbuseIPDB results will fail.")

def get_country_name(code):
    try:
        country = pycountry.countries.get(alpha_2=code)
        return country.name if country else 'N/A'
    except:
        return 'N/A'

def get_virus_total_report(ip, key):
    headers = {'x-apikey': key, 'accept': 'application/json'}
    url = VT_API_URL.format(ip)
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json().get('data', {}).get('attributes', {})
        elif response.status_code == 403:
            logging.warning(f"VT key blocked/rate-limited: {key}")
        else:
            logging.warning(f"VT error {response.status_code} for {ip}")
    except Exception as e:
        logging.error(f"VT request failed for {ip}: {e}")
    return {}

def enrich_ip_virustotal_worker(key, ip_queue, vt_results, progress_bar):
    last_used = 0
    while not ip_queue.empty():
        ip = ip_queue.get()
        elapsed = time.time() - last_used
        if elapsed < MIN_VT_INTERVAL:
            time.sleep(MIN_VT_INTERVAL - elapsed)
        last_used = time.time()

        attrs = get_virus_total_report(ip, key)
        hits = attrs.get('last_analysis_stats', {}).get('malicious', 'N/A')
        country = get_country_name(attrs.get('country', 'N/A'))
        owner = attrs.get('as_owner', 'N/A')

        vt_results[ip] = {
            'hits': hits,
            'owner': owner,
            'country': country
        }
        progress_bar.update(1)
        ip_queue.task_done()

def get_abuseipdb_report(ip):
    headers = {'Accept': 'application/json', 'Key': AIPDB_API_KEY}
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    try:
        response = requests.get(ABUSEIPDB_API_URL, headers=headers, params=params)
        if response.status_code == 200:
            return response.json().get('data', {})
        else:
            logging.warning(f"AbuseIPDB error {response.status_code} for {ip}")
    except Exception as e:
        logging.error(f"AbuseIPDB request failed for {ip}: {e}")
    return {}

def enrich_ip_abuseipdb(ip, aipdb_results):
    data = get_abuseipdb_report(ip)
    score = f"{data.get('abuseConfidenceScore', 'N/A')}% COA"
    isp = data.get('isp', 'N/A')
    country = get_country_name(data.get('countryCode', 'N/A'))

    aipdb_results[ip] = {
        'score': score,
        'isp': isp,
        'country': country
    }
    time.sleep(ABUSEIPDB_DELAY)

def write_results(results):
    with open(OUTPUT_FILE, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(results)

def get_user_choice():
    print("Choose the service to use:")
    print("1. VirusTotal")
    print("2. AbuseIPDB")
    print("3. Both")
    return input("Enter your choice (1/2/3): ").strip()

def main():
    start_time = time.time()

    choice = get_user_choice()
    if choice not in ['1', '2', '3']:
        logging.error("Invalid choice. Exiting.")
        return

    if not os.path.exists(INPUT_FILE):
        logging.error(f"Input file '{INPUT_FILE}' not found.")
        return

    with open(INPUT_FILE, 'r') as f:
        ip_addresses = [ip.strip() for ip in f if ip.strip()]

    if not ip_addresses:
        logging.error("No IPs found in input file.")
        return

    vt_results = {}
    aipdb_results = {}

    if choice in ['1', '3']:
        ip_queues = [Queue() for _ in VT_API_KEYS]
        for i, ip in enumerate(ip_addresses):
            ip_queues[i % len(VT_API_KEYS)].put(ip)

        vt_threads = []
        progress = tqdm(total=len(ip_addresses), desc="VirusTotal")

        for i, key in enumerate(VT_API_KEYS):
            thread = threading.Thread(
                target=enrich_ip_virustotal_worker,
                args=(key, ip_queues[i], vt_results, progress),
                daemon=True
            )
            vt_threads.append(thread)
            thread.start()

        for q in ip_queues:
            q.join()

        for thread in vt_threads:
            thread.join()
        progress.close()

    if choice in ['2', '3']:
        aipdb_threads = []
        for ip in ip_addresses:
            thread = threading.Thread(
                target=enrich_ip_abuseipdb,
                args=(ip, aipdb_results),
                daemon=True
            )
            aipdb_threads.append(thread)
            thread.start()

        for thread in aipdb_threads:
            thread.join()

    final_results = []

    for ip in ip_addresses:
        if choice in ['1', '3']:
            vt_row = vt_results.get(ip, {})
            vt_hits = vt_row.get('hits', 'N/A')
            vt_owner = vt_row.get('owner', 'N/A')
            vt_country = vt_row.get('country', 'N/A')
            final_results.append([ip, f"{vt_hits} hit" if vt_hits == 1 else f"{vt_hits} hits", vt_owner, vt_country, "VirusTotal"])

        if choice in ['2', '3']:
            aipdb_row = aipdb_results.get(ip, {})
            aipdb_score = aipdb_row.get('score', 'N/A')
            aipdb_isp = aipdb_row.get('isp', 'N/A')
            aipdb_country = aipdb_row.get('country', 'N/A')
            final_results.append([ip if choice == '2' else "", aipdb_score, aipdb_isp, aipdb_country, "AbuseIPDB"])

    write_results(final_results)

    duration = time.time() - start_time
    logging.info(f"Script completed in {duration:.2f} seconds ({duration / 60:.2f} minutes).")

if __name__ == '__main__':
    main()
