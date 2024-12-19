import requests
import csv
import time
from tqdm import tqdm
from dotenv import load_dotenv
import os
import pycountry

load_dotenv()

# REMOVE THE SPACES FROM THE INPUT FILE
# INSTALL tqdm and requests USING PIP

VT_API_KEY = os.getenv('VT_API')  # Change to your own API Key in the .env file
AIPDB_API_KEY = os.getenv('AIPDB_API')  # Change to your own API Key in the .env file

API_KEY = VT_API_KEY  # Replace with your VirusTotal API key
INPUT_FILE = 'ips-input.txt'
OUTPUT_FILE = 'ips-output.csv'
VT_API_URL = 'https://www.virustotal.com/api/v3/ip_addresses/{}'
ABUSEIPDB_API_URL = 'https://api.abuseipdb.com/api/v2/check'


def get_abuseipdb_report(ip_address):
		querystring = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
		headers = {'Accept': 'application/json', 'Key': AIPDB_API_KEY}
		response = requests.get(ABUSEIPDB_API_URL, headers=headers, params=querystring)
		if response.status_code == 200:
				return response.json()
		return None


def get_virus_total_report(ip_address):
		headers = {'x-apikey': API_KEY, 'accept': 'application/json'}
		url = VT_API_URL.format(ip_address)
		response = requests.get(url, headers=headers)
		if response.status_code == 200:
				return response.json()
		return None

def get_country_name(country_code):
		try:
				country = pycountry.countries.get(alpha_2=country_code)
				return country.name if country else 'N/A'
		except KeyError:
				return 'N/A'

def get_user_choice():
		print("Choose the service to use:")
		print("1. VirusTotal")
		print("2. AbuseIPDB")
		print("3. Both")
		choice = input("Enter your choice (1/2/3): ")
		return choice

def process_ip_address(ip_address, choice):
		vt_result = None
		abuseipdb_result = None
		results = []

		if choice in ['1', '3']:
				vt_result = get_virus_total_report(ip_address)

		if choice in ['2', '3']:
				abuseipdb_result = get_abuseipdb_report(ip_address)

		# VirusTotal result processing
		if vt_result and 'data' in vt_result and 'attributes' in vt_result['data']:
				vt_attributes = vt_result['data']['attributes']
				vt_hits = vt_attributes.get('last_analysis_stats', {}).get('malicious', 'N/A')
				vt_country_code = vt_attributes.get('country', 'N/A')
				if vt_country_code == 'N/A':
						vt_country_code = vt_attributes.get('country_code', 'N/A')  # Check for alternative key
				vt_country = get_country_name(vt_country_code)
				vt_as_owner = vt_attributes.get('as_owner', 'N/A')
		else:
				vt_hits = 'N/A'
				vt_country = 'N/A'
				vt_as_owner = 'N/A'

		# AbuseIPDB result processing
		if abuseipdb_result and 'data' in abuseipdb_result:
				abuse_data = abuseipdb_result['data']
				abuse_coa = f"{abuse_data.get('abuseConfidenceScore', 'N/A')}% COA"
				abuse_isp = abuse_data.get('isp', 'N/A')
				abuse_country_code = abuse_data.get('countryCode', 'N/A')
				abuse_country = get_country_name(abuse_country_code)
		else:
				abuse_coa = 'N/A'
				abuse_isp = 'N/A'
				abuse_country = 'N/A'

		if choice in ['1', '3']:
				if vt_hits == 1:
						results.append([ip_address, f"{vt_hits} hit", vt_as_owner, vt_country, "VirusTotal"])
				else:
						results.append([ip_address, f"{vt_hits} hits", vt_as_owner, vt_country, "VirusTotal"])

		if choice in ['2', '3']:
				results.append([ip_address, abuse_coa, abuse_isp, abuse_country, "AbuseIPDB"])

		return results

def main():
		choice = get_user_choice()

		with open(INPUT_FILE, 'r') as infile:
				ip_addresses = infile.read().splitlines()

		all_results = []
		for ip_address in tqdm(ip_addresses, desc="Processing IP addresses"):
				results = process_ip_address(ip_address, choice)
				all_results.extend(results)
				time.sleep(15)

		with open(OUTPUT_FILE, 'w', newline='') as outfile:
				writer = csv.writer(outfile, quotechar='"', quoting=csv.QUOTE_MINIMAL)
				writer.writerows(all_results)


if __name__ == '__main__':
		main()