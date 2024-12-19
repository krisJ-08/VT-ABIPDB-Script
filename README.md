# VirusTotal and AbuseIPDB Script

This repository contains a Python script developed by Inspira that integrates with VirusTotal and AbuseIPDB APIs to fetch and format results for our SOC (Security Operations Center) reports. The script outputs the results in a custom format suitable for our reporting needs.

## Features

- Fetches data from VirusTotal and AbuseIPDB.
- Customizable output format for SOC reports.
- Easy to configure and use.

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/virustotal-abuseipdb-script.git
    cd virustotal-abuseipdb-script
    ```

2. Install the `pycountry` dependency:
    ```bash
    pip install pycountry
    ```

## Usage

1. Create a `.env` file in the root directory and add your API keys:
    ```env
    VIRUSTOTAL_API_KEY=your_virustotal_api_key
    ABUSEIPDB_API_KEY=your_abuseipdb_api_key
    ```

2. Input the list of IPs into the `ips-input.txt` file. Each IP should be on a new line:
    ```
    192.168.1.1
    8.8.8.8
    1.1.1.1
    ```

3. Run the script:
    ```bash
    python script.py
    ```

4. The results will be saved in the specified csv file `ips-output.csv` directory.

### HAPPY MONITORING!!!