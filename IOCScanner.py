import sys
import os
from configparser import ConfigParser

def check_packages():
    required_packages = {
        "pyshark": "pyshark",
        "vt-py": "vt",
        "tqdm": "tqdm"
    }
    missing_packages = []
    for package_name, import_name in required_packages.items():
        try:
            __import__(import_name)
        except ImportError:
            missing_packages.append(package_name)

    if missing_packages:
        print(f"The following required packages are missing: {', '.join(missing_packages)}")
        print("Please install them by running: pip install " + " ".join(missing_packages))
        sys.exit(1)

def get_api_key(config_file):
    config = ConfigParser()
    config.read(config_file)
    
    if config.has_section('VirusTotal') and config.has_option('VirusTotal', 'API_KEY'):
        api_key = config.get('VirusTotal', 'API_KEY')
        if api_key:
            return api_key
        else:
            print("API key in config file is empty. Please provide a valid API key.")
            api_key = input("Please enter your VirusTotal API Key: ").strip()
            if not api_key:
                print("No API Key provided. Exiting...")
                sys.exit(1)
            config.set('VirusTotal', 'API_KEY', api_key)
            with open(config_file, 'w') as f:
                config.write(f)
            print(f"API Key saved to {config_file}.")
            return api_key

    else:
        api_key = input("Please enter your VirusTotal API Key: ").strip()
        if not api_key:
            print("No API Key provided. Exiting...")
            sys.exit(1)
        config.add_section('VirusTotal')
        config.set('VirusTotal', 'API_KEY', api_key)
        with open(config_file, 'w') as f:
            config.write(f)
        print(f"API Key saved to {config_file}.")
        return api_key

if __name__ == "__main__":
    check_packages()
    
    # The rest of your imports can now be here because check_packages will exit if a package is missing
    import pyshark
    import vt
    from tqdm import tqdm
    
    # Define the path to the configuration file correctly
#    config_file = 'net_sentinel_config.ini'
    
    # Use the correct variable name for getting the API key
#    API_KEY = get_api_key('')

def extract_iocs_from_pcap(file_path):
    print("Starting to extract IOCs from the pcap file...")
    iocs = {'urls': set(), 'domains': set(), 'ips': set()}
    try:
        cap = pyshark.FileCapture(file_path, only_summaries=True)
        total_packets = len(cap)
        cap.close()
        cap = pyshark.FileCapture(file_path)

        for packet in tqdm(cap, total=total_packets, desc="Extracting IOCs"):
            # Extract URLs from HTTP requests
            if hasattr(packet, 'http') and hasattr(packet.http, 'request_full_uri'):
                iocs['urls'].add(packet.http.request_full_uri)
            
            # Extract IP addresses
            if hasattr(packet, 'ip'):
                iocs['ips'].add(packet.ip.src)
                iocs['ips'].add(packet.ip.dst)
            
            # Extract domain names (DNS queries)
            if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
                iocs['domains'].add(packet.dns.qry_name)
        print("Extraction completed successfully.")
    except FileNotFoundError:
        print(f"File {file_path} not found.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)
    return iocs

def query_virustotal(iocs, api_key):
    # Initialize a dictionary to hold the query results, including successes and failures.
    query_results = {
        'successful': {'urls': [], 'domains': [], 'ips': []},
        'failed': {'urls': [], 'domains': [], 'ips': []}
    }

    with vt.Client(api_key) as client:
        for ioc_type in iocs:
            for ioc in tqdm(iocs[ioc_type], desc=f"Querying {ioc_type}"):
                try:
                    if ioc_type == 'urls':
                        url_id = vt.url_id(ioc)
                        analysis = client.get_object(f"/urls/{url_id}")
                        query_results['successful'][ioc_type].append((ioc, analysis.last_analysis_stats['malicious']))
                    elif ioc_type == 'domains':
                        analysis = client.get_object(f"/domains/{ioc}")
                        query_results['successful'][ioc_type].append((ioc, analysis.last_analysis_stats['malicious']))
                    elif ioc_type == 'ips':
                        analysis = client.get_object(f"/ip_addresses/{ioc}")
                        query_results['successful'][ioc_type].append((ioc, analysis.last_analysis_stats['malicious']))
                except vt.error.APIError as e:
                    query_results['failed'][ioc_type].append((ioc, str(e)))

    return query_results

def print_report(query_results):
    print("\nQuery Report:")

    for category in query_results:
        print(f"\n{category.capitalize()} Queries:")

        for ioc_type in query_results[category]:
            if query_results[category][ioc_type]:
                print(f"\n{ioc_type.capitalize()}:")
                for ioc, result in query_results[category][ioc_type]:
                    print(f"  - {ioc}: {result}")
            else:
                print(f"\nNo {ioc_type} were {category}.")

if __name__ == "__main__":
    check_packages()

    try:
        if len(sys.argv) != 2:
            print("Usage: python IOCScanner.py <path_to_pcap_file>")
            sys.exit(1)
        
        config_file = 'net_sentinel_config.ini'
        API_KEY = get_api_key(config_file)

        PCAP_FILE = sys.argv[1]
        print(f"Processing file: {PCAP_FILE}")
        iocs = extract_iocs_from_pcap(PCAP_FILE)
        if iocs:
            print(f"Extracted IOCs: URLs: {len(iocs['urls'])}, Domains: {len(iocs['domains'])}, IPs: {len(iocs['ips'])}")
            query_results = query_virustotal(iocs, API_KEY)
            print_report(query_results)
        else:
            print("No IOCs extracted from the pcap file.")
    except KeyboardInterrupt:
        print("\nProcess was interrupted by user. Exiting...")
        sys.exit(1)
