<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
</head>
<body>
    <h1>NetSentinel: IOCScanner</h1>
    <p>NetSentinel's IOCScanner is a sophisticated Python script designed for cybersecurity enthusiasts, analysts, and professionals. It extracts Indicators of Compromise (IOCs) from pcap files and checks them against the VirusTotal API for security analysis. This tool facilitates the identification of malicious URLs, domains, and IP addresses within network traffic, providing an efficient method for analyzing potential threats.</p>

  <h2>Installation</h2>
    <h3>Prerequisites</h3>
    <ul>
        <li>Python 3.x</li>
        <li>pip (Python package manager)</li>
    </ul>
    <h3>Required Packages</h3>
    <p>The script requires the following Python packages:</p>
    <ul>
        <li>pyshark</li>
        <li>vt-py (VirusTotal API)</li>
        <li>tqdm (for progress bars)</li>
    </ul>
    <p>To install these packages, run:</p>
    <pre><code>pip install pyshark vt-py tqdm</code></pre>

  <h2>Configuration</h2>
    <p>Before using IOCScanner, you'll need a VirusTotal API key. Follow these steps to obtain and configure your API key:</p>
    <h3>Obtaining a VirusTotal API Key</h3>
    <ol>
        <li>Visit <a href="https://www.virustotal.com/gui/join-us">VirusTotal</a> and sign up for an account or log in if you already have one.</li>
        <li>Once logged in, navigate to your profile settings to find the API Key section.</li>
        <img src="https://storage.googleapis.com/vtdocresources/guides/api/apikey_20231027.png" alt="API key">
        <li>Copy your API key. This key allows the IOCScanner to query VirusTotal's databases for IOC analysis.</li>
    </ol>
    <h3>Configuring Your API Key with IOCScanner</h3>
    <p>When you run IOCScanner for the first time, the script will prompt you to enter your VirusTotal API key. Follow these steps:</p>
    <ol>
        <li>Run the script using a command line interface. If a configuration file doesn't exist, the script will prompt you for your VirusTotal API key:</li>
        <pre><code>python IOCScanner.py path_to_your_pcap_file.pcap</code></pre>
        <h4>or</h4>
        <br/>
        <pre><code>python3 IOCScanner.py path_to_your_pcap_file.pcap</code></pre>
        <li>Enter your VirusTotal API key at the prompt and press Enter. The script will save your API key in <code>net_sentinel_config.ini</code> for future use.</li>
        <li>The script will then proceed to extract IOCs from the provided pcap file, query them against VirusTotal, and generate a report.</li>
    </ol>
    <p>If you need to change your API key in the future, you can edit the <code>net_sentinel_config.ini</code> file directly or delete it. The script will prompt you for a new API key the next time it runs.</p>

  <h2>Usage</h2>
    <p>To use IOCScanner, simply provide the path to a pcap file as a command-line argument:</p>
    <pre><code>python IOCScanner.py path_to_your_pcap_file.pcap</code></pre>
    <p>The script will extract IOCs from the pcap file, query them against VirusTotal, and print a report of the findings.</p>

  <h2>Functionality</h2>
    <ul>
        <li>Checks for required Python packages and prompts for installation if necessary.</li>
        <li>Automatically prompts for and saves your VirusTotal API key.</li>
        <li>Extracts URLs, domains, and IP addresses from pcap files.</li>
        <li>Queries the extracted IOCs against VirusTotal and generates a detailed report.</li>
    </ul>

  <h2>Contributing</h2>
    <p>Contributions to NetSentinel's IOCScanner are welcome! Please feel free to fork the repository, make your changes, and submit a pull request.</p>

  <h2>Disclaimer</h2>
    <p>NetSentinel's IOCScanner is intended for educational and research purposes only. Please use responsibly and in accordance with all applicable laws and regulations.</p>
</body>
</html>
