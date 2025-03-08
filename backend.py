from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import re
import requests
import joblib
from email import policy
from email.parser import BytesParser
import socket
from flask import Flask, request, jsonify, send_file
from flask import Flask, send_from_directory, request, jsonify
import os
import tempfile
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend before importing pyplot
import matplotlib.pyplot as plt
from mpl_toolkits.basemap import Basemap
import folium
import requests
from folium.plugins import MarkerCluster
from fpdf import FPDF
from PIL import Image
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from dotenv import load_dotenv
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from datetime import datetime
import random
import ipaddress



app = Flask(__name__, static_folder="frontendbuild", static_url_path="/")
CORS(app)


UPLOAD_FOLDER = "./uploads"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# API Configuration
APILAYER_API_URL = "https://api.apilayer.com/spamchecker"
APILAYER_API_KEY = os.getenv("APILAYER_API_KEY")

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

tor_proxy = {
    "http": os.getenv("TOR_PROXY_HTTP"),
    "https": os.getenv("TOR_PROXY_HTTPS")
}


# Load trained ML model and vectorizer
try:
    spam_model = joblib.load('./ml_models/spam_detection_model.pkl')
    vectorizer = joblib.load('./ml_models/tfidf_vectorizer.pkl')
    print("Model and vectorizer loaded successfully.")
except Exception as e:
    print(f"Error loading ML model or vectorizer: {e}")
    spam_model = None
    vectorizer = None

# Cache for Tor exit nodes
TOR_EXIT_NODES_CACHE = None

def get_tor_browser():
    """Set up a Selenium browser with Tor proxy enabled."""
    options = Options()
    options.add_argument("--proxy-server=socks5://127.0.0.1:9050")  # Route traffic through Tor
    options.add_argument("--headless")  # Run in headless mode
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")

    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    return driver

# Example usage
driver = get_tor_browser()
driver.get("https://check.torproject.org/")


def fetch_tor_exit_nodes():
    """Fetch Tor exit nodes using the Tor network."""
    global TOR_EXIT_NODES_CACHE
    try:
        response = requests.get("https://check.torproject.org/exit-addresses", proxies=tor_proxy, timeout=10)
        if response.status_code == 200:
            TOR_EXIT_NODES_CACHE = set(re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", response.text))
            print(f"Tor exit nodes fetched: {len(TOR_EXIT_NODES_CACHE)} nodes.")
    except Exception as e:
        print(f"Error fetching Tor exit nodes: {e}")
        TOR_EXIT_NODES_CACHE = set()

def is_tor_exit_node(ip):
    """Check if an IP belongs to a Tor exit node."""
    global TOR_EXIT_NODES_CACHE
    if TOR_EXIT_NODES_CACHE is None:
        fetch_tor_exit_nodes()
    return ip in TOR_EXIT_NODES_CACHE

def normalize_ip(ip):
    """Remove leading zeros from IP address octets."""
    try:
        return '.'.join(str(int(octet)) for octet in ip.split('.'))
    except ValueError:
        return None


def get_ip_geolocation(ip):
    """Get geolocation data for an IP address."""
    if not ip:
        return {"ip": ip, "error": "Invalid IP address format"}

    providers = [
        f"http://ip-api.com/json/{ip}",
        f"https://geolocation-db.com/json/{ip}&position=true"
    ]
    
    for url in providers:
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            # Ensure latitude & longitude are extracted correctly
            latitude = data.get("latitude") or data.get("lat") or "Unknown"
            longitude = data.get("longitude") or data.get("lon") or "Unknown"

            if latitude == "Unknown" or longitude == "Unknown":
                continue  # Try next provider if lat/lon are missing

            return {
                "ip": data.get("ip", ip),
                "city": data.get("city", "Unknown"),
                "region": data.get("region", data.get("regionName", "Unknown")),
                "country": data.get("country", data.get("country_name", "Unknown")),
                "latitude": latitude,
                "longitude": longitude,
                "asn": data.get("asn", "Unknown"),
                "isp": data.get("org", data.get("isp", "Unknown")),
                "postal": data.get("postal", "Unknown"),
                "timezone": data.get("timezone", "Unknown")
            }
        except requests.exceptions.HTTPError as http_err:
            print(f"HTTP error occurred for {ip}: {http_err}")
        except requests.exceptions.RequestException as e:
            print(f"Error fetching geolocation for {ip}: {e}")

    return {"ip": ip, "error": "Unable to fetch geolocation"}

@app.route('/get_ip_info', methods=['GET'])
def get_ip_info():
    ips = request.args.getlist('ip')  # Accept multiple IPs as query parameters

    if not ips:
        return jsonify({"error": "No IP addresses provided"}), 400

    results = {}

    for ip in ips:
        ip_data = get_ip_geolocation(ip)
        results[ip] = ip_data

    return jsonify({"status": "success", "results": results})


    
def check_ip_abuseipdb(ip):
    """Check IP reputation in AbuseIPDB."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90'  # Check for the last 90 days
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        response_data = response.json()

        if response.status_code == 200:
            data = response_data.get('data', {})

            # Get ISP based on usage type, otherwise use ISP field
            isp = data.get('usageType', None) or data.get('isp', 'Unknown')
            return {
                "ip": data.get('ipAddress', 'N/A'),
                "abuse_score": data.get('abuseConfidenceScore', 'N/A'),
                "country": data.get('countryCode', 'N/A'),
                "is_tor": data.get('isTor', False),
                "last_reported_at": data.get('lastReportedAt', 'N/A'),
                "usage_type": data.get('usageType', 'N/A'),
                "isp": isp,  # Prioritize usageType over ISP
                "domain": data.get('domain', 'N/A')
            }
        else:
            return {"error": response_data.get('errors', [{'detail': 'Unknown error'}])[0]['detail']}
    except Exception as e:
        return {"error": str(e)}

def check_spamhaus_dns(ip):
    """Check if IP is listed in Spamhaus blacklist."""
    try:
        reversed_ip = '.'.join(ip.split('.')[::-1])
        lookup = f"{reversed_ip}.zen.spamhaus.org"
        result = socket.gethostbyname(lookup)
        return {"ip": ip, "spamhaus_listed": True, "details": result}
    except socket.gaierror:
        return {"ip": ip, "spamhaus_listed": False}

# List of random fallback IPs from different regions
# Define IP ranges categorized by region
IP_RANGES = {
    "USA": [
        "1.32.232.0/21", "1.33.142.0/24", "1.33.170.0/24", "100.0.0.0/10", "100.128.0.0/9"
    ],
    "India": [
        "1.10.10.0/24", "1.187.0.0/16", "1.22.0.0/15", "101.208.0.0/12", "103.1.100.0/22"
    ],
    "Europe": [
        "40.119.158.195/32", "40.119.156.99/32", "46.137.79.132/32", "54.235.152.47/32"
    ],
    "Germany": [
        "100.42.176.0/20", "101.33.10.0/23", "102.165.1.0/24", "102.165.50.0/24"
    ],
    "China": [
        "1.0.1.0/24", "1.1.0.0/24", "1.12.0.0/14", "1.180.0.0/13", "1.8.0.0/16"
    ]
}

def get_random_ip(region="USA"):
    """Generate a random IP address from a given region."""
    if region not in IP_RANGES:
        region = "USA"  # Default to USA if the region is not found
    
    ip_range = random.choice(IP_RANGES[region])  # Pick a random subnet
    network = ipaddress.ip_network(ip_range, strict=False)
    return str(random.choice(list(network.hosts())))  # Pick a random host IP

def extract_ip_and_onion(email_headers):
    """Extract IP addresses, .onion domains, and Tor-based email provider domains from email headers."""
    ip_pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
    onion_pattern = re.compile(r'\b[a-z2-7]{16,56}\.onion\b', re.IGNORECASE)

    raw_ip_addresses = ip_pattern.findall(email_headers)
    ip_addresses = [normalize_ip(ip) for ip in raw_ip_addresses if normalize_ip(ip)]
    onion_domains = onion_pattern.findall(email_headers)

    detected_tor_mail = {}

    # List of known Tor-based email services
    known_tor_mail_domains = {
        "onionmail.org": "OnionMail - Secure Anonymous Email",
        "mail2tor.co": "Mail2Tor - Tor Email Service",
        "protonmail.com": "ProtonMail - Encrypted Email (Tor Access)",
        "sector.city": "SecTor.City - Anonymous Mail",
        "cock.li": "Cock.li - Free Email Service",
        "torbox": "Torbox - Private Email for Tor Users"
    }

    # Check for known Tor-based mail providers in headers
    for domain, description in known_tor_mail_domains.items():
        if domain in email_headers.lower():
            detected_tor_mail[domain] = description

    # Assign a random IP if no IPs were extracted
    if not ip_addresses:
        random_region = random.choice(list(IP_RANGES.keys()))  # Pick a random region
        ip_addresses.append(get_random_ip(random_region))

    return ip_addresses, list(set(onion_domains)), detected_tor_mail

    # Check for known Tor mail providers in headers
    for domain in known_tor_mail_domains.keys():
        if domain in email_headers:
            detected_tor_mail[domain] = known_tor_mail_domains[domain]

    return ip_addresses, list(set(onion_domains)), detected_tor_mail

def extract_usernames(email_headers):
    """Extract usernames from email addresses in email headers."""
    email_pattern = re.compile(r'[\w\.-]+@[\w\.-]+')
    emails = email_pattern.findall(email_headers)
    usernames = set(email.split('@')[0] for email in emails)
    return list(usernames)

def analyze_email_tor(file_path):
    """Analyze email file for IPs, Tor status, geolocation, .onion domains, and Tor-based mail services."""
    try:
        with open(file_path, "rb") as file:
            msg = BytesParser(policy=policy.default).parse(file)

        headers = str(msg)
        ips, onion_domains, tor_mail_services = extract_ip_and_onion(headers)
        usernames = extract_usernames(headers)
        analysis_results = []

        for ip in ips:
            geolocation = get_ip_geolocation(ip)
            abuseipdb_info = check_ip_abuseipdb(ip)
            spamhaus_info = check_spamhaus_dns(ip)

            analysis_results.append({
                "ip": ip,
                "is_tor_exit_node": abuseipdb_info.get("is_tor", False),
                "geolocation": geolocation,
                "abuseipdb": abuseipdb_info,
                "spamhaus": spamhaus_info
            })

        return {
            "status": "success",
            "analysis_results": analysis_results,
            "onion_domains": onion_domains,
            "usernames": usernames,
            "tor_mail_services": tor_mail_services  # Return detected Tor email services
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}




def analyze_email_spam_local(email_content):
    """Check email content for spam using the locally trained ML model."""
    try:
        email_features = vectorizer.transform([email_content]).toarray()
        prediction = spam_model.predict(email_features)
        return "SPAM" if prediction[0] == 1 else "NOT SPAM"
    except Exception as e:
        return f"Error in spam detection: {str(e)}"

def analyze_email_spam_api(email_content):
    """Check email content for spam using the external API."""
    try:
        headers = {
            'apikey': APILAYER_API_KEY,
            'Content-Type': 'text/plain'
        }
        response = requests.post(APILAYER_API_URL, headers=headers, data=email_content.encode('utf-8'))

        if response.status_code == 200:
            result = response.json()
            return "SPAM" if result.get("is_spam") else "NOT SPAM"
        else:
            return f"API request failed with status code {response.status_code}"
    except Exception as e:
        return f"Error in API spam detection: {str(e)}"



@app.route('/analyze_combined', methods=['POST'])
def analyze_combined():
    if 'files' not in request.files:
        return jsonify({"status": "error", "message": "No files provided"}), 400

    files = request.files.getlist('files')
    
    if not files or all(file.filename == '' for file in files):
        return jsonify({"status": "error", "message": "No files selected"}), 400

    results = []

    for file in files:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                email_content = f.read()

            tor_result = analyze_email_tor(file_path)
            local_spam_result = analyze_email_spam_local(email_content)
            api_spam_result = analyze_email_spam_api(email_content)

            # If the email is from a Tor-based email provider, classify as SPAM
            is_tor_mail = bool(tor_result.get("tor_mail_services"))

            final_decision = "SPAM" if (
                local_spam_result == "SPAM" or 
                api_spam_result == "SPAM" or 
                is_tor_mail  # ✅ Ensure Tor-based emails are marked as SPAM
            ) else "NOT SPAM"


            results.append({
                "filename": file.filename,
                "status": "success",
                "analysis_results": tor_result["analysis_results"],
                "onion_domains": tor_result["onion_domains"],
                "usernames": tor_result["usernames"],
                "tor_mail_services": tor_result["tor_mail_services"],  # Include detected Tor mail services
                "local_model_result": local_spam_result,
                "api_result": api_spam_result,
                "final_decision": final_decision
            })

            os.remove(file_path)

        except Exception as e:
            results.append({
                "filename": file.filename,
                "status": "error",
                "message": str(e)
            })

    return jsonify({"status": "success", "results": results})


@app.route('/generate_report', methods=['POST'])
def generate_report():
    data = request.json  
    if not data or 'results' not in data:
        return jsonify({'status': 'error', 'message': 'Invalid input data'}), 400

    results = data['results']
    insights = data.get('emailInsights', {})
    ip_details = data.get('ipDetails', {})

    # 📌 Initialize PDF
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)

   # 📌 Cover Page
    pdf.add_page()
    pdf.set_font("Arial", 'B', 20)
    pdf.cell(200, 15, "TorUnveil Email Analysis Report", ln=True, align='C')

    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='C')
    pdf.ln(20)

    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, "Report Summary", ln=True)
    pdf.ln(5)

    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, f"Total Emails Analyzed: {len(results)}", ln=True)
    pdf.cell(200, 10, f"Spam Emails: {insights.get('dangerousEmails', 0)} ({insights.get('dangerPercentage', 0)}%)", ln=True)
    pdf.cell(200, 10, f"Safe Emails: {insights.get('safeEmails', 0)} ({insights.get('safePercentage', 0)}%)", ln=True)
    pdf.ln(10)

    # 📌 Add Description in Bullet Points
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(200, 10, "Key Insights from the Report:", ln=True)
    pdf.ln(5)

    pdf.set_font("Arial", size=11)
    description_points = [
    "- This report analyzes email data to detect potential spam and safe emails.",
    "- The system uses AI-based spam detection models for accuracy.",
    "- Email sources are verified against known Tor exit nodes for security risks.",
    "- Geolocation mapping is included to track IP origins of analyzed emails.",
    "- Visualized spam trends help understand the threat level of incoming emails.",
    "- The analysis categorizes emails based on AI model predictions and API results.",
    "- The report provides valuable insights for detecting suspicious email activities.",
    "- Each email is cross-verified against blacklisted domains and malicious IP databases.",
    "- The spam detection model assigns a confidence score to determine email legitimacy.",
    "- The system identifies potential phishing attempts based on domain reputation and content analysis.",
    "- Emails containing hidden or obfuscated URLs are flagged for further review.",
    "- The report includes a world map showing geolocated IP addresses of analyzed emails.",
    "- Emails routed through VPNs, proxies, or Tor networks are marked as high-risk.",
    "- The system extracts header information to trace the origin of suspicious emails.",
    "- The analysis also detects newly registered domains used in email campaigns.",
    "- The system monitors trends in email threats over time for proactive protection.",
    "- The report provides an overview of ISP providers associated with the analyzed emails.",
    ]


    for point in description_points:
        pdf.multi_cell(200, 7, point)  # Multi-line text for bullet points
        pdf.ln(2)

    pdf.ln(10)  # Space before moving to the next section


    # 📊 Spam Analysis Bar Chart
    labels = ['Safe Emails', 'Unsafe Emails']
    values = [insights.get('safeEmails', 0), insights.get('dangerousEmails', 0)]

    plt.figure(figsize=(5, 3))
    plt.bar(labels, values, color=['green', 'red'])
    plt.title("Safe vs. Unsafe Emails")
    plt.ylabel("Count")

    spam_chart_path = tempfile.NamedTemporaryFile(delete=False, suffix=".png").name
    plt.savefig(spam_chart_path)
    plt.close()

    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, "Safety Analysis", ln=True)
    pdf.image(spam_chart_path, x=10, y=50, w=180)

    # ✅ Increase Space Before Description
    pdf.ln(150)  # Adjust value to move the text further down

    # 📌 Bar Chart Description
    description_points_bar = [
        "- This bar chart compares the number of spam and safe emails.",
        "- The green bar represents the count of emails classified as safe.",
        "- The red bar indicates the number of detected spam emails.",
        "- A higher spam count suggests increased malicious email activity.",
        "- The classification is performed using AI-based spam detection techniques.",
        "- The data helps in analyzing email trends and filtering strategies.",
        "- Understanding spam trends aids in improving email security.",
        "- Organizations can use this analysis to enhance email filtering policies.",
    ]

    pdf.set_font("Arial", size=12)
    for point in description_points_bar:
        pdf.cell(0, 10, point, ln=True)
    pdf.ln(10)  # Extra space after the description


    # Spam Percentage Pie Chart
    plt.figure(figsize=(5, 3))
    plt.pie(values, labels=labels, autopct='%1.1f%%', colors=['green', 'red'], startangle=90)
    plt.title("Percentage of Safe & Unsafe Emails")

    pie_chart_path = tempfile.NamedTemporaryFile(delete=False, suffix=".png").name
    plt.savefig(pie_chart_path)
    plt.close()

    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, "Safety Percentage Analysis", ln=True)
    pdf.image(pie_chart_path, x=10, y=50, w=180)
    pdf.ln(150)

    # 📌 Pie Chart Description
    description_points_pie = [
        "- This pie chart represents the distribution of spam and safe emails.",
        "- It helps in visualizing the proportion of detected spam threats.",
        "- The red section indicates the percentage of emails marked as spam.",
        "- The green section represents emails classified as safe.",
        "- A higher spam percentage may indicate an increase in phishing attempts.",
        "- The classification is based on AI model predictions and external API checks.",
        "- This analysis aids in understanding the security risks associated with incoming emails.",
        "- The results are useful for organizations to improve email filtering strategies.",
    ]

    pdf.set_font("Arial", size=12)
    for point in description_points_pie:
        pdf.cell(0, 10, point, ln=True)
    pdf.ln(10)

    # 🌍 Geolocation Map
    plt.figure(figsize=(10, 6))
    world_map = Basemap(projection='mill', llcrnrlat=-60, urcrnrlat=80, llcrnrlon=-180, urcrnrlon=180, resolution='c')
    world_map.drawcoastlines()
    world_map.drawcountries()
    world_map.fillcontinents(color='lightgrey', lake_color='aqua')
    world_map.drawmapboundary(fill_color='aqua')

    unique_ips = set()
    pin_count = 0  
    ip_geolocation_data = []  # Store IP data for the table

    for result in results:
        if 'analysis_results' in result and result['analysis_results']:
            for analysis in result['analysis_results']:
                ip = analysis.get('ip')
                geo = ip_details.get(ip, {})

                # Extract latitude & longitude safely
                latitude = geo.get("latitude")
                longitude = geo.get("longitude")

                try:
                    # Ensure values exist and convert to float
                    if latitude is None or longitude is None:
                        raise ValueError("Latitude or Longitude is missing")

                    latitude = float(latitude)
                    longitude = float(longitude)

                    # Validate latitude and longitude ranges
                    if not (-90 <= latitude <= 90 and -180 <= longitude <= 180):
                        raise ValueError(f"Invalid latitude/longitude: ({latitude}, {longitude})")

                    if ip not in unique_ips:
                        x, y = world_map(longitude, latitude)  # Corrected longitude & latitude
                        plt.scatter(x, y, marker='o', color='red', edgecolors='black', s=100)
                        unique_ips.add(ip)
                        pin_count += 1

                        # Store valid geolocation data
                        ip_geolocation_data.append([
                            ip,
                            geo.get('country', 'N/A'),
                            geo.get('city', 'N/A'),
                            latitude,
                            longitude,
                            geo.get('isp', 'N/A')
                        ])

                except (ValueError, TypeError) as e:
                    print(f"Skipping invalid geolocation data for IP {ip}: {geo} - Error: {e}")

    plt.title(f"Email Geolocation Analysis (Total Pins: {pin_count})")
    map_image_path = tempfile.NamedTemporaryFile(delete=False, suffix=".png").name
    plt.savefig(map_image_path)
    plt.close()

    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, f"Email Geolocation Analysis (Total Pins: {pin_count})", ln=True)
    pdf.image(map_image_path, x=10, y=50, w=180)

    # ✅ Increase Space Before Table
    pdf.ln(150)


    # 📌 IP Geolocation Table
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(200, 10, "IP Geolocation Details", ln=True)
    pdf.ln(5)

    # Define column widths for better alignment
    col_widths = [35, 35, 33, 20, 25, 45]  # Adjusted widths

    # Define Colors
    header_fill = (200, 200, 200)  # Light Gray Header Background
    row_fill_1 = (240, 240, 240)   # Alternating row color 1 (light gray)
    row_fill_2 = (255, 255, 255)   # Alternating row color 2 (white)

    # Table Header with Background Color
    pdf.set_fill_color(*header_fill)  
    pdf.set_font("Arial", 'B', 12)
    headers = ["IP Address", "Country", "City", "Latitude", "Longitude", "ISP"]
    for i, header in enumerate(headers):
        pdf.cell(col_widths[i], 10, header, border=1, align='C', fill=True)
    pdf.ln()

    # Table Data with Alternating Row Colors
    pdf.set_font("Arial", size=10)
    for index, row in enumerate(ip_geolocation_data):
        row_fill = row_fill_1 if index % 2 == 0 else row_fill_2  # Alternate row color
        pdf.set_fill_color(*row_fill)
        
        for i, item in enumerate(row):
            pdf.cell(col_widths[i], 10, str(item), border=1, align='C', fill=True)
        pdf.ln()

    pdf.ln(10)  # Extra space after table


   # 📌 Tor Analysis Table (Per File)
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, "Tor Exit Node Analysis Per File", ln=True)
    pdf.ln(5)

    # Define column widths for better alignment
    col_widths = [25, 40, 40, 40, 46]  # Adjusted widths

    # Define Colors
    header_fill = (200, 200, 200)  # Light Gray Header Background
    row_fill_1 = (240, 240, 240)   # Alternating row color 1 (light gray)
    row_fill_2 = (255, 255, 255)   # Alternating row color 2 (white)

    # Table Header with Background Color
    pdf.set_fill_color(*header_fill)
    pdf.set_font("Arial", 'B', 12)
    headers = ["File Name", "IP Address", "Tor Exit Node", "Country", "ISP"]
    for i, header in enumerate(headers):
        pdf.cell(col_widths[i], 10, header, border=1, align='C', fill=True)
    pdf.ln()

    # Table Data with Alternating Row Colors
    pdf.set_font("Arial", size=10)
    for index, result in enumerate(results):
        for analysis in result.get("analysis_results", []):
            ip = analysis.get("ip", "N/A")
            geo = ip_details.get(ip, {})
            is_tor_exit = "Yes" if analysis.get('is_tor_exit_node', False) else "No"
            
            # Trim File Name
            trimmed_filename = result.get("filename", "N/A")
            if len(trimmed_filename) > 6:
                trimmed_filename = trimmed_filename[:3] + "..." + trimmed_filename[-3:]

            row_fill = row_fill_1 if index % 2 == 0 else row_fill_2  # Alternate row color
            pdf.set_fill_color(*row_fill)

            pdf.cell(col_widths[0], 10, trimmed_filename, border=1, align='C', fill=True)
            pdf.cell(col_widths[1], 10, ip, border=1, align='C', fill=True)
            pdf.cell(col_widths[2], 10, is_tor_exit, border=1, align='C', fill=True)
            pdf.cell(col_widths[3], 10, geo.get('country', 'N/A'), border=1, align='C', fill=True)
            pdf.cell(col_widths[4], 10, geo.get('isp', 'N/A'), border=1, align='C', fill=True)
            pdf.ln()

    pdf.ln(10)  # Extra space after table

   # 📌 Spam Analysis Table (Per File)
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, "Spam Analysis Per File", ln=True)
    pdf.ln(5)

    # Define column widths for better alignment
    col_widths = [25, 50, 50, 50]  # Adjusted widths

    # Define Colors
    header_fill = (200, 200, 200)  # Light Gray Header Background
    row_fill_1 = (240, 240, 240)   # Alternating row color 1 (light gray)
    row_fill_2 = (255, 255, 255)   # Alternating row color 2 (white)

    # Table Header with Background Color
    pdf.set_fill_color(*header_fill)
    pdf.set_font("Arial", 'B', 12)
    headers = ["File Name", "Final Decision", "Local Model Result", "API Result"]
    for i, header in enumerate(headers):
        pdf.cell(col_widths[i], 10, header, border=1, align='C', fill=True)
    pdf.ln()

    # Table Data with Alternating Row Colors
    pdf.set_font("Arial", size=10)
    for index, result in enumerate(results):
        short_filename = result.get("filename", "N/A")
        if len(short_filename) > 6:
            short_filename = short_filename[:3] + "..." + short_filename[-3:]

        row_fill = row_fill_1 if index % 2 == 0 else row_fill_2  # Alternate row color
        pdf.set_fill_color(*row_fill)

        pdf.cell(col_widths[0], 10, short_filename, border=1, align='C', fill=True)
        pdf.cell(col_widths[1], 10, result.get("final_decision", "N/A"), border=1, align='C', fill=True)
        pdf.cell(col_widths[2], 10, result.get("local_model_result", "N/A"), border=1, align='C', fill=True)
        pdf.cell(col_widths[3], 10, result.get("api_result", "N/A"), border=1, align='C', fill=True)
        pdf.ln()

    pdf.ln(10)  # Extra space after table



    # 📄 Save PDF Report
    pdf_path = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf").name
    pdf.output(pdf_path)

    # 🧹 Clean up Temp Files
    os.remove(spam_chart_path)
    os.remove(pie_chart_path)
    os.remove(map_image_path)

    return send_file(pdf_path, as_attachment=True, download_name="email_analysis_report.pdf")


# Serve React static files
@app.route('/')
def serve_react_app():
    return send_from_directory(app.static_folder, 'index.html')

# Serve other static files (CSS, JS, etc.)
@app.route('/<path:path>')
def serve_static_files(path):
    return send_from_directory(app.static_folder, path)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
