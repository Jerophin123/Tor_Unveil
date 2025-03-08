# Tor_Unveil

## Overview
Tor_Unveil is an advanced email analysis tool designed to detect anonymous senders, spam, and potential security threats. It integrates multiple security and intelligence services to analyze email headers, check for Tor exit nodes, verify against abuse databases, and detect phishing or spam content using AI-based models.

## Features
- **Email Header Analysis**: Extracts sender IPs, domains, and detects hidden Tor-based services.
- **Tor Exit Node Detection**: Checks if an IP belongs to the Tor network.
- **Spam & Phishing Detection**: Uses both a trained machine learning model and external APIs.
- **Geolocation Mapping**: Fetches IP geolocation and visualizes suspicious email sources.
- **Blacklist Checks**: Verifies IPs against AbuseIPDB and Spamhaus.
- **PDF Report Generation**: Summarizes findings with visual charts and data tables.
- **Secure API Key Management**: Utilizes environment variables to protect sensitive credentials.

## Installation
### Prerequisites
- Python 3.8+
- Flask
- pip
- Node.js (for frontend, optional)
- Git
- Tor Proxy (for exit node detection)

### Setup
1. **Clone the repository**
   ```sh
   git clone https://github.com/yourusername/Tor_Unveil.git
   cd Tor_Unveil
   ```
2. **Create a virtual environment** (optional but recommended)
   ```sh
   python -m venv venv
   source venv/bin/activate  # On Windows use: venv\Scripts\activate
   ```
3. **Install dependencies**
   ```sh
   pip install -r requirements.txt
   ```
4. **Set up environment variables**
   Create a `.env` file in the root directory and add:
   ```
   APILAYER_API_KEY=your_apilayer_api_key_here
   ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
   TOR_PROXY_HTTP=socks5h://127.0.0.1:9050
   TOR_PROXY_HTTPS=socks5h://127.0.0.1:9050
   ```

## Usage
### Running the Backend Server
```sh
python backend.py
```
The API will be accessible at `http://127.0.0.1:5000/`

### Analyzing Emails
- Use the `/analyze_combined` endpoint to upload emails for analysis.
- Use `/generate_report` to create a PDF report of analyzed emails.

### Running the Frontend (Optional)
If you have a React frontend:
```sh
cd frontend
npm install
npm start
```
This will start the frontend at `http://localhost:3000/`.

## API Endpoints
### 1. **Analyze Email Headers**
   - **Endpoint:** `POST /analyze_combined`
   - **Description:** Uploads email files for analysis.
   - **Response:** JSON with IP analysis, spam detection, and Tor exit node checks.

### 2. **Generate Report**
   - **Endpoint:** `POST /generate_report`
   - **Description:** Generates a PDF report based on analyzed emails.
   - **Response:** PDF file download.

### 3. **Get IP Information**
   - **Endpoint:** `GET /get_ip_info?ip=IP_ADDRESS`
   - **Description:** Fetches geolocation and security data for an IP address.
   - **Response:** JSON with location and ISP details.

## Security Considerations
- Ensure that API keys are stored securely in a `.env` file.
- Always sanitize and validate user-uploaded email files to prevent script injection.
- Use HTTPS in production to secure API communication.

## Contributions
Feel free to contribute by submitting issues or pull requests!

## License
This project is licensed under the MIT License.

## Contact
For questions or support, reach out via GitHub Issues.

