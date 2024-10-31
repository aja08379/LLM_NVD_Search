import requests
import openai
import os
import sys
from dotenv import load_dotenv
from datetime import datetime
from dateutil import parser

# Load environment variables from .env file
load_dotenv()

# Set up your OpenAI API key from environment variables or enter it directly here
openai.api_key = os.getenv("OPENAI_API_KEY")

# NVD API base URL
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

from datetime import datetime

class CVESearchSession:
    def __init__(self, main_term, severity=None, start_date=None, end_date=None, exact_match=False):
        self.main_term = main_term
        self.severity = severity
        self.start_date = start_date
        self.end_date = end_date
        self.exact_match = exact_match
        self.extra_details_requested = False
        self.current_results = []

    def perform_search(self):
        self.current_results = search_nvd_cves(self.main_term, self.severity, self.exact_match, self.start_date, self.end_date)

    def filter_results(self, severity=None, start_date=None, end_date=None):
        def parse_date_from_details(details):
            try:
                published_date_str = details.split("**Published Date:**")[1].split("\n")[0].strip()
                return datetime.strptime(published_date_str, "%Y-%m-%dT%H:%M:%S.%f")
            except (IndexError, ValueError):
                return None

        filtered_results = []
        for cve_id, details in self.current_results:
            published_date = parse_date_from_details(details)

            # Filter by severity if specified
            if severity and severity.lower() not in details.lower():
                continue

            # Filter by date range if start or end dates are specified
            if start_date and (not published_date or published_date < start_date):
                continue
            if end_date and (not published_date or published_date > end_date):
                continue

            filtered_results.append((cve_id, details))

        self.current_results = filtered_results

    def process_follow_up_question(self, follow_up_question):
        _, severity, start_date_str, end_date_str, _ = extract_main_term_severity_and_dates(follow_up_question)

        # Parse date strings if present
        start_date, end_date = None, None
        if start_date_str:
            start_date = parser.parse(start_date_str)
        if end_date_str:
            end_date = parser.parse(end_date_str)

        # Filter current results with new criteria from the follow-up
        self.filter_results(severity, start_date, end_date)

# Main function remains as before, utilizing the updated class methods.


def get_cve_info(cve_id):
    token = os.getenv("CVEDETAILS_API_KEY")
    if not token:
        print("Error: CVEDETAILS_API_KEY not found in .env file")
        return None

    url = f"https://www.cvedetails.com/api/v1/vulnerability/info?cveId={cve_id}&returnAffectedCPEs=false&returnRiskScore=false"
    headers = {
        'accept': 'application/json',
        'Authorization': f'Bearer {token}'
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: Received status code {response.status_code} for CVE ID {cve_id}")
        return None


def format_cve_details(cve_item, cve_info=None):
    cve_id = cve_item.get("cve", {}).get("id", "N/A")
    source_identifier = cve_item.get("cve", {}).get("sourceIdentifier", "N/A")
    published = cve_item.get("cve", {}).get("published", "N/A")
    last_modified = cve_item.get("cve", {}).get("lastModified", "N/A")
    vuln_status = cve_item.get("cve", {}).get("vulnStatus", "N/A")

    descriptions = cve_item.get("cve", {}).get("descriptions", [])
    description_texts = "\n".join([f"{desc.get('lang', 'en')}: {desc.get('value', 'No description')}" for desc in descriptions])

    cvss_v31_data = cve_item.get("cve", {}).get("metrics", {}).get("cvssMetricV31", [])
    if cvss_v31_data:
        cvss_v31_info = cvss_v31_data[0].get("cvssData", {})
        cvss_v31 = f"""
        CVSS v3.1 Metrics:
        - Attack Vector: {cvss_v31_info.get('attackVector', 'N/A')}
        - Attack Complexity: {cvss_v31_info.get('attackComplexity', 'N/A')}
        - Privileges Required: {cvss_v31_info.get('privilegesRequired', 'N/A')}
        - User Interaction: {cvss_v31_info.get('userInteraction', 'N/A')}
        - Scope: {cvss_v31_info.get('scope', 'N/A')}
        - Confidentiality Impact: {cvss_v31_info.get('confidentialityImpact', 'N/A')}
        - Integrity Impact: {cvss_v31_info.get('integrityImpact', 'N/A')}
        - Availability Impact: {cvss_v31_info.get('availabilityImpact', 'N/A')}
        - Base Score: {cvss_v31_info.get('baseScore', 'N/A')}
        - Base Severity: {cvss_v31_info.get('baseSeverity', 'N/A')}
        - Vector String: {cvss_v31_info.get('vectorString', 'N/A')}
        - Version: {cvss_v31_info.get('version', 'N/A')}
        """
    else:
        cvss_v31 = "No CVSS v3.1 data available."

    if cve_info:
        additional_info = "\n".join(
            [
                f"{key.replace('is', '').replace('Exploit', 'Exploit:').replace('Exists', 'Exists:').replace('Score', 'Score:').title()}: "
                f"{'YES' if value == 1 else 'NO' if value == 0 else value}"
                for key, value in cve_info.items()
                if key.startswith("is") or key in ["exploitExists", "epssScore", "epssPercentile"]
            ]
        )
    else:
        additional_info = "No additional cvedetails.com data available."

    formatted_details = f"""
    **CVE ID:** {cve_id}
    **Source Identifier:** {source_identifier}
    **Published Date:** {published}
    **Last Modified:** {last_modified}
    **Vulnerability Status:** {vuln_status}
    **Descriptions:**
    {description_texts}
    {cvss_v31}
    **Additional Details from cvedetails.com:**
    {additional_info}
    """

    return formatted_details.strip()


def extract_main_term_severity_and_dates(question):
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": (
                    "Extract the product name only, the severity level, any start and end dates, "
                    "and whether extra details are requested. The product name should be clean and "
                    "contain only the brand or product name, with no extra descriptive phrases."
                )},
                {"role": "user", "content": (
                    f"Identify the main product or brand name (e.g., 'Apache ActiveMQ Artemis'), severity level "
                    f"(LOW, MEDIUM, HIGH, or CRITICAL), any date range, and if extra details are requested. "
                    f"Return the response strictly as: 'Product Name, Severity, Start Date, End Date, Extra Details' "
                    f"with each item separated by commas. For 'Extra Details,' respond 'Yes' if requested or 'No' if not."
                    f"\n\n'{question}'"
                )}
            ],
            max_tokens=100,
            temperature=0.2
        )
        extracted_text = response['choices'][0]['message']['content'].strip()
        parts = extracted_text.split(",")
        main_term = parts[0].strip() if len(parts) > 0 else None
        severity = parts[1].strip().upper() if len(parts) > 1 and parts[1].strip().upper() in ["LOW", "MEDIUM", "HIGH", "CRITICAL"] else None
        start_date_str = parts[2].strip() if len(parts) > 2 and parts[2].strip() not in ["None", "Not specified"] else None
        end_date_str = parts[3].strip() if len(parts) > 3 and parts[3].strip() not in ["None", "Not specified"] else None
        extra_details_requested = parts[4].strip().lower() == "yes" if len(parts) > 4 else False

        return main_term, severity, start_date_str, end_date_str, extra_details_requested

    except openai.OpenAIError as e:
        print(f"Error with OpenAI API: {e}")
        return None, None, None, None, False

def validate_and_format_dates(start_date_str, end_date_str):
    """
    Validates and formats the start and end dates in ISO-8601 format.
    Ensures the start date is before or equal to the end date and swaps them if necessary.
    """
    if not start_date_str or not end_date_str:
        return None, None
    
    try:
        start_date = parser.parse(start_date_str)
        end_date = parser.parse(end_date_str)
        
        # Ensure start date is not after end date
        if start_date > end_date:
            start_date, end_date = end_date, start_date

        # Convert dates to ISO-8601 format
        start_date_iso = start_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        end_date_iso = end_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]

        return start_date_iso, end_date_iso
    
    except ValueError as e:
        print(f"Invalid date format: {e}")
        return None, None

def search_nvd_cves(keyword, severity=None, exact_match=False, start_date=None, end_date=None):
    url = f"{NVD_API_URL}?keywordSearch={requests.utils.quote(keyword)}"
    if exact_match:
        url += "&keywordExactMatch"
    url += "&resultsPerPage=5"
    if severity:
        url += f"&cvssV3Severity={severity}"

    if start_date and end_date:
        start_date_iso, end_date_iso = validate_and_format_dates(start_date, end_date)
        url += f"&pubStartDate={start_date_iso}&pubEndDate={end_date_iso}"

    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        cve_items = data.get("vulnerabilities", [])
        return [(item["cve"]["id"], format_cve_details(item)) for item in cve_items] if cve_items else []
    except requests.RequestException as e:
        print(f"Error fetching data from NVD: {e}")
        return []


def main():
    if len(sys.argv) < 2:
        print("Usage: python search_cve_openai.py <question>")
        sys.exit(1)

    question = " ".join(sys.argv[1:])
    main_term, severity, start_date, end_date, extra_details_requested = extract_main_term_severity_and_dates(question)
    exact_match = any(term in question.lower() for term in ["exact match", "only this product"])

    session = CVESearchSession(main_term, severity, start_date, end_date, exact_match)
    session.perform_search()

    if session.current_results:
        print("\nInitial CVE Results:\n")
        print("\n\n".join(detail for _, detail in session.current_results))
    else:
        print(f"No results found for '{main_term}' with the specified filters.")
    
    while True:
        follow_up_question = input("Enter follow-up question or 'exit' to quit: ")
        if follow_up_question.lower() == 'exit':
            break
        session.process_follow_up_question(follow_up_question)

        if session.current_results:
            print("\nRefined CVE Results:\n")
            print("\n\n".join(detail for _, detail in session.current_results))
        else:
            print("No results found for the refined filters.")

if __name__ == "__main__":
    main()
