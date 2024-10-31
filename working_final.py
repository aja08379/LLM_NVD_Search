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

def get_cve_info(cve_id):
    """
    Retrieves additional CVE details from cvedetails.com based on the CVE ID.
    """
    token = os.getenv("CVEDETAILS_API_KEY")
    if not token:
        print("Error: CVEDETAILS_API_KEY not found in .env file")
        return None

    url = f"https://www.cvedetails.com/api/v1/vulnerability/info?cveId={cve_id}&returnAffectedCPEs=false&returnRiskScore=false"
    headers = {
        'accept': 'application/json',
        'Authorization': f'Bearer {token}'
    }

    print(f"Debug: Constructed cvedetails.com URL for CVE {cve_id}: {url}")

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        print(f"Debug: Successful response from cvedetails.com for CVE ID {cve_id}")
        print("Debug: cvedetails.com response JSON:", response.json())  # Add this line to print full JSON response
        return response.json()
    else:
        print(f"Error: Received status code {response.status_code} for CVE ID {cve_id}")
        print(f"Debug: Response content: {response.text}")
        return None

def format_cve_details(cve_item, cve_info=None):
    """
    Formats CVE details from the NVD response, including detailed CVSS v3.1 metrics, descriptions, 
    and additional data from cvedetails.com.
    """
    cve_id = cve_item.get("cve", {}).get("id", "N/A")
    source_identifier = cve_item.get("cve", {}).get("sourceIdentifier", "N/A")
    published = cve_item.get("cve", {}).get("published", "N/A")
    last_modified = cve_item.get("cve", {}).get("lastModified", "N/A")
    vuln_status = cve_item.get("cve", {}).get("vulnStatus", "N/A")

    # Extract descriptions
    descriptions = cve_item.get("cve", {}).get("descriptions", [])
    description_texts = "\n".join([f"{desc.get('lang', 'en')}: {desc.get('value', 'No description')}" for desc in descriptions])

    # CVSS v3.1 metrics
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

    # Process cvedetails.com data, transforming 0/1 values to YES/NO
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

    # Combine all details into a formatted string
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
    """
    Extracts main term, severity, dates, and whether extra details are requested from the question.
    Ensures main term includes only the product or brand name without additional phrases.
    """
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

        # Parse the response
        parts = extracted_text.split(",")
        main_term = parts[0].strip() if len(parts) > 0 else None
        severity = parts[1].strip().upper() if len(parts) > 1 and parts[1].strip().upper() in ["LOW", "MEDIUM", "HIGH", "CRITICAL"] else None
        start_date_str = parts[2].strip() if len(parts) > 2 and parts[2].strip() not in ["None", "Not specified"] else None
        end_date_str = parts[3].strip() if len(parts) > 3 and parts[3].strip() not in ["None", "Not specified"] else None
        extra_details_requested = parts[4].strip().lower() == "yes" if len(parts) > 4 else False

        # Debug output to verify extracted values
        print(f"Debug: Extracted main term: {main_term}")
        print(f"Debug: Severity level: {severity if severity else 'None specified'}")
        print(f"Debug: Start date: {start_date_str if start_date_str else 'None specified'}")
        print(f"Debug: End date: {end_date_str if end_date_str else 'None specified'}")
        print(f"Debug: Extra details requested: {'Yes' if extra_details_requested else 'No'}")

        return main_term, severity, start_date_str, end_date_str, extra_details_requested

    except openai.OpenAIError as e:
        print(f"Error with OpenAI API: {e}")
        return None, None, None, None, False

def validate_and_format_dates(start_date_str, end_date_str):
    if not start_date_str or not end_date_str:
        return None, None
    try:
        start_date = parser.parse(start_date_str)
        end_date = parser.parse(end_date_str)
        if start_date > end_date:
            start_date, end_date = end_date, start_date
        date_range = (end_date - start_date).days
        if date_range > 120:
            print("Date range cannot exceed 120 days.")
            sys.exit(1)
        return start_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3], end_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
    except ValueError as e:
        print(f"Invalid date format: {e}.")
        sys.exit(1)

def search_nvd_cves(keyword, severity=None, exact_match=False, start_date=None, end_date=None):
    """
    Searches the NVD database for CVEs based on a single main keyword.
    Optionally filters results based on severity level, date range, and exact match.
    """
    # Construct URL with only the extracted main term as the keywordSearch parameter
    url = f"{NVD_API_URL}?keywordSearch={requests.utils.quote(keyword)}"

    if exact_match:
        url += "&keywordExactMatch"

    url += "&resultsPerPage=5"
    if severity:
        url += f"&cvssV3Severity={severity}"

    # Add date parameters if they are specified and valid
    if start_date and end_date:
        start_date_iso, end_date_iso = validate_and_format_dates(start_date, end_date)
        url += f"&pubStartDate={start_date_iso}&pubEndDate={end_date_iso}"

    # Debug output for constructed URL
    print(f"Constructed NVD URL: {url}")

    try:
        response = requests.get(url)
        response.raise_for_status()  # Check for HTTP errors
        data = response.json()

        cve_items = data.get("vulnerabilities", [])
        if not cve_items:
            return []

        # Process each CVE item and format details
        return [(item["cve"]["id"], format_cve_details(item)) for item in cve_items]

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
    nvd_results = search_nvd_cves(main_term, severity, exact_match, start_date, end_date)

    if not nvd_results:
        print(f"No results found for '{main_term}' with specified filters.")
        return

    final_output = []
    for cve_id, nvd_info in nvd_results:
        final_output.append(f"NVD Info:\n{nvd_info}")
        
        # Fetch data from cvedetails.com if extra details are requested
        if extra_details_requested:
            cve_info = get_cve_info(cve_id)
            
            # Debug output to verify if cvedetails data is retrieved
            print(f"Debug: Retrieved cvedetails.com data for {cve_id}: {cve_info}")
            
            # Pass data to format_cve_details only if it exists
            if cve_info:
                formatted_cve_info = format_cve_details(cve_item={'cve': {'id': cve_id}}, cve_info=cve_info)
                final_output.append(f"cvedetails.com Info:\n{formatted_cve_info}")
            else:
                final_output.append("Error: Could not retrieve additional details from cvedetails.com")

    # Combine and format final output
    formatted_results = "\n\n".join(final_output)
    print("Enhanced CVE Results:\n")
    print(formatted_results)

if __name__ == "__main__":
    main()
