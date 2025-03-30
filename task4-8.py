"""
This script retrieves and analyzes code scanning alerts from a GitHub repository. It fetches alerts with high or critical severity, extracts CWE IDs from the alerts, and fetches the likelihood of exploitation for each CWE from the MITRE API. The results are displayed in a formatted table with color-coded likelihood values.
Modules Used:
- `re`: For regular expression matching to extract CWE IDs.
- `requests`: For making HTTP requests to GitHub and MITRE APIs.
- `prettytable`: For creating a formatted table to display the results.
- `colorama`: For adding color to the output.
Security Considerations:
- The GitHub personal access token is used directly in the Authorization header. Ensure the token is not hardcoded or logged accidentally. Use environment variables to store the token securely.
- Sensitive information like tokens should not be exposed in logs or error messages.
Function: get_cwe_likelihood
Fetches the likelihood of exploitation for a given CWE ID from the MITRE API.
Returns "no data" if the API response is invalid or the data is unavailable.
Security Risk: None identified.
Fetches the likelihood of exploitation for a given CWE ID.
    cwe_id (str): The CWE ID to query.
    str: The likelihood of exploitation (e.g., "High", "Medium", "Low") or "no data" if unavailable.
Function: print_report
Formats and prints the analysis report using PrettyTable.
Highlights entries with missing likelihood data in red.
Security Risk: None identified.
Prints the analysis report in a tabular format with color-coded likelihood values.
    report (list): A list of dictionaries containing alert details and CWE likelihoods.
    None
Function: analyze_cwe
Analyzes alerts to extract CWE IDs and fetch their likelihood of exploitation.
Filters alerts with high or critical severity levels.
Security Risk: None identified.
Analyzes code scanning alerts to extract CWE IDs and fetch their likelihood of exploitation.
    alerts (list): A list of alerts retrieved from the GitHub API.
    None
Function: get_code_scanning_alerts
Fetches code scanning alerts from a GitHub repository using the GitHub API.
Filters alerts by severity (high, critical) and passes them to the analyze_cwe function.
Security Risk: The GitHub token is passed in the Authorization header. Ensure it is stored securely and not logged.

"""
import re
import requests
from prettytable import PrettyTable
from colorama import Fore, Style


def get_cwe_likelihood(cwe_id):
    url = f"https://cwe-api.mitre.org/api/v1/cwe/weakness/{cwe_id}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            try:
                return data["Weaknesses"][0]["LikelihoodOfExploit"]
            except Exception:
                return f"no data"
        else:
            return f"no data"
    except requests.RequestException as e:
        return f"Error: {e}"

def print_report(report):
    table = PrettyTable()
    table.field_names = ["Alert ID", "URL", "Severity", "CWE ID", "Likelihood"]

    for entry in report:
        for cwe in entry["cwe_ids"]:
            likelihood = cwe["likelihood"]
            if likelihood == "no data":
                table.add_row(["", "", "", cwe["id"], f"{Fore.RED}{likelihood}{Style.RESET_ALL}"])
            else:
                table.add_row([entry["id"], entry["url"], entry["severity"], cwe["id"], likelihood])
        table.add_divider()

    print(table)
    
def analyze_cwe(alerts):
    report =[]
    for alert in alerts:
        if alert['rule']['security_severity_level'] in ['high', 'critical']:
            tags = alert['rule']['tags']
            report_entry = {
                "id": alert['number'],
                "url": alert['html_url'],
                "severity": alert['rule']['security_severity_level'],
                "cwe_ids": []
            }
            for cwe in tags:
                match = re.search(r'cwe-(\d+)', cwe, re.IGNORECASE)
                if match:
                    cwe = match.group(1)
                    cwe_likelihood = get_cwe_likelihood(cwe)
                    report_entry["cwe_ids"].append({"id": f"CWE-{cwe}", "likelihood": cwe_likelihood})
            report.append(report_entry)
    
    print_report(report)
            
           

def get_code_scanning_alerts(owner, repo, token):
    url = f"https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts"
    
    
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
         "X-GitHub-Api-Version":"2022-11-28"
    }
    params = {"severity": "high,critical"}
    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        alerts = response.json()
        analyze_cwe(alerts)
    else:
        print(f"Error: {response.status_code}, {response.text}")
        return
        
if __name__ == "__main__":
    owner = "dev-roh"
    repo = "NetSkopeAssignment"
    token = input(" GITHUB_TOKEN: \n") 
    if not token:
        print("Please set the GITHUB_TOKEN environment variable.")
        exit(1)

    get_code_scanning_alerts(owner, repo, token)