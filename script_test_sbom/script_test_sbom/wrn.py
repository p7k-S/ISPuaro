import requests
import json

def fetch_nvd_vulnerabilities(product, version):
    url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    params = {"keyword": f"{product} {version}", "resultsPerPage": 10}
    response = requests.get(url, params=params)
    return response.json() if response.status_code == 200 else None

def fetch_debian_vulnerabilities(product):
    url = f"https://security-tracker.debian.org/tracker/data/json"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        return data.get(product, {})
    return None

def fetch_cve_mitre(product):
    url = f"https://cveawg.mitre.org/api/cve/{product}"
    response = requests.get(url)
    return response.json() if response.status_code == 200 else None

def save_results(filename, data):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

def main():
    product = "GCC"
    version = "4.1.2"
    
    nvd_data = fetch_nvd_vulnerabilities(product, version)
    if nvd_data:
        save_results("nvd_results.json", nvd_data)
    
    debian_data = fetch_debian_vulnerabilities("gcc")
    if debian_data:
        save_results("debian_results.json", debian_data)
    
    mitre_data = fetch_cve_mitre("gcc")
    if mitre_data:
        save_results("mitre_results.json", mitre_data)

if __name__ == "__main__":
    main()

