import requests
import json
import datetime

def fetch_cve_data(product, version):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": f"{product} {version}",
        "resultsPerPage": 10
    }
    
    response = requests.get(base_url, params=params)
    if response.status_code == 200:
        return response.json().get("vulnerabilities", [])
    else:
        print("Ошибка запроса API", response.status_code)
        return []

def generate_sbom(cve_list, product, version):
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{datetime.datetime.now().isoformat()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now().isoformat(),
            "component": {
                "type": "application",
                "name": product,
                "version": version,
                "licenses": ["Unknown"],
                "properties": []
            }
        },
        "vulnerabilities": []
    }
    
    for cve in cve_list:
        cve_data = {
            "id": cve["cve"]["id"],
            "source": "NVD",
            "description": cve["cve"].get("descriptions", [{}])[0].get("value", "No description"),
            "severity": cve.get("cve", {}).get("metrics", {}).get("cvssMetricV2", [{}])[0].get("baseSeverity", "Unknown")
        }
        sbom["vulnerabilities"].append(cve_data)
    
    return sbom

if __name__ == "__main__":
    product = "GCC"
    version = "4.1.2"
    cve_list = fetch_cve_data(product, version)
    sbom_data = generate_sbom(cve_list, product, version)
    
    with open("sbom_vrnlbl.json", "w", encoding="utf-8") as f:
        json.dump(sbom_data, f, indent=4, ensure_ascii=False)
    
    print("SBOM сохранен в sbom_vrnlbl.json")

