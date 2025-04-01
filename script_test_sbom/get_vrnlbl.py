import requests
import json
from datetime import datetime

# 1. Поиск уязвимостей в NVD
url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
params = {
    "virtualMatchString": "cpe:2.3:a:gnu:gcc:4.1.2:*:*:*:*:*:*:*",
    "resultsPerPage": 50
}

response = requests.get(url, params=params)
data = response.json()

# 2. Формируем минимальный SBOM
sbom = {
    "vulnerabilities": []
}

# 3. Добавляем найденные уязвимости
if data.get("totalResults", 0) > 0:
    print(f"Найдено {data['totalResults']} уязвимостей")
    for vuln in data["vulnerabilities"]:
        cve = vuln["cve"]
        sbom["vulnerabilities"].append({
            "id": cve["id"],
            "description": cve["descriptions"][0]["value"],
            "published": cve["published"],
            "source": {
                "name": "NVD",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}"
            }
        })
else:
    print("Уязвимостей не найдено")

# 4. Сохраняем результат
with open("vlnrbl-sbom.json", "w") as f:
    json.dump(sbom, f, indent=2)

print("✅ SBOM сохранен в vlnrbl-sbom.json")

