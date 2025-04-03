import os
import json
import hashlib
import subprocess
import requests
from datetime import datetime

binary_descriptions = {
    "binary1": "cc1",
    "binary2": "cpp",
    "binary3": "ar",
    "binary5": "g++",
    "binary6": "gcc",
    "binary7": "gfortran",
    "binary8": "libgfortran.so"
}

def run_file_command(file_path):
    try:
        result = subprocess.run(['file', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout
    except Exception as e:
        return str(e)

def parse_file_output(file_output):
    architecture = "Intel 80386"
    strip = "False"
    dynamically_linked = "False"
    
    if "x86-64" in file_output:
        architecture = "x86_64"
    if "dynamically linked" in file_output:
        dynamically_linked = "True"
    if "stripped" in file_output:
        strip = "True"
    
    return architecture, strip, dynamically_linked

def get_file_properties(file_path):
    file_output = run_file_command(file_path)
    architecture, strip, dynamically_linked = parse_file_output(file_output)
    
    return [
        {"name": "file:architecture", "value": architecture},
        {"name": "file:strip", "value": strip},
        {"name": "file:dynamically_linked", "value": dynamically_linked},
    ]

def get_component_type(file_name):
    file_extension = os.path.splitext(file_name)[1].lower()
    if file_extension in [".so", ".a", ".dll"]:
        return "library"
    return "application"

def compute_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def generate_bom_ref(file_path):
    return hashlib.md5(file_path.encode('utf-8')).hexdigest()

def get_description(file_name):
    return binary_descriptions.get(file_name, "unknown")

def run_ldd(file_path):
    try:
        result = subprocess.run(['ldd', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout
    except Exception as e:
        return str(e)

def extract_dependencies(ldd_output):
    dependencies = []
    for line in ldd_output.splitlines():
        if '=>' in line:
            parts = line.split('=>')
            lib = parts[0].strip()
            dependencies.append(lib)
    return dependencies

def fetch_vulnerabilities():
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"virtualMatchString": "cpe:2.3:a:gnu:gcc:4.1.2:*:*:*:*:*:*:*", "resultsPerPage": 50}
    response = requests.get(url, params=params)
    data = response.json()
    vulnerabilities = []
    
    if data.get("totalResults", 0) > 0:
        for vuln in data["vulnerabilities"]:
            cve = vuln["cve"]
            vulnerabilities.append({
                "id": cve["id"],
                "description": cve["descriptions"][0]["value"],
                "published": cve["published"],
                "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}"}
            })
    return vulnerabilities

def process_files_in_directory(directory_path):
    components = []
    for root, dirs, files in os.walk(directory_path):
        files.sort()
        for file_name in files:
            file_path = os.path.join(root, file_name)
            ldd_output = run_ldd(file_path)
            dependencies = extract_dependencies(ldd_output)
            
            component = {
                "bom-ref": generate_bom_ref(file_path),
                "type": get_component_type(get_description(file_name)),
                "name": file_name,
                "version": "4.1.2",
                "description": get_description(file_name),
                "hashes": [{"alg": "SHA-256", "content": compute_sha256(file_path)}],
                "properties": get_file_properties(file_path),
                "dependencies": [{"ref": dep} for dep in dependencies]
            }
            components.append(component)
    
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "tools": [{"vendor": "Custom SBOM Generator", "name": "GCC Component Analyzer", "version": "1.0"}],
            "component": {"type": "framework", "name": "GCC Toolchain", "version": "4.1.2", "description": "GNU Compiler Collection (Debian 4.1.1-21)", "purl": "pkg:deb/debian/gcc@4.1.2"},
            "platform": {"name": "x86_64-linux-gnu", "architecture": "x86_64", "operatingSystem": "Linux"}
        },
        "components": components,
        "vulnerabilities": fetch_vulnerabilities()
    }
    return sbom

def save_sbom_to_file(sbom, output_file):
    with open(output_file, 'w') as f:
        json.dump(sbom, f, indent=2)

if __name__ == "__main__":
    directory_path = "../binaries/"
    sbom = process_files_in_directory(directory_path)
    save_sbom_to_file(sbom, "sbom.json")
    print("SBOM записан в файл sbom.json")

