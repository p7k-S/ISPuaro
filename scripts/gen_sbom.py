import re
import os
import json
import hashlib
import subprocess
import requests
import argparse
from datetime import datetime
from urllib.parse import quote

#=============================================================================#
# В словарь можно добавить свое описание компонента которое пойдет в sbom.json#
#=============================================================================#
binary_descriptions = {
    # "binary1": "cc1",
    # "binary2": "cpp",
    # "binary3": "jar",
    # "binary5": "g++",
    # "binary6": "gcc",
    # "binary7": "gfortran",
    # "binary8": "libgfortran.so"
}

SYSTEM_LIB_DIRS = ["/lib", "/usr/lib", "/lib64", "/usr/lib64"]  # Системные директории для поиска библиотек

def run_file_command(file_path):
    try:
        result = subprocess.run(['file', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout
    except Exception as e:
        return str(e)

def parse_file_output(file_output):
    architecture = "Intel 80386"
    strip = "True"
    dynamically_linked = "False"
    
    if "x86-64" in file_output:
        architecture = "x86_64"
    if "dynamically linked" in file_output:
        dynamically_linked = "True"
    if "not stripped" in file_output:
        strip = "False"
    
    return architecture, strip, dynamically_linked

def get_file_properties(file_path):
    file_output = run_file_command(file_path)
    architecture, strip, dynamically_linked = parse_file_output(file_output)
    
    return [
        {"name": "file:architecture", "value": architecture},
        {"name": "file:strip", "value": strip},
        {"name": "file:dynamically_linked", "value": dynamically_linked},
    ]

def get_component_type(file_path):
    filename = os.path.basename(file_path)

    if filename in binary_descriptions:
        lower_name = binary_descriptions[filename]
    else:
        lower_name = filename.lower()
    
    is_library = (
        lower_name.endswith(('.a', '.dll')) or
        lower_name.endswith('.so') or
        ('.so.' in lower_name and lower_name.split('.so.')[-1].isdigit())
    )
    
    if is_library:
        return 'library'
    elif os.access(file_path, os.X_OK):
        return 'application'
    return 'unknown'

def get_version(file_path):
    filename = os.path.basename(file_path)
    if os.access(file_path, os.X_OK):
        try:
            result = subprocess.run([file_path, '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)
            output = result.stdout.strip() or result.stderr.strip()
            first_line = output.splitlines()[0] if output else "unknown"
            versions = first_line
        except Exception as e:
            versions = f"error: {str(e)}"
    else:
        versions = "not executable"

    return versions

def get_gcc_version(directory_path):
    files = sorted(os.listdir(directory_path))
    first_file = os.path.join(directory_path, files[0])
    return get_version(first_file)

def compute_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def generate_bom_ref(file_path):
    return hashlib.md5(file_path.encode('utf-8')).hexdigest()

def get_description(file_name):
    return binary_descriptions.get(file_name, "")

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
            # Если библиотека указана без полного пути, пытаемся найти ее в системных путях
            if not os.path.isabs(lib):
                found = False
                for dir in SYSTEM_LIB_DIRS:
                    lib_path = os.path.join(dir, lib)
                    if os.path.exists(lib_path):
                        dependencies.append(lib_path)
                        found = True
                        break
                if not found:
                    dependencies.append(lib)  # Оставляем зависимость как есть, если не нашли
            else:
                dependencies.append(lib)
    return dependencies

def fetch_vulnerabilities(directory_path, api_key):
    vulnerabilities = []
    
    for file_name in os.listdir(directory_path):
        file_path = os.path.join(directory_path, file_name)
        version_output = get_version(file_path)
        
        if version_output == "not executable":
            continue
            
        words = version_output.split()
        version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', version_output)
        version = version_match.group(0) if version_match else ""
        search_terms = []
        
        if len(words) >= 1:
            first_word = words[0].lower()
            
            if version:
                search_terms.append(f"{first_word} {version}")
                
            search_terms.append(first_word)
        
        unique_terms = set(term for term in search_terms if term.strip())                

        for term in unique_terms:
            print(f"search CVE for: '{term}'")
            try:
                if api_key == "":
                    response = requests.get(
                        "https://services.nvd.nist.gov/rest/json/cves/2.0",
                        params={"keywordSearch": quote(term), "resultsPerPage": 10},
                        timeout=5
                    )
                else:
                    response = requests.get(
                        "https://services.nvd.nist.gov/rest/json/cves/2.0",
                        params={"keywordSearch": quote(term), "resultsPerPage": 10},
                        headers={
                            "apiKey": api_key
                            },
                        timeout=5
                    )
                    
                data = response.json()
                
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln["cve"]
                    description = cve["descriptions"][0]["value"].lower()
                    
                    if term.lower() in description:
                        vuln_entry = {
                            "id": cve["id"],
                            "description": description,
                            "published": cve["published"],
                            "source": {
                                "name": "NVD",
                                "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}"
                            },
                            "affects": [{
                                "ref": generate_bom_ref(file_path),
                                "file": os.path.basename(file_path),
                                "search_term": term,
                                "full_version": version_output,
                                "detected_version": version
                            }]
                        }
                        if vuln_entry not in vulnerabilities:
                            vulnerabilities.append(vuln_entry)
                            
            except Exception as e:
                print(f"Ошибка для '{term}': {str(e)}")
                continue

    print(f"Всего найдено CVE по ключевым словам: {len(vulnerabilities)}")
    # url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    # params = {"virtualMatchString": "cpe:2.3:a:gnu:gcc:4.1.2:*:*:*:*:*:*:*", "resultsPerPage": 50}
    # response = requests.get(url, params=params)
    # data = response.json()
    # vulnerabilities = []
    #
    # if data.get("totalResults", 0) > 0:
    #     for vuln in data["vulnerabilities"]:
    #         cve = vuln["cve"]
    #         vulnerabilities.append({
    #             "id": cve["id"],
    #             "description": cve["descriptions"][0]["value"],
    #             "published": cve["published"],
    #             "source": {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}"}
    #             })
    #
    # print(f"Всего найдено CVE: {len(vulnerabilities)}")

    return vulnerabilities

def process_file(file_path, visited_files):
    if os.path.realpath(file_path) in visited_files:
        return []

    visited_files.add(os.path.realpath(file_path))
    
    libs_deps = extract_dependencies(run_ldd(file_path))

    dependencies = []

    for dep in libs_deps:
        dependencies.append({
            "ref": generate_bom_ref(dep.strip()),
            "origin": "ldd",
            "name": dep.strip()
        })
    
    component = {
        "bom-ref": generate_bom_ref(file_path),
        "type": get_component_type(file_path),
        "name": os.path.basename(file_path),
        "version": get_version(file_path),
        "description": get_description(os.path.basename(file_path)),  # Получаем описание из binary_descriptions если есть
        "hashes": [{"alg": "SHA-256", "content": compute_sha256(file_path)}],
        "properties": get_file_properties(file_path),
        # "dependencies": [{"ref": generate_bom_ref(dep.strip()), "name": dep.strip()} for dep in dependencies]
        "dependencies": dependencies,
    }

    components = [component]

    # Рекурсивно анализируем зависимости
    for dep in libs_deps:
        dep_file_path = dep.strip()
        if os.path.exists(dep_file_path):
            components.extend(process_file(dep_file_path, visited_files))
    
    return components

def generate_components(directory_path):
    components = []
    visited_files = set()

    for file_name in sorted(os.listdir(directory_path)):
        file_path = os.path.join(directory_path, file_name)
        if os.path.isfile(file_path) and file_path not in visited_files:
            components.extend(process_file(file_path, visited_files))

    return components

def build_sbom_from_directory(directory_path, api_key):
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "tools": [{"vendor": "Custom SBOM Generator", "name": "GCC Component Analyzer", "version": "1.0"}],
            "component": {
                "type": "framework",
                "name": "GCC Toolchain",
                "version": get_gcc_version(directory_path),
                "description": "GNU Compiler Collection",
                "purl": "pkg:deb/debian/gcc@4.1.2"
            },
            "platform": {
                "name": "x86_64-linux-gnu",
                "architecture": "x86_64",
                "operatingSystem": "Linux"
            }
        },
        "components": generate_components(directory_path),
        "vulnerabilities": fetch_vulnerabilities(directory_path, api_key)
    }
    return sbom

def save_sbom_to_file(sbom, output_file):
    with open(output_file, 'w') as f:
        json.dump(sbom, f, indent=2)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-key", default="", help="NVD API ключ")
    parser.add_argument("--dir", default="../binaries/", help="Директория с бинарными файлами")
    parser.add_argument("--output", default="sbom.json", help="Выходной файл для SBOM")
    args = parser.parse_args()

    sbom = build_sbom_from_directory(args.dir, args.api_key)
    save_sbom_to_file(sbom, args.output)
    print(f"SBOM записан в файл {args.output}")

if __name__ == "__main__":
    main()
