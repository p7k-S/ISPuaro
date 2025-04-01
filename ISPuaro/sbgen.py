import json
import subprocess
from datetime import datetime

def get_file_info(filename):
    # Используем утилиту file для определения типа файла
    result = subprocess.run(['file', filename], capture_output=True, text=True)
    file_type = result.stdout.strip()
    
    # Извлекаем строки из бинарного файла
    strings_result = subprocess.run(['strings', filename], capture_output=True, text=True)
    strings_output = strings_result.stdout
    
    # Ищем версию GCC в строках
    gcc_version = "unknown"
    for line in strings_output.split('\n'):
        if "GCC: (GNU)" in line:
            gcc_version = line.split()[-1]
    
    return {
        "filename": filename,
        "type": file_type,
        "gcc_version": gcc_version,
        "strings": strings_output.split('\n')[:20]  # первые 20 строк для примера
    }

def generate_sbom(files):
    components = []
    
    for file in files:
        info = get_file_info(file)
        
        component = {
            "type": "library",
            "name": info['filename'],
            "version": info['gcc_version'],
            "description": f"Binary component from GCC {info['gcc_version']}",
            "hashes": [
                {
                    "alg": "SHA-1",
                    "content": subprocess.run(['sha1sum', file], capture_output=True, text=True).stdout.split()[0]
                }
            ],
            "properties": [
                {
                    "name": "file_type",
                    "value": info['type']
                }
            ]
        }
        components.append(component)
    
    sbom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "tools": [
                {
                    "vendor": "Custom",
                    "name": "SBOM Generator",
                    "version": "1.0"
                }
            ]
        },
        "components": components
    }
    
    return sbom

# Пример использования
if __name__ == "__main__":
    import sys
    files = sys.argv[1:]
    sbom = generate_sbom(files)
    with open('sbom.json', 'w') as f:
        json.dump(sbom, f, indent=2)
    print("SBOM generated as sbom.json")
