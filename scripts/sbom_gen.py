import json
import subprocess
from datetime import datetime
from uuid import uuid4
import requests

def run_command(cmd):
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr}"

def generate_gcc_sbom(binaries):
    bom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.4.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "tools": [
                {
                    "vendor": "Custom SBOM Generator",
                    "name": "GCC Component Analyzer",
                    "version": "1.0"
                }
            ],
            "component": {
                "type": "framework",
                "name": "GCC Toolchain",
                "version": "4.1.2",
                "description": "GNU Compiler Collection (Debian 4.1.1-21)",
                "purl": "pkg:deb/debian/gcc@4.1.2",
                "hashes": [
                    {
                        "alg": "SHA-1",
                        "content": run_command("sha1sum " + " ".join([b[0] for b in binaries])).split()[0]
                    }
                ]
            }
        },
        "components": [],
        "dependencies": [],
        "vulnerabilities": []
    }

    for filename, description in binaries:
        print(f"Processing {filename} ({description})...")
        
        commands = [
            f"file {filename}",
            f"{filename} --version",
            f"ldd {filename}",
            # f"readelf -h {filename}",
            f"readelf -d {filename} | grep NEEDED",
            # f"nm -D {filename}",
            # f"objdump -T {filename}",
        ]
        
        commands_output = {}
        for cmd in commands:
            output = run_command(cmd)
            commands_output[cmd] = output

        component = {
            "type": "application",
            "name": filename,
            "description": description,
            "version": "4.1.2",
            "hashes": [
                {
                    "alg": "SHA-1",
                    "content": run_command(f"sha1sum {filename}").split()[0]
                }
            ],
            "properties": []
        }

        for cmd, output in commands_output.items():
            component["properties"].append({"name": cmd, "value": output})

        bom["components"].append(component)

        # Анализ зависимостей (ldd)
        ldd_output = commands_output.get(f"ldd {filename}", "")
        if ldd_output and "Error:" not in ldd_output:
            libraries = []
            for line in ldd_output.splitlines():
                if "=>" in line:
                    lib = line.split("=>")[0].strip()
                    libraries.append(lib)
            if libraries:
                bom["dependencies"].append({
                    "ref": filename,
                    "dependsOn": libraries
                })

    return bom

def main():
    binaries = [
        ("binary1", "cc1"),#100%
        ("binary2", "cpp"),#100%
        ("binary3", "ar"),#100%
        ("binary5", "g++"),#главный драйвер запускает остальные компоненты
        ("binary6", "gcc"),#главный драйвер запускает остальные компоненты
        ("binary7", "gfortran"),#100%
        ("binary8", "libgfortran.so")#100%
    ]

    sbom = generate_gcc_sbom(binaries)
    
    output_file = "gcc_4.1.2_sbom.json"
    with open(output_file, "w") as f:
        json.dump(sbom, f, indent=2)
    
    print(f"Generated single SBOM for GCC 4.1.2 -> {output_file}")

if __name__ == "__main__":
    main()
