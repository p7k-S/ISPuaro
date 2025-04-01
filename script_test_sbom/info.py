import os
import subprocess
from pathlib import Path

def ensure_info_dir():
    info_dir = Path("info")
    if not info_dir.exists():
        info_dir.mkdir()
    return info_dir

def analyze_file(filepath, info_dir):
    """Выполняет анализ файла и сохраняет результаты в папку info"""
    filename = Path(filepath).name
    output_file = info_dir / f"{filename}_analysis.txt"
    
    commands = [
        f"file {filename}",
        f"{filename} --version",
        f"ldd {filename}",
        f"readelf -h {filename}",
        f"readelf -d {filename} | grep NEEDED",
        f"nm -D {filename}",
        f"objdump -T {filename}",
        f"strings {filename}"
    ]
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"Analysis of file: {filename}\n")
        f.write("=" * 50 + "\n\n")
        
        for cmd in commands:
            try:
                f.write(f"Command: {cmd}\n")
                f.write("-" * 50 + "\n")
                
                if cmd.endswith("--version"):
                    result = subprocess.run([f"./{filename}", "--version"], 
                                         capture_output=True, text=True)
                else:
                    result = subprocess.run(cmd, shell=True, 
                                         capture_output=True, text=True)
                
                if result.stdout:
                    f.write(result.stdout)
                if result.stderr:
                    f.write("Error:\n")
                    f.write(result.stderr)
                
                f.write("\n" + "=" * 50 + "\n\n")
            except Exception as e:
                f.write(f"Failed to execute command: {cmd}\n")
                f.write(f"Error: {str(e)}\n")
                f.write("=" * 50 + "\n\n")

def main():
    info_dir = ensure_info_dir()
    
    files = [f for f in os.listdir('.') if os.path.isfile(f)]
    
    script_name = os.path.basename(__file__)
    if script_name in files:
        files.remove(script_name)
    
    for file in files:
        try:
            print(f"Analyzing file: {file}")
            analyze_file(file, info_dir)
            print(f"Analysis saved to: info/{file}_analysis.txt")
        except Exception as e:
            print(f"Failed to analyze file {file}: {str(e)}")

if __name__ == "__main__":
    main()



# syft . -o cyclonedx-json > sbom.json
# jq . sbom.json > sbom_formatted.json
# trivy fs --scanners vuln . -- 0 ??

