import os
import subprocess
from pathlib import Path

def analyze_file(filepath):
    """Выполняет анализ файла и сохраняет результаты в отдельный файл"""
    filename = Path(filepath).name
    output_file = f"{filename}_analysis.txt"
    
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
                
                # Для команды --version, которая может быть частью исполняемого файла
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
    files = [f for f in os.listdir('.') if os.path.isfile(f)]
    
    script_name = os.path.basename(__file__)
    if script_name in files:
        files.remove(script_name)
    
    for file in files:
        try:
            print(f"Analyzing file: {file}")
            analyze_file(file)
            print(f"Analysis completed for {file}. Results saved to {file}_analysis.txt")
        except Exception as e:
            print(f"Failed to analyze file {file}: {str(e)}")

if __name__ == "__main__":
    main()
