import os
import subprocess

if not os.path.exists('../info'):
    os.makedirs('../info')

commands = [
    "file {filename}",
    "ldd {filename}",
    "readelf -h {filename}",
    "readelf -d {filename} | grep NEEDED",
    "nm -D {filename}",
    "objdump -T {filename}",
    "strings {filename}"
]

for num in [1, 2, 3, 5, 6, 7, 8]:
    filename = f"../binares/binary{num}"
    
    if not os.path.exists(filename):
        print(f"Файл {filename} не найден")
        continue
    
    print(f"Анализ {filename}")

    with open(f"../info/binary{num}_info.txt", 'w') as out_file:
        out_file.write(f"=== Анализ файла binary{num} ===\n\n")
        
        for cmd in commands:
            cmd = cmd.format(filename=filename)
            out_file.write(f"$ {cmd}\n")
            out_file.write("-"*60 + "\n")
            
            try:
                result = subprocess.run(cmd, shell=True, check=True,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     text=True)
                out_file.write(result.stdout)
                if result.stderr:
                    out_file.write("\n[Ошибки]:\n")
                    out_file.write(result.stderr)
            except subprocess.CalledProcessError as e:
                out_file.write(f"Ошибка (код {e.returncode}):\n")
                out_file.write(e.stdout)
                if e.stderr:
                    out_file.write("\n[Ошибки]:\n")
                    out_file.write(e.stderr)
            
            out_file.write("\n" + "="*60 + "\n\n")
