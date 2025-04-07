import os
import subprocess

# Создаем директорию для результатов, если ее нет
if not os.path.exists('../info'):
    os.makedirs('../info')

# Команды для анализа файлов
commands = [
    "file {filename}",
    "ldd {filename}",
    "readelf -h {filename}",
    "readelf -d {filename} | grep NEEDED",
    "nm -D {filename}",
    "objdump -T {filename}",
    "strings {filename}"
]

# Директория с бинарными файлами
binaries_dir = '../binaries/'

# Проверяем существование директории
if not os.path.exists(binaries_dir):
    print(f"Директория {binaries_dir} не найдена")
    exit(1)

# Получаем список файлов в директории
binary_files = [f for f in os.listdir(binaries_dir) if os.path.isfile(os.path.join(binaries_dir, f))]

if not binary_files:
    print(f"В директории {binaries_dir} не найдено файлов для анализа")
    exit(0)

# Анализируем каждый файл
for binary_file in binary_files:
    filename = os.path.join(binaries_dir, binary_file)
    
    print(f"Анализ {filename}")

    # Создаем имя файла для результатов (убираем расширение если есть)
    output_name = os.path.splitext(binary_file)[0]
    output_file = f"../info/{output_name}_info.txt"

    with open(output_file, 'w') as out_file:
        out_file.write(f"=== Анализ файла {binary_file} ===\n\n")
        
        for cmd in commands:
            cmd_formatted = cmd.format(filename=filename)
            out_file.write(f"$ {cmd_formatted}\n")
            out_file.write("-"*60 + "\n")
            
            try:
                result = subprocess.run(cmd_formatted, shell=True, check=True,
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

print("Анализ завершен. Результаты сохранены в ../info/")
