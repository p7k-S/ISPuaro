import subprocess
import re
import os

def get_ldd_dependencies(binary_path):
    """Получает зависимости бинарника с помощью ldd."""
    try:
        output = subprocess.check_output(["ldd", binary_path], stderr=subprocess.DEVNULL, text=True)
        dependencies = re.findall(r"\s(\/[^\s]+)\s", output)
        return dependencies
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []

def get_objdump_dependencies(binary_path):
    """Получает зависимости бинарника через objdump."""
    try:
        output = subprocess.check_output(["objdump", "-p", binary_path], stderr=subprocess.DEVNULL, text=True)
        dependencies = re.findall(r"NEEDED\s+(\S+)", output)
        return dependencies
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []

def find_library_paths(libraries):
    """Пытаемся найти полный путь библиотек."""
    paths = []
    for lib in libraries:
        try:
            result = subprocess.run(["ldconfig", "-p"], capture_output=True, text=True)
            matches = re.findall(rf"(\S+/{lib}\.\S+)\s", result.stdout)
            if matches:
                paths.extend(matches)
            else:
                # Попробуем найти через which/whereis
                try:
                    path = subprocess.check_output(["which", lib], stderr=subprocess.DEVNULL, text=True).strip()
                    if path:
                        paths.append(path)
                except subprocess.CalledProcessError:
                    pass
        except FileNotFoundError:
            pass
    return paths

def get_recursive_dependencies(binary_path, seen=None):
    """Рекурсивно получает все зависимости бинарника."""
    if seen is None:
        seen = set()
    
    # Нормализуем путь, чтобы избежать дубликатов
    binary_path = os.path.realpath(binary_path)
    
    if binary_path in seen:
        return []
    
    seen.add(binary_path)
    
    ldd_deps = get_ldd_dependencies(binary_path)
    objdump_deps = get_objdump_dependencies(binary_path)
    full_paths = find_library_paths(objdump_deps)
    all_deps = set(ldd_deps + full_paths)
    
    for dep in list(all_deps):
        if os.path.exists(dep):  # Проверяем, что файл существует
            all_deps.update(get_recursive_dependencies(dep, seen))
        else:
            print(f"Предупреждение: файл зависимости {dep} не найден")
    
    return list(all_deps)

def analyze_directory(directory):
    """Анализирует все файлы в указанной директории."""
    if not os.path.exists(directory):
        print(f"Директория {directory} не найдена")
        return
    
    binaries = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
    
    if not binaries:
        print(f"В директории {directory} не найдено файлов для анализа")
        return
    
    for binary in binaries:
        binary_path = os.path.join(directory, binary)
        print(f"\nАнализ зависимостей для: {binary_path}")
        
        try:
            deps = get_recursive_dependencies(binary_path)
            if deps:
                print("Найдены зависимости:")
                print("\n".join(deps))
            else:
                print("Зависимости не найдены или не могут быть определены")
        except Exception as e:
            print(f"Ошибка при анализе {binary_path}: {str(e)}")

if __name__ == "__main__":
    binaries_dir = "../binaries/"
    analyze_directory(binaries_dir)
