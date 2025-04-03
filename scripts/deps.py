import subprocess
import re
import os

def get_ldd_dependencies(binary_path):
    """Получает зависимости бинарника с помощью ldd."""
    try:
        output = subprocess.check_output(["ldd", binary_path], stderr=subprocess.DEVNULL, text=True)
        dependencies = re.findall(r"\s(\/[^\s]+)\s", output)
        return dependencies
    except subprocess.CalledProcessError:
        return []

def get_objdump_dependencies(binary_path):
    """Получает зависимости бинарника через objdump."""
    try:
        output = subprocess.check_output(["objdump", "-p", binary_path], stderr=subprocess.DEVNULL, text=True)
        dependencies = re.findall(r"NEEDED\s+(\S+)", output)
        return dependencies
    except subprocess.CalledProcessError:
        return []

def find_library_paths(libraries):
    """Пытаемся найти полный путь библиотек."""
    paths = []
    for lib in libraries:
        result = subprocess.run(["ldconfig", "-p"], capture_output=True, text=True)
        match = re.search(rf"(\/[^\s]+{lib})", result.stdout)
        if match:
            paths.append(match.group(1))
    return paths

def get_recursive_dependencies(binary_path, seen=None):
    """Рекурсивно получает все зависимости бинарника."""
    if seen is None:
        seen = set()
    
    if binary_path in seen:
        return []
    
    seen.add(binary_path)
    
    ldd_deps = get_ldd_dependencies(binary_path)
    objdump_deps = get_objdump_dependencies(binary_path)
    full_paths = find_library_paths(objdump_deps)
    all_deps = set(ldd_deps + full_paths)
    
    for dep in list(all_deps):
        all_deps.update(get_recursive_dependencies(dep, seen))
    
    return list(all_deps)

if __name__ == "__main__":
    binaries = ["binary1", "binary2", "binary3", "binary5", "binary6", "binary7", "binary8"]
    for tmp in binaries:
        binary = "../binaries/" + tmp
        if os.path.exists(binary):
            deps = get_recursive_dependencies(binary)
            print(f"{binary}:\n" + "\n".join(deps) + "\n")
        else:
            print(f"{binary} не найден.")

