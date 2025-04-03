import json
import argparse
from collections import defaultdict

def generate_dot_from_sbom(sbom_file, output_dot_file):
    # Загружаем SBOM (предполагаем CycloneDX JSON)
    with open(sbom_file, 'r') as f:
        sbom = json.load(f)
    
    # Собираем компоненты и зависимости
    components = {}
    dependencies = defaultdict(list)
    
    # Извлекаем компоненты
    for component in sbom.get("components", []):
        component_id = component.get("bom-ref", component.get("name", "unknown"))
        component_name = component.get("name", "unknown")
        component_desc = component.get("description", "")
        # Формируем label с именем и описанием
        label = f"{component_name}"
        if component_desc:
            label += f"\n{component_desc}"
        components[component_id] = label
    
    # Извлекаем зависимости (если есть)
    for dep in sbom.get("dependencies", []):
        ref = dep["ref"]
        for depends_on in dep.get("dependsOn", []):
            dependencies[ref].append(depends_on)
    
    # Генерируем DOT-файл
    with open(output_dot_file, 'w') as f:
        f.write("digraph SBOM {\n")
        f.write('  rankdir="LR";\n')  # Горизонтальная ориентация
        f.write('  node [shape=box, style=filled, fillcolor="#f0f0f0"];\n')
        f.write('  node [fontname="Helvetica", fontsize=10];\n')  # Настройки шрифта
        
        # Добавляем узлы (компоненты)
        for comp_id, comp_label in components.items():
            f.write(f'  "{comp_id}" [label="{comp_label}"];\n')
        
        # Добавляем рёбра (зависимости)
        for from_comp, to_comps in dependencies.items():
            for to_comp in to_comps:
                f.write(f'  "{from_comp}" -> "{to_comp}";\n')
        
        f.write("}\n")

if __name__ == "__main__":
    # Настройка парсера аргументов
    parser = argparse.ArgumentParser(description='Generate DOT graph from SBOM file')
    parser.add_argument('input_file', help='Input SBOM file (JSON format)')
    parser.add_argument('output_file', help='Output DOT file')
    
    args = parser.parse_args()
    
    # Генерация графа
    generate_dot_from_sbom(args.input_file, args.output_file)
    print(f"DOT graph successfully generated and saved to {args.output_file}")
