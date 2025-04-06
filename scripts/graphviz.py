import json

def generate_dot_graph(sbom_file):
    # Чтение SBOM из файла
    with open(sbom_file, 'r') as f:
        sbom = json.load(f)

    # Начало DOT графа
    dot_graph = "digraph SBOM {\n"
    dot_graph += '    node [shape=record];\n'

    # Метаданные
    dot_graph += "    // Metadata\n"
    dot_graph += f'    // Platform: {sbom["metadata"]["platform"]["name"]} ({sbom["metadata"]["platform"]["architecture"]})\n'
    dot_graph += f'    // Description: {sbom["metadata"]["component"]["description"]}\n'

    # Добавляем компоненты и зависимости
    for component in sbom['components']:
        component_ref = component['bom-ref']
        component_name = component['name']
        component_type = component['type']
        component_description = component['description']
        
        # Форма узла зависит от типа
        if component_type == "library":
            dot_graph += f'    "{component_ref}" [label="{component_name}\\n{component_description}", shape=ellipse];\n'
        else:
            dot_graph += f'    "{component_ref}" [label="{component_name}\\n{component_description}", shape=box];\n'
        
        # Добавление зависимостей
        if "dependencies" in component:
            for dep in component["dependencies"]:
                dep_ref = dep["ref"]
                origin = dep.get("origin", "ldd")
                
                if origin == "component":
                    dot_graph += f'    "{component_ref}" -> "{dep_ref}" [color=red];\n'
                else:
                    dot_graph += f'    "{component_ref}" -> "{dep_ref}" [color=blue];\n'

    dot_graph += "}\n"
    return dot_graph

# Сохраняем в файл
def save_dot_graph(dot_graph, output_file):
    with open(output_file, 'w') as f:
        f.write(dot_graph)

# Пример использования
sbom_file = 'sbom.json'
dot_graph = generate_dot_graph(sbom_file)
save_dot_graph(dot_graph, 'sbom_graph.dot')

print("DOT граф зависимостей сохранен в sbom_graph.dot")

