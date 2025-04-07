import os
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

    # Получаем основной компонент из метаданных
    main_component_ref = sbom["metadata"]["component"]["purl"]
    main_component_name = sbom["metadata"]["component"]["name"]
    main_component_description = sbom["metadata"]["component"]["description"]
    
    # Добавляем основной компонент с жирной рамкой
    dot_graph += f'    "{main_component_ref}" [label="{main_component_name}\\n{main_component_description}", shape=box, style="bold,filled", fillcolor=lightgray, penwidth=3];\n'

    # Получаем список файлов в директории ../binaries
    binaries_dir = "../binaries"
    binary_files = os.listdir(binaries_dir)

    # Добавляем компоненты
    for component in sbom['components']:
        component_ref = component['bom-ref']
        component_name = component['name']
        component_type = component['type']
        component_description = component['description']
        
        # Пропускаем основной компонент, так как мы его уже добавили
        if component_ref == main_component_ref:
            continue
            
        # Форма узла зависит от типа
        if component_type == "library":
            dot_graph += f'    "{component_ref}" [label="{component_name}\\n{component_description}", shape=ellipse];\n'
        else:
            dot_graph += f'    "{component_ref}" [label="{component_name}\\n{component_description}", shape=box];\n'
        
        # Проверяем, если имя компонента присутствует в списке файлов
        if component_name in binary_files:
            # Если компонент найден в директории, добавляем красную стрелку от основного компонента
            dot_graph += f'    "{main_component_ref}" -> "{component_ref}" [color=red, style=bold, penwidth=3];\n'

        # Добавление зависимостей
        if "dependencies" in component:
            for dep in component["dependencies"]:
                dep_ref = dep["ref"]
                origin = dep.get("origin", "ldd")
                
                # В случае других типов зависимостей, цвет синей линии
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

