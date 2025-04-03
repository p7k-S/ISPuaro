git clone https://github.com/p7k-S/ISPuaro/
cd ISPuaro/scripts/
python info                    #базовый анализ всех бинарников -> ISPuaro/info/
python gen_sbom.py             #генерация SBOM
python graphviz.py sbom.json   #создает .dot файл для графа компонент
dot -Tpng sbom_graph.dot -o sbom_graph.png       #создание .png файла, визуализация графа компонент
