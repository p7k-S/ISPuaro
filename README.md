# 🛠️ ISPuaro 
**Анализ бинарных файлов | Генерация SBOM | Визуализация графа компонент**

## 📋 Требования  
- Python 3.8+  
- Graphviz (`dot`) для визуализации  

## 🚀 Быстрый старт  
```bash
git clone https://github.com/p7k-S/ISPuaro/
cd ISPuaro/scripts/
python info                    #базовый анализ всех бинарников -> ISPuaro/info/
python gen_sbom.py             #генерация SBOM
python graphviz.py sbom.json   #создает .dot файл для графа компонент
dot -Tpng sbom_graph.dot -o sbom_graph.png       #создание .png файла, визуализация графа компонент
```

## 📌 Описание скриптов

### `info.py` - Базовый анализ бинарных файлов
- file {filename}             # Определение типа файла и архитектуры
- ldd {filename}              # Анализ динамических зависимостей
- readelf -h {filename}       # Заголовки ELF-файла
- readelf -d {filename} | grep NEEDED  # Список требуемых библиотек
- nm -D {filename}            # Динамические символы
- objdump -T {filename}       # Таблица динамических символов
- strings {filename}          # Извлечение текстовых строк

по каждому файлу создается ISPuaro/info/binary{num}_info.txt
