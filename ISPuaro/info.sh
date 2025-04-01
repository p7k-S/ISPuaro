#!/bin/sh
for
    file
    --version
    strings
    ldd file
    readelf -h file
    readelf -d file | grep NEEDED
    nm -D имя_файла  # Покажет экспортируемые функции
    objdump -T имя_файла  # Покажет динамические символы
    # diff -u file1.txt file2.txt
