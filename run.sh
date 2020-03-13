#!/bin/bash

rm webserver.log
rm web_sstt
pkill -9 web_sstt
gcc -o web_sstt web_sstt.c
echo "[LOG] Iniciando servidor web en el puerto 8080."
./web_sstt 8080 .
