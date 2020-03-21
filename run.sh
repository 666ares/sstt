#!/bin/bash

gcc -o web_sstt web_sstt.c
echo "[LOG] Iniciando servidor web en el puerto 8080."
./web_sstt 8080 .
