#!/bin/bash

# Nombres de los fichero que debemos borrar
webserver="webserver.log"
ejecutable="web_sstt"

# Eliminamos el log y el ejecutable del servidor
if [ -f $webserver ] ; then
	rm $webserver  
fi

if [ -f $ejecutable ] ; then
	rm $ejecutable
fi

# Matamos el proceso del servidor
pkill -9 web_sstt

# Compilamos
gcc -Wall -o web_sstt web_sstt.c

# Lanzamos
./web_sstt $1 .
