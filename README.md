# Información

Servidor HTTP en C para la asignatura Servicios Telemáticos, capaz de procesar todo tipo
de peticiones GET, con tratamiento de errores para dichas peticiones, mecanismo de 
persistencia, formulario POST básico para validar el correo del usuario, etc.

# Compilación

gcc -o -Wall web_sstt web_sstt.c

# Ejecución

./web_sstt [puerto] [directorio]

# Estructura

web_sstt.c    -> Código fuente del servidor
formularios   -> Ficheros HTML correspondientes a mensajes de error, índices, etc.
recursos      -> Imágenes y GIFs para probar la funcionalidad del servidor.
webserver.log -> Fichero de log de sucesos del servidor.
