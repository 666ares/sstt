#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/stat.h>
#include <regex.h>

#define VERSION			24
#define BUFSIZE			8096
#define ERROR			42
#define LOG			44

#define	OK 			200
#define BADREQUEST	    	400
#define PROHIBIDO		403
#define NOENCONTRADO		404
#define METHODNOTALLOWED	405
#define UNSUPPORTEDMEDIATYPE	415

#define NOFILE			0

#define SEGS_SIN_PETICIONES	10
#define DATE_SIZE		128

static const char *EMAIL = "joseantonio.pastorv%40um.es";

typedef enum Method {GET, POST, UNSUPPORTED} Method;

typedef struct Request {
	enum Method method;
	char *path;
} Request;

struct {
	char *ext;
	char *filetype;
} extensions [] = {
	{"gif", "image/gif" },
	{"jpg", "image/jpg" },
	{"jpeg","image/jpeg"},
	{"png", "image/png" },
	{"ico", "image/ico" },
	{"zip", "image/zip" },
	{"gz",  "image/gz"  },
	{"tar", "image/tar" },
	{"htm", "text/html" },
	{"html","text/html" },
	{0,0} };

void 
debug(int log_message_type, char *message, char *additional_info, 
      int socket_fd)
{
	int fd;
	char logbuffer[BUFSIZE * 2];
	
	switch (log_message_type) {

		case ERROR: 
			(void)sprintf(logbuffer,"ERROR: %s:%s Errno=%d exiting pid=%d",
					message, additional_info, errno, getpid());
			break;

		case PROHIBIDO:
			// Enviar como respuesta 403 Forbidden
			(void)sprintf(logbuffer,"FORBIDDEN: %s:%s", 
					message, additional_info);
			break;

		case NOENCONTRADO:
			// Enviar como respuesta 404 Not Found
			(void)sprintf(logbuffer,"NOT FOUND: %s:%s", 	
					message, additional_info);
			break;

		case LOG: 
			(void)sprintf(logbuffer," INFO: %s:%s:%d", 
					message, additional_info, socket_fd); 
			break;
	}

	if ((fd = open("webserver.log", O_CREAT | O_WRONLY | O_APPEND, 0644)) >= 0) {
		(void)write(fd, logbuffer, strlen(logbuffer));
		(void)write(fd, "\n", 1);
		(void)close(fd);
	}

	if (log_message_type == ERROR || log_message_type == NOENCONTRADO ||
			log_message_type == PROHIBIDO) 
		exit(3);
}

/*
 * Devuelve el tamaño del fichero asociado al descriptor pasado como
 * argumento en bytes.
 * @param 'fd' descriptor del fichero.
 * @return tamaño total del fichero asociado al descriptor (en bytes).
 */

long int
response_size(int fd)
{
	struct stat st;
	
	if (fstat(fd, &st) == 0)
		return st.st_size;
	else
		debug(ERROR, "system call", "fstat", 0);
}

/*
 * Genera la fecha actual en el formato necesario para una
 * respuesta HTTP.
 * @param 'date' cadena donde almacenar la fecha actual.
 *
 * Referencia: 
 * stackoverflow.com/questions/7548759/generate-a-date-string-in-http-response-date-format-in-c/7548846
 */

void
parse_date(char *date)
{
	time_t now = time(0);
	struct tm tm = *gmtime(&now);
	strftime(date, DATE_SIZE, "%a, %d, %b %Y %H:%M:%S %Z", &tm);
}

/* 
 * Elimina todas las subcadenas 'sub' presentes en la cadena 'str'.
 * @param 'str' cadena de la que se desean eliminar las subcadenas.
 * @param 'sub' subcadena que se desea eliminar de 'str'
 * @return 'str' con las ocurrencias de 'sub' eliminadas.
 *
 * Referencia:
 * stackoverflow.com/questions/47116974/remove-a-substring-from-a-string-in-c
 */

char
*strremove(char *str, const char *sub)
{
	char *p, *q, *r;
	if ((q = r = strstr(str, sub)) != NULL) { 
		size_t len = strlen(sub);
		while ((r = strstr(p = r + len, sub)) != NULL) {
			while (p < r)
				*q++ = *p++;
		}
		while ((*q++ = *p++) != '\0')
			continue;
	}
	return str;
}

/*
 * Comprueba si la extensión pasada como argumento está soportada
 * por el servidor.
 * @param 'extension' extensión del archivo solicitado.
 * @return 'NULL' si el fichero no tiene extensión o no está
 * soportada, en otro caso, devuelve el tipo de archivo
 * asociado a esa extensión.
 */

char
*ext_to_filetype(char *extension)
{
	// Saltamos el punto que indica que el fichero tiene extensión
	extension++;

	// El fichero acaba en punto pero no tiene extensión
	if (!strcmp(extension, "")) 
		return NULL;

	int i = 0;
	while (extensions[i].ext != 0) {
		if (!strcmp(extension, extensions[i].ext))
			return extensions[i].filetype;
		i++;
	}

	// La extensión no está soportada
	return NULL;
}

/*
 * Libera la memoria asociada a una estructura de tipo Request.
 * @param 'req' puntero a una estructura que contiene los distintos
 * campos de la petición.
 */

void
free_request(struct Request *req)
{
	free(req->path);
	free(req);
}

/*
 * Parsea la petición HTTP almacenada en el buffer pasado como argumento.
 * @param 'raw_request' array que contiene la petición HTTP leída
 * del socket.
 * @return estructura de tipo Request con los distintos campos de
 * la petición.
 */

struct Request
*parse_request(char raw_request[])
{
	#define S_GET	"GET"
	#define S_POST	"POST"

	// Creamos la estructura que almacenará los datos
	// que necesitamos de la petición
	struct Request *req = NULL;
	req = malloc(sizeof(struct Request));
	if (!req) return NULL;
	memset(req, 0, sizeof(struct Request));

	// Parseamos el método de la petición
	size_t method_len = strcspn(raw_request, " ");
	if (strncmp(raw_request, S_GET, sizeof S_GET - 1) == 0)
		req->method = GET;
	else if (strncmp(raw_request, S_POST, sizeof S_POST - 1) == 0)
		req->method = POST;
	else
		req->method = UNSUPPORTED;
	
	// Saltamos el espacio después del nombre del método
	raw_request += method_len + 1;

	// Parseamos la ruta del fichero solicitado
	size_t path_len = strcspn(raw_request, " ");
	req->path = malloc(path_len + 1);
	if (!req->path) {
		free_request(req);
		return NULL;
	}

	memcpy(req->path, raw_request, path_len);
	req->path[path_len] = '\0';

	return req;
}

/*
 * Compila la expresión regular pasada como argumento y comprueba si
 * hace 'match' con el token también pasado como argumento.
 * @param '_pmatch' tamaño del array donde guardar cada uno de los
 * grupos de la expresión regular
 * @param '_nmatch' número de grupos que deben hacer match
 * @param 'token' cadena sobre la que aplicar la expresión regular
 * @param 'regex' expresión regular
 * @return '1' si la expresión regular hace match, '0' si el token
 * no coincide.
 */

int
compile_and_execute_regex(int _pmatch, int _nmatch, 
			  const char *token,
			  const char *regex)
{
	int is_valid = 0, match, err;
	regex_t preg;
	regmatch_t pmatch[_pmatch];
	size_t nmatch = _nmatch;

	err = regcomp(&preg, regex, REG_EXTENDED);

	if (err == 0) {
		match = regexec(&preg, token, nmatch, pmatch, 0);
		nmatch = preg.re_nsub;
		regfree(&preg);

		if (!match)			is_valid = 1;
		else if (match = REG_NOMATCH)	is_valid = 0;
	}

	return is_valid;
}

/*
 * Comprueba si la petición HTTP almacenada en el buffer pasado como argumento es
 * válida o no.
 * @param 'request' array con la petición HTTP
 * @return '0' si la petición no es válida, '1' si sí lo es
 */

int
is_valid_request(char request[])
{
	// Usamos 'strdup' para crear una copia del buffer y poder modificarlo
	// con strtok
	char *request_copy = strdup(request);

	// Expresiones regulares para validar la primera, el resto de cabeceras
	// y la query de la petición POST que contiene el correo electrónico
	const char *main_header_regex 	= "^([A-Za-z]+)(\\s+)(/.*)(\\s+)(HTTP/1.1)";
	const char *other_headers_regex = "^(.*)(:)(\\s+)(.*)";
    	const char *email_query_regex 	= "^(.*)(=)(.*)";

	// Comprobamos la primera línea de la petición
	char *token = strtok(request_copy, "##");

	if (!compile_and_execute_regex(6, 6, token, main_header_regex)) 
		return 0;

	// Comprobamos el resto de cabeceras
	while (token != NULL) {
		// Obtenemos la siguiente cabecera
		token = strtok(NULL, "##");
		if (token != NULL) {
			// Comprobamos si se trata de la query de una petición POST que
			// contiene el correo o no
            		if (strstr(token, "email=") != NULL)
                		if (!compile_and_execute_regex(4, 4, token, email_query_regex))
                    			return 0;
	 
			else if (!compile_and_execute_regex(5, 5, token, other_headers_regex))
				    return 0;
        	}
	}
	
	// Liberamos el buffer donde hemos copiado la petición y devolvemos
	// '1' indicando que la petición es válida
	free(request_copy);
	return 1;
}

/*
 * Genera una respuesta para la petición HTTP de acuerdo al código
 * pasado como argumento.
 * @param 'fd_form' descriptor del fichero html que se enviará.
 * @param 'status_code' código de respuesta a la petición.
 * @param 'fd' descriptor donde escribir la respuesta.
 * @param 'filetype' tipo del fichero que se va a mandar
 */

void 
response(int fd_form, int status_code, int fd, char *filetype)
{
	char response[BUFSIZE];		// Buffer donde se almacena la respuesta HTTP
	char date[DATE_SIZE];		// Buffer donde se almacena la fecha
	int index;

    	// Construir cabecera según el status_code
	switch (status_code) {
		case OK:
			index = sprintf(response, "%s", "HTTP/1.1 200 OK\r\n");
			break;

		case BADREQUEST:
			index = sprintf(response, "%s", "HTTP/1.1 400 Bad Request\r\n");
			if ((fd_form = open("400.html", O_RDONLY)) < 0)
				debug(ERROR, "system call", "open", 0);
			break;

		case NOENCONTRADO:
			index = sprintf(response, "%s", "HTTP/1.1 404 Not Found\r\n");
			if ((fd_form = open("404.html", O_RDONLY)) < 0)
				debug(ERROR, "system call", "open",  0);
			break;

		case PROHIBIDO:
			index = sprintf(response, "%s", "HTTP/1.1 403 Forbidden\r\n");
			if ((fd_form = open("403.html", O_RDONLY)) < 0)
				debug(ERROR, "system call", "open", 0);
			break;

		case UNSUPPORTEDMEDIATYPE:
			index = sprintf(response, "%s", "HTTP/1.1 415 Unsupported Media Type\r\n");
			if ((fd_form = open("415.html", O_RDONLY)) < 0)
				debug(ERROR, "system call", "open", 0);
			break;
		
		case METHODNOTALLOWED:
			index = sprintf(response, "%s", "HTTP/1.1 405 Method Not Allowed\r\n");
			if ((fd_form = open("405.html", O_RDONLY)) < 0)
				debug(ERROR, "system call", "open", 0);
			break;
	}

    	// Construimos la fecha
	parse_date(date);

    	// Construimos la respuesta
	index += sprintf(response + index, "Server: web_sstt\r\n");	
	index += sprintf(response + index, "Date: %s\r\n", date);
	index += sprintf(response + index, "Connection: keep-alive\r\n");
	index += sprintf(response + index, "Keep-Alive: timeout=10\r\n");
	index += sprintf(response + index, "Content-Length: %ld\r\n", response_size(fd_form));
	index += sprintf(response + index, "Content-Type: %s\r\n", filetype); 
	index += sprintf(response + index, "\r\n");

    	// Escribir respuesta en el descriptor
	write(fd, response, index);

    	// Escribir en el descriptor el contenido del fichero en bloques de
	// como máximo 8 kB
	int bytes_leidos;
	while ((bytes_leidos = read(fd_form, &response, BUFSIZE)) > 0)
		write(fd, response, bytes_leidos);

	// Cerrar formulario
	close(fd_form);
}

/*
 * Indica si el usuario tiene permisos para acceder a la ruta pasada
 * como argumento.
 * @param 'path' cadena con la ruta hasta el fichero solicitado.
 * @return '1' si el usuario no tiene permisos para acceder al
 * fichero, '0' en caso contrario.
 */

int
is_forbidden(char *path) 
{

	char buffer[strlen(path)];
	strcpy(buffer, path);

	// Si se encuentra ls subcadena '../' (acceso a un directorio superior) o la petición
	// comienza por '/' (ruta absoluta) se devuelve 1 indicando que el usuario no tiene
	// acesso al recurso solicitado
	
	if (strstr(buffer, "../") != NULL || buffer[1] == '/') 
		return 1;

	return 0;
}

int
input_timeout(int filedes, unsigned int seconds,
	      unsigned int microsecs)
{
	fd_set rfds;
	struct timeval tv;

	// Initialize the file descriptor set
	FD_ZERO(&rfds);
	FD_SET(filedes, &rfds);

	// Initialize the timeout data structure
	tv.tv_sec = seconds;
	tv.tv_usec = microsecs;

	if ((select(filedes + 1, &rfds, NULL, NULL, &tv)) < 0)
		debug(ERROR, "system call", "select", 0);

	return FD_ISSET(filedes, &rfds);
}

void 
process_web_request(int descriptorFichero)
{	
	debug(LOG, "request", "Ha llegado una petición.", descriptorFichero);

	//
	// Definir buffer y variables necesarias para leer las peticiones
	//
	
	char 	buffer[BUFSIZE + 1];	// Buffer donde se almacena la petición recibida
	struct 	Request *req;		// Estructura donde guardar los distintos campos de la petición
	long 	bytes_leidos;		// Bytes leídos de la petición
	long 	indice;			// Variable auxiliar para recorrer el buffer
	int 	fd;			// Descriptor para abrir los html
	
	//
	// Leer la petición HTTP
	//
	
	bytes_leidos = read(descriptorFichero, buffer, BUFSIZE);

	while (input_timeout(descriptorFichero, 0, 100000))
		bytes_leidos += read(descriptorFichero, buffer + bytes_leidos,
					BUFSIZE - bytes_leidos);

	//
	// Comprobación de errores de lectura
	//	
	
	if (bytes_leidos < 0) {
		close(descriptorFichero);
		debug(ERROR, "system call", "read", 0);
	}

	//
	// Si la lectura tiene datos válidos terminar el buffer con un \0
	// (Cuando 0 < bytes_leidos < BUFSIZE)
	//
        
	if (bytes_leidos < BUFSIZE)
		buffer[bytes_leidos] = '\0';

	//
	// Se eliminan los caracteres de retorno de carro y nueva línea
	//
        	
	for (indice = 0; indice < bytes_leidos; indice++) {
        	if (buffer[indice] == '\r' || buffer[indice] == '\n')
                	buffer[indice] = '#';
        }

	//
	// Comprobar si la petición es válida
	//
        
	if (!is_valid_request(buffer)) {
        	response(NOFILE, BADREQUEST, descriptorFichero, "text/html");
		return;
	}

	// 
	// Parsear la petición para obtener el método y la ruta del
	// fichero solicitado
	//
	
	req = parse_request(buffer);

	//
	// Devolvemos un error indicando que el método no está soportado
	// (No es un GET o un POST)
	//

	if (req->method == UNSUPPORTED) {
		response(NOFILE, METHODNOTALLOWED, descriptorFichero, "text/html");
		return;
	}

	//
	// TRATAR LOS CASOS DE LOS DIFERENTES MÉTODOS QUE SE USAN
	// (Se soporta solo GET)
	//
	
	if (req->method == POST) {
		// Obtenemos la query que contiene el email del usuario
		char *email_query = strstr(buffer, "email=");
		// Sacamos únicamente el email
		char *only_email = strremove(email_query, "email=");

		//
		// Comprobamos el email introducido en el formulario y devolvemos el
		// html correspondiente en función de si es correcto el correo o no
		//
		
		if (strcmp(EMAIL, only_email) == 0) {
			if ((fd = open("accion_form_ok.html", O_RDONLY)) < 0)
				debug(ERROR, "system call", "open", 0);
		}
		else {
			if ((fd = open("accion_form_ko.html", O_RDONLY)) < 0)
				debug(ERROR, "system call", "open", 0);
		}

		response(fd, OK, descriptorFichero, "text/html");
		return;
	}

	else if (req->method == GET) {

		//
		// Como se trata el caso excepcional de la URL que no apunta a ningún
		// fichero html
		//

		if (strcmp(req->path, "/") == 0) {

			if ((fd = open("index.html", O_RDONLY)) < 0)
				debug(ERROR, "system call", "open", 0);
			response(fd, OK, descriptorFichero, "text/html");
			return;
	
		} else {

			//
			// Cómo se trata el caso de acceso ilegal a directorios superiores
			// de la jerarquía de directorios del sistema
			//

			if (is_forbidden(req->path)) {
				response(NOFILE, PROHIBIDO, descriptorFichero, "text/html");
				return;
			}
			
			else {

				//
				// Evaluar el tipo de fichero que se está solicitando, y actuar en
				// consecuencia devolviéndolo si se soporta y devolviendo el error
				// correspondiente en otro caso
				//
					
				char *extension = strrchr(req->path, '.');

				//
				// Si el fichero solicitado no tiene extensión devolvemos el 
				// error correspondiente
				//
				
				if (!extension) {
					response(NOFILE, BADREQUEST, descriptorFichero, "text/html");
					return;
				}
				
				else {
					
					//
					// Comprobamos si la extensión que tiene el fichero solicitado
					// está soportada y devolvemos un error si no lo está
					//
					
					char *filetype = ext_to_filetype(extension);

					if (!filetype) {
						response(NOFILE, UNSUPPORTEDMEDIATYPE, descriptorFichero, "text/html");
						return;
					}
					
					else {
						
						//
						// En caso de que el fichero sea soportado, exista, etc. se envía
						// el fichero con la cabecera correspondiente, y el envio del fichero
						// se hace en bloques de un máximo de 8kB
						//

						if ((fd = open(req->path + 1, O_RDONLY)) < 0)
							response(NOFILE, NOENCONTRADO, descriptorFichero, "text/html");
						else
							response(fd, OK, descriptorFichero, filetype);
						return;
					}
				}	
			}
		}
	}	
	close(descriptorFichero);
    	exit(1);
}

int main(int argc, char **argv)
{
	int i, port, pid, listenfd, socketfd;
	socklen_t length;
	static struct sockaddr_in cli_addr;	// static = Inicializado con ceros
	static struct sockaddr_in serv_addr;	// static = Inicializado con ceros
	
	//  Argumentos que se esperan:
	//
	//  argv[1]
	//  En el primer argumento del programa se espera el puerto en el
	//  que el servidor escuchara
	//
	//  argv[2]
	//  En el segundo argumento del programa se espera el directorio
	//  en el que se encuentran los ficheros del servidor
	//
	//  Verficiar que los argumentos que se pasan al iniciar el programa
	//  son los esperados
	//

	//
	//  Verficiar que el directorio escogido es apto. Que no es un
	//  directorio del sistema y que se tienen permisos para ser usado
	//

	if (chdir(argv[2]) == -1) { 
		(void)printf("ERROR: No se puede cambiar de directorio %s.\n", argv[2]);
		exit(4);
	}

	// Hacemos que el proceso sea un demonio sin hijos zombies
	if (fork() != 0)
		return 0; // El proceso padre devuelve un OK al shell

	(void)signal(SIGCHLD, SIG_IGN); // Ignoramos a los hijos
	(void)signal(SIGHUP, SIG_IGN); 	// Ignoramos cuelgues
	
	debug(LOG, "Web server starting...", argv[1], getpid());
	
	/* setup the network socket */
	if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		debug(ERROR, "system call", "socket", 0);
	
	port = atoi(argv[1]);
	
	if (port < 0 || port > 60000)
		debug(ERROR, "Puerto invalido, prueba un puerto de 1 a 60000", argv[1], 0);
	
	/* Se crea una estructura para la información IP y puerto donde escucha el servidor */
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY); 	/* Escucha en cualquier IP disponible */
	serv_addr.sin_port = htons(port); 		/* ... en el puerto port especificado como parámetro */
	
	if (bind(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) 
		debug(ERROR, "system call", "bind", 0);
	
	if (listen(listenfd, 64) < 0)
		debug(ERROR, "system call", "listen", 0);
	
	while(1) {

		length = sizeof(cli_addr);

		if ((socketfd = accept(listenfd, (struct sockaddr *)&cli_addr, &length)) < 0)
			debug(ERROR, "system call", "accept", 0);
		
		if ((pid = fork()) < 0) {
			debug(ERROR,"system call","fork",0);
		}
		else {
			if (pid == 0) { // Proceso hijo
				(void)close(listenfd);
		
				//
				// Mecanismo de persistencia HTTP. La conexión TCP se cerrará
				// si no se reciben nuevas peticiones en un período fijado por
				// el usuario (en este caso, 'SEGS_SIN_PETICIONES' = 10)
				//
		
				fd_set rfds;
				struct timeval tv;
				int retval = 1;
				
				while (retval) {
					FD_ZERO(&rfds);
					FD_SET(socketfd, &rfds);

					tv.tv_sec = SEGS_SIN_PETICIONES;
					tv.tv_usec = 0;

					retval = select(socketfd + 1, &rfds, NULL, NULL, &tv);

					(retval ? process_web_request(socketfd) : (void)close(socketfd));
				}

			} else { // Proceso padre
				(void)close(socketfd);
			}
		}
	}
}
