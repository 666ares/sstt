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

#define VERSION			        24
#define BUFSIZE			        8096
#define ERROR			        42
#define LOG			        44

// HTTP Status codes
#define	OK 			        200
#define BADREQUEST	    	    	400
#define PROHIBIDO		        403
#define NOENCONTRADO		    	404
#define METHODNOTALLOWED	    	405
#define UNSUPPORTEDMEDIATYPE		415

#define NOFILE			        0

#define SEGS_SIN_PETICIONES	    	10
#define DATE_SIZE		        128

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
debug(int log_message_type, char *message, char *additional_info, int socket_fd)
{
	int fd;
	char logbuffer[BUFSIZE * 2];
	
	switch (log_message_type) {
		case ERROR: 
			(void)sprintf(logbuffer,"ERROR: %s:%s Errno=%d exiting pid=%d", message, 
					additional_info, errno, getpid());
			break;

		case PROHIBIDO:
			// Enviar como respuesta 403 Forbidden
			(void)sprintf(logbuffer,"FORBIDDEN: %s:%s", message, additional_info);
			break;

		case NOENCONTRADO:
			// Enviar como respuesta 404 Not Found
			(void)sprintf(logbuffer,"NOT FOUND: %s:%s", message, additional_info);
			break;

		case LOG: 
			(void)sprintf(logbuffer," INFO: %s:%s:%d", message, additional_info, socket_fd); 
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

int
response_size(int fd)
{
	struct stat file_stat;
	fstat(fd, &file_stat);
	return file_stat.st_size;
}

// stackoverflow.com/questions/7548759/generate-a-date-string-in-http-response-date-format-in-c/7548846
void
parse_date(char *date)
{
	time_t now = time(0);
	struct tm tm = *gmtime(&now);
	strftime(date, DATE_SIZE, "%a, %d, %b %Y %H:%M:%S %Z", &tm);
}

// stackoverflow.com/questions/47116974/remove-a-substring-from-a-string-in-c
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

char
*_ext_to_filetype(char *extension)
{
	// Quitamos el '.'
	extension++;

	// Evitar ficheros acabados en punto pero sin extensión
	if (strcmp(extension, "") == 0)
		return NULL;

	int idx = 0;
	while (extensions[idx].ext != 0) {
		if (strcmp(extension, extensions[idx].ext) == 0)
			return strdup(extensions[idx].filetype);
		idx++;
	}

	return NULL;
}

void
free_request(struct Request *req)
{
	free(req->path);
	free(req);
}

struct Request
*parse_request(char *raw_request)
{
	// Creamos la estructura que almacenará los datos
	// que necesitamos de la petición
	struct Request *req = NULL;
	req = malloc(sizeof(struct Request));
	if (!req) return NULL;
	memset(req, 0, sizeof(struct Request));

	// Parsear método
	size_t method_len = strcspn(raw_request, " ");
	if (memcmp(raw_request, "GET", strlen("GET")) == 0)
		req->method = GET;
	else if (memcmp(raw_request, "POST", strlen("POST")) == 0)
		req->method = POST;
	else
		req->method = UNSUPPORTED;

	raw_request += method_len + 1; // saltar el espacio

	// Parsear path
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

int
compile_and_execute_regex(int _pmatch, int _nmatch, const char *token,
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

int
is_valid_request(char *request)
{
	// 'request' points to a string literal, which cannot be modified
	// (as strtok would like to do), so we make a modifiable copy
	char *request_copy = strdup(request);

	// Regular expressions to validate headers
	const char *main_header_regex = "^([A-Za-z]+)(\\s+)(/.*)(\\s+)(HTTP/1.1)";
	const char *other_headers_regex = "^([A-Za-z]+)(:)(\\s+)(.*)";

	// Check is first line is valid ('XXXX /zzzz HTTP/1.1')
	char *token;
	token = strtok(token, "\r\n");

	if (!compile_and_execute_regex(6, 6, token, main_header_regex))
		return 0;

	while (token != NULL) {
		// Check if current line is valid or not
		token = strtok(NULL, "\r\n");
		if (token != NULL)
			if (!compile_and_execute_regex(5, 5, token, other_headers_regex))
				return 0;
	}

	free(request_copy);
	return 1;
}

void 
response(int fd_form, int status_code, int fd, char *filetype)
{
	char response[BUFSIZE];
	char date[DATE_SIZE];
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
	index += sprintf(response + index, "Server: Ubuntu 16.04 SSTT\r\n");	
	index += sprintf(response + index, "Date: %s\r\n", date);
	index += sprintf(response + index, "Connection: Keep-Alive\r\n");
	index += sprintf(response + index, "Content-Length: %d\r\n", response_size(fd_form));
	index += sprintf(response + index, "Content-Type: %s\r\n", filetype); 
	index += sprintf(response + index, "\r\n");

    	// Escribir respuesta en el descriptor
	write(fd, response, index);

    	// Escribir contenido del fichero en el descriptor
	int bytes_leidos;
	while ((bytes_leidos = read(fd_form, &response, BUFSIZE)) > 0)
		write(fd, response, bytes_leidos);

}

// gnu.org/software/libc/manual/html_node/Waiting-for-I_002fO.html
// manpages.ubuntu.com/manpages/bionic/es/man2/select_tut.2.html
int
input_timeout(int filedes, unsigned int seconds)
{
	fd_set rfds;
	struct timeval tv;

	/* Initialize the file descriptor set. */
	FD_ZERO(&rfds);
	FD_SET(filedes, &rfds);

	/* Initialize the timeout data structure. */
	tv.tv_sec = seconds;
	tv.tv_usec = 0;

	if ((select(filedes + 1, &rfds, NULL, NULL, &tv)) < 0)
		debug(ERROR, "system call", "select", 0);

	return FD_ISSET(filedes, &rfds);
}

int
is_forbidden(char *path)
{
    return 0;

}

void 
process_web_request(int descriptorFichero)
{
	// Mecanismo de persistencia HTTP
	while (input_timeout(descriptorFichero, SEGS_SIN_PETICIONES)) {
	
		debug(LOG, "request", "Ha llegado una petición.", descriptorFichero);

		// Definir buffer y variables necesarias para leer las peticiones
		char buffer[BUFSIZE];
		char *request;

		// Leer la petición HTTP
		int bytes_leidos = read(descriptorFichero, &buffer, BUFSIZE);

		// Comprobación de errores de lectura
		if (bytes_leidos < 0) {
			close(descriptorFichero);
			debug(ERROR, "system call", "read", 0);
		}

		// Si la petición no es válida (no está bien formada...)
        	int ret;
        	if (!is_valid_request(buffer)) {
            		response(NOFILE, BADREQUEST, descriptorFichero, "text/html");
			break;
		}

		// Parsear la petición para obtener el método y el
		// path del archivo que se está pidiendo
		struct Request *req = parse_request(buffer);

		// Si el método no es válido (GOT, PUST, etc)
		if (req->method == UNSUPPORTED)
			response(NOFILE, METHODNOTALLOWED, descriptorFichero, "text/html");
	
		/* POST */
		if (req->method == POST) {
			// Cadena que contiene el email ("email=jose@um.es")
			char *email = strstr(buffer, "email=");
			// Sacamos únicamente el email
			char *only_email = strremove(email, "email=");

			// Comprobar mi email con el introducido en el formulario
			int fd_form;
			if (strcmp(EMAIL, only_email) == 0) {
				if ((fd_form = open("accion_form_ok.html", O_RDONLY)) < 0)
					debug(ERROR, "system call", "open", 0);
			}
			else {
				if ((fd_form = open("accion_form_ko.html", O_RDONLY)) < 0)
					debug(ERROR, "system call", "open", 0);
			}

			// Mandamos la respuesta con el formulario correspondiente
			response(fd_form, OK, descriptorFichero, "text/html");
		}
		/* GET */
		else if (req->method == GET) {
			int fd;

			// Ruta absoluta, página principal
			if (strcmp(req->path, "/") == 0) {
				if ((fd = open("index.html", O_RDONLY)) < 0)
					debug(ERROR, "system call", "open", 0);
				response(fd, OK, descriptorFichero, "text/html");
			} else {
                		// Comprobar si el usuario tiene permiso para acceder al directorio
                		if (is_forbidden(req->path) == 0) {
                    			// Obtener la extensión del fichero solicitado
                    			char *extension = strrchr(req->path, '.');
                    
                    			if (!extension)
                        			response(NOFILE, BADREQUEST, descriptorFichero, "text/html");
					else {
                        			// Obtener el tipo de fichero
                        			char *filetype = _ext_to_filetype(extension);
                        			if (!filetype)
                            				response(NOFILE, UNSUPPORTEDMEDIATYPE, descriptorFichero, "text/html");
						else {
                            				if ((fd = open(req->path + 1, O_RDONLY)) < 0)
                                				response(NOFILE, NOENCONTRADO, descriptorFichero, "text/html");
                            				else
                                				response(fd, OK, descriptorFichero, filetype);
                        			}
                    			}
                		} else 
                    			response(NOFILE, PROHIBIDO, descriptorFichero, "text/html");
			}
			close(fd);
		}
	}
    close(descriptorFichero);
    exit(1);
}

int main(int argc, char **argv)
{
	int i, port, pid, listenfd, socketfd;
	socklen_t length;
	static struct sockaddr_in cli_addr;		// static = Inicializado con ceros
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
				process_web_request(socketfd); // El hijo termina tras llamar a esta función
			} else { // Proceso padre
				(void)close(socketfd);
			}
		}
	}
}
