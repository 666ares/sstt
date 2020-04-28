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

#define VERSION					24
#define BUFSIZE					8096
#define ERROR					42
#define LOG						44
#define PROHIBIDO				403
#define NOENCONTRADO			404
#define SEGS_SIN_PETICIONES		10
#define DATESIZE				128

static const char *EMAIL = "joseantonio.pastorv%40um.es";

int valor_cookie = 0;

typedef enum Method {
	GET, 
	POST, 
	UNSUPPORTED
} Method;

typedef struct Request {
	enum Method method;
	char *path;
} Request;

struct {
	char *ext;
	char *filetype;
} extensions [] = {
	{"gif",  "image/gif" },
	{"jpg",  "image/jpg" },
	{"jpeg", "image/jpeg"},
	{"png",  "image/png" },
	{"ico",  "image/ico" },
	{"zip",  "image/zip" },
	{"gz",   "image/gz"  },
	{"tar",  "image/tar" },
	{"htm",  "text/html" },
	{"html", "text/html" },
	{0,      0} 
};

void 
debug(int log_message_type, char *message, char *additional_info, 
      int socket_fd)
{
	int fd;
	char logbuffer[BUFSIZE * 2];
	
	switch (log_message_type) {
		case ERROR: 
			(void)sprintf(logbuffer,"ERROR: [%s] [%s] [errno = %d] [exiting pid = %d]",
					message, additional_info, errno, getpid());
			break;

		case PROHIBIDO:
			(void)sprintf(logbuffer,"FORBIDDEN: [%s] [%s]", message, additional_info);
			break;

		case NOENCONTRADO:
			(void)sprintf(logbuffer,"NOT FOUND: [%s] [%s]", message, additional_info);
			break;

		case LOG: 
			(void)sprintf(logbuffer," INFO: [%s] [%s] [%d]", message, additional_info, socket_fd); 
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

long int
response_size(int fd)
{
	struct stat st;
	if (!fstat(fd, &st))
		return (st.st_size);
		
	debug(ERROR, "system call", "fstat", 0);
	
	/* Nunca llega aquí */
	return 0;
}

void
parse_date(char *date)
{
	time_t now = time(0);
	struct tm tm = *gmtime(&now);
	strftime(date, DATESIZE, "%a, %d, %b %Y %H:%M:%S %Z", &tm);
}

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
*ext_to_filetype(char *extension)
{
	/* Saltamos el punto */
	extension++;

	/* El fichero acaba en punto pero no tiene extensión */	
	if (!strcmp(extension, ""))
		return NULL;

	for (int i = 0; extensions[i].ext != 0; i++) {
		if (!strcmp(extension, extensions[i].ext))
			return extensions[i].filetype;
	}	

	/* La extensión no está soportada */
	return NULL;
}

void free_request(struct Request *req)
{
	free(req->path); 
    free(req);
}

struct Request *parse_request(char raw_request[]) 
{
	#define S_GET	"GET"
	#define S_POST	"POST"

	struct Request *req = NULL;
	req = malloc(sizeof(struct Request));
	if (!req) 
		return NULL;
	memset(req, 0, sizeof(struct Request));

	/* Parseamos el método */
	size_t method_len = strcspn(raw_request, " ");
	if (strncmp(raw_request, S_GET, sizeof S_GET - 1) == 0)
		req->method = GET;
	else if (strncmp(raw_request, S_POST, sizeof S_POST - 1) == 0)
		req->method = POST;
	else
		req->method = UNSUPPORTED;

	#undef S_GET
	#undef S_POST
	
	/* Saltamos el espacio entre  el método y la ruta */
	raw_request += method_len + 1;

	/* Parseamos la ruta del fichero solicitado */
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

int compile_and_execute_regex(int _pmatch, int _nmatch, 
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

		if (!match)						is_valid = 1;
		else if (match == REG_NOMATCH)	is_valid = 0;
	}
	
	return is_valid;
}

int is_valid_request(char request[])
{
	/* 'strdup' para crear una copia modificable del buffer */
	char *request_copy = strdup(request);

	const char *main_header_regex 	= "^([A-Za-z]+)(\\s+)(/.*)(\\s+)(HTTP/1.1)";
	const char *other_headers_regex = "^(.*)(:)(\\s+)(.*)";
    const char *email_query_regex 	= "^(.*)(=)(.*)";

	/* Comprobamos la primera línea de la petición */
	char *token = strtok(request_copy, "##");
	if (!compile_and_execute_regex(6, 6, token, main_header_regex)) 
		return 0;

	/* Comprobamos el resto de líneas */
	while (token != NULL) {
		token = strtok(NULL, "##");
		if (token != NULL) {
            	if (strstr(token, "email=") != NULL) {
                	if (!compile_and_execute_regex(4, 4, token, email_query_regex))
                    	return 0;
	 			} else {
					if (!compile_and_execute_regex(5, 5, token, other_headers_regex))
						return 0;
				}
        }
	}
	
	free(request_copy);
	/* Petición válida */
	return 1;
}

void abrir_fichero(int *fd, char *fichero)
{
	if ((*fd = open(fichero, O_RDONLY)) < 0)
		debug(ERROR, "system call", "open", 0);
}

void response(int fd_fichero, int fd_escritura,
              char *peticion, char *filetype)
{
	char response[BUFSIZE], date[DATESIZE];	
	int ret, idx;

    #define TOO_MANY_REQ_CODE "429"

	/* Construimos la fecha */
	parse_date(date);

    idx = sprintf(response, "%s\r\n"
                            "Server: web.sstt5819.org\r\n"
                            "Date: %s\r\n"
                            "Connection: keep-alive\r\n"
                            "Keep-Alive: timeout=10, max=5000\r\n"
                            "Content-Length: %ld\r\n"
                            "Content-Type: %s\r\n",
                            peticion, date, response_size(fd_fichero), filetype);
    
	/* 
        Añadimos la cabecera 'Set-Cookie' siempre que la respuesta
	    no sea un 429 (indica que se ha alcanzado el máximo de
	    peticiones) 
    */
    if (strstr(peticion, TOO_MANY_REQ_CODE) == NULL)
        idx += sprintf(response + idx, 
					   "Set-Cookie: cookie_counter=%d; Max-Age=120\r\n",
                       ++valor_cookie);

    #undef TOO_MANY_REQ_CODE

    sprintf(response + idx, "\r\n");

	(void)write(fd_escritura, response, strlen(response));

	/* bloques de como máximo 8 kB */
	while ((ret = read(fd_fichero, &response, BUFSIZE)) > 0)
		(void)write(fd_escritura, response, ret);

	(void)close(fd_fichero);
}

int is_forbidden(char *path) 
{
	char buffer[strlen(path)];
	strcpy(buffer, path);
    
    if (strstr(buffer, "../") != NULL) 
        return 1;

     return 0;
}

int input_timeout(int filedes, unsigned int seconds,
	              unsigned int microsecs)
{
	fd_set rfds;
	struct timeval tv;
	
	/* Initialize the file descriptor set */
	FD_ZERO(&rfds);
	FD_SET(filedes, &rfds);

	/* Initialize the timeout data structure */
	tv.tv_sec = seconds;
	tv.tv_usec = microsecs;

	if ((select(filedes + 1, &rfds, NULL, NULL, &tv)) < 0)
		debug(ERROR, "system call", "select", 0);

	return FD_ISSET(filedes, &rfds);
}

void process_web_request(int descriptorFichero)
{	
	debug(LOG, "Request", "Ha llegado una petición.", descriptorFichero);

	//
	// Definir buffer y variables necesarias para leer las peticiones
	//
	
	char 	buffer[BUFSIZE + 1] = {0};	// Buffer donde se almacena la petición recibida
	struct 	Request *req;				// Estructura donde guardar los distintos campos de la petición
	long 	bytes_leidos;				// Bytes leídos de la petición
	long 	indice;						// Variable auxiliar para recorrer el buffer
	int 	fd;							// Descriptor para abrir los html

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
    	abrir_fichero(&fd, "formularios/400.html");        
        response(fd, descriptorFichero, "HTTP/1.1 400 Bad Request", "text/html");
		return;	
	}

	// 
	// Parsear la petición para obtener método y ruta del
	// fichero solicitado
	//
	
	req = parse_request(buffer);

	//
	// Devolvemos un error indicando que el método no está soportado
	// (No es un GET o un POST)
	//

	if (req->method == UNSUPPORTED) {
        abrir_fichero(&fd, "formularios/405.html");
		response(fd, descriptorFichero, "HTTP/1.1 405 Method Not Allowed", "text/html");
		return;
	}

    //
    // Gestión de cookies
    //

    char *match = "Cookie: cookie_counter=";
    char *contains_cookie = strstr(buffer, match);

    if (contains_cookie) {
        valor_cookie = (int) strtol(&contains_cookie[strlen(match)], (char **)NULL, 10);
        if (valor_cookie >= 10) {
            abrir_fichero(&fd, "formularios/429.html");
            response(fd, descriptorFichero, "HTTP/1.1 429 Too Many Requests", "text/html");
            exit(3);
        }
    }


	//
	// TRATAR LOS CASOS DE LOS DIFERENTES MÉTODOS QUE SE USAN
	// (Se soporta solo GET)
	//
	
	if (req->method == POST) {
		
		//
		// Obtener el correo que ha introducido el usuario
		//

		char *email_query = strstr(buffer, "email=");
		char *only_email = strremove(email_query, "email=");

		//
		// Comprobamos el email introducido en el formulario y devolvemos el
		// html correspondiente en función de si es correcto el correo o no
		//
		
		if (!strcmp(EMAIL, only_email))
			abrir_fichero(&fd, "formularios/correo_bien.html");
		else	
			abrir_fichero(&fd, "formularios/correo_mal.html");

		//
        // Enviar respuesta
		//

		response(fd, descriptorFichero, "HTTP/1.1 200 OK", "text/html");
	}

	else if (req->method == GET) {

		//
		// Como se trata el caso excepcional de la URL que no apunta a ningún
		// fichero html
		//

		if (strcmp(req->path, "/") == 0) {
			abrir_fichero(&fd, "formularios/index.html");
			response(fd, descriptorFichero, "HTTP/1.1 200 OK", "text/html");
		} 
		
		else {

			//
			// Cómo se trata el caso de acceso ilegal a directorios superiores
			// de la jerarquía de directorios del sistema
			//

			if (is_forbidden(req->path)) {		
                abrir_fichero(&fd, "formularios/403.html");
				response(fd, descriptorFichero, "HTTP/1.1 403 Forbidden", "text/html");
			}
			
			else {

				//
				// Evaluar el tipo de fichero que se está solicitando, y actuar en
				// consecuencia devolviéndolo si se soporta y devolviendo el error
				// correspondiente en otro caso
				//
					
				char *extension = strrchr(req->path, '.');

				//
				// Si el fichero solicitado no tiene extensión devolvemos el error correspondiente
				//
				
				if (!extension) {			
                    abrir_fichero(&fd, "formularios/400.html");
					response(fd, descriptorFichero, "HTTP/1.1 400 Bad Request", "text/html");
				}
				
				else {
					
					//
					// Comprobamos si la extensión que tiene el fichero solicitado está soportada
					// y devolvemos un error si no lo está
					//
					
					char *filetype = ext_to_filetype(extension);

					if (!filetype) {		
                        abrir_fichero(&fd, "formularios/415.html");
						response(fd, descriptorFichero, "HTTP/1.1 415 Unsupported Media Type", "text/html");	
					}
					
					else {
						
						//
						// En caso de que el fichero sea soportado, exista, etc. se envía el fichero con la
						// cabecera correspondiente, y el envio del fichero se hace en bloques de un máximo
						// de 8kB
						//

						if ((fd = open(req->path + 1, O_RDONLY)) < 0) {		
                            abrir_fichero(&fd, "formularios/404.html");
							response(fd, descriptorFichero, "HTTP/1.1 404 Not Found", "text/html");
						}
						else {
							response(fd, descriptorFichero, "HTTP/1.1 200 OK", filetype);
						}
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
	// int i;
	int port, pid, listenfd, socketfd;
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
	
	if (argv[1] == NULL || argv[2] == NULL) {
		(void)printf("ERROR: Argumentos no especificados. Uso: ./web_sstt <puerto> <directorio>\n");
		exit(4);
	}

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
	
    (void)printf("*> web server starting (port=%d)\n", port);
	
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
		
				// Mecanismo de persistencia HTTP.
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
