#include <stdio.h>
#include <stdlib.h>
#include <regex.h>
#include <string.h>

int
check_bad_request(const char *request)
{
    /* Flag para indicar si la petición está bien formada o no. */
    int mal_formada = 0;

    /* Obtenemos la primera línea de la petición ('GET / HTTP/1.1') */
    size_t len = strcspn(request, "\r");
    char primera_linea[len];
    primera_linea[len] = '\0';
    memcpy(primera_linea, request, len);

    /* Obtener el resto de cabeceras... */
    char otras[strlen(request) - len];
    otras[strlen(request) - len] = '\0';
    memcpy(otras, request + len, strlen(request) - len);

    char *pedazos[10];
    int i = 0;
    pedazos[i] = strtok(otras, "\r\n");

    while (pedazos[i] != NULL)
        pedazos[++i] = strtok(NULL, "\r\n");

    /*    */

    int match, err;
    regex_t preg;
    regmatch_t pmatch[6];
    size_t nmatch = 6;
    
    const char *main_header_regex   = "^([A-Za-z]+)(\\s+)(/.*)(\\s+)(HTTP/1.1)";
    const char *other_headers_regex = "^([A-Za-z]+)(:)(\\s+)([A-Za-z]+)";

    err = regcomp(&preg, main_header_regex, REG_EXTENDED);

    if (err == 0) {
        match = regexec(&preg, primera_linea, nmatch, pmatch, 0);
        nmatch = preg.re_nsub;
        regfree(&preg);

        if (match == REG_NOMATCH) mal_formada = 1;
    }

    regmatch_t pmatch2[5];
    nmatch = 5;
    int j = 0;

    err = regcomp(&preg, other_headers_regex, REG_EXTENDED);

    if (err == 0) {
        while (pedazos[j] != NULL) {
            match = regexec(&preg, pedazos[j], nmatch, pmatch2, 0);
            nmatch = preg.re_nsub;
            regfree(&preg);
            
            if (match == REG_NOMATCH) mal_formada = 1;
            j++;
        }
    }

    return mal_formada;
}

int
main(void)
{
    
    // const char *request = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const char *request = "GET / HTTP/1.1\r\nHost:localhost\r\n\r\n";    

    int ret = check_bad_request(request);

    if (!ret)
        printf("Bien formada.\n");
    else
        printf("Mal formada.\n");


	return 0;





}
