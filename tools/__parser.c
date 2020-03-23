 #include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <regex.h>

int
compile_and_execute_regex(int _pmatch, int _nmatch, const char *token, const char *regex)
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
		
    if (!match)                     is_valid = 1;
    else if (match == REG_NOMATCH)  is_valid = 0;
	}	

  return is_valid;
}

int
is_valid_request(char *request)
{
    // 'request' points to a string literal, which cannot be modified
    // (as strtok would like to do), so we make a modifiable copy.
    char *request_copy = strdup(request);

    // Regular expressions to validate headers
    const char *main_header_regex = "^([A-Za-z]+)(\\s+)(/.*)(\\s+)(HTTP/1.1)";
    const char *other_headers_regex = "^(.*)(:)(\\s+)(.*)";
    const char *email_query_regex = "^(.*)(=)(.*)";

    // Check if first line is valid ('XXXX /zzzz HTTP/1.1')
    char *token;
    token = strtok(request_copy, "\r\n");

    if (!compile_and_execute_regex(6, 6, token, main_header_regex))
        return 0;

    while (token != NULL) {
        // Check if current line is valid or not.
        token = strtok(NULL, "\r\n");
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
    return 1;
}

int
main(int argc, char **argv) 
{

    char *request = "GET /logo-um.jpg HTTP/1.1\r\n"
                    "Host: 192.168.56.101:8080\r\n"
                    "Connection: keep-alive\r\n"
                    "Cache-Control: max-age=0\r\n"
                    "Upgrade-Insecure-Requests: 1\r\n"
                    "User-Agent: Mozilla/5.0 (X11; rv:47.0) Gecko/20100101 Firefox/47.0\r\n"
                    "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                    "Accept-Language: en-US,en;q=0.5\r\n"
                    "Accept-Encoding: gzip, deflate\r\n"
                    "email=joseantonio.pastor%40.um.es\r\n"
                    "\r\n";

  (is_valid_request(request) ? printf("Valid!\n") : printf("Invalid!\n"));
  return 0;
}
