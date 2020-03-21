#include <stdio.h>
#include <stdlib.h>
#include <regex.h>

int
main(void)
{
	int match;
	int err;
	regex_t preg;
	regmatch_t pmatch[6];
	size_t nmatch = 6;
	const char *str_request = "GET /index.html HTTP/1.1\r\n";
	const char *str_regex = "^([GET|POST]+)(\\s+)(/.*)(\\s+)(HTTP/1.1\r\n)";
	err = regcomp(&preg, str_regex, REG_EXTENDED);
	if (err == 0) {
		match = regexec(&preg, str_request, nmatch, pmatch, 0);
		nmatch = preg.re_nsub;
		regfree(&preg);
		
		if (match == 0) {
			printf("\"%.*s\"\n", pmatch[1].rm_eo - pmatch[1].rm_so,
					      &str_request[pmatch[1].rm_so]);
			printf("\"%.*s\"\n", pmatch[2].rm_eo - pmatch[2].rm_so,
					      &str_request[pmatch[2].rm_so]);
			printf("\"%.*s\"\n", pmatch[3].rm_eo - pmatch[3].rm_so,
					      &str_request[pmatch[3].rm_so]);
			printf("\"%.*s\"\n", pmatch[4].rm_eo - pmatch[4].rm_so,
					      &str_request[pmatch[4].rm_so]);
 			printf("\"%.*s\"\n", pmatch[5].rm_eo - pmatch[5].rm_so,
					      &str_request[pmatch[5].rm_so]);
		} else if (match == REG_NOMATCH) {
			printf("unmatch\n");
		}
	}
	return 0;
}
