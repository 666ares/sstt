#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef enum Method {UNSUPPORTED, GET, POST} Method;

typedef struct Header {
	char *name;
	char *value;
	struct Header *next;
} Header;

typedef struct Request {
	enum Method method;
	char *url;
	struct Header *headers;
} Request;

struct Request *parse_request(const char *raw);

struct Request
*parse_request(const char *raw)
{
	struct Request *req = NULL;
	req = malloc(sizeof(struct Request));
	memset(req, 0, sizeof(struct Request));

	// Method
    	size_t meth_len = strcspn(raw, " ");

	if (meth_len != 3 || meth_len != 4) {
		printf("Falta un espacio entre el método y la ruta.\n");
		exit(1);
	}


    	if (memcmp(raw, "GET", strlen("GET")) == 0) {
        	req->method = GET;
    	} else if (memcmp(raw, "POST", strlen("POST")) == 0) {
        	req->method = POST;
    	} else {
        	req->method = UNSUPPORTED;
    	}

    	raw += meth_len + 1; // move past <SP>

    	// Request-URI
    	size_t url_len = strcspn(raw, " ");
    	req->url = malloc(url_len + 1);
    	if (!req->url) {
        	return NULL;
    	}
    	memcpy(req->url, raw, url_len);
    	req->url[url_len] = '\0';
    	
	if (raw[url_len] != ' ') {
		printf("Falta un espacio entre la ruta y la versión.\n");
		exit(1);
	}

	raw += url_len + 1; // move past <SP>

    	// raw += ver_len + 2; // move past <CR><LF>

    	struct Header *header = NULL, *last = NULL;
    	while (raw[0]!='\r' || raw[1]!='\n') {
        	last = header;
        	header = malloc(sizeof(Header));
        	if (!header) {
            		return NULL;
        	}

        	// name
        size_t name_len = strcspn(raw, ":");
        header->name = malloc(name_len + 1);
        if (!header->name) {
            return NULL;
        }
        memcpy(header->name, raw, name_len);
        header->name[name_len] = '\0';
        raw += name_len + 1; // move past :
        while (*raw == ' ') {
            raw++;
        }

        // value
        size_t value_len = strcspn(raw, "\r\n");
        header->value = malloc(value_len + 1);
        if (!header->value) {
            return NULL;
        }
        memcpy(header->value, raw, value_len);
        header->value[value_len] = '\0';
        raw += value_len + 2; // move past <CR><LF>

        // next
        header->next = last;
    }
    req->headers = header;
    raw += 2; // move past <CR><LF>


    return req;
}

int main(void) {
    char *raw_request = "GET / HTTP/1.1\r\n"
            "Host: localhost:8080\r\n"
            "\r\n";

    struct Request *req = parse_request(raw_request);
    if (req) {
        printf("Method: %d\n", req->method);
        printf("Request-URI: %s\n", req->url);
        puts("Headers:");
        struct Header *h;
        for (h=req->headers; h; h=h->next) {
            printf("%32s: %s\n", h->name, h->value);
        }
    }
    return 0;
}
