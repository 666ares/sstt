#include <stdio.h>
#include <string.h>

int main(void) {
  char *req = "GET / HTTP/1.1\r\nHost:web.sstt5819.org\r\n\r\n";

  size_t len = strcspn(req, "\r");

  char header[len];
  char others[strlen(req) - len];
  header[len] = '\0';
  others[strlen(req) - len] = '\0';

  memcpy(header, req, len);
  printf("%s\n", header);
  
  memcpy(others, req + len, strlen(req) - len); 

  char *pedazos[10];
  int i = 0;

  pedazos[i] = strtok(others, "\r\n");
  
  while (pedazos[i] != NULL)
    pedazos[++i] = strtok(NULL, "\r\n");

  int j = 0;
  while (pedazos[j] != NULL)
    printf("%s\n", pedazos[j++]);

  return 0;
}
