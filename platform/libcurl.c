#include "compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <curl/curl.h>

static void init_curl(void) __attribute__((constructor));
static void init_curl(void) {
  curl_global_init(CURL_GLOBAL_DEFAULT);
}

char *request_get(const char *url) {
  FILE *resp_file = tmpfile();
  if (!resp_file) {
    return NULL;
  }

  char *resp_buf = NULL;

  CURL *curl_handle = curl_easy_init();
  if (!curl_handle) {
    // https://curl.se/libcurl/c/curl_easy_init.html
    // curl_easy_init is unlikely to fail
    errno = EAGAIN; // resource temporarily unavailable
    goto end;
  }

  curl_easy_setopt(curl_handle, CURLOPT_URL, url);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, resp_file);

  CURLcode res = curl_easy_perform(curl_handle);
  curl_easy_cleanup(curl_handle);
  if (res != CURLE_OK) {
    errno = EIO; // I/O error
    goto end;
  }

  long resp_size = ftell(resp_file);
  resp_buf = malloc(resp_size + 1);
  if (!resp_buf) {
    errno = ENOMEM; // out of memory
    goto end;
  }

  rewind(resp_file);
  fread(resp_buf, 1, resp_size, resp_file);
  resp_buf[resp_size] = '\0';

end:
  fclose(resp_file);
  return resp_buf;
}
