/* Copyright © 2023-2025 45gfg9 <45gfg9@45gfg9.net>
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the LICENSE file for more details.
 */

#include "compat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <curl/curl.h>

struct curl_string {
  char *ptr;
  size_t len;
};

static void init_curl(void) __attribute__((constructor));
static void init_curl(void) {
  curl_global_init(CURL_GLOBAL_DEFAULT);
}

static void cleanup_curl(void) __attribute__((destructor));
static void cleanup_curl(void) {
  curl_global_cleanup();
}

static void init_string(struct curl_string *s) {
  s->len = 0;
  s->ptr = calloc(1, 1); // initial null-terminated string
}

static size_t writefunc(char *ptr, size_t size, size_t nmemb, struct curl_string *s) {
  size_t new_len = s->len + size * nmemb;
  char *new_ptr = realloc(s->ptr, new_len + 1);
  if (new_ptr == NULL) {
    errno = ENOMEM;
    return 0; // cause curl to fail
  }

  s->ptr = new_ptr;
  memcpy(s->ptr + s->len, ptr, size * nmemb);
  s->ptr[new_len] = '\0';
  s->len = new_len;

  return size * nmemb;
}

char *request_get_body(const char *url) {
  CURL *curl_handle = curl_easy_init();
  if (!curl_handle) {
    // https://curl.se/libcurl/c/curl_easy_init.html
    // curl_easy_init is unlikely to fail
    errno = EAGAIN; // resource temporarily unavailable
    goto end;
  }

  struct curl_string resp_string;
  init_string(&resp_string);

  curl_easy_setopt(curl_handle, CURLOPT_URL, url);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, writefunc);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &resp_string);

  CURLcode res = curl_easy_perform(curl_handle);
  curl_easy_cleanup(curl_handle);
  if (res != CURLE_OK) {
    fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    errno = EIO; // I/O error
    goto end;
  }

  return resp_string.ptr;

end:
  free(resp_string.ptr);
  return NULL;
}
