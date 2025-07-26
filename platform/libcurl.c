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
#include <unistd.h>
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

static size_t curl_ptr_writefunc(char *ptr, size_t size, size_t nmemb, void *userdata) {
  struct curl_string *s = userdata;
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

static size_t curl_null_writefunc(char *ptr, size_t size, size_t nmemb, void *userdata) {
  (void)ptr;
  (void)userdata;
  return size * nmemb;
}

static char *write_cert_to_tempfile(const char *cert_pem) {
  const char *tmpdir = getenv("TMPDIR");
  if (!tmpdir) {
    tmpdir = "/tmp";
  }

  char *template;
  if (asprintf(&template, "%s/certXXXXXX", tmpdir) == -1) {
    return NULL;
  }

  int fd = mkstemp(template);
  if (fd == -1) {
    free(template);
    return NULL;
  }

  ssize_t written = write(fd, cert_pem, strlen(cert_pem));
  close(fd);

  if (written != (ssize_t)strlen(cert_pem)) {
    unlink(template);
    free(template);
    return NULL;
  }

  return template; // Caller must unlink() and free()
}

char *request_get_body(const srun_handle handle, const char *url) {
  CURL *curl_handle = curl_easy_init();
  if (!curl_handle) {
    // https://curl.se/libcurl/c/curl_easy_init.html
    // curl_easy_init is unlikely to fail
    errno = EAGAIN; // resource temporarily unavailable
    return NULL;
  }

  struct curl_string resp_string;
  init_string(&resp_string);

  curl_easy_setopt(curl_handle, CURLOPT_URL, url);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, curl_ptr_writefunc);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &resp_string);

  if (handle->verbosity >= SRUN_VERBOSITY_DEBUG) {
    curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);
  }

  char *cert_path = NULL;
  if (handle->cert_pem) {
    cert_path = write_cert_to_tempfile(handle->cert_pem);
    if (!cert_path) {
      curl_easy_cleanup(curl_handle);
      errno = EINVAL;
      return NULL;
    }
    srun_log_debug(handle->verbosity, "Certificate written to %s\n", cert_path);
    curl_easy_setopt(curl_handle, CURLOPT_CAINFO, cert_path);
  }

  CURLcode res = curl_easy_perform(curl_handle);
  curl_easy_cleanup(curl_handle);

  if (cert_path) {
    unlink(cert_path);
    free(cert_path);
  }

  if (res != CURLE_OK) {
    srun_log_error("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    free(resp_string.ptr);
    errno = EIO; // I/O error
    return NULL;
  }

  return resp_string.ptr;
}

char *request_get_location(const srun_handle handle, const char *url) {
  CURL *curl_handle = curl_easy_init();
  if (!curl_handle) {
    errno = EAGAIN; // resource temporarily unavailable
    return NULL;
  }

  curl_easy_setopt(curl_handle, CURLOPT_URL, url);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, curl_null_writefunc);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, NULL);

  if (handle->verbosity >= SRUN_VERBOSITY_DEBUG) {
    curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);
  }

  char *cert_path = NULL;
  if (handle->cert_pem) {
    cert_path = write_cert_to_tempfile(handle->cert_pem);
    if (!cert_path) {
      curl_easy_cleanup(curl_handle);
      errno = EIO;
      return NULL;
    }
    srun_log_debug(handle->verbosity, "Certificate written to %s\n", cert_path);
    curl_easy_setopt(curl_handle, CURLOPT_CAINFO, cert_path);
  }

  char *location = NULL;
  CURLcode res = curl_easy_perform(curl_handle);
  if (res == CURLE_OK) {
    res = curl_easy_getinfo(curl_handle, CURLINFO_REDIRECT_URL, &location);
    if (res == CURLE_OK) {
      if (location && location[0]) {
        location = strdup(location);
      }
    } else {
      srun_log_error("curl_easy_getinfo() failed: %s\n", curl_easy_strerror(res));
    }
  } else {
    srun_log_error("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
  }

  curl_easy_cleanup(curl_handle);
  if (cert_path) {
    unlink(cert_path);
    free(cert_path);
  }
  return location;
}
