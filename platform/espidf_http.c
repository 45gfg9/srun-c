#include "compat.h"

#include <string.h>
#include <stdlib.h>
#include <esp_http_client.h>

char *request_get_body(const char *url) {
  char *response = NULL;
  esp_http_client_config_t config = {
      .url = url,
      .method = HTTP_METHOD_GET,
  };

  esp_http_client_handle_t client = esp_http_client_init(&config);
  if (esp_http_client_perform(client) == ESP_OK) {
    int content_length = esp_http_client_get_content_length(client);
    if (content_length > 0) {
      response = (char *)malloc(content_length + 1);
      if (response) {
        int read_len = esp_http_client_read_response(client, response, content_length);
        if (read_len >= 0) {
          response[read_len] = '\0';
        } else {
          free(response);
          response = NULL;
        }
      }
    }
  }

  esp_http_client_cleanup(client);
  return response;
}

char *request_get_location(const char *url) {
  char *response = NULL;
  esp_http_client_config_t config = {
      .url = url,
      .method = HTTP_METHOD_GET,
      .disable_auto_redirect = true,
  };

  esp_http_client_handle_t client = esp_http_client_init(&config);
  if (esp_http_client_perform(client) == ESP_OK) {
    int status_code = esp_http_client_get_status_code(client);
    if (status_code >= 300 && status_code < 400) {
      char *location = NULL;
      if (esp_http_client_get_header(client, "Location", &location) == ESP_OK && location) {
        response = strdup(location);
      }
    }
  }

  esp_http_client_cleanup(client);
  return response;
}
