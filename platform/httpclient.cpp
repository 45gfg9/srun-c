#include "compat.h"

#include <HTTPClient.h>

char *request_get(const char *url) {
  char *response = nullptr;
  HTTPClient http;
  http.begin(url);
  int httpCode = http.GET();
  if (httpCode > 0) {
    String payload = http.getString();
    response = strdup(payload.c_str());
  }
  http.end();
  return response;
}
