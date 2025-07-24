/* Copyright © 2023-2025 45gfg9 <45gfg9@45gfg9.net>
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the LICENSE file for more details.
 */

#include "compat.h"

// Currently we just reuse ESP32 and ESP8266 code for as much as possible.
// If two APIs ever deviate too much, we do separate handling then.

#if ESP8266
#include <ESP8266HTTPClient.h>
#else
#include <HTTPClient.h>
#endif

char *request_get_body(const char *url) {
  char *response = nullptr;
  HTTPClient http;

#if ESP8266
  WiFiClient client;
  http.begin(client, url);
#else
  http.begin(url);
#endif

  int httpCode = http.GET();
  if (httpCode > 0) {
    String payload = http.getString();
    response = strdup(payload.c_str());
  }
  http.end();
  return response;
}

char *request_get_location(const char *url) {
  char *response = nullptr;
  HTTPClient http;

#if ESP8266
  WiFiClient client;
  http.begin(client, url);
#else
  http.begin(url);
#endif

  int httpCode = http.GET();
  if (httpCode >= 300 && httpCode < 400) {
    String location = http.getLocation();
    if (!location.isEmpty()) {
      response = strdup(location.c_str());
    }
  }
  http.end();
  return response;
}
