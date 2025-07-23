#include "compat.h"
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>

int parse_chal_response(struct chal_response *response, const char *json) {
  cJSON *root = cJSON_Parse(json);
  if (!root) {
    errno = EINVAL; // Invalid JSON format
    return -1;
  }

  cJSON *challenge = cJSON_GetObjectItem(root, "challenge");
  cJSON *client_ip = cJSON_GetObjectItem(root, "client_ip");

  if (!cJSON_IsString(challenge) || !cJSON_IsString(client_ip)) {
    cJSON_Delete(root);
    errno = EINVAL; // Missing or invalid fields
    return -1;
  }

  response->challenge = strdup(challenge->valuestring);
  response->client_ip = strdup(client_ip->valuestring);

  cJSON_Delete(root);
  return 0;
}

char *create_info_field(srun_handle handle) {
  cJSON *info = cJSON_CreateObject();
  if (!info) {
    errno = ENOMEM;
    return NULL;
  }

  cJSON_AddStringToObject(info, "username", handle->username);
  cJSON_AddStringToObject(info, "password", handle->password);
  cJSON_AddStringToObject(info, "ip", handle->client_ip);
  cJSON_AddNumberToObject(info, "acid", handle->ac_id);
  cJSON_AddStringToObject(info, "enc_ver", "srun_bx1");

  char *info_str = cJSON_PrintUnformatted(info);
  cJSON_Delete(info);

  if (!info_str) {
    errno = ENOMEM;
  }
  return info_str;
}
