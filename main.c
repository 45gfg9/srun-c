/* Copyright © 2023-2025 45gfg9 <45gfg9@45gfg9.net>
 * This work is free. You can redistribute it and/or modify it under the
 * terms of the Do What The Fuck You Want To Public License, Version 2,
 * as published by Sam Hocevar. See the LICENSE file for more details.
 */

#include "srun_config.h"

#include "srun.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include <sys/wait.h>

#if defined __APPLE__
#include <readpassphrase.h>
#elif defined(__has_include) && __has_include(<bsd/readpassphrase.h>)
#include <bsd/readpassphrase.h>
#else
#warning "libbsd not found, will use potentially insecure fallback implementation"
#define RPP_ECHO_ON 1
#define RPP_ECHO_OFF 0
static inline char *readpassphrase(const char *prompt, char *buf, size_t bufsiz, int flags) {
  if (!bufsiz) {
    errno = EINVAL;
    return NULL;
  }

  buf[0] = '\0';
  if (flags & RPP_ECHO_ON) {
    fprintf(stderr, "%s", prompt);
    fflush(stderr);
    if (!fgets(buf, bufsiz, stdin)) {
      return NULL;
    }
    buf[strcspn(buf, "\n")] = '\0';
  } else {
    char *pass = getpass(prompt);
    if (!pass) {
      return NULL;
    }

    strncpy(buf, pass, bufsiz - 1);
    buf[bufsiz - 1] = '\0';
    memset(pass, 0, strlen(pass));
  }
  return buf;
}
#endif

#ifdef SRUN_GIT_HASH
#define GIT_HASH_STR " (" SRUN_GIT_HASH ")"
#else
#define GIT_HASH_STR ""
#endif

enum {
  ACTION_LOGIN,
  ACTION_LOGOUT,
};

static const char *prog_name;

static struct cli_opts {
  char *host;
  char *username;
  char *password;
  char *ip;

  char *cert_pem;
  int ac_id;

  enum srun_verbosity verbosity;
} opts;

static void print_version(void) {
  printf("Version: %s " SRUN_VERSION GIT_HASH_STR ", Built on " SRUN_BUILD_TIME ".\n", prog_name);

  puts("Default configurations:");

#ifdef SRUN_CONF_HOST
  puts("  URL: " SRUN_CONF_HOST);
#else
  puts("  URL: (not set)");
#endif
#ifdef SRUN_CONF_USERNAME
  puts("  username: " SRUN_CONF_USERNAME);
#else
  puts("  username: (not set)");
#endif
#ifdef SRUN_CONF_PASSWORD
  puts("  password: (set)");
#else
  puts("  password: (not set)");
#endif
#ifdef SRUN_CONF_IP
  puts("  client IP: " SRUN_CONF_IP);
#else
  puts("  client IP: (not set)");
#endif
#ifdef SRUN_CONF_AC_ID
  printf("  ac_id: %d\n", SRUN_CONF_AC_ID);
#else
  puts("  ac_id: (not set)");
#endif
#ifdef SRUN_CONF_CERT_PEM
  pid_t openssl_pid = fork();
  if (openssl_pid == -1) {
    perror("fork");
  } else if (openssl_pid == 0) {
    int pipefd[2];
    pipe(pipefd);
    write(pipefd[1], SRUN_CONF_CERT_PEM, sizeof SRUN_CONF_CERT_PEM - 1);
    close(pipefd[1]);
    dup2(pipefd[0], STDIN_FILENO);
    close(pipefd[0]);
    execlp("openssl", "openssl", "x509", "-noout", "-text", NULL);
    puts("openssl not found in PATH; skipping certificate info.");
    exit(EXIT_SUCCESS);
  } else {
    int status;
    waitpid(openssl_pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
      fprintf(stderr, "openssl exited with status %d\n", status);
    }
  }
#else
  puts("CA certificate: (not set)");
#endif
}

static void print_help(void) {
  print_version();
  printf("\nUsage: %s <login | logout> [options]\n", prog_name);
  puts("Options:");
  puts("  -h, --help");
  puts("          print this help message and exit");
  puts("  -f, --config=FILE");
  puts("          read options from FILE in JSON format");
  puts("  -H, --host=HOST");
  puts("          use HOST as the authentication server");
  puts("          HOST should not include any path");
  puts("  -u, --username=USERNAME");
  puts("          use USERNAME to login");
  puts("  -p, --password=PASSWORD");
  puts("          use PASSWORD to login");
  puts("          If not specified, the program will ask interactively");
  puts("          Password without username is not allowed and is ignored");
  puts("  -a, --ac-id=ID");
  puts("          use ID as ac_id for the login request");
  puts("          If not specified, try to guess from the authentication server");
  puts("  -i, --ip=IP");
  puts("          use IP as the client IP");
  puts("  -c, --cert-file=FILE");
  puts("          use FILE as the PEM certificate");
  puts("  -q, --quiet");
  puts("          suppress standard output");
  puts("  -v, --verbose");
  puts("          enable verbose output to stderr");
  puts("          Can be specified multiple times to increase verbosity, maximum is 2");
  puts("  -V, --version");
  puts("          print version information and exit");
}

static char *read_cert_file(const char *path) {
  FILE *f = fopen(path, "r");
  if (!f) {
    perror(prog_name);
    return NULL;
  }
  free(opts.cert_pem);

  // read file contents
  fseek(f, 0, SEEK_END);
  size_t file_size = ftell(f);
  rewind(f);
  opts.cert_pem = malloc(file_size + 1);
  if (!opts.cert_pem) {
    perror(prog_name);
    fclose(f);
    return NULL;
  }
  size_t bytes_read = fread(opts.cert_pem, 1, file_size, f);
  opts.cert_pem[bytes_read] = '\0';
  fclose(f);

  char *cert_begin = strstr(opts.cert_pem, "-----BEGIN CERTIFICATE-----");
  char *cert_end = NULL;
  if (cert_begin) {
    cert_end = strstr(cert_begin, "-----END CERTIFICATE-----");
  }

  if (!cert_begin || !cert_end) {
    fprintf(stderr, "Invalid certificate file: %s\n", path);
    free(opts.cert_pem);
    opts.cert_pem = NULL;
    return NULL;
  }
  if (cert_begin != opts.cert_pem) {
    size_t cert_len = strlen(cert_begin);
    memmove(opts.cert_pem, cert_begin, cert_len);
    opts.cert_pem[cert_len] = '\0';
  }

  return opts.cert_pem;
}

static void parse_opt(int argc, char *const *argv) {
  static const struct option LONG_OPTS[] = {
      {"help", no_argument, NULL, 'h'},
      {"host", required_argument, NULL, 'H'},
      {"username", required_argument, NULL, 'u'},
      {"password", required_argument, NULL, 'p'},
      {"ac-id", required_argument, NULL, 'a'},
      {"ip", required_argument, NULL, 'i'},
      {"cert-file", required_argument, NULL, 'c'},
      {"quiet", no_argument, NULL, 'q'},
      {"verbose", no_argument, NULL, 'v'},
      {"version", no_argument, NULL, 'V'},
      {0},
  };
  static const char SHORT_OPTS[] = "hH:u:p:a:i:c:qvV";

  int c;
  while ((c = getopt_long(argc, argv, SHORT_OPTS, LONG_OPTS, NULL)) != -1) {
    switch (c) {
      case 'h':
        print_help();
        exit(EXIT_SUCCESS);
      case 'H':
        free(opts.host);
        opts.host = strdup(optarg);
        break;
      case 'u':
        free(opts.username);
        opts.username = strdup(optarg);
        break;
      case 'p':
        free(opts.password);
        opts.password = strdup(optarg);
        break;
      case 'a':
        opts.ac_id = (int)strtol(optarg, NULL, 0);
        break;
      case 'i':
        free(opts.ip);
        opts.ip = strdup(optarg);
        break;
      case 'c':
        read_cert_file(optarg);
        break;
      case 'q':
        opts.verbosity = SRUN_VERBOSITY_SILENT;
        break;
      case 'v':
        if (opts.verbosity < SRUN_VERBOSITY_VERBOSE) {
          opts.verbosity = SRUN_VERBOSITY_VERBOSE;
        } else {
          opts.verbosity = SRUN_VERBOSITY_DEBUG;
        }
        break;
      case 'V':
        print_version();
        exit(EXIT_SUCCESS);
      default:
        fprintf(stderr, "Try `%s --help' for more information.\n", prog_name);
        exit(EXIT_FAILURE);
    }
  }
}

static int perform_login(srun_handle handle) {
  if (!opts.username || opts.username[0] == '\0') {
    // can't set password without username
    free(opts.password);
    opts.password = NULL;

    char rpp_buffer[512];
    readpassphrase("Username: ", rpp_buffer, sizeof rpp_buffer, RPP_ECHO_ON);
    srun_setopt(handle, SRUNOPT_USERNAME, rpp_buffer);
  }

  if (!opts.password || opts.password[0] == '\0') {
    char rpp_buffer[512];
    readpassphrase("Password: ", rpp_buffer, sizeof rpp_buffer, RPP_ECHO_OFF);
    srun_setopt(handle, SRUNOPT_PASSWORD, rpp_buffer);
  }

  int result = srun_login(handle);
  if (result == SRUNE_OK) {
    printf("Successfully logged in.\n");
  } else {
    printf("Login failed: error %d\n", result);
    if (result == SRUNE_SYSTEM && errno) {
      perror(prog_name);
    }
  }
  return result;
}

static int perform_logout(srun_handle handle) {
  if (!opts.username || opts.username[0] == '\0') {
    char rpp_buffer[512];
    readpassphrase("Username: ", rpp_buffer, sizeof rpp_buffer, RPP_ECHO_ON);
    srun_setopt(handle, SRUNOPT_USERNAME, rpp_buffer);
  }

  int result = srun_logout(handle);
  if (result == SRUNE_OK) {
    printf("Successfully logged out.\n");
  } else {
    printf("Logout failed: error %d\n", result);
    if (result == SRUNE_SYSTEM && errno) {
      perror(prog_name);
    }
  }
  return result;
}

int main(int argc, char **argv) {
  int retval = EXIT_FAILURE;
  prog_name = basename(argv[0]);

  if (argc == 1) {
    goto no_action;
  }

  // provide default values
  opts.verbosity = SRUN_VERBOSITY_NORMAL;
  opts.ac_id = SRUN_AC_ID_UNKNOWN;
#ifdef SRUN_CONF_HOST
  opts.host = strdup(SRUN_CONF_HOST);
#endif
#ifdef SRUN_CONF_USERNAME
  opts.username = strdup(SRUN_CONF_USERNAME);
#endif
#ifdef SRUN_CONF_PASSWORD
  opts.password = strdup(SRUN_CONF_PASSWORD);
#endif
#ifdef SRUN_CONF_IP
  opts.ip = strdup(SRUN_CONF_IP);
#endif
#ifdef SRUN_CONF_CERT_PEM
  opts.cert_pem = strdup(SRUN_CONF_CERT_PEM);
#endif
#ifdef SRUN_CONF_AC_ID
  opts.ac_id = SRUN_CONF_AC_ID;
#endif

  const char *action_str = argv[1];

  parse_opt(argc, argv);

  if (opts.verbosity == SRUN_VERBOSITY_SILENT && freopen("/dev/null", "w", stdout) == NULL) {
    fprintf(stderr, "Failed to redirect stdout to /dev/null: %s\n", strerror(errno));
    goto exit_cleanup;
  }

  int action;
  if (strcmp(action_str, "login") == 0) {
    action = ACTION_LOGIN;
  } else if (strcmp(action_str, "logout") == 0) {
    action = ACTION_LOGOUT;
  } else {
    fprintf(stderr, "Invalid action: %s\n", action_str);
no_action:
    fprintf(stderr, "Please specify action: login or logout.\n");
help_guide:
    fprintf(stderr, "Try `%s --help' for more information.\n", prog_name);
    goto exit_cleanup;
  }

  if (!(opts.host && opts.host[0])) {
    fprintf(stderr, "Missing fields for %s.\n", action_str);
    goto help_guide;
  }

  srun_handle handle = srun_create();

  srun_setopt(handle, SRUNOPT_HOST, opts.host);
  srun_setopt(handle, SRUNOPT_AC_ID, opts.ac_id);
  if (opts.username && opts.username[0]) {
    srun_setopt(handle, SRUNOPT_USERNAME, opts.username);
  }
  if (opts.password && opts.password[0]) {
    srun_setopt(handle, SRUNOPT_PASSWORD, opts.password);
  }
  if (opts.ip && opts.ip[0]) {
    srun_setopt(handle, SRUNOPT_IP, opts.ip);
  }
  if (opts.cert_pem && opts.cert_pem[0]) {
    srun_setopt(handle, SRUNOPT_CACERT, opts.cert_pem);
  }
  srun_setopt(handle, SRUNOPT_VERBOSITY, opts.verbosity);

  if (action == ACTION_LOGIN) {
    retval = perform_login(handle) != SRUNE_OK;
  } else if (action == ACTION_LOGOUT) {
    retval = perform_logout(handle) != SRUNE_OK;
  }

  srun_cleanup(handle);
  handle = NULL;

exit_cleanup:
  free(opts.host);
  free(opts.username);
  free(opts.password);
  free(opts.ip);
  free(opts.cert_pem);
  memset(&opts, 0, sizeof opts);

  return retval;
}
