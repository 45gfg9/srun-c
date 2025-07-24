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
#include <signal.h>
#include <sys/wait.h>

#if defined __APPLE__
#include <readpassphrase.h>
#else
#include <bsd/readpassphrase.h>
#include <bsd/string.h>
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

static struct {
  char *auth_server;
  char *client_ip;
  char *username;
  char *password;

  char *cert_pem;
  int ac_id;

  enum srun_verbosity verbosity;
} cli_args;

static void print_version(void) {
  printf("Version: %s " SRUN_VERSION GIT_HASH_STR ", Built on " SRUN_BUILD_TIME ".\n", prog_name);
  puts("Default configurations:");
#ifdef SRUN_CONF_AUTH_URL
  puts("  auth server URL: " SRUN_CONF_AUTH_URL);
#endif
#ifdef SRUN_CONF_DEFAULT_USERNAME
  puts("  username: " SRUN_CONF_DEFAULT_USERNAME);
#endif
#ifdef SRUN_CONF_DEFAULT_PASSWORD
  puts("  password set.");
#endif
#ifdef SRUN_CONF_DEFAULT_CLIENT_IP
  puts("  Default client IP: " SRUN_CONF_DEFAULT_CLIENT_IP);
#endif
#ifdef SRUN_CONF_DEFAULT_CERT
  pid_t openssl_pid = fork();

  if (openssl_pid == -1) {
    perror("fork");
  } else if (openssl_pid == 0) {
    puts("CA certificate info:");
    int pipefd[2];
    pipe(pipefd);
    write(pipefd[1], SRUN_CONF_DEFAULT_CERT, sizeof SRUN_CONF_DEFAULT_CERT);
    close(pipefd[1]);
    dup2(pipefd[0], STDIN_FILENO);
    close(pipefd[0]);
    execlp("openssl", "openssl", "x509", "-noout", "-subject", "-issuer", "-dates", "-fingerprint", NULL);
    puts("openssl not found in PATH; skipping certificate info.");
    exit(EXIT_SUCCESS);
  } else {
    int status;
    waitpid(openssl_pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
      fprintf(stderr, "openssl exited with status %d\n", status);
      exit(EXIT_FAILURE);
    }
  }
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
  puts("  -s, --auth-server=HOST");
  puts("          use HOST as the authentication server");
  puts("  -u, --username=USERNAME");
  puts("          use USERNAME to login");
  puts("  -p, --password=PASSWORD");
  puts("          use PASSWORD to login");
  puts("          If not specified, the program will ask interactively");
  puts("          Password without username is not allowed and is ignored");
  puts("  -a, --ac-id=ID");
  puts("          use ID as ac_id for the login request");
  puts("          If not specified, try to guess from the authentication server");
  puts("  -i, --client-ip=IP");
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
  free(cli_args.cert_pem);

  // read file contents
  fseek(f, 0, SEEK_END);
  size_t file_size = ftell(f);
  rewind(f);
  cli_args.cert_pem = malloc(file_size + 1);
  if (!cli_args.cert_pem) {
    perror(prog_name);
    fclose(f);
    return NULL;
  }
  fread(cli_args.cert_pem, 1, file_size, f);
  fclose(f);

  char *cert_begin = strstr(cli_args.cert_pem, "-----BEGIN CERTIFICATE-----");
  if (!cert_begin) {
    fprintf(stderr, "Invalid certificate file: %s\n", path);
    free(cli_args.cert_pem);
    cli_args.cert_pem = NULL;
    return NULL;
  }
  if (cert_begin != cli_args.cert_pem) {
    size_t cert_len = strlen(cert_begin);
    memmove(cli_args.cert_pem, cert_begin, cert_len);
    cli_args.cert_pem[cert_len] = '\0';
  }

  return cli_args.cert_pem;
}

static void parse_opt(int argc, char *const *argv) {
  static const struct option LONG_OPTS[] = {
      {"help", no_argument, NULL, 'h'},
      {"auth-server", required_argument, NULL, 's'},
      {"username", required_argument, NULL, 'u'},
      {"password", required_argument, NULL, 'p'},
      {"ac-id", required_argument, NULL, 'a'},
      {"client-ip", required_argument, NULL, 'i'},
      {"cert-file", required_argument, NULL, 'c'},
      {"quiet", no_argument, NULL, 'q'},
      {"verbose", no_argument, NULL, 'v'},
      {"version", no_argument, NULL, 'V'},
      {},
  };
  static const char *const SHORT_OPTS = "hs:u:p:a:i:c:qvV";

  int c;
  while ((c = getopt_long(argc, argv, SHORT_OPTS, LONG_OPTS, NULL)) != -1) {
    switch (c) {
      case 'h':
        print_help();
        exit(EXIT_SUCCESS);
      case 's':
        free(cli_args.auth_server);
        cli_args.auth_server = strdup(optarg);
        break;
      case 'u':
        free(cli_args.username);
        cli_args.username = strdup(optarg);
        break;
      case 'p':
        free(cli_args.password);
        cli_args.password = strdup(optarg);
        break;
      case 'a':
        cli_args.ac_id = (int)strtol(optarg, NULL, 0);
        break;
      case 'i':
        free(cli_args.client_ip);
        cli_args.client_ip = strdup(optarg);
        break;
      case 'c':
        read_cert_file(optarg);
        break;
      case 'q':
        cli_args.verbosity = SRUN_VERBOSITY_SILENT;
        break;
      case 'v':
        if (cli_args.verbosity < SRUN_VERBOSITY_VERBOSE) {
          cli_args.verbosity = SRUN_VERBOSITY_VERBOSE;
        } else {
          cli_args.verbosity = SRUN_VERBOSITY_DEBUG;
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
  if (cli_args.username[0] == '\0') {
    // can't set password without username
    cli_args.password[0] = '\0';
    readpassphrase("Username: ", cli_args.username, sizeof cli_args.username, RPP_ECHO_ON);
    srun_setopt(handle, SRUNOPT_USERNAME, cli_args.username);
  }

  if (cli_args.password[0] == '\0') {
    readpassphrase("Password: ", cli_args.password, sizeof cli_args.password, RPP_ECHO_OFF);
    srun_setopt(handle, SRUNOPT_PASSWORD, cli_args.password);
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
  // TODO
  (void)handle;
  return -1;
}

static void sigsegv_handler(int signum) {
  if (errno) {
    write(STDERR_FILENO, prog_name, strlen(prog_name));
    write(STDERR_FILENO, ": ", 2);
    const char *errstr = strerror(errno);
    write(STDERR_FILENO, errstr, strlen(errstr));
    write(STDERR_FILENO, "\n", 1);
  }

  signal(signum, SIG_DFL); // reset the signal handler to default
  raise(signum);           // re-raise the signal to terminate the program
}

int main(int argc, char **argv) {
  int retval = EXIT_FAILURE;
  prog_name = basename(argv[0]);
  signal(SIGSEGV, sigsegv_handler);

  if (argc == 1) {
    goto no_action;
  }

  // provide default values
#ifdef SRUN_CONF_AUTH_URL
  cli_args.auth_server = strdup(SRUN_CONF_AUTH_URL);
#endif
#ifdef SRUN_CONF_DEFAULT_USERNAME
  cli_args.username = strdup(SRUN_CONF_DEFAULT_USERNAME);
#endif
#ifdef SRUN_CONF_DEFAULT_PASSWORD
  cli_args.password = strdup(SRUN_CONF_DEFAULT_PASSWORD);
#endif
#ifdef SRUN_CONF_DEFAULT_AC_ID
  cli_args.ac_id = SRUN_CONF_DEFAULT_AC_ID;
#endif
#ifdef SRUN_CONF_DEFAULT_CERT
  cli_args.cert_pem = strdup(SRUN_CONF_DEFAULT_CERT);
#endif
#ifdef SRUN_CONF_DEFAULT_CLIENT_IP
  cli_args.client_ip = strdup(SRUN_CONF_DEFAULT_CLIENT_IP);
#endif
  cli_args.verbosity = SRUN_VERBOSITY_NORMAL;

  const char *action_str = argv[1];

  parse_opt(argc, argv);

  if (cli_args.verbosity == SRUN_VERBOSITY_SILENT) {
    freopen("/dev/null", "w", stdout);
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

  if (!cli_args.auth_server || !cli_args.auth_server[0]) {
    fprintf(stderr, "Missing fields for %s.\n", action_str);
    goto help_guide;
  }

  srun_handle handle = srun_create();

  srun_setopt(handle, SRUNOPT_AUTH_SERVER, cli_args.auth_server);
  srun_setopt(handle, SRUNOPT_AC_ID, cli_args.ac_id);
  if (cli_args.username) {
    srun_setopt(handle, SRUNOPT_USERNAME, cli_args.username);
  }
  if (cli_args.password) {
    srun_setopt(handle, SRUNOPT_PASSWORD, cli_args.password);
  }
  if (cli_args.client_ip) {
    srun_setopt(handle, SRUNOPT_CLIENT_IP, cli_args.client_ip);
  }
  // if (cli_args.cert_pem) {
  //   srun_setopt(handle, SRUNOPT_SERVER_CERT, cli_args.cert_pem);
  // }
  srun_setopt(handle, SRUNOPT_VERBOSITY, cli_args.verbosity);

  if (action == ACTION_LOGIN) {
    retval = perform_login(handle) != SRUNE_OK;
  } else if (action == ACTION_LOGOUT) {
    retval = perform_logout(handle) != SRUNE_OK;
  }

  srun_cleanup(handle);
  handle = NULL;

exit_cleanup:
  free(cli_args.auth_server);
  free(cli_args.username);
  free(cli_args.password);
  free(cli_args.client_ip);
  free(cli_args.cert_pem);
  memset(&cli_args, 0, sizeof cli_args);

  return retval;
}
