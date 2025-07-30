# `srun-c`

Yet another **srun** login utility, but written in C and with ESP8266 / ESP32 support.

## Build for \*nix

Users of Linux, macOS, and other Unix-like systems can build a standalone binary using CMake. The following dependencies are required:

- CMake (for building)
- OpenSSL (or Mbed TLS, see below)
- libcurl
- cJSON
- libbsd (for Linux; optional but **strongly recommended**, see below)

For macOS:

```sh
brew install cmake openssl cjson
```

For Debian-based Linux distributions:

```sh
sudo apt install make cmake libssl-dev libcurl4-openssl-dev libcjson-dev libbsd-dev
```

Build:

```sh
cmake -B cmake-build -DCMAKE_BUILD_TYPE=RelWithDebInfo  # or Release, at your choice
cmake --build cmake-build --config RelWithDebInfo
```

> [!WARNING]
> **For Linux users:** `libbsd` provides `readpassphrase()` used to read password from the terminal securely. If it is installed, it will be used automatically. If not, a less secure fallback implementation will be used.
>
> macOS or BSD users can ignore this warning as `readpassphrase()` is provided by the system.

You can choose the crypto library to use by setting the `SRUN_CRYPTO` variable. Supported values are `openssl`, `mbedtls`, and `self` which uses a self-contained implementation of SHA-1 and HMAC-MD5 (see [`platform/md.c`](platform/md.c)). The default is `openssl`. If neither OpenSSL nor Mbed TLS is found, `self` will be used automatically.

```sh
cmake -B cmake-build -DSRUN_CRYPTO=mbedtls  # or openssl, self
```

### Command Line Usage

```sh
# login
./cmake-build/srun login -H https://auth.my.edu -a 12 -u HarumiEna -p mysupersecretpassword
# login, ask username and password interactively
./cmake-build/srun login -H https://auth.my.edu -a 12
# logout
./cmake-build/srun logout -H https://auth.my.edu -a 12
# help
./cmake-build/srun -h
```

### Provide Default Values

See `CMakeLists.txt` for the default values of the options at compile time. Settings that have default values can be omitted from the command line. For example, if you set `SRUN_CONF_HOST` to your institution's authentication server hostname, you can omit the `-H` option. If `-H` is provided, it will override the default value.

> [!CAUTION]
> Also be aware that the password is stored in plaintext in the binary and can be dumped using `strings` or similar tools. If this is a concern, consider setting the correct file permissions, or avoid compiling the password into the binary.

## Build for ESP8266 / ESP32 / your own project

Integrating `srun-c` into your own project is a bit more complicated. You need to drop a few files into your project.

1. Copy `srun.c`, `srun.h`, and `platform/compat.h` to your project.
2. Copy one of `platform/libcurl.c`, `platform/esp_arduino_http.cpp`, or `platform/espidf_http.c` depending on the HTTP library you have / want to use.
   - Use `libcurl.c` for Unix-like systems.
   - Use `esp_arduino_http.cpp` for ESP8266 or ESP32 with Arduino framework.
   - Use `espidf_http.c` for ESP32 with ESP-IDF.
3. Copy one of `platform/openssl.c`, `platform/mbedtls.c`, or `platform/md.c` depending on the crypto library you have / want to use.
    - For Unix-like systems, any is fine but you usually want `openssl.c` or `mbedtls.c` as they may utilize hardware acceleration.
    - For ESP32, use `mbedtls.c` as ESP-IDF provides it.
    - For projects with minimal dependencies (like ESP8266), use `md.c`.
4. Copy one of `platform/cjson.c` or `platform/arduinojson.cpp` depending on the JSON library you have / want to use.
    - `cjson.c` requires `cJSON` library (which ESP32 has), while `arduinojson.cpp` is for ArduinoJson library.

Your project structure should look like this (feel free to adjust paths or file names, or just use a flat structure):

```
├── include  # make sure this is in your include path
│   ├── ArduinoJson.hpp
│   ├── compat.h
│   └── srun.h
└── src
    ├── arduinojson.cpp
    ├── esp_arduino_http.cpp
    ├── mbedtls.c
    └── srun.c
```

If you wish to use other libraries, you will need to implement your own compatibility layer. See `platform/compat.h` and existing implementations under `platform/` for a quick understanding of how to do this.

### API Usage

`srun-c` tries to follow a libcurl-style API. Below is a minimal example.

```c
// login
srun_handle handle = srun_create();
srun_setopt(handle, SRUNOPT_HOST, "https://auth.my.edu");
srun_setopt(handle, SRUNOPT_USERNAME, "HarumiEna");
srun_setopt(handle, SRUNOPT_PASSWORD, "mysupersecretpassword");
srun_setopt(handle, SRUNOPT_AC_ID, 12);  // see below

int ret = perform_login(handle);
if (ret != SRUN_OK) {
  fprintf(stderr, "Login failed: %d\n", ret);
}

// logout
ret = perform_logout(handle);
if (ret != SRUN_OK) {
  fprintf(stderr, "Logout failed: %d\n", ret);
}

srun_cleanup(handle);
```

`SRUNOPT_HOST` should only contain the hostname and optionally the scheme and port, but not any path. It is required for login and logout operations.

`SRUNOPT_USERNAME` and `SRUNOPT_PASSWORD` are required for login operations, but not for logout operations.

The Srun portal requires `ac_id`, an integer that may vary by institution. You usually can find it in the URL of the login page. If it is not set, `srun-c` will try to guess it from the authentication page, but this may not always work.

For detailed API usage, refer to the header file `srun.h`. For a more complete example, see `main.c`.

#### Caveats for ESP8266

ESP8266 may get slow when handling HTTPS requests due to its limited resources. It also does not support TLS certificate for IP addresses, for example `https://10.1.2.3` even if CA certificate is provided.

> [!CAUTION]
> If you encounter issues, consider using HTTP but be aware that HTTP is insecure. Srun portal uses a XXTEA-variant encryption for the login request, but it is virtually useless; **if someone intercepts a full request, they can decrypt it and get your credentials.** This is left to you as an exercise.

## TODO

- [ ] Support for ESP32 cert bundle
- [ ] Test if `ac_id` is required for logout
- [ ] Support for `srun-c` as a PlatformIO library

## License

This work is free. You can redistribute it and/or modify it under the terms of the Do What The Fuck You Want To Public License, Version 2, as published by Sam Hocevar. See the LICENSE file for more details.
