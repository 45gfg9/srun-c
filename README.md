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
>
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
./cmake-build/srun login -b https://auth.my.edu -a 12 -u HarumiEna -p mysupersecretpassword
# login, ask username and password interactively
./cmake-build/srun login -b https://auth.my.edu -a 12
# logout
./cmake-build/srun logout -b https://auth.my.edu -a 12
# help
./cmake-build/srun -h
```

## Build for ESP8266 / ESP32 / your own project

Integrating `srun-c` into your own project is a bit more complicated. You need to drop a few files into your project.

1. Copy `srun.c`, `srun.h`, and `platform/compat.h` to your project.
2. Copy one of `platform/libcurl.c`, `platform/esp8266_arduino_http.cpp`, or `platform/espidf_http.c` depending on the HTTP library you have / want to use.
   - Use `libcurl.c` for Unix-like systems.
   - Use `espidf_http.c` for ESP32.
   - Use `esp8266_arduino_http.cpp` for ESP8266 with Arduino framework.
3. Copy one of `platform/openssl.c`, `platform/mbedtls.c`, or `platform/md.c` depending on the crypto library you have / want to use.
    - For Unix-like systems, any is fine but you usually want `openssl.c` or `mbedtls.c` as they may utilize hardware acceleration.
    - For ESP32, use `mbedtls.c` as ESP-IDF provides it.
    - For ESP8266 or projects with minimal dependencies, use `md.c`.
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
    ├── esp8266_arduino_http.cpp
    ├── md.c
    └── srun.c
```

If you wish to use other libraries, you will need to implement your own compatibility layer. See `platform/compat.h` and existing implementations under `platform/` for a quick understanding of how to do this.

### API Usage

`srun-c` tries to follow an `esp_http_client`-style API. Below is a minimal example.

```c
// login
srun_config config = {
    .base_url = "https://auth.my.edu",
    .username = "HarumiEna",
    .password = "mysupersecretpassword",
    .ac_id = 12,
};
srun_handle handle = srun_create(&config);

int ret = srun_login(handle);
if (ret != SRUN_OK) {
  fprintf(stderr, "Login failed: %d\n", ret);
}

// logout
ret = srun_logout(handle);
if (ret != SRUN_OK) {
  fprintf(stderr, "Logout failed: %d\n", ret);
}

srun_cleanup(handle);
```

`base_url` should only contain the hostname and optionally the scheme and port, but not any path. It is required for login and logout operations.

`username` and `password` are required for login operations, but not for logout operations.

The Srun portal requires `ac_id`, an integer that may vary by institution. You usually can find it in the URL of the login page. If it is not set, `srun-c` will try to guess it from the authentication page, but this is not guaranteed to work in all cases (also see below).

For detailed API usage, refer to the header file `srun.h`. For a more complete example, see `main.c`.

#### Caveats for ESP8266

ESP8266 has very limited resources. HTTPS requires some amount of RAM, and if your project also uses much RAM, you may encounter crashes or instability.

> [!CAUTION]
>
> If you encounter issues, consider using HTTP but be aware that HTTP is insecure. Srun portal uses a XXTEA-variant encryption for the login request, but it is virtually useless; **if someone intercepts a full request, they can decrypt it and get your credentials.** This is left to you as an exercise.
>
> Depending on your institution's setup, `ac_id` detection may require HTTPS, other than that it may work fine with HTTP.

## TODO

- [ ] Test if `rad_user_dm` is sufficient for logout (need testers!)
- [ ] Support for `srun-c` as a PlatformIO library

## License

This work is free. You can redistribute it and/or modify it under the terms of the Do What The Fuck You Want To Public License, Version 2, as published by Sam Hocevar. See the LICENSE file for more details.
