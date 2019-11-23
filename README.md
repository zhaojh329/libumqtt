# libumqtt

[1]: https://img.shields.io/badge/license-MIT-brightgreen.svg?style=plastic
[2]: /LICENSE
[3]: https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=plastic
[4]: https://github.com/zhaojh329/libumqtt/pulls
[5]: https://img.shields.io/badge/Issues-welcome-brightgreen.svg?style=plastic
[6]: https://github.com/zhaojh329/libumqtt/issues/new
[7]: https://img.shields.io/badge/release-1.0.2-blue.svg?style=plastic
[8]: https://github.com/zhaojh329/libumqtt/releases
[9]: https://travis-ci.org/zhaojh329/libumqtt.svg?branch=master
[10]: https://travis-ci.org/zhaojh329/libumqtt

[![license][1]][2]
[![PRs Welcome][3]][4]
[![Issue Welcome][5]][6]
[![Release Version][7]][8]
[![Build Status][9]][10]

[libev]: http://software.schmorp.de/pkg/libev.html
[openssl]: https://github.com/openssl/openssl
[mbedtls]: https://github.com/ARMmbed/mbedtls
[CyaSSl(wolfssl)]: https://github.com/wolfSSL/wolfssl

A Lightweight and fully asynchronous MQTT 3.1.1 client C library based on [libev].
And provide Lua-binding.

# Features
* Lightweight - 27KB(Using glibc,stripped)
* Fully asynchronous - Use [libev] as its event backend
* Support QoS 0, 1 and 2
* Support ssl - OpenSSL, mbedtls and CyaSSl(wolfssl)
* Code structure is concise and understandable, also suitable for learning
* Lua-binding

# Dependencies
* [libev]
* [mbedtls] - If you choose mbedtls as your SSL backend
* [CyaSSl(wolfssl)] - If you choose wolfssl as your SSL backend
* [openssl] - If you choose openssl as your SSL backend


# Install dependent packages

    sudo apt install libev-dev libssl-dev liblua5.2-dev

# Build and install

    git clone --recursive https://github.com/zhaojh329/libumqtt.git
    cd libumqtt
    git submodule update --init --recursive
    mkdir build && cd build
    cmake ..
    make && sudo make install

# Contributing
If you would like to help making [libumqtt](https://github.com/zhaojh329/libumqtt) better,
see the [CONTRIBUTING.md](/CONTRIBUTING.md) file.
