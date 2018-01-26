# libumqtt

[1]: https://img.shields.io/badge/license-GPLV3-brightgreen.svg?style=plastic
[2]: /LICENSE
[3]: https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=plastic
[4]: https://github.com/zhaojh329/libumqtt/pulls
[5]: https://img.shields.io/badge/Issues-welcome-brightgreen.svg?style=plastic
[6]: https://github.com/zhaojh329/libumqtt/issues/new
[7]: https://img.shields.io/badge/release-0.0.1-blue.svg?style=plastic
[8]: https://github.com/zhaojh329/libumqtt/releases
[9]: https://travis-ci.org/zhaojh329/libumqtt.svg?branch=master
[10]: https://travis-ci.org/zhaojh329/libumqtt

[![license][1]][2]
[![PRs Welcome][3]][4]
[![Issue Welcome][5]][6]
[![Release Version][7]][8]
[![Build Status][9]][10]

[libubox]: https://git.openwrt.org/?p=project/libubox.git
[ustream-ssl]: https://git.openwrt.org/?p=project/ustream-ssl.git
[openssl]: https://github.com/openssl/openssl
[mbedtls]: https://github.com/ARMmbed/mbedtls
[CyaSSl(wolfssl)]: https://github.com/wolfSSL/wolfssl

Lightweight MQTT client C library based on libubox for Embedded Linux. Use [libubox] as its event backend.

`Keep Watching for More Actions on This Space`

# Dependencies
* [libubox]
* [ustream-ssl] - If you need to support SSL
* [mbedtls] - If you choose mbedtls as your SSL backend
* [CyaSSl(wolfssl)] - If you choose wolfssl as your SSL backend
* [openssl] - If you choose openssl as your SSL backend

# Contributing
If you would like to help making [libumqtt](https://github.com/zhaojh329/libumqtt) better,
see the [CONTRIBUTING.md](/CONTRIBUTING.md) file.
