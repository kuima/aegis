# trojan

[![Build Status](https://dev.azure.com/GreaterFire/Trojan-GFW/_apis/build/status/trojan-gfw.trojan?branchName=master)](https://dev.azure.com/GreaterFire/Trojan-GFW/_build/latest?definitionId=5&branchName=master)

An unidentifiable mechanism that helps you bypass GFW.

Trojan features multiple protocols over `TLS` to avoid both active/passive detections and ISP `QoS` limitations.

Trojan is not a fixed program or protocol. It's an idea, an idea that imitating the most common service, to an extent that it behaves identically, could help you get across the Great FireWall permanently, without being identified ever. We are the GreatER Fire; we ship Trojan Horses.

## Documentations

An online documentation can be found [here](https://trojan-gfw.github.io/trojan/).  
Installation guide on various platforms can be found in the [wiki](https://github.com/trojan-gfw/trojan/wiki/Binary-&-Package-Distributions).

## Compatibility and Runtime Updates

This fork keeps the original Trojan protocol and client compatibility intact:

- The request format remains `hex(SHA224(password)) + CRLF + SOCKS5-like request + CRLF + payload`.
- Existing Trojan clients can continue to connect without protocol or configuration changes.
- Non-Trojan and invalid-password traffic is still forwarded to the configured fallback endpoint.

The server runtime has been modernized with:

- TLS version controls via `ssl.min_version` and `ssl.max_version` (`TLSv1.2` minimum by default).
- Buffered first-request parsing, so valid Trojan requests are not misclassified when the first TLS/TCP payload is fragmented.
- Timeouts for TLS handshakes, initial Trojan requests, and outbound connection establishment.
- Outbound endpoint fallback across all DNS results, with IPv4 preference preserved when configured.
- A hardened systemd unit template and an updated multi-stage Docker build.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Dependencies

- [CMake](https://cmake.org/) >= 3.16
- [Boost](http://www.boost.org/) >= 1.74.0
- [OpenSSL](https://www.openssl.org/) >= 1.1.1
- [libmysqlclient](https://dev.mysql.com/downloads/connector/c/) (optional, only when building with MySQL support)

OpenSSL 3.x is recommended for new builds. OpenSSL 3.5 is the current LTS line supported until April 8, 2030.

MySQL support is disabled by default in CMake and Docker builds. Enable it only when database-backed authentication is required.

## Build

```bash
cmake -S . -B build -DENABLE_MYSQL=OFF
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Enable MySQL support explicitly:

```bash
cmake -S . -B build -DENABLE_MYSQL=ON
cmake --build build -j
```

## Docker

The Dockerfile uses the current Alpine stable branch by default and installs packages from that branch at build time.

```bash
docker build -t trojan .
docker run --rm -v "$PWD/examples/server.json-example:/config/config.json:ro" trojan
```

Build with MySQL authenticator support:

```bash
docker build --build-arg ENABLE_MYSQL=ON -t trojan:mysql .
```

## License

[GPLv3](LICENSE)
