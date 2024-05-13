[![Build Status](https://travis-ci.org/helium/ecc_compact.svg?branch=master)](https://travis-ci.org/helium/ecc_compact)
[![Coverage Status](https://coveralls.io/repos/github/helium/ecc_compact/badge.svg?branch=master)](https://coveralls.io/github/helium/ecc_compact?branch=master)


Overview
--------

This library is a utility module to help with point-compression techniques
for NIST P-256 and SEC-2 K-256 elliptic curve public keys. Refer to the
documentation (built using `make doc`) for more information.

Building
--------

Simply use `make` to build the library.

Running in a OTP 20.1 docker container
--------
If you don't have OTP 20.1 locally, you can run it in a docker container like so:
```
docker-compose run dev ./rebar3 as test do eunit
```

Limitations
-----------

This library only supports point-compaction for NIST P-256 keys and point
compression for SEC-2 K-256 keys. Other curves and compression combinations
could be supported, but the work has not yet been done. Contributions welcome.
