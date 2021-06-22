# spq-sigs
C++ Simple (hash-based) Post-Quantum Signing

This is to be a header-only template library running on top of the [BLAKE2b](https://www.blake2.net/) function of the 
[sodium library](https://libsodium.gitbook.io/doc/). The design is roughly based on that of [XMSS](https://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.400.6086) and [LMS](https://datatracker.ietf.org/doc/html/rfc8554). The implementation favors simplicity and leveraging of the BLAKE2b hashing primatives over maximum signature size efficiency.

This C++ library started out as a port of the Python [PySpqSigs](https://github.com/pibara/pyspqsigs) library. It is now being refactored and extended after attempts to make this a funded HIVE project ended up failing. Once multi-tree and wallets have been implemented in this C++ library, the refactored and extended C++ implementation will get backported to Python. An important part of the Python backport will be moving from hashlib to libsodium.

## status

* A signing key has been implemented.
* A signature validator has been implemented.
* The C++ signing key has been tested to work with the validator.
* Basic compiler flag based code quality has been enforced. 
* Currently working on a signature deserialization and validator class.

## todo

* Implement multi-tree signing keys and signatures
* Private key serialization and de-serialization
* Private key password protection (use libsodium)
* Intermediate signature caching
* Add multi-threading
* Work on const-correctness.
* Document usage
* Add a sample project with cmake and stuff.

## todo (post Python backport)

* Test signing/validation cross language compatability and fix if needed.
* Test serialization/deserialization python/c++ cross-compatibility.

