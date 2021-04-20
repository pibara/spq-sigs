# spq-sigs
C++ Simple (hash-based) Post-Quantum Signing

This repo will soon contain a first version of a C++ equivalent of the 
Python [pyspqsigs](https://github.com/pibara/pyspqsigs) library.

This is to be a header-only template library running on top of the BLAKE2b function of the 
sodium library.

## status

* Currently working on porting the SigningKey class from the python lib to C++.

## todo

* Add multi-threading
* Add (de)-serialization
* Test c++ signing key with Python validator and fix any incompatabilities
* Implement C++ validator (port from python)
* Test validator with C++ signingkey impl
* Test validator with python signinkey impl
* Test serialization/deserialization python/c++ cross-compatibility.
* Cleanup code
* Add comments
* Document usage
* Add a sample project with cmake and stuff.

