# spq-sigs
C++ Simple (hash-based) Post-Quantum Signing

This is to be a header-only template library running on top of the [BLAKE2b](https://www.blake2.net/) function of the 
[sodium library](https://libsodium.gitbook.io/doc/). The design is roughly based on that of [XMSS](https://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.400.6086) and [LMS](https://datatracker.ietf.org/doc/html/rfc8554). The implementation favors simplicity and leveraging of the BLAKE2b hashing primatives over maximum signature size efficiency.

This C++ library started out as a port of the Python [PySpqSigs](https://github.com/pibara/pyspqsigs) library. It is now being refactored and extended after attempts to make this a funded HIVE project ended up failing. Once multi-tree and wallets have been implemented in this C++ library, the refactored and extended C++ implementation will get backported to Python. An important part of the Python backport will be moving from hashlib to libsodium.

## Done

* A signing key has been implemented.
* A signature validator has been implemented.
* The C++ signing key has been tested to work with the validator.
* Basic compiler flag based code quality has been enforced. 
* Added some long overdue comments to the code.
* Implemented multi-tree signing (experimental) up to four levels.
* Replace seperate multy-tree templates with a variadic template solution.
* Implement (variadic) multi-tree signature validation.
* Updatate API to work with optionally omitted sub-key signing signatures.
* Add multi-tree signature serialization/deserialisation where known sub-key signing signatures can optionally be ommitted. 

## Todo for Minimal Viable Product

* Use crypto\_kdf\_derive\_from\_key at multiple layers
  * key-level in multi-tree signing (7 bits from 64 bits of subkey\_id)
  * specific index within single tree singing (16 bits from 64 bits of subkey\_id)
  * subkey (40 bits from 64 bits of subkey\_id)
  * left/right wots chain (1 bit from 64 bits of subkey\_id)
* Private key serialization and de-serialization (for wallets and persistence).
* Private key password protection (use libsodium).
* Code cleanup.

# Todo post-MVP
* Add multi-threading.
* Factor in something close to just in time pre-calculation of replacement keys.
* Work on const-correctness.
* Document usage.
* Add a sample project with cmake and stuff.
* Profile and performance improve where possible.

## todo post Python backport

* Test signing/validation cross language compatability and fix if needed.
* Test serialization/deserialization python/c++ cross-compatibility.

# other spq-sigs repos

Currently the C++ repo is where all development happens. Here are some links to (mostly empty) repos for languages spq-sigs will eventually (likely) be ported to.

* [pysqpsigs](https://github.com/pibara/pyspqsigs) (Python) Please note, the current code is from a proof-of concept. The C++ implementation design will soon get backported to Python.
* [js-spq-sigs](https://github.com/pibara/js-spq-sigs) (JavaScript) Nothing there yet. This one is an esential one to get done after C++ and Python.
* [m-spq-sigs](https://github.com/pibara/m-spq-sigs) (Monte) This is one that might or might not come to be. Need to look into this one deeper before we know if it will even become possible, but as a cool ocap language, I think it is worth a try and a relatively high place on the priorities list.
* [r-spq-sigs](https://github.com/pibara/r-spq-sigs) (Rust) Nothing there yet. Rust is an amazing language, haven't done much serious projects with it yet, on my list for that reason.
* [c-spq-sigs](https://github.com/pibara/c-spq-sigs) (Clojure) Nothing there yet. This one is on the list for one reason only and it may disapear for the same reason. At my day job we use FlureeDB a lot, and I would really like to help make FlureeDB support Simple Post-Quantum Signatures.
* e-spq-sigs (Elixir) Nothing there yet. Only here because Elixir is a cool language with libsodium bindings that I feel I should learn.
