#include <iostream>
#include "spq_sigs.hpp"

constexpr unsigned char hashlen=24;
constexpr unsigned char wotsbits=12;
constexpr unsigned char merkledepth=10;
constexpr bool do_threads=true;
typedef spqsigs::signing_key<hashlen, wotsbits, merkledepth, do_threads > signing_key;
typedef spqsigs::signature<hashlen, wotsbits, merkledepth> verifyable_signature;

int main() {
    std::cout << "Creating a new signing key. This may take a while." << std::endl;
    auto skey = signing_key();
    std::string msg("This is just a test.");
    std::cout << "Making two signatures" << std::endl;
    std::string signature = skey.sign_message(msg);
    std::cout << "signature length: " <<  signature.length() << " bytes" << std::endl;
    signature = skey.sign_message(msg);
    std::cout << "signature length: " << signature.length() << " bytes" << std::endl;
    auto sign = verifyable_signature(signature);
    bool ok = sign.validate(msg);
    std::cout << ok << std::endl;
}
