#include <iostream>
#include "spq_sigs.hpp"

int main(int args, char **argv) {
    std::cout << "Creating a new signing key. This may take a while." << std::endl;
    auto skey = spqsigs::signing_key<24, 12, 10, true >();
    std::string msg("This is just a test.");
    std::cout << "Making two signatures" << std::endl;
    std::string signature = skey.sign_message(msg);
    std::cout << "signature length: " <<  signature.length() << " bytes" << std::endl;
    signature = skey.sign_message(msg);
    std::cout << "signature length: " << signature.length() << " bytes" << std::endl;
}
