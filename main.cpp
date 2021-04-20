#include <iostream>
#include "spq_sigs.hpp"

int main(int args, char **argv) {
    auto skey = spqsigs::signing_key<24, 12, 10, true >();
    std::string msg("This is just a test.");
    std::string signature = skey.sign_message(msg);
    std::cout << msg << std::endl << signature << std::endl << std::endl;
    signature = skey.sign_message(msg);
    std::cout << msg << std::endl << std::hex << signature << std::endl << std::endl;
}
