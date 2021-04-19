#include <iostream>
#include "spq_sigs.hpp"

int main(int args, char **argv) {
    auto skey = spqsigs::signing_key<24UL, 12,10>(6);
    std::string msg("This is just a test.");
    std::string signature = skey.sign_message(msg);
    std::cout << signature << std::endl;
}
