#include <iostream>
#include "spq_sigs.hpp"


std::string as_hex(std::string binary) {
    std::string rval;
    const char *charset = "0123456789ABCDEF";
    for (unsigned int index=0; index < binary.size(); index++) {
        unsigned char chr =  reinterpret_cast<const unsigned char *>(binary.c_str())[index];
        int b1 = (chr / 16) % 16;
        int b2 = chr % 16;
        rval += charset[b1];
        rval += charset[b2];
    }
    return rval;
}

constexpr unsigned char hashlen=24;
constexpr unsigned char wotsbits=12;
constexpr unsigned char merkleheight=10;
typedef spqsigs::signing_key<hashlen, wotsbits, merkleheight> signing_key;
typedef spqsigs::signature<hashlen, wotsbits, merkleheight> verifyable_signature;
typedef spqsigs::multitree_signing_key<hashlen, wotsbits, merkleheight, merkleheight> signing_key_2l;
typedef spqsigs::multitree_signature<hashlen, wotsbits, merkleheight, merkleheight> verifyable_signature_2l;
typedef spqsigs::multitree_signing_key<hashlen, wotsbits, merkleheight, merkleheight, merkleheight> signing_key_3l;
typedef spqsigs::multitree_signature<hashlen, wotsbits, merkleheight, merkleheight, merkleheight> verifyable_signature_3l;

int main() {
    std::cout << "Creating a new signing key. This may take a while." << std::endl;
    std::cout << " - key meant to sign " <<  (1 << merkleheight) << " messages" << std::endl;
    auto skey2l = signing_key_2l();
    auto skey3l = signing_key_3l();
    auto skey = signing_key();
    std::cout << "Signing key generated, running signing test." << std::endl;
    std::string msg("This is just a test.");
    int ok_count = 0;
    int fail_count = 0;
    int except_count = 0;
    for (int ind=0; ind < (1 << merkleheight); ind++) {
	try {
            std::cout << std::endl << "Making signature " << ind << " out of " << (1 << merkleheight) << std::endl;
            std::string signature = skey.sign_message(msg);
            std::cout << "signature length: " <<  signature.length() << " bytes" << std::endl;
	    std::cout << "signature: " << as_hex(signature) << std::endl;
	    std::cout << std::endl << "Parsing signature" << std::endl;
            auto sign = verifyable_signature(signature);
	    auto sign2 = verifyable_signature_2l(signature);
	    auto sign3 = verifyable_signature_3l(signature);
            std::cout << "validating" << std::endl;
            if (sign.validate(msg)) {
                ok_count += 1;
	    } else {
                fail_count += 1;
	    }
	} catch  (const spqsigs::signingkey_exhausted&) {
             except_count += 1;
	}
        std::cout << std::endl << "OK:" << ok_count << " FAIL:" << fail_count << " EXCEPT:" << except_count  << std::endl;
    }
    try {
        std::string signature2 = skey.sign_message(msg);
    } catch (const spqsigs::signingkey_exhausted&) {
        std::cout << "Cought expected exception. Signing key exhausted." << std::endl;
    }
}
