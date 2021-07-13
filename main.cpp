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
constexpr unsigned char merkleheight1=4;
constexpr unsigned char merkleheight2=4;
constexpr unsigned char merkleheight3=4;
constexpr unsigned char merkleheight4=4;
typedef spqsigs::signing_key<hashlen, wotsbits, merkleheight> signing_key;
typedef spqsigs::signature<hashlen, wotsbits, merkleheight> verifyable_signature;

typedef spqsigs::multi_signing_key<hashlen, wotsbits, merkleheight1, merkleheight2> signing_key_2l;
typedef spqsigs::multi_signature<hashlen, wotsbits, merkleheight1, merkleheight2> verifyable_signature_2l;
typedef spqsigs::deserializer<hashlen, wotsbits, merkleheight1, merkleheight2>  deserializer_2l;

typedef spqsigs::multi_signing_key<hashlen, wotsbits, merkleheight1, merkleheight2, merkleheight3> signing_key_3l;
typedef spqsigs::multi_signature<hashlen, wotsbits, merkleheight1, merkleheight2, merkleheight3> verifyable_signature_3l;
typedef spqsigs::deserializer<hashlen, wotsbits, merkleheight1, merkleheight2, merkleheight3>  deserializer_3l;

typedef spqsigs::multi_signing_key<hashlen, wotsbits, merkleheight1, merkleheight2, merkleheight3, merkleheight4> signing_key_4l;
typedef spqsigs::multi_signature<hashlen, wotsbits, merkleheight1, merkleheight2, merkleheight3, merkleheight4> verifyable_signature_4l;
//typedef spqsigs::deserializer<hashlen, wotsbits, merkleheight1, merkleheight2, merkleheight3, merkleheight4>  deserializer_4l;


int main() {
    std::cout << "Signing key generated, running signing test." << std::endl;
    std::string msg("This is just a test.");
    int ok_count = 0;
    int fail_count = 0;
    int except_count = 0;
    std::cout << "Creating a new signing key. This may take a while." << std::endl;
    std::cout << " - key meant to sign " <<  (1ull << merkleheight) << " messages" << std::endl;
    auto skey = signing_key();
    for (int ind=0; ind < (1 << merkleheight); ind++) {
	try {
            std::cout  << "Making signature " << ind << " out of " << (1 << merkleheight) << " ";
            std::string signature = skey.sign_message(msg);
            // std::cout << "signature length: " <<  signature.length() << " bytes" << std::endl;
	    // std::cout << "signature: " << as_hex(signature) << std::endl;
	    // std::cout << std::endl << "Parsing signature" << std::endl;
            auto sign = verifyable_signature(signature);
            if (sign.validate(msg)) {
                ok_count += 1;
		std::cout << "VALIDATED" << std::endl;
	    } else {
		std::cout << "ERROR" << std::endl;
                fail_count += 1;
	    }
	} catch  (const spqsigs::signingkey_exhausted&) {
             except_count += 1;
	}
    }
    std::cout << std::endl << "OK:" << ok_count << " FAIL:" << fail_count << " EXCEPT:" << except_count  << std::endl;
    try {
        std::string signature2 = skey.sign_message(msg);
    } catch (const spqsigs::signingkey_exhausted&) {
        std::cout << "Cought expected exception. Signing key exhausted." << std::endl;
    }
    ok_count = 0;
    fail_count = 0;
    except_count = 0;
    std::cout << "Creating a new double-tree signing key. This may take a while." << std::endl;
    std::cout << " - key meant to sign " <<  (1ull << (merkleheight1 + merkleheight2)) << " messages" << std::endl;
    auto skey2l = signing_key_2l();
    std::vector<std::string> cached;
    cached.push_back("");
    cached.push_back(skey2l.pubkey());
    spqsigs::reducer reducer2l;
    spqsigs::expander expander2l;
    deserializer_2l deserialize2l; 
    for (int ind=0; ind < (1 << (merkleheight1 + merkleheight2)); ind++) {
        try {
	    std::cout <<  "Making signature " << ind << " out of " << (1 << (merkleheight1 + merkleheight2)) << " ";
            auto signature = skey2l.sign_message(msg);
	    reducer2l.reduce(signature);
	    std::string serialized2l = spqsigs::serialize(signature, skey2l.pubkey());
	    std::cout << " " << serialized2l.size() << "-byte signature "; 
	    auto deserialized = deserialize2l(serialized2l);
	    signature = deserialized.second;
            expander2l.expand(signature);
            auto sign2 = verifyable_signature_2l(signature, cached);
	    if (sign2.validate(msg)) {
                 std::cout << "OK" << std::endl;
	    } else {
                 std::cout << "FAIL, WE HAVE WORK TO DO HERE" << std::endl;
	    }

        } catch  (const spqsigs::signingkey_exhausted&) {
	    std::cout << "OOPS" << std::endl;
            except_count += 1;
	}
    }
    std::cout << std::endl << " EXCEPT:" << except_count  << std::endl;
    ok_count = 0;
    fail_count = 0;
    except_count = 0;
    std::cout << "Creating a new triple-tree signing key. This may take a while." << std::endl;
    std::cout << " - key meant to sign " <<  (1ull << (merkleheight1 + merkleheight2 + merkleheight3)) << " messages" << std::endl;
    auto skey3l = signing_key_3l();
    std::vector<std::string> cached2;
    cached2.push_back("");
    cached2.push_back("");
    cached2.push_back(skey3l.pubkey());
    spqsigs::reducer reducer3l;
    spqsigs::expander expander3l;
    for (int ind=0; ind < (1 << (merkleheight1 + merkleheight2 +merkleheight3)); ind++) {
        try {
            std::cout <<  "Making signature " << ind << " out of " << (1 << (merkleheight1 + merkleheight2 + merkleheight3)) << " ";
            auto signature = skey3l.sign_message(msg);
	    reducer3l.reduce(signature);
	    std::string serialized3l = spqsigs::serialize(signature, skey3l.pubkey());
            std::cout << " " << serialized3l.size() << " -byte signature ";
	    //FIXME: we need a working deserialize here!
            expander3l.expand(signature);
            auto sign3 = verifyable_signature_3l(signature, cached2);
	    if (sign3.validate(msg)) {
                 std::cout << "OK" << std::endl;
            } else {
                 std::cout << "FAIL, WE HAVE WORK TO DO HERE" << std::endl;
            }
        } catch  (const spqsigs::signingkey_exhausted&) {
            std::cout << "OOPS" << std::endl;
            except_count += 1;
        }
    }
    std::cout << std::endl << " EXCEPT:" << except_count  << std::endl;
    ok_count = 0;
    fail_count = 0;
    except_count = 0;
    std::cout << "Creating a new quadrupal-tree signing key. This may take a while." << std::endl;
    std::cout << " - key meant to sign " <<  (1ull << (merkleheight1 + merkleheight2 + merkleheight3 + merkleheight4)) << " messages" << std::endl;
    auto skey4l = signing_key_4l();
    std::vector<std::string> cached3;
    cached3.push_back("");
    cached3.push_back("");
    cached3.push_back("");
    cached3.push_back(skey4l.pubkey());
    spqsigs::reducer reducer4l;
    spqsigs::expander expander4l;
    for (int ind=0; ind < (1 << (merkleheight1 + merkleheight2 + merkleheight3 + merkleheight4)); ind++) {
        try {
            std::cout <<  "Making signature " << ind << " out of " << (1 << (merkleheight1 + merkleheight2 + merkleheight3 + merkleheight4)) << " ";
            auto signature = skey4l.sign_message(msg);
	    reducer4l.reduce(signature);
	    std::string serialized4l = spqsigs::serialize(signature, skey3l.pubkey());
            std::cout << " " << serialized4l.size() << "-byte signature ";
	    //FIXME: we need a working deserialize here!
            expander4l.expand(signature);
            auto sign4 = verifyable_signature_4l(signature, cached3);
	    if (sign4.validate(msg)) {
                 std::cout << "OK" << std::endl;
            } else {
                 std::cout << "FAIL, WE HAVE WORK TO DO HERE" << std::endl;
            }
        } catch  (const spqsigs::signingkey_exhausted&) {
            std::cout << "OOPS" << std::endl;
            except_count += 1;
        }
    }
    std::cout << std::endl << " EXCEPT:" << except_count  << std::endl;
}
