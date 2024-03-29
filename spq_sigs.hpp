#ifndef SPQ_SIGS_HPP
#define SPQ_SIGS_HPP
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cassert>
#include <string>
#include <vector>
#include <map>
#include <stdexcept>
#include <algorithm>
#include <string_view>
#include <exception>
#include <iomanip>
#include <sodium.h>
#include <arpa/inet.h>
#include <exception>
//TODO: Add documenting comments to multi tree part of this file.
//FIXME: implement serialize for signing keys and multi tree signing keys
//FIXME: Improve on reducer/expander setup to better match serialization and persistent state on both ends.
//FIXME: Add basic secret encryption (wallet) for signing keys and multi tree signing keys
//FIXME: Improve API for working with persistent storage (wallet, but without files, those don't belong in library API)
//FIXME: Work on code quality
//TODO: After backport to Python, validate interoperability.
//TODO: Add multi threading
//TODO: Work on const-correctness.
//TODO: Document usage.
//TODO: Add a sample project with cmake and stuff.
//TODO:Profile and performance improve where possible.


namespace spqsigs {
struct signingkey_exhausted : std::exception {
    using std::exception::exception;
};
struct insufficient_expand_state : std::exception {
    using std::exception::exception;
};
// declaration for signing_key class template defined at bottom of this file.
template<uint8_t hashlen=24, uint8_t wotsbits=12, uint8_t merkleheight=10>
struct signing_key;
template<uint8_t hashlen, uint8_t wotsbits, uint8_t merkleheight>
struct signature;

// Anything in the non_api sub namespace is not part of the public API of this single-file header-only library.
namespace non_api {
//Empty class for calling constructor of hashing primative with a request to use a newly
//generated salt.
class GENERATE {};
// declaration for private_keys class template
template<uint8_t hashlen,  uint8_t merkleheight, uint8_t wotsbits, uint32_t pubkey_size>
struct private_keys;

//Master key
template<uint8_t hashlen>
struct master_key {
          //Hash length must be 16 up to 64 bytes long.
          static_assert(hashlen > 15, "Hash size should be at least 128 bits (16 bytes).");
          static_assert(hashlen < 65,  "Hash size of more then 512 bits is not supported");
          master_key() {
              crypto_kdf_keygen(m_master_key);
          }
          master_key(std::string keybytes) {
              if (keybytes.length() != crypto_kdf_KEYBYTES) {
                 throw std::invalid_argument("Wrong master-key string-length.");
              }
              std::memcpy(m_master_key, reinterpret_cast<const uint8_t *>(keybytes.c_str()), crypto_kdf_KEYBYTES);
          }
          operator std::string() {
              return std::string(reinterpret_cast<const char *>(m_master_key),crypto_kdf_KEYBYTES);
          }
          std::string operator[](uint64_t index) {
              uint8_t output[hashlen];
              crypto_kdf_derive_from_key(output, hashlen, index, "Signatur", m_master_key);
              return std::string(reinterpret_cast<const char *>(output), hashlen);
          }
      private:
          uint8_t m_master_key[crypto_kdf_KEYBYTES];
};

//constexpr-able function for determining subkeys needed per signature.
template<uint8_t hashlen, uint8_t wotsbits>
uint16_t determine_subkeys_per_signature() {
      //Hash length must be 16 up to 64 bytes long.
      static_assert(hashlen > 15, "Hash size should be at least 128 bits (16 bytes).");
      static_assert(hashlen < 65,  "Hash size of more then 512 bits is not supported");
      //The number of bits used for wots encoding must be 3 upto 16 bits.
      static_assert(wotsbits < 17, "Wots chains longer than 64k hash operations (wotsbits>16) are not supported");
      static_assert(wotsbits > 3, "A wots chain should be at least 16 hash operations long (wotsbits > 1)");
      static_assert(39 * wotsbits >= hashlen * 8, "Wotsbits and hashlen must not combine into signing keys of more than 39 subkeys each");
      return (hashlen * 8 + wotsbits -1) / wotsbits;
}

//Determine (deep) the required key count at a given level and below.
template<uint8_t hashlen, uint8_t wotsbits, uint8_t merkleheight, uint8_t ...Args>
struct determine_required_keycount {
          //Hash length must be 16 up to 64 bytes long.
          static_assert(hashlen > 15, "Hash size should be at least 128 bits (16 bytes).");
          static_assert(hashlen < 65,  "Hash size of more then 512 bits is not supported");
          //The number of bits used for wots encoding must be 3 upto 16 bits.
          static_assert(wotsbits < 17, "Wots chains longer than 64k hash operations (wotsbits>16) are not supported");
          static_assert(wotsbits > 3, "A wots chain should be at least 16 hash operations long (wotsbits > 1)");
          //The height of a singe merkle-tree must be 3 up to 16 levels.
          static_assert(merkleheight < 17, "A single merkle tree should not be more than 16 levels high");
          static_assert(merkleheight > 2, "A single merkle tree should be at least two levels high. A value between 8 and 10 is recomended");
          static_assert(39 * wotsbits >= hashlen * 8, "Wotsbits and hashlen must not combine into signing keys of more than 39 subkeys each");
          uint64_t operator()() {
                  determine_required_keycount<hashlen, wotsbits, Args...> determine;
                  uint64_t rval = 1 +
                    (1<<merkleheight) *
                    (2 * determine_subkeys_per_signature<hashlen, wotsbits>() + determine());
                  return rval;
          }
};

//Determine (shallow or at deepest level) the required key count at a given level
template<uint8_t hashlen, uint8_t wotsbits, uint8_t merkleheight>
struct determine_required_keycount<hashlen, wotsbits, merkleheight> {
          //Hash length must be 16 up to 64 bytes long.
          static_assert(hashlen > 15, "Hash size should be at least 128 bits (16 bytes).");
          static_assert(hashlen < 65,  "Hash size of more then 512 bits is not supported");
          //The number of bits used for wots encoding must be 3 upto 16 bits.
          static_assert(wotsbits < 17, "Wots chains longer than 64k hash operations (wotsbits>16) are not supported");
          static_assert(wotsbits > 3, "A wots chain should be at least 16 hash operations long (wotsbits > 1)");
          //The height of a singe merkle-tree must be 3 up to 16 levels.
          static_assert(merkleheight < 17, "A single merkle tree should not be more than 16 levels high");
          static_assert(merkleheight > 2, "A single merkle tree should be at least two levels high. A value between 8 and 10 is recomended");
          static_assert(39 * wotsbits >= hashlen * 8, "Wotsbits and hashlen must not combine into signing keys of more than 39 subkeys each");
          uint64_t operator()() {
              uint64_t rval = 1 +
                  (1<<merkleheight) *
                  2* determine_subkeys_per_signature<hashlen, wotsbits>();
              return rval;
      }
};


//Get the proper index and/or high-entropy subkey data for one or both of the subkey WOTS chains
template<uint8_t hashlen>
struct subkey_index_generator {
          //Hash length must be 16 up to 64 bytes long.
          static_assert(hashlen > 15, "Hash size should be at least 128 bits (16 bytes).");
          static_assert(hashlen < 65,  "Hash size of more then 512 bits is not supported");
          subkey_index_generator(uint64_t own, master_key<hashlen> &mkey):
                  m_own(own),
                  m_master_key(mkey) {}
          virtual ~subkey_index_generator() {}
          uint64_t operator[](bool reverse) {
              if (reverse) {
                  return m_own +1;
              }
              return m_own;
          }
          std::string operator()(bool reverse=false) {
              if (reverse) {
                  return m_master_key[m_own +1];
              }
              return m_master_key[m_own];
          }
      private:
          uint64_t m_own;
          master_key<hashlen> &m_master_key;
};


// Get the wots level index (these represent two directions of WOTS chains each)
template<uint8_t hashlen, uint8_t wotsbits>
struct wots_index_generator {
          //Hash length must be 16 up to 64 bytes long.
          static_assert(hashlen > 15, "Hash size should be at least 128 bits (16 bytes).");
          static_assert(hashlen < 65,  "Hash size of more then 512 bits is not supported");
          //The number of bits used for wots encoding must be 3 upto 16 bits.
          static_assert(wotsbits < 17, "Wots chains longer than 64k hash operations (wotsbits>16) are not supported");
          static_assert(wotsbits > 3, "A wots chain should be at least 16 hash operations long (wotsbits > 1)");
          static_assert(39 * wotsbits >= hashlen * 8, "Wotsbits and hashlen must not combine into signing keys of more than 39 subkeys each");
          wots_index_generator(uint64_t own, master_key<hashlen> &mkey):
                  m_own(own),
                  m_master_key(mkey) {}
          virtual ~wots_index_generator() {}
          subkey_index_generator<hashlen> operator[](uint16_t subindex) {
              if (subindex >= determine_subkeys_per_signature<hashlen, wotsbits>()) {
                  throw std::out_of_range("invalid subkey index");
              }
              return subkey_index_generator<hashlen>(m_own + 2*subindex, m_master_key);
          }
          operator uint64_t() {
              return m_own;
          }
      private:
          uint64_t m_own;
          master_key<hashlen> &m_master_key;
};

// Get the index for a level key.
template<uint8_t hashlen, uint8_t wotsbits, uint8_t merkleheight, uint8_t ...Args>
struct unique_index_generator {
          //Hash length must be 16 up to 64 bytes long.
          static_assert(hashlen > 15, "Hash size should be at least 128 bits (16 bytes).");
          static_assert(hashlen < 65,  "Hash size of more then 512 bits is not supported");
          //The number of bits used for wots encoding must be 3 upto 16 bits.
          static_assert(wotsbits < 17, "Wots chains longer than 64k hash operations (wotsbits>16) are not supported");
          static_assert(wotsbits > 3, "A wots chain should be at least 16 hash operations long (wotsbits > 1)");
          //The height of a singe merkle-tree must be 3 up to 16 levels.
          static_assert(merkleheight < 17, "A single merkle tree should not be more than 16 levels high");
          static_assert(merkleheight > 2, "A single merkle tree should be at least two levels high. A value between 8 and 10 is recomended");
          static_assert(39 * wotsbits >= hashlen * 8, "Wotsbits and hashlen must not combine into signing keys of more than 39 subkeys each");
          unique_index_generator(master_key<hashlen> &mkey, uint64_t own=0):
                  m_master_key(mkey),
                  m_own(own),
		  m_cast(mkey, own),
                  m_determine(),
                  m_determine2(),
                  m_generate(
                      own + m_determine()
                  ) {}
          virtual ~unique_index_generator() {}
	  unique_index_generator& operator=(const unique_index_generator& other) {
              m_master_key=other.m_master_key;
	      m_own = other.m_own;
	      m_cast = this->cast();
              m_generate = other.m_generate;
	      return *this;
	  }
          unique_index_generator<hashlen, wotsbits, Args...> operator()(uint64_t index){
              if (index >= (1<<merkleheight)) {
                  throw std::out_of_range("invalid index for key structure");
              }
              return unique_index_generator<hashlen, wotsbits, Args...>(m_master_key, m_generate + index * m_determine2());
          }
          uint64_t operator[](uint16_t index) {
              if (index >= (1<<merkleheight)) {
                  throw std::out_of_range("invalid index for key structure");
              }
              return m_own + 1 + index * 2* determine_subkeys_per_signature<hashlen, wotsbits>();
          }
          operator uint64_t(){ return m_own;}
          operator std::string(){ return m_master_key[m_own]; }
	  unique_index_generator<hashlen, wotsbits, merkleheight> cast() {
              return m_cast;
	  }
      private:
          master_key<hashlen> &m_master_key;
          uint64_t m_own;
	  unique_index_generator<hashlen, wotsbits, merkleheight> m_cast;
          determine_required_keycount<hashlen, wotsbits, merkleheight> m_determine;
          determine_required_keycount<hashlen, wotsbits, Args...> m_determine2;
          uint64_t m_generate;
};

template<uint8_t hashlen, uint8_t wotsbits, uint8_t merkleheight>
struct unique_index_generator<hashlen, wotsbits, merkleheight> {
          //Hash length must be 16 up to 64 bytes long.
          static_assert(hashlen > 15, "Hash size should be at least 128 bits (16 bytes).");
          static_assert(hashlen < 65,  "Hash size of more then 512 bits is not supported");
          //The number of bits used for wots encoding must be 3 upto 16 bits.
          static_assert(wotsbits < 17, "Wots chains longer than 64k hash operations (wotsbits>16) are not supported");
          static_assert(wotsbits > 3, "A wots chain should be at least 16 hash operations long (wotsbits > 1)");
          //The height of a singe merkle-tree must be 3 up to 16 levels.
          static_assert(merkleheight < 17, "A single merkle tree should not be more than 16 levels high");
          static_assert(merkleheight > 2, "A single merkle tree should be at least two levels high. A value between 8 and 10 is recomended");
          static_assert(39 * wotsbits >= hashlen * 8, "Wotsbits and hashlen must not combine into signing keys of more than 39 subkeys each");
          unique_index_generator(master_key<hashlen> &mkey, uint64_t own):
              m_master_key(mkey),
              m_own(own) {}
          virtual ~unique_index_generator() {}
	  unique_index_generator& operator=(const unique_index_generator& other) {
              m_master_key=other.m_master_key;
              m_own = other.m_own;
	      return *this;
          }
          wots_index_generator<hashlen, wotsbits> operator[](uint16_t index) {
              if (index >= (1<<merkleheight)) {
                  throw std::out_of_range("invalid index for key structure");
              }
              return wots_index_generator<hashlen, wotsbits>(m_own + 1 + index * 2 * determine_subkeys_per_signature<hashlen, wotsbits>(), m_master_key);
          }
          operator uint64_t(){ return m_own;}
          operator std::string(){ return m_master_key[m_own]; }
      private:
          master_key<hashlen> &m_master_key;
          uint64_t m_own;
};

// Helper function for converting a digest to a vector of numbers that can be signed using a
// different subkey each.
template<uint8_t hashlen, uint8_t wotsbits>
std::vector<uint32_t> digest_to_numlist(std::string &msg_digest)
{
    //Hash length must be 16 up to 64 bytes long.
    static_assert(hashlen > 15, "Hash size should be at least 128 bits (16 bytes).");
    static_assert(hashlen < 65,  "Hash size of more then 512 bits is not supported");
    //The number of bits used for wots encoding must be 3 upto 16 bits.
    static_assert(wotsbits < 17, "Wots chains longer than 64k hash operations (wotsbits>16) are not supported");
    static_assert(wotsbits > 3, "A wots chain should be at least 16 hash operations long (wotsbits > 1)");
    std::vector<uint32_t> rval;
    //Calculate (compile-time) how many sub-keys are needed for signing hashlen bytes of data
    constexpr static int subkey_count =  (hashlen * 8 + wotsbits -1) / wotsbits;
    //Calculate how many aditional bits we need to pad our input with because subkey_count would give us
    // sligthly more than hashlen input to sign.
    constexpr static size_t morebits = subkey_count * wotsbits - hashlen * 8;
    //variable used to store remaing bits from previous subkey signature (or padding at operation start)
    uint32_t val = 0;
    //remaining bits to sign with single subkey
    uint32_t remaining_bits = wotsbits - morebits;
    //byte of input digest we are currently signing
    uint32_t byteindex = 0;
    //Cast to unsigned for use with libsodium
    const unsigned char *data = reinterpret_cast<const unsigned char *>(msg_digest.c_str());
    while (byteindex < hashlen) {
        //Add whole bytes to val before signing.
        while (remaining_bits > 8) {
            val = (val << 8) + data[byteindex];
            byteindex++;
            remaining_bits -= 8;
        }
        //Add partial byte to val before signing
        val = (val << remaining_bits) + (data[byteindex] >> (8-remaining_bits));
        //Append the value to sign to the return vector of this function
        rval.push_back(val);
        //Zero out bits of current bytes already used for the value just applied
        uint32_t val2 = ((data[byteindex] << remaining_bits) & 255) >> remaining_bits;
        //Number of bits actually used for next value by previous operation.
        uint32_t used_bits = 8 - remaining_bits;
        //If wotsbits is smaller than a byte, see if we need to push back more signable numbers for the current byte.
        while (used_bits >= wotsbits) {
            //Shift-left val2 as to get the next value
            val = val2 >> (used_bits - wotsbits);
            //Add sub-byte signable value to return vector
            rval.push_back(val);
            //Once more, calculate number of bits actually used for next value by previous operation.
            used_bits -= wotsbits;
            //Zero out more bits of current bytes already used for the value just applied
            val2 = ((val2 << (8-used_bits)) & 255) >> (8-used_bits);
        }
        //use val2 in the next time around (if any).
        val = val2;
        // remaining bits to sign with single subkey next time around the loop
        remaining_bits = wotsbits - used_bits;
        // On to the next digest byte.
        byteindex++;
    }
    return rval;
}

//Helper function for turning a small number into a vector of booleans (bits).
template<uint8_t merkleheight>
std::vector<bool> as_bits(uint32_t signing_key_index)
{
    //The height of a singe merkle-tree must be 3 up to 16 levels.
    static_assert(merkleheight < 17, "A single merkle tree should not be more than 16 levels high");
    static_assert(merkleheight > 2, "A single merkle tree should be at least two levels high. A value between 8 and 10 is recomended");
    std::vector<bool> rval;
    //Go from left (higher index value) to right (zero).
    for (uint8_t index=merkleheight; index>0; index--) {
        //Convert one bit into a boolean.
        bool val = (((signing_key_index >> (index - 1)) & 1) == 1);
        //Add boolena to return vector.
        rval.push_back(val);
    }
    return rval;
}

// Hashing primative for 'hashlen' long digests, with a little extra. The hashing primative runs using libsodium.
template<uint8_t hashlen, uint8_t wotsbits, uint8_t merkleheight>
struct primative {
    //Hash length must be 16 up to 64 bytes long.
    static_assert(hashlen > 15, "Hash size should be at least 128 bits (16 bytes).");
    static_assert(hashlen < 65,  "Hash size of more then 512 bits is not supported");
    //The number of bits used for wots encoding must be 3 upto 16 bits.
    static_assert(wotsbits < 17, "Wots chains longer than 64k hash operations (wotsbits>16) are not supported");
    static_assert(wotsbits > 3, "A wots chain should be at least 16 hash operations long (wotsbits > 1)");
    //The height of a singe merkle-tree must be 3 up to 16 levels.
    static_assert(merkleheight < 17, "A single merkle tree should not be more than 16 levels high");
    static_assert(merkleheight > 2, "A single merkle tree should be at least two levels high. A value between 8 and 10 is recomended");
    static_assert(39 * wotsbits >= hashlen * 8, "Wotsbits and hashlen must not combine into signing keys of more than 39 subkeys each");
    // Virtual distructor
    virtual ~primative() {}
    //Hash the input with the salt and return the digest.
    std::string operator()(std::string &input)
    {
        unsigned char output[hashlen];
        crypto_generichash_blake2b(output,
                                   hashlen,
                                   reinterpret_cast<const unsigned char *>(input.c_str()),
                                   input.length(),
                                   reinterpret_cast<const unsigned char *>(m_salt.c_str()),
                                   hashlen);
        return std::string(reinterpret_cast<const char *>(output), hashlen);
    };
    //Hash the input with the salt 'times' times. This is used for wots chains.
    std::string operator()(std::string &input, size_t times)
    {
        unsigned char output[hashlen];
        std::memcpy(output, input.c_str(), hashlen);
        crypto_generichash_blake2b_state state;
        for (uint32_t index=0; index < times; index++) {
            crypto_generichash_blake2b_init(&state,
                                            reinterpret_cast<const unsigned char *>(m_salt.c_str()),
                                            hashlen,
                                            hashlen);
            crypto_generichash_blake2b_update(&state, output, hashlen);
            crypto_generichash_blake2b_final(&state, output, hashlen);
        }
        auto rval = std::string(reinterpret_cast<const char *>(output), hashlen);
        return rval;
    };
    //Hash two inputs with salts and return the digest.
    std::string operator()(std::string &input, std::string &input2)
    {
        unsigned char output[hashlen];
        crypto_generichash_blake2b_state state;
        crypto_generichash_blake2b_init(&state,
                                        reinterpret_cast<const unsigned char *>(m_salt.c_str()),
                                        hashlen,
                                        hashlen);
        crypto_generichash_blake2b_update(&state,
                                          reinterpret_cast<const unsigned char *>(input.c_str()),
                                          hashlen);
        crypto_generichash_blake2b_update(&state,
                                          reinterpret_cast<const unsigned char *>(input2.c_str()),
                                          hashlen);
        crypto_generichash_blake2b_final(&state, output, hashlen);
        return std::string(reinterpret_cast<const char *>(output), hashlen);
    };
    //Convert the seed, together with the index of the full-message-signing-key, the sub-index
    // of the wotsbits chunk of bits to sign, and the bit indicating the left or right wots chain
    // for these indices, into the secret key for signing wotsbits bits with.
    //std::string seed_to_secret(std::string &seed, uint64_t master_index)
    //{
        //unsigned char unsalted[hashlen];
        //unsigned char output[hashlen];
        //std::string sidec = (side) ? "R" : "L";
        //std::string designator=std::to_string(index) + sidec + std::to_string(subindex);
        //crypto_generichash_blake2b(unsalted,
        //                           hashlen,
        //                           reinterpret_cast<const unsigned char *>(designator.c_str()),
        //                           designator.length(),
        //                           reinterpret_cast<const unsigned char *>(seed.c_str()),
        //                           hashlen);
        //crypto_generichash_blake2b(output,
        //                           hashlen,
        //                           unsalted,
        //                           hashlen,
        //                           reinterpret_cast<const unsigned char *>(m_salt.c_str()),
        //                           hashlen);
        //return std::string(reinterpret_cast<const char *>(output), hashlen);
	//FIXME: use libsodium key derivation.
//	auto ind = master_index;
//	ind++;
//	return seed;
  //  };
    //Retreive the salt for serialization purposes and later usage.
    std::string get_salt()
    {
        return m_salt;
    }
    void refresh(std::string &salt)
    {
        m_salt = salt;
    }
    friend signing_key<hashlen, wotsbits, merkleheight>;
    friend signature<hashlen, wotsbits, merkleheight>;
private:
    // Standard constructor using an existing salt.
    primative(std::string &salt): m_salt(salt) {}
    //Alternative constructor. Generates a random salt.
    //primative(GENERATE): m_salt(make_seed()) {}
    std::string m_salt;
};

//A private key is a collection of subkeys that together can create a one-time-signature for
// a single transaction/message digest.
template<uint8_t hashlen, int subkey_count, uint8_t wotsbits, uint8_t merkleheight, uint32_t pubkey_size>
struct private_key {
    //Hash length must be 16 up to 64 bytes long.
    static_assert(hashlen > 15, "Hash size should be at least 128 bits (16 bytes).");
    static_assert(hashlen < 65,  "Hash size of more then 512 bits is not supported");
    //The number of bits used for wots encoding must be 3 upto 16 bits.
    static_assert(wotsbits < 17, "Wots chains longer than 64k hash operations (wotsbits>16) are not supported");
    static_assert(wotsbits > 3, "A wots chain should be at least 16 hash operations long (wotsbits > 1)");
    //The height of a singe merkle-tree must be 3 up to 16 levels.
    static_assert(merkleheight < 17, "A single merkle tree should not be more than 16 levels high");
    static_assert(merkleheight > 2, "A single merkle tree should be at least two levels high. A value between 8 and 10 is recomended");
    static_assert(39 * wotsbits >= hashlen * 8, "Wotsbits and hashlen must not combine into signing keys of more than 39 subkeys each");
    // A tiny chunk of a one-time (wots) signing key, able to sign a chunk of 'wotsbits' bits with.
    struct subkey {
        //constructor, takes hashing primative, a seed, the one-time-signature index and the
        // chunk sub-index and created the chunk private for both direction wots chains.
        subkey(primative<hashlen, wotsbits, merkleheight> &hashprimative,
               subkey_index_generator<hashlen> entropy,
               size_t index,
               size_t subindex,
               std::string restore=""):
            m_index(index),
            m_subindex(subindex),
            m_hashprimative(hashprimative),
            m_private(), m_public(restore)
        {
	    for (bool side : { false, true }) {
		std::string secret = entropy(side);
                m_private.push_back(secret);
            }
        };
        // virtual destructor
        virtual ~subkey() {};
        // calculate the public key for matching the private key for signing
        // the chunk of wotsbits, we do this by hashing both the left and the
        // right private key a largeish number of times (2^wotsbits times)
        std::string pubkey()
        {
            if (m_public == "") {
                std::string privkey_1 = m_hashprimative(m_private[0], 1<<wotsbits);
                std::string privkey_2 = m_hashprimative(m_private[1], 1<<wotsbits);
                m_public = m_hashprimative(privkey_1, privkey_2);
            }
            return m_public;
        };
        // We use the index operator for signing a chunk of 'wotsbits' bits
        // encoded into an unsigned integer.
        std::string operator [](uint32_t index)
        {
            return m_hashprimative(m_private[0], index) + m_hashprimative(m_private[1], (1<<wotsbits) - index -1);
        }
    private:
        size_t m_index;
        size_t m_subindex;
        primative<hashlen, wotsbits, merkleheight> &m_hashprimative; // The core hashing primative
        std::vector<std::string> m_private;  // The private key as generated at construction.
        std::string m_public;                // The public key, calculated lazy, on demand.
    };
    // Virtual destructor
    virtual ~private_key() {};
    //Get the pubkey for the single-use private key.
    std::string pubkey()
    {
        std::string rval("");
        //Compose by concattenating the pubkey for all the sub keys.
        std::for_each(std::begin(m_subkeys), std::end(m_subkeys), [&rval, this](subkey &value) {
            rval += value.pubkey();
        });
        return rval;
    };
    //Note: the square bracket operator is used for signing a digest.
    std::string operator [](std::string &digest)
    {
        //Convert the digest to a list of numbers that we shall sign with the sub keys for this private key.
        auto numlist = digest_to_numlist<hashlen, wotsbits>(digest);
        std::string rval;
        size_t nl_len = numlist.size();
        //Concattenate all the subkey based signatures into one large signing key.
        for(size_t index=0; index < nl_len; index++) {
            rval += m_subkeys[index][numlist[index]];
        };
        return rval;
    };
    //Only private_keys should invoke the constructor
    friend private_keys<hashlen, merkleheight, wotsbits, pubkey_size>;
private:
    //Private constructor, should only get invoked by private_keys
    private_key(primative<hashlen, wotsbits, merkleheight> &hashprimative,
                wots_index_generator<hashlen, wotsbits> entropy,
                size_t index,
                std::string &recovery,
		uint64_t master_index): m_subkeys(), m_master_index(master_index)
    {
        auto FIXME = recovery;
        //Compose from its sub-keys.
        for(uint16_t subindex=0; subindex < subkey_count; subindex++) {
            m_subkeys.push_back(subkey(hashprimative, entropy[subindex], index, subindex));
        }
    };
    std::vector<subkey> m_subkeys;
    uint64_t m_master_index;
};

// Collection of all one-time signing keys belonging with a signing key
template<uint8_t hashlen,  uint8_t merkleheight, uint8_t wotsbits, uint32_t pubkey_size>
struct private_keys {
    //Hash length must be 16 up to 64 bytes long.
    static_assert(hashlen > 15, "Hash size should be at least 128 bits (16 bytes).");
    static_assert(hashlen < 65,  "Hash size of more then 512 bits is not supported");
    //The number of bits used for wots encoding must be 3 upto 16 bits.
    static_assert(wotsbits < 17, "Wots chains longer than 64k hash operations (wotsbits>16) are not supported");
    static_assert(wotsbits > 3, "A wots chain should be at least 16 hash operations long (wotsbits > 1)");
    //The height of a singe merkle-tree must be 3 up to 16 levels.
    static_assert(merkleheight < 17, "A single merkle tree should not be more than 16 levels high");
    static_assert(merkleheight > 2, "A single merkle tree should be at least two levels high. A value between 8 and 10 is recomended");
    static_assert(39 * wotsbits >= hashlen * 8, "Wotsbits and hashlen must not combine into signing keys of more than 39 subkeys each");
    static constexpr uint32_t subkey_count =  (hashlen * 8 + wotsbits -1) / wotsbits;
    // Virtual destructor
    virtual ~private_keys() {};
    //Square bracket operator used to access specific private key.
    private_key<hashlen, (hashlen*8 + wotsbits -1)/wotsbits,wotsbits, merkleheight, pubkey_size> &operator [](uint32_t index)
    {
        return this->m_keys[index];
    };
    void refresh(primative<hashlen, wotsbits, merkleheight> &hashprimative, non_api::unique_index_generator<hashlen, wotsbits, merkleheight> entropy, uint64_t master_index)
    {
        m_master_index = master_index;
        std::vector<private_key<hashlen,(hashlen * 8 + wotsbits -1) / wotsbits, wotsbits, merkleheight, pubkey_size>>  empty;
        m_keys.swap(empty);
        for (uint16_t index=0; index < pubkey_size; index++) {
            m_keys.push_back(
                private_key<hashlen, subkey_count, wotsbits, merkleheight, pubkey_size>(hashprimative,
                        entropy[index],
                        index,
                        m_empty,
			m_master_index + index * 2 * subkey_count));
        }
    }
    std::string pubkey()
    {
        std::string rval;
        for ( auto &privkey : m_keys) {
            rval += privkey.pubkey();
        }
        return rval;
    }
    //Only signing_key should invoke the constructor for private_keys
    friend signing_key<hashlen, wotsbits, merkleheight>;
private:
    //Private constructor, only to be called from signing_key
    private_keys(primative<hashlen, wotsbits, merkleheight> &hashprimative,
		 non_api::unique_index_generator<hashlen, wotsbits, merkleheight> entropy,
		 std::string &recovery,
                 uint64_t master_index):
        m_keys(), m_empty(), m_master_index(master_index)
    {
        // Construct from multiple private_key's
        for (uint16_t index=0; index < pubkey_size; index++) {
            m_keys.push_back(
                private_key<hashlen, subkey_count, wotsbits, merkleheight, pubkey_size>(hashprimative,
                        entropy[index],
                        index,
                        recovery,
			m_master_index + 2 * index * subkey_count));
        }
    };
    std::vector<private_key<hashlen,(hashlen * 8 + wotsbits -1) / wotsbits, wotsbits, merkleheight, pubkey_size>>  m_keys;
    std::string m_empty;
    uint64_t m_master_index;
};
}
// Public API signing_key
template<uint8_t hashlen, uint8_t wotsbits, uint8_t merkleheight>
struct signing_key {
    //Hash length must be 16 up to 64 bytes long.
    static_assert(hashlen > 15, "Hash size should be at least 128 bits (16 bytes).");
    static_assert(hashlen < 65,  "Hash size of more then 512 bits is not supported");
    //The number of bits used for wots encoding must be 3 upto 16 bits.
    static_assert(wotsbits < 17, "Wots chains longer than 64k hash operations (wotsbits>16) are not supported");
    static_assert(wotsbits > 3, "A wots chain should be at least 16 hash operations long (wotsbits > 1)");
    //The height of a singe merkle-tree must be 3 up to 16 levels.
    static_assert(merkleheight < 17, "A single merkle tree should not be more than 16 levels high");
    static_assert(merkleheight > 2, "A single merkle tree should be at least two levels high. A value between 8 and 10 is recomended");
    static_assert(39 * wotsbits >= hashlen * 8, "Wotsbits and hashlen must not combine into signing keys of more than 39 subkeys each");
    // The merkle-tree that maps a larger collection of single use private/public keys, to a single merkle-root public key.
    // Also used in encoding signatures.
    struct merkle_tree {
        //Merkle-tree constructor
        merkle_tree(non_api::primative<hashlen, wotsbits, merkleheight> & hashfunction,
                    non_api::private_keys<hashlen,
                    merkleheight,
                    wotsbits,
                    static_cast<unsigned short>(1) << merkleheight > &privkey): m_hashfunction(hashfunction),
            m_private_keys(privkey),
            m_merkle_tree()
        {
        };
        //Virtual destructor
        virtual ~merkle_tree() {};

        void refresh()
        {
            m_merkle_tree.clear();
            this->populate<merkleheight>(0, "");
        }
        //Get the merkle-root, what is the same as the signing_key public key.
        std::string pubkey()
        {
            //Populate the tree if it hasn't already been.
            if ( m_merkle_tree.find("") == m_merkle_tree.end() ) {
                this->populate<merkleheight>(0, "");
            }
            //Return the merkle root
            return m_merkle_tree[""];
        };
        //Square bracket operator is used to get the merkle-tree signature-header for a given signing key index number.
        //The merkle-tree signature-header contains those merkle tree node hashes needed to get from the wots signature
        //public key to the merkle root node.
        std::string operator [](uint32_t signing_key_index)
        {
            //Populate if needed.
            if ( m_merkle_tree.find("") == m_merkle_tree.end() ) {
                this->populate<merkleheight>(0, "");
            }
            //Convert the signing key index into a vector of booleans
            std::vector<bool> index_bits = non_api::as_bits<merkleheight>(signing_key_index);
            std::string rval;
            // For each depth in the tree extract one node.
            for (uint8_t bindex=0; bindex < merkleheight; bindex++) {
                std::string key;
                //For each bit of a given depth, except the last, pick use the input designation
                for (uint8_t index=0; index<bindex; index++) {
                    key += index_bits[index] ? std::string("1") : std::string("0");
                }
                //For the last bit, get the oposing node.
                key += index_bits[bindex] ? std::string("0") : std::string("1");
                rval += m_merkle_tree[key];
            }
            return rval;
        };
    private:
        //Populate the merkle tree by populating the public keys for all the private keys of the signing key.
        //Populating is initiated at merkleheight height, and works its way down.
        template<uint8_t remaining_height>
        std::string populate(uint32_t start, std::string prefix)
        {
            if constexpr (remaining_height != 0) {
                //Polulate the left branch and get the top node hash
                std::string left = this->populate<remaining_height-1>(start,prefix + "0");
                //Populate the right branch and get the top node hash
                std::string right = this->populate<remaining_height-1>(start + (1 << (remaining_height - 1)),
                                    prefix + "1");
                //Set the node hash value at this level.
                m_merkle_tree[prefix] = m_hashfunction(left, right);
            }
            else {
                //Leaf-node, the salted hash of the  wots pubkey.
                std::string pkey = m_private_keys[start].pubkey();
                m_merkle_tree[prefix] =  m_hashfunction(pkey);
            }
            return m_merkle_tree[prefix];
        }
        non_api::primative<hashlen, wotsbits, merkleheight> &m_hashfunction;
        non_api::private_keys<hashlen,
                merkleheight,
                wotsbits,
                static_cast<unsigned short>(1) << merkleheight > &m_private_keys;
        std::map<std::string, std::string> m_merkle_tree;
    };
    signing_key(non_api::unique_index_generator<hashlen, wotsbits, merkleheight> entropy):
	m_entropy(entropy),
	m_next_index(0),
	m_salt(entropy),
        m_hashfunction(m_salt),
        m_empty(),
        m_master_index(entropy),
        m_privkeys(m_hashfunction, entropy, m_empty, m_master_index),
        m_merkle_tree(m_hashfunction, m_privkeys)
    {
        //Get pubkey as a way to populate.
        this->m_merkle_tree.pubkey();
    };
    //Make a new key when current one is exhausted
    void refresh(non_api::unique_index_generator<hashlen, wotsbits, merkleheight> entropy)
    {
        m_master_index = entropy;
        m_next_index = 0;
	std::string salt(entropy);
        m_hashfunction.refresh(salt);
        m_privkeys.refresh(m_hashfunction, entropy, m_master_index);
        m_merkle_tree.refresh();
    }
    //Sign a hashlength bytes long digest.
    std::string sign_digest(std::string digest)
    {
        assert(digest.length() == hashlen);
        //Throw an exception when key is already fully exhausted
        if (this->m_next_index >= (1 << merkleheight)) {
            throw signingkey_exhausted();
        }
        //Get the signature index in network order.
        uint16_t ndx = htons(this->m_next_index);
        std::string ndxs = std::string(reinterpret_cast<const char *>(&ndx), 2);
        //Compose the signature of its parts.
        std::string rval = this->m_merkle_tree.pubkey() + //The signing key's pubkey
                           this->m_hashfunction.get_salt() +         //The signing key's salt
                           ndxs +                                    //The signature wots priv/pubkey index
                           this->m_merkle_tree[m_next_index] +       //The merkle-tree header, a collection of merkle tree
			                                             // nodes needed to get from wots signatures to pubkey.
                           this->m_privkeys[m_next_index][digest];   //The collection of wots signatures.
        this->m_next_index++;
        return rval;
    };
    //Sign an arbitrary length message
    std::string sign_message(std::string &message)
    {
        //Take the hash of the message.
        std::string digest = m_hashfunction(message);
        //Sign the hash
        return this->sign_digest(digest);
    };
    //Future API call for serializing the signing key.
    std::tuple<std::string,  uint16_t, std::string>  get_state()
    {
        return std::make_tuple(m_hashfunction.get_salt(), m_next_index,  m_privkeys.pubkey());
    }
    uint16_t get_next_index()
    {
        return m_next_index;
    }
    std::string pubkey()
    {
        return m_merkle_tree.pubkey();
    }
    //Virtual destructor
    virtual ~signing_key() {}
private:
    non_api::unique_index_generator<hashlen, wotsbits, merkleheight> m_entropy;
    uint16_t m_next_index;
    std::string m_salt;
    non_api::primative<hashlen, wotsbits, merkleheight> m_hashfunction;
    std::string m_empty;
    uint64_t m_master_index;
    non_api::private_keys<hashlen, merkleheight, wotsbits, static_cast<unsigned short>(1) << merkleheight > m_privkeys;
    merkle_tree m_merkle_tree;
};

// The multi-tree variant of the signing key. First for three and more merkle trees.
template<uint8_t hashlen, uint8_t wotsbits, uint8_t merkleheight, uint8_t merkleheight2, uint8_t ...Args>
struct multi_signing_key {
    //Hash length must be 16 up to 64 bytes long.
    static_assert(hashlen > 15, "Hash size should be at least 128 bits (16 bytes).");
    static_assert(hashlen < 65,  "Hash size of more then 512 bits is not supported");
    //The number of bits used for wots encoding must be 3 upto 16 bits.
    static_assert(wotsbits < 17, "Wots chains longer than 64k hash operations (wotsbits>16) are not supported");
    static_assert(wotsbits > 3, "A wots chain should be at least 16 hash operations long (wotsbits > 1)");
    //The height of a singe merkle-tree must be 3 up to 16 levels.
    static_assert(merkleheight < 17, "A single merkle tree should not be more than 16 levels high");
    static_assert(merkleheight > 2, "A single merkle tree should be at least two levels high. A value between 8 and 10 is recomended");
    static_assert(merkleheight2 < 17, "A single merkle tree should not be more than 16 levels high");
    static_assert(merkleheight2 > 2, "A single merkle tree should be at least two levels high. A value between 8 and 10 is recomended");
    static_assert(39 * wotsbits >= hashlen * 8, "Wotsbits and hashlen must not combine into signing keys of more than 39 subkeys each");
    multi_signing_key(bool assume_peer_caching, non_api::unique_index_generator<hashlen, wotsbits, merkleheight, merkleheight2, Args...> entropy):
	m_entropy(entropy),
	m_child_index(0),
	m_root_key(entropy.cast()),
        m_signing_key(assume_peer_caching, entropy(m_child_index)),
        m_signing_key_signature(m_root_key.sign_digest(m_signing_key.pubkey())),
        m_assume_peer_caching(assume_peer_caching) {
	}
    std::pair<std::string, std::vector<std::pair<std::string, std::string>>> sign_message(std::string &message)
    {
        try {
            auto rval = m_signing_key.sign_message(message);
            rval.second.push_back(std::make_pair(m_signing_key.pubkey(), m_signing_key_signature));
            return rval;
        }
        catch  (const spqsigs::signingkey_exhausted&) {
            m_signing_key.refresh();
            m_signing_key_signature = m_root_key.sign_digest(m_signing_key.pubkey());
            auto rval = m_signing_key.sign_message(message);
            rval.second.push_back(std::make_pair(m_signing_key.pubkey(), m_signing_key_signature));
            return rval;
        }
    }
    std::vector<std::pair<std::tuple<std::string, uint16_t, std::string>, std::string>> get_state()
    {
        auto rval = m_signing_key.get_state();
        rval.push_back(std::pair<std::tuple<std::string, uint16_t, std::string>, std::string>(m_root_key.get_state(), m_signing_key_signature));
        return rval;
    }

    std::string pubkey()
    {
        return m_root_key.pubkey();
    }
    void refresh()
    {
	m_child_index++;
	m_signing_key.refresh(m_entropy(m_child_index));
	m_signing_key_signature = m_root_key.sign_digest(m_signing_key.pubkey());
    }
    void refresh(non_api::unique_index_generator<hashlen, wotsbits, merkleheight2, Args...> new_entropy)
    {   
	m_entropy = new_entropy;
	m_child_index = 0;
        m_root_key.refresh(new_entropy);
        m_signing_key.refresh(m_entropy(m_child_index));
        m_signing_key_signature = m_root_key.sign_digest(m_signing_key.pubkey());
    }
    virtual ~multi_signing_key() {}
private:
    non_api::unique_index_generator<hashlen, wotsbits, merkleheight, merkleheight2, Args...> m_entropy;
    uint16_t m_child_index;
    signing_key<hashlen, wotsbits, merkleheight> m_root_key;
    multi_signing_key<hashlen, wotsbits, merkleheight2, Args...> m_signing_key;
    std::string m_signing_key_signature;
    bool m_assume_peer_caching;
};

// The multi-tree variant of the signing key. This one is for two merkle trees to close of the stack.
template<uint8_t hashlen, uint8_t wotsbits, uint8_t merkleheight, uint8_t merkleheight2>
struct multi_signing_key<hashlen, wotsbits, merkleheight, merkleheight2> {
    //Hash length must be 16 up to 64 bytes long.
    static_assert(hashlen > 15, "Hash size should be at least 128 bits (16 bytes).");
    static_assert(hashlen < 65,  "Hash size of more then 512 bits is not supported");
    //The number of bits used for wots encoding must be 3 upto 16 bits.
    static_assert(wotsbits < 17, "Wots chains longer than 64k hash operations (wotsbits>16) are not supported");
    static_assert(wotsbits > 3, "A wots chain should be at least 16 hash operations long (wotsbits > 1)");
    //The height of a singe merkle-tree must be 3 up to 16 levels.
    static_assert(merkleheight < 17, "A single merkle tree should not be more than 16 levels high");
    static_assert(merkleheight > 2, "A single merkle tree should be at least two levels high. A value between 8 and 10 is recomended");
    static_assert(merkleheight2 < 17, "A single merkle tree should not be more than 16 levels high");
    static_assert(merkleheight2 > 2, "A single merkle tree should be at least two levels high. A value between 8 and 10 is recomended");
    static_assert(39 * wotsbits >= hashlen * 8, "Wotsbits and hashlen must not combine into signing keys of more than 39 subkeys each");
    multi_signing_key(bool assume_peer_caching, non_api::unique_index_generator<hashlen, wotsbits, merkleheight, merkleheight2> entropy) :
	m_entropy(entropy),
	m_cast(entropy.cast()),
	m_child_index(0),
        m_root_key(m_cast),
        m_signing_key(entropy(m_child_index)),
        m_signing_key_signature(m_root_key.sign_digest(m_signing_key.pubkey())),
        m_assume_peer_caching(assume_peer_caching) {
	}
    std::pair<std::string, std::vector<std::pair<std::string, std::string>>> sign_message(std::string &message)
    {
        std::string signature;
        try {
            signature = m_signing_key.sign_message(message);
        }
        catch  (const spqsigs::signingkey_exhausted&) {
            m_child_index++;
            m_signing_key.refresh(m_entropy(m_child_index));
            m_signing_key_signature = m_root_key.sign_digest(m_signing_key.pubkey());
            signature = m_signing_key.sign_message(message);
        }
        std::vector<std::pair<std::string, std::string>> rval;
        rval.push_back(std::make_pair(m_signing_key.pubkey(), m_signing_key_signature));
        return std::make_pair(signature,rval);
    }
    std::vector<std::pair<std::tuple<std::string, uint16_t, std::string>, std::string>> get_state()
    {
        std::vector<std::pair<std::tuple<std::string, uint16_t, std::string>, std::string>> rval;
        rval.push_back(std::pair<std::tuple<std::string, uint16_t, std::string>, std::string>(m_signing_key.get_state(), std::string("")));
        rval.push_back(std::pair<std::tuple<std::string, uint16_t, std::string>, std::string>(m_root_key.get_state(), m_signing_key_signature));
        return rval;
    }
    std::string pubkey()
    {
        return m_root_key.pubkey();
    }
    void refresh()
    {
	m_child_index++;
	m_signing_key.refresh(m_entropy(m_child_index));
	m_signing_key_signature = m_root_key.sign_digest(m_signing_key.pubkey());
    }
    void refresh(non_api::unique_index_generator<hashlen, wotsbits, merkleheight, merkleheight2> new_entropy)
    {
        m_entropy = new_entropy;
        m_child_index = 0;
        m_root_key.refresh(new_entropy.cast());
        m_signing_key.refresh(m_entropy(m_child_index));
        m_signing_key_signature = m_root_key.sign_digest(m_signing_key.pubkey());
    }
    uint64_t get_step() {
        return 1 + (1<<merkleheight);
    }
    virtual ~multi_signing_key() {}
private:
    non_api::unique_index_generator<hashlen, wotsbits, merkleheight, merkleheight2> m_entropy;
    non_api::unique_index_generator<hashlen, wotsbits, merkleheight> m_cast;
    uint16_t m_child_index;
    signing_key<hashlen, wotsbits, merkleheight> m_root_key;
    signing_key<hashlen, wotsbits, merkleheight2> m_signing_key;
    std::string m_signing_key_signature;
    bool m_assume_peer_caching;
};

// Work In Progress
template<uint8_t hashlen, uint8_t ...Args> 
struct spq_signing_key {
        spq_signing_key(bool assume_peer_caching=false): m_master_key(), m_entropy(m_master_key), m_multi_key(assume_peer_caching, m_entropy) {}
	spq_signing_key(std::string private_key, bool assume_peer_caching): m_master_key(private_key), m_entropy(m_master_key), m_multi_key(assume_peer_caching, m_entropy) {}
        std::pair<std::string, std::vector<std::pair<std::string, std::string>>> sign_message(std::string &message) {
            return m_multi_key.sign_message(message);
	}
	std::string public_key() {
	    return m_multi_key.pubkey();
	}
	std::string private_key() {
            return m_master_key;
	}
    private:
        non_api::master_key<hashlen> m_master_key;
	non_api::unique_index_generator<hashlen, Args...> m_entropy;
	multi_signing_key<hashlen, Args...> m_multi_key;
};

//Public-API signature
template<uint8_t hashlen, uint8_t wotsbits, uint8_t merkleheight>
struct signature {
    //Hash length must be 16 up to 64 bytes long.
    static_assert(hashlen > 15, "Hash size should be at least 128 bits (16 bytes).");
    static_assert(hashlen < 65,  "Hash size of more then 512 bits is not supported");
    //The number of bits used for wots encoding must be 3 upto 16 bits.
    static_assert(wotsbits < 17, "Wots chains longer than 64k hash operations (wotsbits>16) are not supported");
    static_assert(wotsbits > 3, "A wots chain should be at least 16 hash operations long (wotsbits > 1)");
    //The height of a singe merkle-tree must be 3 up to 16 levels.
    static_assert(merkleheight < 17, "A single merkle tree should not be more than 16 levels high");
    static_assert(merkleheight > 2, "A single merkle tree should be at least two levels high. A value between 8 and 10 is recomended");
    static_assert(39 * wotsbits >= hashlen * 8, "Wotsbits and hashlen must not combine into signing keys of more than 39 subkeys each");
    signature(std::string sigstring): m_pubkey(), m_salt(), m_index(0), m_mt_bits(),m_merkle_tree_header(), m_signature_body()
    {
        constexpr int subkey_count = (hashlen * 8 + wotsbits -1) / wotsbits;
        constexpr size_t expected_length = 2 + hashlen * (2 + merkleheight + 2 * subkey_count);
        // * check signature length
        if (sigstring.length() != expected_length) {
            throw std::invalid_argument("Wrong signature size. *1");
        }
        // * get pubkey, salt, index, mt-header and wots-body and store them till validate gets invoked
        m_pubkey = std::string(sigstring.c_str(), hashlen);
        m_salt = std::string(sigstring.c_str()+hashlen, hashlen);
        std::string s_index = std::string(sigstring.c_str()+hashlen*2, 2);
        const unsigned char * us_index = reinterpret_cast<const unsigned char *>(s_index.c_str());
        m_index = (us_index[0] << 8) + us_index[1];
        m_mt_bits = non_api::as_bits<merkleheight>(m_index);
        std::reverse(m_mt_bits.begin(), m_mt_bits.end());
        for (int index=0; index < merkleheight; index++) {
            m_merkle_tree_header.push_back(std::string(sigstring.c_str()+hashlen*(2+index)+2, hashlen));
        }
        std::reverse(m_merkle_tree_header.begin(), m_merkle_tree_header.end());
        for (int index=0; index < subkey_count; index++) {
            std::vector<std::string> newval;
            for (int direction=0; direction<2; direction++) {
                newval.push_back(std::string(sigstring.c_str()+2 + hashlen * (2 + merkleheight + 2 * index + direction),
                                             hashlen));
            }
            m_signature_body.push_back(newval);
        }
    }
    bool validate(std::string message, bool is_digest=false)
    {
        // * get the message digest
        non_api::primative<hashlen, wotsbits, merkleheight> hashfunction(m_salt);
        std::string digest = message;
        if (is_digest == false) {
            digest = hashfunction(message);
        }
        //Convert the digest to a list of numbers, the same list used for signing.
        auto numlist = non_api::digest_to_numlist<hashlen, wotsbits>(digest);
        // * complete the wots chains and calculate what should be the WOTS pubkey for this index.
        std::string big_ots_pubkey("");
        for (size_t index=0; index < numlist.size(); index++) {
            auto signature_chunk = m_signature_body[index];
            int chunk_num = numlist[index];
            //Complete wots chains
            std::string pk1 = hashfunction(signature_chunk[0], (1 << wotsbits) - chunk_num);
            std::string pk2 = hashfunction(signature_chunk[1], chunk_num + 1);
            //Combine left and right into one pubkey and append that to the big WOTS pubkey reconstruction.
            big_ots_pubkey += hashfunction(pk1, pk2);
        }
        //Take the salted hash of the large WOTS pubkey reconstruction
        std::string calculated_pubkey = hashfunction(big_ots_pubkey);
        //Reconstruct what should be the pubkey from the previous hash and the merkle-tree header nodes.
        for (size_t index=0; index < m_mt_bits.size(); index++) {
            if  (m_mt_bits[index]) {
                calculated_pubkey = hashfunction(m_merkle_tree_header[index], calculated_pubkey);
            }
            else {
                calculated_pubkey = hashfunction(calculated_pubkey, m_merkle_tree_header[index]);
            }
        }
        //If everything is irie, the pubkey and the reconstructed pubkey should be the same.
        return calculated_pubkey == m_pubkey;
    }
    //Get the current index, this is the statefull part of the signing key.
    uint32_t get_index()
    {
        return m_index;
    }
    //Get the public key of the signing key.
    std::string get_pubkey()
    {
        return m_pubkey;
    }
    //Get the value of the salt string for this signing key.
    std::string get_pubkey_salt()
    {
        return m_salt;
    }
private:
    std::string m_pubkey;
    std::string m_salt;
    uint32_t m_index;
    std::vector<bool> m_mt_bits;
    std::vector<std::string> m_merkle_tree_header;
    std::vector<std::vector<std::string>> m_signature_body;
};


template<uint8_t hashlen, uint8_t wotsbits, uint8_t merkleheight, uint8_t merkleheight2, uint8_t ...Args>
struct multi_signature {
    //Hash length must be 16 up to 64 bytes long.
    static_assert(hashlen > 15, "Hash size should be at least 128 bits (16 bytes).");
    static_assert(hashlen < 65,  "Hash size of more then 512 bits is not supported");
    //The number of bits used for wots encoding must be 3 upto 16 bits.
    static_assert(wotsbits < 17, "Wots chains longer than 64k hash operations (wotsbits>16) are not supported");
    static_assert(wotsbits > 3, "A wots chain should be at least 16 hash operations long (wotsbits > 1)");
    //The height of a singe merkle-tree must be 3 up to 16 levels.
    static_assert(merkleheight < 17, "A single merkle tree should not be more than 16 levels high");
    static_assert(merkleheight > 2, "A single merkle tree should be at least two levels high. A value between 8 and 10 is recomended");
    static_assert(merkleheight2 < 17, "A single merkle tree should not be more than 16 levels high");
    static_assert(merkleheight2 > 2, "A single merkle tree should be at least two levels high. A value between 8 and 10 is recomended");
    static_assert(39 * wotsbits >= hashlen * 8, "Wotsbits and hashlen must not combine into signing keys of more than 39 subkeys each");
    multi_signature(std::pair<std::string, std::vector<std::pair<std::string, std::string>>> &sig,
                    std::vector<std::string> &last_known,
                    int treedepth=0):
        m_level_ok(true),
        m_cached(true),
        m_signature(sig),
        m_index(0),
        m_last_known(last_known),
        m_treedepth(treedepth),
        m_deeper_signature(sig, last_known, treedepth + 1),
        m_pubkey(), m_salt()
    {
        auto tree_count = treedepth +  sizeof...(Args) + 2;
        auto my_index = tree_count - treedepth - 2;
        auto expected = last_known[my_index];
        auto found = sig.second[my_index].first;
        if (found != expected) {
            m_cached = false;
            signature<hashlen, wotsbits, merkleheight> pubkey_signature(sig.second[my_index].second);
            m_level_ok = pubkey_signature.validate(found, true);
            if (m_level_ok) {
                if (pubkey_signature.get_pubkey() != last_known[my_index + 1]) {
                    if (my_index < tree_count - 2) {
                        if (pubkey_signature.get_pubkey() != sig.second[my_index + 1].first) {
                            m_level_ok = false;
                        }
                    }
                    else {
                        m_level_ok = false;
                    }
                }
                else {
                    m_pubkey = pubkey_signature.get_pubkey();
                    m_salt = pubkey_signature.get_pubkey_salt();
                }
            }
        }
    }
    bool validate(std::string message)
    {
        return m_level_ok  and m_deeper_signature.validate(message);
    }
    std::vector<uint32_t> get_index()
    {
        std::vector<uint32_t> rval = m_deeper_signature.get_index();
        if (m_cached == false) {
            rval.insert(rval.begin(), m_index);
        }
        return rval;
    }
    std::vector<std::string> get_pubkey()
    {
        std::vector<std::string> rval = m_deeper_signature.get_pubkey();
        if (m_cached == false) {
            rval.insert(rval.begin(), m_pubkey);
        }
        return rval;
    }
    std::vector<std::string> get_pubkey_salt()
    {
        std::vector<std::string> rval = m_deeper_signature.get_pubkey_salt();
        if (m_cached == false) {
            rval.insert(rval.begin(), m_salt);
        }
        return rval;
    }
    virtual ~multi_signature() {}
private:
    bool m_level_ok;
    bool m_cached;
    std::pair<std::string, std::vector<std::pair<std::string, std::string>>> m_signature;
    uint16_t m_index;
    std::vector<std::string> &m_last_known;
    int m_treedepth;
    multi_signature<hashlen, wotsbits, merkleheight2, Args...> m_deeper_signature;
    std::string m_pubkey;
    std::string m_salt;
};

template<uint8_t hashlen, uint8_t wotsbits, uint8_t merkleheight, uint8_t merkleheight2>
struct multi_signature<hashlen, wotsbits, merkleheight, merkleheight2> {
    //Hash length must be 16 up to 64 bytes long.
    static_assert(hashlen > 15, "Hash size should be at least 128 bits (16 bytes).");
    static_assert(hashlen < 65,  "Hash size of more then 512 bits is not supported");
    //The number of bits used for wots encoding must be 3 upto 16 bits.
    static_assert(wotsbits < 17, "Wots chains longer than 64k hash operations (wotsbits>16) are not supported");
    static_assert(wotsbits > 3, "A wots chain should be at least 16 hash operations long (wotsbits > 1)");
    //The height of a singe merkle-tree must be 3 up to 16 levels.
    static_assert(merkleheight < 17, "A single merkle tree should not be more than 16 levels high");
    static_assert(merkleheight > 2, "A single merkle tree should be at least two levels high. A value between 8 and 10 is recomended");
    static_assert(merkleheight2 < 17, "A single merkle tree should not be more than 16 levels high");
    static_assert(merkleheight2 > 2, "A single merkle tree should be at least two levels high. A value between 8 and 10 is recomended");
    static_assert(39 * wotsbits >= hashlen * 8, "Wotsbits and hashlen must not combine into signing keys of more than 39 subkeys each");
    multi_signature(std::pair<std::string, std::vector<std::pair<std::string, std::string>>> &sig,
                    std::vector<std::string> &last_known,
                    int treedepth=0):
        m_level_ok(true),
        m_cached(true),
        m_message_signature(sig.first),
        m_index(0),
        m_last_known(last_known),
        m_treedepth(treedepth),
        m_pubkey(), m_salt()
    {
        auto tree_count = treedepth  + 2;
        auto my_index = tree_count - treedepth - 2;
        auto expected = last_known[my_index];
        auto found = sig.second[my_index].first;
        if (found != expected) {
            m_cached = false;
            std::string signature_string(sig.second[my_index].second);
            signature<hashlen, wotsbits, merkleheight> pubkey_signature(signature_string);
            m_level_ok = pubkey_signature.validate(m_message_signature.get_pubkey(), true);
            if (m_level_ok) {
                if (pubkey_signature.get_pubkey() != last_known[my_index + 1]) {
                    if (my_index < tree_count - 2) {
                        if (pubkey_signature.get_pubkey() != sig.second[my_index + 1].first) {
                            m_level_ok = false;
                        }
                    }
                    else {
                        m_level_ok = false;
                    }
                }
                else {
                    m_pubkey = pubkey_signature.get_pubkey();
                    m_salt = pubkey_signature.get_pubkey_salt();
                }
            }
        }
    }
    bool validate(std::string message)
    {
        bool rval = false;
        if (m_level_ok) {
            if (m_message_signature.validate(message)) {
                rval = true;
            }
        }
        return  rval;
    }
    std::vector<uint32_t> get_index()
    {
        std::vector<uint32_t>  rval;
        rval.push_back(m_message_signature.get_index());
        if (m_cached == false) {
            rval.push_back(m_index);
        }
        return rval;
    }
    std::vector<std::string> get_pubkey()
    {
        std::vector<std::string> rval;
        rval.push_back(m_message_signature.get_pubkey());
        if (m_cached == false) {
            rval.push_back(m_pubkey);
        }
        return rval;
    }
    std::vector<std::string> get_pubkey_salt()
    {
        std::vector<std::string> rval;
        rval.push_back(m_message_signature.get_pubkey_salt());
        if (m_cached == false) {
            rval.push_back(m_salt);
        }
        return rval;
    }
    virtual ~multi_signature() {}
private:
    bool m_level_ok;
    bool m_cached;
    signature<hashlen, wotsbits, merkleheight2> m_message_signature;
    uint16_t m_index;
    std::vector<std::string> &m_last_known;
    int m_treedepth;
    std::string m_pubkey;
    std::string m_salt;
};

template<uint8_t hashlen, uint8_t wotsbits, uint8_t merkleheight, uint8_t merkleheight2, uint8_t ...Args>
struct deserializer {
    //Hash length must be 16 up to 64 bytes long.
    static_assert(hashlen > 15, "Hash size should be at least 128 bits (16 bytes).");
    static_assert(hashlen < 65,  "Hash size of more then 512 bits is not supported");
    //The number of bits used for wots encoding must be 3 upto 16 bits.
    static_assert(wotsbits < 17, "Wots chains longer than 64k hash operations (wotsbits>16) are not supported");
    static_assert(wotsbits > 3, "A wots chain should be at least 16 hash operations long (wotsbits > 1)");
    //The height of a singe merkle-tree must be 3 up to 16 levels.
    static_assert(merkleheight < 17, "A single merkle tree should not be more than 16 levels high");
    static_assert(merkleheight > 2, "A single merkle tree should be at least two levels high. A value between 8 and 10 is recomended");
    static_assert(merkleheight2 < 17, "A single merkle tree should not be more than 16 levels high");
    static_assert(merkleheight2 > 2, "A single merkle tree should be at least two levels high. A value between 8 and 10 is recomended");
    static_assert(39 * wotsbits >= hashlen * 8, "Wotsbits and hashlen must not combine into signing keys of more than 39 subkeys each");
    deserializer(): m_deserializer() {}
    std::pair<std::string, std::pair<std::string, std::vector<std::pair<std::string, std::string>>>> operator()(std::string in)
    {
        auto rval = m_deserializer(in);
        size_t processed_length = rval.second.first.size();
        for ( auto &i : rval.second.second ) {
            if (i.second == "") {
                processed_length += hashlen;
            }
            else {
                processed_length += i.second.size();
            }
        }
        constexpr int subkey_count = (hashlen * 8 + wotsbits -1) / wotsbits;
        constexpr size_t expected_length = 2 + hashlen * (2 + merkleheight + 2 * subkey_count);
        auto remaining = in.substr(processed_length, in.size() - processed_length);
        if (remaining.size() >= expected_length) {
            auto parent = rval.second.second[rval.second.second.size()-1].second.substr(0,hashlen);
            rval.second.second.push_back(std::pair<std::string, std::string>(parent,remaining.substr(0,expected_length)));
        }
        else {
            rval.second.second.push_back(std::pair<std::string, std::string>(remaining.substr(0,hashlen), ""));
        }
        return rval;
    }
private:
    deserializer<hashlen, wotsbits, merkleheight2, Args...> m_deserializer;
};

template<uint8_t hashlen, uint8_t wotsbits, uint8_t merkleheight, uint8_t merkleheight2>
struct deserializer<hashlen, wotsbits, merkleheight, merkleheight2> {
    //Hash length must be 16 up to 64 bytes long.
    static_assert(hashlen > 15, "Hash size should be at least 128 bits (16 bytes).");
    static_assert(hashlen < 65,  "Hash size of more then 512 bits is not supported");
    //The number of bits used for wots encoding must be 3 upto 16 bits.
    static_assert(wotsbits < 17, "Wots chains longer than 64k hash operations (wotsbits>16) are not supported");
    static_assert(wotsbits > 3, "A wots chain should be at least 16 hash operations long (wotsbits > 1)");
    //The height of a singe merkle-tree must be 3 up to 16 levels.
    static_assert(merkleheight < 17, "A single merkle tree should not be more than 16 levels high");
    static_assert(merkleheight > 2, "A single merkle tree should be at least two levels high. A value between 8 and 10 is recomended");
    static_assert(merkleheight2 < 17, "A single merkle tree should not be more than 16 levels high");
    static_assert(merkleheight2 > 2, "A single merkle tree should be at least two levels high. A value between 8 and 10 is recomended");
    static_assert(39 * wotsbits >= hashlen * 8, "Wotsbits and hashlen must not combine into signing keys of more than 39 subkeys each");
    std::pair<std::string, std::pair<std::string, std::vector<std::pair<std::string, std::string>>>> operator()(std::string in)
    {
        constexpr int subkey_count = (hashlen * 8 + wotsbits -1) / wotsbits;
        constexpr size_t expected_length2 = 2 + hashlen * (2 + merkleheight + 2 * subkey_count);
        constexpr size_t expected_length = 2 + hashlen * (2 + merkleheight2 + 2 * subkey_count);
        constexpr size_t expected_total_length_full = expected_length + expected_length2;
        constexpr size_t expected_total_length_reduced = expected_length + 2 * hashlen;
        auto subin = in.substr(0,expected_total_length_full);
        if (subin.size() < expected_total_length_full) {
            subin = in.substr(0, expected_total_length_reduced);
        }
        if (subin.size() == expected_total_length_full) {
            std::string mainsig = subin.substr(0, expected_length);
            std::string key1 =  subin.substr(0, hashlen);
            std::string sig1 = subin.substr(expected_length, subin.size() - expected_length);
            std::string pubkey = subin.substr(expected_length, hashlen);
            std::vector<std::pair<std::string, std::string>> rval;
            std::pair<std::string, std::string> pair(key1, sig1);
            rval.push_back(pair);
            std::pair<std::string, std::vector<std::pair<std::string, std::string>>> rval2(mainsig, rval);
            return std::pair<std::string, std::pair<std::string, std::vector<std::pair<std::string, std::string>>>>(pubkey, rval2);
        }
        else {
            if (subin.size() == expected_total_length_reduced) {
                std::string mainsig = subin.substr(0, expected_length);
                std::string key1 =  subin.substr(0, hashlen);
                std::string sig1("");
                std::string pubkey = subin.substr(subin.size()-hashlen, hashlen);
                std::vector<std::pair<std::string, std::string>> rval;
                std::pair<std::string, std::string> pair(key1, sig1);
                rval.push_back(pair);
                std::pair<std::string, std::vector<std::pair<std::string, std::string>>> rval2(mainsig, rval);
                return std::pair<std::string,
                                 std::pair<std::string,
                                           std::vector<
                                               std::pair<std::string,
                                                         std::string>
                                           >
                                          >
                                >(pubkey, rval2);
            }
            else {
                throw std::invalid_argument("Wrong signature size (*2).");
            }
        }

    }
};

std::string serialize(std::pair<std::string, std::vector<std::pair<std::string, std::string>>> in, std::string pubkey)
{
    std::string rval = in.first;
    bool end_reached(false);
    for ( auto &i : in.second ) {
        if (end_reached) {
            rval += i.first;
        }
        else {
            if (i.second == "") {
                rval += i.first;
                end_reached = true;
            }
            else {
                rval += i.second;
            }
        }
    }
    if (end_reached) {
        rval += pubkey;
    }
    return rval;
}

struct reducer {
    reducer(): m_last_time() {}
    void reduce(std::pair<std::string, std::vector<std::pair<std::string, std::string>>> &in)
    {
        if (m_last_time.size() == 0) {
            for ( auto &i : in.second ) {
                m_last_time.push_back(i.first);
            }
        }
        else {
            bool skip_rest = false;
            size_t index = 0;
            for ( auto &i : in.second ) {
                if (skip_rest or i.first == m_last_time[index]) {
                    skip_rest = true;
                    i.second = std::string("");
                }
                else {
                    m_last_time[index] = i.first;
                }
                index++;
            }
        }
    }
private:
    std::vector<std::string> m_last_time;
};
struct expander {
    expander(): m_last_time(),m_last_time_keys() {}
    void expand(std::pair<std::string, std::vector<std::pair<std::string, std::string>>> &in)
    {
        if (m_last_time.size() == 0) {
            for ( auto &i : in.second ) {
                if (i.second == "") {
                    throw insufficient_expand_state();
                }
                m_last_time.push_back(i.first);
                m_last_time_keys.push_back(i.second);
            }
        }
        else {
            size_t index = 0;
            for ( auto &i : in.second ) {
                if (i.first == m_last_time[index]) {
                    if  (i.second == std::string("")) {
                        i.second = m_last_time_keys[index];
                    }
                }
                else {
                    if (i.second == "") {
                        throw insufficient_expand_state();
                    }
                    m_last_time[index] = i.first;
                    m_last_time_keys[index] = i.second;
                }
                index++;
            }
        }
    }
private:
    std::vector<std::string> m_last_time;
    std::vector<std::string> m_last_time_keys;
};
}
#endif
