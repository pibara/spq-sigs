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

//FIXME: look at const correctness


#include <exception>
#include <iostream>


namespace spqsigs {
	struct signingkey_exhausted : std::exception
        {
            using std::exception::exception;
        };
	// declaration for signing_key class template defined at bottom of this file. 
	template<unsigned char hashlen=24, unsigned char wotsbits=12, unsigned char merkleheight=10>
		struct signing_key;
        template<unsigned char hashlen, unsigned char wotsbits, unsigned char merkleheight>
                struct signature;

	// Anything in the non_api sub namespace is not part of the public API of this single-file header-only library.
	namespace non_api {
                //Empty class for calling constructor of hashing primative with a request to use a newly
                //generated salt.
                class GENERATE {};
		// declaration for private_keys class template 
		template<unsigned char hashlen,  unsigned char merkleheight, unsigned char wotsbits, uint32_t pubkey_size>
			struct private_keys;

		// Helper function for converting a digest to a vector of numbers that can be signed using a
		// different subkey each.
		template<unsigned char hashlen, unsigned char wotsbits>
			std::vector<uint32_t> digest_to_numlist(std::string &msg_digest) {
				std::vector<uint32_t> rval;
				//Calculate (compile-time) how many sub-keys are needed for signing hashlen bytes of data
				constexpr static int subkey_count =  (hashlen * 8 + wotsbits -1) / wotsbits;
                                //Calculate how many aditional bits we need to pad our input with because subkey_count would give us sligthly more than hashlen input to sign.
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
						byteindex +=1;
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
					byteindex +=1;
				}
				return rval;
			}

		//Helper function for turning a small number into a vector of booleans (bits).
		template<unsigned char merkleheight>
			std::vector<bool> as_bits(uint32_t signing_key_index) {
				std::vector<bool> rval;
				//Go from left (higher index value) to right (zero).
				for (unsigned char index=merkleheight; index>0; index--) {
					//Convert one bit into a boolean.
					bool val = (((signing_key_index >> (index - 1)) & 1) == 1);
					//Add boolena to return vector.
					rval.push_back(val);
				}
				return rval;
			}

		// Hashing primative for 'hashlen' long digests, with a little extra. The hashing primative runs using libsodium.
		template<unsigned char hashlen, unsigned char wotsbits, unsigned char merkleheight>
			struct primative {
				// Virtual distructor
				virtual ~primative(){}
				// Function for generating a securely random 'hashlen' long seed or salt.
				static std::string make_seed(){
					char output[hashlen];
					//Use libsodium to get our random bytes
					randombytes_buf(output, hashlen);
					return std::string(output, hashlen);
				};
				//Hash the input with the salt and return the digest.
				std::string operator()(std::string &input) {
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
				std::string operator()(std::string &input, size_t times) {
					unsigned char output[hashlen];
					std::memcpy(output, input.c_str(), hashlen);
					crypto_generichash_blake2b_state state;
					for (uint32_t index=0;index < times; index++) {
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
				std::string operator()(std::string &input, std::string &input2) {
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
				std::string seed_to_secret(std::string &seed, size_t index, size_t subindex, size_t side) {
					unsigned char unsalted[hashlen];
					unsigned char output[hashlen];
					std::string sidec = (side) ? "R" : "L";
					std::string designator=std::to_string(index) + sidec + std::to_string(subindex);
					crypto_generichash_blake2b(unsalted,
							hashlen,
							reinterpret_cast<const unsigned char *>(designator.c_str()),
							designator.length(),
							reinterpret_cast<const unsigned char *>(seed.c_str()),
							hashlen);
					crypto_generichash_blake2b(output,
							hashlen,
							unsalted,
							hashlen,
							reinterpret_cast<const unsigned char *>(m_salt.c_str()),
							hashlen);
					return std::string(reinterpret_cast<const char *>(output), hashlen);;
				};
				//Retreive the salt for serialization purposes and later usage.
				std::string get_salt() {
					return m_salt;
				}
				void refresh() {
                                    m_salt = make_seed();
				}
				friend signing_key<hashlen, wotsbits, merkleheight>;
				friend signature<hashlen, wotsbits, merkleheight>;
				private:
				// Standard constructor using an existing salt.
				primative(std::string &salt): m_salt(salt) {}
				//Alternative constructor. Generates a random salt.
				primative(GENERATE): m_salt(make_seed()) {}
				std::string m_salt;
			};

		//A private key is a collection of subkeys that together can create a one-time-signature for
		// a single transaction/message digest.
		template<unsigned char hashlen, int subkey_count, unsigned char wotsbits, unsigned char merkleheight, uint32_t pubkey_size>
			struct private_key {
				// A tiny chunk of a one-time (wots) signing key, able to sign a chunk of 'wotsbits' bits with.
				struct subkey {
					//constructor, takes hashing primative, a seed, the one-time-signature index and the
					// chunk sub-index and created the chunk private for both direction wots chains.
					subkey(primative<hashlen, wotsbits, merkleheight> &hashprimative,
							std::string seed,
							size_t index,
							size_t subindex):
						m_index(index),
						m_subindex(subindex),
						m_hashprimative(hashprimative),
						m_private(), m_public("") {
							for (size_t side=0; side < 2; side ++) {
								m_private.push_back(
										hashprimative.seed_to_secret(seed,
											index,
											subindex,
											side));
							}
						};
					// virtual destructor
					virtual ~subkey(){};
					// calculate the public key for matching the private key for signing
					// the chunk of wotsbits, we do this by hashing both the left and the
					// right private key a largeish number of times (2^wotsbits times)
					std::string pubkey() {
						if (m_public == "") {
							std::string privkey_1 = m_hashprimative(m_private[0], 1<<wotsbits);
							std::string privkey_2 = m_hashprimative(m_private[1], 1<<wotsbits);
							m_public = m_hashprimative(privkey_1, privkey_2);
						}
						return m_public;
					};
					// We use the index operator for signing a chunk of 'wotsbits' bits
					// encoded into an unsigned integer.
					std::string operator [](uint32_t index){
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
				virtual ~private_key(){};
				//Get the pubkey for the single-use private key.
				std::string pubkey() {
					std::string rval("");
					//Compose by concattenating the pubkey for all the sub keys.
					std::for_each(std::begin(m_subkeys), std::end(m_subkeys), [&rval, this](subkey &value) {
							rval += value.pubkey();
							});
					return rval;
				};
				//Note: the square bracket operator is used for signing a digest.
				std::string operator [](std::string &digest)  {
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
						std::string seed,
						size_t index): m_subkeys(){
					//Compose from its sub-keys.
					for(size_t subindex=0; subindex < subkey_count; subindex++) {
						m_subkeys.push_back(subkey(hashprimative, seed, index, subindex));
					}
				};
				std::vector<subkey> m_subkeys;
			};

		// Collection of all one-time signing keys belonging with a signing key
		template<unsigned char hashlen,  unsigned char merkleheight, unsigned char wotsbits, uint32_t pubkey_size>
			struct private_keys {
				static constexpr uint32_t subkey_count =  (hashlen * 8 + wotsbits -1) / wotsbits;
				// Virtual destructor
				virtual ~private_keys(){};
				//Square bracket operator used to access specific private key.
				private_key<hashlen, (hashlen*8 + wotsbits -1)/wotsbits ,wotsbits, merkleheight, pubkey_size> &operator [](uint32_t index)  {
					return this->m_keys[index];
				};
				void refresh(primative<hashlen, wotsbits, merkleheight> &hashprimative, std::string seed) {
                                    std::vector<private_key<hashlen,(hashlen * 8 + wotsbits -1) / wotsbits, wotsbits, merkleheight, pubkey_size>>  empty;
				    m_keys.swap(empty);
                                    for (size_t index=0; index < pubkey_size; index++) {
                                            m_keys.push_back(
                                                            private_key<hashlen, subkey_count, wotsbits, merkleheight, pubkey_size>(hashprimative, seed, index));
                                    }
				}
				//Only signing_key should invoke the constructor for private_keys
				friend signing_key<hashlen, wotsbits, merkleheight>;
				private:
				//Private constructor, only to be called from signing_key
				private_keys(primative<hashlen, wotsbits, merkleheight> &hashprimative, std::string seed): m_keys() {
					// Construct from multiple private_key's
					for (size_t index=0; index < pubkey_size; index++) {
						m_keys.push_back(
								private_key<hashlen, subkey_count, wotsbits, merkleheight, pubkey_size>(hashprimative, seed, index));
					}
				};
				std::vector<private_key<hashlen,(hashlen * 8 + wotsbits -1) / wotsbits, wotsbits, merkleheight, pubkey_size>>  m_keys;
			};
	}
	// Public API signing_key
	template<unsigned char hashlen, unsigned char wotsbits, unsigned char merkleheight>
		struct signing_key {
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
				m_merkle_tree() {
				};
				//Virtual destructor
				virtual ~merkle_tree(){};

				void refresh() {
                                    m_merkle_tree.clear();
                                    this->populate<merkleheight>(0, "");
				}
				//Get the merkle-root, what is the same as the signing_key public key.
				std::string pubkey() {
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
				std::string operator [](uint32_t signing_key_index)  {
					//Populate if needed.
					if ( m_merkle_tree.find("") == m_merkle_tree.end() ) {
						this->populate<merkleheight>(0, "");
					}
					//Convert the signing key index into a vector of booleans
					std::vector<bool> index_bits = non_api::as_bits<merkleheight>(signing_key_index);
					std::string rval;
                                        // For each depth in the tree extract one node.
					for (unsigned char bindex=0; bindex < merkleheight; bindex++) {
						std::string key;
						//For each bit of a given depth, except the last, pick use the input designation
						for (unsigned char index=0; index<bindex; index++) {
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
				template<unsigned char remaining_height>
					std::string populate(uint32_t start, std::string prefix) {
						if constexpr (remaining_height != 0) {
							//Polulate the left branch and get the top node hash
							std::string left = this->populate<remaining_height-1>(start,prefix + "0");
							//Populate the right branch and get the top node hash
							std::string right = this->populate<remaining_height-1>(start + (1 << (remaining_height - 1)),
									prefix + "1");
							//Set the node hash value at this level.
							m_merkle_tree[prefix] = m_hashfunction(left, right);
						} else {
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
			//Signing key instantiation constraints.
			//Hash length must be 3 up to 64 bytes long. Shortes than 16 isn't recomended for purposes other than educational use.
			static_assert(hashlen > 2, "Hash size should be at least 24 bits (3 bytes). For non-demo usage 128 bit (16 bytes) is suggested.");
			static_assert(hashlen < 65,  "Hash size of more then 512 bits is not supported");
			//The number of bits used for wots encoding must be 3 upto 16 bits. 
			static_assert(wotsbits < 17, "Wots chains longer than 64k hash operations (wotsbits>16)are not supported");
			static_assert(wotsbits > 2, "A wots chain should be at least 4 hash operations long (botsbits > 1)");
			//The height of a singe merkle-tree must be 3 up to 16 levels.
			static_assert(merkleheight < 17, "A single merkle tree should not be more than 16 levels high");
			static_assert(merkleheight > 2, "A single merkle tree should ve at least two levels high. A value between 8 and 10 is recomended");
			signing_key(): m_next_index(0),
			    m_seed(non_api::primative<hashlen, wotsbits, merkleheight>::make_seed()),
			    m_hashfunction(non_api::GENERATE()),
			    m_privkeys(m_hashfunction, m_seed),
			    m_merkle_tree(m_hashfunction, m_privkeys) {
				    //Get pubkey as a way to populate.
				    this->m_merkle_tree.pubkey();
			};
			//Make a new key when current one is exhausted
			void refresh() {
			    m_next_index = 0;
                            m_seed = non_api::primative<hashlen, wotsbits, merkleheight>::make_seed();
			    m_hashfunction.refresh();
			    m_privkeys.refresh(m_hashfunction, m_seed);
			    m_merkle_tree.refresh();
			}
			//Future API for restoring a signing key from serialization.
			signing_key(std::string serialized) {
				throw std::runtime_error("not yet implemented");
			};
			//Sign a hashlength bytes long digest.
			std::string sign_digest(std::string digest) {
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
					this->m_merkle_tree[m_next_index] +       //The merkle-tree header, a collection of merkle tree nodes needed to get from wots signatures to pubkey.
					this->m_privkeys[m_next_index][digest];   //The collection of wots signatures.
				this->m_next_index++;
				return rval;
			};
			//Sign an arbitrary length message
			std::string sign_message(std::string &message) {
				//Take the hash of the message.
				std::string digest = m_hashfunction(message);
				//Sign the hash
				return this->sign_digest(digest);	 
			};
			//Future API call for serializing the signing key.
			std::string get_state() {
				// FIXME: implement serialize
				throw std::runtime_error("not yet implemented");
			}
			std::string pubkey() {
                            return m_merkle_tree.pubkey();
			}
			//Virtual destructor
			virtual ~signing_key(){}
			private:
			uint16_t m_next_index;
			std::string m_seed;
			non_api::primative<hashlen, wotsbits, merkleheight> m_hashfunction;
			non_api::private_keys<hashlen, merkleheight, wotsbits, static_cast<unsigned short>(1) << merkleheight > m_privkeys;
			merkle_tree m_merkle_tree;
		};

        //FIXME: We should try to replace the below with a variadic alternative.

	// A multi tree signing key consisting of two levels.
	template<unsigned char hashlen, unsigned char wotsbits, unsigned char merkleheight, unsigned char merkleheight2>
                struct two_tree_signing_key {
                    two_tree_signing_key(): m_root_key(), m_signing_key(), m_signing_key_signature(m_root_key.sign_digest(m_signing_key.pubkey())) {}
		    std::pair<std::string, std::vector<std::pair<std::string, std::string>>> sign_message(std::string &message){
			std::string signature;
			try {
			    signature = m_signing_key.sign_message(message);
			} catch  (const spqsigs::signingkey_exhausted&) {
                            m_signing_key.refresh();
			    m_signing_key_signature = m_root_key.sign_digest(m_signing_key.pubkey());
			    signature = m_signing_key.sign_message(message);
			}
		        std::vector<std::pair<std::string, std::string>> rval;
			rval.push_back(std::make_pair(m_signing_key.pubkey(), m_signing_key_signature));
		        return std::make_pair(signature,rval);
		    }
		    std::string get_state() {
		        return "bogus";
		    }
		    std::string pubkey() {
                        return m_root_key.pubkey();
                    }
		    void refresh() {
                        m_root_key.refresh();
                        m_signing_key.refresh();
			m_signing_key_signature = m_root_key.sign_digest(m_signing_key.pubkey());
		    }
		    virtual ~two_tree_signing_key(){}
		  private:
                    signing_key<hashlen, wotsbits, merkleheight> m_root_key;
		    signing_key<hashlen, wotsbits, merkleheight2> m_signing_key;
		    std::string m_signing_key_signature;
		};

	// A multi tree signing key consisting of three levels
	template<unsigned char hashlen, unsigned char wotsbits, unsigned char merkleheight, unsigned char merkleheight2, unsigned char merkleheight3>
                struct three_tree_signing_key {
                    three_tree_signing_key(): m_root_key(), m_signing_key(), m_signing_key_signature(m_root_key.sign_digest(m_signing_key.pubkey())) {}
		    std::pair<std::string, std::vector<std::pair<std::string, std::string>>> sign_message(std::string &message){
                        try { 
			    auto rval = m_signing_key.sign_message(message);
			    rval.second.push_back(std::make_pair(m_signing_key.pubkey(), m_signing_key_signature));
			    return rval;
			} catch  (const spqsigs::signingkey_exhausted&) {
			    m_signing_key.refresh();
                            m_signing_key_signature = m_root_key.sign_digest(m_signing_key.pubkey());
			    auto rval = m_signing_key.sign_message(message);
                            rval.second.push_back(std::make_pair(m_signing_key.pubkey(), m_signing_key_signature));
                            return rval;
			}
                    }
                    std::string get_state() {
                        return "bogus";
                    }
		    std::string pubkey() {
                        return m_root_key.pubkey();
                    }
		    void refresh() {
                        m_root_key.refresh();
                        m_signing_key.refresh();
                        m_signing_key_signature = m_root_key.sign_digest(m_signing_key.pubkey());
                    }
                    virtual ~three_tree_signing_key(){}
                  private:
                    signing_key<hashlen, wotsbits, merkleheight> m_root_key;
		    two_tree_signing_key<hashlen, wotsbits, merkleheight2, merkleheight3> m_signing_key;
		    std::string m_signing_key_signature;
                };

	// A mulkti tree signing key consisting of four levels.
	template<unsigned char hashlen, unsigned char wotsbits, unsigned char merkleheight, unsigned char merkleheight2, unsigned char merkleheight3, unsigned char merkleheight4>
                struct four_tree_signing_key {
                    four_tree_signing_key(): m_root_key(), m_signing_key(), m_signing_key_signature(m_root_key.sign_digest(m_signing_key.pubkey())) {}
		    std::pair<std::string, std::vector<std::pair<std::string, std::string>>>  sign_message(std::string &message){
			try {
                            auto rval = m_signing_key.sign_message(message);
                            rval.second.push_back(std::make_pair(m_signing_key.pubkey(), m_signing_key_signature));
                            return rval;
                        } catch  (const spqsigs::signingkey_exhausted&) {
                            m_signing_key.refresh();
                            m_signing_key_signature = m_root_key.sign_digest(m_signing_key.pubkey());
                            auto rval = m_signing_key.sign_message(message);
                            rval.second.push_back(std::make_pair(m_signing_key.pubkey(), m_signing_key_signature));
                            return rval;
			}
                    }
                    std::string get_state() {
                        return "bogus";
                    }
		    void refresh() {
                        m_root_key.refresh();
                        m_signing_key.refresh();
                        m_signing_key_signature = m_root_key.sign_digest(m_signing_key.pubkey());
                    }
                    virtual ~four_tree_signing_key(){}
                  private:
                    signing_key<hashlen, wotsbits, merkleheight> m_root_key;
                    three_tree_signing_key<hashlen, wotsbits, merkleheight2, merkleheight3, merkleheight4> m_signing_key;
		    std::string m_signing_key_signature;
                };


	//Public-API signature
	template<unsigned char hashlen, unsigned char wotsbits, unsigned char merkleheight>
		struct signature {
			signature(std::string sigstring): m_pubkey(), m_salt(), m_index(0), m_mt_bits() ,m_merkle_tree_header(), m_signature_body() {
				//Signature instantiation constraints.
                                //Hash length must be 3 up to 64 bytes long. Shortes than 16 isn't recomended for purposes other than educational use.
                                static_assert(hashlen > 2, "Hash size should be at least 24 bits (3 bytes). For non-demo usage 128 bit (16 bytes) is suggested.");
                                static_assert(hashlen < 65, "Hash size of more then 512 bits is not supported");
                                //The number of bits used for wots encoding must be 3 upto 16 bits.
                                static_assert(wotsbits < 17, "Wots chains longer than 64k hash operations (wotsbits>16)are not supported");
                                static_assert(wotsbits > 2, "A wots chain should be at least 4 hash operations long (botsbits > 1)");
                                //The height of a singe merkle-tree must be 3 up to 16 levels.
                                static_assert(merkleheight < 17, "A single merkle tree should not be more than 16 levels high");
                                static_assert(merkleheight > 2, "A single merkle tree should ve at least two levels high. A value between 8 and 10 is recomended");
				constexpr int subkey_count = (hashlen * 8 + wotsbits -1) / wotsbits;
                                constexpr size_t expected_length = 2 + hashlen * (2 + merkleheight + 2 * subkey_count);
				// * check signature length
				if (sigstring.length() != expected_length) {
					throw std::invalid_argument("Wrong signature size.");
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
			bool validate(std::string message) {
				// * get the message digest
				non_api::primative<hashlen, wotsbits, merkleheight> hashfunction(m_salt);
				std::string digest = hashfunction(message);
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
				    } else {
                                        calculated_pubkey = hashfunction(calculated_pubkey, m_merkle_tree_header[index]);
				    }
				}
				//If everything is irie, the pubkey and the reconstructed pubkey should be the same.
				return calculated_pubkey == m_pubkey;
			}
			//Get the current index, this is the statefull part of the signing key.
			uint32_t get_index() {
				return m_index;
			}
			//Get the public key of the signing key.
			std::string get_pubkey() {
				return m_pubkey;
			}
			//Get the value of the salt string for this signing key.
			std::string get_pubkey_salt() {
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

        //FIXME: The below is complete nonsense right now, implement

	template<unsigned char hashlen, unsigned char wotsbits, unsigned char merkleheigh, unsigned char merkleheigh2>
                struct two_tree_signature {
			two_tree_signature(std::string sigstring) {
			    std::string v = sigstring;
			}
                        bool validate(std::string message) {
                            return (message == "hohoho");
			}
			std::vector<uint32_t> get_index() {
                            return std::vector<uint32_t>();
			}
			std::vector<std::string> get_pubkey() {
                            return std::vector<std::string>();
			}
			std::vector<std::string> get_pubkey_salt() {
                            return std::vector<std::string>();
			}
			virtual ~two_tree_signature(){}
		};

	template<unsigned char hashlen, unsigned char wotsbits, unsigned char merkleheigh, unsigned char merkleheigh2, unsigned char merkleheigh3>
                struct three_tree_signature {
                        three_tree_signature(std::string sigstring) {
                            std::string v = sigstring;
                        }
                        bool validate(std::string message) {
                            return (message == "hohoho");
                        }
                        std::vector<uint32_t> get_index() {
                            return std::vector<uint32_t>();
                        }
                        std::vector<std::string> get_pubkey() {
                            return std::vector<std::string>();
                        }
                        std::vector<std::string> get_pubkey_salt() {
                            return std::vector<std::string>();
                        }
                        virtual ~three_tree_signature(){}
                };

	template<unsigned char hashlen, unsigned char wotsbits, unsigned char merkleheigh, unsigned char merkleheigh2, unsigned char merkleheigh3, unsigned char merkleheigh4>
                struct four_tree_signature {
                        four_tree_signature(std::string sigstring) {
                            std::string v = sigstring;
                        }
                        bool validate(std::string message) {
                            return (message == "hohoho");
                        }
                        std::vector<uint32_t> get_index() {
                            return std::vector<uint32_t>();
                        }
                        std::vector<std::string> get_pubkey() {
                            return std::vector<std::string>();
                        }
                        std::vector<std::string> get_pubkey_salt() {
                            return std::vector<std::string>();
                        }
                        virtual ~four_tree_signature(){}
                };
}
#endif
