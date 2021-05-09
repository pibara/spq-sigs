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
#include <exception>
#include <iostream> //FIXME: remove iostream debugging
#include <sodium.h>
#include <arpa/inet.h>

//FIXME: look at const correctness

namespace spqsigs {
	//Empty class for calling constructor of hashing primative with a request to use a newly
	//generated salt.
	class GENERATE {};
	// declaration for signing_key class template defined at bottom of this file. 
	template<unsigned char hashlen=24, unsigned char wotsbits=12, unsigned char merkledepth=10, bool do_threads=false>
		struct signing_key;
        template<unsigned char hashlen, unsigned char wotsbits, unsigned char merkledepth>
                struct signature;

	namespace non_api {

		// declaration for private_keys class template 
		template<unsigned char hashlen,  unsigned char merkledepth, unsigned char wotsbits, uint32_t pubkey_size>
			struct private_keys;

		// Helper function for converting a digest to a vector of numbers that can be signed using a
		// different subkey each.
		template<unsigned char hashlen, unsigned char wotsbits>
			std::vector<uint32_t> digest_to_numlist(std::string &msg_digest) {
				std::vector<uint32_t> rval;
				constexpr static int subkey_count =  (hashlen * 8 + wotsbits -1) / wotsbits;
				constexpr static size_t morebits = subkey_count * wotsbits - hashlen * 8;
				uint32_t val = 0;
				uint32_t remaining_bits = wotsbits - morebits;
				uint32_t byteindex = 0;
				const unsigned char *data = reinterpret_cast<const unsigned char *>(msg_digest.c_str());
				while (byteindex < hashlen) {
					while (remaining_bits > 8) {
						val = (val << 8) + data[byteindex];
						byteindex +=1;
						remaining_bits -= 8;
					}
					val = (val << remaining_bits) + (data[byteindex] >> (8-remaining_bits));
					rval.push_back(val);
					uint32_t val2 = ((data[byteindex] << remaining_bits) & 255) >> remaining_bits;
					uint32_t used_bits = 8 - remaining_bits;
					while (used_bits >= wotsbits) {
						val = val2 >> (used_bits - wotsbits);
						rval.push_back(val);
						used_bits -= wotsbits;
						val2 = ((val2 << (8-used_bits)) & 255) >> (8-used_bits);
					}
					val = val2;
					remaining_bits = wotsbits - used_bits;
					byteindex +=1;
				}
				return rval;
			}

		// Helper function for use in merkletree creation (key creation). Determine if two branches
		// should be handled by paralel threads at given level. 
		template<unsigned char merkledepth, unsigned char remaining_depth, bool do_threads>
			constexpr bool use_threads() {
				if constexpr ((do_threads == false) or 
						(merkledepth < 4) or 
						(merkledepth - remaining_depth > 2)) {
					return false;
				} else {
					return true;
				}
			}

		//Helper function for turning a small number into a vector of booleans (bits).
		template<unsigned char wotsbits>
			std::vector<bool> as_bits(uint32_t wotsval) {
				std::vector<bool> rval;
				for (unsigned char index=wotsbits; index>0; index--) {
					bool val = (((wotsval >> (index - 1)) & 1) == 1);
					rval.push_back(val);
				}
				return rval;
			}

		// Hashing primative for 'hashlen' long digests, with a little extra. The hashing primative runs using libsodium.
		template<unsigned char hashlen, unsigned char wotsbits, unsigned char merkledepth>
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
				std::string operator()(std::string &input){
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
				std::string operator()(std::string &input, size_t times){
					unsigned char output[hashlen];
					strncpy(reinterpret_cast<char *>(output),
							reinterpret_cast<const char *>(input.c_str()), hashlen);
					crypto_generichash_blake2b_state state;
					for (uint32_t index=0;index < times; index++) {
						crypto_generichash_blake2b_init(&state,
								reinterpret_cast<const unsigned char *>(m_salt.c_str()),
								hashlen,
								hashlen);
						crypto_generichash_blake2b_update(&state, output, hashlen);
						crypto_generichash_blake2b_final(&state, output, hashlen);
					}
					return std::string(reinterpret_cast<const char *>(output), hashlen);
				};
				//Hash two inputs with salts and return the digest.
				std::string operator()(std::string &input, std::string &input2){
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
				std::string seed_to_secret(std::string &seed, size_t index, size_t subindex, size_t side){
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
				friend signing_key<hashlen, wotsbits, merkledepth, true>;
				friend signing_key<hashlen, wotsbits, merkledepth, false>;
				friend signature<hashlen, wotsbits, merkledepth>;
				private:
				// Standard constructor using an existing salt.
				primative(std::string &salt): m_salt(salt) {}
				//Alternative constructor. Generates a random salt.
				primative(GENERATE): m_salt(make_seed()) {}
				std::string m_salt;
			};

		//A private key is a collection of subkeys that together can create a one-time-signature for
		// a single transaction/message digest.
		template<unsigned char hashlen, int subkey_count, unsigned char wotsbits, unsigned char merkledepth, uint32_t pubkey_size>
			struct private_key {
				// A tiny chunk of a one-time (wots) signing key, able to sign a chunk of 'wotsbits' bits with.
				struct subkey {
					//constructor, takes hashing primative, a seed, the one-time-signature index and the
					// chunk sub-index and created the chunk private for both direction wots chains.
					subkey(primative<hashlen, wotsbits, merkledepth> &hashprimative,
							std::string seed,
							size_t index,
							size_t subindex):
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
					std::string operator [](uint32_t index) {
						return m_hashprimative(m_private[0], index) + m_hashprimative(m_private[0], (1<<wotsbits) - index -1);
					}
					private:
					primative<hashlen, wotsbits, merkledepth> &m_hashprimative; // The core hashing primative
					std::vector<std::string> m_private;  // The private key as generated at construction.
					std::string m_public;                // The public key, calculated lazy, on demand.
				};
				virtual ~private_key(){};
				std::string pubkey() {
					std::string rval("");
					std::for_each(std::begin(m_subkeys), std::end(m_subkeys), [&rval, this](subkey &value) {
							rval += value.pubkey();
							});
					return rval;
				};
				std::string operator [](std::string digest)  {
					auto numlist = digest_to_numlist<hashlen, wotsbits>(digest);
					std::string rval;
					size_t nl_len = numlist.size();
					for(size_t index=0; index < nl_len; index++) {
						rval += m_subkeys[index][numlist[index]];
					};
					return rval;
				};
				friend private_keys<hashlen, merkledepth, wotsbits, pubkey_size>;
				private:
				private_key(primative<hashlen, wotsbits, merkledepth> &hashprimative,
						std::string seed,
						size_t index): m_subkeys(){
					for(size_t subindex=0; subindex < subkey_count; subindex++) {
						m_subkeys.push_back(subkey(hashprimative, seed, index, subindex));
					}
				};
				std::vector<subkey> m_subkeys;
			};

		template<unsigned char hashlen,  unsigned char merkledepth, unsigned char wotsbits, uint32_t pubkey_size>
			struct private_keys {
				static constexpr uint32_t subkey_count =  (hashlen * 8 + wotsbits -1) / wotsbits;
				virtual ~private_keys(){};
				private_key<hashlen, (hashlen*8 + wotsbits -1)/wotsbits ,wotsbits, merkledepth, pubkey_size> &operator [](uint32_t index)  {
					return this->m_keys[index];
				};
				friend signing_key<hashlen, wotsbits, merkledepth, true>;
				friend signing_key<hashlen, wotsbits, merkledepth, false>;
				private:
				private_keys(primative<hashlen, wotsbits, merkledepth> &hashprimative, std::string seed): m_keys() {
					for (size_t index=0; index < pubkey_size; index++) {
						m_keys.push_back(
								private_key<hashlen, subkey_count, wotsbits, merkledepth, pubkey_size>(hashprimative, seed, index));
					}
				};
				std::vector<private_key<hashlen,(hashlen * 8 + wotsbits -1) / wotsbits, wotsbits, merkledepth, pubkey_size>>  m_keys;
			};
	}
	template<unsigned char hashlen, unsigned char wotsbits, unsigned char merkledepth, bool do_threads>
		struct signing_key {
			struct merkle_tree {
				merkle_tree(non_api::primative<hashlen, wotsbits, merkledepth> & hashfunction,
						non_api::private_keys<hashlen,
						merkledepth,
						wotsbits,
						static_cast<unsigned short>(1) << merkledepth > &privkey): m_hashfunction(hashfunction),
				m_private_keys(privkey),
				m_merkle_tree() {
				};
				virtual ~merkle_tree(){};
				std::string pubkey() {
					if ( m_merkle_tree.find("") == m_merkle_tree.end() ) {
						this->populate<merkledepth>(0, "");
					}
					return m_merkle_tree[""];
				};
				std::string operator [](uint32_t wotsval)  {
					if ( m_merkle_tree.find("") == m_merkle_tree.end() ) {
						this->populate<merkledepth>(0, "");
					}
					std::vector<bool> wots_val_bits = non_api::as_bits<wotsbits>(wotsval);
					std::string rval;
					for (unsigned char bindex=0; bindex < merkledepth; bindex++) {
						std::string key;
						for (unsigned char index; index<bindex; index++) {
							key += wots_val_bits[index] ? "1" : "0";
						}
						key += wots_val_bits[bindex] ? "0" : "1";
						rval += m_merkle_tree[key];
					}
					return rval;
				};
				private:
				template<unsigned char remaining_depth>
					std::string populate(uint32_t start, std::string prefix) {
						if constexpr (remaining_depth != 0) {
							//if constexpr (use_threads<merkledepth, remaining_depth, do_threads>()) {
							// FIXME: Run the two sub-trees in seperate threaths ans wait for results
							//std::cerr << "threaded: " << prefix << std::endl;
							//}
							std::string left = this->populate<remaining_depth-1>(start,prefix + "0");
							std::string right = this->populate<remaining_depth-1>(start + (1 << (remaining_depth - 1)),
									prefix + "1");
							m_merkle_tree[prefix] = m_hashfunction(left, right);
						} else {
							std::string pkey = m_private_keys[start].pubkey();
							m_merkle_tree[prefix] =  m_hashfunction(pkey);
						}
						return m_merkle_tree[prefix];
					}
				non_api::primative<hashlen, wotsbits, merkledepth> &m_hashfunction;
				non_api::private_keys<hashlen,
					merkledepth,
					wotsbits,
					static_cast<unsigned short>(1) << merkledepth > m_private_keys;
				std::map<std::string, std::string> m_merkle_tree;
			};
			static_assert(hashlen > 2);
			static_assert(hashlen < 65);
			static_assert(wotsbits < 17);
			static_assert(wotsbits > 2);
			static_assert(merkledepth < 17);
			static_assert(merkledepth > 2);
			signing_key(): m_next_index(0),
			m_seed(non_api::primative<hashlen, wotsbits, merkledepth>::make_seed()),
			m_hashfunction(GENERATE()),
			m_privkeys(m_hashfunction, m_seed),
			m_merkle_tree(m_hashfunction, m_privkeys) {
			};
			signing_key(std::string serialized) {
				throw std::runtime_error("not yet implemented");
			};
			std::string sign_digest(std::string &digest) {
				assert(digest.length() == hashlen);
				uint16_t ndx = htons(this->m_next_index);
				std::string ndxs = std::string(reinterpret_cast<const char *>(&ndx), 2);
				std::string rval = this->m_merkle_tree.pubkey() +
					this->m_hashfunction.get_salt() +
					ndxs +
					this->m_merkle_tree[m_next_index] +
					this->m_privkeys[m_next_index][digest];
				this->m_next_index++;
				return rval;
			};
			std::string sign_message(std::string &message) {
				std::string digest = m_hashfunction(message);
				return this->sign_digest(digest);	 
			};
			std::string get_state() {
				// FIXME: implement serialize
				throw std::runtime_error("not yet implemented");
			}
			virtual ~signing_key(){}
			private:
			uint16_t m_next_index;
			std::string m_seed;
			non_api::primative<hashlen, wotsbits, merkledepth> m_hashfunction;
			non_api::private_keys<hashlen, merkledepth, wotsbits, static_cast<unsigned short>(1) << merkledepth > m_privkeys;
			merkle_tree m_merkle_tree;
		};

	template<unsigned char hashlen, unsigned char wotsbits, unsigned char merkledepth>
		struct signature {
			signature(std::string sigstring): m_pubkey(), m_salt(), m_index(0), m_merkle_tree_header(), m_signature_body() {
				static_assert(hashlen > 2);
				static_assert(hashlen < 65);
				static_assert(wotsbits < 17);
				static_assert(wotsbits > 2);
				static_assert(merkledepth < 17);
				static_assert(merkledepth > 2);
				// * check signature length
				constexpr size_t subkey_count = (hashlen * 8 + wotsbits -1) / wotsbits;
				constexpr size_t expected_length = 2 + hashlen * (2 + merkledepth + 2 * subkey_count);
				if (sigstring.length() != expected_length) {
					throw std::invalid_argument("Wrong signature size.");
				}
				// * get pubkey, salt, index, mt-header and wots-body
				m_pubkey = sigstring.substr(0,hashlen);
				m_salt = sigstring.substr(hashlen,hashlen);
				std::string s_index = sigstring.substr(hashlen*2,2);
				const unsigned char * us_index = reinterpret_cast<const unsigned char *>(s_index.c_str());
				m_index = (us_index[0] << 8) + us_index[1];
				for (int index=0; index < merkledepth; index++) {
					m_merkle_tree_header.push_back(sigstring.substr(hashlen*(2+index)+2, hashlen));
				}
				for (int index=0; index < merkledepth; index++) {
					std::vector<std::string> newval;
					for (int direction=0; direction<2; direction++) {
						newval.push_back(sigstring.substr(2 + hashlen * (2 + merkledepth + 2 * index + direction),
									hashlen));  
					}
					m_signature_body.push_back(newval);
				}
			}
			bool validate(std::string message) {
				// * get the message digest
				non_api::primative<hashlen, wotsbits, merkledepth> hashfunction(m_salt);
				std::string digest = hashfunction(message);
				auto numlist = non_api::digest_to_numlist<hashlen, wotsbits>(digest);
				// * complete the wots chains
				std::string big_ots_pubkey("");
				for (size_t index=0; index < numlist.size(); index++) {
					auto signature_chunk = m_signature_body[index];
					int chunk_num = numlist[index];
					std::string pk1 = hashfunction(signature_chunk[0], (1 << wotsbits) - chunk_num);
					std::string pk2 = hashfunction(signature_chunk[1], chunk_num +1);
					big_ots_pubkey += hashfunction(pk1, pk2); 
				}
				// FIXME: implement below.
				// * reconstruct the merkle tree root
				// * check the merkle tree root
				return true;
			}
			uint32_t get_index() {
				return m_index;
			}
			std::string get_pubkey() {
				return m_pubkey;
			}
			std::string get_pubkey_salt() {
				return m_salt;
			}
			private:
			std::string m_pubkey;
			std::string m_salt;
			uint32_t m_index;
			std::vector<std::string> m_merkle_tree_header;
			std::vector<std::vector<std::string>> m_signature_body;
		};
}
#endif
