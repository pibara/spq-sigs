#ifndef SPQ_SIGS_HPP
#define SPQ_SIGS_HPP
#include <cstddef>
#include <string>
#include <map>
#include <vector>
#include <sodium.h>

namespace spqsigs {
  template<int hashlen>
  std::string make_seed(){
     char output[hashlen];
     randombytes_buf(output, hashlen);
     return std::string(output, hashlen);
  };
  template<int hashlen>
  struct blake2 {
         blake2(std::string &salt): m_salt(salt) {}
	 virtual ~blake2(){}
	 std::string operator()(std::string &input){
             char output[hashlen];
	     crypto_generichash_blake2b(output, hashlen, reinterpret_cast<const unsigned char *>(input.c_str()), input.length(), reinterpret_cast<const unsigned char *>(m_salt.c_str()), hashlen);  
	     return std::string(output, hashlen);
	 };
	 std::string operator()(std::string &input, size_t times){
             unsigned char output[hashlen];
	     strncpy(output, reinterpret_cast<const unsigned char *>(input.c_str()), hashlen);
	     crypto_generichash_blake2b_state state;
	     for (int index=0;index < times; index++) {
		 crypto_generichash_blake2b_init(&state, reinterpret_cast<const unsigned char *>(m_salt.c_str()), hashlen, hashlen);
		 crypto_generichash_blake2b_update(&state, output, hashlen);
                 crypto_generichash_blake2b_final(&state, output, hashlen);
	     }
             return std::string(output, hashlen);
         };
	 std::string operator()(std::string &input, std::string &input2){
	     char output[hashlen];
	     crypto_generichash_blake2b_state state;
	     crypto_generichash_blake2b_init(&state, reinterpret_cast<const unsigned char *>(m_salt.c_str()), hashlen, hashlen);
	     crypto_generichash_blake2b_update(&state, reinterpret_cast<const unsigned char *>(input.c_str()), hashlen);
	     crypto_generichash_blake2b_update(&state, reinterpret_cast<const unsigned char *>(input2.c_str()), hashlen);
             crypto_generichash_blake2b_final(&state, output, hashlen);
	     return std::string(output, hashlen);
	 };
	 std::string seed_to_secret(std::string &seed, size_t index, size_t subindex, char side){
	     char unsalted[hashlen];
	     char output[hashlen];
	     std::string designator=std::to_string(index) + side + std::to_string(subindex);
             crypto_generichash_blake2b(unsalted, hashlen, reinterpret_cast<const unsigned char *>(designator.c_str()), designator.length(), reinterpret_cast<const unsigned char *>(seed.c_str()), hashlen);
             crypto_generichash_blake2b(output, hashlen, unsalted, hashlen, reinterpret_cast<const unsigned char *>(m_salt.c_str()), hashlen);
             return std::string(output, hashlen);;
	 };
     private:
	 std::string &m_salt;
  };
  template<size_t hashlen, size_t wotsbits>
  struct subkey {
        subkey(){};
	virtual ~subkey(){};
  };
  template<size_t hashlen, size_t subkey_count, size_t wotsbits>
  struct private_key {
        private_key(){};
	virtual ~private_key(){}
     private:
	std::vector<subkey<hashlen, wotsbits>> m_subkeys;
  };
  template<size_t hashlen,  size_t merkledepth, size_t wotsbits>
  struct private_keys {
        private_keys(blake2<hashlen> hashfunction) {
	   static size_t subkey_count =  (hashlen * 8 + wotsbits -1) / wotsbits;
	};
	virtual ~private_keys(){}
     private:
	std::map<std::string,private_key<hashlen,(hashlen * 8 + wotsbits -1) / wotsbits, wotsbits>>  m_keys;
  };
  template<size_t hashlen, size_t wotsbits, size_t merkledepth>
  struct merkle_tree {
        merkle_tree(blake2<hashlen> hashfunction,
			            private_keys<hashlen, wotsbits, merkledepth> privkey){};
	virtual ~merkle_tree(){};
  };
  template<size_t hashlen=24, size_t wotsbits=12, size_t merkledepth=10>
  struct signing_key {
         signing_key(size_t multiproc=8): m_seed(make_seed<hashlen>()),
		                      m_hashfunction(m_seed),
	                              m_privkeys(m_hashfunction),
	                              m_merkle_tree(m_hashfunction, m_privkeys) {

         };
         signing_key(std::string serialized) {

         };
         void sign_digest(std::byte *digest, std::byte *signature) {
             return;
         };
         void sign_message(const std::byte *message, size_t length, std::byte *signature) {
             return ;
         };
         std::string get_state() {
             return "";
         }
         virtual ~signing_key(){}
     private:
	 std::string m_seed;
	 blake2<hashlen> m_hashfunction;
	 private_keys<hashlen, wotsbits, merkledepth> m_privkeys;
	 merkle_tree<hashlen, wotsbits, merkledepth> m_merkle_tree;
  };
}
#endif
