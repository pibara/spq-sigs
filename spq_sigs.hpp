#ifndef SPQ_SIGS_HPP
#define SPQ_SIGS_HPP
#include <cstddef>
#include <string>
#include <map>
#include <vector>
#include <sodium.h>

namespace spqsigs {
  template<int hashlen>
  struct digest {
	 digest(){};
	 virtual ~digest(){};
         std::byte m_bytes[hashlen];
  };
  template<int hashlen>
  digest<hashlen> make_seed(){
     digest<hashlen> rval;
     randombytes_buf(rval.m_bytes, hashlen);
     return rval;
  };
  template<int hashlen>
  struct blake2 {
         blake2(digest<hashlen> &salt):/*m_blake2b(hashlen),*/ m_salt(salt) {}
	 virtual ~blake2(){}
	 digest<hashlen> operator()(const std::byte *input, long long inlen=hashlen){
             digest<hashlen> rval;
	     crypto_generichash_blake2b(rval.m_bytes, hashlen, input, inlen, m_salt.m_bytes, hashlen);  
	     return rval;
	 };
	 digest<hashlen> operator()(digest<hashlen> &input){
	     digest<hashlen> rval;
             crypto_generichash_blake2b(rval.m_bytes, hashlen, input.m_bytes, hashlen, m_salt.m_bytes, hashlen);
             return rval;
	 };
	 digest<hashlen> operator()(digest<hashlen> &input, digest<hashlen> &input2){
	     digest<hashlen> rval;
	     crypto_generichash_blake2b_state state;
	     crypto_generichash_blake2b_init(&state, m_salt.m_bytes, hashlen, hashlen);
	     crypto_generichash_blake2b_update(&state, input.m_bytes, hashlen);
	     crypto_generichash_blake2b_update(&state, input2.m_bytes, hashlen);
             crypto_generichash_blake2b_final(&state, rval.m_bytes, hashlen);
	     return rval;
	 };
	 digest<hashlen> seed_to_secret(digest<hashlen> & seed, size_t index, size_t subindex, char side){
	     std::string designator=std::to_string(index) + side + std::to_string(subindex);
             digest<hashlen> unsalted;
             crypto_generichash_blake2b(unsalted.m_bytes, hashlen, designator.c_str(), designator.length(), seed.m_bytes, hashlen);
	     digest<hashlen> rval;
             crypto_generichash_blake2b(rval.m_bytes, hashlen, unsalted.m_bytes, hashlen, m_salt.m_bytes, hashlen);
             return rval;
	 };
     private:
	 digest<hashlen> &m_salt;
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
	 digest<hashlen> m_seed;
	 blake2<hashlen> m_hashfunction;
	 private_keys<hashlen, wotsbits, merkledepth> m_privkeys;
	 merkle_tree<hashlen, wotsbits, merkledepth> m_merkle_tree;
  };
}
#endif
