#ifndef SPQ_SIGS_HPP
#define SPQ_SIGS_HPP
#include <cstddef>
#include <string>
#include <map>
#include <vector>

namespace spqsigs {
  template<int hashlen>
  struct blake2 {
         blake2() {}
	 virtual ~blake2(){}
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
         signing_key(size_t multiproc=8):m_hashfunction(),
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
	 blake2<hashlen> m_hashfunction;
	 private_keys<hashlen, wotsbits, merkledepth> m_privkeys;
	 merkle_tree<hashlen, wotsbits, merkledepth> m_merkle_tree;
  };
}
#endif
