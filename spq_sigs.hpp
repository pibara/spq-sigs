#ifndef SPQ_SIGS_HPP
#define SPQ_SIGS_HPP
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include <stdexcept>
#include <algorithm>
#include <iostream> //FIXME: remove iostream debugging
#include <sodium.h>
#include <arpa/inet.h>

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
             unsigned char output[hashlen];
	     crypto_generichash_blake2b(output, hashlen, reinterpret_cast<const unsigned char *>(input.c_str()), input.length(), reinterpret_cast<const unsigned char *>(m_salt.c_str()), hashlen);  
	     return std::string(reinterpret_cast<const char *>(output), hashlen);
	 };
	 std::string operator()(std::string &input, size_t times){
             unsigned char output[hashlen];
	     strncpy(reinterpret_cast<char *>(output), reinterpret_cast<const char *>(input.c_str()), hashlen);
	     crypto_generichash_blake2b_state state;
	     for (int index=0;index < times; index++) {
		 crypto_generichash_blake2b_init(&state, reinterpret_cast<const unsigned char *>(m_salt.c_str()), hashlen, hashlen);
		 crypto_generichash_blake2b_update(&state, output, hashlen);
                 crypto_generichash_blake2b_final(&state, output, hashlen);
	     }
             return std::string(reinterpret_cast<const char *>(output), hashlen);
         };
	 std::string operator()(std::string &input, std::string &input2){
	     unsigned char output[hashlen];
	     crypto_generichash_blake2b_state state;
	     crypto_generichash_blake2b_init(&state, reinterpret_cast<const unsigned char *>(m_salt.c_str()), hashlen, hashlen);
	     crypto_generichash_blake2b_update(&state, reinterpret_cast<const unsigned char *>(input.c_str()), hashlen);
	     crypto_generichash_blake2b_update(&state, reinterpret_cast<const unsigned char *>(input2.c_str()), hashlen);
             crypto_generichash_blake2b_final(&state, output, hashlen);
	     return std::string(reinterpret_cast<const char *>(output), hashlen);
	 };
	 std::string seed_to_secret(std::string &seed, size_t index, size_t subindex, size_t side){
	     unsigned char unsalted[hashlen];
	     unsigned char output[hashlen];
	     std::string sidec = (side) ? "R" : "L";
	     std::string designator=std::to_string(index) + sidec + std::to_string(subindex);
             crypto_generichash_blake2b(unsalted, hashlen, reinterpret_cast<const unsigned char *>(designator.c_str()), designator.length(), reinterpret_cast<const unsigned char *>(seed.c_str()), hashlen);
             crypto_generichash_blake2b(output, hashlen, unsalted, hashlen, reinterpret_cast<const unsigned char *>(m_salt.c_str()), hashlen);
             return std::string(reinterpret_cast<const char *>(output), hashlen);;
	 };
     private:
	 std::string &m_salt;
  };
  template<size_t hashlen, size_t wotsbits>
  struct subkey {
        subkey(blake2<hashlen> &blake2b, std::string seed, size_t index, size_t subindex): m_blake2b(blake2b){
	    for (size_t side=0; side < 2; side ++) {
	        m_private.push_back(blake2b.seed_to_secret(seed, index, subindex, side));
	    }
	};
	virtual ~subkey(){};
	std::string pubkey() {
            if (m_public == "") {
              std::string privkey_1 = m_blake2b(m_private[0], 1<<wotsbits);
	      std::string privkey_2 = m_blake2b(m_private[1], 1<<wotsbits);
              m_public = m_blake2b(privkey_1, privkey_2);
	    }
            return m_public;
	};
        std::string operator [](uint16_t index) {
	    return m_blake2b(m_private[0], index) + m_blake2b(m_private[0], (1<<wotsbits) - index -1);
	}
     private:
	blake2<hashlen> &m_blake2b;
        std::vector<std::string> m_private;
        std::string m_public;
  };
  template<size_t hashlen, size_t wotsbits>
  std::vector<uint16_t> digest_to_numlist(std::string &msg_digest) {
      std::vector<uint16_t> rval;
      constexpr static size_t subkey_count =  (hashlen * 8 + wotsbits -1) / wotsbits;
      constexpr static size_t morebits = subkey_count * wotsbits - hashlen * 8;
      uint16_t val = 0;
      size_t remaining_bits = wotsbits - morebits;
      size_t byteindex = 0;
      const unsigned char *data = reinterpret_cast<const unsigned char *>(msg_digest.c_str());
      while (byteindex < hashlen) {
         while (remaining_bits > 8) {
             val = (val << 8) + data[byteindex];
	     byteindex +=1;
             remaining_bits -= 8;
	 }
	 val = (val << remaining_bits) + (data[byteindex] >> (8-remaining_bits));
	 rval.push_back(val);
	 uint16_t val2 = ((data[byteindex] << remaining_bits) & 255) >> remaining_bits;
	 uint16_t used_bits = 8 - remaining_bits;
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
  };
  template<size_t hashlen, size_t subkey_count, size_t wotsbits>
  struct private_key {
        private_key(blake2<hashlen> &blake2b, std::string seed, size_t index){
	    for(size_t subindex=0; subindex < subkey_count; subindex++) {
               m_subkeys.push_back(subkey<hashlen, wotsbits>(blake2b, seed, index, subindex));
	    }
	};
	virtual ~private_key(){};
	std::string pubkey() {
            std::string rval = "";
	    std::for_each(std::begin(m_subkeys), std::end(m_subkeys), [&rval](subkey<hashlen, wotsbits> & value) {
                rval += value;
            });
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
     private:
	std::vector<subkey<hashlen, wotsbits>> m_subkeys;
  };
  template<size_t hashlen,  size_t merkledepth, size_t wotsbits, size_t pubkey_size>
  struct private_keys {
	static constexpr size_t subkey_count =  (hashlen * 8 + wotsbits -1) / wotsbits;
        private_keys(blake2<hashlen> &blake2b, std::string seed, size_t multiproc) {
	   for (size_t index=0; index < pubkey_size; index++) {
               m_keys.push_back(private_key<hashlen, subkey_count, wotsbits>(blake2b, seed, index));
	   }
	};
	virtual ~private_keys(){};
	private_key<hashlen, (hashlen*8 + wotsbits -1)/wotsbits ,wotsbits> &operator [](uint16_t index)  {
            return this->m_keys[index];
        };
     private:
	std::vector<private_key<hashlen,(hashlen * 8 + wotsbits -1) / wotsbits, wotsbits>>  m_keys;
  };
  template<size_t hashlen, size_t wotsbits, size_t merkledepth>
  struct merkle_tree {
        merkle_tree(blake2<hashlen> & hashfunction,
	            private_keys<hashlen,
		                 merkledepth,
		                 wotsbits,
		                 1 << merkledepth > &privkey): m_hashfunction(hashfunction),
	                                                      m_private_keys(privkey){
	};
	virtual ~merkle_tree(){};
	std::string pubkey() {
	    if ( m_merkle_tree.find("") == m_merkle_tree.end() ) {
                this->populate();
	    }
            return m_merkle_tree[""];
	};
	std::string operator [](uint16_t)  {
	    if ( m_merkle_tree.find("") == m_merkle_tree.end() ) {
                this->populate();
            }
	    //FIXME: implement this as in python lib.
	    return "BOGUS-MTHEADER";
	};
     private:
	void populate() {
	    m_merkle_tree[""] = "POPULATE-NOT-IMPLEMENTED";
            // FIXME: Populate merkletree from private keys.
	};
	blake2<hashlen> &m_hashfunction;
	private_keys<hashlen,
                     merkledepth,
                     wotsbits,
                     1 << merkledepth > m_private_keys;
	std::map<std::string, std::string> m_merkle_tree;
  };
  template<size_t hashlen=24, size_t wotsbits=12, size_t merkledepth=10>
  struct signing_key {
         signing_key(size_t multiproc=8): m_next_index(0), 
		                          m_seed(make_seed<hashlen>()),
	                                  m_salt(make_seed<hashlen>()),
		                          m_hashfunction(m_salt),
	                                  m_privkeys(m_hashfunction, m_seed, multiproc),
	                                  m_merkle_tree(m_hashfunction, m_privkeys) {
         };
         signing_key(std::string serialized) {
             throw std::runtime_error("not yet implemented");
         };
	 std::string sign_digest(std::string &digest) {
	     uint16_t ndx = htons(this->m_next_index);
	     std::string ndxs = std::string(reinterpret_cast<const char *>(&ndxs), 2);
             std::string rval = this->m_merkle_tree.pubkey() +
                                this->m_salt +
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
             throw std::runtime_error("not yet implemented");
         }
         virtual ~signing_key(){}
     private:
	 uint16_t m_next_index;
	 std::string m_seed;
	 std::string m_salt;
	 blake2<hashlen> m_hashfunction;
	 // private_keys<hashlen, wotsbits, merkledepth, 1 << merkledepth > m_privkeys;
	 private_keys<hashlen, merkledepth, wotsbits, 1 << merkledepth > m_privkeys;
	 merkle_tree<hashlen, wotsbits, merkledepth> m_merkle_tree;
  };
  //FIXME: implement a validator as in python lib.
}
#endif
