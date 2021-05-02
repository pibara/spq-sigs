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
#include <iostream> //FIXME: remove iostream debugging
#include <sodium.h>
#include <arpa/inet.h>

namespace spqsigs {
  class GENERATE {};
  template<unsigned char hashlen>
  struct primative {
         primative(std::string &salt): m_salt(salt) {}
	 virtual ~primative(){}
	 static std::string make_seed(){
             char output[hashlen];
             randombytes_buf(output, hashlen);
             return std::string(output, hashlen);
	 };
	 primative(GENERATE): m_salt(make_seed()) {}
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
	 std::string get_salt() {
             return m_salt;
	 }
     private:
	 std::string m_salt;
  };
  template<unsigned char hashlen, unsigned char wotsbits>
  struct subkey {
        subkey(primative<hashlen> &hashprimative, std::string seed, size_t index, size_t subindex): m_hashprimative(hashprimative){
	    for (size_t side=0; side < 2; side ++) {
	        m_private.push_back(hashprimative.seed_to_secret(seed, index, subindex, side));
	    }
	};
	virtual ~subkey(){};
	std::string pubkey() {
            if (m_public == "") {
              std::string privkey_1 = m_hashprimative(m_private[0], 1<<wotsbits);
	      std::string privkey_2 = m_hashprimative(m_private[1], 1<<wotsbits);
              m_public = m_hashprimative(privkey_1, privkey_2);
	    }
            return m_public;
	};
        std::string operator [](uint16_t index) {
	    return m_hashprimative(m_private[0], index) + m_hashprimative(m_private[0], (1<<wotsbits) - index -1);
	}
     private:
	primative<hashlen> &m_hashprimative;
        std::vector<std::string> m_private;
        std::string m_public;
  };
  template<unsigned char hashlen, unsigned char wotsbits>
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

  template<unsigned char hashlen,  unsigned char merkledepth, unsigned char wotsbits, uint16_t pubkey_size>
  struct private_keys;

  template<unsigned char hashlen, unsigned char subkey_count, unsigned char wotsbits, unsigned char merkledepth, uint16_t pubkey_size>
  struct private_key {
	virtual ~private_key(){};
	std::string pubkey() {
            std::string rval("");
	    std::for_each(std::begin(m_subkeys), std::end(m_subkeys), [&rval, this](subkey<hashlen, wotsbits> & value) {
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
	private_key(primative<hashlen> &hashprimative, std::string seed, size_t index){
            for(size_t subindex=0; subindex < subkey_count; subindex++) {
               m_subkeys.push_back(subkey<hashlen, wotsbits>(hashprimative, seed, index, subindex));
            }
        };
	std::vector<subkey<hashlen, wotsbits>> m_subkeys;
  };

  template<unsigned char hashlen=24, unsigned char wotsbits=12, unsigned char merkledepth=10, bool do_threads=false>
  struct signing_key;

  template<unsigned char hashlen,  unsigned char merkledepth, unsigned char wotsbits, uint16_t pubkey_size>
  struct private_keys {
	static constexpr uint16_t subkey_count =  (hashlen * 8 + wotsbits -1) / wotsbits;
	virtual ~private_keys(){};
	private_key<hashlen, (hashlen*8 + wotsbits -1)/wotsbits ,wotsbits, merkledepth, pubkey_size> &operator [](uint16_t index)  {
            return this->m_keys[index];
        };
	friend signing_key<hashlen, wotsbits, merkledepth, true>;
	friend signing_key<hashlen, wotsbits, merkledepth, false>;
     private:
	private_keys(primative<hashlen> &hashprimative, std::string seed) {
           for (size_t index=0; index < pubkey_size; index++) {
               m_keys.push_back(private_key<hashlen, subkey_count, wotsbits, merkledepth, pubkey_size>(hashprimative, seed, index));
           }
        };
	std::vector<private_key<hashlen,(hashlen * 8 + wotsbits -1) / wotsbits, wotsbits, merkledepth, pubkey_size>>  m_keys;
  };
  template<unsigned char merkledepth, unsigned char remaining_depth, bool do_threads>
  constexpr bool use_threads() {
      if constexpr ((do_threads == false) or (merkledepth < 4) or (merkledepth - remaining_depth > 2)) {
          return false;
      } else {
          return true;
      }
  };
  template<unsigned char wotsbits>
  std::vector<bool> as_bits(uint16_t wotsval) {
      std::vector<bool> rval;
      for (unsigned char index=wotsbits; index>0; index--) {
	  bool val = (((wotsval >> (index - 1)) & 1) == 1);
          rval.push_back(val);
      }
      return rval;
  }
  template<unsigned char hashlen, unsigned char wotsbits, unsigned char merkledepth, bool do_threads>
  struct signing_key {
         struct merkle_tree {
               merkle_tree(primative<hashlen> & hashfunction,
       	                   private_keys<hashlen,
		                        merkledepth,
		                        wotsbits,
		                        1 << merkledepth > &privkey): m_hashfunction(hashfunction),
	                                                              m_private_keys(privkey){
	       };
	       virtual ~merkle_tree(){};
	       std::string pubkey() {
	           if ( m_merkle_tree.find("") == m_merkle_tree.end() ) {
                       this->populate<merkledepth>(0, "");
	           }
                   return m_merkle_tree[""];
	       };
	       std::string operator [](uint16_t wotsval)  {
	           if ( m_merkle_tree.find("") == m_merkle_tree.end() ) {
                       this->populate<merkledepth>(0, "");
                   }
                   std::vector<bool> wots_val_bits = as_bits<wotsbits>(wotsval);
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
	       std::string populate(uint16_t start, std::string prefix) {
	           if constexpr (remaining_depth != 0) {
		       //if constexpr (use_threads<merkledepth, remaining_depth, do_threads>()) {
		           // FIXME: Run the two sub-trees in seperate threaths ans wait for results
                           //std::cerr << "threaded: " << prefix << std::endl;
		       //}
                       std::string left = this->populate<remaining_depth-1>(start,prefix + "0");
	               std::string right = this->populate<remaining_depth-1>(start + (1 << (remaining_depth - 1)),prefix + "1");
                       m_merkle_tree[prefix] = m_hashfunction(left, right);
	           } else {
		       std::string pkey = m_private_keys[start].pubkey();
                       m_merkle_tree[prefix] =  m_hashfunction(pkey);
	           }
	           return m_merkle_tree[prefix];
	       };
	       primative<hashlen> &m_hashfunction;
	       private_keys<hashlen,
                            merkledepth,
                            wotsbits,
                            1 << merkledepth > m_private_keys;
	       std::map<std::string, std::string> m_merkle_tree;
         };
	 static_assert(hashlen > 2);
	 static_assert(hashlen < 65);
	 static_assert(wotsbits < 17);
	 static_assert(wotsbits > 2);
	 static_assert(merkledepth < 17);
	 static_assert(merkledepth > 2);
         signing_key(): m_next_index(0),
		        m_seed(primative<hashlen>::make_seed()),
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
	     std::string ndxs = std::string(reinterpret_cast<const char *>(&ndxs), 2);
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
	 primative<hashlen> m_hashfunction;
	 private_keys<hashlen, merkledepth, wotsbits, 1 << merkledepth > m_privkeys;
	 merkle_tree m_merkle_tree;
  };
  //FIXME: implement a validator as in python lib.
}
#endif
