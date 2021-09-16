#include <cstdint>
#include <vector>
#include <string>
#include <exception>
#include <stdexcept>
#include <cstring>
#include <sodium.h>

#include <iostream>

namespace spqsigs {
namespace impl {
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
		  m_determine(),
		  m_determine2(),
	          m_generate(
		      own + m_determine()
		  ) {}
	  virtual ~unique_index_generator() {}
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
      private:
	  master_key<hashlen> &m_master_key;
	  uint64_t m_own;
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

  } // end of impl namespace
}

int main() {
    spqsigs::impl::master_key<24> mk;
    spqsigs::impl::unique_index_generator<24,12,3,4,5> ig(mk);
    uint64_t top = ig;
    std::cout << "########################################" << std::endl;
    std::cout << top << std::endl;
    for (int i0=0; i0<8; i0++) {
	    std::cout << " -> " << ig[i0] << std::endl;
    }
    for (int i1=0;i1<8;i1++) {
	std::cout << "-#######################################" << std::endl;
        auto l2 = ig(i1);
	uint64_t l2v = l2;
	std::cout << " * " << l2v << std::endl;
	for (int i0=0; i0<16; i0++) {
            std::cout << "  -> " << l2[i0] << std::endl;
        }
	for (int i2=0;i2<16;i2++) {
	    std::cout << "--######################################" << std::endl;
            auto l3 = l2(i2);
	    uint64_t l3v = l3;
            std::cout << "  + " << l3v << std::endl;
	    for (int i3=0; i3<32; i3++) {
                 auto key = l3[i3];
		 for (int subkey=0; subkey<16; subkey++) {
                     auto skey = key[subkey];
		     auto index1 = skey[false];
		     auto index2 = skey[true];
		     auto secret1 = skey(false);
                     auto secret2 = skey(true);
		     std::cout << "    : " << i1 << "," << i2 << "," << i3 << "[" << subkey << ",false] = " << index1 << ":"  << secret1 << std::endl;
		     std::cout << "    : " << i1 << "," << i2 << "," << i3 << "[" << subkey << ",true] = " << index2 << ":" << secret2 << std::endl;
		 }
            }
	    std::cout << "--######################################" << std::endl;
	}
	std::cout << "-#######################################" << std::endl;
    }
    std::cout << "########################################" << std::endl;
    return 0;
}
