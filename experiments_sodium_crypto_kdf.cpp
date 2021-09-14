#include <cstdint>
#include <vector>
#include <string>
#include <exception>
#include <stdexcept>
#include <cstring>
#include <sodium.h>

#include <iostream>

namespace spqsigs {

  template<uint8_t hashlen>
  struct master_key {
          master_key() {
              crypto_kdf_keygen(m_master_key);
          }
          master_key(std::string keybytes) {
              if (keybytes.length() != crypto_kdf_KEYBYTES) {
                 throw std::invalid_argument("Wrong master-key string-length.");
	      }
              std::memcpy(m_master_key, keybytes.c_str(), crypto_kdf_KEYBYTES);
	  }
	  operator std::string() {
              return std::string(m_master_key,crypto_kdf_KEYBYTES);
	  }
	  std::string operator[](uint64_t index) {
              uint8_t output[hashlen];
	      crypto_kdf_derive_from_key(output, hashlen, index, "Signatur", m_master_key);
	      return std::string(output, hashlen);
	  }
      private:
	  uint8_t m_master_key[crypto_kdf_KEYBYTES];
  };

  template<uint8_t hashlen, uint8_t wotsbits>
  uint16_t determine_subkeys_per_signature() {
      return (hashlen * 8 + wotsbits -1) / wotsbits;
  }

  template<uint8_t hashlen, uint8_t wotsbits, uint8_t merkleheight, uint8_t ...Args>
  struct determine_required_keycount { 
      uint64_t operator()(bool deep=true) {
	  if (deep) {
	      determine_required_keycount<hashlen, wotsbits, Args...> determine;
	      uint64_t rval = 1 + 
                    (1<<merkleheight) * 
                    (determine_subkeys_per_signature<hashlen, wotsbits>() + determine(deep));
              return rval;
	  } else {
              uint64_t rval = 1 +
		     (1<<merkleheight) *
		     determine_subkeys_per_signature<hashlen, wotsbits>();
	      return rval;
	  }
      }
  };

  template<uint8_t hashlen, uint8_t wotsbits, uint8_t merkleheight>
  struct determine_required_keycount<hashlen, wotsbits, merkleheight> {
      uint64_t operator()(bool deep=true) {
          uint64_t rval = determine_subkeys_per_signature<hashlen, wotsbits>() * (1<<merkleheight) + 1;
          return rval;
      }
  };


  template<uint8_t hashlen, uint8_t wotsbits, uint8_t merkleheight, uint8_t ...Args>
  struct unique_index_generator {
	  unique_index_generator(master_key<hashlen> &mkey, uint64_t own=0):
		  m_master_key(mkey),
		  m_own(own),
		  m_determine(),
	          m_generate(
		      own + m_determine(false)
		  ) {}
	  virtual ~unique_index_generator() {}
	  unique_index_generator<hashlen, wotsbits, Args...> operator()(){
	      auto rval = m_generate;
              m_generate += m_determine();
	      return unique_index_generator<hashlen, wotsbits, Args...>(m_master_key, rval);
	  }
	  uint64_t operator[](uint16_t index) {
              return m_own + 1 + index * determine_subkeys_per_signature<hashlen, wotsbits>();
	  }
	  operator uint64_t(){ return m_own;}
      private:
	  master_key<hashlen> &m_master_key;
	  uint64_t m_own;
	  determine_required_keycount<hashlen, wotsbits, Args...> m_determine;
	  uint64_t m_generate;
  };

  template<uint8_t hashlen, uint8_t wotsbits, uint8_t merkleheight>
  struct unique_index_generator<hashlen, wotsbits, merkleheight> {
          unique_index_generator(master_key<hashlen> &mkey, uint64_t own):
	      m_master_key(mkey),
	      m_own(own) {}
          virtual ~unique_index_generator() {}
	  uint64_t operator[](uint16_t index) {
              return m_own + 1 + index * determine_subkeys_per_signature<hashlen, wotsbits>();
          }
	  operator uint64_t(){ return m_own;}
      private:
	  master_key<hashlen> &m_master_key;
          uint64_t m_own;
  };

  template <uint8_t hashlen, uint8_t wotsbits, uint8_t merkleheight, uint8_t ...Args>
  struct unique_index_restore {
      void operator()(uint64_t index, std::vector<uint16_t> &result) {
          determine_required_keycount<hashlen, wotsbits, Args...> determine;
	  auto required_keycount = determine();
	  uint16_t rval = index / required_keycount;
	  result.push_back(rval);
	  unique_index_restore<hashlen, wotsbits, Args...> next_level;
	  next_level(index - required_keycount * rval, result);
      }
  };

  template <uint8_t hashlen, uint8_t wotsbits, uint8_t merkleheight>
  struct unique_index_restore<hashlen, wotsbits, merkleheight> {
      void operator()(uint64_t index, std::vector<uint16_t> &result) {
          uint16_t rval = index;
          result.push_back(rval);
      }
  };

}

int main() {
    spqsigs::master_key<24> mk;
    spqsigs::unique_index_generator<24,12,3,4,5> ig(mk);
    uint64_t top = ig;
    std::cout << "########################################" << std::endl;
    std::cout << top << std::endl;
    for (int i0=0; i0<8; i0++) {
	    std::cout << " -> " << ig[i0] << std::endl;
    }
    for (int i1=0;i1<8;i1++) {
	std::cout << "-#######################################" << std::endl;
        auto l2 = ig();
	uint64_t l2v = l2;
	std::cout << " * " << l2v << std::endl;
	for (int i0=0; i0<16; i0++) {
            std::cout << "  -> " << l2[i0] << std::endl;
        }
	for (int i2=0;i2<16;i2++) {
	    std::cout << "--######################################" << std::endl;
            auto l3 = l2();
	    uint64_t l3v = l3;
            std::cout << "  + " << l3v << std::endl;
	    for (int i3=0; i3<32; i3++) {
                std::cout << "  -> " << l3[i3] << " " << i3 + (32 * (i2 + (16*i1))) << "(" << i1 << "," << i2 << "," << i3 << ")" <<std::endl;
		//std::vector<uint16_t> reverse;
		//spqsigs::unique_index_restore<24,12,3,4,5> restore;
		//restore(l3[i3], reverse);
		//std::cout << "      " << i1 << "," << i2 << "," << i3 << " -> ";
		//for (auto i: reverse)
                //    std::cout << i << ',';
		//std::cout << std::endl;
            }
	    std::cout << "--######################################" << std::endl;
	}
	std::cout << "-#######################################" << std::endl;
    }
    std::cout << "########################################" << std::endl;
}
