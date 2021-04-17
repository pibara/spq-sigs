#include "spq_sigs.hpp"

int main(int args, char **argv) {
    auto skey = spqsigs::signing_key<24UL, 12,10>(6);
}
