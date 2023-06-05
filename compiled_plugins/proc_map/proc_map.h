#ifndef __PROCMAP_H__
#include <glib.h>
#include "panda/plugin.h"

// We match the qemu7 qpp api with two gpointers per callback
PPP_CB_TYPEDEF(void, on_current_proc_change, gpointer, gpointer);

//const uint64_t fnv_prime = 0x100000001b3ULL;
const uint32_t fnv_prime = 0x811C9DC5;

// Only really need this for coverage
uint32_t hash(char *input) {
    uint32_t rv = 0;
    for (size_t i=0; i < strlen(input); i++) {
      rv *= fnv_prime;
      rv ^= (uint32_t)input[i];
    }

    return rv;
}

struct hash_tuple {
  //https://www.geeksforgeeks.org/how-to-create-an-unordered_map-of-tuples-in-c/
  template <class T1, class T2>
    size_t operator()(const std::tuple<T1, T2>& x) const {
      return std::get<0>(x) ^ std::get<1>(x);
    }
};

#endif