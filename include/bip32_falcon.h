/*
 * BIP32-Falcon: Hierarchical deterministic keys for Falcon signatures
 */

#ifndef BIP32_FALCON_H
#define BIP32_FALCON_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t seed_material[64]; // Full 64-byte output of derivation hash
    uint32_t depth;
    uint32_t child_number;
} bip32_node_t;

int bip32_master(bip32_node_t *out, const uint8_t *entropy, size_t seed_len);

int bip32_derive(bip32_node_t *out, const bip32_node_t *parent, uint32_t index);

int bip44_derive_path(bip32_node_t *out, const bip32_node_t *master, const char *path);

#ifdef __cplusplus
}
#endif

#endif /* BIP32_FALCON_H */
