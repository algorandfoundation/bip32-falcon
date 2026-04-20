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
    uint8_t seed_material[64]; // seed (SHA512 output) for key generation
    uint8_t chain_code[32]; // Is this even needed for falcon?
    uint32_t depth;
    uint32_t child_number;
} bip32_node_t;

int bip32_master(bip32_node_t *out, const uint8_t *entropy, size_t seed_len);

int bip32_derive(bip32_node_t *out, const bip32_node_t *parent, uint32_t index);

int bip44_derive_path(bip32_node_t *out, const bip32_node_t *master, const char *path);

int falcon_from_node(void *privkey_buf, size_t buf_size, const bip32_node_t *node);

#ifdef __cplusplus
}
#endif

#endif /* BIP32_FALCON_H */
