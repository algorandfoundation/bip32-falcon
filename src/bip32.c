#include "bip32_falcon.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>
#include "../external/falcon/falcon.h"

int bip32_master(bip32_node_t *out, const uint8_t *entropy, size_t seed_len)
{
    uint8_t master_seed[64];
    unsigned int master_seed_len = 0;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
    EVP_DigestUpdate(ctx, entropy, seed_len);
    EVP_DigestFinal_ex(ctx, master_seed, &master_seed_len);
    EVP_MD_CTX_free(ctx);

    printf("Master seed, SHA512(entropy): ");
    for (size_t i = 0; i < master_seed_len; i++) {
        printf("%02x", master_seed[i]);
    }
    printf("\n");

    out->depth = 0;
    out->child_number = 0;
    memcpy(out->seed_material, master_seed, 64);

    return (int)master_seed_len;
}

/** Unlike regular BIP32 for ECC, for FALCON we don't distinguish between 
 * hardened and non-hardened derivation, since at the time of writing this,
 * we don't know if it's even possible to have a similar scheme 
 * with Lattice-based signatures. 
 *
 * - We assume derivations always require private key material, so we don't have a separate "public" derivation function.
 * - The index is just a unsigned 32-bit integer
 *
 * Derivation is defined as: 
 *  child_seed_material = HMAC-SHA512(parent_seed_material || index)
 *  child_depth = parent_depth + 1
 *  child_number = index
 */
int bip32_derive(bip32_node_t *out, const bip32_node_t *parent, uint32_t index)
{
    unsigned int child_seed_material_len = 64;
    uint8_t index_be[4];

    // convert index to big-endian
    index_be[0] = (uint8_t)(index >> 24);
    index_be[1] = (uint8_t)(index >> 16);
    index_be[2] = (uint8_t)(index >> 8);
    index_be[3] = (uint8_t)index;

    unsigned char *result = HMAC(EVP_sha512(),
                                 parent->seed_material, 64,
                                 index_be, sizeof(index_be),
                                 out->seed_material, &child_seed_material_len);
    if (result == NULL) {
        return -1;
    }

    printf("Derived seed material; HMAC-SHA512(parent_seed_material || %u): ", index);
    for (size_t i = 0; i < 64; i++) {
        printf("%02x", out->seed_material[i]);
    }
    printf("\n");

    out->depth = parent->depth + 1;
    out->child_number = index;

    return (int)child_seed_material_len;
}

/**
 * BIP44 path derivation
 *
 * The path is a string like "m/44'/0'/0'/0/0" where each component is a level of derivation.
 * The 'm' at the start indicates the master node, and each subsequent component is an index for derivation. 
 *
 * For simplicity, we will not implement hardened vs non-hardened derivation, and just treat all indices as normal.
 */ 
int bip44_derive_path(bip32_node_t *out, const bip32_node_t *master, const char *path)
{
    // Start with the master node
    bip32_node_t current = *master;

    const char *p = path;
    if (*p != 'm') {
        printf("Invalid path: must start with 'm'\n");
        return -1;
    }
    p++; // skip 'm'
    
    while (*p) { // run until end of string
        if (*p != '/') {
            printf("Invalid path: components must be separated by '/'\n");
            return -1;
        }
        p++; // skip '/'

        // Handle hardened index (e.g., "44'") - remove the apostrophe
        char *endptr;
        uint32_t index = strtoul(p, &endptr, 10);
        if (endptr == p) {
            printf("Invalid path: could not parse index\n");
            return -1;
        }
        p = endptr; // move past the index

        // As far as we known we don't have an equivalentfor
        // hardened vs soft derivations for lattice based sigs
        // Complying with BIP44, but we ignore the apostrophe if it's there
        // Effectivaly, all derivations are "hardened" in the sense that they require private key material, 
        if (*p == '\'') {
            p++;
        }

        bip32_node_t child_node;
        int ret = bip32_derive(&child_node, &current, index);
        if (ret < 0) {
            printf("Derivation failed at index %u\n", index);
            return -1;
        }

        current = child_node;
    }
    
    *out = current; 

    printf("Derived node at path %s:\n", path);
    printf("Depth: %u\n", out->depth);
    printf("Child number: %u\n", out->child_number);

    printf("Final derived seed material: ");
    for (size_t i = 0; i < 32; i++) {
        printf("%02x", out->seed_material[i]);
    }
    printf("\n");

    return 0;
}
