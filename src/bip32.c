#include "bip32_falcon.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>
#include "../external/falcon/falcon.h"

int bip32_master(bip32_node_t *out, const uint8_t *entropy, size_t seed_len)
{
    //sha512 
    uint8_t master_root_seed[64];
    unsigned int master_root_seed_len = 0;
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
    EVP_DigestUpdate(ctx, entropy, seed_len);
    EVP_DigestFinal_ex(ctx, master_root_seed, &master_root_seed_len);
    EVP_MD_CTX_free(ctx);

    printf("Master seed, SHA512(entropy): ");
    for (size_t i = 0; i < master_root_seed_len; i++) {
        printf("%02x", master_root_seed[i]);
    }
    printf("\n");

    out->depth = 0;
    out->child_number = 0;
    memcpy(out->seed_material, master_root_seed, 32);
    //chain code is the second half of the master key
    memcpy(out->chain_code, master_root_seed + 32, 32);

    return master_root_seed_len;
}

/** Unlike regular BIP32 for ECC, for FALCON we don't distinguish between 
 * hardened and non-hardened derivation, since at the time of writing this,
 * we don't know if it's even possible to have a similar scheme 
 * with Lattice-based signatures. 
 *
 * - We assume derivations always require private key material, so we don't have a separate "public" derivation function.
 * - The index is just a 32-bit integer
 *
 * Derivation is defined as: 
 *  child_seed_material = SHA512(parent_seed_material || index)
 *  child_depth = parent_depth + 1
 *  child_number = index
 */
int bip32_derive(bip32_node_t *out, const bip32_node_t *parent, uint32_t index)
{
    // derive seed material
    unsigned int child_seed_material_len = 0;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }
    EVP_DigestInit_ex(ctx, EVP_sha512(), NULL);
    EVP_DigestUpdate(ctx, parent->chain_code, 32);
    EVP_DigestUpdate(ctx, parent->seed_material, 32);
    EVP_DigestUpdate(ctx, &index, sizeof(index));
    EVP_DigestFinal_ex(ctx, out->seed_material, &child_seed_material_len);
    EVP_MD_CTX_free(ctx);

    printf("Derived seed material; SHA512(parent_seed_material || %d): ", index);
    for (size_t i = 0; i < child_seed_material_len; i++) {
        printf("%02x", out->seed_material[i]);
    }
    printf("\n");

    // assign index and depth
    out->depth = parent->depth + 1;
    out->child_number = index;

    return child_seed_material_len;
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
    
    // by the end we should have derived 5 levels
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
