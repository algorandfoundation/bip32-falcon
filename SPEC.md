# HD "BIP32/44-Like" Falcon Derivation Flows

The spirit of this proposal is to handle derivation of seeds, separate from actual keys. 
And at the end of the derivation process, then we seed the falcon keygen with the derived seed material.

## Master Seed

```
I             = SHA512(entropy)
seed_material = I
depth         = 0
child_number  = 0
```

`note:` **entropy** derived from the user's mnemonic (BIP39) or any other entropy source. 

## Child Derivation (CKD)

All derivations are hardened.

```
I             = HMAC-SHA512(key = parent.seed_material,
                            data = index_BE)
seed_material = I
depth         = parent.depth + 1
child_number  = index
```

`index_BE` is the 4-byte big-endian encoding of the 32-bit index.

`note:` Big-endian encoding for BIP32 consistency (if we care about that). 

## BIP32 Path Derivation

Parse `m / i0 / i1 / ... / in`.
Start from the master node and sequentially apply CKD.

### BIP44

We limit depth to the "standard" 5 levels of BIP44 (purpose, coin_type, account, change, address_index).

## Node

```c
typedef struct {
    uint8_t  seed_material[64];
    uint32_t depth;
    uint32_t child_number;
} bip32_node_t;
```

`note:` We're excluding the traditional chaincode and fingerprint fields since they're not needed for Falcon key derivation.

## Falcon Keygen Binding

At the end of the derivation process.

```c
shake256_init_prng_from_seed(&rng, node->seed_material, 64);
falcon_det1024_keygen(&rng, privkey, pubkey);
```

## Serialization

No `xprv`/`xpub` encoding. Nodes are stored as the raw `bip32_node_t`
