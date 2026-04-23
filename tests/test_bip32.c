#include "bip32_falcon.h"
#include "../external/falcon/falcon.h"
#include "../external/falcon/deterministic.h"
#include <stdio.h>
#include <string.h>

int test_bip32_master_key(void)
{
    const uint8_t seed[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    bip32_node_t node;
    int ret = bip32_master(&node, seed, sizeof(seed));

    if (ret < 0) {
        printf("FAIL: bip32_master returned %d\n", ret);
        return 1;
    }

    if (node.depth != 0) {
        printf("FAIL: depth should be 0, got %u\n", node.depth);
        return 1;
    }

    if (node.child_number != 0) {
        printf("FAIL: child_number should be 0, got %u\n", node.child_number);
        return 1;
    }

    printf("Master key length: %d\n", ret);

    // output the node
    printf("Master node: \n");
    printf("  Seed material: \n");
    for (size_t i = 0; i < 64; i++) {
        printf("%02x", node.seed_material[i]);
    }
    printf("\n");

    printf("PASS: bip32_master_key\n");
    return 0;
}

int test_bip32_derive(void)
{
  const uint8_t root_seed[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    bip32_node_t root_node;
    int ret = bip32_master(&root_node, root_seed, sizeof(root_seed));
    if (ret < 0) {
        printf("FAIL: bip32_master returned %d\n", ret);
        return -1;
    }

    uint32_t index = 42;
    bip32_node_t child_node;
    ret = bip32_derive(&child_node, &root_node, index);
    if (ret < 0) {
        printf("FAIL: bip32_derive returned %d\n", ret);
        return -1;
    }

    printf("Derived child node at index %u:\n", index);
    printf("Child depth: %u\n", child_node.depth);
    printf("Child number: %u\n", child_node.child_number);
    printf("Child seed material: \n");
    for (size_t i = 0; i < 64; i++) {
        printf("%02x", child_node.seed_material[i]);
    }
    printf("\n");

    printf("PASS: bip32_derive\n");
    return 0;
}

int test_bip32_derive_and_get_falcon_keys(void)
{
  bip32_node_t root_node;

  const uint8_t root_seed[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
  };

  int ret = bip32_master(&root_node, root_seed, sizeof(root_seed));
  if (ret < 0) {
      printf("FAIL: bip32_master returned %d\n", ret);
      return -1;
  }

  uint32_t index = 42;
  bip32_node_t child_node;
  ret = bip32_derive(&child_node, &root_node, index);
  if (ret < 0) {
      printf("FAIL: bip32_derive returned %d\n", ret);
      return -1;
  }

  // generate falcon-1024 keys from the child node's seed material
  shake256_context key_rng;
  shake256_init_prng_from_seed(&key_rng, child_node.seed_material, 64);

  uint8_t privkey[FALCON_PRIVKEY_SIZE(10)];
  uint8_t pubkey[FALCON_PUBKEY_SIZE(10)];
  uint8_t tmp[FALCON_TMPSIZE_KEYGEN(10)];

  ret = falcon_keygen_make(&key_rng, 10, privkey, sizeof(privkey),
                           pubkey, sizeof(pubkey), tmp, sizeof(tmp));
  if (ret != 0) {
      printf("FAIL: falcon_keygen_make returned %d\n", ret);
      return -1;
  }

  printf("Falcon-1024 keypair generated successfully\n");
  printf("  Private key size: %zu bytes\n", sizeof(privkey));
  printf("  Public key size: %zu bytes\n", sizeof(pubkey));

  printf("PASS: bip32_derive_and_get_falcon_keys\n");
  return 0;
}

int bip44_test(void)
{
  bip32_node_t master_node;
  const uint8_t root_seed[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
  };

  int ret = bip32_master(&master_node, root_seed, sizeof(root_seed));
  if (ret < 0) {
    printf("FAIL: bip32_master returned %d\n", ret);
    return -1;
  }

  const char *path = "m/44'/283'/0'/0/0";
  bip32_node_t derived_node;

  printf("Deriving node at path %s...\n", path);

  ret = bip44_derive_path(&derived_node, &master_node, path);
  if (ret < 0) {
    printf("FAIL: bip32_derive_path returned %d\n", ret);
    return -1;
  }

  printf("Derived node at path %s:\n", path);
  printf("Depth: %u\n", derived_node.depth);
  printf("Child number: %u\n", derived_node.child_number);
  printf("Seed material: \n");
  for (size_t i = 0; i < 64; i++) {
    printf("%02x", derived_node.seed_material[i]);
  }
  printf("\n");

  // calculate falcon keys from the derived node
  shake256_context key_rng;
  shake256_init_prng_from_seed(&key_rng, derived_node.seed_material, 64);

  uint8_t pubkey[FALCON_DET1024_PUBKEY_SIZE];
	uint8_t privkey[FALCON_DET1024_PRIVKEY_SIZE];
        uint8_t signature[FALCON_DET1024_SIG_COMPRESSED_MAXSIZE];
	size_t sig_len;

        const char *msg = "Hello w0RlD";
  size_t data_len = strlen(msg);
	uint8_t data[data_len];
	memcpy(data, msg, data_len);

  // fill with zeroes
	memset(privkey, 0, FALCON_DET1024_PRIVKEY_SIZE);
	memset(pubkey, 0, FALCON_DET1024_PUBKEY_SIZE);
	memset(signature, 0, FALCON_DET1024_SIG_COMPRESSED_MAXSIZE);

  ret = falcon_det1024_keygen(&key_rng, privkey, pubkey);
  if (ret != 0) {
    printf("FAIL: falcon_keygen_make returned %d\n", ret);
    return -1;
  }

  printf("Falcon-1024 keypair generated successfully from BIP44 path\n");
  // printf(" Pvt Key: ");
  // for (size_t i = 0; i < sizeof(privkey); i++) {
  //     printf("%02x", privkey[i]);
  // }
  // printf("\n Pub Key: ");
  // for (size_t i = 0; i < sizeof(pubkey); i++) {
  //     printf("%02x", pubkey[i]);
  // }
  // printf("\n");
  printf("  Private key size: %zu bytes\n", sizeof(privkey));
  printf("  Public key size: %zu bytes\n", sizeof(pubkey));
  printf("\n");


  // produce signature and verify it
  ret = falcon_det1024_sign_compressed(signature, &sig_len, privkey, data, data_len);

  if (ret != 0) {
    printf("FAIL: falcon_sign_make returned %d\n", ret);
    return -1;
  }
  printf("Signature generated successfully\n");

  // print sig
  printf(" Signature: ");
  for (size_t i = 0; i < sig_len; i++) {
      printf("%02x", signature[i]);
  }
  printf("\n");

  // verify the signature
	int v = falcon_det1024_get_salt_version(signature);
	if (v != FALCON_DET1024_CURRENT_SALT_VERSION) {
		fprintf(stderr, "unexpected salt version: %d", v);
    return -1;
	}

	ret = falcon_det1024_verify_compressed(signature, sig_len, pubkey, data, data_len);
	if (ret != 0) {
		fprintf(stderr, "verify_compressed failed: %d\n", ret);
	  return -1;
	}

  printf("Signature verified successfully\n");

  printf("PASS: bip44_test\n");
  return 0;
}

int main(void)
{
  int failures = 0;

  failures += test_bip32_master_key();
  failures += test_bip32_derive();
  failures += test_bip32_derive_and_get_falcon_keys();
  failures += bip44_test();

  if (failures == 0) {
    printf("All tests PASSED!\n");
    return 0;
  } else {
    printf("%d test(s) FAILED!\n", failures);
    return 1;
  }
}
