from aes_core.ofb import aes_ofb_encrypt

print("🔑 Starting Variable IV Tests...\n")

# Static test vector (plaintext and key are fixed)
plaintext = bytes.fromhex("00000000000000000000000000000000")
key = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")

# Test cases: (iv_hex, expected_ciphertext_hex)
test_vectors = [
    ("80000000000000000000000000000000", "ddc6bf790c15760d8d9aeb6f9a75fd4e"),
    ("c0000000000000000000000000000000", "0a6bdc6d4c1e6280301fd8e97ddbe601"),
    ("fffff800000000000000000000000000", "d5e38bf15f16d90e3e214041d774daa8"),
    ("fffffffff80000000000000000000000", " 54fafe26e4287f17d1935f87eb9ade01"),
]

# Run and validate each test
for i, (iv_hex, expected_cipher_hex) in enumerate(test_vectors, start=1):
    iv = bytes.fromhex(iv_hex)
    expected = bytes.fromhex(expected_cipher_hex)
    result = aes_ofb_encrypt(key, iv, plaintext)
    assert result[:16] == expected, f"❌ Test {i} failed for IV={iv_hex}: got {result.hex()}, expected {expected.hex()}"
    print(f"✅ Test {i} passed. IV={iv_hex}")


print("🔑 Finished Variable IV Tests\n")