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
    ("fffffffff80000000000000000000000", "54fafe26e4287f17d1935f87eb9ade01"),
    ("fffffe00000000000000000000000000", "6ef4cc4de49b11065d7af2909854794a"),
    ("fff00000000000000000000000000000", "c218faa16056bd0774c3e8d79c35a5e4"),
    ("fffffffffffffffffffff80000000000", "9ad983f3bf651cd0393f0a73cccdea50"),
    ("ffffffffffffffffffe0000000000000","a013014d4ce8054cf2591d06f6f2f176"),
    ("fffc0000000000000000000000000000", "dc8f0e4915fd81ba70a331310882f6da"),
    ("fffffffffffe00000000000000000000" ,"1a518dddaf9efa0d002cc58d107edfc8")
]

# Run and validate each test
for i, (iv_hex, expected_cipher_hex) in enumerate(test_vectors, start=1):
    iv = bytes.fromhex(iv_hex)
    expected = bytes.fromhex(expected_cipher_hex)
    result = aes_ofb_encrypt(key, iv, plaintext)
    assert result[:16] == expected, f"❌ Test {i} failed for IV={iv_hex}: got {result.hex()}, expected {expected.hex()}"
    print(f"✅ Test {i} passed. IV={iv_hex}")


print("🔑 Finished Variable IV Tests\n")