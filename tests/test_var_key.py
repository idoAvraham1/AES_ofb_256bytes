from aes_core.ofb import aes_ofb_encrypt

print("🔑 Starting Variable Key Tests...\n")

# Static test vector (plaintext and IV are the same in all tests)
plaintext = bytes.fromhex("00000000000000000000000000000000")
iv = bytes.fromhex("00000000000000000000000000000000")

# Test cases: (key_hex, expected_ciphertext_hex)
test_vectors = [
    ("8000000000000000000000000000000000000000000000000000000000000000" , "e35a6dcb19b201a01ebcfa8aa22b5759"),
    ("fe00000000000000000000000000000000000000000000000000000000000000" , "60e32246bed2b0e859e55c1cc6b26502"),
    ("ffc0000000000000000000000000000000000000000000000000000000000000" , "a3f599d63a82a968c33fe26590745970"),
    ("fffc000000000000000000000000000000000000000000000000000000000000" , "4dcede8da9e2578f39703d4433dc6459"),
    ("ffffffff00000000000000000000000000000000000000000000000000000000" ,"ad9fc613a703251b54c64a0e76431711"),
    ("fffffffffffffffffffc00000000000000000000000000000000000000000000" ,"ab980296197e1a5022326c31da4bf6f3"),
    ("fffffffffffffffffffe00000000000000000000000000000000000000000000" , "f97d57b3333b6281b07d486db2d4e20c"),
    ("ffffffffffffffffffffc0000000000000000000000000000000000000000000", "ad4916f5ee5772be764fc027b8a6e539"),
    ("fffffffffffffffffffff0000000000000000000000000000000000000000000" , "4e6e627c1acc51340053a8236d579576"),
    ("ffffffff80000000000000000000000000000000000000000000000000000000" , "33ac9eccc4cc75e2711618f80b1548e8"),
   
   
]

# Run and validate each test
for i, (key_hex, expected_cipher_hex) in enumerate(test_vectors, start=1):
    key = bytes.fromhex(key_hex)
    expected = bytes.fromhex(expected_cipher_hex)
    result = aes_ofb_encrypt(key, iv, plaintext)
    assert result[:16] == expected, f"❌ Test {i} failed: got {result.hex()}, expected {expected.hex()}"
    print(f"✅ Test {i} passed. key={key_hex}")

print("🔑 Finished Variable Key Tests\n")