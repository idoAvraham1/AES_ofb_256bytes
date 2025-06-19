from aes_core.ofb import aes_ofb_encrypt

print("🔑 Starting Variable Key Tests...\n")

# Static test vector (plaintext and IV are the same in all tests)
plaintext = bytes.fromhex("00000000000000000000000000000000")
iv = bytes.fromhex("00000000000000000000000000000000")

# Test cases: (key_hex, expected_ciphertext_hex)
test_vectors = [
    ("8000000000000000000000000000000000000000000000000000000000000000", "e35a6dcb19b201a01ebcfa8aa22b5759"),
    ("fe00000000000000000000000000000000000000000000000000000000000000", "60e32246bed2b0e859e55c1cc6b26502"),
    ("ffc0000000000000000000000000000000000000000000000000000000000000", "a3f599d63a82a968c33fe26590745970"),
    ("fffc000000000000000000000000000000000000000000000000000000000000", "4dcede8da9e2578f39703d4433dc6459"),
]

# Run and validate each test
for i, (key_hex, expected_cipher_hex) in enumerate(test_vectors, start=1):
    key = bytes.fromhex(key_hex)
    expected = bytes.fromhex(expected_cipher_hex)
    result = aes_ofb_encrypt(key, iv, plaintext)
    assert result[:16] == expected, f"❌ Test {i} failed: got {result.hex()}, expected {expected.hex()}"
    print(f"✅ Test {i} passed. key={key_hex}")

print("🔑 Finished Variable Key Tests\n")