from .aes import key_expansion, aes_encrypt_block

def aes_ofb_encrypt(key, iv, plaintext):
    """

    Encrypts plaintext using AES-256 in OFB mode.

    Parameters:
    - key (bytes): 32-byte AES key.
    - iv (bytes): 16-byte initialization vector.
    - plaintext (bytes): Input data to encrypt.

    Returns:
    - bytes: Ciphertext output (same length as plaintext).
    """
  
  
    assert len(key) == 32, "AES-256 key must be 32 bytes"
    assert len(iv) == 16, "AES block size (IV) must be 16 bytes"

    w = key_expansion(key)      # Expand the AES-256 key into 60 round words
    ciphertext = bytearray()
    feedback = iv               # Start feedback chain with IV

    for i in range(0, len(plaintext), 16):
        # 1. Encrypt current feedback block to generate keystream
        keystream = aes_encrypt_block(feedback, w)

        # 2. Extract current plaintext block (can be less than 16 bytes at end)
        plaintext_block = plaintext[i : i + 16]

        # 3. XOR plaintext block with keystream
        cipher_block = bytes(
            b ^ k for b, k in zip(plaintext_block, keystream)
        )

        # 4. Append to ciphertext
        ciphertext.extend(cipher_block)

        # 5. Update feedback with current keystream
        feedback = keystream

    return bytes(ciphertext)

def aes_ofb_decrypt(key, iv, ciphertext):
    return aes_ofb_encrypt(key, iv, ciphertext) #OFB mode decryption is identical to encryption.
