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

    Notes:
    - OFB mode turns AES into a stream cipher.
    - The IV is encrypted to produce a keystream block.
    - That keystream is XORed with plaintext.
    - Feedback is updated with the encrypted output (not ciphertext).
    """
    assert len(key) == 32, "AES-256 key must be 32 bytes"
    assert len(iv) == 16, "AES block size (IV) must be 16 bytes"

    w = key_expansion(key)      # Generate expanded round keys
    ciphertext = bytearray()
    feedback = iv               # Initialize feedback with IV

    for i in range(0, len(plaintext), 16):
        stream_block = aes_encrypt_block(feedback, w)         # Encrypt feedback
        block = plaintext[i:i+16]                             # Get 16-byte chunk
        xor_block = bytes([b ^ s for b, s in zip(block, stream_block[:len(block)])])
        ciphertext.extend(xor_block)
        feedback = stream_block                               # Update feedback

    return bytes(ciphertext)



def aes_ofb_decrypt(key, iv, ciphertext):
    return aes_ofb_encrypt(key, iv, ciphertext) #OFB mode decryption is identical to encryption.
