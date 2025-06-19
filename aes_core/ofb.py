from .aes import key_expansion, aes_encrypt_block

def aes_ofb_encrypt(key, iv, plaintext):
    assert len(key) == 32
    assert len(iv) == 16

    w = key_expansion(key)
    ciphertext = bytearray()
    feedback = iv

    for i in range(0, len(plaintext), 16):
        stream_block = aes_encrypt_block(feedback, w)
        block = plaintext[i:i+16]
        xor_block = bytes([b ^ s for b, s in zip(block, stream_block[:len(block)])])
        ciphertext.extend(xor_block)
        feedback = stream_block

    return bytes(ciphertext)

def aes_ofb_decrypt(key, iv, ciphertext):
    return aes_ofb_encrypt(key, iv, ciphertext)
