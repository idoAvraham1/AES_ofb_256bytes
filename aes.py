import copy
import struct

# # AES S-box used for SubBytes transformation (non-linear substitution)
s_box = [
    # 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,  # 0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,  # 1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,  # 2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,  # 3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,  # 4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,  # 5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,  # 6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,  # 7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,  # 8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,  # 9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,  # A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,  # B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,  # C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,  # D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,  # E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16   # F
]

# Round constants for key expansion (used in AES key schedule)
rcon = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1b000000, 0x36000000
]

# Applies S-box substitution to a 32-bit word (used in key expansion)
def sub_word(word):
    return ((s_box[(word >> 24) & 0xFF] << 24) |
            (s_box[(word >> 16) & 0xFF] << 16) |
            (s_box[(word >> 8) & 0xFF] << 8) |
            s_box[word & 0xFF])

# Rotates a 32-bit word left by one byte (used in key expansion)
def rot_word(word):
    return ((word << 8) & 0xFFFFFFFF) | (word >> 24)

# Expands 256-bit key into round keys (AES-256 has 14 rounds)
def key_expansion(key):
    Nk, Nb, Nr = 8, 4, 14  # Nk: key words, Nb: block words, Nr: rounds
    w = [0] * (Nb * (Nr + 1))  # total number of 32-bit round keys

    # Load initial key into w[0..Nk-1]
    for i in range(Nk):
        w[i] = struct.unpack(">I", key[4*i : 4*(i+1)])[0]

    # Generate the rest of the keys
    for i in range(Nk, Nb * (Nr + 1)):
        temp = w[i - 1]
        if i % Nk == 0:
            temp = sub_word(rot_word(temp)) ^ rcon[(i // Nk) - 1]
        elif i % Nk == 4:
            temp = sub_word(temp)
        w[i] = w[i - Nk] ^ temp
    return w

# Applies S-box substitution to each byte in the state
def sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = s_box[state[r][c]]

# Shifts the rows of the state matrix (AES ShiftRows)
def shift_rows(state):
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]

# Multiplies by x in GF(2^8)
def xtime(a):
    return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

# MixColumns step for a single column (Galois field matrix multiplication)
def mix_single_column(a):
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)

# Applies MixColumns transformation to all columns in the state
def mix_columns(state):
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        mix_single_column(col)
        for r in range(4):
            state[r][c] = col[r]

# XORs the round key with the state matrix
def add_round_key(state, w, rnd):
    for c in range(4):
        word = w[rnd * 4 + c]
        for r in range(4):
            state[r][c] ^= (word >> (24 - r * 8)) & 0xFF

# AES block encryption: 128-bit block, 256-bit key, 14 rounds
def aes_encrypt_block(block, w):
    state = [[0] * 4 for _ in range(4)]

    # Initialize state matrix from input block (column-major order)
    for i in range(16):
        state[i % 4][i // 4] = block[i]

    # Initial round key addition
    add_round_key(state, w, 0)

    # Rounds 1 to 13
    for round in range(1, 14):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, w, round)

    # Final round (no MixColumns)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, w, 14)

    # Convert state matrix back to byte array (column-major)
    output = bytearray(16)
    for i in range(16):
        output[i] = state[i % 4][i // 4]
    return bytes(output)

# AES-256 encryption in OFB (Output Feedback) mode
def aes_ofb_encrypt(key, iv, plaintext):
    assert len(key) == 32  # 256-bit key
    assert len(iv) == 16   # 128-bit IV (block size)

    w = key_expansion(key)  # Generate round keys
    ciphertext = bytearray()
    feedback = iv  # OFB feedback starts with IV

    # Encrypt in blocks of 16 bytes
    for i in range(0, len(plaintext), 16):
        stream_block = aes_encrypt_block(feedback, w)  # Encrypt feedback to get keystream
        block = plaintext[i:i+16]  # Current plaintext block
        xor_block = bytes([b ^ s for b, s in zip(block, stream_block[:len(block)])])  # XOR plaintext with keystream
        ciphertext.extend(xor_block)
        feedback = stream_block  # Update feedback for next block

    return bytes(ciphertext)

# AES-256 decryption in OFB mode (same as encryption)
def aes_ofb_decrypt(key, iv, ciphertext):
    return aes_ofb_encrypt(key, iv, ciphertext)
   