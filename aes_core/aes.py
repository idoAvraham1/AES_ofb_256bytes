import struct
from .constants import s_box, rcon

def sub_word(word):
    return ((s_box[(word >> 24) & 0xFF] << 24) |
            (s_box[(word >> 16) & 0xFF] << 16) |
            (s_box[(word >> 8) & 0xFF] << 8) |
            s_box[word & 0xFF])

def rot_word(word):
    return ((word << 8) & 0xFFFFFFFF) | (word >> 24)

def key_expansion(key):
    Nk, Nb, Nr = 8, 4, 14
    w = [0] * (Nb * (Nr + 1))
    for i in range(Nk):
        w[i] = struct.unpack(">I", key[4*i: 4*(i+1)])[0]
    for i in range(Nk, Nb * (Nr + 1)):
        temp = w[i - 1]
        if i % Nk == 0:
            temp = sub_word(rot_word(temp)) ^ rcon[(i // Nk) - 1]
        elif i % Nk == 4:
            temp = sub_word(temp)
        w[i] = w[i - Nk] ^ temp
    return w

def sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = s_box[state[r][c]]

def shift_rows(state):
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]

def xtime(a):
    return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

def mix_single_column(a):
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)

def mix_columns(state):
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        mix_single_column(col)
        for r in range(4):
            state[r][c] = col[r]

def add_round_key(state, w, rnd):
    for c in range(4):
        word = w[rnd * 4 + c]
        for r in range(4):
            state[r][c] ^= (word >> (24 - r * 8)) & 0xFF

def aes_encrypt_block(block, w):
    state = [[0] * 4 for _ in range(4)]
    for i in range(16):
        state[i % 4][i // 4] = block[i]
    add_round_key(state, w, 0)
    for round in range(1, 14):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, w, round)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, w, 14)
    output = bytearray(16)
    for i in range(16):
        output[i] = state[i % 4][i // 4]
    return bytes(output)
