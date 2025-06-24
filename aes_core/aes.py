import struct
from .constants import s_box, rcon

def sub_word(word):
    """
    Apply S-box substitution on a 4-byte word.
    Each byte of the input word is substituted using the AES S-box.
    """
    return ((s_box[(word >> 24) & 0xFF] << 24) |
            (s_box[(word >> 16) & 0xFF] << 16) |
            (s_box[(word >> 8) & 0xFF] << 8) |
            s_box[word & 0xFF])

def rot_word(word):
    """
    Rotate 4-byte word left by 8 bits (1 byte).
    For example, 0x12345678 becomes 0x34567812.
    """
    return ((word << 8) & 0xFFFFFFFF) | (word >> 24)

def key_expansion(key):
    """
    Expand the original 256-bit key into a key schedule for all AES rounds.

    - AES-256: Nk=8 (8 32-bit words), Nb=4 (4 columns per state), Nr=14 (14 rounds)
    - Output: 60 words (each 4 bytes) → enough for 15 round keys (14 + initial)

    Key schedule generation rules:
    - For every word w[i]:
        - If i % Nk == 0: apply rot_word + sub_word + rcon
        - If i % Nk == 4: apply sub_word only
        - Otherwise: XOR previous word with word Nk places before
    """
    Nk, Nb, Nr = 8, 4, 14 # 256-bit key, 4 columns per state, 14 rounds
    w = [0] * (Nb * (Nr + 1))  # total 60 words
    for i in range(Nk):
        w[i] = struct.unpack(">I", key[4*i: 4*(i+1)])[0]  # Read key as big-endian 32-bit words
    for i in range(Nk, Nb * (Nr + 1)):
        temp = w[i - 1]
        if i % Nk == 0:
            # Apply core key expansion operation (with rotation and substitution)
            temp = sub_word(rot_word(temp)) ^ rcon[(i // Nk) - 1]
        elif i % Nk == 4:
            # Apply sub_word every 4 steps (special case)
            temp = sub_word(temp)
        w[i] = w[i - Nk] ^ temp
    return w


def sub_bytes(state):
    """
    Substitute each byte in the state with its S-box value.
    """
    for r in range(4):
        for c in range(4):
            state[r][c] = s_box[state[r][c]]

def shift_rows(state):
    """
    Left-rotate rows of the state:
    Row 0: no shift
    Row 1: shift left by 1
    Row 2: shift left by 2
    Row 3: shift left by 3
    """
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]

def xtime(a):
    """
    Multiply by 2 in GF(2^8). If MSB is 1, reduce using the AES polynomial.
    """
    return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

def mix_single_column(a):
    """
    Mix one column using the MixColumns transformation.
    a is a list of 4 bytes (one column).
    """
    # t = XOR of all 4 bytes (used in multiple places)
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    # u = copy of first byte (used in transformation)
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)

def mix_columns(state):
    """
    Apply MixColumns to each column of the state.
    """
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        mix_single_column(col)
        for r in range(4):
            state[r][c] = col[r]

def add_round_key(state, w, rnd):
    """
    XOR the state with the round key for round `rnd`.
    `w` is the expanded key (list of 4-byte words).
    """
    for c in range(4):
        # Extract the word for the current column in this round
        # Apply byte-wise XOR between the word and the column
        word = w[rnd * 4 + c]
        for r in range(4):
            state[r][c] ^= (word >> (24 - r * 8)) & 0xFF

def aes_encrypt_block(block, w):
    """
    Encrypt a single 16-byte block using AES-256 and the expanded key `w`.
    Returns the encrypted 16-byte ciphertext.
    """
    # Convert 16-byte input block into 4x4 state matrix (column-major)
    state = [[0] * 4 for _ in range(4)]
    for i in range(16):
        state[i % 4][i // 4] = block[i]

    # Initial AddRoundKey
    add_round_key(state, w, 0)

    # 13 full rounds
    for round in range(1, 14):
        sub_bytes(state)   # Non-linear substitution
        shift_rows(state)  # Row-wise permutation
        mix_columns(state) # Column diffusion (except in last round)
        add_round_key(state, w, round)  # XOR with round key

    # Final round (no MixColumns)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, w, 14)

    # Convert state matrix back to bytes
    output = bytearray(16)
    for i in range(16):
        output[i] = state[i % 4][i // 4]

    return bytes(output)

