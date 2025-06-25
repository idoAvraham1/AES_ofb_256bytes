import struct
from .constants import s_box, rcon


############ AES UTILS ############
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
    For example, [B8, BA, C7, 49] -> [BA, C7, 49, B8].
    """
    return ((word << 8) & 0xFFFFFFFF) | (word >> 24)


def xtime(a):
    """
    Multiply by 2 in GF(2^8):
    - If the MSB of 'a' is 0, use (a << 1)
    - If the MSB is 1, reduce with (a << 1) ^ 0x1B (mod 0x11B)
    - & 0xFF keeps the result within 8 bits
    """
    return (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)


def mix_single_column(a):
    """
    Perform MixColumns on a single column of the AES state.

    This computes the matrix multiplication:
        [2 3 1 1]
        [1 2 3 1] * a  (in GF(2^8))
        [1 1 2 3]
        [3 1 1 2]

    Optimized using:
    - 3·x = 2·x ⊕ x = xtime(x) ^ x
    - Shared term t = a0 ^ a1 ^ a2 ^ a3  

    Example: row 0 computes 2·a0 ⊕ 3·a1 ⊕ a2 ⊕ a3
      = 2·a0 ⊕ (2·a1 ⊕ a1) ⊕ a2 ⊕ a3
      = a0 ⊕ a1 ⊕ a2 ⊕ a3 ⊕ 2·(a0 ⊕ a1)
      = t ⊕ xtime(a0 ⊕ a1)
    """
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)


############ AES STEPS ############
def key_expansion(key):
    """
    Expand a 256-bit AES key into a full key schedule for all encryption rounds.
    For details, see: https://en.wikipedia.org/wiki/AES_key_schedule
    
    - AES-256 parameters:
      - Nk = 8  (number of 32-bit words in the key)
      - Nb = 4  (number of columns in the state)
      - Nr = 14 (number of rounds)

    - Output:
      - 60 words (4 bytes each), forming 15 round keys (initial + 14 rounds)
      - Round keys are generated using:
        - rot_word: rotates a 32-bit word left by 1 byte
        - sub_word: applies S-box substitution to each byte
        - rcon: round constant added to introduce non-linearity
    """
    Nk, Nb, Nr = 8, 4, 14  # AES-256: key has 8 words, state has 4 columns, 14 rounds total
    w = [0] * (Nb * (Nr + 1))  # Final key schedule will contain 4*(Nr+1) = 60 words

    # Step 1: Copy the original key into the first Nk words of w
    for i in range(Nk):
        w[i] = struct.unpack(">I", key[4*i: 4*(i+1)])[0]  # Read 4 bytes as big-endian 32-bit word

    # Step 2: Generate the remaining words
    for i in range(Nk, Nb * (Nr + 1)):
        temp = w[i - 1]

        if i % Nk == 0:
            # Every Nk words, apply the key schedule core:
            # 1. Rotate the previous word (rot_word)
            # 2. Apply S-box substitution (sub_word)
            # 3. XOR with round constant 
            temp = sub_word(rot_word(temp)) ^ rcon[(i // Nk) - 1]

        elif i % Nk == 4:
            # For AES-256, every 4th word (but not multiple of Nk), also apply S-box
            temp = sub_word(temp)

        # XOR with the word Nk positions earlier to produce the next word
        w[i] = w[i - Nk] ^ temp

    return w



def add_round_key(state, w, rnd):
    """
    XOR the state with the round key for round `rnd`.
    Each round key consists of 4 words (16 bytes), applied column-wise to the state.
    """
    for c in range(4):
        word = w[rnd * 4 + c]  # c-th word of the rnd-th round key 
        # Break the 32-bit word into 4 bytes
        bytes_ = [
            (word >> 24) & 0xFF,  # top byte
            (word >> 16) & 0xFF,
            (word >> 8)  & 0xFF,
            word & 0xFF           # bottom byte
        ]
        # XOR each byte into the corresponding row of this column
        for r in range(4):
            state[r][c] ^= bytes_[r]


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
    Row 1: shift left by 1 // [a,b,c,d] -> [b,c,d,a]
    Row 2: shift left by 2 // [a,b,c,d] -> [c,d,a,b]
    Row 3: shift left by 3 // [a,b,c,d] -> [d,a,b,c] 
    """
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]

    
def mix_columns(state):
    """
    Apply MixColumns to each column of the state.
    """
    for c in range(4):
        # Extract the c-th column (as a list of 4 bytes)
        col = [state[r][c] for r in range(4)]
        
        mix_single_column(col)
        
        # Write back the transformed column into the state
        for r in range(4):
            state[r][c] = col[r]

    
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
        sub_bytes(state)   
        shift_rows(state)  
        mix_columns(state) 
        add_round_key(state, w, round)  

    # Final round (no MixColumns)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, w, 14)

    # Convert state matrix back to bytes
    output = bytearray(16)
    for i in range(16):
        output[i] = state[i % 4][i // 4]

    return bytes(output)

