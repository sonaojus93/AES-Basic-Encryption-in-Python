# Project 2


# AES S-box and Rcon
s_box = [
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
]

Rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

divider= "-----------------------------------------------------------------------------------"

############################################################################
# Helper functions
def to_matrix(bytes_list):
    return [[bytes_list[row + 4 * col] for col in range(4)] for row in range(4)]

def from_matrix(matrix):
    return [matrix[row][col] for col in range(4) for row in range(4)]

def sub_bytes(state,aes_s_box):
    return [[aes_s_box[b] for b in row] for row in state]

def print_state(state,label):
    ciphertext = from_matrix(state)
    print(f"{label}: {' '.join(f'{b:02x}' for b in ciphertext)}")

############################################################################
# Generate the Modified S_Box based on Group Code
def modified_sbox(group_a, group_b):
    modified = s_box.copy()
    row_a_start, row_b_start = group_a * 16, group_b * 16
    modified[row_a_start:row_a_start + 16], modified[row_b_start:row_b_start + 16] = modified[row_b_start:row_b_start + 16], modified[row_a_start:row_a_start + 16]
    return modified

# Create modified S-box for group code (4, 8)
modified_s_box = modified_sbox(4, 8)

#############. AES KEY SCHEDULER. #####################################
def key_schedule(key,aes_s_box):
    w = [key[i:i+4] for i in range(0, 16, 4)]
    for i in range(10):
        temp = w[-1][1:] + w[-1][:1]
        temp = [aes_s_box[b] for b in temp]
        temp[0] ^= Rcon[i]
        w.append([a ^ b for a, b in zip(w[-4], temp)])
        for _ in range(3):
            w.append([a ^ b for a, b in zip(w[-4], w[-1])])

    round_keys = []
    for i in range(11):
        round_key_flat = sum(w[4*i : 4*(i+1)], [])
        # Explicitly format keys in column-major order
        round_keys.append([round_key_flat[row + 4 * col] for col in range(4) for row in range(4)])

    # Display round keys in straight line format
    print("2. Round Keys Generated:")
    print(divider)
    for i, rk in enumerate(round_keys):
        print(f"Round {i} Key: {' '.join(f'{b:02x}' for b in rk)}")
    print(divider)

    return round_keys

#############. AES ADD ROUND KEY STEP. ###############################
def add_round_key(state, key_flat):
    key_matrix = to_matrix(key_flat)
    return [[state[r][c] ^ key_matrix[r][c] for c in range(4)] for r in range(4)]

#############. AES SHIFT ROW STEP. ###################################
def shift_rows(state):
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]
    return state

#############. AES MIXCOLUMNS STEP. ###################################
def gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        high_bit_set = a & 0x80
        a <<= 1
        a &= 0xFF
        if high_bit_set:
            a ^= 0x1B
        b >>= 1
    return p

def mix_single_column(column):
    return [
        gmul(column[0], 2) ^ gmul(column[1], 3) ^ column[2] ^ column[3],
        column[0] ^ gmul(column[1], 2) ^ gmul(column[2], 3) ^ column[3],
        column[0] ^ column[1] ^ gmul(column[2], 2) ^ gmul(column[3], 3),
        gmul(column[0], 3) ^ column[1] ^ column[2] ^ gmul(column[3], 2)
    ]

def mix_columns(state):
    mixed = [[0]*4 for _ in range(4)]
    for i in range(4):
        col = [state[row][i] for row in range(4)]
        mixed_col = mix_single_column(col)
        for row in range(4):
            mixed[row][i] = mixed_col[row]
    return mixed

def aes_encryption(plaintext, key, s_box):
    state = to_matrix(plaintext)
    round_keys = key_schedule(key, s_box)

    # AES Rounds
    print("3. Data output rounds:")
    print(divider)
    state = add_round_key(state, round_keys[0])
    print_state(state, "Add Round Key(Original Key): ")
    print(divider)

    for rnd in range(1, 11):
        state = sub_bytes(state,s_box)
        state = shift_rows(state)
        if rnd != 10:
            state = mix_columns(state)
        state = add_round_key(state, round_keys[rnd])
        print_state(state, f"Round {rnd}")


    print(divider)
    ciphertext = from_matrix(state)
    print(f"Final ciphertext: {' '.join(f'{b:02x}' for b in ciphertext)}")
    print(divider)


def main():
  # ======================================================================
  # STANDARD AES ENCRYPTION
  plaintext_ori = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
              0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
  key_ori = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]

  print("\n\nStandard AES Encryption using Example Plaintext and Key:")
  print(divider)
  print("1. Original Plaintext and Key:")
  print(divider)
  print_state(to_matrix(plaintext_ori), "Plaintext")
  print_state(to_matrix(key_ori), "Key")
  print(divider)

  aes_encryption(plaintext_ori,key_ori,s_box)

  # ======================================================================
  # MODIFIED AES ENCRYPTION
  plaintext_grp = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xab, 0xe1]
  key_grp = [0x1a, 0x0c, 0x24, 0xf2, 0x87, 0x54, 0x95, 0xbc,
        0xb7, 0x08, 0x0e, 0x43, 0x92, 0x0f, 0x56, 0x91]

  print("\n\nModified AES Encryption using Example Plaintext and Key:")
  print(divider)
  # Now perform modified AES
  print("1. Swap S-box rows 4 and 8 to create the modified S-box")
  print(divider)
  print("2. Group Plaintext and Key:")
  print(divider)
  print_state(to_matrix(plaintext_grp), "Plaintext")
  print_state(to_matrix(key_grp), "Key")
  print(divider)

  aes_encryption(plaintext_grp,key_grp,modified_s_box)

if __name__ == "__main__":
    main()


