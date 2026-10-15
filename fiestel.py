# Educational block cipher: 128-bit Feistel network with AES S-box, ECB mode,
# PKCS#7 padding, Base64 output. NOT for real-world security.
 
import base64
import binascii
 
# AES S-box (FIPS 197, Sec. 5.1.1)
S_BOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]
 
ROUNDS = 12
BLOCK_SIZE = 16
HALF = 8
 
 
def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))
 
 
def substitute(data):
    return bytes(S_BOX[x] for x in data)
 
 
def permute_half(data):
    return data[3:] + data[:3]
 
 
# Feistel round function: key XOR -> S-box -> byte permutation.
def F(half, subkey):
    x = xor_bytes(half, subkey)
    x = substitute(x)
    x = permute_half(x)
    return x
 
 
# Key schedule (custom): rotate, S-box, XOR with round number.
def generate_round_keys(key):
    if len(key) != BLOCK_SIZE:
        raise ValueError("Key must be exactly 16 bytes")
    keys = []
    current = xor_bytes(key[:HALF], key[HALF:])
    for round_number in range(1, ROUNDS + 1):
        rotated = current[1:] + current[:1]
        transformed = bytearray(substitute(rotated))
        transformed[0] ^= round_number
        current = bytes(transformed)
        keys.append(current)
    return keys
 
 
# Feistel network on one block: L, R = R, L xor F(R, K_i); halves swapped at the end.
def encrypt_block(block, round_keys):
    L, R = block[:HALF], block[HALF:]
    for i in range(ROUNDS):
        L, R = R, xor_bytes(L, F(R, round_keys[i]))
    return R + L
 
 
# Decryption: same network, round keys in reverse order.
def decrypt_block(block, round_keys):
    A, B = block[:HALF], block[HALF:]
    for i in reversed(range(ROUNDS)):
        A, B = B, xor_bytes(A, F(B, round_keys[i]))
    return B + A
 
 
# PKCS#7 padding (RFC 5652, Sec. 6.3).
def pad(data):
    amount = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([amount]) * amount
 
 
def unpad(data):
    if not data:
        raise ValueError("Invalid padding")
    amount = data[-1]
    if amount < 1 or amount > BLOCK_SIZE or amount > len(data):
        raise ValueError("Invalid padding")
    if data[-amount:] != bytes([amount]) * amount:
        raise ValueError("Invalid padding")
    return data[:-amount]
 
 
# ECB mode: every 16-byte block is encrypted independently. Output is Base64.
def encrypt_message(message, key):
    round_keys = generate_round_keys(key)
    message = pad(message)
    encrypted = bytearray()
 
    for i in range(0, len(message), BLOCK_SIZE):
        encrypted.extend(encrypt_block(message[i:i + BLOCK_SIZE], round_keys))
 
    return base64.b64encode(bytes(encrypted)).decode()
 
 
def decrypt_message(encoded_message, key):
    try:
        raw = base64.b64decode(encoded_message.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("Input is not valid Base64")
 
    if len(raw) == 0 or len(raw) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length must be a non-zero multiple of 16 bytes")
 
    round_keys = generate_round_keys(key)
    decrypted = bytearray()
 
    for i in range(0, len(raw), BLOCK_SIZE):
        decrypted.extend(decrypt_block(raw[i:i + BLOCK_SIZE], round_keys))
 
    try:
        return unpad(bytes(decrypted)).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        raise ValueError("Wrong key or corrupted data")
 
 
def get_key():
    while True:
        key = input("Enter a key (exactly 16 bytes, ASCII recommended): ").encode("utf-8")
        if len(key) == BLOCK_SIZE:
            return key
        print(f"The key is {len(key)} bytes long, but must be exactly 16. "
              "Note: non-ASCII characters take 2+ bytes each.")
 
 
def main():
    while True:
        print("\n1. Encrypt")
        print("2. Decrypt")
        print("3. Exit")
        choice = input("Choose an option: ").strip()
 
        if choice == "1":
            key = get_key()
            message = input("Enter plaintext: ").encode("utf-8")
            print("\nEncrypted text:")
            print(encrypt_message(message, key))
 
        elif choice == "2":
            key = get_key()
            encrypted = input("Enter encrypted text: ")
            try:
                print("\nDecrypted text:")
                print(decrypt_message(encrypted, key))
            except ValueError as e:
                print(f"Decryption failed: {e}")
 
        elif choice == "3":
            break
 
        else:
            print("Invalid option.")
 
 
if __name__ == "__main__":
    main()
