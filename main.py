import argparse
from aes_core.ofb import aes_ofb_encrypt

def parse_hex(input_str, name):
    try:
        
        if name == "plaintext" and len(input_str) % 2 != 0: # Allow odd length by padding with one 0
                input_str+="0"

        return bytes.fromhex(input_str)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid hex string for {name}: {input_str}")

def main():
    parser = argparse.ArgumentParser(description="AES-OFB Encrypt/Decrypt Tool")
    parser.add_argument('-k', '--key', required=True, type=lambda x: parse_hex(x, 'key'), help='Key in hex (32 bytes for AES-256)')
    parser.add_argument('-i', '--iv', required=True, type=lambda x: parse_hex(x, 'IV'), help='IV in hex (16 bytes)')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-p', '--plaintext', type=lambda x: parse_hex(x, 'plaintext'), help='Plaintext to encrypt (hex)')
    group.add_argument('-c', '--ciphertext', type=lambda x: parse_hex(x, 'ciphertext'), help='Ciphertext to decrypt (hex)')

    args = parser.parse_args()

    text = args.plaintext or args.ciphertext
    result = aes_ofb_encrypt(args.key, args.iv, text)

    if args.plaintext:
        print("🔒 Encrypted:", result.hex())
    else:
        print("🔓 Decrypted:", result.hex())

if __name__ == '__main__':
    main()
    
    
    
# Usage:    
# python main.py -k 0000000000000000000000000000000000000000000000000000000000000000 -i 80000000000000000000000000000000 -p  00000000000000000000000000000000
# 🔒 Encrypted: ddc6bf790c15760d8d9aeb6f9a75fd4e


# python main.py -k 0000000000000000000000000000000000000000000000000000000000000000 -i 80000000000000000000000000000000 -c ddc6bf790c15760d8d9aeb6f9a75fd4e
# 🔓 Decrypted: 00000000000000000000000000000000