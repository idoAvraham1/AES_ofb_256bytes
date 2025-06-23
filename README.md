# AES-OFB Mode Encryption Project

This project implements AES encryption in Output Feedback (OFB) mode. It supports testing against known test vectors and can encrypt or decrypt arbitrary text using OFB mode.

## Project Structure
---

aes_core/

├── aes.py # Core AES implementation

├── ofb.py # OFB mode wrapper around AES


tests/

├── test_var_key.py # Tests AES-OFB with varying keys

├── test_var_iv.py # Tests AES-OFB with varying IVs

├── tests_runner.py # Runs all tests


main.py # Encrypt/decrypt user-supplied input

---

## Usage

### Run All Tests
```bash
python -m tests.tests_runner
```

### Encrypt Input
```bash
python main.py -k <hex_key> -i <hex_iv> -p <plaintext>
```
### Decrypt Input
```bash
python main.py -k <hex_key> -i <hex_iv> -c <ciphertext>
```
---

## Example 

###  Encrypt Input
```bash
python main.py -k 0000000000000000000000000000000000000000000000000000000000000000 \
                             -i 80000000000000000000000000000000 \
                             -p 00000000000000000000000000000000
```
Output: 🔒 Encrypted: ddc6bf790c15760d8d9aeb6f9a75fd4e

###  Decrypt Input
```bash
python main.py -k 0000000000000000000000000000000000000000000000000000000000000000 \
                             -i 80000000000000000000000000000000 \
                             -c ddc6bf790c15760d8d9aeb6f9a75fd4e
```
Output:  🔓 Decrypted: 00000000000000000000000000000000

