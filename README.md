# DevOps Engineer Assessment Task - Solution for Task 1 (Treasure Hunt)

## Objective
The objective of Task 1 was to decode an encrypted message, provided as a Base64-encoded string, and document the process. The clues hinted at using AES encryption with specific parameters.

## Initial Clue Analysis
The clue provided was a Base64 string:

"YWVzKGRhdGEse3JvdmVybmFtZXllYXJ9KTtkOGI4YTA1NjNmMGNlOTU5MGY5MzBmYjhmZDZhZWY5OTgyMGIxMWRhYjQxZjQ1OWFhOTg0MTQ2MjlhMzRlZjY1ODgyZGVjYWViZThhMzQ5NjliZDNiMzdkZjFhMzEyOTA0YTJkNDhjMGY1MzM4ZDZhNzZhYTIyMThhNzZhODZjYmJjNjY5NDRhYmU3N2Y5NGVjNzZmMGZmNGY3YThkZjhhZWI0MzFhYzRmMTI1M2U1YWUwODM4NjNjNjQzZWE5OGIyZmE1MzFjZTU3M2FiYTg2OTZiZmY1MjE4NmIxNjE4MDJhNDg0OTM0NmUwNzFlM2FhMzJhYzRlNjI1NmFiOTZkNDBiOTdmZTE5ZDY2OGYxMzIyNDdhYjRlOGRmZDM5MjU2OTUwODliOTI2ZTgwZTcxNjkyMTM1ODRhZjJkNWNkZmViMmVjYjA1MjIwNDVmMDk0OGQ4YWZmYjI1YTk4MDAw"

## Steps Taken to Solve the Clue

### Step 1: Decoding Base64
The first step was to decode the provided Base64 string. After decoding, it resulted in unreadable output, which appeared to be AES-encrypted data. This suggested that further decryption was needed with the correct encryption key and mode.

### Step 2: Analyzing Encryption Details
Hints suggested that the encryption used was AES, possibly with ECB or CBC mode, and that the key was derived from the rover name and its launch year. Potential Mars rovers included:
- **Sojourner (1997)**
- **Spirit (2004–2010)**
- **Opportunity (2004–2018)**
- **Curiosity (2012–present)**
- **Perseverance (2021–present)**

### Step 3: Attempted Decryption Approaches

#### 1. **AES with ECB Mode and SHA-256 Hashing**
   - Key Format: `data,{rovername}{year}`
   - Hashing Method: SHA-256

Here’s the code used for this attempt:

```python
from Crypto.Cipher import AES
import base64
import hashlib

# Base64-encoded string with padding correction
encoded_data = "d8b8a0563f0ce9590f930fb8fd6aef99820b11dab41f459aa98414629a34ef65882decaaebe8a34969bd3b37df1a312904a2d48c0f5338d6a76aa2218a76a86cbbc66944abe77f94ec76f0ff4f7a8df8aeb431ac4f1253e5ae083863c643ea98b2fa531ce573aba8696bff52186b161802a4849346e071e3aa32ac4e6256ab96d40b97fe19d668f132247ab4e8dfd3925695089b926e80e7169213584af2d5cdfe..."
while len(encoded_data) % 4 != 0:
    encoded_data += "="  # Ensure correct Base64 padding

# Decode the Base64 string
encrypted_data = base64.b64decode(encoded_data)

# Ensure data is aligned to 16 bytes (AES block size)
if len(encrypted_data) % 16 != 0:
    encrypted_data = encrypted_data[:len(encrypted_data) - (len(encrypted_data) % 16)]

# Rover names and years
rovers = {
    "Sojourner": ["1997"],
    "Spirit": ["2004", "2010"],
    "Opportunity": ["2004", "2018"],
    "Curiosity": ["2012"],
    "Perseverance": ["2021"]
}

def decrypt_aes(encrypted_data, rover_name, year):
    key = f"data,{rover_name}{year}".encode()  # Create key from rover name and year
    key = hashlib.sha256(key).digest()  # Hash key with SHA-256

    cipher = AES.new(key, AES.MODE_ECB)  # Create AES cipher in ECB mode
    decrypted_data = cipher.decrypt(encrypted_data)  # Attempt decryption

    try:
        return decrypted_data.decode('utf-8')  # Return decrypted text if readable
    except UnicodeDecodeError:
        return None  # Return None if decoding fails

for rover, years in rovers.items():
    for year in years:
        result = decrypt_aes(encrypted_data, rover, year)
        if result:
            print(f"Decrypted data with rover '{rover}' and year '{year}':\n{result}")
            break
        else:
            print(f"Failed with rover '{rover}' and year '{year}'")  # Log failed attempts
```
#### 2. **AES with CBC Mode, Zeroed IV, MD5 Hashing, and PKCS7 Padding**
   - Mode: AES CBC Mode with an IV of all zeros
   - Key Format Variants:
     - `data,{rovername}{year}`
     - `{rovername},{year}`
     - `data-{rovername}-{year}`
   - Hashing Method: MD5
   - Padding: PKCS7 Unpadding

```python
from Crypto.Cipher import AES
import base64
import hashlib
from Crypto.Util.Padding import unpad

# Base64-encoded string with padding correction
encoded_data = "d8b8a0563f0ce9590f930fb8fd6aef99820b11dab41f459aa98414629a34ef65882decaaebe8a34969bd3b37df1a312904a2d48c0f5338d6a76aa2218a76a86cbbc66944abe77f94ec76f0ff4f7a8df8aeb431ac4f1253e5ae083863c643ea98b2fa531ce573aba8696bff52186b161802a4849346e071e3aa32ac4e6256ab96d40b97fe19d668f132247ab4e8dfd3925695089b926e80e7169213584af2d5cdfe..."
while len(encoded_data) % 4 != 0:
    encoded_data += "="  # Ensure correct Base64 padding

# Decode the Base64 string
encrypted_data = base64.b64decode(encoded_data)

# Ensure data alignment to 16 bytes (AES block size)
if len(encrypted_data) % 16 != 0:
    encrypted_data = encrypted_data[:len(encrypted_data) - (len(encrypted_data) % 16)]

# Rover names and years
rovers = {
    "Sojourner": ["1997"],
    "Spirit": ["2004", "2010"],
    "Opportunity": ["2004", "2018"],
    "Curiosity": ["2012", "2024"],
    "Perseverance": ["2021", "2024"]
}

def decrypt_aes_cbc_md5(encrypted_data, rover_name, year):
    key_variants = [
        f"data,{rover_name}{year}",
        f"{rover_name},{year}",
        f"data-{rover_name}-{year}"
    ]
    iv = b'\x00' * 16  # Default IV of all zeros

    for key_str in key_variants:
        key = hashlib.md5(key_str.encode()).digest()  # Create key with MD5
        cipher = AES.new(key, AES.MODE_CBC, iv)  # Initialize AES CBC mode cipher
        
        try:
            decrypted_data = cipher.decrypt(encrypted_data)  # Decrypt data
            decrypted_data = unpad(decrypted_data, AES.block_size, style='pkcs7')  # PKCS7 unpadding
            return decrypted_data.decode('utf-8')
        except (UnicodeDecodeError, ValueError):
            continue  # Move to the next key variant if decryption fails

for rover, years in rovers.items():
    for year in years:
        result = decrypt_aes_cbc_md5(encrypted_data, rover, year)
        if result:
            print(f"Decrypted data with rover '{rover}' and year '{year}':\n{result}")
            break
        else:
            print(f"Failed with rover '{rover}' and year '{year}'")  # Log failed attempts
```
