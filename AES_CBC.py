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
