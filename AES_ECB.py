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
