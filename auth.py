import bcrypt
from db import fetch_user_password

def hash_password(plaintext):
    plaintext_bytes = plaintext.encode("utf-8")
    hashed = bcrypt.hashpw(plaintext_bytes,bcrypt.gensalt())

    return hashed

def verify_password(username,plaintext):
    plaintext_byte = plaintext.encode("utf-8")
    existing_passwd = fetch_user_password(username)
    if existing_passwd:
        return False
    
    return bcrypt.checkpw(plaintext_byte,existing_passwd)
    
