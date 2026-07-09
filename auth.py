import bcrypt
from db import fetch_user

def hash_password(plaintext):
    plaintext_bytes = plaintext.encode("utf-8")
    hashed = bcrypt.hashpw(plaintext_bytes,bcrypt.gensalt())

    return hashed

def verify_password(plaintext,hashed_password):
    if not plaintext or hashed_password:
        return False
    
    plaintext_byte = plaintext.encode("utf-8")
    hashed_password_byte = hashed_password.encode("utf-8")
   
    
    return bcrypt.checkpw(plaintext_byte,hashed_password_byte)
    

