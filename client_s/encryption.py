import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import os
import base64

# مفتاح AES ثابت (يجب تغييره ليكون أكثر أمانًا)
AES_KEY = b'ThisIsASecretKey'  # 16 bytes key (128-bit AES)

def encrypt_aes(data):
    iv = os.urandom(16)  # إنشاء IV عشوائي
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # إضافة الحشو
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    
    # التشفير
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # دمج IV مع النص المشفر
    return base64.b64encode(iv + ciphertext).decode()

# إعداد التسجيل (logging)
logging.basicConfig(level=logging.DEBUG)
def decrypt_aes(encrypted_data):
    try:
        encrypted_data = base64.b64decode(encrypted_data)
        iv = encrypted_data[:16]  # استخراج IV
        ciphertext = encrypted_data[16:]  # استخراج النص المشفر
        cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # فك التشفير
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # إزالة الحشو
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        

        return data.decode()
    except ValueError as e:
        logging.error(f"Error in decrypt_aes (ValueError): {e}")
        # logging.error(f"Encrypted data: {encrypted_data}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error in decrypt_aes: {e}")
        raise