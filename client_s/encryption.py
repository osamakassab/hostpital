import logging
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import os
import base64

# مفتاح AES ثابت (يجب تغييره ليكون أكثر أمانًا)
AES_KEY = b'ThisIsASecretKey'  # 16 bytes key (128-bit AES)



def encrypt_with_key(data, public_key_pem: str) -> str:
    """
    تشفير البيانات باستخدام المفتاح العام (RSA).
    
    :param data: البيانات المراد تشفيرها (نص).
    :param public_key_pem: المفتاح العام بتنسيق PEM.
    :return: البيانات المشفرة (base64).
    """
    try:
        # تحويل البيانات إلى بايت إذا كانت نصًا
        if isinstance(data, str):
            data = data.encode()  # تحويل النص إلى بايت

        # تحميل المفتاح العام
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),  # تحويل المفتاح إلى بايت
            backend=default_backend()
        )
        
        # تشفير البيانات
        encrypted_data = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # تحويل إلى base64
        return base64.b64encode(encrypted_data).decode()
    except Exception as e:
        print(f"Error encrypting data: {e}")
        raise


def encrypt_with_AES(data, public_key_pem: str) -> str:
        iv = os.urandom(16)  # إنشاء IV عشوائي
        cipher = Cipher(algorithms.AES(public_key_pem), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # إضافة الحشو
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data.encode()) + padder.finalize()
        
        # التشفير
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # دمج IV مع النص المشفر
        return base64.b64encode(iv + ciphertext).decode()
        
def decrypt_session_key(encrypted_data,sesion_key):
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:16]  # استخراج IV
    ciphertext = encrypted_data[16:]  # استخراج النص المشفر
    
    cipher = Cipher(algorithms.AES(sesion_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # فك التشفير
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # إزالة الحشو
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode()

def decrypt_with_RSA(encrypted_data, private_key_pem) -> bytes:
    """
    فك تشفير البيانات باستخدام المفتاح الخاص (RSA).
    
    :param encrypted_data: البيانات المشفرة (base64).
    :param private_key_pem: المفتاح الخاص بتنسيق PEM.
    :return: البيانات المفكوكة (نص).
    """
    try:
        # تحميل المفتاح الخاص
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),  # تحويل المفتاح إلى بايت
            password=None,  # إذا كان المفتاح محميًا بكلمة مرور، قم بتمريرها هنا
            backend=default_backend()
        )
        
        # فك تشفير البيانات
        decrypted_data = private_key.decrypt(
            base64.b64decode(encrypted_data),  # تحويل البيانات من base64 إلى بايت
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # تحويل البايت إلى نص
        return decrypted_data.decode()
    except Exception as e:
        print(f"Error decrypting data: {e}")
        raise


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
    """
    فك تشفير البيانات باستخدام AES.
    
    :param encrypted_data: البيانات المشفرة (str) بتنسيق base64.
    :return: البيانات المفكوكة (بايت).
    """
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
        
        return data  # إرجاع البيانات كبايت (بدون تحويل إلى نص)
    except ValueError as e:
        logging.error(f"Error in decrypt_aes (ValueError): {e}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error in decrypt_aes: {e}")
        raise