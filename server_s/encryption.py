from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import os
import base64

from config import SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY
AES_KEY = b'ThisIsASecretKey' 
# تشفير البيانات
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

# فك التشفير
def decrypt_aes(encrypted_data):
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

# توليد مفاتيح RSA للسيرفر
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
        

# فك التشفير
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


# تشفير البيانات باستخدام مفتاح السيرفر العام
def encrypt_with_server_public_key(data):
    public_key = serialization.load_pem_public_key(SERVER_PUBLIC_KEY.encode(), backend=default_backend())
    encrypted = public_key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

def decrypt_with_server_private_key(encrypted_data: str) -> bytes:
    """
    فك تشفير البيانات باستخدام المفتاح الخاص للخادم.
    
    :param encrypted_data: البيانات المشفرة (base64).
    :return: البيانات المفكوكة (بايت).
    """
    try:
        # تحميل المفتاح الخاص
        private_key = serialization.load_pem_private_key(
            SERVER_PRIVATE_KEY.encode(),
            password=None,
            backend=default_backend()
        )
        
        # فك تشفير البيانات
        decrypted_data = private_key.decrypt(
            base64.b64decode(encrypted_data),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_data
    except Exception as e:
        print(f"Error decrypting data: {e}")
        raise

def encrypt_with_key(data, key_pem) -> str:
    """
    تشفير البيانات باستخدام المفتاح العام (RSA).
    
    :param data: البيانات المراد تشفيرها (بايت).
    :param public_key_pem: المفتاح العام بتنسيق PEM.
    :return: البيانات المشفرة (base64).
    """
    # print("SERVER_PUBLIC)KEY IN encrypt_with_public_key",key_pem)

    try:
        # تحميل المفتاح العام
        public_key = serialization.load_pem_public_key(
            key_pem.encode(),
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

def decrypt_with_key(encrypted_data, key_pem) -> bytes:
    """
    فك تشفير البيانات باستخدام المفتاح الخاص (RSA).
    
    :param encrypted_data: البيانات المشفرة (base64).
    :param key_pem: المفتاح الخاص بتنسيق PEM.
    :return: البيانات المفكوكة (بايت).
    """
    try:
        # تحميل المفتاح الخاص
        private_key = serialization.load_pem_private_key(
            key_pem.encode(),
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
        
        return decrypted_data  # إرجاع البيانات المفكوكة كبايت
    except Exception as e:
        print(f"Error decrypting data: {e}")
        raise
    
    
    
