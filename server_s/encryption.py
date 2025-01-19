from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import os
import base64
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
def generate_server_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # تحويل المفاتيح إلى صيغة قابلة للحفظ
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem.decode(), public_pem.decode()

# توليد مفاتيح السيرفر وتخزينها في متغيرات عالمية
SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY = generate_server_rsa_keys()

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

# فك تشفير البيانات باستخدام مفتاح السيرفر الخاص
def decrypt_with_server_private_key(encrypted_data):
    private_key = serialization.load_pem_private_key(SERVER_PRIVATE_KEY.encode(), password=None, backend=default_backend())
    decrypted = private_key.decrypt(
        base64.b64decode(encrypted_data),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()