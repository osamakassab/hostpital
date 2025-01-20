import hashlib
import sqlite3
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet

from config import SERVER_PRIVATE_KEY

# إعداد قاعدة البيانات
def creat_database():
    print("Setting up database...")
    conn = sqlite3.connect("hospital.db", check_same_thread=False)
    cursor = conn.cursor()
    # تمكين وضع WAL لتحسين التزامن
    cursor.execute('PRAGMA journal_mode=WAL;')
    # إنشاء جدول المستخدمين إذا لم يكن موجودًا
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE,
                        password TEXT,
                        national_id TEXT,
                        age INTEGER,
                        job TEXT,
                        phone TEXT,
                        address TEXT,
                        specialization TEXT,
                        role TEXT
                    )''')
                    # التحقق من وجود العمود قبل إضافته
    cursor.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in cursor.fetchall()]
    
    if "public_key" not in columns:
        cursor.execute('''ALTER TABLE users ADD COLUMN public_key TEXT''')
    
    if "private_key" not in columns:
        cursor.execute('''ALTER TABLE users ADD COLUMN private_key TEXT''')
    # إنشاء جدول المواعيد إذا لم يكن موجودًا
    cursor.execute('''CREATE TABLE IF NOT EXISTS appointments (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT,
                        doctor_name TEXT,
                        appointment_date TEXT,
                        appointment_time TEXT
                    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS medical_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    chronic_diseases TEXT,
                    surgeries TEXT,
                    medications TEXT,
                    FOREIGN KEY (username) REFERENCES users(username)
                )''')
    # إذا كان الجدول موجودًا مسبقًا ولكن العمود غير موجود
    try:
        cursor.execute("ALTER TABLE appointments ADD COLUMN appointment_time TEXT")
    except sqlite3.OperationalError:
        # العمود موجود بالفعل
        pass
    conn.commit()
    return conn


def generate_rsa_keys():
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

# إنشاء مفتاح تشفير لحماية المفتاح الخاص
ENCRYPTION_KEY = Fernet.generate_key()
cipher = Fernet(ENCRYPTION_KEY)

def encrypt_private_key(private_key):
    return cipher.encrypt(private_key.encode()).decode()

def decrypt_private_key(encrypted_private_key):
    return cipher.decrypt(encrypted_private_key.encode()).decode()

# تسجيل حساب جديد
def register_user(data, conn):
    try:
        cursor = conn.cursor()
        
        # تشفير كلمة المرور
        hashed_password = hashlib.sha256(data["password"].encode()).hexdigest()

        # إنشاء مفاتيح المستخدم
        private_key, public_key = generate_rsa_keys()

        # تشفير المفتاح الخاص قبل التخزين
        encrypted_private_key = encrypt_private_key(private_key)

        # إدخال المستخدم مع المفاتيح في قاعدة البيانات
        cursor.execute('''INSERT INTO users (username, password, national_id, age, job, phone, address, specialization, role, public_key, private_key)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (data["username"], hashed_password, data["national_id"], data["age"], data["job"],
                        data["phone"], data["address"], data["specialization"], data["role"],
                        public_key, encrypted_private_key))
        
        conn.commit()
        return "Account created successfully with RSA keys!"
    except sqlite3.IntegrityError:
        return "Error: Username already exists."
    except Exception as e:
        return f"Error: {e}"
    
def login_user(data, conn):
    cursor = conn.cursor()
    hashed_password = hashlib.sha256(data['password'].encode()).hexdigest()
    cursor.execute('''SELECT role, public_key FROM users WHERE username = ? AND password = ?''',
                    (data['username'], hashed_password))
    user = cursor.fetchone()
    
    # التحقق مما إذا كان المستخدم موجودًا
    if user is None:
        return "Error: Invalid username or password."
    
    # استرجاع الدور والمفتاح العام للمستخدم
    role = user[0]
    user_public_key = user[1]  # استرجاع المفتاح العام للمستخدم
    
    return f"Login successful! Role: {role}|UserPublicKey:{user_public_key}"
# حجز موعد
def book_appointment(data, conn):
    cursor = conn.cursor()
    try:
        # التحقق من أن الطبيب موجود وله دور "doctor"
        cursor.execute("SELECT * FROM users WHERE username = ? AND role = ?", (data["doctor_name"], "doctor"))
        doctor = cursor.fetchone()
        if not doctor:
            return f"Error: Doctor {data['doctor_name']} does not exist."

        # التحقق من وجود موعد في نفس التاريخ والوقت مع نفس الطبيب
        cursor.execute('''SELECT * FROM appointments 
                        WHERE doctor_name = ? AND appointment_date = ? AND appointment_time = ?''',
                    (data["doctor_name"], data["appointment_date"], data["appointment_time"]))
        existing_appointment = cursor.fetchone()
        if existing_appointment:
            return f"Error: Doctor {data['doctor_name']} is already booked on {data['appointment_date']} at {data['appointment_time']}."

        # إدخال الموعد إذا لم يكن هناك تضارب
        cursor.execute('''INSERT INTO appointments (username, doctor_name, appointment_date, appointment_time)
                        VALUES (?, ?, ?, ?)''',
                    (data["username"], data["doctor_name"], data["appointment_date"], data["appointment_time"]))
        conn.commit()
        return f"Appointment booked with Dr. {data['doctor_name']} on {data['appointment_date']} at {data['appointment_time']}."
    except Exception as e:
        return f"Error booking appointment: {str(e)}"
    
def save_medical_record(data, conn):
    try:
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO medical_records (username, chronic_diseases, surgeries, medications)
                        VALUES (?, ?, ?, ?)''',
                    (data["username"], data["chronic_diseases"], data["surgeries"], data["medications"]))
        conn.commit()
        return "Medical record saved successfully!"
    except Exception as e:
        return f"Error saving medical record: {e}"