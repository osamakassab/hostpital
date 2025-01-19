
from client_s.client_network import send_request


def register_user():
    """
    تسجيل مستخدم جديد.
    """
    print("\n--- Register ---")
    username = input("Username: ")
    password = input("Password: ")
    national_id = input("National ID: ")
    age = int(input("Age: "))
    job = input("Job: ")
    phone = input("Phone: ")
    address = input("Address: ")
    specialization = input("Specialization (leave blank if patient): ")
    role = input("Role (doctor/patient): ").strip().lower()

    # التحقق من الإدخال
    if role not in ["doctor", "patient"]:
        print("Invalid role. Please choose 'doctor' or 'patient'.")
        return

    # بناء الطلب
    request = {
        "type": "register",
        "username": username,
        "password": password,
        "national_id": national_id,
        "age": age,
        "job": job,
        "phone": phone,
        "address": address,
        "specialization": specialization,
        "role": role
    }
    print(send_request(request))

def login_user():
    """
    تسجيل دخول المستخدم.
    """
    print("\n--- Login ---")
    username = input("Username: ")
    password = input("Password: ")

    request = {
        "type": "login",
        "username": username,
        "password": password
    }
    response = send_request(request)
    print(response)

    # إذا تم تسجيل الدخول كمريض
    if "Login successful" in response and "Role: patient" in response:
        patient_menu(username)
    elif "Login successful" in response and "Role: doctor" in response:
        doctor_menu(username)

def patient_menu(username):
    """
    قائمة المريض بعد تسجيل الدخول.
    
    :param username: اسم المستخدم للمريض.
    """
    while True:
        print("\n--- Welcome Patient ---")
        print("1. Book an appointment")
        print("2. Add medical record")
        print("3. Logout")
        action = input("Choose an option: ")
        if action == "1":
            book_appointment(username)
        elif action == "2":
            add_medical_record(username)
        elif action == "3":
            print("Logging out...")
            break
        else:
            print("Invalid option. Please try again.")

def book_appointment(username):
    """
    حجز موعد مع طبيب.
    
    :param username: اسم المستخدم للمريض.
    """
    doctor_name = input("Enter the doctor's name: ")
    appointment_date = input("Enter the appointment date (YYYY-MM-DD): ")
    appointment_time = input("Enter the appointment time (HH:MM): ")
    appointment_request = {
        "type": "book_appointment",
        "username": username,
        "doctor_name": doctor_name,
        "appointment_date": appointment_date,
        "appointment_time": appointment_time
    }
    appointment_response = send_request(appointment_request)
    print(appointment_response)

def add_medical_record(username):
    """
    إضافة سجل طبي للمريض.
    
    :param username: اسم المستخدم للمريض.
    """
    chronic_diseases = input("Enter chronic diseases: ")
    surgeries = input("Enter previous surgeries: ")
    medications = input("Enter regular medications: ")
    medical_record_request = {
        "type": "add_medical_record",
        "username": username,
        "chronic_diseases": chronic_diseases,
        "surgeries": surgeries,
        "medications": medications
    }
    record_response = send_request(medical_record_request)
    # print ("send to network:",medical_record_request)
    print(record_response)

def doctor_menu(username):
    """
    قائمة الطبيب بعد تسجيل الدخول.
    
    :param username: اسم المستخدم للطبيب.
    """
    print("\n--- Welcome Doctor ---")
    # يمكن إضافة وظائف خاصة بالطبيب هنا