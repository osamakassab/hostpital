import socket
import threading
import json
import sys
import os

# إضافة المسار الجذر للمشروع إلى sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY, generate_server_rsa_keys
from server_s.database import book_appointment, creat_database, login_user, register_user, save_medical_record
from server_s.encryption import   decrypt_aes, encrypt_aes, encrypt_with_server_public_key


# معالجة الاتصال مع العميل
def handle_client(client_socket, address, conn):
    print(f"Connection established with {address}")
    while True:
        try:
            # استقبال الطلب المشفر
            encrypted_request = client_socket.recv(1024).decode()
            if not encrypted_request:
                break
            # فك التشفير بناءً على نوع الطلب
            request_data = None
            try:
                request_data = json.loads(decrypt_aes(encrypted_request))  # محاولة فك التشفير باستخدام AES
            except Exception as e:
                client_socket.send(encrypt_aes(f"Error: Invalid encryption format - {str(e)}").encode())
                continue  # تخطي هذه الدورة من اللوب والانتقال إلى الدورة التالية
            # التحقق من صحة البيانات
            if not request_data or "type" not in request_data:
                client_socket.send(encrypt_aes("Error: Invalid request format.").encode())
                continue
            # معالجة الطلب
            response = "Invalid request type."
            if request_data["type"] == "register":
                response = register_user(request_data, conn)
            elif request_data["type"] == "login":
                response = login_user(request_data, conn)
                if "Login successful" in response:
                    
                    print("respon on server:",response)
                    
                    # استخراج المفتاح العام للمستخدم من الرد
                    user_public_key = response.split("|UserPublicKey:")[1]
                    # تعديل الرد لإزالة المفتاح العام للمستخدم
                    response = response.split("|UserPublicKey:")[0]
                    # print("Response on server without keys:", response)
                    # تشفير الرد
                    encrypted_response = encrypt_aes(response)
                    # إرسال الرد المشفر بعد إرسال المفتاح العام
                    client_socket.send(encrypted_response.encode())
                    
                    encrypted_serverkey = encrypt_aes(SERVER_PUBLIC_KEY)
                    client_socket.send(encrypted_serverkey.encode())

                    client_socket.close()
            elif request_data["type"] == "book_appointment":
                response = book_appointment(request_data, conn)
            elif request_data["type"] == "add_medical_record":
                response = save_medical_record(request_data, conn)
            # تشفير الرد بناءً على نوع الطلب
            if request_data["type"] in ["register",  "book_appointment", "add_medical_record"]:
                encrypted_response = encrypt_aes(response)
            else:
                encrypted_response = encrypt_aes("Invalid request type.")
                
            # print("encrypted_response befor send to client:  ",encrypted_response)
            # إرسال الرد المشفر إلى العميل
            client_socket.send(encrypted_response.encode())
        except Exception as e:
            encrypted_error = encrypt_aes(f"Error: {str(e)}")
            client_socket.send(encrypted_error.encode())
            break
    client_socket.close()
    
def start_server():
    conn = creat_database()
    generate_server_rsa_keys()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", 7000))
    server_socket.listen(5)
    print("Server is listening on port 7000...")
    # طباعة المفتاح العام
    # print("(Public Key):")
    # print(SERVER_PUBLIC_KEY)
    # # طباعة المفتاح الخاص
    # print("(Private Key):")
    # print(SERVER_PRIVATE_KEY)
    while True:
        client_socket, address = server_socket.accept()
        client_handler = threading.Thread(target=handle_client, args=(client_socket, address, conn))
        client_handler.start()

if __name__ == "__main__":
    start_server()