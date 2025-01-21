import socket
import threading
import json
import sys
import os

# إضافة المسار الجذر للمشروع إلى sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import SERVER_PRIVATE_KEY, SERVER_PUBLIC_KEY, generate_server_rsa_keys
from server_s.database import book_appointment, creat_database, login_user, register_user, save_medical_record
from server_s.encryption import   decrypt_aes, decrypt_session_key, decrypt_with_key, decrypt_with_server_private_key, encrypt_aes, encrypt_with_AES, encrypt_with_server_public_key

session_key = None
# معالجة الاتصال مع العميل
def handle_client(client_socket, address, conn):
    global session_key  # الإشارة إلى المتغير العام
    print(f"Connection established with {address}")
    while True:
        try:
            # استقبال الطلب المشفر
            encrypted_request = client_socket.recv(1024).decode()
            # print("encrypted_request from client ",encrypted_request)
            if not encrypted_request:
                break
            # فك التشفير بناءً على نوع الطلب
            request_data = None
            try:
                # محاولة فك التشفير باستخدام AES أولاً
                decrypted_data = decrypt_aes(encrypted_request)
                request_data = json.loads(decrypted_data)
            except Exception as aes_error:
                # إذا فشل فك التشفير باستخدام AES، حاول فك التشفير باستخدام RSA
                try:
                    # تفك تشفير الرسالة باستخدام RSA
                    decrypted_data_rsa = decrypt_session_key(encrypted_request,session_key)
                    # print("decrypted_data withe server private_key............",decrypted_data_rsa)
                    request_data = json.loads(decrypted_data_rsa )
                except Exception as privet_error:
                    # إذا فشل فك التشفير باستخدام RSA أيضًا
                    error_message = f"Error: Invalid encryption format - AES: {aes_error}, privet_error: {privet_error}"
                    print(error_message)
                    client_socket.send(encrypt_aes(error_message).encode())
                    continue  # تخطي هذه الدورة من اللوب والانتقال إلى الدورة التالية
            # التحقق من صحة البيانات
            if not request_data or "type" not in request_data:
                client_socket.send(encrypt_aes("Error: Invalid request format.").encode())
                continue
            # معالجة الطلب
            response = "Invalid request type."
            if request_data["type"] == "register":
                response = register_user(request_data, conn)
            elif request_data["type"] == "send_session_key":
                encrypted_session_key = request_data["encrypted_session_key"]
                session_key = decrypt_with_server_private_key(encrypted_session_key)
                response = "Session key approved"
                client_socket.send(response.encode())
                response = login_user(request_data, conn)
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
            if request_data["type"] in ["register",  "book_appointment"]:
                encrypted_response = encrypt_aes(response)
            elif  request_data["type"] in ["add_medical_record"]:
                encrypted_response = encrypt_with_AES(response,session_key)
                
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
    # print("SERVER_PUBLIC)KEY",SERVER_PUBLIC_KEY)
    # اختبار تشفير/فك تشفير

    # المفتاح العام الحقيقي
    # session_key = os.urandom(32)
    # encrypted = encrypt_with_public_key(session_key, SERVER_PUBLIC_KEY)
    # decrypted = decrypt_with_server_private_key(encrypted)
    # print("Original:", session_key)
    # print("Decrypted:", decrypted)
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