import socket
import threading
import json

from server_s.database import book_appointment, creat_database, login_user, register_user, save_medical_record
from server_s.encryption import decrypt_aes, encrypt_aes, encrypt_with_server_public_key


# معالجة الاتصال مع العميل
def handle_client(client_socket, address, conn):
    print(f"Connection established with {address}")

    while True:
        try:
            # استقبال الطلب المشفر
            encrypted_request = client_socket.recv(1024).decode()
            # print(f" server Encrypted request: {encrypted_request}")#   طباعة الرد المشفر
            if not encrypted_request:
                break
            # فك التشفير بناءً على نوع الطلب
            request_data = None
            try:
                request_data = json.loads(decrypt_aes(encrypted_request))  # محاولة فك التشفير باستخدام AES
                # print(f" server request_data: {request_data}")
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
            elif request_data["type"] == "book_appointment":
                response = book_appointment(request_data, conn)
            elif request_data["type"] == "add_medical_record":
                response =save_medical_record(request_data, conn)

            # تشفير الرد بناءً على نوع الطلب
            if request_data["type"] in ["register", "login", "book_appointment","add_medical_record"]:
                encrypted_response = encrypt_aes(response)
            # elif request_data["type"] == "add_medical_record":
            #     encrypted_response = encrypt_with_server_public_key(response)
            else:
                encrypted_response = encrypt_aes("Invalid request type.")
            # print(f" server befor send encrypted_response: {(encrypted_response)}")
            client_socket.send(encrypted_response.encode())
        except Exception as e:
            encrypted_error = encrypt_aes(f"Error: {str(e)}")
            client_socket.send(encrypted_error.encode())
            break
    client_socket.close()


def start_server():
    conn = creat_database()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", 7000))
    server_socket.listen(5)
    print("Server is listening on port 7000...")

    while True:
        client_socket, address = server_socket.accept()
        client_handler = threading.Thread(target=handle_client, args=(client_socket, address, conn))
        client_handler.start()

if __name__ == "__main__":
    start_server()