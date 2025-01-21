import socket
import json
import os
from client_s.encryption import decrypt_session_key, encrypt_aes, decrypt_aes, encrypt_with_AES, encrypt_with_key
global SERVER_PUBLIC_KEY 

def send_session_key(session_key, server_public_key):
    """
    إرسال مفتاح الجلسة المشفر إلى الخادم وانتظار الموافقة.
    """
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(("127.0.0.1", 7000))

        # تشفير مفتاح الجلسة باستخدام المفتاح العام للخادم
        encrypted_session_key = encrypt_with_key(session_key, server_public_key)
        # print("encrypted_session_key redy to send to server..................",encrypted_session_key)

        # إعداد الطلب كـ JSON وإرساله كبايت
        request = json.dumps({
            "type": "send_session_key",
            "encrypted_session_key": encrypted_session_key
        })
        
        encrypted_request = encrypt_aes(request)
        client_socket.send(encrypted_request.encode())

        # استقبال الرد من الخادم
        response = client_socket.recv(1024).decode().strip()
        print(response)
        return response == "Session key approved"
        
    except Exception as e:
        print(f"Error in send_session_key: {e}")
        return False
    finally:
        client_socket.close()

def send_encrypted_data(request, session_key,server_public_key):
    """
    إرسال البيانات المشفرة باستخدام مفتاح الجلسة.
    
    :param data: البيانات المراد إرسالها (قاموس).
    :param session_key: مفتاح الجلسة (بايت).
    :return: الرد من الخادم.
    """
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", 7000))  # الاتصال بالمخدم
    json_request = json.dumps(request)
    # تشفير البيانات باستخدام مفتاح الجلسة
    json_request = json.dumps(request)
    
    encrypted_data_aes = encrypt_with_AES(json_request, session_key)
    # encrypt_data_puplickey=encrypt_with_key(encrypted_data_aes, server_public_key)
    
    # print("request berfor send...........",encrypted_data_aes)
    client_socket.send(encrypted_data_aes.encode())
    resev_response = client_socket.recv(1024).decode().strip()
    response=decrypt_session_key(resev_response,session_key)
    return response

def send_request(request):
    """
    إرسال طلب إلى الخادم واستقبال الرد.
    
    :param request: الطلب كقاموس (dict).
    :return: الرد من الخادم مع المفتاح العام.
    """
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(("127.0.0.1", 7000))  # الاتصال بالمخدم

        # تشفير الطلب
        json_request = json.dumps(request)
        encrypted_request = encrypt_aes(json_request)

        # إرسال الطلب المشفر
        client_socket.send(encrypted_request.encode())

        # استقبال الرد المشفر الأول
        encrypted_response = client_socket.recv(1024).decode()

        # فك تشفير الرد الأول
        decrypted_response = decrypt_aes(encrypted_response)
        response = decrypted_response.decode()  # تحويل البيانات المفكوكة إلى نص

        # التحقق مما إذا كان الرد يحتوي على "Login successful"
        if "Login successful" in response:
            # انتظار رسالة أخرى من الخادم تحتوي على المفتاح العام المشفر
            encrypted_serverkey = client_socket.recv(1024).decode()
            # فك تشفير المفتاح العام للخادم
            server_public_key = decrypt_aes(encrypted_serverkey).decode()  # تحويل البيانات المفكوكة إلى نص
            global SERVER_PUBLIC_KEY
            SERVER_PUBLIC_KEY = server_public_key
            # إرجاع الرد مع المفتاح العام
            response_data = {
                "response": response,
                "server_public_key": server_public_key
            }
        else:
            # إرجاع الرد فقط إذا لم يكن تسجيل الدخول ناجحًا
            response_data = {
                "response": response,
                "server_public_key": None
            }

        client_socket.close()
        return response_data
    except socket.error as e:
        print(f"Socket error: {e}")
        return None