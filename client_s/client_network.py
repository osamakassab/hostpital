import socket
import json

from client_s.encryption import decrypt_aes, encrypt_aes

def send_request(request):
    """
    إرسال طلب إلى الخادم واستقبال الرد.
    
    :param request: الطلب كقاموس (dict).
    :return: الرد من الخادم مع المفتاح العام.
    """
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", 7000))  # الاتصال بالمخدم

    # تشفير الطلب
    json_request = json.dumps(request)
    encrypted_request = encrypt_aes(json_request)

    # إرسال الطلب المشفر
    client_socket.send(encrypted_request.encode())

    # استقبال الرد المشفر الأول
    encrypted_response = client_socket.recv(1024).decode()
    print("Encrypted response from server to client:", encrypted_response)

    # فك تشفير الرد الأول
    response = decrypt_aes(encrypted_response)
    print("Decrypted response from server to client:", response)

    # التحقق مما إذا كان الرد يحتوي على "Login successful"
    if "Login successful" in response:
        # انتظار رسالة أخرى من الخادم تحتوي على المفتاح العام المشفر
        encrypted_serverkey = client_socket.recv(1024).decode()
        print("Encrypted server key from server to client:", encrypted_serverkey)
        # فك تشفير المفتاح العام للخادم
        server_public_key = decrypt_aes(encrypted_serverkey)
        print("Decrypted server public key:", server_public_key)
    else:
        # إرجاع الرد فقط إذا لم يكن تسجيل الدخول ناجحًا
        client_socket.close()
        return response
    client_socket.close()
    return response