import socket
import json

from client_s.encryption import decrypt_aes, encrypt_aes

def send_request(request):
    """
    إرسال طلب إلى الخادم واستقبال الرد.
    
    :param request: الطلب كقاموس (dict).
    :return: الرد من الخادم.
    """
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", 7000))  # الاتصال بالمخدم

    # تشفير الطلب
    json_request = json.dumps(request)
    encrypted_request = encrypt_aes(json_request)

    # إرسال الطلب المشفر
    client_socket.send(encrypted_request.encode())

    # استقبال الرد المشفر
    encrypted_response = client_socket.recv(1024).decode()
    print("client encrypted_response",encrypted_response)

    # فك تشفير الرد
    response = decrypt_aes(encrypted_response)

    client_socket.close()
    return response