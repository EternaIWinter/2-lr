import hashlib
import smtplib
import base64
import inline
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

def login_email():
    login = input('Введите логин: ')
    passw = inline.input('Введите пароль: ', secret= True)
    try:
        with smtplib.SMTP('smtp.yandex.ru', 587) as server:
            server.starttls()
            server.login(login, passw)
            return login, passw
    except(Exception):
        print('Логин или пароль неверны')
        return '',''

def sign_message(file_key, mess):
    file_sign = 'sign.txt'
    with open(file_key, mode='rb') as file:
        keydata = file.read()
    PrivK = serialization.load_pem_private_key(keydata, password=None) 
    hash_obj = hashlib.sha256(mess.encode('utf-8'))
    hash = hash_obj.digest()
    sign = PrivK.sign(hash,
                       padding.PSS(mgf=padding.MGF1(hashes.SHA256()), 
                                   salt_length=padding.PSS.MAX_LENGTH),
                       hashes.SHA256())
    sign_b64 = base64.b64encode(sign)
    with open(file_sign, 'wb') as signature_file:
        signature_file.write(sign_b64)
    signature_file.close()
    return file_sign

def main():
    send_email = ''
    send_pass = ''
    file_key = 'key.pem'
    file_sign = ''
    mess = ''
    message = MIMEMultipart()
    message['Subject'] = '2 laboratornaya'
    out_menu = '''        1 - войти в аккаунт почтового сервиса
        2 - набрать сообщение
        3 - указать файл с ключами
        4 - поставить электронную подпись
        5 - отправить письмо
        6 - выход'''
    while True:
        print(out_menu)
        try:
            choice = int(input(' '))
        except(Exception) as err:
           print(err)
        if choice == 1:
            send_email, send_pass = login_email()
        elif choice == 2:
            mess = input('Введите текст сообщения: ')
            body_mess = MIMEText(mess)
            message.attach(body_mess)
        elif choice == 3:
            try:
                #file_key = input('Укажите файл с ключами: ')
                open(file_key)
            except(Exception):
                print("Неверно указан файл")
        elif choice == 4:
            file_sign = sign_message(file_key, mess)
        elif choice == 5 and mess != '':
            try:
                addressee = send_email#input('Введите адрес, куда нужно отправить сообщение')
                message['To'] = addressee
                message['From'] = send_email
                if file_sign != '':
                    with open(file_sign, 'rb') as file:
                        sign_part = MIMEApplication(file.read(), _subtype='signature')
                        sign_part.add_header('Content-Disposition', 'attachment', filename=file_sign)
                        message.attach(sign_part)
                with smtplib.SMTP('smtp.yandex.ru', 587) as server:
                    server.starttls()
                    server.login(send_email, send_pass)
                    server.sendmail(send_email, addressee, message.as_string())
            except(Exception) as exc:
                print(exc)
        elif choice == 6:
            print('Удачи')
            break
    return None
if __name__ == '__main__':
    main()