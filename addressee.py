import hashlib
import base64
import email
import imaplib
from send import login_email
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

def get_body(message):
    body = ''
    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain':
                body = part.get_payload(decode=True).decode()
    else:
        body = message.get_payload(decode=True).decode()
    return body

def output(imap, letter_ids):
    i = 1
    for id in letter_ids:
        res, msg = imap.fetch(id, '(RFC822)')
        message = email.message_from_bytes(msg[0][1])
        subject = message['subject']
        body = ''
        body = get_body(message)
        attachments = []
        for part in message.walk():
            file = part.get_filename()
            if file:
                attachments.append(file)
        print(f'Письмо {i}')
        print(f'Тема: {subject}')
        print(f'Сообщение: {body}')
        print(f'Прикрепленные файлы: {attachments}')
        i+=1
    return None

def check(flag_revers = False):
    choice = input(' ') 
    if flag_revers:
        if choice == 'д' or choice == 'y':
            return True
    if choice == 'n' or choice == 'н':
        print('Удачи')
        return True
    return False

def login_to_account():
    login = 'vechnay.zima@yandex.ru'#''
    email_pass = ''
    while True:
        print("Вход в аккаунт: \n")
        login, email_pass = login_email()
        if login == '':
            print('Повторить попытку?')
            if check(flag_revers=True):
                continue
            else:
                print('Удачи')
                break
        else:
            break
    imap = imaplib.IMAP4_SSL('imap.yandex.ru')
    imap.login(login, email_pass)
    imap.select("INBOX")
    return imap

def letter_selection(imap, letter_ids):
    flag_sign = False
    select_letter_id = int(input('Введите номер письма: ')) - 1
    res, msg = imap.fetch(letter_ids[select_letter_id], '(RFC822)')
    message = email.message_from_bytes(msg[0][1])
    body = get_body(message)
    for part in message.walk():
        filename = part.get_filename()
        if filename:
            flag_sign = True
            with open(filename, 'wb') as file:
                file.write(part.get_payload(decode=True))
    return body, flag_sign

def check_sign(body):
    with open(input('Укажите файл с ключами: '), mode='rb') as file:
        keydata = file.read()
    PrivK = serialization.load_pem_private_key(keydata, password=None)    
    PubK = PrivK.public_key()
    hash_object = hashlib.sha256(body.encode('utf-8'))
    hash = hash_object.digest()
    with open('sign.txt', 'rb') as sign_file:
        sign_b64 = sign_file.read()
    sign = base64.b64decode(sign_b64)
    try:
        PubK.verify(sign, hash,
                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                          hashes.SHA256())
        print("\n***Подпись верна.***\n")
    except:
        print("\n***Подпись недействительна.***\n") 

def main():
    imap = login_to_account()
    status, letter_ids = imap.search(None, 'ALL')   
    letter_ids = letter_ids[0].split()[-5:]

    while True:
        output(imap, letter_ids)
        print("Хотите выбрать письмо?")
        if check():
            break

        body,flag_sign = letter_selection(imap, letter_ids)

        if flag_sign:
            print("Хотите проверить подпись письма?")
            if check():
                continue
            check_sign(body)
    return None
if __name__ == '__main__':
    main()