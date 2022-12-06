
from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad,unpad

def generateRSAkeys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    file_out = open('private_key.pem','wb')
    file_out.write(private_key)

    public_key = key.publickey().export_key()
    file_out = open('public_key.pem','wb')
    file_out.write(public_key)
    

AES_K = b'AKeyForAESlen=16'
AES_IV = b'AvectorAESlen=16'

def MyAESencrypt(text):
    aesCBCencrypter = AES.new(AES_K,AES.MODE_CBC,AES_IV)
    cipher_text = aesCBCencrypter.encrypt(text)
    return cipher_text

def MyAESdecrypt(text):
    aesCBCdecrypter = AES.new(AES_K,AES.MODE_CBC,AES_IV)
    plain_text = aesCBCdecrypter.decrypt(text)
    return plain_text

def MyFullEncrypt(text):
    digest = SHA256.new(text)
    try:
        PrivK = open('private_key.pem')
    except IOError:
        generateRSAkeys()
        PrivK = open('private_key.pem')
    private_key = RSA.import_key(PrivK.read())
    signature = pkcs1_15.new(private_key).sign(digest)
    M_lenM_EkraHM = pad(str(len(text)).encode('utf-8'),16) + text + signature
    M_lenM_EkraHM = pad(M_lenM_EkraHM,16)
    return MyAESencrypt(M_lenM_EkraHM)
    


def MyFullDecrypt(cipher):
    PubK = open('other.pem')
    other_public_key = RSA.import_key(PubK.read())
    aesdcr = MyAESdecrypt(cipher)
    aesdcr = unpad(aesdcr,16)
    lenM = int(str(unpad(aesdcr[0:16],16),encoding='utf-8'))
    M = aesdcr[16:][0:lenM]
    sign = aesdcr[16:][lenM:]
    digest = SHA256.new(M)
    try:
        pkcs1_15.new(other_public_key).verify(digest, sign)
        print('signature Valid')
    except (ValueError,TypeError):
        print('signature InValid')


def MyRSAencrypt(text,other_public_key):
    #用对方的公钥加密，收到时用自己的私钥解密
    text = text.encode('utf-8')
    text = pad(text,16)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(text)
    return encrypted

def MyRSAdecrypt(encrypted):
    #用对方的公钥加密，收到时用自己的私钥解密
    try:
        PrivK = open('private_key.pem')
    except IOError:
        generateRSAkeys()
        PrivK = open('private_key.pem')
    private_key = RSA.import_key(PrivK.read())
    cipher = PKCS1_OAEP.new(private_key)
    decrypted = cipher.decrypt(encrypted)
    decrypted = unpad(decrypted,16)
    return decrypted


    
test_message = 'try test our socket program'
test_text2 = 'try a test string again'
public_key = RSA.import_key(open('public_key.pem').read())
cipher = MyFullEncrypt(test_message)
MyFullDecrypt(cipher,public_key)

enc = MyRSAencrypt(test_text2, public_key)
print(enc,type(enc))
dec = MyRSAdecrypt(enc)
print(dec)



