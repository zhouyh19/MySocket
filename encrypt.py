# run 'pip install pycryptodome' first
# 我现在实现并验证了加密的整套流程，不过需要注意，实际运行时候服务器怎么获取用户（反之也一样）的公钥呢？是握手的时候发吗
import cgi,base64,hashlib
from Crypto.Cipher import AES
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
    #加密流程：先做SHA256，用这个hash结果做RSA signature,把原消息的长度数值补全到16字节放最前面
    #便于解密。之后把这一部分补齐到16字节的整数倍后做AES加密传输
    text = text.encode('utf-8')
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
    print(M_lenM_EkraHM)
    return MyAESencrypt(M_lenM_EkraHM)
    


def MyFullDecrypt(cipher,other_public_key):
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
    
test_message = 'try test our socket program'
public_key = RSA.import_key(open('public_key.pem').read())
cipher = MyFullEncrypt(test_message)
MyFullDecrypt(cipher,public_key)
