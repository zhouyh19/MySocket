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
    

#AES_K = b'AKeyForAESlen=16'
#AES_IV = b'AvectorAESlen=16'

def MyAESencrypt(text,AES_K):
    aesCBCencrypter = AES.new(AES_K,AES.MODE_CBC,AES_K[:16])
    cipher_text = aesCBCencrypter.encrypt(text)
    return cipher_text

def MyAESdecrypt(text,AES_K):
    aesCBCdecrypter = AES.new(AES_K,AES.MODE_CBC,AES_K[:16])
    plain_text = aesCBCdecrypter.decrypt(text)
    return plain_text

def MyFullEncrypt(text,AES_= b'AKeyForAESlen=16'):
    digest = SHA256.new(text)
    PrivK = open('private_key.pem')
    private_key = RSA.import_key(PrivK.read())
    signature = pkcs1_15.new(private_key).sign(digest)
    M_lenM_EkraHM = pad(str(len(text)).encode('utf-8'),16) + text + signature
    M_lenM_EkraHM = pad(M_lenM_EkraHM,16)
    return MyAESencrypt(M_lenM_EkraHM,AES_K)
    


def MyFullDecrypt(cipher,other_public_key,AES_K= b'AKeyForAESlen=16'):
    other_public_key=RSA.import_key(other_public_key)
    aesdcr = MyAESdecrypt(cipher,AES_K)
    aesdcr = unpad(aesdcr,16)
    lenM = int(str(unpad(aesdcr[0:16],16),encoding='utf-8'))
    M = aesdcr[16:][0:lenM]
    sign = aesdcr[16:][lenM:]
    digest = SHA256.new(M)
    try:
        pkcs1_15.new(other_public_key).verify(digest, sign)
        valid=True
    except (ValueError,TypeError):
        valid=False
    return M,valid


def MyRSAencrypt(text,other_public_key):
    other_public_key=RSA.import_key(other_public_key)
    text = text.encode('utf-8')
    text = pad(text,16)
    cipher = PKCS1_OAEP.new(other_public_key)
    encrypted = cipher.encrypt(text)
    return encrypted

def MyRSAdecrypt(encrypted):
    PrivK = open('private_key.pem')
    private_key = RSA.import_key(PrivK.read())
    cipher = PKCS1_OAEP.new(private_key)
    decrypted = cipher.decrypt(encrypted)
    decrypted = unpad(decrypted,16)
    return decrypted
