from Crypto.Cipher import AES as aes
from Crypto.Util.Padding import pad, unpad
import base64

from dhke import DHKE

class AES:
    def __init__(self, key:str, key_size=256):
        self.key = key[:32] # flaw i couldnt understand
        self.key_size = key_size
    
    def encrypt(self, message):
        encrypter_system = aes.new(self.key, aes.MODE_ECB)
        padded_message = pad(message.encode(), aes.block_size)
        cipher = encrypter_system.encrypt( padded_message )
        return base64.b64encode(cipher).decode('utf-8')
    
    def decrypt(self, cipher):
        cipher_bytes = base64.b64decode(cipher)
        encrypter_system = aes.new(self.key, aes.MODE_ECB)
        padded_msg = encrypter_system.decrypt(cipher_bytes)
        return unpad( padded_msg, aes.block_size ).decode('utf-8')
    
if __name__ == '__main__':
    d = DHKE('0.0.0.0')
    
    key = str(d.getSharedKey())[:32].encode()
    a = AES( key )
    msg = "ABC"
    c = a.encrypt(msg)
    z = a.decrypt(c)
    print(f' {msg} ==> {c} ==> {z}')