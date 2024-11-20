import rsa

class RSA:
    def __init__(self):
        self.pub, self.prv = rsa.newkeys(1024)
    
    def saveKeys(self):
        with open('PUBLIC.pem', 'wb') as f:
            f.write( self.pub.save_pkcs1('PEM') )
        
        with open('PRIVATE.pem', 'wb') as f:
            f.write( self.prv.save_pkcs1('PEM') )

    def loadKeys(self):
        with open('PUBLIC.pem', 'rb') as f:
            self.pub = rsa.PublicKey.load_pkcs1(f.read())
        
        with open('PRIVATE.pem', 'rb') as f:
            self.prv = rsa.PrivateKey.load_pkcs1(f.read())

    def encrypt(self, msg : str):
        return rsa.encrypt( msg.encode(), self.pub )
    
    def decrypt(self, cypher):
        return rsa.decrypt( cypher, self.prv ).decode()
    
    def sign(self, msg: str):
        return rsa.sign( msg.encode(), self.prv, 'SHA-256' )
    
    def verify(self, msg:str, sgn):
        rsa.verify( msg.encode(), sgn, self.pub )

if __name__ == '__main__':
    r = RSA()
    r.saveKeys()
    print(r.decrypt(r.encrypt("HELLO")))
    
    
    
    sgn = r.sign("Hello")
    r.verify( "Hello", sgn )