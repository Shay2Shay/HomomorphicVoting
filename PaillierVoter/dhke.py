from paillier_cryptosystem import Utils
import random

class DHKE:
    def __init__(self, targetIP: str = '0.0.0.0'):
        self.bitsize = 256 # 107
        self.myKEY = {
            'a': None,
            'pub': None,
            'g': None,
            'n': None,
            'other': None,
            'shared': None
        }
        self.targetIP = targetIP
        self.setup()
        self.keyExchange()

    def setup(self):
        n = Utils.primeGenerator(self.bitsize)
        self.myKEY['n'] = n # recieve g,n
        
        g = random.randint(1, n-1)
        assert g < n and 0 < g
        self.myKEY['g'] = g # recieve g,n
        
        a = 12
        self.myKEY['a'] = a
        
        pub = pow(g, a, n)
        self.myKEY['pub'] = pub

    def keyExchange(self):
        # send g, n
        # other = request.....
        b = 15
        other = pow(self.myKEY['g'], b, self.myKEY['n'])
        self.myKEY['other'] = other
        
        shared = pow(other, self.myKEY['a'], self.myKEY['n'])
        self.myKEY['shared'] = shared
    
    def getSharedKey(self):
        return self.myKEY['shared']

if __name__ == '__main__':
    dhke = DHKE('0.0.0.0')
    shared = dhke.getSharedKey()
    print(shared)
    key_str = bin(shared)[2:]
    print(len(key_str))