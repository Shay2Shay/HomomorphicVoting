from fastapi import FastAPI
import requests
from paillier_cryptosystem import PaillierCryptosystem
import json

def strToJSON(msg:str):
    return json.loads(msg)

BACKEND = 'http://127.0.0.1:8080'
app = FastAPI()

pc = PaillierCryptosystem()
pc.keyGen()

# 3000

@app.get('/')
def home():
    return {'message': 'server is up'}

@app.get('/paillierpub')
def paillierpub():
    return pc.getPublicKey()

@app.get('/liveresults')
def liveresults():
    res = requests.get(f'{BACKEND}/liveresults')
    res = strToJSON(res.text)
    count = res['count']
    for k in count:
        count[k] = PaillierCryptosystem.decrypt(pc.getPrivateKey(), count[k])
    print("results:", count)
    return {'results': count}