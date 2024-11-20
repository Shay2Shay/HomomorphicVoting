from fastapi import FastAPI, Form
from typing import Annotated
from fastapi.middleware.cors import CORSMiddleware
import requests

from jsonHandler import loadJSON, saveJSON, strToJSON
from dhke import DHKE
from myrsa import RSA
from aes import AES
from paillier_cryptosystem import PaillierCryptosystem

BACKEND = 'http://127.0.0.1:8080'
PAILLIER = 'http://127.0.0.1:3000'

def saveDB(db):
    saveJSON(db, 'db.json')

db = loadJSON('db.json')

paillier_pub = requests.get(f'{PAILLIER}/paillierpub')
paillier_pub = strToJSON(paillier_pub.text)
print(paillier_pub)



app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],            # Allows specified origins
    allow_credentials=True,
    allow_methods=["*"],               # Allows all methods (GET, POST, etc.)
    allow_headers=["*"],               # Allows all headers
)

@app.get('/')
def home():
    return {"message": "Hello World"}

@app.get('/savedb')
def proxy1():
    saveDB(db)

@app.get('/login/{email}')
def login(email: str):
    res = requests.post(f'{BACKEND}/login', {'email': email})
    res = strToJSON(res.text)
    return {"message": res["message"]}

@app.get('/otprsa/{email}/{otp}')
def OTPandRSA(email: str, otp: int):
    rsa = RSA()
    if email not in db:
        return {"message": "Perform Previous Steps 1st"}
    db[email]['rsa'] = {}
    db[email]['rsa']['pub_n'] = rsa.pub.n
    db[email]['rsa']['pub_e'] = rsa.pub.e
    db[email]['rsa']['prv_d'] = rsa.prv.d
    db[email]['rsa']['prv_p'] = rsa.prv.p
    db[email]['rsa']['prv_q'] = rsa.prv.q
    # saveDB(db)
    res = requests.post(f'{BACKEND}/otprsa/', {
        'email': email,
        'otp': otp,
        'rsaPub_n': rsa.pub.n,
        'rsaPub_e': rsa.pub.e,
    })
    res = strToJSON(res.text)
    print(res)
    return {"message": res['message']}

@app.get('/dhke/{email}')
def dhke(email: str):
    db[email] = {}
    dhke = DHKE()
    res = requests.post(f'{BACKEND}/dhke/', {
        'email': email,
        'pubKeyDHKE': dhke.myKEY['pub'],
        'n': dhke.myKEY['n'],
        'g': dhke.myKEY['g']
    })
    res = strToJSON(res.text)
    if res['message'] == 'FAILED':
        del db[email]
        return {
            'sharedKey' : "FAILED"
        }
    shared = str(pow( res['pubKey'], dhke.myKEY['a'], dhke.myKEY['n'] ))
    db[email]['shared'] = shared
    return {
        "message": f"generated dhke for {email}",
        "sharedKey" : shared
    }

@app.get('/vote/{email}/{val}')
def vote(email: str, val:str):
    ballot = {
        'yes': 0,
        'no': 0
    }
    ballot[val] += 1
    
    for k in ballot:
        ballot[k] = PaillierCryptosystem.encrypt( paillier_pub, ballot[k] )
    
    data = {
        'email': email,
        'yes': ballot['yes'],
        'no': ballot['no']
    }
    res = requests.post(f'{BACKEND}/vote/', data)
    res = strToJSON(res.text)
    return {
        "message": res['message'],
        'ballot': ballot
    }

@app.get('/liveresults/')
def liveresults():
    print("HI   ")
    res = requests.get(f'{PAILLIER}/liveresults')
    res = strToJSON(res.text)
    print(res)
    return {'results': res['results']}