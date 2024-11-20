from fastapi import FastAPI, Form
from typing import Annotated
from jsonHandler import loadJSON, saveJSON, strToJSON
from dhke import DHKE
import smtplib
import requests
from paillier_cryptosystem import PaillierCryptosystem
with open('password.txt', 'r') as f: 
    PASSWORD = f.readline()

server = smtplib.SMTP('smtp.gmail.com', 587)
server.starttls()
server.login('animesh.s21@iiits.in', PASSWORD)

PAILLIER = 'http://127.0.0.1:3000'
paillier_pub = requests.get(f'{PAILLIER}/paillierpub')
paillier_pub = strToJSON(paillier_pub.text)
print(paillier_pub)
count = {
    'yes': PaillierCryptosystem.encrypt( paillier_pub, 0 ),
    'no': PaillierCryptosystem.encrypt( paillier_pub, 0 )
}

def sendOTP(email):
    server.sendmail('animesh.s21@iiits.in', email, "OTP is 1 for your voting access")
    print("OTP SENT")

def validateLogin(email, db: dict) -> bool:
    return email in db

def registerPubKey(email, pubKey, db):
    db[email]['rsa'] = pubKey
    saveJSON(db, 'db.json')
    return

def registerSharedKey(email, pubKeyDHKE, n, g, db):
    dhke = DHKE()
    a = dhke.myKEY['a']
    sharedkey = pow(pubKeyDHKE, a, n)
    db[email]['aes'] = sharedkey
    saveJSON(db, 'db.json')
    return pow(g, a, n)






db = loadJSON('db.json')
tempotp = {}


app = FastAPI()

@app.get('/')
async def root():
    return {
        'example': "Hello World"
    }

@app.post("/dhke/")
async def dhke(email: Annotated[str, Form()], pubKeyDHKE: Annotated[int, Form()], n: Annotated[int, Form()], g: Annotated[int, Form()]):
    if email not in db:
        print(f"Failed DHKE : {email}")
        return {"message": "FAILED"}
    pub = registerSharedKey(email, pubKeyDHKE, n, g, db)
    print(f"Done DHKE : {email}")
    return {"message": "PASS", 'pubKey': pub}

# @app.post("/login/")
# async def login(email: Annotated[str, Form()], rsa1024pubkey: Annotated[int, Form()]):
#     if validateLogin(email=email, db=db):
#         registerPubKey(email, rsa1024pubkey, db)
#         print(f"Registered : {email}")
#         return {"message": "DONE"}
#     print(f"Failed to Register : {email}")
#     return {"message": "FAILED"}

@app.post('/login/')
async def login(email: Annotated[str, Form()]):
    if email not in db:
        return {"message": "Not a valid email for voting"}
    sendOTP(email)
    tempotp[email] = 1
    return {"message": "OTP sent"}

@app.post('/otprsa/')
def OTPandRSA(email: Annotated[str, Form()], otp: Annotated[int, Form()], rsaPub_n: Annotated[int, Form()], rsaPub_e: Annotated[int, Form()]):
    if email not in tempotp:
        return {'message': "Invalid Email ID"}
    if otp != 1:
        return {"message": "Invalid OTP"}
    if email not in db:
        return {"message": "error on backend - email not in db but in tempotp"}
    db[email]['rsa'] = {}
    db[email]['rsa']['pub_n'] = rsaPub_n
    db[email]['rsa']['pub_e'] = rsaPub_e
    saveJSON(db, 'db.json')
    return {"message": f"RSA key registered for {email}"}

@app.post('/vote/')
def vote(email:Annotated[str, Form()], yes:Annotated[int, Form()], no:Annotated[int, Form()]):
    if email not in db:
        return {"message": "authenticate 1st"}
    count['yes'] = PaillierCryptosystem.homomorphicADD(paillier_pub, count['yes'], yes)
    count['no'] = PaillierCryptosystem.homomorphicADD(paillier_pub, count['no'], no)
    del db[email]
    return {'message': "Vote Counted, you are being removed"}

@app.get('/liveresults')
def liveresults():
    print(count)
    return {'count': count}

# 8080