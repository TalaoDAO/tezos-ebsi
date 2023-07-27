
from hexbytes import HexBytes
from eth_account.messages import encode_defunct,defunct_hash_message
import hashlib
from flask import Flask,render_template, request, jsonify, redirect,session, Response,send_file
from flask_mobility import Mobility
import uuid 
from flask_qrcode import QRcode
import json
import redis
import string
import random
import os
import environment
from datetime import datetime, timedelta
import didkit
from pytezos.crypto import key
import logging
import requests
from flask_session import Session
from flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration, ClientMetadata
from flask_pyoidc.user_session import UserSession
import flask


logging.basicConfig(level=logging.INFO)
myenv = os.getenv('MYENV')
if not myenv :
   myenv='achille'
mode = environment.currentMode(myenv)
#nft api config
domain = "https://api.dev.pyratzlabs.com"
api_key = json.dumps(json.load(open("keys.json", "r"))["api_key"])
headers = {
    "Authorization": f"Token {api_key}",
}
blockchain_id = 3
account_id = 122
fa2_contract_id = 'fc2055a8-8a3a-423f-9d81-f4b543c46abf'
fa2_contract_address = 'KT1VuCBGQW4WakHj1PXhFC1G848dKyNy34kB'
#app config
app = Flask(__name__,static_folder=os.path.abspath('/home/achille/static'))
QRcode(app)
app.secret_key =json.dumps(json.load(open("keys.json", "r"))["appSecretKey"])
Mobility(app)
app.config.update(
    OIDC_REDIRECT_URI = mode.server+"/redirect", # your application redirect uri. Must not be used in your code
    SECRET_KEY = json.dumps(json.load(open("keys.json", "r"))["appSecretKey"]) # your application secret code for session, random
)
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_COOKIE_NAME'] = 'talao'
app.config['SESSION_TYPE'] = 'redis' # Redis server side session
app.config['SESSION_FILE_THRESHOLD'] = 100
sess = Session()
sess.init_app(app)
"""
Init OpenID Connect client PYOIDC with the 3 bridge parameters :  client_id, client_secret and issuer URL
"""
client_metadata = ClientMetadata(
    client_id='fofadhfrez',
    client_secret= json.dumps(json.load(open("keys.json", "r"))["client_secret"]),
    post_logout_redirect_uris=['http://127.0.0.1:4000/logout']) # your post logout uri (optional)

provider_config = ProviderConfiguration(issuer='https://talao.co/sandbox/ebsi',
                                        client_metadata=client_metadata)

auth = OIDCAuthentication({'default': provider_config}, app)

characters = string.digits
red= redis.Redis(host='127.0.0.1', port=6379, db=0)


def mint_nft(address):
    token_id=int(requests.get("https://api.ghostnet.tzkt.io/v1/tokens?contract=KT1VuCBGQW4WakHj1PXhFC1G848dKyNy34kB&sort.desc=tokenId&limit=1").json()[0]["tokenId"])+1
    fa2_token_data = {
    'contract': fa2_contract_id, 
    'sender': account_id, 
    'owner': address, 
    'token_id': token_id, 
    'token_amount': 1, 
    'ipfs_uri': 'ipfs://bafkreiexhisb6dzzrj4ccmavpsjnyya6nh5b3kk3y6dopi3dt3rtpvr2gq',
    }
    mint_call_resp = requests.post(
        f"{domain}/fa2-token/",
        data=fa2_token_data,
        headers=headers,
    )
    mint_monitoring_resp = requests.get(
        f"{domain}/fa2-token/{str(mint_call_resp.json()['id'])}/",
        headers=headers,
    )
    return mint_monitoring_resp.json()["state"]


def char2Bytes(text):
    return text.encode('utf-8').hex()


def create_payload (input, type) :
  formattedInput = ' '.join([
    'Tezos Signed Message:',
    'altme.io',
    datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
    input
  ])
  sep = '05' if type == 'MICHELINE'  else  '03'
  bytes = char2Bytes(formattedInput)
  return  sep + '01' + '00' + char2Bytes(str(len(bytes)))  + bytes


def init_app(app,red) :
    app.add_url_rule('/',  view_func=dapp_wallet, methods = ['GET', 'POST'], defaults={'red' : red})
    app.add_url_rule('/validate_sign' , view_func=validate_sign,methods=['GET'])
    app.add_url_rule('/stream',  view_func=wallet_link_stream, methods = ['GET', 'POST'], defaults={'red' : red})
    return


@auth.oidc_auth('default')
def dapp_wallet(red):
    user_session = UserSession(flask.session)   
    logging.info(user_session.access_token)
    logging.info(user_session.id_token)
    logging.info(user_session.userinfo)

    if request.method == 'GET' :
        session['is_connected'] = True
        nonce = ''.join(random.choice(characters) for i in range(6))
        session["nonce"] = "Verify address owning for Altme : " + nonce        
        session['cryptoWalletPayload'] = create_payload(session['nonce'],'MICHELINE')
        return render_template('dapp.html',nonce= session['cryptoWalletPayload'],link=mode.server+"validate_sign",)

        if not request.MOBILE:
            return render_template('dapp.html',nonce= session['cryptoWalletPayload'],link=mode.server+"validate_sign",)
        else:
            return render_template('dappMOBILE.html',nonce= session['cryptoWalletPayload'],link=mode.server+"validate_sign")
    else :
        if not session.get('is_connected') :
            return jsonify('Unauthorized'), 403
        id = str(uuid.uuid1())
        red.setex(id, 180, json.dumps({"associatedAddress" : session["addressVerified"],
                                        "accountName" : request.headers["wallet"],
                                        "cryptoWalletPayload" : str(session['nonce']),
                                        "cryptoWalletSignature" : request.headers["cryptoWalletSignature"]
                                        
                                }))        
        logging.info({"associatedAddress" : session["addressVerified"],
                                        "accountName" : request.headers["wallet"],
                                        "cryptoWalletPayload" : str(session['nonce']),
                                        "cryptoWalletSignature" : request.headers["cryptoWalletSignature"]
                                        
                                })
        status=mint_nft(session["addressVerified"])
        data={"status":status}
        return json.dumps(data)


# server event push for user agent EventSource
def wallet_link_stream(red):
    def event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('altme-identity')
        for message in pubsub.listen():
            if message['type']=='message':
                yield 'data: %s\n\n' % message['data'].decode()  
    headers = { "Content-Type" : "text/event-stream",
                "Cache-Control" : "no-cache",
                "X-Accel-Buffering" : "no"}
    return Response(event_stream(red), headers=headers)
        

def validate_sign():
        try:
            logging.info(key.Key.from_encoded_key(request.headers.get('pubKey')).verify(request.headers.get('signature'), session.get('cryptoWalletPayload')))
            logging.info("address verified : " +key.Key.from_encoded_key(request.headers.get('pubKey')).public_key_hash())
            if(key.Key.from_encoded_key(request.headers.get('pubKey')).public_key_hash()!=request.headers.get('address')):
                return redirect (mode.server+'error',403)
            session["addressVerified"]=key.Key.from_encoded_key(request.headers.get('pubKey')).public_key_hash()
            return({'status':'ok'}),200
        except ValueError:
            pass
            return redirect (mode.server+'error',403)


@app.route('/error',methods=['GET'])
def error():
    logging.info(error)
    return render_template("error.html")


@app.route('/static/<filename>',methods=['GET'])
def serve_static(filename):
    return send_file('./static/'+filename, download_name=filename)


@app.route('/logout',methods=['POST'])
def logout():
    user_session = UserSession(flask.session)   
    user_session.clear()
    session.clear()
    return "ok",200


@app.route('/verifier',methods=['GET'])
def verifier():
    return render_template("diploma_verifier.html",url="https://altme.io/")


init_app(app,red)


if __name__ == '__main__':
    logging.info("app init")

    
    app.run( host = mode.IP, port= mode.port, debug =True)


