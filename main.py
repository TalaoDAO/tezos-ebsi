from flask import Flask, render_template, request, jsonify, redirect, session, Response, send_file
import uuid
from flask_qrcode import QRcode
import json
import redis
import string
import random
import os
import environment
from datetime import datetime, timedelta
from pytezos.crypto import key
import logging
import requests
from flask_session import Session
from flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration, ClientMetadata
from flask_pyoidc.user_session import UserSession
import flask
import base64

logging.basicConfig(level=logging.INFO)
myenv = os.getenv('MYENV')
if not myenv:
    myenv = 'achille'
mode = environment.currentMode(myenv)
# nft api config
DOMAIN = "https://api.dev.pyratzlabs.com"
HEADERS = {
    "Authorization": f"Token {json.load(open('keys.json', 'r'))['api_key']}",
}
#ghostnet config
#blockchain_id = 3
#ACCOUNT_ID = 122
#FA2_CONTRACT_ADDRESS = 'KT1VuCBGQW4WakHj1PXhFC1G848dKyNy34kB'
#FA2_CONTRACT_ID = 'fc2055a8-8a3a-423f-9d81-f4b543c46abf'

blockchain_id = 6
ACCOUNT_ID = 130
FA2_CONTRACT_ID = "cf8db132-a55b-4459-85c7-b06e09f9c30a"
FA2_CONTRACT_ADDRESS = 'KT1Wv4dPiswWYj2H9UrSrVNmcMd9w5NtzczG'
PINATA_API_KEY = json.load(open("keys.json", "r"))["pinata_api_key"]
PINATA_SECRET_API_KEY = json.load(open("keys.json", "r"))[
    "pinata_secret_api_key"]
# app config
app = Flask(__name__, static_folder=os.path.abspath('/home/achille/static'))
QRcode(app)
app.secret_key = json.load(open("keys.json", "r"))["appSecretKey"]
app.config.update(
    # your application redirect uri. Must not be used in your code
    OIDC_REDIRECT_URI=mode.server+"redirect",
    # your application secret code for session, random
    SECRET_KEY=json.dumps(json.load(open("keys.json", "r"))["appSecretKey"])
)
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_COOKIE_NAME'] = 'talao'
app.config['SESSION_TYPE'] = 'redis'  # Redis server side session
app.config['SESSION_FILE_THRESHOLD'] = 100
sess = Session()
sess.init_app(app)
"""
Init OpenID Connect client PYOIDC with the 3 bridge parameters :  client_id, client_secret and issuer URL
"""
client_metadata = ClientMetadata(
    client_id='fofadhfrez',
    client_secret=json.load(open("keys.json", "r"))["client_secret"],
    # post_logout_redirect_uris=['http://127.0.0.1:4000/logout']
    # your post logout uri (optional)
)
provider_config = ProviderConfiguration(issuer='https://talao.co/sandbox/ebsi',
                                        client_metadata=client_metadata)
auth = OIDCAuthentication({'default': provider_config}, app)

red = redis.Redis(host='127.0.0.1', port=6379, db=0)


def mint_nft(address):
    token_id = int(requests.get(
        "https://api.ghostnet.tzkt.io/v1/tokens?contract=KT1VuCBGQW4WakHj1PXhFC1G848dKyNy34kB&sort.desc=tokenId&limit=1").json()[0]["tokenId"])+1
    ipfs_uri = add_to_ipfs(token_id)
    logging.info(ipfs_uri)
    fa2_token_data = {
        'contract': FA2_CONTRACT_ID,
        'sender': ACCOUNT_ID,
        'owner': address,
        'token_id': token_id,
        'token_amount': 1,
        'ipfs_uri': "ipfs://"+ipfs_uri,
    }
    logging.info(fa2_token_data)
    mint_call_resp = requests.post(
        f"{DOMAIN}/fa2-token/",
        data=fa2_token_data,
        headers=HEADERS,
    )
    id = str(mint_call_resp.json()['id'])
    mint_monitoring_resp = requests.get(
        f"{DOMAIN}/fa2-token/{id}/",
        headers=HEADERS,
    )
    nft = mint_monitoring_resp.json()
    logging.info(nft)
    return json.dumps({"state": nft["state"], "id": id})


def char2Bytes(text):
    return text.encode('utf-8').hex()


def get_payload_from_token(token):
    """
    For verifier
    check the signature and return None if failed
    """
    payload = token.split('.')[1]
    # solve the padding issue of the base64 python lib
    payload += "=" * ((4 - len(payload) % 4) % 4)
    return json.loads(base64.urlsafe_b64decode(payload).decode())


def add_to_ipfs(id):
    logging.info('adding to ipfs')
    name="The Alumnis by Tezos "+str(id)
    headers = {
        'Content-Type': 'application/json',
        'pinata_api_key': PINATA_API_KEY,
        'pinata_secret_api_key': PINATA_SECRET_API_KEY}
    data = {
        'pinataMetadata': {
            'name': name
        },
        'pinataContent': {
            "name": name,
            "editions": "1",
            "description": "To reward newly graduated European students who have claimed their diploma in the verifiable credential format (EBSI), Altme and the Tezos Foundation are offering a unique non-transferable NFT to each student ! Each NFT represents a unique proof of graduation and offers exclusive advantages, benefits and opportunities in the Tezos ecosystem.",
            "symbol": "ALM",
            "artifactUri": "ipfs://QmWe1VkU9UffbmsNzB7eXvdLnXZGPBn2jMVWhcqCweKANq",
            "displayUri": "ipfs://QmcUBZMW7HAX6VHtqP3V5yxx52jcj94j9rpbtuNMgGpRtf",
            "thumbnailUri": "ipfs://QmcUBZMW7HAX6VHtqP3V5yxx52jcj94j9rpbtuNMgGpRtf",
            "formats": [
                {
                    "uri": "ipfs://bafkreibonqljtq7qy7qod33ncplxljpipjvg4qddhnusicypqz6dm6qb5e",
                    "mimeType": "model/glb-binary"
                },
                {
                    "uri": "ipfs://bafybeicz2hep264bj3teyqiccovx3zez454mi57cd7ozzsbk3i4xthruxy",
                    "mimeType": "image/png"
                },
                {
                    "uri": "ipfs://bafybeicz2hep264bj3teyqiccovx3zez454mi57cd7ozzsbk3i4xthruxy",
                    "mimeType": "image/png"
                }
            ],
        }
    }
    r = requests.post('https://api.pinata.cloud/pinning/pinJSONToIPFS',
                      data=json.dumps(data), headers=headers)
    if not 199 < r.status_code < 300:
        logging.warning("POST access to Pinatta refused")
        return None
    else:
        logging.info('added to ipfs')
        return r.json()['IpfsHash']


def create_payload(input, type):
    formattedInput = ' '.join([
        'Tezos Signed Message:',
        'altme.io',
        datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        input
    ])
    sep = '05' if type == 'MICHELINE' else '03'
    bytes = char2Bytes(formattedInput)
    return sep + '01' + '00' + char2Bytes(str(len(bytes))) + bytes


def init_app(app, red):
    app.add_url_rule('/',  view_func=dapp_wallet,
                     methods=['GET', 'POST'], defaults={'red': red})
    app.add_url_rule('/validate_sign',
                     view_func=validate_sign, methods=['GET'])
    app.add_url_rule('/stream',  view_func=wallet_link_stream,
                     methods=['GET', 'POST'], defaults={'red': red})
    return


@auth.oidc_auth('default')
def dapp_wallet(red):
    user_session = UserSession(flask.session)
    logging.info(get_payload_from_token(
        user_session.userinfo["vp_token_payload"]["vp"]["verifiableCredential"][0]))
    if request.method == 'GET':
        characters = string.digits
        session['is_connected'] = True
        nonce = ''.join(random.choice(characters) for i in range(6))
        session["nonce"] = "Verify address owning for Altme : " + nonce
        session['cryptoWalletPayload'] = create_payload(
            session['nonce'], 'MICHELINE')
        return render_template('dapp.html', nonce=session['cryptoWalletPayload'], link=mode.server+"validate_sign",)
    else:
        if not session.get('is_connected'):
            return jsonify('Unauthorized'), 403
        id = str(uuid.uuid1())
        """red.setex(id, 180, json.dumps({"associatedAddress" : session["addressVerified"],
                                        "accountName" : request.headers["wallet"],
                                        "cryptoWalletPayload" : str(session['nonce']),
                                        "cryptoWalletSignature" : request.headers["cryptoWalletSignature"]
                                        
                                }))        
        logging.info({"associatedAddress" : session["addressVerified"],
                                        "accountName" : request.headers["wallet"],
                                        "cryptoWalletPayload" : str(session['nonce']),
                                        "cryptoWalletSignature" : request.headers["cryptoWalletSignature"]
                                        
                                })"""
        mint = json.loads(mint_nft(session["addressVerified"]))
        status = mint["state"]
        id = mint["id"]
        data = {"status": status, "id": id}
        return json.dumps(data)


# server event push for user agent EventSource
def wallet_link_stream(red):
    def event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('altme-identity')
        for message in pubsub.listen():
            if message['type'] == 'message':
                yield 'data: %s\n\n' % message['data'].decode()
    headers = {"Content-Type": "text/event-stream",
               "Cache-Control": "no-cache",
               "X-Accel-Buffering": "no"}
    return Response(event_stream(red), headers=headers)


def validate_sign():
    try:
        logging.info(key.Key.from_encoded_key(request.headers.get('pubKey')).verify(
            request.headers.get('signature'), session.get('cryptoWalletPayload')))
        logging.info("address verified : " + key.Key.from_encoded_key(
            request.headers.get('pubKey')).public_key_hash())
        if (key.Key.from_encoded_key(request.headers.get('pubKey')).public_key_hash() != request.headers.get('address')):
            return redirect(mode.server+'error', 403)
        session["addressVerified"] = key.Key.from_encoded_key(
            request.headers.get('pubKey')).public_key_hash()
        return ({'status': 'ok'}), 200
    except ValueError:
        pass
        return redirect(mode.server+'error', 403)


@app.route('/error', methods=['GET'])
def error():
    logging.info(error)
    return render_template("error.html")


@app.route('/static/img/<filename>', methods=['GET'])
def serve_img(filename):
    return send_file('./static/img/'+filename, download_name=filename)


@app.route('/static/<filename>', methods=['GET'])
def serve_static(filename):
    return send_file('./static/'+filename, download_name=filename)


@app.route('/logout', methods=['POST'])
def logout():
    user_session = UserSession(flask.session)
    user_session.clear()
    session.clear()
    return "ok", 200


@app.route('/verifier', methods=['GET'])
def verifier():
    return render_template("diploma_verifier.html", url="https://altme.io/")


@app.route('/status_nft', methods=['GET'])
def status():
    id = request.headers["id"]
    mint_monitoring_resp = requests.get(
        f"{DOMAIN}/fa2-token/{id}/",
        headers=HEADERS,
    )
    nft = mint_monitoring_resp.json()
    logging.info(nft)
    return json.dumps({"state": nft["state"]})


init_app(app, red)


if __name__ == '__main__':
    logging.info("app init")

    app.run(host=mode.IP, port=mode.port, debug=True)
