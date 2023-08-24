import requests
import json
import logging

PINATA_API_KEY=json.load(open("keys.json", "r"))["pinata_api_key"]
PINATA_SECRET_API_KEY=json.load(open("keys.json", "r"))["pinata_secret_api_key"]


def add_to_ipfs(data_dict, name) :
    headers = {
        'Content-Type': 'application/json',
        'pinata_api_key': PINATA_API_KEY,
        'pinata_secret_api_key': PINATA_SECRET_API_KEY}
    data = {
        'pinataMetadata' : {
            'name' : name
        },
        'pinataContent' : data_dict
    }
    r = requests.post('https://api.pinata.cloud/pinning/pinJSONToIPFS', data=json.dumps(data), headers=headers)
    if not 199<r.status_code<300 :
        logging.warning("POST access to Pinatta refused")
        return None
    else :
        return r.json()['IpfsHash']
print(add_to_ipfs({"test":"json2"},"test_name"))
    
