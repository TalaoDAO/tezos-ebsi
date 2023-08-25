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
    
def add_file_to_pinata (filename) :
    try :
        this_file = open(filename, mode='rb')  # b is important -> binary
    except IOError :
        logging.error('IOEroor open file ')
        return None
    headers = { 'pinata_api_key': PINATA_API_KEY,
              'pinata_secret_api_key':  PINATA_SECRET_API_KEY}
    payload = { 'file' : this_file.read()}
    try :
        response = requests.post('https://api.pinata.cloud/pinning/pinFileToIPFS', files=payload, headers=headers)
    except :
        logging.error('IPFS connexion problem')
        return None
    this_file.close()
    return response.json()['IpfsHash']

print(add_file_to_pinata("nft.png"))
    
