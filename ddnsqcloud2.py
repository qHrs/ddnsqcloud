# -*- coding: utf-8 -*-

#-------------------------------------------------------
# Name:         ddnsqcloud2
# Description:  
# Author:       QPanda
# Date:         2020/3/21 22:25
#-------------------------------------------------------

import base64
import hashlib
import hmac
import time
import re
import subprocess
import random
import requests

secret_id = "AKIDsXv46tDggxyiCRd8oL0b9TW6UwGmo4rO"
secret_key = "SSDoALG0UjjUzPO4XjWVEjyxgKOHUP5V"


def get_string_to_sign(method, endpoint, params):
    s = method + endpoint + "/?"
    query_str = "&".join("%s=%s" % (k, params[k]) for k in sorted(params))
    return s + query_str


def sign_str(key, s, method):
    hmac_str = hmac.new(key.encode("utf8"), s.encode("utf8"), method).digest()
    return base64.b64encode(hmac_str)


if __name__ == '__main__':
    ipv6Addr = '2409:8a62:287:9ab0:b128:51fd:fd4c:d4e3'  # getIPAddress()
    timestamp = int(time.time())
    nonce = random.randint(1000, 9999)
    endpoint = "cns.api.qcloud.com/v2/index.php"
    data = {
        'Action': 'RecordList',
        'Nonce': nonce,
        'Region': 'ap-chengdu',
        'SecretId': secret_id,
        'SignatureMethod': 'HmacSHA256',
        'Timestamp': timestamp,
        'domain': 'qpanda.vip',
        'length': '20',
        'offset': '0'
    }
    s = get_string_to_sign("GET", endpoint, data)
    data["Signature"] = sign_str(secret_key, s, hashlib.sha256)
    print(data["Signature"])
    # 此处会实际调用，成功后可能产生计费
    resp = requests.get("https://" + endpoint, params=data)
    print(resp.url)
    print('-----------------------------------')
    print(resp.content)