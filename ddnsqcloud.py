# -*- coding: utf-8 -*-

#-------------------------------------------------------
# Name:         ddnsqcloud
# Description:  腾讯云IPv6 ddns
# Author:       QPanda
# Date:         2020/3/21 18:21
#-------------------------------------------------------

import hmac
import base64
import hashlib
import time
import re
import subprocess
import random
import urllib.request
from urllib import parse
from hashlib import sha256

secretId = ""
secretKey = ""
endpoint = "cns.api.qcloud.com/v2/index.php"

def getSignature(url):
    data = "GET" + url  # 加密数据
    signature = base64.b64encode(hmac.new(secretKey.encode('utf-8'), data.encode("utf8"), hashlib.sha256).digest())
    return signature

def getSignStr(data, endpoint):
    s = endpoint + "?"
    #query_str = "&".join("%s=%s" % (k, params[k]) for k in sorted(params))
    argDict = sorted(data.items(), key=lambda data:data[0])
    queryStr = urllib.parse.urlencode(argDict)
    return s + queryStr

# 获取IPV6地址 适用于 linux系统
def getIPAddress():
   process = subprocess.Popen("ifconfig | grep global | awk '{print $2}'", shell=True, stdout=subprocess.PIPE)
   output = (process.stdout.read())
   pattern = '(([a-f0-9]{1,4}:){7}[a-f0-9]{1,4})'
   m = re.search(pattern, str(output))
   if m:
       return m.group()
   else:
       return None


def main():

    timestamp = int(time.time())
    nonce = random.randint(1000, 9999)
    ipv6Addr = '2409:8a62:287:9ab0:b128:51fd:fd4c:d4e3' # getIPAddress()

    '''
    获取解析记录列表
    data = {'SecretId': secretId,
              'Region': 'ap-chengdu',
              'Timestamp': timestamp,
              'Nonce': nonce,
              'SignatureMethod': 'HmacSHA256',
              'Action': 'RecordList',
              'offset': '0',
              'length': '20',
              'domain': 'qpanda.vip'}
'''

    data = {
              'SecretId': secretId,
              'Region': 'ap-chengdu',
              'Timestamp': timestamp,
              'Nonce': nonce,
              'SignatureMethod': 'HmacSHA256',
              'Action': 'RecordModify',
              'domain': 'qpanda.vip',
              'recordId': '559670399',
              'subDomain': 'nc',
              'recordType': 'AAAA',
              'recordLine': '默认',
              'value': ipv6Addr
    }


    dataUrl = getSignStr(data, endpoint)
    signature = getSignature(dataUrl)
    getUrl = "https://" + dataUrl + "&Signature=" + parse.quote(signature)
    print(getUrl)

    response = urllib.request.urlopen(getUrl)
    print(response.read().decode('utf-8'))


if __name__ == '__main__':
    main()