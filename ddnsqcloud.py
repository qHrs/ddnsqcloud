# -*- coding: utf-8 -*-

#-------------------------------------------------------
# Name:         ddnsqcloud
# Description:  腾讯云IPv6 ddns
# Author:       QPanda
# Date:         2020/3/21 18:21
#-------------------------------------------------------

import hmac
import base64
import time
import re
import subprocess
import random
import urllib.request
from urllib import parse
from hashlib import sha256


def getSignature(url):
    appsecret = "SSDoALG0UjjUzPO4XjWVEjyxgKOHUP5V".encode('utf-8')  # 秘钥
    data = "GET" + url  # 加密数据
    signature = base64.b64encode(hmac.new(appsecret, data.encode("utf8"), digestmod=sha256).digest())
    return signature


def main():

    secretId = "AKIDsXv46tDggxyiCRd8oL0b9TW6UwGmo4rO"
    timestamp = int(time.time())
    nonce = random.randint(1,10)
    argDict = {'SecretId': 'AKIDsXv46tDggxyiCRd8oL0b9TW6UwGmo4rO',
              'Region': 'ap-chengdu',
              'Timestamp': timestamp,
              'Nonce': nonce,
              'SignatureMethod': 'HmacSHA256',
              'Action': 'RecordList',
              'offset': '0',
              'length': '20',
              'domain': 'qpanda.vip'}

    argDict = sorted(argDict.items(), key=lambda argDict : argDict[0])
    argUrl = urllib.parse.urlencode(argDict)

    getUrl = "cns.api.qcloud.com/v2/index.php?" + argUrl
    signature = getSignature(getUrl)
    getUrl = "https://" + getUrl + "&Signature=" + parse.quote(signature)
    print(getUrl)

    response = urllib.request.urlopen(getUrl)
    print(response.read().decode('utf-8'))

'''
# 获取IPV6地址 适用于 linux系统
def getIPAddress():
   getIPV6_process = subprocess.Popen("ifconfig | grep global | awk '{print $2}'", shell = True, stdout = subprocess.PIPE)
   output = (getIPV6_process.stdout.read())
   ipv6_pattern='(([a-f0-9]{1,4}:){7}[a-f0-9]{1,4})'
   m = re.search(ipv6_pattern, str(output))
   if m:
       return m.group()
   else:
       return None
'''

if __name__ == '__main__':
    main()