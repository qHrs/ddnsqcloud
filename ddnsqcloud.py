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
import string
import logging
import urllib.request
from urllib import parse

secretId = ""
secretKey = ""
endpoint = "cns.api.qcloud.com/v2/index.php"
logging.basicConfig(level=10,
			format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
             filename=r'ddns.log')      # filename 是将信息写入 text.log  文件中

def getSignature(url):
    data = "GET" + url  # 加密数据
    signature = base64.b64encode(hmac.new(secretKey.encode('utf-8'), data.encode("utf8"), hashlib.sha256).digest())
    return signature

def getSignStr(data, endpoint):
    s = endpoint + "?"
    queryStr = "&".join("%s=%s" % (k, data[k]) for k in sorted(data))
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
    ipv6Addr = getIPAddress()

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
    getUrl = urllib.parse.quote(getUrl, safe=string.printable)
    # print(getUrl)

    response = urllib.request.urlopen(getUrl)
    logging.info(response.read().decode('utf-8'))  # 正常信息
    # print(response.read().decode('utf-8'))


if __name__ == '__main__':
    main()