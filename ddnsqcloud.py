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
from hashlib import sha256

def main():
'''
https://cvm.api.qcloud.com/v2/index.php?
Action=DescribeInstances
&SecretId=AKIDsXv46tDggxyiCRd8oL0b9TW6UwGmo4rO
&Region=ap-chengdu-1
&Timestamp=1584785190
&Nonce=11886
&Signature=q/U+S9ETv9t2Tr2nBqrs3rwlKYMu+404mNCu4xh1NAw=
&SignatureMethod=HmacSHA256
&Action=RecordList
&offset=0
&length=20
&domain=qpanda.vip
'''

def getIPAddress():


def getSignature():
    appsecret = "AKIDsXv46tDggxyiCRd8oL0b9TW6UwGmo4rO".encode('utf-8')  # 秘钥
    data = "GETcvm.api.qcloud.com/v2/index.php?Action=RecordList&domain=qpanda.vip&length=20&Nonce=59485&offset=0&Region=ap-chengdu-1&SecretId=AKIDsXv46tDggxyiCRd8oL0b9TW6UwGmo4rO&Signature=mysignature&SignatureMethod=HmacSHA256&Timestamp=1584784792".encode(
        'utf-8')  # 加密数据
    signature = base64.b64encode(hmac.new(appsecret, data, digestmod=sha256).digest())
    return signature



if __name__ == '__main__':
    main()