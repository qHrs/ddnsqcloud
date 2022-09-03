#-------------------------------------------------------
# Name:         ddnsqcloud
# Description:  腾讯云IPv6 ddns API 3.0
# Author:       QPanda
# Date:         2022/09/03
#-------------------------------------------------------

import time
import re
import subprocess
import logging
import requests

token = ""
url = "https://dnsapi.cn/Record.Modify"
logging.basicConfig(level=10,
			format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
             filename=r'ddns.log')      # filename 是将信息写入 text.log  文件中

# 获取IPV6地址 适用于 linux系统
def getIPAddress():
   process = subprocess.Popen("/sbin/ifconfig | grep global | awk '{print $2}'", shell=True, stdout=subprocess.PIPE)
   output = (process.stdout.read())
   pattern = '(([a-f0-9]{1,4}:){7}[a-f0-9]{1,4})'
   m = re.search(pattern, str(output))
   if m:
       return m.group()
   else:
       return None


def main():

    ipv6Addr = getIPAddress() #'2409:8a62:289:1c10:d50f:2a17:9424:ac23' 

    data = {
              'login_token': token,
              'format':'json',
              'domain': 'qpanda.vip',
              'record_id': '',
              'sub_domain': 'kb',
              'record_type': 'AAAA',
              'record_line': '默认',
              'mx': '1',
              'value': ipv6Addr
    }

    response = requests.post(url, data)
    print(response.json())
    logging.info("{}-{}-{}".format(time.asctime( time.localtime(time.time())),ipv6Addr,response.json()))  # 正常信息

if __name__ == '__main__':
    main()
