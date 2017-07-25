#!/usr/bin/env python
import urllib2, sys
from bs4 import BeautifulSoup as bs4

# HTTP-proxies (if response == 403):
# 46.166.129.226, 109.238.2.83, 176.193.213.61

dmn = sys.argv[1]
prx = urllib2.ProxyHandler({'http' : 'http://46.166.129.226:80'})
opn = urllib2.build_opener(prx)
urllib2.install_opener(opn)
req = urllib2.urlopen('https://www.virustotal.com/en/domain/' + dmn + '/information')
res = req.read()
sou = bs4(res, 'html.parser')
fin = []

for sdn in sou.findAll('a', {'target' : '_blank'}):
	if dmn in sdn.text:
		fin.append(sdn.text.strip())

for sdn in fin:
print(sdn)
