#!/usr/bin/env python3
from ctf_gameserver import checkerlib
from string import ascii_letters
from random import choice
from hashlib import sha1
import requests as rq
import logging
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os

class BuerographieChecker(checkerlib.BaseChecker):
    PORT = 13731
    if os.environ.get('FLAG_LENGTH') != None:
        FLAG_LENGTH = 37
    else:
        FLAG_LENGTH = 38

    def _generate_random_string(self, size):
        return ''.join(choice(ascii_letters) for x in range(size))

    def _url(self, ip, port):
        return 'http://[' + self.ip + ']:' + str(self.PORT)

    def place_flag(self, tick):
        url = self._url(self.ip, self.PORT)
        username = 'BGU_' + self._generate_random_string(12)
        password = self._generate_random_string(16)
        logging.info(f'pf: {username} login with {password}')
        flag = checkerlib.get_flag(tick)

        if tick % 2 == 1:
            # place flag in message at odd ticks
            logging.info(f'pf msg: {flag=}')
            message = flag
            supply_name = self._generate_random_string(12)
            supply = self._generate_random_string(12)
        else:
            # place flag in supply at even ticks
            logging.info(f'pf sup: {flag=}')
            message = self._generate_random_string(20)
            supply_name = 'BGS_' + self._generate_random_string(12)
            supply = flag

        try:
            s = rq.Session()
            r = s.post(url + '/register', data = {'user': username, 'pass': password, 'pass2': password})
            if r.status_code != 201:
                logging.error(f'pf: register failed {r.status_code} {r.text}')
                return checkerlib.CheckResult.FAULTY

            r = s.post(url + '/login', data = {'user': username, 'pass': password})
            if r.status_code != 200:
                logging.error(f'pf: login failed {r.status_code} {r.text}')
                return checkerlib.CheckResult.FAULTY

            r = s.post(url + '/staff/message', data = {'message': message})
            if r.status_code != 200:
                logging.error(f'pf msg: post message failed {r.status_code} {r.text}')
                return checkerlib.CheckResult.FAULTY

            r = s.post(url + '/staff/supply', files = {'supply': (supply_name, supply)})
            if r.status_code != 201:
                logging.error(f'pf sup: upload supply failed {r.status_code} {r.text}')
                return checkerlib.CheckResult.FAULTY

        except Exception as e:
            logging.error(f'pf: connection failed {e}')
            return checkerlib.CheckResult.DOWN

        checkerlib.store_state(str(tick), {
            'username': username,
            'password': password,
            'message': message,
            'supplyname': supply_name,
            'supply': supply
        })

        checkerlib.set_flagid(f'{{"username": "{username}", "supplyname": "{supply_name}"}}')
        logging.info(f'pf: place flag OK!')

        return checkerlib.CheckResult.OK


    def check_service(self):
        url = self._url(self.ip, self.PORT)
        try:
            s1 = rq.Session()
            r = s1.get(url + '/health')
            if r.status_code != 200:
                logging.error(f'cs: health check failed {r.status_code} {r.text}')
                return checkerlib.CheckResult.FAULTY

            logging.info(f'cs: cross-access message')
            username1 = self._generate_random_string(16)
            password1 = self._generate_random_string(16)
            logging.info(f'cs: user1 {username1} login with {password1}')
            r = s1.post(url + '/register', data = {'user': username1, 'pass': password1, 'pass2': password1})
            if r.status_code != 201:
                logging.error(f'cs: register failed {r.status_code} {r.text}')
                return checkerlib.CheckResult.FAULTY
            r = s1.post(url + '/login', data = {'user': username1, 'pass': password1})
            if r.status_code != 200:
                logging.error(f'cs: login failed {r.status_code} {r.text}')
                return checkerlib.CheckResult.FAULTY

            username2 = self._generate_random_string(16)
            password2 = self._generate_random_string(16)
            logging.info(f'cs: user2 {username2} login with {password2}')
            s2 = rq.Session()
            r = s2.post(url + '/register', data = {'user': username2, 'pass': password2, 'pass2': password2})
            if r.status_code != 201:
                logging.error(f'cs: register failed {r.status_code} {r.text}')
                return checkerlib.CheckResult.FAULTY

            r = s2.post(url + '/login', data = {'user': username2, 'pass': password2})
            if r.status_code != 200:
                logging.error(f'cs: login failed {r.status_code} {r.text}')
                return checkerlib.CheckResult.FAULTY

            message2 = self._generate_random_string(8)
            r = s2.post(url + '/staff/message', data = {'message': message2})
            if r.status_code != 200:
                logging.error(f'cs msg: post message failed {r.status_code} {r.text}')
                return checkerlib.CheckResult.FAULTY

            # this kind of fix shouldn't happen
            r = s1.get(url + f'/staff/message/{username2}')
            if r.status_code != 200:
                logging.error(f'cs: user1 {username1} cant cross-access message of user2 {username2}')
                return checkerlib.CheckResult.FAULTY
            m = r.json()['message']
            if not m:
                logging.error(f'cs: message of {username2} empty')
                return checkerlib.CheckResult.FAULTY

            logging.info(f'cs: cross-access message {m} works')
            return checkerlib.CheckResult.OK

        except Exception as e:
            logging.error(f'cs: connection failed {e}')
            return checkerlib.CheckResult.DOWN


    def check_flag(self, tick):
        url = self._url(self.ip, self.PORT)
        staff = checkerlib.load_state(str(tick))
        if staff == None:
            logging.error(f'cf: staff not found')
            return checkerlib.CheckResult.FLAG_NOT_FOUND

        username = staff['username']
        password = staff['password']
        message_local = staff['message']
        supply_name = staff['supplyname']
        supply_local = staff['supply']
        logging.info(f'cf: {staff}')
        if not username or not password or not message_local or not supply_name or not supply_local:
            logging.error(f'cf: one of the fields is none')
            return checkerlib.CheckResult.FAULTY

        try:
            s = rq.Session()
            r = s.post(url + '/login', data = {'user': username, 'pass': password})
            if r.status_code != 200:
                logging.error(f'cf: login failed {r.status_code} {r.text}')
                return checkerlib.CheckResult.FAULTY

            r = s.get(url + f'/staff/message/{username}')
            if r.status_code != 200:
                logging.error(f'cf: get message failed {r.status_code} {r.text}')
                return checkerlib.CheckResult.FAULTY

            message_remote = r.json()['message']
            if not message_remote:
                logging.error(f'cf: message empty')
                return checkerlib.CheckResult.FLAG_NOT_FOUND

            hash1 = sha1()
            hash1.update((username + supply_name).encode())
            digest = hash1.hexdigest()

            r = s.get(url + '/staff/supply/' + digest)
            if r.status_code != 200:
                logging.error(f'cf: login failed {r.status_code} {r.text}')
                return checkerlib.CheckResult.FAULTY
            supply_remote = r.text
            if not supply_remote:
                logging.error(f'cf: supply empty')
                return checkerlib.CheckResult.FLAG_NOT_FOUND

        except Exception as e:
            logging.error(f'cf: connection failed {e}')
            return checkerlib.CheckResult.DOWN

        if tick % 2 == 1:
            # check flag in message at odd ticks
            if not message_remote:
                logging.error('cf msg: message empty')
                return checkerlib.CheckResult.FLAG_NOT_FOUND
            if len(message_remote) < 2 * self.FLAG_LENGTH:
                logging.error(f'cf msg: message too short {message_remote}')
                return checkerlib.CheckResult.FLAG_NOT_FOUND
            encmsg = message_remote[0 : 2*self.FLAG_LENGTH]
            encmsg = bytes.fromhex(encmsg)
            kdf = PBKDF2HMAC(algorithm = hashes.SHA256(), length = len(encmsg), salt = b'salt', iterations = 10)
            key = kdf.derive(password.encode())
            msg = [a ^ b for (a, b) in zip(encmsg, key)]
            msg = ''.join(chr(c) for c in msg)

            if msg != message_local:
                logging.error(f'cf msg: {message_local=} != {msg=}')
                return checkerlib.CheckResult.FLAG_NOT_FOUND
            else:
                logging.info(f'cf msg: check message flag OK!')
                return checkerlib.CheckResult.OK

        else:
            # check flag in supply at odd ticks
            if supply_local != supply_remote:
                logging.error(f'cf sup: {supply_local=} != {supply_remote}')
                return checkerlib.CheckResult.FLAG_NOT_FOUND
            else:
                logging.info(f'cf sup: check supply flag OK!')
                return checkerlib.CheckResult.OK


if __name__ == '__main__':
    checkerlib.run_check(BuerographieChecker)
