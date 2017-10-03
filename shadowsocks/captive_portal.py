#!/usr/bin/python
# -*- coding: utf-8 -*-
import logging
import time

LOGIN_STATUS_NOT_LOGIN = 0
LOGIN_STATUS_LOGIN = 1


class CaptivePortalGate(object):
    def __init__(self, address_white_list,
                 login_expiration_time=43200,
                 inactive_expiration_time=60):
        self._user_map = {}  # key: IP address, value:is_login
        self._address_white_list = address_white_list
        self._login_expiration_time = login_expiration_time
        self._inactive_expiration_time = inactive_expiration_time

    def can_pass_through(self, client_ip, remote_address_type, remote_address,
                         remote_port):
        is_in_white_list = (remote_address_type,
                            remote_address,
                            remote_port) in self._address_white_list
        return self.is_login(client_ip) or is_in_white_list

    def is_login(self, client_ip):
        return self._user_map.get(
            client_ip,
            {}).get('status', LOGIN_STATUS_NOT_LOGIN) == LOGIN_STATUS_LOGIN

    def login(self, client_ip):
        now = int(time.time())
        self._user_map[client_ip] = dict(
            status=LOGIN_STATUS_LOGIN,
            login_time=now,
            last_active_time=now)
        logging.info("{} login successfully.".format(client_ip))

    def update_active(self, client_ip):
        if client_ip not in self._user_map:
            return
        now = int(time.time())
        self._user_map[client_ip].update(dict(
            last_active_time=now
        ))

    def check_expirations(self):
        logging.info("check_expirations")
        now = int(time.time())
        expired_ips = []
        for ip in self._user_map:
            login_info = self._user_map[ip]
            expired = (login_info['status'] == LOGIN_STATUS_LOGIN and
                       now - login_info['login_time'] >
                       self._login_expiration_time) or \
                      (login_info['status'] == LOGIN_STATUS_LOGIN and
                       now - login_info['last_active_time'] >
                       self._inactive_expiration_time)

            if expired:
                expired_ips.append(ip)

        for ip in expired_ips:
            del self._user_map[ip]
            logging.info("{} is expired and deleted.".format(ip))
