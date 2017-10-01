class CaptivePortalGate(object):
    def __init__(self, address_white_list):
        self._user_map = {}  # key: IP address, value:is_login
        self._address_white_list = address_white_list

    def can_pass_through(self, client_ip, remote_address_type, remote_address,
                         remote_port):
        is_login = self._user_map.get(client_ip, False)
        is_in_white_list = (remote_address_type,
                            remote_address,
                            remote_port) in self._address_white_list
        return is_login or is_in_white_list

    def login(self, client_ip):
        self._user_map[client_ip] = True

