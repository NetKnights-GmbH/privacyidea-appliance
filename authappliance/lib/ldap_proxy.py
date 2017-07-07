import re

import configobj
import validate
from pi_ldapproxy.config import load_config

LDAP_PROXY_CONFIG_FILE = '/etc/privacyidea/proxy.ini'

DEFAULT_PROXY_CONFIG = """
[privacyidea]
instance = http://10.0.0.1

[ldap-backend]
endpoint = tcp:host=10.0.0.2:port=389
use-tls = false
test-connection = true

[service-account]
dn =
password =

[ldap-proxy]
endpoint =
passthrough-binds =
bind-service-account =
allow-search =

[user-mapping]
strategy =
pattern =

[realm-mapping]
strategy = static
realm =

[bind-cache]
enabled = false

[app-cache]
enabled = false
"""

def extract_from_endpoint(endpoint, attribute):
    match = re.search(attribute + '=([^:]+)', endpoint)
    if match is not None:
        return match.group(1)
    else:
        return ''

class LDAPProxyConfig(object):
    def __init__(self, filename=LDAP_PROXY_CONFIG_FILE):
        self.filename = filename
        self.config = load_config(self.filename) # TODO: This exits if config is malformed!

    def save(self):
        with open(self.filename, 'w') as f:
            self.config.write(f)

    @property
    def backend_settings(self):
        """
        :return: a tuple (protocol, host, port) where:
         * protocol is LDAP, LDAPS or the empty string
         * host is a string (which may be empty)
         * port is a string (which may be empty)
        """
        endpoint = self.config.get('ldap-backend', {}).get('endpoint', '')
        if endpoint.startswith('tcp:'):
            protocol = 'LDAP'
        elif endpoint.startswith('tls:'):
            protocol = 'LDAPS'
        host = extract_from_endpoint(endpoint, 'host')
        port = extract_from_endpoint(endpoint, 'port')
        return protocol, host, port

    def set_backend_endpoint(self, endpoint):
        self.config.setdefault('ldap-backend', {})['endpoint'] = endpoint
        self.save()

    @property
    def proxy_settings(self):
        """
        :return: a tuple (port, interface) where
         * port is a string (which may be empty)
         * interface is a string (which may be empty)
        """
        endpoint = self.config.get('ldap-proxy', {}).get('endpoint', '')
        port = extract_from_endpoint(endpoint, 'port')
        interface = extract_from_endpoint(endpoint, 'interface')
        return port, interface

    def set_proxy_endpoint(self, endpoint):
        self.config.setdefault('ldap-proxy', {})['endpoint'] = endpoint
        self.save()

    @property
    def passthrough_binds(self):
        return self.config.get('ldap-proxy', {}).get('passthrough-binds', [])

    def set_passthrough_binds(self, passthrough_binds):
        self.config.setdefault('ldap-proxy', {})['passthrough-binds'] = passthrough_binds
        self.save()

    def add_passthrough_bind(self, dn):
        passthrough_binds = self.passthrough_binds
        passthrough_binds.append(dn)
        self.set_passthrough_binds(passthrough_binds)

    def remove_passthrough_bind(self, dn):
        passthrough_binds = self.passthrough_binds
        passthrough_binds.remove(dn)
        self.set_passthrough_binds(passthrough_binds)

    @property
    def service_account(self):
        section = self.config.get('service-account', {})
        return section.get('dn', ''), section.get('password', '')

    def set_service_account(self, dn, password):
        self.config['service-account'] = {
            'dn': dn,
            'password': password
        }
        self.save()

    @property
    def user_mapping_strategy(self):
        return self.user_mapping_config.get('strategy', '')

    @property
    def user_mapping_config(self):
        return self.config.get('user-mapping', {})

    def set_user_mapping_config(self, config):
        self.config['user-mapping'] = config
        self.save()