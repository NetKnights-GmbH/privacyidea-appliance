import socket
from contextlib import contextmanager

import os
import re

import configobj
import validate
from pi_ldapproxy.config import load_config

from authappliance.lib.appliance import ApacheConfig

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
        self.reset()
        self.autosave_enabled = True

    def reset(self):
        if self.exists:
            self.config = load_config(self.filename)  # TODO: This exits if config is malformed!
        else:
            self.config = configobj.ConfigObj()

    def set_default_config(self):
        """
        set all config options that are not configurable by any accessor methods below
        :return:
        """
        self.config['bind-cache'] = {'enabled': False}
        self.config['app-cache'] = {'enabled': False}
        self.config.setdefault('ldap-backend', {})['use-tls'] = False
        self.config.setdefault('ldap-backend', {})['test-connection'] = False # TODO
        privacyidea_cert, _ = ApacheConfig().get_certificates()
        self.config['privacyidea'] = {
            'instance': 'https://{}'.format(socket.getfqdn()), # TODO: should probably use the hostname from the cert?
                                                               # Or disable validation entirely?
            'certificate': privacyidea_cert,
        }
        self.autosave()

    @property
    def exists(self):
        return os.path.exists(self.filename)

    def save(self):
        """
        Save configuration (i.e. write it to the disk).
        """
        with open(self.filename, 'w') as f:
            self.config.write(f)

    def autosave(self):
        """
        Save configuration, but only if autosave is enabled.
        """
        if self.autosave_enabled:
            self.save()

    @contextmanager
    def set_autosave(self, autosave_enabled):
        """
        Context manager that can be used to temporarily disable config autosaving::

            with c.set_autosave(False):
                # ...
                # all operations here will not automatically save the config
                # but this will:
                c.save()

        """
        old_value = self.autosave_enabled
        self.autosave_enabled = autosave_enabled
        yield
        self.autosave_enabled = old_value

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
        else:
            protocol = ''
        host = extract_from_endpoint(endpoint, 'host')
        port = extract_from_endpoint(endpoint, 'port')
        return protocol, host, port

    def set_backend_endpoint(self, endpoint):
        self.config.setdefault('ldap-backend', {})['endpoint'] = endpoint
        self.autosave()

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
        self.autosave()

    @property
    def passthrough_binds(self):
        return self.config.get('ldap-proxy', {}).get('passthrough-binds', [])

    def set_passthrough_binds(self, passthrough_binds):
        self.config.setdefault('ldap-proxy', {})['passthrough-binds'] = passthrough_binds
        self.autosave()

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
        self.autosave()

    @property
    def user_mapping_strategy(self):
        return self.user_mapping_config.get('strategy', '')

    @property
    def user_mapping_config(self):
        return self.config.get('user-mapping', {})

    def set_user_mapping_config(self, config):
        self.config['user-mapping'] = config
        self.autosave()

    @property
    def realm_mapping_strategy(self):
        return self.realm_mapping_config.get('strategy', '')

    @property
    def realm_mapping_config(self):
        return self.config.get('realm-mapping', {})

    def set_realm_mapping_config(self, config):
        self.config['realm-mapping'] = config
        self.autosave()

    @property
    def search_permissions(self):
        ldap_proxy_settings = self.config.setdefault('ldap-proxy', {})
        return (ldap_proxy_settings.get('allow-search', False),
                ldap_proxy_settings.get('bind-service-account', False))

    def set_search_permissions(self, allow_search, bind_service_account):
        ldap_proxy_settings = self.config.setdefault('ldap-proxy', {})
        ldap_proxy_settings['allow-search'] = allow_search
        ldap_proxy_settings['bind-service-account'] = bind_service_account
        self.autosave()