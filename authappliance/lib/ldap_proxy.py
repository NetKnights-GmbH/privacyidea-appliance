# -*- coding: utf-8 -*-
#  copyright 2017-2018 friedrich.weber@netknights.it
#  License:  AGPLv3
#  contact:  http://www.privacyidea.org
#
# This code is free software; you can redistribute it and/or
# License as published by the Free Software Foundation; either
# version 3 of the License, or any later version.
#
# This code is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU AFFERO GENERAL PUBLIC LICENSE for more details.
#
# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
import socket
from contextlib import contextmanager

import os
import re

import configobj
import sys

import subprocess

import validate

from authappliance.lib.appliance import ApacheConfig

LDAP_PROXY_CONFIG_FILE = '/etc/privacyidea-ldap-proxy/proxy.ini'
LDAP_PROXY_UNIT_FILE = 'privacyidea-ldap-proxy.service'

SYSTEMD_MANAGER_INTERFACE = 'org.freedesktop.systemd1.Manager'

CONFIG_SPEC = """
[privacyidea]
instance = string
certificate = string(default='')

[ldap-backend]
endpoint = string
use-tls = boolean
test-connection = boolean(default=True)

[ldap-proxy]
endpoint = string
passthrough-binds = force_list
bind-service-account = boolean(default=False)
allow-search = boolean(default=False)

[service-account]
dn = string
password = string

[bind-cache]
enabled = boolean
timeout = integer(default=3)

[app-cache]
enabled = boolean
timeout = integer(default=3)
attribute = string(default='objectclass')
value-prefix = string(default='App-')

[user-mapping]
strategy = string

[realm-mapping]
strategy = string
"""


def extract_from_endpoint(endpoint, attribute):
    match = re.search(attribute + r'=([^:]+)', endpoint)
    if match is not None:
        return match.group(1)
    else:
        return ''


def _load_config(filename):
    with open(filename, 'r') as f:
        config = configobj.ConfigObj(f, configspec=CONFIG_SPEC.splitlines())

    validator = validate.Validator()
    result = config.validate(validator, preserve_errors=True)
    if not result:
        print('Invalid LDAP Proxy configuration at {!r}: {!r}'.format(filename, result))
        sys.exit(1)
    return config


class LDAPProxyConfig(object):
    def __init__(self, filename=LDAP_PROXY_CONFIG_FILE):
        self.config = configobj.ConfigObj()
        self.filename = filename
        self.reset()
        self.autosave_enabled = True

    def reset(self):
        if self.exists:
            self.config = _load_config(self.filename)  # TODO: This exits if config is malformed!

    @property
    def initialized(self):
        if self.exists:
            self.reset()  # ?
            protocol, host, port = self.backend_settings
            if host == '192.0.2.1':
                # this host is used in the default config shipped with the ldap-proxy ubuntu package
                return False
            else:
                # otherwise, someone has done something with the configuration
                return True
        else:
            return False

    def set_default_config(self):
        """
        set all config options that are not configurable by any accessor methods below
        :return:
        """
        self.config['bind-cache'] = {'enabled': False}
        self.config['app-cache'] = {'enabled': False}
        self.config.setdefault('ldap-backend', {})['use-tls'] = False
        self.config.setdefault('ldap-backend', {})['test-connection'] = False
        privacyidea_cert, _ = ApacheConfig().get_certificates()
        self.config['privacyidea'] = {
            # TODO: should probably use the hostname from the cert?
            #  Or disable validation entirely?
            'instance': 'https://{}'.format(socket.getfqdn()),
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


class LDAPProxyService(object):
    def __init__(self):
        pass

    def _get_enablement_status(self):
        return self._get_systemd_property('UnitFileState')

    @property
    def enabled(self):
        return self._get_enablement_status() == 'enabled'

    def enable(self):
        return self._invoke_systemctl(['enable', LDAP_PROXY_UNIT_FILE])

    def disable(self):
        return self._invoke_systemctl(['disable', LDAP_PROXY_UNIT_FILE])

    @property
    def active(self):
        state = self._get_systemd_property('ActiveState')
        return state in ('active', 'reloading', 'activating')

    @staticmethod
    def _invoke_systemctl(arguments):
        proc = subprocess.Popen(['systemctl'] + arguments,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        return proc.wait() == 0

    @staticmethod
    def _get_systemd_property(property_name):
        """
        Invoke ``systemctl show`` to retrieve the value of the given property
        of the LDAP proxy unit file. Return it as a string.
        """
        proc = subprocess.Popen(['systemctl', 'show', LDAP_PROXY_UNIT_FILE, '-p', property_name],
                                stdout=subprocess.PIPE, encoding='utf8')
        output = proc.communicate()[0].strip()
        return output.split("=", 1)[1]

    def restart(self):
        """ restart the unit. If it is inactive, it will be started. """
        return self._invoke_systemctl(['restart', LDAP_PROXY_UNIT_FILE])

    def stop(self):
        return self._invoke_systemctl(['stop', LDAP_PROXY_UNIT_FILE])
