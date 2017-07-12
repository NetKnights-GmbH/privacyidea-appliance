import socket
from contextlib import contextmanager

import os
import re

import configobj
import sys

import subprocess

import dbus
import validate
from dbus import DBusException

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
    match = re.search(attribute + '=([^:]+)', endpoint)
    if match is not None:
        return match.group(1)
    else:
        return ''

def _load_config(filename):
    with open(filename, 'r') as f:
        config = configobj.ConfigObj(f, configspec=CONFIG_SPEC.splitlines())

    validator = validate.Validator()
    result = config.validate(validator, preserve_errors=True)
    if result != True:
        print('Invalid LDAP Proxy configuration at {!r}: {!r}'.format(filename, result))
        sys.exit(1)
    return config

class LDAPProxyConfig(object):
    def __init__(self, filename=LDAP_PROXY_CONFIG_FILE):
        self.filename = filename
        self.reset()
        self.autosave_enabled = True

    def reset(self):
        if self.exists:
            self.config = _load_config(self.filename)  # TODO: This exits if config is malformed!
        else:
            # Create config directory if it does not exist
            directory = os.path.dirname(self.filename)
            if not os.path.exists(directory):
                os.makedirs(directory)
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

class LDAPProxyService(object):
    def __init__(self):
        self.bus = dbus.SystemBus()
        self.proxy = self.bus.get_object('org.freedesktop.systemd1',
                                         '/org/freedesktop/systemd1')
        self.manager = dbus.Interface(self.proxy,
                                      dbus_interface=SYSTEMD_MANAGER_INTERFACE)

    def _get_enablement_status(self):
        return self.manager.GetUnitFileState(LDAP_PROXY_UNIT_FILE)

    def _get_unit(self):
        path = self.proxy.GetUnit(LDAP_PROXY_UNIT_FILE,
                                  dbus_interface=SYSTEMD_MANAGER_INTERFACE)
        return self.bus.get_object('org.freedesktop.systemd1', path)

    @property
    def enabled(self):
        return self._get_enablement_status() == 'enabled'

    def enable(self):
        self.manager.EnableUnitFiles([LDAP_PROXY_UNIT_FILE], False, False)
        # TODO: check return value?

    def disable(self):
        self.manager.DisableUnitFiles([LDAP_PROXY_UNIT_FILE], False)

    @property
    def active(self):
        try:
            unit = self._get_unit()
        except DBusException:
            # If the unit does not exist, it is inactive
            return False
        state = unit.Get('org.freedesktop.systemd1.Unit', 'ActiveState',
                         dbus_interface='org.freedesktop.DBus.Properties')
        # TODO: Should we rather only check for 'active'?
        return state in ('active', 'reloading', 'activating')

    def _invoke_systemctl(self, arguments):
        proc = subprocess.Popen(['systemctl'] + arguments,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        return proc.wait() == 0

    def restart(self):
        """ restart he unit. If it is inactive, it will be started. """
        # NOTE: We do not use the dbus interface here because
        # using `systemctl restart` has the advantage that we wait
        # until the unit is actually restarted.
        return self._invoke_systemctl(['restart', LDAP_PROXY_UNIT_FILE])

    def stop(self):
        return self._invoke_systemctl(['stop', LDAP_PROXY_UNIT_FILE])

