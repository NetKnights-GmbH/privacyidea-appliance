# -*- coding: utf-8 -*-
#  copyright 2014 Cornelius Kölbel
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
"""
text dialog based setup tool to configure the privacyIDEA basics.
"""
import locale
import argparse
import sys
import platform
import os
import re
from traceback import print_exc

# If the ``privacyidea`` Python package cannot be imported normally,
# append the virtualenv site-packages of the privacyIDEA 3.x distribution
# packages to the search path and try again.
site_version = 'python' + '.'.join(platform.python_version_tuple()[0:2])
PRIVACYIDEA_SITE_PACKAGES = '/opt/privacyidea/lib/' + site_version + '/site-packages/'
PRIVACYIDEA_VPN = 'privacyideaVPN'
try:
    import privacyidea
except ImportError:
    if os.path.isdir(PRIVACYIDEA_SITE_PACKAGES):
        sys.path.append(PRIVACYIDEA_SITE_PACKAGES)
    try:
        import privacyidea
    except ImportError:
        print('The privacyidea module cannot be found in the search '
              'path: {!r}'.format(sys.path), file=sys.stderr)
        print_exc(file=sys.stderr)
        print('Exiting.', file=sys.stderr)
        sys.exit(1)

import time
from functools import partial

import pipes
import shutil

from authappliance.lib.appliance import (Backup, Audit, FreeRADIUSConfig,
                                         ApacheConfig,
                                         PrivacyIDEAConfig,
                                         OSConfig, MySQLConfig,
                                         DEFAULT_CONFIG,
                                         CRON_USER, BACKUP_CMD, RemoteMySQLConfig,
                                         SERVICE_APACHE,
                                         SERVICE_FREERADIUS, SERVICE_LDAP_PROXY)
from privacyidea.lib.auth import (create_db_admin, get_db_admins,
                                  delete_db_admin)
from privacyidea.app import create_app
from netaddr import IPAddress, IPNetwork, AddrFormatError
from paramiko.client import SSHClient
from paramiko import SSHException, AutoAddPolicy
from subprocess import Popen, PIPE
import random
from tempfile import NamedTemporaryFile

from authappliance.lib.extdialog import ExtDialog
from authappliance.lib.ldap_proxy import LDAPProxyConfig, LDAPProxyService
from authappliance.lib.tincparser.tincparser import (TincConfFile, LocalIOHandler,
                                                     SFTPIOHandler, UpScript,
                                                     NetsBoot)
from authappliance.lib.updates import Updates, UPDATE_UPDATES, UPDATE_SECURITY
from authappliance.lib.utils import (execute_ssh_command_and_wait, to_unicode)

DESCRIPTION = __doc__
VERSION = "2.0"

#: This holds the services that should be restarted
#: at the end of the session. It should be modified
#: using mark_service_for_restart and
#: reset_services_for_restart.
services_for_restart = set()


def mark_service_for_restart(service):
    """
    Add ``service`` to set of services that should be restarted.
    """
    services_for_restart.add(service)


def reset_services_for_restart():
    """
    Clear the set of services that should be restarted.
    """
    services_for_restart.clear()


class WebserverMenu(object):

    def __init__(self, app, dialog):
        self.app = app
        self.os = OSConfig()
        self.d = dialog
        self.apache = ApacheConfig()

    def menu(self):
        bt = "Webservice configuration"
        choices = [(self.restart, "restart services", ""),
                   (lambda: None, "-" * 40, ""),
                   (self.generate_self, "Generate selfsigned certificate", ""),
                   (lambda: None, "-" * 40, ""),
                   (self.generate_csr, "Generate Certificate Signing Request", ""),
                   (self.import_certificate, "Import certificate", ""),
                   (lambda: None, "-" * 40, ""),
                   (self.generate_private_key, "Regenerate private key", "")]
        while 1:
            menu = self.d.value_menu("Configure Webserver",
                                     choices=choices,
                                     cancel='Back',
                                     backtitle=bt)
            if menu is not None:
                menu()
            else:
                break

    def generate_self(self):
        code = self.d.yesno("Do you want to recreate the self signed "
                            "certificate?")
        if code == self.d.OK:
            self.apache.create_self_signed()
            mark_service_for_restart(SERVICE_APACHE)

    def generate_private_key(self):
        code, tags = self.d.menu("Regenerate private key. "
                                 "When regenerating the private key you also "
                                 "need a new certificate! "
                                 "Do not regenerate the private key while "
                                 "you are waiting for a certificate signing "
                                 "request to be signed. In this case "
                                 "the certificate will not match the "
                                 "private key anymore.",
                                 choices=[("2048", "2048 bit"),
                                          ("4096", "4096 bit"),
                                          ("8192", "8192 bit")],
                                 backtitle="Regenerate private key")
        if code == self.d.OK:
            self.apache.create_private_key(tags)
            mark_service_for_restart(SERVICE_APACHE)

    def generate_csr(self):
        csr = self.apache.generate_csr()
        code = self.d.msgbox("The certificate signing request is written "
                             "to {0}. \nCopy this file and pass it to your "
                             "certificate authority for getting it signed. \n"
                             "Do not regenerate the private "
                             "key after you have sent the CSR to your "
                             "certificate authority.".format(csr),
                             width=70, height=10)

    def import_certificate(self):
        cert, keyfile = self.apache.get_certificates()
        homedir = os.getenv("HOME")
        code = self.d.msgbox("You received a signed certificate from a "
                             "certificate authority. Copy this file to the "
                             "directory \n{0}.\n"
                             "In the following dialog you may choose, "
                             "which certificate you want to use for your "
                             "webserver.".format(homedir),
                             width=70, height=10)

        bt = "Import certificate (.pem, .crt, .der, .cer)"
        files = self.apache.get_imports(homedir)
        choices = []
        for bfile in sorted(files.keys()):
            choices.append((bfile, "%s" % (files[bfile].get("time"))))
        if len(choices) == 0:
            self.d.msgbox("No certificate found!")
        else:
            code, tags = self.d.menu("Choose the certificate you want to "
                                     "use for the webserver.",
                                     choices=choices,
                                     backtitle=bt,
                                     width=78)
            if code == self.d.OK:
                self.apache.import_cert(homedir + "/" + tags, cert)
                mark_service_for_restart(SERVICE_APACHE)

    def restart(self):
        code = self.d.yesno("Do you want to restart the services for the "
                            "changes to take effect?")
        if code == self.d.OK:
            self.os.restart(SERVICE_APACHE)


class Peer(object):
    files = ["/etc/privacyidea/enckey", "/etc/privacyidea/logging.cfg",
             "/etc/privacyidea/private.pem", "/etc/privacyidea/public.pem",
             "/var/lib/mysql/ca.pem", "/var/lib/mysql/ca-key.pem",
             "/var/lib/mysql/server-cert.pem", "/var/lib/mysql/server-key.pem"]

    def __init__(self, dialog, pConfig, dbConfig, remote_ip=None,
                 password=None, local_ip=None):
        self.remote_ip = remote_ip
        self.local_ip = local_ip
        self.password = password
        self.d = dialog
        self.pConfig = pConfig
        self.dbConfig = dbConfig
        self.ssh = SSHClient()
        self.os = OSConfig()
        self.info = ""
        self.file_local = ""
        self.file_remote = ""
        self.position_local = ""
        self.position_remote = ""

    def get_redundancy_status(self, role):
        """
        Given a role (one of "MASTER", "SLAVE"), run "SHOW <role> STATUS" locally
        and return the result as a dictionary.
        """
        if role.upper() not in ('MASTER', 'SLAVE'):
            raise RuntimeError('{} should be one of MASTER, SLAVE'.format(role.upper()))
        result, err = self._execute_local_sql("SHOW {} STATUS".format(role))
        lines = result.splitlines()
        assert len(lines) == 2
        keys = lines[0].strip().split('\t')
        values = lines[1].strip().split('\t')
        return dict(zip(keys, values))

    def get_peer_data(self):
        bt = "Add another SQL Master"
        code, ip = self.d.inputbox(
            "Enter the IP Address of the other privacyIDEA server.",
            backtitle=bt)
        if code != self.d.OK:
            return False

        try:
            self.remote_ip = IPAddress(ip)
        except:
            self.d.msgbox("Invalid IP address")
            return False

        code, password = self.d.passwordbox(
            "Enter the root password of the other machine. Please NOTE: "
            "On an Ubuntu machine Root SSH login with password is forbidden. "
            "You need to change 'PermitRootLogin' in the "
            "/etc/ssh/sshd_config. Otherwise authentication will fail.",
            insecure=True, backtitle=bt)
        if code != self.d.OK:
            return False

        self.password = password

        code, local_ip = self.d.inputbox(
            "Enter the local IP Address of this machine, to which the remote "
            "server will connect.", backtitle=bt)
        if code != self.d.OK:
            return False

        try:
            self.local_ip = IPAddress(local_ip)
        except:
            self.d.msgbox("Invalid IP address")
            return False

        return True

    def add_info(self, new_info):
        self.info += new_info + "\n"
        self.d.infobox(self.info, height=20, width=60)

    def stop_redundancy(self):
        self.info = ""
        self.add_info("Stopping local webserver")
        self.os.restart(service="apache2", action="stop")

        # To stop redundancy we remove
        # several fields from the my.cnf file.
        self.add_info("Removing config from my.cnf...")
        self.dbConfig.set("mysqld", "bind-address", "127.0.0.1")
        for setting in ["server-id", "auto_increment_increment",
                        "auto_increment_offset", "log_bin", "binlog_do_db"]:
            self.dbConfig.delete("mysqld", setting)

        # delete the replication user
        self.add_info("Dropping replicator user...")
        _, err = self._execute_local_sql("drop user 'replicator'@'%';")
        if err:
            self.add_info("Error dropping replicator user!")

        # stop the slave
        self.add_info("Stopping the slave...")
        _, err = self._execute_local_sql("stop slave; reset slave;")
        if err:
            self.add_info("Error stopping slave: {0}".format(err))
        # restart mysql
        self.add_info("Restarting MySQL server...")
        self.dbConfig.restart()
        self.add_info("Starting local webserver...")
        self.os.restart(service="apache2", action="start")
        self.add_info("done.")
        self.display_messages()

    def _execute_local_sql(self, sql):
        p = Popen(['mysql', '--defaults-extra-file=/etc/mysql/debian.cnf'],
                  stdin=PIPE, stdout=PIPE, stderr=PIPE, universal_newlines=True)
        output, err = p.communicate(sql)
        if err:
            self.add_info("====== ERROR =======")
            self.add_info(err)
        return output, err

    @staticmethod
    def _escape_for_shell(argument):
        return "'{}'".format(argument.replace("'", r"'\''"))

    def _execute_remote_sql(self, sql):
        assert '"' not in sql
        ret, stdout, stderr = execute_ssh_command_and_wait(self.ssh,
            'echo {} | mysql --defaults-extra-file=/etc/mysql/debian.cnf'.format(
                self._escape_for_shell(sql)))
        if stderr:
            self.add_info("====== ERROR =======")
            self.add_info(stderr)
        return stdout, stderr

    def _create_sftp_connection(self, user="root"):
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        ssh.connect(str(self.remote_ip), username=user, password=self.password)
        sftp = ssh.open_sftp()
        return ssh, sftp

    def setup_tinc(self, local_vpn_ip, remote_vpn_ip, vpn_subnet, vpn_name=PRIVACYIDEA_VPN):
        """
        Set up a tinc tunnel between self.local_ip and self.remote_ip
        and update self.local_ip and self.remote_ip accordingly.
        """
        self.add_info("Setting up the tinc VPN ...")

        # create SFTP client to remote server
        ssh, sftp = self._create_sftp_connection()
        local_io_handler = LocalIOHandler()
        remote_io_handler = SFTPIOHandler(sftp)

        tinc_net_directory = '/etc/tinc/{}/'.format(vpn_name)
        # create directories locally and remotely
        for io_handler in (local_io_handler, remote_io_handler):
            io_handler.makedirs(os.path.join(tinc_net_directory, 'hosts'))
        tinc_conf = os.path.join(tinc_net_directory, 'tinc.conf')
        # Local tinc.conf
        local_tinc_conf = TincConfFile(local_io_handler, tinc_conf)
        local_tinc_conf.update({
            'Name': 'pinode1',
            'Device': '/dev/net/tun',
            'AddressFamily': 'ipv4'
        })
        local_tinc_conf.save()

        # Remote tinc.conf
        remote_tinc_conf = TincConfFile(remote_io_handler, tinc_conf)
        remote_tinc_conf.update({
            'Name': 'pinode2',
            'Device': '/dev/net/tun',
            'AddressFamily': 'ipv4',
            'ConnectTo': 'pinode1'
        })
        remote_tinc_conf.save()

        # this command generates /etc/tinc/[vpn_name]/rsa_key.priv and /etc/tinc/[vpn_name]/hosts/[hostname]
        generate_key_command = 'tincd -n {} -K 4096'.format(pipes.quote(vpn_name))

        # Generate local keypair
        proc = Popen(generate_key_command, shell=True, stdout=PIPE,
                     stderr=PIPE, universal_newlines=True)
        _stdout, stderr = proc.communicate('\n\n')  # press <RETURN> two times
        if proc.returncode != 0:
            self.add_info("ERROR: Could not generate local keypair")
            self.add_info(stderr)
            return False

        # Generate remote keypair
        returncode, _stdout, stderr = execute_ssh_command_and_wait(ssh, generate_key_command)
        if returncode != 0:
            self.add_info("ERROR: Could not generate remote keypair")
            self.add_info(stderr)
            return False

        # Locally configure the pinode1 host file (which already contains the pubkey)
        pinode1_filename = os.path.join(tinc_net_directory, 'hosts', 'pinode1')
        pinode2_filename = os.path.join(tinc_net_directory, 'hosts', 'pinode2')
        local_pinode1_conf = TincConfFile(local_io_handler, pinode1_filename)
        local_pinode1_conf.update({
            'Address': str(self.local_ip),
            'Subnet': local_vpn_ip,
        })
        local_pinode1_conf.save()
        # Remote configure the pinode2 host file (which already contains the pubkey)
        remote_pinode2_conf = TincConfFile(remote_io_handler, pinode2_filename)
        remote_pinode2_conf.update({
            'Address': str(self.remote_ip),
            'Subnet': remote_vpn_ip,
        })
        remote_pinode2_conf.save()

        # Exchange host files (and thus RSA pubkeys)
        # pinode1 -> REMOTE
        sftp.put(pinode1_filename, pinode1_filename)
        # REMOTE -> pinode2
        sftp.get(pinode2_filename, pinode2_filename)

        # Create tinc-up scripts
        tinc_up_filename = os.path.join(tinc_net_directory, 'tinc-up')
        tinc_up_config = '\n'.join([
            'ip link set $INTERFACE up',
            'ip addr add {ip} dev $INTERFACE',
            'ip route add {network} dev $INTERFACE'])

        # locally
        local_tinc_up = UpScript(local_io_handler, tinc_up_filename)
        local_tinc_up.appliance_section = tinc_up_config.format(
            ip=local_vpn_ip,
            network=vpn_subnet,
        ).split('\n')
        local_tinc_up.save()
        local_io_handler.chmod(tinc_up_filename, 0o755)

        # remotely
        remote_tinc_up = UpScript(remote_io_handler, tinc_up_filename)
        remote_tinc_up.appliance_section = tinc_up_config.format(
            ip=remote_vpn_ip,
            network=vpn_subnet,
        ).split('\n')
        remote_tinc_up.save()
        remote_io_handler.chmod(tinc_up_filename, 0o755)

        # add network to nets.boot
        nets_boot_filename = '/etc/tinc/nets.boot'
        # locally
        local_nets_boot = NetsBoot(local_io_handler, nets_boot_filename)
        local_nets_boot.add(vpn_name)
        local_nets_boot.save()

        # remotely
        remote_nets_boot = NetsBoot(remote_io_handler, nets_boot_filename)
        remote_nets_boot.add(vpn_name)
        remote_nets_boot.save()

        # Start the tinc nets
        start_command = 'systemctl enable tinc@{} --now'.format(pipes.quote(PRIVACYIDEA_VPN))
        # locally
        proc = Popen(start_command, shell=True, stderr=PIPE,
                     universal_newlines=True)
        _stdout, stderr = proc.communicate()
        if proc.returncode != 0:
            self.add_info('ERROR: Could not bring up the tinc VPN locally')
            self.add_info(stderr)
            return False
        # remotely
        returncode, _stdout, stderr = execute_ssh_command_and_wait(ssh, start_command)
        if returncode != 0:
            self.add_info('ERROR: Could not bring up the tinc VPN remotely')
            self.add_info(stderr)
            return False

        # Wait a few seconds for tincd to start
        time.sleep(3)

        # Try to ping LOCAL -> REMOTE
        # Ping ten times -- return code will be 0 even if the first few pings do not get a reply.
        ping_command = 'ping -c 10 {}'
        proc = Popen(ping_command.format(remote_vpn_ip), shell=True,
                     stdout=PIPE, universal_newlines=True)
        stdout, _stderr = proc.communicate()
        if proc.returncode != 0:
            self.add_info('ERROR: Could not ping remote host from local host')
            self.add_info(stdout)
            return False

        # Try to ping REMOTE -> LOCAL
        returncode, stdout, _stderr = execute_ssh_command_and_wait(ssh, ping_command.format(
            local_vpn_ip))
        if returncode != 0:
            self.add_info('ERROR: Could not ping local host from remote host')
            self.add_info(stdout)
            return False

        # and we are done.
        # we now set local_ip and remote_ip to the VPN IP addresses!
        self.local_ip = local_vpn_ip
        self.remote_ip = remote_vpn_ip

        self.add_info('The tinc VPN was set up successfully!')

        ssh.close()
        return True

    @staticmethod
    def is_tinc_configured(vpn_name=PRIVACYIDEA_VPN):
        """ Return true if /etc/tinc/privacyideaVPN exists and
        /etc/tinc/nets.boot contains the VPN name """
        if os.path.exists(os.path.join('/etc/tinc', vpn_name)):
            nets_boot = NetsBoot(LocalIOHandler(), '/etc/tinc/nets.boot')
            if vpn_name in nets_boot.nets:
                return True
        return False

    def delete_tinc(self, vpn_name=PRIVACYIDEA_VPN):
        """ Stop and delete the tinc network """
        self.info = ""
        # Shutdown, ignore the return value
        stop_command = 'systemctl disable tinc@{} --now'.format(pipes.quote(vpn_name))
        proc = Popen(stop_command, shell=True)
        proc.wait()
        self.add_info('tincd for {} has been shut down.'.format(vpn_name))

        # Remove from nets.boot
        nets_boot = NetsBoot(LocalIOHandler(), '/etc/tinc/nets.boot')
        if vpn_name in nets_boot.nets:
            nets_boot.remove(vpn_name)
        nets_boot.save()
        self.add_info('{} has been removed from /etc/tinc/nets.boot.'.format(vpn_name))
        # Remove directory
        vpn_directory = os.path.join('/etc/tinc', vpn_name)
        shutil.rmtree(vpn_directory)

        self.add_info('{} has been successfully deleted!'.format(vpn_name))
        self.display_messages()

    def display_messages(self):
        self.d.scrollbox(to_unicode(self.info), height=20, width=60)

    def setup_freeradius(self):
        """
        Copy FreeRADIUS configuration to the remote peer and restart the
        freeradius daemon.
        """
        self.info = ""
        # Collect all local FreeRADIUS config files that should be copied.
        # This includes /etc/privacyidea/rlm_perl.ini
        # but excludes /etc/freeradius/certs (because it contains private keys)
        # and /etc/freeradius/sites-enabled (because it contains symlinks)
        config_files = ["/etc/privacyidea/rlm_perl.ini"]
        # check the freeradius version
        if os.path.exists('/etc/freeradius/3.0'):
            rad_ver = 3
            config_directories = ["/etc/freeradius/3.0",
                                  "/etc/freeradius/3.0/mods-available",
                                  "/etc/freeradius/3.0/sites-available"]
        else:
            rad_ver = 2
            config_directories = ["/etc/freeradius",
                                  "/etc/freeradius/modules",
                                  "/etc/freeradius/sites-available"]
        for directory in config_directories:
            for filename in os.listdir(directory):
                absolute_filename = os.path.join(directory, filename)
                if os.path.isfile(absolute_filename):
                    config_files.append(absolute_filename)
        self.add_info("copying FreeRADIUS configuration:")
        # create SSH and SFTP client to remote server
        ssh, sftp = self._create_sftp_connection()

        # Copy configuration files to remote server
        for filename in config_files:
            if os.path.exists(filename):
                self.add_info(filename)
                sftp.put(filename, filename)
        self.add_info("")
        self.sync_enabled_symlinks(sftp, config_directories[2])
        if rad_ver == 3:
            # with freeradius 3 the modules must be enabled explicitely
            self.sync_enabled_symlinks(sftp, config_directories[1],
                                       module='mod')

        self.add_info("")
        self.add_info("Restarting remote FreeRADIUS server ...")
        execute_ssh_command_and_wait(ssh, "service freeradius restart")
        self.add_info("... done!")

        ssh.close()
        self.display_messages()
        return True

    def sync_enabled_symlinks(self, sftp, available_dir, module='site'):
        enabled_dir = re.sub(r'-available$', '-enabled', available_dir)
        # Transfer enabled/disabled sites
        local_enabled = set(os.listdir(enabled_dir))
        remote_enabled = set(sftp.listdir(enabled_dir))
        # Remotely disable sites that are not enabled locally
        for entry in remote_enabled:
            if entry not in local_enabled:
                self.add_info("Remotely disabling {0!s} "
                              "{1!s} ...".format(module, entry))
                entry_linkname = os.path.join(enabled_dir, entry)
                sftp.unlink(entry_linkname)
        # Enable locally enabled sites that are not already enabled remotely
        for entry in local_enabled:
            if entry not in remote_enabled:
                self.add_info("Remotely enabling {0!s} "
                              "{1!s} ...".format(module, entry))
                available_filename = os.path.join(available_dir, entry)
                enabled_filename = os.path.join(enabled_dir, entry)
                sftp.symlink(available_filename, enabled_filename)

    def setup_redundancy(self):
        #
        # Copy files in /etc/privacyidea
        #
        self.info = ""
        self.add_info("copying files to remote server...")
        ssh, sftp = self._create_sftp_connection()
        for file in self.files:
            if os.path.exists(file):
                sftp.put(file, file)

        # adjust remote pi.cfg
        remote_config = PrivacyIDEAConfig(DEFAULT_CONFIG, opener=sftp.file)
        local_config = PrivacyIDEAConfig(DEFAULT_CONFIG)

        new_remote_config = local_config.config.copy()
        # copy the local pi.cfg to the remote config except the
        # keys listed in ``save_remote_config_keys``.
        save_remote_config_keys = ['SQLALCHEMY_DATABASE_URI']
        for key in save_remote_config_keys:
            new_remote_config[key] = remote_config.config[key]
        remote_config.config = new_remote_config
        remote_config.save()

        #
        # Setup my.cnf, locally and remotely
        #
        shared_my_cnf_values = {"auto_increment_increment": 2,
                                "log_bin": "/var/log/mysql/mysql-bin.log",
                                "binlog_do_db": "pi",
                                "bind-address": "0.0.0.0",
                                "ssl_ca":  "ca.pem",
                                "ssl_cert": "server-cert.pem",
                                "ssl_key": "server-key.pem"
                                }
        remote_my_cnf_values = {"server-id": 2,
                                "auto_increment_offset": 2}
        local_my_cnf_values = {"server-id": 1,
                               "auto_increment_offset": 1}

        self.add_info("Setup my.cnf on local server...")

        conf_values = shared_my_cnf_values.copy()
        conf_values.update(local_my_cnf_values)
        for key, value in conf_values.items():
            self.dbConfig.set('mysqld', key, value)

        self.add_info("Setup my.cnf on remote server...")

        remote_my_cnf = RemoteMySQLConfig(sftp)
        conf_values = shared_my_cnf_values.copy()
        conf_values.update(remote_my_cnf_values)
        for key, value in conf_values.items():
            remote_my_cnf.set('mysqld', key, value)

        ssh.close()

        #
        # Restart services
        #
        self.add_info("Restarting local MySQL server...")
        self.dbConfig.restart()
        self.add_info("Restarting remote MySQL server...")
        self.ssh.connect(str(self.remote_ip), username="root",
                         password=self.password)
        ret, stdout, stderr = execute_ssh_command_and_wait(self.ssh, "service mysql restart")
        if ret != 0:
            self.add_info(stderr)
        #
        # Configuring mysql
        #
        # Before configuring mysql we stop the webserver
        self.add_info("Stopping local webserver")
        self.os.restart(service="apache2", action="stop")
        self.add_info("Stopping remote webserver")
        ret, stdout, stderr = execute_ssh_command_and_wait(self.ssh, "service apache2 stop")
        if ret != 0:
            self.add_info(stderr)

        self.add_info("Configuring MySQL on local server...")
        # We start at 40, since 39 is "'" which might lead to confusion.
        # Create a random password of random length
        replicator_password = "".join([random.choice(
            "01234567890abcdefghijklmnopqrstuvwxyzABZDEFGHIJKLMNOPQRSTUVWXYZ")
            for x in
            range(random.randrange(21, 31))])

        # Add the replication users on both machines
        self.add_info("Drop and add replication user on local machine...")
        self._execute_local_sql("drop user if exists 'replicator'@'%';")
        self._execute_local_sql("""create user 'replicator'@'%' identified by '{}' REQUIRE SSL;
                                  grant replication slave on *.* to 'replicator'@'%';""".format(replicator_password))

        self.add_info("Drop and add replication user on remote machine...")
        # Drop user
        _, err = self._execute_remote_sql("drop user if exists 'replicator'@'%'")
        self._execute_remote_sql("""create user 'replicator'@'%' identified by '{}' REQUIRE SSL;
                                  grant replication slave on *.* to 'replicator'@'%';""".format(replicator_password))
        #
        # dump it and copy it to the other server
        #
        self.add_info("Dumping and copying the existing database...")

        dumpfile = NamedTemporaryFile(mode="w", delete=False)
        p = Popen(["mysqldump", "--defaults-extra-file=/etc/mysql/debian.cnf",
                   "--databases", "pi"],
                  stdout=dumpfile, stderr=PIPE, universal_newlines=True)
        _output, err = p.communicate()
        r = p.wait()
        if r == 0:
            self.add_info("Saved SQL dump to {0}".format(dumpfile.name))
            # copy the file.name to the remote machine and run the file.
            self.add_info("Copying to remote server and creating remote "
                          "database. This may take a while...")
            ssh, sftp = self._create_sftp_connection()
            sftp.put(dumpfile.name, dumpfile.name)
            ssh.close()
            # delete the file
            os.unlink(dumpfile.name)
            # run the file remotely
            # mysql -u root -p < test.sql
            ret, stdout, stderr = execute_ssh_command_and_wait(self.ssh,
                "cat {dumpfile} | mysql --defaults-extra-file=/etc/mysql/debian.cnf".format(dumpfile=dumpfile.name))
            if stderr:
                self.add_info("ERROR: {0}".format(stderr))
            else:
                self.add_info("Dumped SQL database on remote server")
            # delete remote file
            execute_ssh_command_and_wait(self.ssh,
                "rm -f {dumpfile}".format(dumpfile=dumpfile.name))
        else:
            self.add_info("ERROR: {0}".format(err))

        #
        # Get the position on server1
        #
        output, err = self._execute_local_sql("show master status;")
        r = p.returncode
        if r == 0:
            self.add_info(output)
            for line in output.split("\n"):
                elems = line.split()
                if len(elems) > 2 and elems[2] == "pi":
                    self.file_local = elems[0]
                    self.position_local = elems[1]
                    self.add_info("Local File:     {0}".format(self.file_local))
                    self.add_info("Local Position: {0}".format(
                        self.position_local))

        self.add_info("Configuring MySQL on remote server...")
        # clean up the old database
        output, _ = self._execute_remote_sql('show master status;')
        self.add_info(output)
        for line in output.split("\n"):
            elems = line.split()
            if len(elems) > 2 and elems[2] == "pi":
                self.file_remote = elems[0]
                self.position_remote = elems[1]
                self.add_info("Remote File:     {0}".format(self.file_remote))
                self.add_info("Remote Position: {0}".format(
                    self.position_remote))

        # create everything remote
        self.add_info("Add replication on remote server...")
        self._execute_remote_sql("""
            stop slave;
            CHANGE MASTER TO MASTER_HOST = '{local_ip}', MASTER_USER = 'replicator',
            MASTER_PASSWORD = '{replicator_password}', MASTER_LOG_FILE = '{local_file}', MASTER_LOG_POS = {local_position}, master_ssl=1, master_ssl_ca='/var/lib/mysql/ca.pem', master_ssl_cert='/var/lib/mysql/server-cert.pem', master_ssl_key='/var/lib/mysql/server-key.pem';
            start slave;""".format(
            replicator_password=replicator_password,
            local_file=self.file_local,
            local_position=self.position_local,
            local_ip=self.local_ip))

        #
        #  Configure replication on LOCAL host
        #
        self.add_info("Add replication on local server...")
        self._execute_local_sql("""
            stop slave;
            CHANGE MASTER TO MASTER_HOST = '{remote_ip}', MASTER_USER = 'replicator',
            MASTER_PASSWORD = '{replicator_password}', MASTER_LOG_FILE = '{remote_file}', MASTER_LOG_POS = {remote_position}, master_ssl=1, master_ssl_ca='/var/lib/mysql/ca.pem', master_ssl_cert='/var/lib/mysql/server-cert.pem', master_ssl_key='/var/lib/mysql/server-key.pem';
            start slave;""".format(
            replicator_password=replicator_password,
            remote_ip=self.remote_ip,
            remote_file=self.file_remote,
            remote_position=self.position_remote))

        self.add_info("Starting local webserver")
        self.os.restart(service="apache2", action="start")
        self.add_info("Starting remote webserver")
        execute_ssh_command_and_wait(self.ssh, "service apache2 start")
        self.add_info("\nRedundant setup complete.")

        self.display_messages()


class DBMenu(object):

    def __init__(self, app, dialog, pConfig):
        self.app = app
        self.d = dialog
        self.pConfig = pConfig
        self.db = MySQLConfig()
        self.peer = Peer(self.d, self.pConfig, self.db)

    def menu(self):
        bt = "Configure the database connection"
        choices = [(self.db_init, "init tables", "create missing tables"),
                   (self.redundancy_status, "view redundancy", ""),
                   (self.setup_redundancy, "setup redundancy", "master master replication"),
                   (self.stop_redundancy, "stop redundancy", "revert to single database")]
        while 1:
            current_config = self.pConfig.get_DB()
            menu = self.d.value_menu(
                "The current database configuration string is %s" % current_config,
                choices=choices,
                cancel='Back',
                backtitle=bt)
            if menu is not None:
                menu()
            else:
                break

    def setup_redundancy(self):
        if self.peer.get_peer_data():
            # Now we need to check, if the remote machine is
            # running privacyIDEA and MySQL.
            try:
                self.peer.ssh.set_missing_host_key_policy(
                    AutoAddPolicy())
                self.peer.ssh.connect(str(self.peer.remote_ip),
                                      username="root",
                                      password=self.peer.password)
                ret, output_pi, error_pi = execute_ssh_command_and_wait(self.peer.ssh,
                    'dpkg -l privacyidea-apache2')
                ret, output_radius, error_radius = execute_ssh_command_and_wait(self.peer.ssh,
                    'dpkg -l privacyidea-radius')
                ret, output_mysql, error_mysql = execute_ssh_command_and_wait(self.peer.ssh,
                    'dpkg -l mysql-server')
                # Check if tinc is installed, just in case we need it later.
                _, output_tinc, _ = execute_ssh_command_and_wait(self.peer.ssh, 'dpkg -l tinc')
                tinc_installed = bool(output_tinc)
                self.peer.ssh.close()
                if not output_mysql:
                    self.d.msgbox(
                        "MySQL server not installed on {0!s}. "
                        "Please install mysql-server.".format(
                            self.peer.remote_ip))
                    return
                if not output_pi:
                    self.d.msgbox(
                        "privacyIDEA not installed on "
                        "{0!s}. Please install "
                        "privacyidea-apache2.".format(
                            self.peer.remote_ip))
                    return
                radius_installed = bool(output_radius)
            except SSHException as exx:
                self.d.msgbox("{0!s}".format(exx))
                return

            code = self.d.yesno(
                "OK. privacyIDEA and MySQL is installed on the "
                "remote server. We are ready to setup redundancy. "
                "Data will be cloned to the remote server. All "
                "privacyIDEA data on the remote server will be "
                "lost. Shall we proceed?", width=60)
            if code != self.d.OK:
                return
            else:
                code = self.d.yesno(
                    "By default, communication between the MySQL peers is "
                    "unencrypted. Optionally, the appliance tool can set up "
                    "an encrypted tinc VPN tunnel between the two peers. "
                    "Should we set up encrypted master-master replication?",
                    width=60)
                if code == self.d.OK:
                    if not tinc_installed:
                        self.d.msgbox("tinc is not installed on {0!s}. Please install tinc.".format(
                            self.peer.remote_ip))
                        return
                if code == self.d.OK:
                    code, subnet_string = self.d.inputbox("Please choose a subnet for the VPN which is "
                                                          "not yet used, using CIDR notation.",
                                                          init="172.20.1.0/30")
                    if code == self.d.OK:
                        try:
                            subnet = IPNetwork(subnet_string)
                        except AddrFormatError:
                            self.d.msgbox("You have to specify a subnet in CIDR notation.")
                            return
                        if subnet.prefixlen > 30:
                            self.d.msgbox("You have specify at least a /30 subnet.")
                            return
                        hosts = list(subnet.iter_hosts())
                        tinc_ready = self.peer.setup_tinc(str(hosts[0]),
                                                          str(hosts[1]),
                                                          str(subnet))
                        self.peer.display_messages()
                        if not tinc_ready:
                            self.d.msgbox("The tinc VPN could not be set up. Thus, we abort the redundancy setup.")
                            return
                    else:
                        return
                code = self.d.yesno(
                    "The privacyIDEA appliance includes a FreeRADIUS server that redirects authentication requests "
                    "to the local privacyIDEA instance. Should we copy the current local FreeRADIUS configuration to "
                    "the remote server?",
                    width=60
                )
                if code == self.d.OK:
                    if not radius_installed:
                        self.d.msgbox("privacyidea-radius is not installed on {}. Please install "
                                      "privacyidea-radius.".format(self.peer.remote_ip), width=60)
                        return
                    self.peer.setup_freeradius()
                self.peer.setup_redundancy()

    def stop_redundancy(self):
        message = ("Do you really want to stop the redundancy? This "
                   "server will be reverted to a single master. The "
                   "other master will not be touched. You can simply "
                   "shut down the other machine.")
        if self.peer.is_tinc_configured():
            message += "\n"
            message += "The tinc VPN 'privacyideaVPN' will also be deleted."

        code = self.d.yesno(message, width=60, height=10)
        if code == self.d.OK:
            self.peer.stop_redundancy()
            if self.peer.is_tinc_configured():
                self.peer.delete_tinc()

    def redundancy_status(self):
        r, bind, server_id = self.db.is_redundant()
        info = [
            u"Master-Master replication active: {active!s}\n"
            u"Server ID: {server_id!s}\n"
            u"Bind Address: {bind_address!s}\n".format(active=r, bind_address=bind, server_id=server_id)]
        if r:
            master_status = self.peer.get_redundancy_status("MASTER")
            slave_status = self.peer.get_redundancy_status("SLAVE")
            slave_sql_error = slave_status['Last_SQL_Error'] or '(none)'
            slave_io_error = slave_status['Last_IO_Error'] or '(none)'
            info.append(
                u"Master\n"
                u"------\n"
                u"File: {master_file}\n"
                u"Position: {master_position}\n"
                u"\n"
                u"Slave\n"
                u"-----\n"
                u"Last SQL Error: {slave_sql_error}\n"
                u"Last IO Error: {slave_io_error}".format(master_file=master_status['File'],
                                                          master_position=master_status['Position'],
                                                          slave_sql_error=slave_sql_error,
                                                          slave_io_error=slave_io_error))
        self.d.msgbox("\n".join(info), width=60, height=20)

    def db_init(self):
        db_connect = self.pConfig.get_DB()
        code = self.d.yesno("Do you want to recreate the tables? "
                            "Existing data will not be lost. Only new tables "
                            "in the database scheme will be created on %s" %
                            db_connect,
                            width=70,
                            backtitle="Create database tables")
        if code == self.d.OK:
            r = self.pConfig.DB_init()
            if r:
                self.d.msgbox("Created database tables.")
            else:
                self.d.scrollbox("Error creating database tables.")


class AuditMenu(object):

    def __init__(self, app, dialog):
        self.app = app
        self.d = dialog
        self.Audit = Audit()

    def menu(self):
        bt = "Audit Log Rotation"
        self.Audit.read()
        while 1:
            code, tags = self.d.menu("Auditlog Rotate",
                                     choices=[("Configure Audit Log", "")],
                                     cancel='Back',
                                     backtitle=bt)
            if code == self.d.OK:
                if tags.startswith("Configure"):
                    self.config()
            else:
                break

    def config(self):
        '''
        Display the cronjobs of user privacyidea
        '''
        bt = "Define rotation times."
        while 1:
            cronjobs = self.Audit.get_cronjobs()
            choices = [(self.add, "Add new rotate check date", "")]
            for cronjob in cronjobs:
                comment = cronjob.get_time_comment()
                if comment:
                    full_comment = "{} audit rotation".format(comment)
                else:
                    full_comment = "audit rotation"
                choices.append((partial(self.delete, cronjob),
                                " ".join(cronjob.time),
                                full_comment))
            choice = self.d.value_menu("Here you can define times, when to run a audit rotation check.",
                                       cancel='Back',
                                       choices=choices,
                                       backtitle=bt,
                                       width=70)

            if choice is not None:
                choice()
            else:
                break

    def add(self):
        '''
        Add an audit rotation
        '''
        bt = "Add a new Audit rotation"
        age = ""
        watermark = ""

        code, typ = self.d.menu("You can either rotate the audit log by age "
                                "or by the number of log entries:",
                                choices=[("by age", "",
                                          "Audit entries older than certain days will be deleted."),
                                         ("by entries", "",
                                          "If the number of entries exceed "
                                          "the highwatermark, the entries "
                                          "will be deleted to lowwatermark.")],
                                backtitle=bt, item_help=1)
        if code != self.d.OK:
            return

        if typ.startswith("by age"):
            code, age = self.d.inputbox("Number of days how old the oldest "
                                        "log entry should be:",
                                        width=70,
                                        backtitle=bt)
        else:
            code, watermark = self.d.inputbox("Please enter <highwatermark>,"
                                              "<lowwatermark>.",
                                              width=70,
                                              backtitle=bt)

        if code != self.d.OK:
            return

        code, bdate = self.d.inputbox("The date to run the audit rotation. "
                                      "Please enter it like this:\n"
                                      "<Minute>  <Hour>  <Day-of-Month> "
                                      " <Month>  <Day-of-Week>\n"
                                      "You may use '*' as wildcard entry.",
                                      width=70,
                                      backtitle=bt)

        if code == self.d.OK:
            date_fragments = bdate.split()
            if len(date_fragments) > 5:
                return
            params = {"age": age,
                      "watermark": watermark}
            self.Audit.add_rotate(date_fragments, params)

    def delete(self, cronjob):
        '''
        Delete the Audit rotation
        '''
        bt = "Delete an audit rotation"
        code = self.d.yesno("Do you want to delete the following audit rotation job?\n\n{}".format(
            cronjob.get_time_summary()
        ), backtitle=bt, width=70)
        if code == self.d.OK:
            self.Audit.del_rotate(cronjob)


class UpdatesMenu(object):
    def __init__(self, app, dialog):
        self.app = app
        self.d = dialog
        self.updates = Updates()

    def menu(self):
        while True:
            self.updates.read()
            choices = [(self.add_update, "Add new update cronjob", "")]
            for cronjob, options in self.updates.get_update_cronjobs():
                choices.append((partial(self.delete_update, cronjob),
                                " ".join(cronjob.time),
                                "'{}' packages".format(options['-t'])))
            menu = self.d.value_menu("Updates",
                                     choices=choices,
                                     cancel='Back',
                                     backtitle='Automatic Updates Configuration')
            if menu is not None:
                menu()
            else:
                break

    def add_update(self):
        bt = "Add an automatic update job"
        code, update_date = self.d.inputbox("The date to run the update. "
                                      "Please enter it like this:\n"
                                      "<Minute>  <Hour>  <Day-of-Month> "
                                      " <Month>  <Day-of-Week>\n"
                                      "You may use '*' as wildcard entry.",
                                      width=70,
                                      backtitle=bt)

        if code != self.d.OK:
            return

        date_fragments = update_date.split()
        if len(date_fragments) > 5:
            return

        update_type = self.d.value_radiolist("Please specify which updates should be installed.",
                                             choices=[
                                                 (UPDATE_SECURITY, "security", "Install security updates only"),
                                                 (UPDATE_UPDATES, "updates", "Install general updates")
                                             ],
                                             current=UPDATE_SECURITY,
                                             backtitle=bt)
        if update_type is None:
            return

        code = self.d.yesno("Some updates might require a reboot to take effect, like installing a new kernel.\n"
                            "Should the system be rebooted after the update, if the update requires a reboot?",
                            width=70,
                            backtitle=bt)
        boot = (code == self.d.OK)

        self.updates.add_update_cronjob(date_fragments, update_type, boot)

    def delete_update(self, cronjob):
        code = self.d.yesno("Do you want to delete the following automatic update job?\n\n"
                            "{}\n{}".format(cronjob.command, cronjob.get_time_summary()),
                            width=70)
        if code == self.d.OK:
            self.updates.delete_cronjob(cronjob)


class BackupMenu(object):

    def __init__(self, app, dialog):
        self.app = app
        self.d = dialog
        self.Backup = Backup()

    def menu(self):
        bt = "Backup and Restore configuration"
        self.Backup.read()
        choices = [(self.config, "Configure backup", ""),
                   (self.now, "Backup now", ""),
                   (self.view, "View Backups", ""),
                   (self.cleanup, "Set backup rotation", "")]
        while 1:
            menu = self.d.value_menu("Backup and Restore",
                                     choices=choices,
                                     cancel='Back',
                                     backtitle=bt)
            if menu is not None:
                menu()
            else:
                break

    def config(self):
        '''
        Display the cronjobs of user privacyidea
        '''
        bt = "Define backup times"
        while 1:
            cronjobs = self.Backup.get_cronjobs()
            choices = [(self.add, "Add new backup date", "")]
            for cronjob in cronjobs:
                if cronjob.user == CRON_USER and \
                        cronjob.command.startswith(BACKUP_CMD):
                    comment = cronjob.get_time_comment()
                    if comment:
                        full_comment = "{} backup job.".format(comment)
                    else:
                        full_comment = "backup job."
                    choices.append((partial(self.delete, cronjob),
                                    " ".join(cronjob.time),
                                    full_comment))
            choice = self.d.value_menu("Here you can define times, when to run a backup.",
                                       cancel='Back',
                                       choices=choices,
                                       backtitle=bt)

            if choice is not None:
                choice()
            else:
                break
        pass

    def cleanup(self):
        """
        Ask for a number of days and set these backup rotation
        :return:
        """
        bt = "Set the number of days, backups should be saved"
        code, bdays = self.d.inputbox("Enter number of days, for long we should keep the backups.",
                                      width=70,
                                      backtitle=bt)
        if code == self.d.OK:
            try:
                days = int(bdays)
            except ValueError:
                days = 90
            self.Backup.backup_clean(days)

    def add(self):
        '''
        Add a backup date.
        '''
        bt = "Add a new backup date"
        code, bdate = self.d.inputbox("The date to run the backup. "
                                      "Please enter it like this:\n"
                                      "<Minute>  <Hour>  <Day-of-Month> "
                                      " <Month>  <Day-of-Week>\n"
                                      "You may use '*' as wildcard entry.\n"
                                      "Please note that the backup will not contain the encryption key.",
                                      width=70,
                                      backtitle=bt)

        if code == self.d.OK:
            date_fragments = bdate.split()
            if len(date_fragments) > 5:
                return
            self.Backup.add_backup_time(date_fragments)

    def delete(self, cronjob):
        '''
        Delete a backup date
        '''
        bt = "Delete a backup date"
        code = self.d.yesno("Do you want to delete the following backup job?\n\n{}".format(cronjob.get_time_summary()),
                            backtitle=bt,
                            width=70)
        if code == self.d.OK:
            # Delete backup job.
            self.Backup.del_backup(cronjob)

    def restore(self, tag):
        '''
        Restore a backup
        '''
        bt = "Restore a backup"
        code = self.d.yesno("Are you sure you want to restore the backup %s? "
                            "Current data will be lost. The restore will "
                            "administrator settings, token database, audit log, RADIUS "
                            "clients, server certificates... "
                            "If unsure, please "
                            "perform a backup before restoring the old one."
                            % tag,
                            width=70)
        if code == self.d.OK:
            # Restore the backup
            self.d.gauge_start("Restoring backup %s" % tag, percent=20)
            success, stdout, stderr = self.Backup.restore_backup(tag)
            self.d.gauge_update(percent=90)
            time.sleep(1)
            self.d.gauge_stop()
            if success:
                self.d.scrollbox(u"Backup successfully restored!\n\n{}".format(stdout))
                mark_service_for_restart(SERVICE_APACHE)
            else:
                text = u"""
Restore failed:

{}
""".format(stderr)
                self.d.scrollbox(text)

    def now(self):
        '''
        Run the backup now.
        '''
        success, stdout, stderr = self.Backup.backup_now()
        if success:
            self.d.msgbox(u"Backup successfully created! "
                          u"Please note that it does not contain the encryption key.")
        else:
            text = u"""
Backup failed:

{}
""".format(stderr)
            self.d.scrollbox(text)

    def view(self):
        '''
        View the saved backup files to restore one.
        '''
        bt = "Restore a backup"
        while 1:
            backups = self.Backup.get_backups()
            choices = []
            for bfile in sorted(backups.keys(), reverse=True):
                choices.append((bfile, "%s %s" % (backups[bfile].get("size"),
                                                  backups[bfile].get("time"))))
            if len(choices) == 0:
                self.d.msgbox("No backups found!")
                break
            else:
                code, tags = self.d.menu("Choose a backup you wish to "
                                         "restore...",
                                         choices=choices,
                                         backtitle=bt,
                                         width=78)
                if code == self.d.OK:
                    self.restore(tags)
                else:
                    break


class RadiusMenu(object):

    def __init__(self, app, dialog):
        self.app = app
        self.d = dialog
        try:
            self.RadiusConfig = FreeRADIUSConfig()
        except:
            # No Radius Server available
            self.RadiusConfig = None

    @property
    def should_display(self):
        return bool(self.RadiusConfig)

    def menu(self):
        choices = [(self.clients, "client config", ""),
                   (self.sites, "sites", "Enable and disable RADIUS sites")]
        while 1:
            menu = self.d.value_menu("Configure FreeRADIUS",
                                     choices=choices,
                                     cancel='Back')
            if menu is not None:
                menu()
            else:
                break

    def sites(self):
        sites = self.RadiusConfig.get_sites()
        code, tags = self.d.checklist("The FreeRADIUS sites you want to "
                                      "enable. You should only enable "
                                      "'privacyidea' unless you know "
                                      "exactly what you are doing!",
                                      choices=sites,
                                      backtitle="Enable sites")
        if code == self.d.OK:
            self.RadiusConfig.enable_sites(tags)
            mark_service_for_restart(SERVICE_FREERADIUS)

    def clients(self):
        while 1:
            clients = [("Add new client", "Add a new RADIUS client")]
            clients_from_file = self.RadiusConfig.clients_get()
            for client, v in clients_from_file.items():
                clients.append((client, "%s/%s (%s)" % (v.get("ipaddr"),
                                                        v.get("netmask"),
                                                        v.get("shortname"))))
            code, tags = self.d.menu("You can select an existing RADIUS client "
                                     "to either delete it or change it "
                                     "or create a new client",
                                     choices=clients,
                                     cancel='Back',
                                     backtitle="Manage RADIUS clients")

            if code == self.d.OK:
                if tags.startswith("Add new"):
                    self.add()
                else:
                    self.manage(tags)
            else:
                break

    def add(self):
        bt = "Add a new RADIUS client"
        code, clientname = self.d.inputbox("The name of the new client",
                                           backtitle=bt)
        if code != self.d.OK:
            return
        code, ip = self.d.inputbox("The IP address of the new client %s" %
                                   clientname,
                                   backtitle=bt)
        if code != self.d.OK:
            return

        code, netmask = self.d.radiolist("The netmask of the new client %s." % clientname,
                                         choices=[("32", "255.255.255.255 ("
                                                         "single Host)", 0),
                                                  ("24", "255.255.255.0", 1),
                                                  ("16", "255.255.0.0", 0),
                                                  ("8", "255.0.0.0", 0),
                                                  ("0", "0.0.0.0 ("
                                                        "everything)", 0),
                                                  ("1", "128.0.0.0", 0),
                                                  ("2", "192.0.0.0", 0),
                                                  ("3", "224.0.0.0", 0),
                                                  ("4", "240.0.0.0", 0),
                                                  ("5", "248.0.0.0", 0),
                                                  ("6", "252.0.0.0", 0),
                                                  ("7", "254.0.0.0", 0),
                                                  ("9", "255.128.0.0", 0),
                                                  ("10", "255.192.0.0", 0),
                                                  ("11", "255.224.0.0", 0),
                                                  ("12", "255.240.0.0", 0),
                                                  ("13", "255.248.0.0", 0),
                                                  ("14", "255.252.0.0", 0),
                                                  ("15", "255.254.0.0", 0),
                                                  ("17", "255.255.128.0", 0),
                                                  ("18", "255.255.192.0", 0),
                                                  ("19", "255.255.224.0", 0),
                                                  ("20", "255.255.240.0", 0),
                                                  ("21", "255.255.248.0", 0),
                                                  ("22", "255.255.252.0", 0),
                                                  ("23", "255.255.254.0", 0),
                                                  ("25", "255.255.255.128", 0),
                                                  ("26", "255.255.255.192", 0),
                                                  ("27", "255.255.255.224", 0),
                                                  ("28", "255.255.255.240", 0),
                                                  ("29", "255.255.255.248", 0),
                                                  ("30", "255.255.255.252", 0),
                                                  ("31", "255.255.255.254", 0)
                                                  ],
                                         backtitle=bt)
        if code != self.d.OK:
            return

        code, secret = self.d.inputbox("The secret of the new client %s" %
                                       clientname,
                                       backtitle=bt)

        code, shortname = self.d.inputbox("The shortname of the new client %s" %
                                          clientname,
                                          backtitle=bt)

        if code == self.d.OK:
            client = {}
            if ip:
                client["ipaddr"] = ip
            if netmask:
                client["netmask"] = netmask
            if secret:
                client["secret"] = secret
            if shortname:
                client["shortname"] = shortname
            self.RadiusConfig.client_add({clientname: client})
            mark_service_for_restart(SERVICE_FREERADIUS)

    def manage(self, clientname):
        bt = "Manage client %s" % clientname
        code, tags = self.d.menu("Manage client %s." % clientname,
                                 choices=[("Delete client", "")],
                                 backtitle=bt)
        if code == self.d.OK:
            if tags.startswith("Delete"):
                code = self.d.yesno("Do you really want to delete the "
                                    "RADIUS client %s?" % clientname)
                if code == self.d.OK:
                    self.RadiusConfig.client_delete(clientname)
                    mark_service_for_restart(SERVICE_FREERADIUS)


class LDAPProxyMenu(object):
    def __init__(self, app, dialog):
        self.app = app
        self.d = dialog
        self.config = LDAPProxyConfig()
        self.service = LDAPProxyService()

    @property
    def should_display(self):
        return self.config.exists

    def menu(self):
        while 1:
            choices = []
            if self.service.enabled:
                if not self.service.active:
                    restart_label = "Start LDAP Proxy"
                else:
                    restart_label = "Restart LDAP Proxy"
                choices.extend([(self.restart_service, restart_label, ""),
                                (self.disable_service, "Disable LDAP Proxy", ""),
                                (lambda: None, "=" * 40, ""),
                                (self.proxy_settings, "Port and Interface", ""),
                                (self.ldap_backend, "LDAP Backend", ""),
                                (self.passthrough_binds, "Passthrough Binds", ""),
                                (self.service_account, "Service Account", ""),
                                (self.user_mapping, "User Mapping", ""),
                                (self.realm_mapping, "Realm Mapping", ""),
                                (self.search_permissions, "Search Permissions", "")])
            else:
                choices.append((self.enable_service, "Enable LDAP Proxy", ""))
            menu = self.d.value_menu("LDAP Proxy",
                                     choices=choices,
                                     cancel='Back')
            if menu is not None:
                menu()
            else:
                break

    def restart_service(self):
        if not self.service.restart():
            self.d.msgbox("Could not restart the LDAP Proxy.")

    def enable_service(self):
        """
        Enable and start the LDAP proxy.
        However, check if the config is initialized first. If not, run the wizard and enable it afterwards.
        """
        if not self.config.initialized:
            # Don't proceed if the wizard has been canceled
            if not self.wizard():
                return
        self.service.enable()
        self.restart_service()

    def disable_service(self):
        """ disable and stop the LDAP proxy """
        self.service.stop()
        self.service.disable()

    def mark_for_restart(self):
        mark_service_for_restart(SERVICE_LDAP_PROXY)

    def wizard(self):
        self.d.msgbox('Welcome to the LDAP Proxy Wizard!')  # TODO: Wording
        # This is a list of functions to call sequentially in order to initially configure the LDAP Proxy.
        # If any of the functions fails (returns False), the user has cancelled the wizard.
        # The config file is only written if the wizard is completed successfully.
        steps = [
            self.proxy_settings,
            self.ldap_backend,
            lambda: self.passthrough_binds('Continue'),
            self.user_mapping,
            self.realm_mapping,
            # NOTE: Service Account will be configured implicitly by the user mapping or search permissions dialogs!
            self.search_permissions,
        ]
        with self.config.set_autosave(False):
            self.config.set_default_config()
            # Add empty service account and empty passthrough DN list, otherwise the config is considered invalid
            self.config.set_service_account('', '')
            self.config.set_passthrough_binds([])
            # Run through all steps. If any step fails, reset the config and cancel the wizard.
            for step in steps:
                if not step():
                    self.config.reset()
                    return False
            # If we reach this, we can finally save the config!
            self.config.save()
            self.d.msgbox('Congratulations! You have successfully set up the LDAP proxy.')
        return True

    def user_mapping(self):
        while True:
            mapping_choices = [('match', 'match', '', 'Extract username from DN using a regular expression'),
                               ('lookup', 'lookup', '', 'Extract username from a LDAP attribute')]
            strategy = self.d.value_radiolist("Please select the strategy that should be used to map "
                                              "Bind DNs to privacyIDEA usernames",
                                              choices=mapping_choices,
                                              current=self.config.user_mapping_strategy,
                                              item_help=True)
            if strategy is None:
                return False
            if strategy == 'match':
                current_pattern = self.config.user_mapping_config.get('pattern', '')
                code, pattern = self.d.inputbox("Please enter a regular expression to match incoming Bind DNs "
                                                "against. The pattern should have one capturing group, which is "
                                                "the privacyIDEA username.",
                                                width=70,
                                                init=current_pattern)
                if code != self.d.OK:
                    return False
                self.config.set_user_mapping_config({
                    'strategy': 'match',
                    'pattern': pattern,
                })
                self.mark_for_restart()
                return True
            elif strategy == 'lookup':
                current_attribute = self.config.user_mapping_config.get('attribute', '')
                code, attribute = self.d.inputbox("Please enter the LDAP attribute which "
                                                  "contains the privacyIDEA username.",
                                                  width=70,
                                                  init=current_attribute)
                if code != self.d.OK:
                    return False
                self.config.set_user_mapping_config({
                    'strategy': 'lookup',
                    'attribute': attribute,
                })
                self.mark_for_restart()
                # Ensure that there is a service account set
                service_account_dn, service_account_password = self.config.service_account
                if not service_account_dn:
                    self.d.msgbox('In order to use the "lookup" mapping strategy, a service account needs to be '
                                  'configured in the following.',
                                  width=70)
                    return self.service_account()
                else:
                    return True
            else:
                raise NotImplementedError()

    def realm_mapping(self):
        mapping_choices = [('static', 'static',
                            '', 'Statically assign the same realm to all users')]
        strategy = self.d.value_radiolist('Please select the strategy according to which privacyIDEA realms '
                                          'should be assigned to authentication requests.',
                                          choices=mapping_choices,
                                          current=self.config.realm_mapping_strategy,
                                          item_help=True)
        if strategy is None:
            return False
        if strategy == 'static':
            current_realm = self.config.realm_mapping_config.get('realm', '')
            code, realm = self.d.inputbox("Please enter the privacyIDEA realm that should be assigned to "
                                          "all authentication requests. You can also leave it blank to use "
                                          "the privacyIDEA default realm.",
                                          width=70,
                                          init=current_realm)
            if code != self.d.OK:
                return False
            self.config.set_realm_mapping_config({
                'strategy': 'static',
                'realm': realm
            })
            self.mark_for_restart()
            return True
        else:
            raise NotImplementedError()

    def passthrough_binds(self, cancel_label='Back'):
        while True:
            dns = self.config.passthrough_binds
            choices = [(self.add_passthrough_bind, 'Add new Passthrough Bind DN', '')]
            for dn in dns:
                choices.append((partial(self.remove_passthrough_bind, dn), dn, ''))
            menu = self.d.value_menu("You can select an existing DN "
                                     "to delete it or create a new passthrough bind DN",
                                     choices=choices,
                                     backtitle="Manage Passthrough Binds",
                                     cancel=cancel_label)
            if menu is not None:
                menu()
            else:
                return True

    def service_account(self):
        service_account_dn, service_account_password = self.config.service_account
        code, dn = self.d.inputbox('Please enter the Distinguished Name of the Service Account:',
                                   init=service_account_dn,
                                   width=60)
        if code != self.d.OK:
            return False
        code, password = self.d.passwordbox('Please enter the password of the Service Account:\n'
                                            '(your typing will not be visible)',
                                            width=60)
        if code != self.d.OK:
            return False
        # if the given password is empty, the user probably wants to re-use the currently set password
        # TODO: What if the password is intentionally empty?
        if not password:
            password = service_account_password
        self.config.set_service_account(dn, password)
        self.mark_for_restart()
        return True

    def add_passthrough_bind(self):
        code, dn = self.d.inputbox('Please enter the Distinguished Name for '
                                   'which LDAP Bind Requests '
                                   'should be forwarded directly to the LDAP Backend:',
                                   width=60)
        if code != self.d.OK:
            return
        self.config.add_passthrough_bind(dn)
        self.mark_for_restart()

    def remove_passthrough_bind(self, dn):
        code = self.d.yesno("Do you really want to delete the Passthrough Bind DN\n{}?".format(dn),
                            width=60)
        if code == self.d.OK:
            self.config.remove_passthrough_bind(dn)
            self.mark_for_restart()

    def proxy_settings(self):
        current_port, current_interface = self.config.proxy_settings
        port = self._ask_for_ldap_port('Please enter the port to serve the LDAP '
                                       'proxy on (default: 389):',
                                       init=current_port)
        if port is None:
            return False
        code, interface = self.d.inputbox('Please enter the interface to serve the LDAP '
                                          'proxy on (leave blank to listen on all interfaces):',
                                          init=current_interface)
        if code != self.d.OK:
            return False
        # TODO: Test connection?
        endpoint = self._build_server_endpoint_string(port, interface)
        self.config.set_proxy_endpoint(endpoint)
        self.mark_for_restart()
        return True

    def _ask_for_ldap_port(self, message, init=''):
        while True:
            code, port_string = self.d.inputbox(message, init=init)
            if code != self.d.OK:
                return None
            try:
                if port_string:
                    port = int(port_string)
                else:
                    port = 389
                return port
            except ValueError:
                self.d.msgbox('{} is not a valid port!'.format(port_string))

    def ldap_backend(self):
        current_protocol, current_host, current_port = self.config.backend_settings
        code, host = self.d.inputbox('Please enter the IP address of the LDAP backend:',
                                     init=current_host)
        if code != self.d.OK:
            return False
        port = self._ask_for_ldap_port('Please enter the port to connect to (default: 389):',
                                       init=current_port)
        if port is None:
            return False
        protocol = self.d.value_radiolist('Please choose the protocol to use for the connection:',
                                          choices=[('LDAP', 'LDAP', 'unencrypted LDAP'),
                                                   # ('STARTTLS', 'LDAP and opportunistic TLS'),
                                                   #  TODO: STARTTLS not yet supported
                                                   ('LDAPS', 'LDAPS', 'LDAP over TLS')],
                                          current=current_protocol)
        if protocol is None:
            return False
        # TODO: give trust roots
        endpoint = self._build_client_endpoint_string(protocol, host, port)
        self.config.set_backend_endpoint(endpoint)
        self.mark_for_restart()
        # TODO: We could actually test the connection here!
        return True

    def search_permissions(self):
        choices = [
            # allow-search = false, bind-service-account = false
            ((False, False),
             'no searches are forwarded', '',
             'LDAP searches are never forwarded to the backend.'),
            # allow-search = true, bind-service-account = false
            ((True, False),
             'only searches by passthrough DNs are forwarded', '',
             'Only LDAP searches by users listed in "Passthrough'
             ' DNs" are forwarded to the backend.'),
            # allow-search = true, bind-service-account = true
            ((True, True),
             'all searches are forwarded', '',
             'All authenticated users can issue LDAP searches after authentication.')]
        # TODO: What to do if the user has set allow-search=False, bind-service-account=True?
        choice = self.d.value_radiolist('Please choose how incoming LDAP Search Requests should be '
                                        'handled by the LDAP Proxy.',
                                        choices=choices,
                                        item_help=True,
                                        current=self.config.search_permissions,
                                        width=70)
        if choice is None:
            return False
        allow_search, bind_service_account = choice
        self.config.set_search_permissions(allow_search, bind_service_account)
        self.mark_for_restart()
        if allow_search and bind_service_account:
            # display disclaimer
            self.d.msgbox('From now on, all searches by authenticated users are forwarded to the LDAP server. '
                          'Please note that this is accomplished by forwarding search requests '
                          'to the LDAP backend in the context of the service account, which may constitute '
                          'an information leak!',
                          width=70)
            # Ensure that there is a service account set
            service_account_dn, service_account_password = self.config.service_account
            if not service_account_dn:
                self.d.msgbox('In order to forward all searches to the LDAP backend, a service account needs to be '
                              'configured in the following.',
                              width=70)
                return self.service_account()
            else:
                return True
        else:
            return True

    @staticmethod
    def _build_client_endpoint_string(protocol, host, port):
        prefix = {'LDAP': 'tcp', 'LDAPS': 'tls'}[protocol]
        return '{prefix}:host={host}:port={port}'.format(prefix=prefix,
                                                         host=host,
                                                         port=port)

    @staticmethod
    def _build_server_endpoint_string(port, interface=''):
        if interface:
            interface_string = ':interface={}'.format(interface)
        else:
            interface_string = ''
        return 'tcp:port={port}'.format(port=port) + interface_string


class MainMenu(object):

    def __init__(self, config=None):
        if config:
            self.config_file = config
        else:
            self.config_file = DEFAULT_CONFIG

        try:
            self.pConfig = PrivacyIDEAConfig(self.config_file)
        except IOError:
            sys.stderr.write("=" * 75)
            sys.stderr.write("\nCan not access {0!s}. You need to have read "
                             "and write access to this "
                             "file.\n".format(self.config_file))
            sys.exit(5)

        self.app = create_app(config_name="production")
        self.d = ExtDialog(dialog="dialog")
        self.radiusDialog = RadiusMenu(self.app, self.d)
        self.backupDialog = BackupMenu(self.app, self.d)
        self.updatesDialog = UpdatesMenu(self.app, self.d)
        self.dbDialog = DBMenu(self.app, self.d, self.pConfig)
        self.webserverDialog = WebserverMenu(self.app, self.d)
        self.auditDialog = AuditMenu(self.app, self.d)
        self.ldap_proxy_dialog = LDAPProxyMenu(self.app, self.d)

    def restart_services_if_needed(self):
        if services_for_restart:
            code = self.d.yesno("Do you want to restart the services for the "
                                "changes to take effect?")
            if code == self.d.OK:
                for service in services_for_restart:
                    OSConfig.restart(service, True)
                reset_services_for_restart()

    def main_menu(self):
        # As we use ``self.d.choice``, we can simply pass the function to call as the return value.
        choices = [(self.privacyidea_menu,
                    "privacyIDEA", "",
                    "Configure privacyIDEA application stuff like administrators.")
                   ]
        if self.radiusDialog.should_display:
            choices.append((self.radiusDialog.menu,
                            "FreeRADIUS", "",
                            "Configure RADIUS settings like the RADIUS clients."))
        choices.append((self.dbDialog.menu,
                        "Database", "",
                        "Configure database and setup redundancy"))
        choices.append((self.webserverDialog.menu,
                        "Webserver", "",
                        "Restart Webserver"))
        choices.append((self.backupDialog.menu,
                        "Backup and Restore", "",
                        "Backup or Restore of privacyIDEA "
                        "configuration and database."))
        choices.append((self.updatesDialog.menu,
                        "Updates", "",
                        "Define times when the system should be updated automatically."))
        choices.append((self.auditDialog.menu,
                        "Audit Rotation", "",
                        "Define times when to check if the Audit log should "
                        "be rotated."))
        if self.ldap_proxy_dialog.should_display:
            choices.append((self.ldap_proxy_dialog.menu,
                            "LDAP Proxy", "",
                            "Configure a local instance of the privacyIDEA LDAP Proxy"))

        while 1:
            menu = self.d.value_menu("Which subject do you want to configure?",
                                     choices=choices,
                                     backtitle="privacyIDEA configuration",
                                     cancel="Exit",
                                     item_help=True)
            if menu is not None:
                menu()
            else:
                # End
                self.restart_services_if_needed()
                break

    def privacyidea_menu(self):
        choices = [(self.privacyidea_view, "view config", "Display configuration.", ""),
                   (self.privacyidea_loglevel, "loglevel", "Change log level.", ""),
                   (self.privacyidea_adminrealms, "admin realms", "Modify admin realms.", ""),
                   (self.privacyidea_admins, "manage local admins", "Modify admins.", ""),
                   (self.privacyidea_danger_menu, "Danger zone!", "Enter at your own risk!",
                    "Here you may recreated your encryption and signing keys.")]
        while 1:
            menu = self.d.value_menu(
                "Configure privacyidea",
                choices=choices,
                menu_height=22,
                cancel='Back',
                backtitle="privacyIDEA configuration",
                item_help=True)

            if menu is not None:
                menu()
            else:
                break

    def privacyidea_danger_menu(self):
        choices = [(self.privacyidea_initialize,
                    "initialize pi.cfg", "Create new pi.cfg-file.",
                    "This will also create new salt and pepper."
                    " Admins will not be able to login anymore!"),
                   (self.privacyidea_enckey, "encryption key", "Create new encryption key.",
                    "Token seeds can not be decrypted anymore!"),
                   (self.privacyidea_sign, "signing key", "Create new audit signing key.",
                    "Old audit entries can not be verified anymore.")]
        while 1:
            menu = self.d.value_menu(
                "privacyIDEA Danger Zone",
                choices=choices,
                menu_height=22,
                cancel='Back',
                backtitle="privacyIDEA Danger Zone",
                item_help=True)

            if menu is not None:
                menu()
            else:
                break

    def privacyidea_admins(self):
        while 1:
            with self.app.app_context():
                db_admins = get_db_admins()
            admins = [("Add new admin", "Add a new administrator")]
            for admin in db_admins:
                admins.append((admin.username, admin.email or ""))
            code, tags = self.d.menu("You can select an existing administrator "
                                     "to either delete it or change the "
                                     "password or create a new admin",
                                     choices=admins,
                                     cancel='Back',
                                     backtitle="Manage administrators")

            if code == self.d.OK:
                if tags == "Add new admin":
                    self.privacyidea_admin_add()
                else:
                    self.privacyidea_admin_manage(tags)
            else:
                break

    def privacyidea_admin_manage(self, admin_name):
        bt = "Manage administrator"
        code, tags = self.d.menu("Manage admin %s" % admin_name,
                                 choices=[("Delete admin", ""),
                                          ("Change password", "")],
                                 backtitle=bt)
        if code == self.d.OK:
            if tags.startswith("Delete"):
                code = self.d.yesno("Do you really want to delete the "
                                    "administrator %s?" % admin_name)
                if code == self.d.OK:
                    with self.app.app_context():
                        delete_db_admin(admin_name)

            if tags.startswith("Change password"):
                password = self.privacyidea_admin_password(admin_name)
                pass

    def privacyidea_admin_password(self, admin_name, create=False):
        bt = "Setting password for administrator %s" % admin_name
        password = None
        while 1:
            code, password1 = self.d.passwordbox("Enter the password for the "
                                                 "administrator %s.\n"
                                                 "(Your typing will not be "
                                                 "visible)" %
                                                 admin_name,
                                                 backtitle=bt)

            if code == self.d.OK:
                code, password2 = self.d.passwordbox("Repeat the password",
                                                     backtitle=bt)
                if code == self.d.OK:
                    if password1 != password2:
                        self.d.msgbox("The passwords do not match. "
                                      "Please try again.")
                    else:
                        password = password1
                        with self.app.app_context():
                            create_db_admin(self.app, admin_name,
                                            password=password)
                        break
                else:
                    break
            else:
                break
        return password

    def privacyidea_admin_add(self):
        bt = "Add a new administrator"
        code, admin_name = self.d.inputbox("The username of the new "
                                           "administrator",
                                           backtitle=bt)

        if code == self.d.OK:
            password = self.privacyidea_admin_password(admin_name,
                                                       create=True)

    def privacyidea_adminrealms(self):
        adminrealms = self.pConfig.get_superusers()
        # convert to string
        adminrealms = ",".join(adminrealms)
        code, tags = self.d.inputbox("You may enter a comma separated list "
                                     "of realms that are recognized as "
                                     "admin realms.",
                                     init=adminrealms,
                                     width=40,
                                     backtitle="configure admin realms")
        if code == self.d.OK:
            # convert to list with no whitespaces in elements
            adminrealms = [x.strip() for x in tags.split(",")]
            self.pConfig.set_superusers(adminrealms)
            self.pConfig.save()
            mark_service_for_restart(SERVICE_APACHE)

    def privacyidea_initialize(self):
        code = self.d.yesno("Do you want to initialize "
                            "the config file? Old privacyIDEA "
                            "configurations will be overwritten!",
                            backtitle="Initialize privacyIDEA configuration",
                            defaultno=1)
        if code == self.d.OK:
            self.pConfig.initialize()
            self.pConfig.save()
            mark_service_for_restart(SERVICE_APACHE)

    def privacyidea_enckey(self):
        code = self.d.yesno("Do you want to create a new encryption key? "
                            "All token keys will not be readable anymore!",
                            backtitle="Create a new encryption key.",
                            defaultno=1)
        if code == self.d.OK:
            r, f = self.pConfig.create_encryption_key()
            if r:
                self.d.msgbox("Successfully created new encryption key %s." %
                              f)
            else:
                self.d.msgbox("Failed to create new encryption key %s!" %
                              f)

    def privacyidea_sign(self):
        code = self.d.yesno("Do you want to create a new audit trail "
                            "signing key? "
                            "Older audit entries can not be verified anymore.",
                            backtitle="Create a new signing key.",
                            defaultno=1)
        if code == self.d.OK:
            r, f = self.pConfig.create_audit_keys()
            if r:
                self.d.msgbox("Successfully created new audit keys %s." %
                              f)
            else:
                self.d.msgbox("Failed to create new audit keys %s!" % f)

    def privacyidea_loglevel(self):
        loglevel = self.pConfig.get_loglevel()
        code, tags = self.d.radiolist(
            "choose a loglevel",
            choices=[("logging.DEBUG", "Excessive logging.",
                      int(loglevel == "logging.DEBUG")),
                     ("logging.INFO", "Normal logging.",
                      int(loglevel == "logging.INFO")),
                     ("logging.WARN", "Only log warnings.",
                      int(loglevel == "logging.WARN")),
                     ("logging.ERROR", "Sparse logging.",
                      int(loglevel == "logging.ERROR"))],
            backtitle="privacyIDEA loglevel.")
        if code == self.d.OK:
            self.pConfig.set_loglevel(tags)
            self.pConfig.save()
            mark_service_for_restart(SERVICE_APACHE)

    def privacyidea_view(self):
        text = u"""
    The secret key file             : %s
    List of the admin realms        : %s
    Loglevel                        : %s
    """ % (self.pConfig.get_keyfile(),
           self.pConfig.get_superusers(),
           self.pConfig.get_loglevel())
        self.d.scrollbox(text)


def create_arguments():
    parser = argparse.ArgumentParser(description=DESCRIPTION,
                                     fromfile_prefix_chars='@')
    parser.add_argument("-f", "--file",
                        help="The pi.cfg file.",
                        required=False)
    parser.add_argument("-v", "--version",
                        help="Print the version of the program.",
                        action='version', version='%(prog)s ' + VERSION)

    args = parser.parse_args()
    return args


def main():
    locale.setlocale(locale.LC_ALL, '')
    os.environ['NCURSES_NO_UTF8_ACS'] = '1'
    args = create_arguments()
    pS = MainMenu(config=args.file)
    pS.main_menu()
