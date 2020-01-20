#!/usr/bin/python
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
from pwd import getpwnam

import os
import time

import string
from ast import literal_eval
from stat import ST_SIZE, ST_MTIME, S_IWUSR, S_IRUSR
import re
import sys
import random

from authappliance.lib.mysqlparser import mysqlparser
from authappliance.lib.freeradiusparser.freeradiusparser import ClientConfParser
from authappliance.lib.crontabparser.cronjobparser import CronJobParser, CronJob
from authappliance.lib.utils import to_unicode
import socket
from subprocess import Popen, PIPE, call

DATABASE = "privacyidea"
DBUSER = "privacyidea"
POOL = "./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
CRONTAB = "/etc/crontab"
CRON_USER = "privacyidea"
RESTORE_CMD = "pi-manage backup restore %s"
DEFAULT_CONFIG = "/etc/privacyidea/pi.cfg"
BACKUP_DIR = "/var/lib/privacyidea/backup"
BACKUP_CMD = "pi-manage backup create -d %s" % BACKUP_DIR
BACKUP_CLEAN_CMD = "find {backup_dir} -atime +{backup_days} -delete"
AUDIT_CMD = "pi-manage rotate_audit "

SERVICE_APACHE = 'apache2'
SERVICE_FREERADIUS = 'freeradius'
SERVICE_LDAP_PROXY = 'privacyidea-ldap-proxy'


def generate_password(size=6, characters=string.ascii_lowercase +
                      string.ascii_uppercase + string.digits):
    return ''.join(random.choice(characters) for _x in range(size))


class Audit(object):

    def __init__(self):
        self.CP = CronJobParser()

    def read(self):
        ''' Shortcut for self.CP.read '''
        self.CP.read()

    def get_cronjobs(self):
        '''
        Parse the crontab and return the audit rotation cronjobs
        '''
        for cronjob in self.CP.cronjobs:
            if cronjob.user == CRON_USER and cronjob.command.startswith(AUDIT_CMD):
                yield cronjob

    def add_rotate(self, dc, params):
        """
        Add a new audit rotate cron job
        :param dc: date components
        :type dc: list 
        :param params: 
        :return: 
        """
        audit_cmd = AUDIT_CMD
        params = params or {}
        age = params.get("age")
        watermark = params.get("watermark")
        if watermark:
            high, low = watermark.split(",")
            high = int(high.strip())
            low = int(low.strip())
            if high < low:
                high, low = low, high
            audit_cmd += " --highwatermark {0!s} --lowwatermark " \
                         "{1!s}".format(high, low)
        else:
            age = age or 180
            audit_cmd += " --age {0!s} ".format(age)

        self.CP.cronjobs.append(CronJob.from_time(audit_cmd, CRON_USER, dc))
        self.CP.save(CRONTAB)

    def del_rotate(self, cronjob):
        """        
        Remove a cronjob instance from the crontab and save.
        """
        self.CP.cronjobs.remove(cronjob)
        self.CP.save(CRONTAB)


class Backup(object):
    
    def __init__(self,
                 config_dir="/etc/privacyidea/backup",
                 data_dir="/var/lib/privacyidea/backup"):
        self.data_dir = data_dir
        self.CP = CronJobParser()

    def read(self):
        ''' Shortcut for self.CP.read '''
        self.CP.read()

    def backup_now(self, password=None):
        '''
        Create a backup of the system right now
        The current backup will not contain the
        encryption key. This will be encrypted with
        the password.
        Return a tuple (success, stdout, stderr).
        '''
        proc = Popen(BACKUP_CMD, shell=True, stdout=PIPE, stderr=PIPE,
                     universal_newlines=True)
        stdout, stderr = proc.communicate()
        return proc.returncode == 0, stdout, stderr
        
    def restore_backup(self, bfile, password=None):
        '''
        Restore the backup file.
        
        :param bfile: the tgz file name without the path
        :type bfile: string
        :return: tuple (success, stdout, stderr)
        '''
        proc = Popen(RESTORE_CMD % BACKUP_DIR + "/" + bfile, shell=True,
                     stdout=PIPE, stderr=PIPE, universal_newlines=True)
        stdout, stderr = proc.communicate()
        return proc.returncode == 0, stdout, stderr

    def get_cronjobs(self):
        '''
        Parse the cronjobs and yield all backup cronjobs
        '''
        for cronjob in self.CP.cronjobs:
            if cronjob.user == CRON_USER and cronjob.command.startswith(BACKUP_CMD):
                yield cronjob
    
    def add_backup_time(self, dc):
        '''
        Add a backup time to the cronjobs
        
        :param dc: Date component of minute, hour, dom, month, dow
        :type dc: list
        '''
        self.CP.cronjobs.append(CronJob.from_time(BACKUP_CMD, CRON_USER, dc))
        self.CP.save(CRONTAB)
        # Check that privayidea can write the relevant files. Set correct permissions if possible.
        if os.geteuid() == 0:
            self._fix_cron_permissions(BACKUP_DIR)
            self._fix_cron_permissions('/etc/privacyidea/mysql.cnf')

    def backup_clean(self, days=30):
        """
        Add a backup cleaning to the cronjobs
        The backup clean job runs at night at 2 am.

        :param days: Backups older than these days get deleted.
        :return:
        """
        to_delete = [cronjob for cronjob in self.CP.cronjobs
                     if cronjob.command.startswith("find {0!s}".format(BACKUP_DIR))]
        for cronjob in to_delete:
            self.CP.cronjobs.remove(cronjob)
        # Set the new cronjob to rotate the backup_dir
        bcmd = BACKUP_CLEAN_CMD.format(backup_dir=BACKUP_DIR, backup_days=days)
        self.CP.cronjobs.append(CronJob(bcmd, "0", hour="2"))
        self.CP.save(CRONTAB)

    @staticmethod
    def _fix_cron_permissions(filename):
        """
        Check if ``filename`` belongs to root. If it does, chown it to CRON_USER.
        Only call this as root.
        """
        if os.path.exists(filename):
            stat = os.stat(filename)
            if stat.st_uid == 0:
                # Fix permissions! Set owner to CRON_USER
                cron_user_id = getpwnam(CRON_USER).pw_uid
                os.chown(filename, cron_user_id, -1)

    def get_backups(self):
        '''
        List the available backups in the self.data_dir
        
        :return: dict of backups. Key is the filename, and
                 "size" and "time"
        '''
        backups = {}
        try:
            allfiles = os.listdir(self.data_dir)
        except OSError:
            return backups
        
        for f in allfiles:
            if f.startswith("privacyidea-backup"):
                st = os.stat(self.data_dir + "/" + f)
                size = "%iMB" % (int(st[ST_SIZE]) // (1024 * 1024))
                mtime = time.asctime(time.localtime(st[ST_MTIME]))
                backups[f] = {"size": size,
                              "time": mtime}
        return backups
    
    def del_backup(self, cronjob):
        '''
        Delete a backup time from the cronjob
        '''
        self.CP.cronjobs.remove(cronjob)
        self.CP.save(CRONTAB)


class PrivacyIDEAConfig(object):
    
    ini_template = """import logging
# The realm, where users are allowed to login as administrators
SUPERUSER_REALM = ["super"]
# Your database
#SQLALCHEMY_DATABASE_URI = 'sqlite:////etc/privacyidea/data.sqlite'
# This is used to encrypt the auth_token
#SECRET_KEY = 't0p s3cr3t'
# This is used to encrypt the admin passwords
#PI_PEPPER = "Never know..."
# This is used to encrypt the token data and token passwords
PI_ENCFILE = '/etc/privacyidea/enckey'
# This is used to sign the audit log
#PI_AUDIT_MODULE = 'privacyidea.lib.auditmodules.base'
PI_AUDIT_KEY_PRIVATE = '/etc/privacyidea/private.pem'
PI_AUDIT_KEY_PUBLIC = '/etc/privacyidea/public.pem'
PI_PEPPER = 'zzsWra6vnoYFrlVXJM3DlgPO'
SECRET_KEY = 'sfYF0kW6MsZmmg9dBlf5XMWE'
SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://pi:P4yvb3d1Thw_@localhost/pi'
PI_LOGFILE = "/var/log/privacyidea/privacyidea.log"
PI_LOGLEVEL = logging.DEBUG
PI_LOGCONFIG = "/etc/privacyidea/logging.cfg"
"""
    
    def __init__(self, file="/etc/privacyidea/pi.cfg", init=False, opener=open):
        self.file = file
        self.opener = opener
        if init:
            # get the default values
            self.initialize()
        else:
            # read the file
            with opener(self.file, 'r') as f:
                content = f.read()
            self._content_to_config(to_unicode(content))

    def _content_to_config(self, content):
        """

        :param content:
        :type content: str
        :return:
        """
        self.config = {}
        for l in content.split("\n"):
            l = l.strip()
            if l and not l.startswith("import") and not l.startswith("#"):
                key, value = l.split("=", 1)
                key = key.strip()
                value = value.strip()
                if key == "PI_LOGLEVEL":
                    # PI_LOGLEVEL should be one of logging.DEBUG, logging.INFO, logging.WARN, logging.ERROR,
                    # so we store it as a string.
                    parsed_value = value
                else:
                    # All other values should be literals.
                    parsed_value = literal_eval(value)
                self.config[key] = parsed_value

    def initialize(self):
        """
        Initialize the ini file
        """
        content = self.ini_template
        self._content_to_config(content)

    def save(self):
        with self.opener(self.file, 'w') as f:
            f.write("import logging\n")
            for key, value in self.config.items():
                if key == "PI_LOGLEVEL":
                    # PI_LOGLEVEL should be one of "logging.DEBUG", "logging.INFO", "logging.WARN", "logging.ERROR".
                    # Hence, we directly write its value to the pi.cfg file.
                    value_repr = value
                else:
                    # For all other values, we write the string representation.
                    value_repr = repr(value)
                f.write("{0} = {1}\n".format(key, value_repr))
        print("Config file %s saved." % self.file)

    def get_keyfile(self):
        return self.config.get("PI_ENCFILE")

    def get_superusers(self):
        return self.config.get("SUPERUSER_REALM", [])

    def set_superusers(self, realms):
        """
        This sets the superuser realms. A list of known realms is provided.

        :param realms: List of the realms of superusers
        :type realms: list
        :return: None
        """
        self.config["SUPERUSER_REALM"] = realms

    def get_loglevel(self):
        return self.config.get("PI_LOGLEVEL")
    
    def set_loglevel(self, level):
        if level not in ["logging.DEBUG", "logging.INFO",
                         "logging.WARN", "logging.ERROR"]:
            raise Exception("Invalid loglevel specified")
        self.config["PI_LOGLEVEL"] = level

    def create_audit_keys(self):
        # We can not use the RawConfigParser, since it does not
        # replace the (here)s statement
        private = self.config.get("PI_AUDIT_KEY_PRIVATE")
        public = self.config.get("PI_AUDIT_KEY_PUBLIC")

        print("Create private key %s" % private)
        r = call("openssl genrsa -out %s 2048" % private,
                 shell=True)
        if r == 0:
            print("create private key: %s" % private)

        print("Create public key %s" % public)
        r = call("openssl rsa -in %s -pubout -out %s" % (private, public),
                 shell=True)
        if r == 0:
            print("written public key: %s" % private)
            return True, private
        
        return False, private
    
    def create_encryption_key(self):
        # We can not use the RawConfigParser, since it does not
        # replace the (here)s statement
        enckey = self.config.get("PI_ENCFILE")

        r = call("dd if=/dev/urandom of='%s' bs=1 count=96" % enckey,
                 shell=True)
        if r == 0:
            print("written enckey: %s" % enckey)
            return True, enckey
        return False, enckey

    def get_DB(self):
        return self.config.get("SQLALCHEMY_DATABASE_URI")

    def DB_init(self):
        r = call("/usr/bin/pi-manage createdb", shell=True)
        if r == 0:
            print("Created database")
        return True


class FreeRADIUSConfig(object):
       
    def __init__(self, client="/etc/freeradius/clients.conf"):
        '''
        Clients are always kept persistent on the file system
        :param client: clients.conf file.
        '''
        # check if the clients.conf file exists and is readable
        client3 = "/etc/freeradius/3.0/clients.conf"
        if os.access(client, os.F_OK | os.R_OK | os.W_OK):
            self.config_file = client
        elif os.access(client3, os.F_OK | os.R_OK | os.W_OK):
            self.config_file = client3
        else:
            raise FileNotFoundError()
        self.ccp = ClientConfParser(infile=self.config_file)
        self.config_path = os.path.dirname(self.config_file)
        self.dir_enabled = os.path.join(self.config_path,  "sites-enabled")
        self.dir_available = os.path.join(self.config_path, "sites-available")

    def clients_get(self):
        clients = self.ccp.get_dict()
        return clients
    
    def client_add(self, client=None):
        '''
        :param client: dictionary with a key as the client name and attributes
        :type client: dict
        '''
        if client:
            clients = self.clients_get()
            for client, attributes in client.items():
                clients[client] = attributes
            
            self.ccp.save(clients, self.config_file)
        
    def client_delete(self, clientname=None):
        '''
        :param clientname: name of the client to be deleted
        :type clientname: string
        '''
        if clientname:
            clients = self.clients_get()
            # TODO: We fail to delete the last client?
            clients.pop(clientname, None)
            self.ccp.save(clients, self.config_file)

    def set_module_perl(self):
        '''
        Set the perl module
        '''
        f = open(self.config_path + "/modules/perl", "w")
        f.write("""perl {
        module = /usr/share/privacyidea/freeradius/privacyidea_radius.pm
}
        """)
        
    def enable_sites(self, sites):
        """
        :param sites: list of activated links
        :type sitess: list
        """
        if not os.path.exists(self.dir_enabled):
            os.mkdir(self.dir_enabled)

        active_list = os.listdir(self.dir_enabled)
        # deactivate site
        for site in active_list:
            if site not in sites:
                # disable site
                os.unlink(self.dir_enabled +
                          "/" + site)
        # activate site
        for site in sites:
            # enable site
            if not os.path.exists(self.dir_enabled +
                                  "/" + site):
                os.symlink(self.dir_available +
                           "/" + site,
                           self.dir_enabled +
                           "/" + site)
    
    def get_sites(self):
        '''
        returns the contents of /etc/freeradius/sites-available
        '''
        ret = []
        file_list = os.listdir(self.dir_available)
        active_list = os.listdir(self.dir_enabled)
        for k in file_list:
            if k in active_list:
                ret.append((k, "", 1))
            else:
                ret.append((k, "", 0))
        return ret


class OSConfig(object):

    def __init__(self):
        pass

    def reboot(self, echo=False):
        """
        Reboot OS
        """
        p = Popen(["sudo", 'reboot'])
        r = p.wait()
        if r == 0:
            if echo:
                print("Rebooting system.")
        else:
            if echo:
                print("Unable to reboot system!")

    def halt(self, echo=False):
        """
        Shutdown OS
        """
        p = Popen(["sudo", 'halt'])
        r = p.wait()
        if r == 0:
            if echo:
                print("Halting system.")
        else:
            if echo:
                print("Unable to halt system!")

    def set_password(self, username):
        call(["passwd", username])

    def change_password(self, username, password, echo=False):
        p = Popen(['chpasswd'], stdin=PIPE, stderr=PIPE, universal_newlines=True)
        _output, err = p.communicate(u"%s:%s" % (username, password))
        r = p.returncode
        if r == 0:
            if echo:
                print("Password changed.")
        else:
            if echo:
                print(err)

    def get_diskfree(self):
        # TODO: get the disk size
        return ""

    @classmethod
    def ifdown(cls, iface):
        p = Popen(['sudo', 'ifdown', iface])
        r = p.wait()
        print(r)

    @classmethod
    def ifup(cls, iface):
        p = Popen(['sudo', 'ifup', iface])
        r = p.wait()
        print(r)

    @classmethod
    def restart(cls, service=None, do_print=False, action="restart"):
        '''
        Restart the webserver or another service.

        This functions restarts the service using
         * the `service` tool, if /etc/init.d/<service> exists
         * the `systemctl` tool otherwise

        :param service: Service to restart, defaults to apache
        '''
        service = service or SERVICE_APACHE
        if os.path.exists(os.path.join('/etc/init.d', service)):
            commandline = ['sudo', 'service', service, action]
        else:
            commandline = ['sudo', 'systemctl', action, service]
        p = Popen(commandline, stderr=PIPE, universal_newlines=True)
        _out, err = p.communicate()
        if p.returncode == 0:
            if do_print:
                print("Service %s %s" % (service, action))
        else:
            if do_print:
                print("Unable to {0!s} service {1!s}: {2!s}".format(action,
                                                                    service,
                                                                    err))


class ApacheConfig(object):

    def __init__(self, filename=None):
        self.filename = filename or \
                        "/etc/apache2/sites-enabled/privacyidea.conf"

    def get_certificates(self):
        '''
        return a tuple of the certificate and the private key
        '''
        cert = None
        key = None
        f = open(self.filename, "r")
        content = f.read()
        f.close()

        for l in content.split("\n"):
            m = re.match(r"\s*SSLCertificateKeyFile\s*(.*)", l)
            if m:
                key = m.group(1)
            m = re.match(r"\s*SSLCertificateFile\s*(.*)", l)
            if m:
                cert = m.group(1)

        return cert, key

    def get_imports(self, homedir=None):
        '''
        Return a list of possible importable certificates in the directory 
        homedir.
        
        :return: dict of certificates. Key is the filename, and
                 "size" and "time"
        '''
        homedir = homedir or os.getenv("HOME")
        files = {}
        try:
            allfiles = os.listdir(homedir)
        except OSError:
            return files

        for f in allfiles:
            if f[-4:].lower() in [".pem", ".crt", ".cer", ".der"]:
                st = os.stat(homedir + "/" + f)
                size = "%iMB" % (int(st[ST_SIZE]) // (1024 * 1024))
                mtime = time.asctime(time.localtime(st[ST_MTIME]))
                try:
                    f = f.decode("ascii")
                    files[f] = {"size": size,
                                "time": mtime}
                except UnicodeDecodeError:
                    pass
        return files

    def import_cert(self, src, dst):
        """
        Copy the file from src to dst and convert it to PEM
        :param src: 
        :param dst: 
        :return: 
        """
        r = call("openssl x509 -in {src} -out {dst} -outform PEM".format(
            src=src, dst=dst), shell=True)
        if r == 1:
            # try DER
            r = call("openssl x509 -in {src} -out {dst} -inform DER -outform "
                     "PEM".format(src=src, dst=dst), shell=True)
        if r == 0:
            print("Copied the certificate file")
        else:
            print("Failed to copy certificate file: %s" % r)
            sys.exit(r)

    def create_private_key(self, keysize=4096):
        cert, keyfile = self.get_certificates()
        os.chmod(keyfile, S_IWUSR)
        command = ("openssl genrsa -out {1} {0!s}".format(keysize, keyfile))
        print(command)
        r = call(command, shell=True)
        if r == 0:
            print("Created a new private key")
            os.chmod(keyfile, S_IRUSR)
        else:
            print("Failed to create private key")
            sys.exit(r)

    def create_self_signed(self, hostname=None, days=1000):
        hostname = hostname or socket.getfqdn()
        cert, keyfile = self.get_certificates()
        print("Generating SSL certificate {0}".format(cert))
        command = ("openssl req -x509 -new -key "
                   "{key} -days {days} -subj /CN={hostname} -out "
                   "{cert}".format(key=keyfile, cert=cert, days=days,
                                   hostname=hostname))
        r = call(command, shell=True)
        if r == 0:
            print("Created the self signed certificate")
        else:
            print("Failed to create self signed certificate: %i" % r)
            sys.exit(r)

    def generate_csr(self, hostname=None):
        hostname = hostname or socket.getfqdn()
        cert, keyfile = self.get_certificates()
        csr = "{homedir}/{filename}.csr".format(filename=os.path.basename(cert),
                                               homedir=os.getenv("HOME"))
        print("Generating CSR {0}".format(csr))
        command = ("openssl req -new -key "
                   "{key} -subj /CN={hostname} -out "
                   "{csr}".format(key=keyfile, csr=csr, hostname=hostname))
        r = call(command, shell=True)
        if r == 0:
            print("Created the CSR.")
        else:
            print("Failed to create CSR: %i" % r)
            sys.exit(r)
        return csr


class WebserverConfig(object):

    NGINX = 0
    UWSGI = 1
    default_file = ["privacyidea", "privacyidea.xml"]
    default_dir_enabled = ["/etc/nginx/sites-enabled",
                           "/etc/uwsgi/apps-enabled"]
    default_dir_available = ["/etc/nginx/sites-available",
                             "/etc/uwsgi/apps-available"]

    def __init__(self, files=None):
        '''
        :param files: The default config files for nginx and uwsgi
        :type files: list of two files
        '''
        if files is None:
            files = self.default_file
        self.configfile = files

    def is_active(self):
        '''
        :return: A list of boolean indicating if nginx and uwsgi are active
        '''
        r1 = os.path.isfile(self.default_dir_enabled[0] + "/" +
                            self.configfile[0])
        r2 = os.path.isfile(self.default_dir_enabled[1] + "/" +
                            self.configfile[1])
        return r1, r2

    def get(self):
        config = nginxparser.load(open(self.default_dir_available[self.NGINX]
                                       + "/" +
                                       self.configfile[self.NGINX]))
        return config

    def enable(self):
        for i in [self.NGINX, self.UWSGI]:
            if not os.path.exists(self.default_dir_enabled[i]):
                os.mkdir(self.default_dir_enabled[i])

            if not os.path.exists(self.default_dir_enabled[i] +
                                  "/" + self.configfile[i]):
                os.symlink(self.default_dir_available[i] +
                           "/" + self.configfile[i],
                           self.default_dir_enabled[i] +
                           "/" + self.configfile[i])
        return

    def enable_webservice(self, webservices):
        """
        :param webservices: list of activated links
        :type webservices: list
        """
        if not os.path.exists(self.default_dir_enabled[self.NGINX]):
            os.mkdir(self.default_dir_enabled[self.NGINX])

        active_list = os.listdir(self.default_dir_enabled[self.NGINX])
        # deactivate services
        for service in active_list:
            if service not in webservices:
                # disable webservice
                os.unlink(self.default_dir_enabled[self.NGINX] +
                          "/" + service)
        # activate services
        for service in webservices:
            # enable webservice
            if not os.path.exists(self.default_dir_enabled[self.NGINX] +
                                  "/" + service):
                os.symlink(self.default_dir_available[self.NGINX] +
                           "/" + service,
                           self.default_dir_enabled[self.NGINX] +
                           "/" + service)

    def get_webservices(self):
        '''
        returns the contents of /etc/nginx/sites-available
        '''
        ret = []
        file_list = os.listdir(self.default_dir_available[self.NGINX])
        active_list = os.listdir(self.default_dir_enabled[self.NGINX])
        for k in file_list:
            if k in active_list:
                ret.append((k, "", 1))
            else:
                ret.append((k, "", 0))
        return ret

    def disable(self):
        for i in [self.NGINX, self.UWSGI]:
            os.unlink(self.default_dir_enabled[i] + "/" + self.configfile[i])
        return

    @staticmethod
    def _get_val(data, key):
        '''
        returns a value for a given key from a list of tuples.
        '''
        for kv in data:
            if kv[0] == key:
                return kv[1]
        return

    def get_certificates(self):
        '''
        return a tuple of the certificate and the private key
        '''
        config = self.get()
        cert = None
        key = None
        for server in config:
            if server[0] == ["server"]:
                # server config
                if self._get_val(server[1], "listen")[-3:].lower() == "ssl":
                    # the ssl config
                    cert = self._get_val(server[1], "ssl_certificate")
                    key = self._get_val(server[1], "ssl_certificate_key")
        return cert, key

    def create_certificates(self):
        certificates = self.get_certificates()
        hostname = socket.getfqdn()
        print("Generating SSL certificate %s and key %s" % certificates)
        if certificates[0] and certificates[1]:
            command = ("openssl req -x509 -newkey rsa:2048 -keyout %s -out"
                       " %s -days 1000 -subj /CN=%s -nodes" %
                       (certificates[1],
                        certificates[0],
                        hostname))
            r = call(command, shell=True)
            if r == 0:
                print("Created the certificate and the key.")
                os.chmod(certificates[1], 0x400)
            else:
                print("Failed to create key and certificate: %i" % r)
                sys.exit(r)


class MySQLConfig(object):

    def __init__(self):
        """
        Config Object for MySQL Configuration

        :param config_file: The MySQL config file
        """
        self.config = mysqlparser.MySQLConfiguration("/etc/mysql/my.cnf")

    def is_redundant(self):
        """
        Check if we have a redundant setup

        :return: True or False
        """
        bind_address = self.config.get_dict("mysqld", "bind-address")
        server_id = self.config.get_dict("mysqld", "server-id")
        if bind_address == "127.0.0.1" or not server_id:
            ret = False, bind_address, server_id
        else:
            ret = True, bind_address, server_id

        return ret

    def get(self, section=None, key=None):
        return self.config.get_dict(section=section, key=key)

    def set(self, section, key, value):
        config = self.get()
        config[section][key] = value
        self.config.save(config, )

    def delete(self, section, key):
        config = self.get()
        if key in config.get(section):
            del config[section][key]
            self.config.save(config)

    def restart(self):
        call("service mysql restart", shell=True)


class RemoteMySQLConfig(MySQLConfig):

    def __init__(self, sftp):
        """
        Config Object for MySQL Configuration on a remote server, accessed via ssh

        :param config_file: The MySQL config file
        """
        self.sftp = sftp
        self.config = mysqlparser.MySQLConfiguration("/etc/mysql/my.cnf", sftp.file)

    def restart(self):
        raise NotImplementedError()
