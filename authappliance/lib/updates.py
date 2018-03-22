# -*- coding: utf-8 -*-
#  copyright 2018 friedrich.weber@netknights.it
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

import getopt
import shlex

from authappliance.lib.appliance import CRONTAB
from authappliance.lib.crontabparser.cronjobparser import CronJobParser, CronJob

UPDATE_COMMAND = "/usr/bin/pi-appliance-update"
UPDATE_SECURITY = 'security'
UPDATE_UPDATES = 'updates'

def parse_update_options(command):
    """
    Given a pi-appliance-update command, parse its options and return a dictionary.
    :param command: pi-appliance-update invocation as a string
    :return: a dictionary. The key '-t' maps to 'security' (default) or 'updates'.
    If '-c' or '-b' were given, they map to the empty string.
    """
    if not command.startswith(UPDATE_COMMAND):
        raise RuntimeError("Invalid command: {!r}".format(command))
    args_list = shlex.split(command[len(UPDATE_COMMAND):].strip())
    options_list, args = getopt.getopt(args_list, 't:bch')
    if args:
        raise RuntimeError("Invalid command: {!r}".format(command))
    options = dict(options_list)
    if '-t' in options:
        if options['-t'] not in (UPDATE_SECURITY, UPDATE_UPDATES):
            raise RuntimeError("Invalid command: {!r}".format(command))
    else:
        options['-t'] = UPDATE_SECURITY
    return options

class Updates(object):
    def __init__(self):
        self.cp = CronJobParser()

    def read(self):
        """
        Re-read crontab.
        """
        self.cp.read()

    def get_update_cronjobs(self):
        """
        :return: yield all update cronjobs found by the cronjob parser as list (CronJob object, options dict)
        """
        for cronjob in self.cp.cronjobs:
            if cronjob.command.startswith(UPDATE_COMMAND):
                yield (cronjob, parse_update_options(cronjob.command))

    def add_update_cronjob(self, date_fragments, type_=UPDATE_SECURITY, boot=False, clean=False):
        """
        Add an update cronjob to the crontab.
        :param date_fragments: a list of at most 5 strings specifying the cronjob time
        :param type_: one of ('security', 'updates')
        :param boot: boolean determining if the system should reboot after updates
        :param clean: boolean determining if package files should be cleaned after updates
        """
        command = [UPDATE_COMMAND, '-t', type_]
        if boot:
            command.append('-b')
        if clean:
            command.append('-c')
        self.cp.cronjobs.append(CronJob.from_time(
            ' '.join(command),
            "root",
            date_fragments
        ))
        self.cp.save(CRONTAB)

    def delete_cronjob(self, cronjob):
        """
        Delete a given cronjob object from the crontab and write the modified crontab.
        """
        self.cp.cronjobs.remove(cronjob)
        self.cp.save(CRONTAB)
