#!/usr/bin/python
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


def execute_ssh_command_and_wait(ssh, command, buffer_size=1024):
    """
    Execute ``command`` via SSH, wait for its termination and return a tuple
    ``(return code, stdout output as string, stderr output as string)``.
    :param ssh: SSHClient object
    :param command: command as string
    :return: 3-tuple
    """
    stdin_file, stdout_file, stderr_file = ssh.exec_command(command)
    stdout_data = []
    stderr_data = []
    while True:
        if stdout_file.channel.recv_ready():
            stdout_data.append(stdout_file.channel.recv(buffer_size))
        if stderr_file.channel.recv_ready():
            stderr_data.append(stderr_file.channel.recv(buffer_size))
        if stdout_file.channel.exit_status_ready():
            break
    exit_status = stdout_file.channel.recv_exit_status()
    return exit_status, ''.join(stdout_data), ''.join(stderr_data)