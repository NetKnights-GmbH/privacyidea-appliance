# -*- coding: utf-8 -*-
#VERSION = "1.5dev9"
VERSION = "2.1dev1"
from setuptools import setup, find_packages
import os
import sys

# Taken from kennethreitz/requests/setup.py
package_directory = os.path.realpath(os.path.dirname(__file__))


def get_file_contents(file_path):
    """Get the context of the file using full path name."""
    content = ""
    try:
        full_path = os.path.join(package_directory, file_path)
        content = open(full_path, 'r').read()
    except:
        print >> sys.stderr, "### could not open file: %r" % file_path
    return content


setup(
    name='pi-appliance',
    version=VERSION,
    description='Appliance package for privacyIDEA: identity, multifactor authentication, '
                'authorization, audit',
    author='privacyidea.org',
    license='AGPL v3',
    author_email='cornelius@privacyidea.org',
    url='http://www.privacyidea.org',
    install_requires=["pythondialog"
                      ],
    scripts=['authappliance/pi-appliance',
             'tools/pi-appliance-update'],
    packages=find_packages(),
    keyword="OTP Appliance",
    include_package_data=True,
    classifiers=["License :: OSI Approved :: "
                 "GNU Affero General Public License v3",
                 "Programming Language :: Python",
                 "Development Status :: 5 - Production/Stable",
                 "Topic :: Internet",
                 "Topic :: Security",
                 "Topic :: System ::"
                 " Systems Administration :: Authentication/Directory"
                 ],
    zip_safe=False,
    long_description=get_file_contents('README.md')
)
