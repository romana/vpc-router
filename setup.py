"""
Copyright 2017 Pani Networks Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

"""

import io
import os

from setuptools import setup

import vpcrouter


here = os.path.abspath(os.path.dirname(__file__))


def read(filename):
    buf = ""
    with io.open(filename, encoding='utf-8') as f:
        buf = f.read()
    return buf


long_description = read('README.txt')


setup(
    name                 = 'vpcrouter',
    version              = vpcrouter.__version__,
    url                  = "http://github.com/romana/vpc-router/",
    license              = "Apache Software License",
    author               = "Juergen Brendel",
    author_email         = "jbrendel@paninetworks.com",
    description          = "Automated route management, backup routes and "
                           "route failover for Amazon VPC environments",
    long_description     = long_description,
    packages             = ['vpcrouter'],
    include_package_data = True,
    install_requires     = [
        'argparse==1.2.1',
        'boto==2.47.0',
        'bottle==0.12.13',
        'netaddr==0.7.19',
        'wsgiref==0.1.2',
        'watchdog==0.8.3',
        'ping==0.2'
    ],
    classifiers          = [
        'Programming Language :: Python',
        'Development Status :: 5 - Stable',
        'Natural Language :: English',
        'Environment :: No Input/Output (Daemon)',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Topic :: System :: Clustering',
        'Topic :: System :: Networking'
    ]
)
