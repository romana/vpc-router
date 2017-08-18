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

import os

from setuptools import setup, find_packages


import vpcrouter


here = os.path.abspath(os.path.dirname(__file__))


def get_readme():
    try:
        import pypandoc
        return pypandoc.convert('README.md', 'rst')
    except (IOError, ImportError):
        return ""


long_description = get_readme()


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
    packages             = find_packages(),
    include_package_data = True,
    entry_points         = {
        'console_scripts' : ['vpcrouter=vpcrouter.main:main'],
    },
    install_requires     = [
        'argparse==1.2.1',
        'boto==2.47.0',
        'bottle==0.12.13',
        'netaddr==0.7.19',
        'wsgiref==0.1.2',
        'watchdog==0.8.3',
        'multiping==1.0.2',
    ],
    dependency_links     = [
        "https://github.com/romana/multi-ping/tarball/master#egg=multiping-1.0.2"
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
