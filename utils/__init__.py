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

#
# Utility functions, which are used by different modules.
#

import netaddr

from errors import ArgsError


def ip_check(ip, netmask_expected=False):
    """
    Sanity check that the specified string is indeed an IP address or mask.

    """
    try:
        if netmask_expected:
            if "/" not in ip:
                raise netaddr.core.AddrFormatError()
            netaddr.IPNetwork(ip)
        else:
            netaddr.IPAddress(ip)
    except netaddr.core.AddrFormatError:
        if netmask_expected:
            raise ArgsError("Not a valid CIDR (%s)" % ip)
        else:
            raise ArgsError("Not a valid IP address (%s)" % ip)
