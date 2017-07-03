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
# Generally useful functions for the watcher module
#

from vpcrouter.errors import ArgsError

from vpcrouter import utils


# A shared dict in which we keep the current route state, in case someone is
# interested.
CURRENT_STATE = {
    "failed_ips" : [],
    "route_spec" : {},
    "routes" : {}
}


class WatcherPlugin(object):
    """
    Base class for all watcher plugins.

    """
    def __init__(self, conf):
        self.conf = conf

    def start(self):
        raise NotImplementedError()

    def stop(self):
        raise NotImplementedError()

    def get_route_spec_queue(self):
        raise NotImplementedError()

    @classmethod
    def add_arguments(cls, parser):
        raise NotImplementedError()

    @classmethod
    def check_arguments(cls, conf):
        raise NotImplementedError()


def parse_route_spec_config(data):
    """
    Parse and sanity check the route spec config.

    The config data is a blob of JSON that needs to be in this format:

    {
        "<CIDR-1>" : [ "host-1-ip", "host-2-ip", "host-3-ip" ],
        "<CIDR-2>" : [ "host-4-ip", "host-5-ip" ],
        "<CIDR-3>" : [ "host-6-ip", "host-7-ip", "host-8-ip", "host-9-ip" ]
    }

    Returns the validated route config.

    Raises ValueError exception in case of problems.

    """
    # Sanity checking on the data object
    if type(data) is not dict:
        raise ValueError("Expected dictionary at top level")
    try:
        for k, v in data.items():
            utils.ip_check(k, netmask_expected=True)
            if type(v) is not list:
                raise ValueError("Expect list of IPs as values in dict")
            for ip in v:
                utils.ip_check(ip)

    except ArgsError as e:
        raise ValueError(e.message)

    return data
