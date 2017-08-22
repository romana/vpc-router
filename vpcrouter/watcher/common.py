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

import Queue

from vpcrouter        import utils
from vpcrouter.errors import ArgsError


class WatcherPlugin(object):
    """
    Base class for all watcher plugins.

    Every plugin should implement all of these functions.

    A plugin watches for configuration changes in the route-spec. If there is
    an update, it pushes a new route-spec out on a queue, which the rest of the
    vpc-router uses to listen for new route-specs. The queue has to be created
    by the plugin. A reference to the queue needs to be made available via the
    get_route_spec_queue() method.

    It's up to the plugin to implement a thread or process and how exactly and
    from where it gets information about routes and eligible target hosts.
    Whatever mechanism is chosen, the plugin should provide a start() and
    stop() method.

    If a plugin requires additional command line arguments, it can add those
    via the add_arguments() callback. It should provide sanity checking for
    those arguments via the check_arguments() callback.

    """
    def __init__(self, conf):
        """
        Gives access to the config of the program to the plugin.

        This includes all parameters, not just the ones specific to the
        plugin.

        Also creates the queue that each plugin needs to use to communicate
        updated route specs out.

        """
        self.conf         = conf
        self.q_route_spec = Queue.Queue()

    def get_plugin_name(self):
        return type(self).__name__.lower()

    def start(self):
        """
        Start the config watch thread or process.

        """
        raise NotImplementedError()

    def stop(self):
        """
        Stop the config watch thread or process.

        """
        raise NotImplementedError()

    def get_info(self):
        """
        Return information about the plugin and all the config parameters in a
        dictionary, with the plugin name as the key to a second-level
        dictionary, which contains all the parameters:

            {
                <plugin_name> : {
                    <param1> : <value1>,
                    <param2> : <value2>,
                    ...
                }
            }

        """
        return {self.get_plugin_name() : "(no info provided)"}

    def get_route_spec_queue(self):
        """
        Return the queue, which the plugin uses to announce new route specs
        that it detected.

        """
        return self.q_route_spec

    @classmethod
    def get_version(self):
        """
        Return the version of the plugin.

        Built-in plugins should return the string "built-in", while external
        plugins should overwrite this and return their own version string.

        """
        return "built-in"

    @classmethod
    def add_arguments(cls, parser, sys_arg_list=None):
        """
        Callback to add command line options for this plugin to the argparse
        parser.

        Return list with names of new arguments.

        """
        return []

    @classmethod
    def check_arguments(cls, conf):
        """
        Callback to perform sanity checking for the plugin's specific
        parameters.

        Should raise exception in case of error.

        """
        return


def parse_route_spec_config(data):
    """
    Parse and sanity check the route spec config.

    The config data is a blob of JSON that needs to be in this format:

    {
        "<CIDR-1>" : [ "host-1-ip", "host-2-ip", "host-3-ip" ],
        "<CIDR-2>" : [ "host-4-ip", "host-5-ip" ],
        "<CIDR-3>" : [ "host-6-ip", "host-7-ip", "host-8-ip", "host-9-ip" ]
    }

    Returns the validated route config. This validation is performed on any
    route-spec pushed out by the config watcher plugin.

    Duplicate hosts in the host lists are removed.

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
            hosts = set(v)   # remove duplicates
            for ip in hosts:
                utils.ip_check(ip)
            clean_host_list = sorted(list(hosts))
            data[k] = clean_host_list

    except ArgsError as e:
        raise ValueError(e.message)

    return data
