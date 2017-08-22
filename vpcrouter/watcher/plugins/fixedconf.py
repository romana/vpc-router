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
# A watcher plugin for a fixed configuration
#

import logging

from vpcrouter         import utils
from vpcrouter.watcher import common


class Fixedconf(common.WatcherPlugin):
    """
    Implement a watcher plugin for a fixed config provided on the command line.

    This plugin adds two command line arguments to vpc-router:

    --fixed_cidr:  The route CIDR
    --fixed_hosts: A list of IP addresses of eligible routers, separated by ':'

    """
    def start(self):
        """
        Start the config watch thread or process.

        """
        # Normally, we should start a thread or process here, pass the message
        # queue self.q_route_spec to that thread and let it send route
        # configurations through that queue. But since we're just sending a
        # single, fixed configuration, we can just do that right here.
        # Note that the q_route_spec queue was created by the __init__()
        # function of the WatcherPlugin base class.
        logging.info("Fixedconf watcher plugin: Started")

        # The configuration provided on the command line is available to every
        # plugin. Here we are reading our own parameters.
        cidr       = self.conf['fixed_cidr']
        hosts      = self.conf['fixed_hosts'].split(":")
        route_spec = {cidr : hosts}
        try:
            # Probably don't really have to parse the route spec (sanity check)
            # one more time, since we already sanity checked the command line
            # options.
            common.parse_route_spec_config(route_spec)
            self.q_route_spec.put(route_spec)
        except Exception as e:
            logging.warning("Fixedconf watcher plugin: "
                            "Invalid route spec: %s" % str(e))

    def stop(self):
        """
        Stop the config watch thread or process.

        """
        # We didn't start a thread, so we don't really have anything to do here
        logging.info("Fixedconf watcher plugin: Stopped")

    def get_info(self):
        """
        Return plugin information.

        """
        return {
            self.get_plugin_name() : {
                "version" : self.get_version(),
                "params" : {
                    "fixed_cidr"  : self.conf['fixed_cidr'],
                    "fixed_hosts" : self.conf['fixed_hosts']
                }
            }
        }

    @classmethod
    def add_arguments(cls, parser, sys_arg_list=None):
        """
        Callback to add command line options for this plugin to the argparse
        parser.

        """
        parser.add_argument('--fixed_cidr', dest="fixed_cidr", required=True,
                            help="specify the route CIDR "
                                 "(only in fixedconf mode)")
        parser.add_argument('--fixed_hosts', dest="fixed_hosts", required=True,
                            help="list of host IPs, separated by ':' "
                                 "(only in fixedconf mode)")
        return ["fixed_cidr", "fixed_hosts"]

    @classmethod
    def check_arguments(cls, conf):
        """
        Callback to perform sanity checking for the plugin's specific
        parameters.

        """
        # Perform sanity checking on CIDR
        utils.ip_check(conf['fixed_cidr'], netmask_expected=True)

        # Perform sanity checking on host list
        for host in conf['fixed_hosts'].split(":"):
            utils.ip_check(host)
