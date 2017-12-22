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
# A test plugin, which always returns 'True' for all IP addresses.
# This is mostly just useful for testing.
#

import logging

from vpcrouter.monitor import common


class Always(common.MonitorPlugin):
    """
    A health monitor plugin, which uses ICMP echo requests (ping) to check
    instances for health.

    """
    def __init__(self, conf):
        super(Always, self).__init__(conf, "AlwaysHealth")

    def get_monitor_interval(self):
        """
        Return the sleep time between monitoring intervals.

        """
        return 1

    def do_health_checks(self, list_of_ips):
        """
        Perform a health check on a list of IP addresses, using ICMPecho.

        Return tuple with list of failed IPs and questionable IPs.

        """
        return [], []

    def start(self):
        """
        Start the monitoring thread of the plugin.

        """
        logging.info("Always health monitor plugin: Pretending to start "
                     "watching instances.")

    def stop(self):
        """
        Stop the monitoring thread of the plugin.

        The super-class will send the stop signal on the monitor-IP queue,
        which prompts the loop to stop.

        """
        logging.info("Always health monitor plugin: Stopped")

    def get_info(self):
        """
        Return plugin information.

        """
        return {
            self.get_plugin_name() : {
                "version" : self.get_version(),
                "params" : {}
            }
        }
