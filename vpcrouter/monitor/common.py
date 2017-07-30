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
# Base class, exceptions and signals for the health monitor plugins.
#

import Queue


class StopReceived(Exception):
    """
    Raised after monitor thread receives stop signal.

    """
    pass


class MonitorPluginStopSignal(object):
    """
    An object of this type received on the monitor-ips queue should signal
    'stop' to the monitoring plugin.

    """
    pass


class MonitorPlugin(object):
    """
    Base class for all monitor plugins.

    Every plugin should implement all of these functions.

    """
    def __init__(self, conf):
        """
        Gives access to the config of the program to the plugin.

        This includes all parameters, not just the ones specific to the
        plugin.

        Also creates two queues:
        * A queue to receive updated sets of IP addresses.
        * A queue to send out notices of failed IP addresses.

        """
        self.conf          = conf
        self.q_monitor_ips = Queue.Queue()
        self.q_failed_ips  = Queue.Queue()

    def start(self):
        """
        Start the health monitor thread or process.

        """
        raise NotImplementedError()

    def stop(self):
        """
        Stop the health monitor thread or process.

        """
        self.q_monitor_ips.put(MonitorPluginStopSignal())

    def get_queues(self):
        """
        Return the queues, which the plugin uses to receive new IP lists and to
        announce lists of failed IPs.

        """
        return (self.q_monitor_ips, self.q_failed_ips)

    @classmethod
    def add_arguments(cls, parser):
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
