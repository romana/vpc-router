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
# A monitor plugin for checking instance health with a TCP connection
# establishment attempt.
#

import logging
import socket
import threading

from vpcrouter.errors  import ArgsError
from vpcrouter.monitor import common


class Tcp(common.MonitorPlugin):
    """
    A health monitor plugin, which uses ICMP echo requests (ping) to check
    instances for health.

    """
    def __init__(self, conf):
        super(Tcp, self).__init__(conf, "TcpHealth")

    def _do_tcp_check(self, ip, results):
        """
        Attempt to establish a TCP connection.

        If not successful, record the IP in the results dict.

        Always closes the connection at the end.

        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((ip, self.conf['tcp_check_port']))
        except:
            # Any problem during the connection attempt? We won't diagnose it,
            # we just indicate failure by adding the IP to the list
            results.append(ip)
        finally:
            sock.close()

    def get_monitor_interval(self):
        """
        Return the sleep time between monitoring intervals.

        """
        return self.conf['tcp_check_interval']

    def do_health_checks(self, list_of_ips):
        """
        Perform a health check on a list of IP addresses.

        Each check (we use a TCP connection attempt) is run in its own thread.

        Gather up the results and return the list of those addresses that
        failed the test.

        TODO: Currently, this starts a thread for every single address we want
        to check. That's probably not a good idea if we have thousands of
        addresses.  Therefore, we should implement some batching for large
        sets.

        """
        threads = []
        results = []

        # Start the thread for each IP we wish to check.
        for count, ip in enumerate(list_of_ips):
            thread = threading.Thread(
                                target = self._do_tcp_check,
                                name   = "%s:%s" % (self.thread_name, ip),
                                args   = (ip, results))
            thread.start()
            threads.append(thread)

        # ... make sure all threads are done...
        for thread in threads:
            thread.join()

        # ... and send back all the failed IPs.
        return results

    def start(self):
        """
        Start the monitoring thread of the plugin.

        """
        logging.info("TCP health monitor plugin: Starting to watch "
                     "instances.")

        self.monitor_thread = threading.Thread(target = self.start_monitoring,
                                               name   = self.thread_name)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    def stop(self):
        """
        Stop the monitoring thread of the plugin.

        The super-class will send the stop signal on the monitor-IP queue,
        which prompts the loop to stop.

        """
        super(Tcp, self).stop()
        self.monitor_thread.join()
        logging.info("TCP health monitor plugin: Stopped")

    def get_info(self):
        """
        Return plugin information.

        """
        return {
            self.get_plugin_name() : {
                "version" : self.get_version(),
                "params" : {
                    "tcp_check_interval" : self.conf['tcp_check_interval'],
                    "tcp_check_port"     : self.conf['tcp_check_port']
                }
            }
        }

    @classmethod
    def add_arguments(cls, parser, sys_arg_list=None):
        """
        Arguments for the TCP health monitor plugin.

        """
        parser.add_argument('--tcp_check_interval',
                            dest='tcp_check_interval',
                            required=False, default=2, type=float,
                            help="TCP health-test interval in seconds, "
                                 "default 2 "
                                 "(only for 'tcp' health monitor plugin)")
        parser.add_argument('--tcp_check_port',
                            dest='tcp_check_port',
                            required=False, default=22, type=int,
                            help="Port for TCP health-test, default 22 "
                                 "(only for 'tcp' health monitor plugin)")
        return ["tcp_check_interval", "tcp_check_port"]

    @classmethod
    def check_arguments(cls, conf):
        """
        Sanity check plugin options values.

        As a side effect, it also converts the specified interval and port
        to an integer.

        """
        # Checking the interval
        if not conf['tcp_check_interval']:
            raise ArgsError("A TCP health-test interval needs to be "
                            "specified (--tcp_check_interval).")

        if not (1 <= conf['tcp_check_interval'] <= 3600):
            raise ArgsError("Specified TCP health-test interval must be "
                            "between 1 and 3600 seconds")

        # Checking the port
        if not conf['tcp_check_port']:
            raise ArgsError("A port for the TCP health-test needs to be "
                            "specified (--tcp_check_port).")

        if not (1 <= conf['tcp_check_port'] <= 65535):
            raise ArgsError("Specified port for TCP health-test must be "
                            "between 1 and 65535")
