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
# A monitor plugin for checking instance health with ICMP Echo requests.
#

import logging
import ping
import socket
import threading
import time

from vpcrouter.errors  import ArgsError
from vpcrouter.monitor import common


class EchoPermissionError(Exception):
    """
    Indicating a permission error, usually when we try to run the ping code
    not as root.

    """
    pass


class Icmpecho(common.MonitorPlugin):
    """
    A health monitor plugin, which uses ICMP echo requests (ping) to check
    instances for health.

    """
    def my_do_one(self, dest_addr, ping_id, timeout, psize):
        """
        Returns either the delay (in seconds) or none on timeout.

        This is a copy of the do_one function in the ping packet, but
        importantly, the ID for the ping packet is different (it's now passed
        in from the caller). Originally, the PID was used, which is not thread
        safe.

        """
        icmp = socket.getprotobyname("icmp")
        try:
            my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        except socket.error, (errno, msg):
            if errno == 1:
                raise EchoPermissionError()
            raise  # raise the original error

        ping.send_one_ping(my_socket, dest_addr, ping_id, psize)
        delay = ping.receive_one_ping(my_socket, ping_id, timeout)

        my_socket.close()
        return delay

    def _do_ping(self, ip, ping_id, results):
        """
        Send a single ping to a specified IP address.

        The result is either a time in seconds for the ping, or None if no
        result was received from the pinged IP address in time. Store the
        result in the results dict that's provided to us.

        """
        res = None
        try:
            res = self.my_do_one(ip, ping_id, 2, 16)
        except EchoPermissionError:
            logging.error("Cannot send ICMP echo: Note that ICMP messages "
                          "can only be sent from processes running as root.")
        except Exception:
            # If an unreachable name or IP is specified then we might even get
            # an exception here. Still just return None in that case.
            pass
        results[ip] = res

    def get_monitor_interval(self):
        """
        Return the sleep time between monitoring intervals.

        """
        return self.conf['icmp_check_interval']

    def do_health_checks(self, list_of_ips):
        """
        Perform a health check on a list of IP addresses.

        Each check (we use ICMP echo) is run in its own thread.

        Gather up the results and return the list of those addresses that
        failed the test.

        TODO: Currently, this starts a thread for every single address we want
        to check. That's probably not a good idea if we have thousands of
        addresses.  Therefore, we should implement some batching for large
        sets.

        """
        threads = []
        results = {}

        # Start the thread for each IP we wish to ping.  We calculate a unique
        # ID for the ICMP echo request sent by each thread.  It's based on the
        # slowly increasing time stamp (just 8 bits worth of the seconds since
        # epoch)...
        nowsecs = int(time.time()) % 255
        for count, ip in enumerate(list_of_ips):
            ping_id = (nowsecs << 8) + count  # ... plus running count of pkts
            thread = threading.Thread(target=self._do_ping,
                                      args=(ip, ping_id, results))
            thread.start()
            threads.append(thread)

        # ... make sure all threads are done...
        for thread in threads:
            thread.join()

        # ... and gather up the results and send back if needed
        return [k for (k, v) in results.items() if v is None]

    def start(self):
        """
        Start the configfile change monitoring thread.

        """
        logging.info("ICMPecho health monitor plugin: Starting to watch "
                     "instances.")

        self.monitor_thread = threading.Thread(target = self.start_monitoring,
                                               name   = "HealthMon")
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    def stop(self):
        """
        Stop the config change monitoring thread.

        """
        super(Icmpecho, self).stop()
        self.monitor_thread.join()
        logging.info("ICMPecho health monitor plugin: Stopped")

    @classmethod
    def add_arguments(cls, parser):
        """
        Arguments for the configfile mode.

        """
        parser.add_argument('--icmp_check_interval',
                            dest='icmp_check_interval',
                            required=False, default=2,
                            help="ICMPecho interval in seconds "
                                 "(only for 'icmpecho' health monitor plugin)")
        return ["icmp_check_interval"]

    @classmethod
    def check_arguments(cls, conf):
        """
        Sanity checks for options needed for configfile mode.

        As a side effect, it also converts the specified interval to a
        float.

        """
        if not conf['icmp_check_interval']:
            raise ArgsError("An ICMPecho interval needs to be specified "
                            "(--icmp_check_interval).")

        try:
            conf['icmp_check_interval'] = float(conf['icmp_check_interval'])
        except Exception:
            raise ArgsError("Specified ICMPecho interval '%s' must be "
                            "a number." % conf['icmp_check_interval'])

        if not (1 <= conf['icmp_check_interval'] <= 3600):
            raise ArgsError("Specified ICMPecho interval must be between "
                            "1 and 3600 seconds")
