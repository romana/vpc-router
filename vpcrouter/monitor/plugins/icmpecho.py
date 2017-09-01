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
import datetime
import multiping
import threading

from vpcrouter.errors  import ArgsError
from vpcrouter.monitor import common


class Icmpecho(common.MonitorPlugin):
    """
    A health monitor plugin, which uses ICMP echo requests (ping) to check
    instances for health.

    """
    def __init__(self, conf):
        super(Icmpecho, self).__init__(conf, "IcmpechoHealth")
        self.ping_count           = 0
        self.measurements         = []
        self.max_num_measurements = 10

    def get_monitor_interval(self):
        """
        Return the sleep time between monitoring intervals.

        """
        return self.conf['icmp_check_interval']

    def update_stats(self, responses, no_responses):
        """
        Maintain some stats about our requests.

        """
        slowest_rtt = 0.0
        slowest_ip  = None
        fastest_rtt = 9999999.9
        fastest_ip  = None
        rtt_total   = 0.0

        for ip, rtt in responses.items():
            rtt_total += rtt
            if rtt > slowest_rtt:
                slowest_rtt = rtt
                slowest_ip  = ip
            elif rtt < fastest_rtt:
                fastest_rtt = rtt
                fastest_ip  = ip

        sorted_rtts = sorted(responses.values())
        l           = len(sorted_rtts)
        if l == 0:
            median_rtt = 0.0
        elif l % 2 == 1:
            # Odd number: Median is the middle element
            median_rtt = sorted_rtts[int(l / 2)]
        else:
            # Even number (average between two middle elements)
            median_rtt = (sorted_rtts[int(l / 2) - 1] +
                          sorted_rtts[int(l / 2)]) / 2.0

        now = datetime.datetime.now().isoformat()
        m = {
            "time" : now,
            "num_responses" : len(responses),
            "num_no_responses" : len(no_responses),
            "slowest" : {
                "ip"  : slowest_ip,
                "rtt" : slowest_rtt
            },
            "fastest" : {
                "ip"  : fastest_ip,
                "rtt" : fastest_rtt
            },
            "average_rtt" : rtt_total / len(responses),
            "median_rtt" : median_rtt
        }

        self.measurements.insert(0, m)
        self.measurements = self.measurements[:self.max_num_measurements]

    def do_health_checks(self, list_of_ips):
        """
        Perform a health check on a list of IP addresses, using ICMPecho.

        Return tuple with list of failed IPs and questionable IPs.

        """
        # Calculate a decent overall timeout time for a ping attempt: 3/4th of
        # the monitoring interval. That way, we know we're done with this ping
        # attempt before the next monitoring attempt is started.
        ping_timeout = self.get_monitor_interval() * 0.75

        # Calculate a decent number of retries. For very short intervals we
        # shouldn't have any retries, for very long ones, we should have
        # several ones. Converting the timeout to an integer gives us what we
        # want: For timeouts less than 1 we have no retry at all.
        num_retries = int(ping_timeout)

        try:
            self.ping_count += len(list_of_ips)
            responses, no_responses = multiping.multi_ping(
                                        list_of_ips, ping_timeout, num_retries)
            self.update_stats(responses, no_responses)

        except Exception as e:
            logging.error("Exception while trying to monitor servers: %s" %
                          str(e))
            # Need to assume all IPs failed
            no_responses = list_of_ips

        return no_responses, []  # return empty list for questionable IPs

    def start(self):
        """
        Start the monitoring thread of the plugin.

        """
        logging.info("ICMPecho health monitor plugin: Starting to watch "
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
        super(Icmpecho, self).stop()
        self.monitor_thread.join()
        logging.info("ICMPecho health monitor plugin: Stopped")

    def get_stats(self):
        """
        Return dictionary of statistics that were accumulated over the running
        time of the plugin.

        """
        return {
            "pings_sent"   : self.ping_count,
            "measurements" : self.measurements,
        }

    def get_info(self):
        """
        Return plugin information.

        """
        return {
            self.get_plugin_name() : {
                "version" : self.get_version(),
                "params" : {
                    "icmp_check_interval" : self.conf['icmp_check_interval'],
                },
                "stats" : self.get_stats()
            }
        }

    @classmethod
    def add_arguments(cls, parser, sys_arg_list=None):
        """
        Arguments for the ICMPecho health monitor plugin.

        """
        parser.add_argument('--icmp_check_interval',
                            dest='icmp_check_interval',
                            required=False, default=2, type=float,
                            help="ICMPecho interval in seconds, default 2 "
                                 "(only for 'icmpecho' health monitor plugin)")
        return ["icmp_check_interval"]

    @classmethod
    def check_arguments(cls, conf):
        """
        Sanity check plugin options values.

        As a side effect, it also converts the specified interval to a
        float.

        """
        if not conf['icmp_check_interval']:
            raise ArgsError("An ICMPecho interval needs to be specified "
                            "(--icmp_check_interval).")

        if not (1 <= conf['icmp_check_interval'] <= 3600):
            raise ArgsError("Specified ICMPecho interval must be between "
                            "1 and 3600 seconds")
