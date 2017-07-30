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
import Queue
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

    def _get_new_working_set(self):
        """
        Get a new list of IPs to work with from the queue.

        This returns None if there is no update.

        Read all the messages from the queue on which we get the IP addresses
        that we have to monitor. We will ignore all of them, except the last
        one, since maybe we received two updates in a row, but each update
        is a full state, so only the last one matters.

        Raises the StopReceived exception if the stop signal ("None") was
        received on the notification queue.

        """
        new_list_of_ips = None
        while True:
            try:
                new_list_of_ips = self.q_monitor_ips.get_nowait()
                self.q_monitor_ips.task_done()
                if type(new_list_of_ips) is common.MonitorPluginStopSignal:
                    raise common.StopReceived()
            except Queue.Empty:
                # No more messages, all done reading monitor list for now
                break
        return new_list_of_ips

    def _do_health_checks(self, list_of_ips):
        """
        Perform a health check on a list of IP addresses.

        Each check (we use ICMP echo right now) is run in its own thread.

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

    def start_monitoring(self):
        """
        Monitor IP addresses and send notifications if one of them has failed.

        This function will continuously monitor q_monitor_ips for new lists of
        IP addresses to monitor. Each message received there is the full state
        (the complete lists of addresses to monitor).

        Push out (return) any failed IPs on q_failed_ips. This is also a list
        of IPs, which may be empty if all instances work correctly.

        If q_monitor_ips receives a 'None' instead of list then this is
        intepreted as a stop signal and the function exits.

        """
        time.sleep(1)

        # This is our working set. This list may be updated occasionally when
        # we receive messages on the q_monitor_ips queue. But irrespective of
        # any received updates, the list of IPs in here is regularly checked.
        list_of_ips             = []
        currently_failed_ips    = set()

        # Accumulating failed IPs for 10 intervals before rechecking them to
        # see if they are alive again
        recheck_failed_interval = 10

        try:
            interval_count = 0
            while True:
                # See if we should update our working set
                new_ips = self._get_new_working_set()
                if new_ips:
                    list_of_ips = new_ips

                # Don't check failed IPs for liveness on every interval. We
                # keep a list of currently-failed IPs for that purpose.
                live_ips_to_check = [ip for ip in list_of_ips if
                                     ip not in currently_failed_ips]
                logging.debug("Checking live IPs: %s" %
                              (",".join(live_ips_to_check)
                               if live_ips_to_check else "(none alive)"))

                # Independent of any updates: Perform health check on all IPs
                # in the working set and send messages out about any failed
                # once as necessary.
                if live_ips_to_check:
                    failed_ips = self._do_health_checks(live_ips_to_check)
                    if failed_ips:
                        self.q_failed_ips.put(failed_ips)
                        # Update list of currently failed IPs with any new ones
                        currently_failed_ips.update(failed_ips)
                        logging.info('Currently failed IPs: %s' %
                                     ",".join(currently_failed_ips))

                if interval_count == recheck_failed_interval:
                    # Ever now and then clean out our currently failed IP cache
                    # so that we can recheck them to see if they are still
                    # failed.
                    interval_count = 0
                    currently_failed_ips = set()

                time.sleep(self.conf['interval'])
                interval_count += 1

        except common.StopReceived:
            # Received the stop signal, just exiting the thread function
            return

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
        parser.add_argument('-i', '--interval', dest='interval',
                            required=False, default=2,
                            help="ICMPecho interval in seconds "
                                 "(only in ping mode)")
        return ["interval"]

    @classmethod
    def check_arguments(cls, conf):
        """
        Sanity checks for options needed for configfile mode.

        As a side effect, it also converts the specified interval to a
        float.

        """
        if not conf['interval']:
            raise ArgsError("An ICMPecho interval needs to be specified (-i).")

        try:
            conf['interval'] = float(conf['interval'])
        except Exception:
            raise ArgsError("Specified ICMPecho interval '%s' must be "
                            "a number." %
                            conf['interval'])

        if not (1 <= conf['interval'] <= 3600):
            raise ArgsError("Specified ICMPecho interval must be between "
                            "1 and 3600 seconds")
