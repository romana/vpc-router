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

import logging
import Queue
import time

from vpcrouter.currentstate import CURRENT_STATE


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
    def __init__(self, conf, thread_name):
        """
        Gives access to the config of the program to the plugin.

        This includes all parameters, not just the ones specific to the
        plugin.

        Also creates three queues:
        * A queue to receive updated sets of IP addresses.
        * A queue to send out notices of failed IP addresses.
        * A queue to inform about questionable or failing IPs (still
          operational, but with some indication that it will soon change).

        """
        self.conf               = conf
        self.thread_name        = thread_name

        self.q_monitor_ips      = Queue.Queue()
        self.q_failed_ips       = Queue.Queue()
        self.q_questionable_ips = Queue.Queue()

    def get_plugin_name(self):
        return type(self).__name__.lower()

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
        Return the queues, which the plugin uses to receive new IP lists, to
        announce lists of failed IPs and to communicate about questionable IP
        addresses.

        """
        return (self.q_monitor_ips, self.q_failed_ips, self.q_questionable_ips)

    def get_new_working_set(self):
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
                if type(new_list_of_ips) is MonitorPluginStopSignal:
                    raise StopReceived()
            except Queue.Empty:
                # No more messages, all done reading monitor list for now
                break
        if new_list_of_ips is not None:
            CURRENT_STATE.working_set = new_list_of_ips
        return new_list_of_ips

    def get_monitor_interval(self):
        """
        Return the sleep time between monitoring intervals.

        """
        raise NotImplementedError()

    def get_info(self):
        """
        Return information about the plugin and all the config parameters in a
        dictionary, with the plugin name as the key to a second-level
        dictionary, which contains all the parameters:

            {
                <plugin_name> : {
                    "version" : <version>,
                    "params" : {
                        <param1> : <value1>,
                        <param2> : <value2>,
                        ...
                    }
                }
            }

        """
        return {self.get_plugin_name() : "(no info provided)"}

    def do_health_checks(self, list_of_ips):
        """
        Perform a health check on a list of IP addresses.

        Return a list of failed IP addresses.

        """
        raise NotImplementedError()

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
        list_of_ips                = []

        currently_failed_ips       = set()
        currently_questionable_ips = set()

        # Accumulating failed IPs for 10 intervals before rechecking them to
        # see if they are alive again
        recheck_failed_interval = 10

        try:
            interval_count = 0
            while not CURRENT_STATE._stop_all:
                start_time = time.time()
                # See if we should update our working set
                new_ips = self.get_new_working_set()
                if new_ips:
                    list_of_ips = new_ips
                    # Update the currently-failed-IP list to only include IPs
                    # that are still in the spec. The list update may have
                    # removed some of the historical, failed IPs altogether.
                    currently_failed_ips = \
                            set([ip for ip in currently_failed_ips
                                 if ip in list_of_ips])
                    # Same for the questionable IPs
                    currently_questionable_ips = \
                            set([ip for ip in currently_questionable_ips
                                 if ip in list_of_ips])

                # Don't check failed IPs for liveness on every interval. We
                # keep a list of currently-failed IPs for that purpose.
                # But we will check questionable IPs, so we don't exclude
                # those.
                live_ips_to_check = [ip for ip in list_of_ips if
                                     ip not in currently_failed_ips]
                logging.debug("Checking live IPs: %s" %
                              (",".join(live_ips_to_check)
                               if live_ips_to_check else "(none alive)"))

                # Independent of any updates: Perform health check on all IPs
                # in the working set and send messages out about any failed
                # ones as necessary.
                if live_ips_to_check:
                    failed_ips, questionable_ips = \
                                    self.do_health_checks(live_ips_to_check)
                    if failed_ips:
                        # Update list of currently failed IPs with any new ones
                        currently_failed_ips.update(failed_ips)
                        logging.info('Currently failed IPs: %s' %
                                     ",".join(currently_failed_ips))
                        # Let the main loop know the full set of failed IPs
                        self.q_failed_ips.put(list(currently_failed_ips))

                    if questionable_ips:
                        # Update list of currently questionable IPs with any
                        # new ones
                        currently_questionable_ips.update(failed_ips)
                        logging.info('Currently questionable IPs: %s' %
                                     ",".join(currently_questionable_ips))
                        # Let the main loop know the full set of questionable
                        # IPs
                        self.q_questionable_ips.put(
                                            list(currently_questionable_ips))

                if interval_count == recheck_failed_interval:
                    # Ever now and then clean out our currently failed IP cache
                    # so that we can recheck them to see if they are still
                    # failed. We also clear out the questionable IPs, so that
                    # they don't forever accumulate.
                    interval_count             = 0
                    currently_failed_ips       = set()
                    currently_questionable_ips = set()

                # Wait until next monitoring interval: We deduct the time we
                # spent in this loop.
                end_time = time.time()
                time.sleep(self.get_monitor_interval() -
                           (end_time - start_time))
                interval_count += 1

            logging.debug("Monitoring loop ended: Global stop")

        except StopReceived:
            # Received the stop signal, just exiting the thread function
            return

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
