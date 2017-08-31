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
# A monitor plugin that combines reports from multiple health monitor
# plugins (sub-plugins).
#
# This allows plugin authors to combine multiple, simple or specialized
# health monitor plugins into more complex health monitors.
#
# The multi-plugin reports an instance as 'failed' if ANY of the sub-plugins
# report it as failed.
#

import logging
import threading
import time

from vpcrouter                  import utils
from vpcrouter.errors           import ArgsError
from vpcrouter.monitor          import common, MONITOR_DEFAULT_PLUGIN_MODULE
from vpcrouter.plugin_framework import load_plugin


class ExpireSet(object):
    """
    Maintain a list of recently updated entries.

    If an entry has not received an update within a certain time, it is removed
    from the list.

    """
    def __init__(self, expire_time):
        """
        Create the expiring set.

        An entry that has not received an updated within the last 'expire_time'
        seconds is removed.

        """
        self.timed_data  = {}
        self.expire_time = expire_time

    def _expire_data(self):
        """
        Remove all expired entries.

        """
        expire_time_stamp = time.time() - self.expire_time
        self.timed_data   = {d: t for d, t in self.timed_data.items()
                             if t > expire_time_stamp}

    def update(self, data_set):
        """
        Refresh the time of all specified elements in the supplied data set.

        """
        now = time.time()
        for d in data_set:
            self.timed_data[d] = now
        self._expire_data()

    def get(self):
        """
        Return the current data set.

        """
        self._expire_data()
        return list(self.timed_data.keys())


class Multi(common.MonitorPlugin):
    """
    A health monitor plugin, which uses multiple simpler health monitor
    plugins.

    This plugin starts a specified set of other health monitor plugins and
    manages the queues to/from those plugins, while at the same time
    representing the usual 2-queue interface to the rest of VPC router.

    Any updates about new instances are sent by the Multi plugin to all the
    sub-plugins.

    Any reports about failed IP addresses from any of those plugins are
    combined and sent to the VPC router as a single message.

    """
    def __init__(self, conf, **kwargs):

        super(Multi, self).__init__(conf, "MultiHealth")

        self.my_wait_interval       = 0
        self.plugins                = []
        self.monitor_ip_queues      = {}
        self.failed_ip_queues       = {}
        self.questionable_ip_queues = {}

        # For testing purposes, it is convenient to supply already pre-created
        # test plugins. We do this by calling the Multi plugin with an extra
        # parameter during tests, which is a list of test-plugin names and
        # instances (not classes).
        test_plugins = kwargs.get("TEST_PLUGINS")

        # Now "load" and start sub-plugins. Slightly different approach to be
        # taken, depending on test or real mode.
        if not test_plugins:
            # No, we are not running in a test, no test-plugin list was
            # specified. Therefore, we use the expected multi_plugins parameter
            # to load real plugin classes.
            logging.info("Multi-plugin health monitor: Loading plugins %s" %
                         self.conf['multi_plugins'])
            plugins_and_names = \
                        self.load_sub_plugins_from_str(
                                    self.conf['multi_plugins']).items()
        else:
            # Yes, we run in test mode. Instead of loading plugin classes, we
            # just use the list of pre-initialized plugins that was provided to
            # us in the special TEST_PLUGINS parameter.
            plugins_and_names = test_plugins

        # Load and start each sub-plugin
        self.failed_queue_lookup       = {}
        self.questionable_queue_lookup = {}
        for pname, pc in plugins_and_names:
            if test_plugins:
                # In test configuration we get already initialized instances
                # of the test plugins.
                plugin = pc
            else:
                # In normal configuration we have plugin classes, which need to
                # be instantiated first.
                plugin = pc(self.conf)

            self.plugins.append(plugin)
            plugin.start()

            # Gather up all the queues we need to communicate with the
            # sub-plugins. The only reason we need to remember which queue
            # belongs to what plugin is so that we can produce nicer logging
            # messages. For the logic of the multi-plugin it doesn't really
            # matter which plugin reports what failed IP.
            q_monitor_ips, q_failed_ips, q_questionable_ips = \
                                                        plugin.get_queues()
            self.monitor_ip_queues[pname]         = q_monitor_ips
            self.failed_queue_lookup[pname]       = q_failed_ips
            self.questionable_queue_lookup[pname] = q_questionable_ips

            # Also calculate our waiting interval: Double the max of each
            # plugin's interval. That's sufficient to make sure we get updates
            # if there are any.
            self.my_wait_interval = max(self.my_wait_interval,
                                        plugin.get_monitor_interval())
        self.my_wait_interval *= 2

        # We will keep the reportedly failed and questionable IP addresses in
        # accumulating buffers. This is important, since otherwise, an update
        # from one plugin may wipe out the update provided just before from
        # another plugin.
        self.report_failed_acc       = ExpireSet(self.my_wait_interval * 10)
        self.report_questionable_acc = ExpireSet(self.my_wait_interval * 10)

    def get_monitor_interval(self):
        """
        Return the sleep time between monitoring intervals.

        For the multi plugin the sleep time is double of the max monitoring
        interval of each sub-plugin. That should give us plenty of time to
        receive updates.

        """
        return self.my_wait_interval

    def get_info(self):
        """
        Return plugin information.

        """
        plugin_infos = {}
        for pc in self.plugins:
            plugin_infos.update(pc.get_info())
        return {
            self.get_plugin_name() : {
                "version"     : self.get_version(),
                "sub-plugins" : plugin_infos,
                "params" : {
                    "multi_plugins" : self.conf['multi_plugins']
                },
            }
        }

    def _accumulate_ips_from_plugins(self, ip_type_name, plugin_queue_lookup,
                                     ip_accumulator):
        """
        Retrieve all IPs of a given type from all sub-plugins.

        ip_type_name:        A name of the type of IP we are working with.
                             Used for nice log messages. Example 'failed',
                             'questionable'.
        plugin_queue_lookup: Dictionary to lookup the queues (of a given type)
                             for a plugins, by plugin name.
        ip_accumulator:      An expiring data set for this type of IP address.

        Returns either a set of addresses to send out on our own reporting
        queues, or None.

        """
        all_reported_ips  = set()
        for pname, q in plugin_queue_lookup.items():
            # Get all the IPs of the specified type from all the plugins.
            ips = utils.read_last_msg_from_queue(q)
            if ips:
                logging.debug("Sub-plugin '%s' reported %d "
                              "%s IPs: %s" %
                              (pname, len(ips), ip_type_name,
                               ",".join(ips)))
                all_reported_ips.update(ips)  # merge all the lists
            else:
                logging.debug("Sub-plugin '%s' reported no "
                              "%s IPs." % (pname, ip_type_name))

        # Send out the combined list of reported IPs. The receiver of this
        # message expects this list to always be the full list of IPs. So, IF
        # they get a message, it needs to be complete, since otherwise any IP
        # not mentioned in this update is considered healthy.
        #
        # Since different sub-plugins may report different IPs at different
        # times (and not always at the same time), we need to accumulate those
        # IPs that are recorded by different sub-plugins over time.
        #
        # We use an 'expiring data set' to store those: If any plugin refreshes
        # an IP as failed then the entry remains, otherwise, it will expire
        # after some time. The expiring data set therefore, is an accumulation
        # of recently reported IPs. We always report this set, whenever we send
        # out an update of IPs.
        #
        # Each type of IP (for example, 'failed' or 'questionable') has its own
        # accumulator, which was passed in to this function.
        if all_reported_ips:
            ip_accumulator.update(all_reported_ips)
            current_ips = ip_accumulator.get()
            logging.info("Multi-plugin health monitor: "
                         "Reporting combined list of %s "
                         "IPs: %s" %
                         (ip_type_name,
                          ",".join(current_ips)))
            return current_ips
        else:
            logging.debug("No failed IPs to report.")
            return None

    def start_monitoring(self):
        """
        Pass IP lists to monitor sub-plugins and get results from them.

        Override the common definition of this function, since in the multi
        plugin it's a little different: Instead of monitoring ourselves, we
        just use a number of other plugins to gather results. The multi plugin
        just serves as a proxy and (de)multiplexer for those other plugins.

        Note that we don't have to push any updates about failed IPs if nothing
        new was detected. Therefore, our own updates can be entirely driven by
        updates from the sub-plugin, which keeps our architecture simple.

        """
        logging.info("Multi-plugin health monitor: Started in thread.")
        try:
            while True:
                # Get new IP addresses and pass them on to the sub-plugins
                new_ips = self.get_new_working_set()
                if new_ips:
                    logging.debug("Sending list of %d IPs to %d plugins." %
                                  (len(new_ips), len(self.plugins)))
                    for q in self.monitor_ip_queues.values():
                        q.put(new_ips)

                # Get any notifications about failed or questionable IPs from
                # the plugins.
                all_failed_ips = self._accumulate_ips_from_plugins(
                                            "failed",
                                            self.failed_queue_lookup,
                                            self.report_failed_acc)
                if all_failed_ips:
                    self.q_failed_ips.put(all_failed_ips)

                all_questionable_ips = self._accumulate_ips_from_plugins(
                                            "questionable",
                                            self.questionable_queue_lookup,
                                            self.report_questionable_acc)
                if all_questionable_ips:
                    self.q_questionable_ips.put(all_questionable_ips)

                time.sleep(self.get_monitor_interval())

        except common.StopReceived:
            # Received the stop signal, just exiting the thread function
            return

    def start(self):
        """
        Start the monitoring thread of the plugin.

        Importantly, this starts the threads of the various specified baseic
        plugins.

        """

        logging.info("Multi-plugin health monitor: Starting")
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
        super(Multi, self).stop()
        self.monitor_thread.join()

        logging.info("Multi-plugin health monitor: Stopping plugins")
        for p in self.plugins:
            p.stop()

        logging.info("Multi-plugin health monitor: Stopped")

    @classmethod
    def load_sub_plugins_from_str(cls, plugins_str):
        """
        Load plugin classes based on column separated list of plugin names.

        Returns dict with plugin name as key and class as value.

        """
        plugin_classes = {}
        if plugins_str:
            for plugin_name in plugins_str.split(":"):
                pc = load_plugin(plugin_name, MONITOR_DEFAULT_PLUGIN_MODULE)
                plugin_classes[plugin_name] = pc
        return plugin_classes

    @classmethod
    def add_arguments(cls, parser, sys_arg_list=None):
        """
        Arguments for the Multi health monitor plugin.

        """
        parser.add_argument('--multi_plugins',
                            dest='multi_plugins', required=True,
                            help="Column seperated list of health monitor "
                                 "plugins (only for 'multi' health monitor "
                                 "plugin)")

        arglist = ["multi_plugins"]

        # Read the list of the specified sub-plugins ahead of time, so we can
        # get their classes and add their parameters.
        sub_plugin_names_str = \
                utils.param_extract(sys_arg_list, None, "--multi_plugins")
        sub_plugin_classes = \
                cls.load_sub_plugins_from_str(sub_plugin_names_str).values()

        # Store the list of the sub-plugins in the class, so we can iterate
        # over those during parameter evaluation later on.
        cls.multi_plugin_classes = sub_plugin_classes

        # Now also add the parameters for the sub-plugins
        for pc in sub_plugin_classes:
            arglist.extend(pc.add_arguments(parser, sys_arg_list))

        return arglist

    @classmethod
    def check_arguments(cls, conf):
        """
        Sanity check plugin options values.

        """
        # Checking the specified list of basic health monitor plugins, which
        # should be run by the multi plugin.
        if not conf.get('multi_plugins'):
            raise ArgsError("A specification of health monitor plugins "
                            "is required (--multi_plugins).")

        # Now check parameters for all sub-plugins. We use the list of classes
        # for sub-plugins that we discovered earlier while adding parameters
        # for those sub-plugins.
        for mpc in cls.multi_plugin_classes:
            mpc.check_arguments(conf)
