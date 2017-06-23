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
# Functions for watching route spec in daemon mode
#

import itertools
import json
import logging
import os
import Queue
import time

from errors  import ArgsError, VpcRouteSetError
from monitor import start_monitor_in_background
from utils   import ip_check
from vpc     import handle_spec

from bottle             import route, run, request, response
from watchdog.events    import FileSystemEventHandler, FileModifiedEvent
from watchdog.observers import Observer


class RouteSpecChangeEventHandler(FileSystemEventHandler):
    """
    Our own event handler class, to be used to process events on the route-spec
    file.

    """
    def __init__(self, *args, **kwargs):
        self._route_spec_fname   = kwargs['route_spec_fname']
        self._route_spec_abspath = kwargs['route_spec_abspath']
        self._q_route_spec       = kwargs['q_route_spec']

        del kwargs['route_spec_fname']
        del kwargs['route_spec_abspath']
        del kwargs['q_route_spec']

        super(RouteSpecChangeEventHandler, self).__init__(*args, **kwargs)


    def on_modified(self, event):
        if type(event) is FileModifiedEvent and \
                                    event.src_path == self._route_spec_abspath:
            logging.info("Detected file change event for %s" %
                          self._route_spec_abspath)
            try:
                route_spec = read_route_spec_config(self._route_spec_fname)
                self._q_route_spec.put(route_spec)
            except ValueError as e:
                # In case of error in the config file, we don't send out a
                # message with a broken or empty list. Probably just temporary,
                # shouldn't stop operation of the system.
                logging.warning("Cannot parse route spec: %s" % str(e))



def read_route_spec_config(fname):
    """
    Read, parse and sanity check the route spec config file.

    The config file needs to be in this format:

    {
        "<CIDR-1>" : [ "host-1-ip", "host-2-ip", "host-3-ip" ],
        "<CIDR-2>" : [ "host-4-ip", "host-5-ip" ],
        "<CIDR-3>" : [ "host-6-ip", "host-7-ip", "host-8-ip", "host-9-ip" ]
    }

    Returns the validated route config.

    """
    try:
        try:
            f = open(fname, "r")
        except IOError as e:
            # Cannot open file? Doesn't exist?
            raise ValueError("Cannot open file: " + str(e))
        data = json.loads(f.read())
        f.close()
        # Sanity checking on the data object
        if type(data) is not dict:
            raise ValueError("Expected dictionary at top level")
        try:
            for k, v in data.items():
                ip_check(k, netmask_expected=True)
                if type(v) is not list:
                    raise ValueError("Expect list of IPs as values in dict")
                for ip in v:
                    ip_check(ip)

        except ArgsError as e:
            raise ValueError(e.message)

    except ValueError as e:
        logging.error("Config file ignored: %s" % str(e))
        data = None

    return data


def _process_route_spec(route_spec, region_name, vpc_id, failed_ips):
    """
    Processes a full route spec. Update routes.

    """
    try:
        handle_spec(region_name, vpc_id, route_spec, failed_ips)
        # Get all the hosts, independent of route they belong to
    except VpcRouteSetError as e:
        logging.error("Cannot set route: %s" % str(e))


def _start_health_monitoring_thread(sleep_time):
    """
    Start the thread that montors the health of instances.

    It receives updates messages of which instances to monitor on a queue and
    returns messages about failed instances on another queue.

    It crates those two queues and returns those as well as a handle on the
    monitoring thread in a 3-tuple.

    """
    monitor_thread, q_monitor_ips, q_failed_ips = \
                                    start_monitor_in_background(sleep_time)
    return monitor_thread, q_monitor_ips, q_failed_ips


def _start_config_change_detection_thread(fname, region_name, vpc_id):
    """
    Monitor the route spec file for any changes.

    Returns a 3-tuple with the handle on the observer thread, a queue on which
    it communicates the full route spec whenever it changes.

    """
    q_route_spec = Queue.Queue()
    # Initial content of file needs to be processed at least once, before we
    # start watching for any changes to it. Therefore, we will write it out on
    # the queue right away.
    route_spec = {}
    try:
        route_spec = read_route_spec_config(fname)
        if route_spec:
            q_route_spec.put(route_spec)
    except ValueError as e:
        logging.warning("Cannot parse route spec: %s" % str(e))


    # Now prepare to watch for any changes in that file.
    # Find the parent directory of the config file, since this is where we will
    # attach a watcher to.
    abspath    = os.path.abspath(fname)
    parent_dir = os.path.dirname(abspath)

    # Create the file watcher and run in endless loop
    handler = RouteSpecChangeEventHandler(route_spec_fname   = fname,
                                          route_spec_abspath = abspath,
                                          q_route_spec       = q_route_spec)
    observer_thread = Observer()
    observer_thread.name = "ConfMon"
    observer_thread.schedule(handler, parent_dir)
    observer_thread.start()

    return observer_thread, q_route_spec


def _read_last_msg_from_queue(q):
    """
    Read all messages from a queue and return the last one.

    This is useful in our case, since all messages are always the complete
    state of things. Therefore, intermittent messages can be ignored.

    """
    msg = None
    while True:
        try:
            # The list of IPs is always a full list.
            msg = q.get_nowait()
            q.task_done()
        except Queue.Empty:
            # No more messages, all done for now
            return msg


def _update_health_monitor_with_new_ips(route_spec, all_ips,
                                        q_monitor_ips):
    """
    Take the current route spec and compare to the current list of known IP
    addresses. If the route spec mentiones a different set of IPs, update the
    monitoring thread with that new list.

    Return the current set of IPs mentioned in the route spec.

    """
    # Extract all the IP addresses from the route spec, unique and sorted.
    new_all_ips = \
        sorted(set(itertools.chain.from_iterable(route_spec.values())))
    if new_all_ips != all_ips:
        logging.debug("New route spec detected. Updating "
                      "health-monitor with: %s" %
                      ",".join(new_all_ips))
        # Looks like we have a new list of IPs
        all_ips = new_all_ips
        q_monitor_ips.put(all_ips)
    else:
        logging.debug("New route spec detected. No changes in "
                      "IP address list, not sending update to "
                      "health-monitor.")

    return all_ips


def start_daemon_as_watcher(region_name, vpc_id, fname, iterations=None,
                            sleep_time=1):
    """
    Start the VPC router as watcher, who listens for changes in a config file.

    The config file describes a routing spec. The spec should provide a
    destination CIDR and a set of hosts. The VPC router establishes a route to
    the first host in the set for the given CIDR.

    VPC router watches for any changes in the file and updates/adds/deletes
    routes as necessary.

    The 'iterations' argument allows us to limit the running time of the watch
    loop for test purposes. Not used during normal operation. Also, for faster
    tests, sleep_time can be set to values less than 1.

    This function starts three threads:

    - "ConfMon":   A file-change observer on the route spec file.
    - "HealthMon": Monitors health of instances mentioned in the route spec.
    - "HttpSrv":   A small HTTP server providing status information.

    It then drops into a loop to receive messages from the health monitoring
    thread and re-process the config if any failed IPs are reported.

    """
    # Start the health monitoring thread
    monitor_thread, q_monitor_ips, q_failed_ips = \
            _start_health_monitoring_thread(sleep_time)

    # Start the config change monitoring thread
    observer_thread, q_route_spec =  \
            _start_config_change_detection_thread(fname, region_name, vpc_id)

    # Start the HTTP server thread

    # -------------------------------------------------------------
    # Start the loop to process messages from the monitoring
    # threads about any failed IP addresses or updated route specs.
    try:
        all_ips    = []  # a cache of the IP addresses we currently know about
        route_spec = {}
        time.sleep(sleep_time*2)   # Wait to allow monitor to report results
        while True:
            # Get the latest messages from the route-spec monitor and the
            # health-check monitor. At system start the route-spec queue should
            # immediately have been initialized with a first message.
            failed_ips     = _read_last_msg_from_queue(q_failed_ips)
            new_route_spec = _read_last_msg_from_queue(q_route_spec)

            # Need to communicate a new set of IPs to the health
            # monitoring thread, in case the list changed
            if new_route_spec:
                route_spec = new_route_spec
                all_ips = _update_health_monitor_with_new_ips(route_spec,
                                                              all_ips,
                                                              q_monitor_ips)

            # Spec of list of failed IPs changed? Update routes...
            if new_route_spec or failed_ips:
                _process_route_spec(route_spec, region_name, vpc_id,
                                    failed_ips if failed_ips else [])

            # If iterations are provided, count down and exit
            if iterations is not None:
                iterations -= 1
                if iterations == 0:
                    break

            time.sleep(sleep_time)

    except KeyboardInterrupt:
        # Allow exit via keyboard interrupt, useful during development
        pass

    logging.debug("Stopping config change observer...")
    observer_thread.stop()   # Stop signal for config watcher thread
    logging.debug("Stopping health-check monitor...")
    q_monitor_ips.put(None)  # Stop signal to monitor thread

    observer_thread.join()
    monitor_thread.join()


