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

from watchdog.events    import FileSystemEventHandler, FileModifiedEvent
from watchdog.observers import Observer


FAILED_IPS    = []
Q_MONITOR_IPS = None
Q_FAILED_IPS  = None


class RouteSpecChangeEventHandler(FileSystemEventHandler):
    """
    My own event handler class, to be used to process events on the route-spec
    file. Since it calls the process function, it needs to know info about the
    file itself (paths and filenames) as well as the AWS side (region and VPC).

    """
    def __init__(self, *args, **kwargs):
        self._route_spec_fname   = kwargs['route_spec_fname']
        self._route_spec_abspath = kwargs['route_spec_abspath']
        self._region_name        = kwargs['region_name']
        self._vpc_id             = kwargs['vpc_id']

        del kwargs['route_spec_fname']
        del kwargs['route_spec_abspath']
        del kwargs['region_name']
        del kwargs['vpc_id']

        super(RouteSpecChangeEventHandler, self).__init__(*args, **kwargs)


    def on_modified(self, event):
        logging.debug("Detected file change event for %s" %
                      self._route_spec_abspath)
        if type(event) is FileModifiedEvent and \
                                    event.src_path == self._route_spec_abspath:
            _parse_and_process(self._route_spec_fname,
                               self._region_name,
                               self._vpc_id)


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


def _parse_and_process(fname, region_name, vpc_id):
    """
    Read and parse spec file, update routes, let monitor thread know which
    IPs are in the config.

    """
    try:
        route_spec = read_route_spec_config(fname)
        if not route_spec:
            return
        handle_spec(region_name, vpc_id, route_spec, True, FAILED_IPS)
        # Get all the hosts, independent of route they belong to
        all_hosts = set(itertools.chain.from_iterable(route_spec.values()))
        Q_MONITOR_IPS.put(list(all_hosts))
    except ValueError as e:
        logging.warning("Cannot parse route spec: %s" % str(e))
    except VpcRouteSetError as e:
        logging.error("Cannot set route: %s" % str(e))


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

    """
    global Q_MONITOR_IPS, Q_FAILED_IPS, FAILED_IPS

    # Start the monitoring thread
    monitor_thread, Q_MONITOR_IPS, Q_FAILED_IPS = \
                                    start_monitor_in_background(sleep_time)

    # Initial content of file needs to be processed at least once, before we
    # start watching for any changes to it.
    _parse_and_process(fname, region_name, vpc_id)

    # Now prepare to watch for any changes in that file.
    # Find the parent directory of the config file, since this is where we will
    # attach a watcher to.
    abspath    = os.path.abspath(fname)
    parent_dir = os.path.dirname(abspath)

    # Create the file watcher and run in endless loop
    handler = RouteSpecChangeEventHandler(route_spec_fname   = fname,
                                          route_spec_abspath = abspath,
                                          region_name        = region_name,
                                          vpc_id             = vpc_id)
    observer_thread = Observer()
    observer_thread.schedule(handler, parent_dir)
    observer_thread.start()

    try:
        while True:
            time.sleep(sleep_time)

            # Loop until we have processed all available message from the queue
            while True:
                try:
                    failed_ips = Q_FAILED_IPS.get_nowait()
                    Q_FAILED_IPS.task_done()
                    # The message is just an IP address of a host that's not
                    # accessible anymore.
                    FAILED_IPS = failed_ips
                    logging.info("Detected failed IPs: %s" %
                                 ",".join(failed_ips))
                    _parse_and_process(fname, region_name, vpc_id)
                except Queue.Empty:
                    # No more messages, all done for now
                    break

            # If iterations are provided, count down and exit
            if iterations is not None:
                iterations -= 1
                if iterations == 0:
                    break

    except KeyboardInterrupt:
        # Allow exit via keyboard interrupt, useful during development
        pass

    logging.debug("Stopping config change observer...")
    observer_thread.stop()   # Stop signal for config watcher thread
    logging.debug("Stopping health-check monitor...")
    Q_MONITOR_IPS.put(None)  # Stop signal to monitor thread

    observer_thread.join()
    monitor_thread.join()


