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
# Functions for watching route spec config file for changes.
#

import json
import logging
import os
import Queue

from watchdog.events    import FileSystemEventHandler, FileModifiedEvent
from watchdog.observers import Observer

from . import util


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

        logging.debug("Started config file change monitoring thread")


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
        data = util.parse_route_spec_config(data)

    except ValueError as e:
        logging.error("Config file ignored: %s" % str(e))
        data = None

    return data


def start_config_change_detection_thread(fname, region_name, vpc_id):
    """
    Monitor the route spec file for any changes.

    Returns a tuple with the handle on the observer thread and a queue on which
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

