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
# A watcher plugin for observing a route spec config file for changes.
#

import datetime
import json
import logging
import os

import watchdog.events
import watchdog.observers

from vpcrouter.errors  import ArgsError
from vpcrouter.watcher import common


class RouteSpecChangeEventHandler(watchdog.events.FileSystemEventHandler):
    """
    Our own event handler class, to be used to process events on the route-spec
    file.

    """
    def __init__(self, *args, **kwargs):
        self._route_spec_fname   = kwargs['route_spec_fname']
        self._route_spec_abspath = kwargs['route_spec_abspath']
        self._q_route_spec       = kwargs['q_route_spec']
        self._plugin             = kwargs['plugin']

        del kwargs['route_spec_fname']
        del kwargs['route_spec_abspath']
        del kwargs['q_route_spec']
        del kwargs['plugin']

        super(RouteSpecChangeEventHandler, self).__init__(*args, **kwargs)

    def on_modified(self, event):
        if type(event) is watchdog.events.FileModifiedEvent and \
                                    event.src_path == self._route_spec_abspath:
            logging.info("Detected file change event for %s" %
                          self._route_spec_abspath)
            try:
                route_spec = read_route_spec_config(self._route_spec_fname)
                self._q_route_spec.put(route_spec)
                if self._plugin:
                    self._plugin.last_route_spec_update = \
                                            datetime.datetime.now()
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
        data = common.parse_route_spec_config(data)

    except ValueError as e:
        logging.error("Config ignored: %s" % str(e))
        data = None

    return data


class Configfile(common.WatcherPlugin):
    """
    Implements the WatcherPlugin interface for the 'configfile' plugin.

    Establishes a watcher thread, which detectes any changes to the config
    file and re-reads it.

    The plugin adds a command line argument to vpc-router:

    -f / --file: The name of the config file, which should be monitored.

    """
    def __init__(self, *args, **kwargs):
        super(Configfile, self).__init__(*args, **kwargs)
        self.last_route_spec_update = None

    def start(self):
        """
        Start the configfile change monitoring thread.

        """
        fname = self.conf['file']
        logging.info("Configfile watcher plugin: Starting to watch route spec "
                     "file '%s' for changes..." % fname)

        # Initial content of file needs to be processed at least once, before
        # we start watching for any changes to it. Therefore, we will write it
        # out on the queue right away.
        route_spec = {}
        try:
            route_spec = read_route_spec_config(fname)
            if route_spec:
                self.last_route_spec_update = datetime.datetime.now()
                self.q_route_spec.put(route_spec)
        except ValueError as e:
            logging.warning("Cannot parse route spec: %s" % str(e))

        # Now prepare to watch for any changes in that file.  Find the parent
        # directory of the config file, since this is where we will attach a
        # watcher to.
        abspath    = os.path.abspath(fname)
        parent_dir = os.path.dirname(abspath)

        # Create the file watcher and run in endless loop
        handler = RouteSpecChangeEventHandler(
                                    route_spec_fname   = fname,
                                    route_spec_abspath = abspath,
                                    q_route_spec       = self.q_route_spec,
                                    plugin             = self)
        self.observer_thread = watchdog.observers.Observer()
        self.observer_thread.name = "ConfMon"
        self.observer_thread.schedule(handler, parent_dir)
        self.observer_thread.start()

    def stop(self):
        """
        Stop the config change monitoring thread.

        """
        self.observer_thread.stop()
        self.observer_thread.join()
        logging.info("Configfile watcher plugin: Stopped")

    def get_info(self):
        """
        Return plugin information.

        """
        return {
            self.get_plugin_name() : {
                "version" : self.get_version(),
                "params" : {
                    "file" : self.conf['file']
                },
                "stats" : {
                    "last_route_spec_update" :
                        self.last_route_spec_update.isoformat()
                        if self.last_route_spec_update else "(no update, yet)"
                }
            }
        }

    @classmethod
    def add_arguments(cls, parser, sys_arg_list=None):
        """
        Arguments for the configfile mode.

        """
        parser.add_argument('-f', '--file', dest='file', required=True,
                            help="config file for routing groups "
                                 "(only in configfile mode)")
        return ["file"]

    @classmethod
    def check_arguments(cls, conf):
        """
        Sanity checks for options needed for configfile mode.

        """
        try:
            # Check we have access to the config file
            f = open(conf['file'], "r")
            f.close()
        except IOError as e:
            raise ArgsError("Cannot open config file '%s': %s" %
                            (conf['file'], e))
