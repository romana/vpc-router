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

import os
import json
import time

from errors import ArgsError
from utils  import ip_check
from vpc    import handle_request

from watchdog.events    import FileSystemEventHandler, FileModifiedEvent
from watchdog.observers import Observer


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
        f = open(fname, "r")
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
        print "*** Error: Malformed config file ignored: %s" % str(e)

    return data


def process_route_spec_config(vpc_id, route_spec):
    """
    Looks through the route spec and updates routes accordingly.

    Idea: Make sure we have a route for each CIDR.

    If we have a route to any of the IP addresses for a given CIDR then we are
    good. Otherwise, pick one (usually the first) IP and create a route to that
    IP.

    """
    print "Processing: ", route_spec


def start_daemon_as_watcher(vpc_id, fname):
    """
    Start the VPC router as watcher, who listens for changes in a config file.

    The config file describes a routing spec. The spec should provide a
    destination CIDR and a set of hosts. The VPC router establishes a route to
    the first host in the set for the given CIDR.

    VPC router watches for any changes in the file and updates/adds/deletes
    routes as necessary.

    """
    # Do one initial read and parse of the config file to start operation
    try:
        route_spec = read_route_spec_config(fname)
        process_route_spec_config(vpc_id, route_spec)
    except ValueError as e:
        print "@@@ Warning: Cannot parse route spec: %s" % str(e)


    # Now prepare to watch for any changes in that file.
    # Find the parent directory of the config file, since this is where we will
    # attach a watcher to.
    abspath    = os.path.abspath(fname)
    parent_dir = os.path.dirname(abspath)

    class MyEventHandler(FileSystemEventHandler):
        """
        My own event handler class, knows the absolute path we just calculated
        and only looks for file-modified events of this file.

        """
        def on_modified(self, event):
            if type(event) is FileModifiedEvent and event.src_path == abspath:
                try:
                    route_spec = read_route_spec_config(fname)
                    process_route_spec_config(vpc_id, route_spec)
                except ValueError as e:
                    print "@@@ Warning: Cannot parse route spec: %s" % str(e)

    # Create the file watcher and run in endless loop
    observer = Observer()
    observer.schedule(MyEventHandler(), parent_dir)
    observer.start()
    try:
        while True:
            time.sleep(10) # seems to be no change in if we modifiy this time
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


