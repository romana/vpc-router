#!/usr/bin/env python

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

import argparse
import logging
import sys

from errors  import ArgsError, VpcRouteSetError
from http    import start_daemon_with_http_api
from utils   import ip_check
from vpc     import handle_request
from watcher import start_daemon_as_watcher


def parse_args():
    """
    Parse command line arguments and return relevant values in a dict.

    Also perform basic sanity checking on some arguments.

    """
    conf = {}
    # Setting up the command line argument parser
    parser = argparse.ArgumentParser(
        description="VPC router: Manage routes in VPC route table")
    # General arguments
    parser.add_argument('-l', '--logfile', dest='logfile',
                        default='/tmp/vpc-router.log',
                        help="full path name for the logfile "
                             "(default: /tmp/vpc-router.log"),
    parser.add_argument('-r', '--region', dest="region",
                        default="ap-southeast-2",
                        help="the AWS region of the VPC")
    parser.add_argument('-v', '--vpc', dest="vpc_id", required=True,
                        help="the ID of the VPC in which to operate")
    parser.add_argument('-m', '--mode', dest='mode', default='cli',
                        help="either 'cli' or 'watcher' (default: cli)")
    parser.add_argument('--verbose', dest="verbose", action='store_true',
                        help="produces more output")

    # Arguments for the watcher mode
    parser.add_argument('-f', '--file', dest='watch_file',
                        help="config file for routing groups "
                             "(required in watcher mode)"),
    parser.add_argument('-a', '--address', dest="listen_addr",
                        default="localhost",
                        help="address to listen on for commands "
                             "(only in watcher mode, default: localhost)")
    parser.add_argument('-p', '--port', dest="listen_port", default="33289",
                        type=int,
                        help="port to listen on for commands "
                             "(only in watcher mode, default: 33289)")

    # Arguments for the CLI mode
    parser.add_argument('-c', '--cmd', dest="command",
                        help="either 'show', 'add' or 'del' "
                             "(only in CLI mode, default: show)")
    parser.add_argument('-C', '--CIDR', dest="dst_cidr",
                        help="the destination CIDR of the route "
                             "(only in CLI mode)")
    parser.add_argument('-i', '--ip', dest="router_ip",
                        help="IP address of router instance "
                             "(only in CLI more for 'add' command)")

    args = parser.parse_args()
    conf['vpc_id']      = args.vpc_id
    conf['region_name'] = args.region
    conf['command']     = args.command
    conf['dst_cidr']    = args.dst_cidr
    conf['router_ip']   = args.router_ip
    conf['mode']        = args.mode
    conf['file']        = args.watch_file
    conf['port']        = args.listen_port
    conf['addr']        = args.listen_addr
    conf['logfile']     = args.logfile
    conf['verbose']     = args.verbose

    # Sanity checking of arguments
    try:
        if conf['mode'] == 'watcher':
            # Sanity checks for various options needed in watcher mode:
            # - HTTP port and address
            # - Route spec config file
            if not 0 < conf['port'] < 65535:
                raise ArgsError("Invalid listen port '%d' for http mode." %
                                conf['port'])
            if not conf['addr'] == "localhost":
                # maybe a proper address was specified?
                ip_check(conf['addr'])
            if not conf['file']:
                raise ArgsError("A config file needs to be specified (-f).")
            try:
                # Check we have access to the config file
                f = open(conf['file'], "r")
                f.close()
            except IOError as e:
                raise ArgsError("Cannot open config file '%s': %s" %
                                (conf['file'], e))
        elif conf['mode'] == 'cli':
            # Sanity check if started with command line arguments
            if conf['command'] not in [ 'add', 'del', 'show' ]:
                raise ArgsError("Only commands 'add', 'del' or 'show' are "
                                "allowed (not '%s')." % conf['command'])
            if not conf['dst_cidr']:
                raise ArgsError("Destination CIDR argument missing.")
            if conf['command'] == 'add':
                if not conf['router_ip']:
                    raise ArgsError("Router IP address argument missing.")
            else:
                if conf['router_ip']:
                    raise ArgsError("Router IP address only allowed for "
                                    "'add'.")

            ip_check(conf['dst_cidr'], netmask_expected=True)
            if conf['router_ip']:
                ip_check(conf['router_ip'])

        else:

            raise ArgsError("Invalid operating mode '%s'." % conf['mode'])

    except ArgsError as e:
        parser.print_help()
        raise e

    return conf


def setup_logging(conf):
    """
    Configure the logging framework.

    If run in CLI mode then all log output is simply written to stdout.

    """
    if conf['verbose']:
        level = logging.DEBUG
    else:
        level = logging.INFO
    if conf['mode'] == "cli":
        # Just to stdout
        logging.basicConfig(level=level, format=None)
    else:
        logging.basicConfig(filename=conf['logfile'], level=level,
                            format='%(asctime)s - %(levelname)-8s - '
                                   '%(threadName)-11s - %(message)s')

    # Don't want to see all the debug messages from BOTO and watchdog
    logging.getLogger('boto').setLevel(logging.INFO)
    logging.getLogger('watchdog.observers.inotify_buffer'). \
                                                setLevel(logging.INFO)


#
# Main body of the executable.
#
if __name__ == "__main__":
    try:
        # Parse command line
        conf = parse_args()

        # Setup logging
        setup_logging(conf)

        if conf['mode'] == "http":
            logging.info("*** Starting vpc-router in HTTP server mode ***")
            start_daemon_with_http_api(conf['addr'], conf['port'],
                                       conf['region_name'], conf['vpc_id'])
        elif conf['mode'] == "watcher":
            logging.info("*** Starting vpc-router in watcher mode ***")
            start_daemon_as_watcher(conf['region_name'], conf['vpc_id'],
                                    conf['file'])
        else:
            # One off run from the command line
            msg, found = handle_request(
                conf['region_name'], conf['vpc_id'], conf['command'],
                conf['router_ip'], conf['dst_cidr'], conf['mode'] != 'cli')
            if found:
                sys.exit(0)
            else:
                sys.exit(1)
    except ArgsError as e:
        print "\n*** Error: %s\n" % e.message
    except VpcRouteSetError as e:
        logging.error(e.message)
    sys.exit(1)

