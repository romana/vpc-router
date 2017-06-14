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
# Functions for parsing of command line options.
#

import argparse

from errors import ArgsError
from utils  import ip_check

def parse_args():
    """
    Parse command line arguments and return relevant values in a dict.

    Also perform basic sanity checking on some arguments.

    """
    conf = {}
    # Setting up the command line argument parser
    parser = argparse.ArgumentParser(
        description="VPC router: Set routes in VPC route table")
    parser.add_argument('-d', '--daemon', dest='daemon', action='store_true',
                        help="start as daemon, wait for commands via network")
    parser.add_argument('-w', '--watcher', dest='watcher', action='store_true',
                        help="start as daemon, wait for routing spec updates"),
    parser.add_argument('-f', '--file', dest='watch_file',
                        help="config file for routing groups (watcher only)"),
    parser.add_argument('-v', '--vpc', dest="vpc_id", required=True,
                        help="the ID of the VPC in which to operate")
    parser.add_argument('-a', '--address', dest="listen_addr",
                        default="localhost",
                        help="address to listen on for commands "
                             "(only daemon mode)")
    parser.add_argument('-p', '--port', dest="listen_port", default="33289",
                        type=int,
                        help="port to listen on for commands "
                             "(only daemon mode)")
    parser.add_argument('-c', '--cmd', dest="command",
                        help="either 'show', 'add' or 'del' (default: 'show')")
    parser.add_argument('-r', '--region', dest="region",
                        default="ap-southeast-2",
                        help="the AWS region of the VPC")
    parser.add_argument('-C', '--CIDR', dest="dst_cidr",
                        help="the destination CIDR of the route")
    parser.add_argument('-i', '--ip', dest="router_ip",
                        help="IP address of router instance (only for 'add')")
    args = parser.parse_args()
    conf['vpc_id']      = args.vpc_id
    conf['region_name'] = args.region
    conf['command']     = args.command
    conf['dst_cidr']    = args.dst_cidr
    conf['router_ip']   = args.router_ip
    conf['daemon']      = args.daemon
    conf['watcher']     = args.watcher
    conf['file']        = args.watch_file
    conf['port']        = args.listen_port
    conf['addr']        = args.listen_addr

    # Sanity checking of arguments
    try:
        if conf['daemon']:
            # Sanity checks if started in daemon mode
            if not 0 < conf['port'] < 65535:
                raise ArgsError("Invalid listen port '%d' for daemon mode." %
                                conf['port'])
            if not conf['addr'] == "localhost":
                # maybe a proper address was specified?
                ip_check(conf['addr'])

        elif conf['watcher']:
            if not conf['file']:
                raise ArgsError("A config file needs to be specified (-f).")
            try:
                # Check we have access to the config file
                f = open(conf['file'], "r")
                f.close()
            except IOError as e:
                raise ArgsError("Cannot open config file '%s': %s" %
                                (conf['file'], e))
        else:
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

    except ArgsError as e:
        parser.print_help()
        raise e

    return conf


