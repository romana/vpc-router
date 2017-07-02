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

import utils
import vpc
import watcher


def _setup_arg_parser():
    """
    Configure and return the argument parser for the command line options.

    """
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
    parser.add_argument('-m', '--mode', dest='mode', default='http',
                        help="either 'conffile' or 'http' "
                             "(default: http)")
    parser.add_argument('--verbose', dest="verbose", action='store_true',
                        help="produces more output")

    # Arguments for the conffile mode
    parser.add_argument('-f', '--file', dest='conf_file',
                        help="config file for routing groups "
                             "(only in conffile mode)"),

    # Arguments for the http mode
    parser.add_argument('-a', '--address', dest="listen_addr",
                        default="localhost",
                        help="address to listen on for commands "
                             "(only in http mode, default: localhost)")
    parser.add_argument('-p', '--port', dest="listen_port", default="33289",
                        type=int,
                        help="port to listen on for commands "
                             "(only in http mode, default: 33289)")

    return parser


def _check_http_mode_conf(conf):
    """
    Sanity checks for options needed for http mode.

    """
    if not 0 < conf['port'] < 65535:
        raise ArgsError("Invalid listen port '%d' for http mode." %
                        conf['port'])
    if not conf['addr'] == "localhost":
        # maybe a proper address was specified?
        utils.ip_check(conf['addr'])


def _check_conffile_mode_conf(conf):
    """
    Sanity checks for options needed for conffile mode.

    """
    if not conf['file']:
        raise ArgsError("A config file needs to be specified (-f).")
    try:
        # Check we have access to the config file
        f = open(conf['file'], "r")
        f.close()
    except IOError as e:
        raise ArgsError("Cannot open config file '%s': %s" %
                        (conf['file'], e))


def parse_args():
    """
    Parse command line arguments and return relevant values in a dict.

    Also perform basic sanity checking on some arguments.

    """
    conf = {}
    # Setting up the command line argument parser
    parser = _setup_arg_parser()

    args = parser.parse_args()
    conf['vpc_id']      = args.vpc_id
    conf['region_name'] = args.region
    conf['command']     = args.command
    conf['mode']        = args.mode
    conf['file']        = args.conf_file
    conf['port']        = args.listen_port
    conf['addr']        = args.listen_addr
    conf['logfile']     = args.logfile
    conf['verbose']     = args.verbose

    # Sanity checking of arguments.
    try:
        if conf['mode'] == 'http':
            _check_http_mode_conf(conf)
        elif conf['mode'] == 'conffile':
            _check_conffile_mode_conf(conf)
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
        conf = parse_args()
        setup_logging(conf)
    except Exception as e:
        print "\n*** Error: %s\n" % e.message

    try:
        logging.info("*** Starting vpc-router in %s mode ***" % conf['mode'])
        watcher.start_watcher(conf)
    except Exception as e:
        logging.error(e.message)

    sys.exit(1)
