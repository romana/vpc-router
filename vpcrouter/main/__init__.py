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

# The main entry point for the executable and functions to parse command line
# arguments.

import argparse
import logging
import sys

import vpcrouter

from vpcrouter                  import monitor
from vpcrouter                  import utils
from vpcrouter                  import watcher
from vpcrouter.currentstate     import CURRENT_STATE
from vpcrouter.errors           import ArgsError
from vpcrouter.main             import http_server
from vpcrouter.plugin_framework import load_plugin
from vpcrouter.vpc              import get_ec2_meta_data


def _setup_arg_parser(args_list, watcher_plugin_class, health_plugin_class):
    """
    Configure and return the argument parser for the command line options.

    If a watcher and/or health-monitor plugin_class is provided then call the
    add_arguments() callback of the plugin class(es), in order to add plugin
    specific options.

    Some parameters are required (vpc and region, for example), but we may be
    able to discover them automatically, later on. Therefore, we allow them to
    remain unset on the command line. We will have to complain about those
    parameters missing later on, if the auto discovery fails.

    The args_list (from sys.argv) is passed in, since some plugins have to do
    their own ad-hoc extraction of certain parameters in order to add things
    to the official parameter list.

    Return parser and the conf-name of all the arguments that have been added.

    """
    parser = argparse.ArgumentParser(
                    description="VPC router: Manage routes in VPC route table")
    # General arguments
    parser.add_argument('--verbose', dest="verbose", action='store_true',
                        help="produces more output")
    parser.add_argument('-l', '--logfile', dest='logfile',
                        default='-',
                        help="full path name for the logfile, "
                             "or '-' for logging to stdout, "
                             "default: '-' (logging to stdout)"),
    parser.add_argument('-r', '--region', dest="region_name",
                        required=False, default=None,
                        help="the AWS region of the VPC")
    parser.add_argument('-v', '--vpc', dest="vpc_id",
                        required=False, default=None,
                        help="the ID of the VPC in which to operate")
    parser.add_argument('--ignore_routes', dest="ignore_routes",
                        required=False, default=None,
                        help="Comma separated list of CIDRs or IPs for "
                             "routes which vpc-router should ignore.")
    parser.add_argument('--route_recheck_interval',
                        dest="route_recheck_interval",
                        required=False, default="30", type=int,
                        help="time between regular checks of VPC route "
                             "tables, default: 30")
    parser.add_argument('-a', '--address', dest="addr",
                        default="localhost",
                        help="address to listen on for HTTP requests, "
                             "default: localhost")
    parser.add_argument('-p', '--port', dest="port",
                        default="33289", type=int,
                        help="port to listen on for HTTP requests, "
                             "default: 33289")
    parser.add_argument('-m', '--mode', dest='mode', required=True,
                        help="name of the watcher plugin")
    parser.add_argument('-H', '--health', dest='health', required=False,
                        default=monitor.MONITOR_DEFAULT_PLUGIN,
                        help="name of the health-check plugin, "
                             "default: %s" % monitor.MONITOR_DEFAULT_PLUGIN)

    arglist = ["logfile", "region_name", "vpc_id", "route_recheck_interval",
               "verbose", "addr", "port", "mode", "health", "ignore_routes"]

    # Inform the CurrentState object of the main config parameter names, which
    # should be rendered in an overview.
    CURRENT_STATE.main_param_names = list(arglist)

    # Let each watcher and health-monitor plugin add its own arguments.
    for plugin_class in [watcher_plugin_class, health_plugin_class]:
        if plugin_class:
            arglist.extend(plugin_class.add_arguments(parser, args_list))

    return parser, arglist


def _parse_args(args_list, watcher_plugin_class, health_plugin_class):
    """
    Parse command line arguments and return relevant values in a dict.

    Also perform basic sanity checking on some arguments.

    If plugin classes have been provided then a callback into those classes is
    used to extend the arguments with plugin-specific options.

    Likewise, the sanity checking will then also invoke a callback into the
    plugins, in order to perform a sanity check on the plugin options.

    """
    conf = {}

    # Setting up the command line argument parser. Note that we pass the
    # complete list of all plugins, so that their parameter can be added to the
    # official parameter handling, the help screen, etc. Some plugins may even
    # add further plugins themselves, but will handle this themselves.
    parser, arglist = _setup_arg_parser(args_list, watcher_plugin_class,
                                        health_plugin_class)
    args            = parser.parse_args(args_list)

    # Transcribe argument values into our own dict
    for argname in arglist:
        conf[argname] = getattr(args, argname)

    # Sanity checking of arguments. Let the watcher and health-monitor plugin
    # class check their own arguments.
    for plugin_class in [watcher_plugin_class, health_plugin_class]:
        if plugin_class:
            try:
                plugin_class.check_arguments(conf)
            except ArgsError as e:
                parser.print_help()
                raise e

    # Sanity checking of other args
    if conf['route_recheck_interval'] < 5 and \
                        conf['route_recheck_interval'] != 0:
        raise ArgsError("route_recheck_interval argument must be either 0 "
                        "or at least 5")

    if not 0 < conf['port'] < 65535:
        raise ArgsError("Invalid listen port '%d' for built-in http server." %
                        conf['port'])

    if not conf['addr'] == "localhost":
        # Check if a proper address was specified (already raises a suitable
        # ArgsError if not)
        utils.ip_check(conf['addr'])

    if conf['ignore_routes']:
        # Parse the list of addresses and CIDRs
        for a in conf['ignore_routes'].split(","):
            a = a.strip()
            a = utils.check_valid_ip_or_cidr(a, return_as_cidr=True)
            CURRENT_STATE.ignore_routes.append(a)

    # Store a reference to the config dict in the current state
    CURRENT_STATE.conf = conf

    return conf


def _setup_logging(conf):
    """
    Configure the logging framework.

    If run in CLI mode then all log output is simply written to stdout.

    """
    if conf['verbose']:
        level = logging.DEBUG
    else:
        level = logging.INFO

    fname = conf['logfile'] if conf['logfile'] != "-" else None

    logging.basicConfig(filename=fname, level=level,
                        format='%(asctime)s - %(levelname)-8s - '
                               '%(threadName)-15s - %(message)s')

    # Don't want to see all the messages from BOTO and watchdog
    logging.getLogger('boto').setLevel(logging.CRITICAL)
    logging.getLogger('watchdog.observers.inotify_buffer'). \
                                                setLevel(logging.CRITICAL)


def main():
    """
    Starting point of the executable.

    """
    try:
        # A bit of a hack: We want to load the plugins (specified via the mode
        # and health parameter) in order to add their arguments to the argument
        # parser. But this means we first need to look into the CLI arguments
        # to find them ... before looking at the arguments. So we first perform
        # a manual search through the argument list for this purpose only.
        args = sys.argv[1:]

        # Loading the watcher plugin
        mode_name = utils.param_extract(args, "-m", "--mode", default=None)
        if mode_name:
            watcher_plugin_class = \
                load_plugin(mode_name, watcher.WATCHER_DEFAULT_PLUGIN_MODULE)
        else:
            watcher_plugin_class = None

        # Loading the health monitor plugin
        health_check_name = \
            utils.param_extract(args, "-H", "--health",
                                default=monitor.MONITOR_DEFAULT_PLUGIN)
        if health_check_name:
            health_plugin_class = \
                load_plugin(health_check_name,
                            monitor.MONITOR_DEFAULT_PLUGIN_MODULE)
        else:
            health_plugin_class = None

        # Provide complete arg parsing for vpcrouter and all plugin classes.
        conf = _parse_args(sys.argv[1:],
                           watcher_plugin_class, health_plugin_class)

        if not health_plugin_class or not watcher_plugin_class:
            logging.error("Watcher plugin or health monitor plugin class "
                          "are missing.")
            sys.exit(1)

        _setup_logging(conf)

        # If we are on an EC2 instance then some data is already available to
        # us. The return data items in the meta data match some of the command
        # line arguments, so we can pass this through to the parser function to
        # provide defaults for those parameters. Specifically: VPC-ID and
        # region name.
        if not conf['vpc_id'] or not conf['region_name']:
            meta_data = get_ec2_meta_data()
            if 'vpc_id' not in meta_data or 'region_name' not in meta_data:
                logging.error("VPC and region were not explicitly specified "
                              "and can't be auto-discovered.")
                sys.exit(1)
            else:
                conf.update(meta_data)

        try:
            info_str = "vpc-router (%s): mode: %s (%s), " \
                       "health-check: %s (%s)" % \
                       (vpcrouter.__version__,
                        conf['mode'], watcher_plugin_class.get_version(),
                        health_check_name, health_plugin_class.get_version())
            logging.info("*** Starting %s ***" % info_str)
            CURRENT_STATE.versions = info_str

            http_srv = http_server.VpcRouterHttpServer(conf)
            CURRENT_STATE._vpc_router_http = http_srv

            watcher.start_watcher(conf,
                                  watcher_plugin_class, health_plugin_class)
            http_srv.stop()
            logging.info("*** Stopping vpc-router ***")
        except Exception as e:
            import traceback
            traceback.print_exc()
            logging.error(e.message)
            logging.error("*** Exiting")
    except Exception as e:
        print "\n*** Error: %s\n" % e.message

    sys.exit(1)
