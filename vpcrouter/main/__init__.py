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
import importlib
import logging
import sys

from vpcrouter.errors  import ArgsError, PluginError

from vpcrouter.vpc     import get_ec2_meta_data
from vpcrouter         import watcher


def _setup_arg_parser(watcher_plugin_class, health_plugin_class):
    """
    Configure and return the argument parser for the command line options.

    If a watcher and/or health-monitor plugin_class is provided then call the
    add_arguments() callback of the plugin class(es), in order to add plugin
    specific options.

    Some parameters are required (vpc and region, for example), but we may be
    able to discover them automatically, later on. Therefore, we allow them to
    remain unset on the command line. We will have to complain about those
    parameters missing later on, if the auto discovery fails.

    Return parser and the conf-name of all the arguments that have been added.

    """

    parser = argparse.ArgumentParser(
                    description="VPC router: Manage routes in VPC route table")
    # General arguments
    parser.add_argument('-l', '--logfile', dest='logfile',
                        default='-',
                        help="full path name for the logfile, "
                             "or '-' for logging to stdout "
                             "(default: '-' (logging to stdout))"),
    parser.add_argument('-r', '--region', dest="region_name",
                        required=False, default=None,
                        help="the AWS region of the VPC")
    parser.add_argument('-v', '--vpc', dest="vpc_id",
                        required=False, default=None,
                        help="the ID of the VPC in which to operate")
    parser.add_argument('-m', '--mode', dest='mode', required=True,
                        help="name of the watcher plugin")
    parser.add_argument('-H', '--health', dest='health', required=False,
                        default="icmpecho",
                        help="name of the health-check plugin")
    parser.add_argument('--verbose', dest="verbose", action='store_true',
                        help="produces more output")

    arglist = ["logfile", "region_name", "vpc_id", "mode", "health", "verbose"]

    # Let each watcher and health-monitor plugin add its own arguments
    if watcher_plugin_class:
        arglist.extend(watcher_plugin_class.add_arguments(parser))
    if health_plugin_class:
        arglist.extend(health_plugin_class.add_arguments(parser))

    return parser, arglist


def parse_args(args_list, watcher_plugin_class=None, health_plugin_class=None):
    """
    Parse command line arguments and return relevant values in a dict.

    Also perform basic sanity checking on some arguments.

    If a watcher plugin class has been passed in, a callback into that class
    will be used to extend the arguments with plugin-specific options.

    Likewise, the sanity checking will then also invoke a callback into the
    plugin, chosen by the -m (mode) option, in order to perform a sanity check
    on the plugin options.

    """
    conf = {}

    # Setting up the command line argument parser
    parser, arglist = _setup_arg_parser(watcher_plugin_class,
                                        health_plugin_class)

    args = parser.parse_args(args_list)

    # Transcribe argument values into our own dict
    for argname in arglist:
        conf[argname] = getattr(args, argname)

    # Sanity checking of arguments. Let the watcher and health-monitor plugin
    # class check their own arguments.
    for plugin_class in [watcher_plugin_class, health_plugin_class]:
        if plugin_class is not None:
            try:
                plugin_class.check_arguments(conf)
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

    fname = conf['logfile'] if conf['logfile'] != "-" else None

    logging.basicConfig(filename=fname, level=level,
                        format='%(asctime)s - %(levelname)-8s - '
                               '%(threadName)-11s - %(message)s')

    # Don't want to see all the messages from BOTO and watchdog
    logging.getLogger('boto').setLevel(logging.CRITICAL)
    logging.getLogger('watchdog.observers.inotify_buffer'). \
                                                setLevel(logging.CRITICAL)


def load_plugin(plugin_name, default_plugin_module):
    """
    Load a plugin plugin.

    Supports loading of plugins that are part of the vpcrouter, as well as
    external plugins: If the plugin name has a dotted notation then it
    assumes it's an external plugin and the dotted notation is the complete
    import path. If it's just a single word then it looks for the plugin in
    the specified default module.

    Return the plugin class.

    """
    try:
        if "." in plugin_name:
            # Assume external plugin, full path
            plugin_mod_name   = plugin_name
            plugin_class_name = plugin_name.split(".")[-1].capitalize()
        else:
            # One of the built-in plugins
            plugin_mod_name   = "%s.%s" % (default_plugin_module, plugin_name)
            plugin_class_name = plugin_name.capitalize()

        plugin_mod        = importlib.import_module(plugin_mod_name)
        plugin_class      = getattr(plugin_mod, plugin_class_name)
        return plugin_class
    except ImportError as e:
        raise PluginError("Cannot load '%s'" % plugin_mod_name)
    except AttributeError:
        raise PluginError("Cannot find plugin class '%s' in "
                          "plugin '%s'" %
                          (plugin_class_name, plugin_mod_name))
    except Exception as e:
        raise PluginError("Error while loading plugin '%s': %s" %
                          (plugin_mod_name, str(e)))


def _param_extract(args, short_form, long_form):
    """
    Quick extraction of a parameter from the command line argument list.

    In some cases we need to parse a few arguments before the official
    arg-parser starts.

    Returns parameter value, or None if not present.

    """
    val = None            # Parameter wasn't defined
    for i, a in enumerate(args):
        # Long form may use "--xyz=foo", so need to split on '=', but it
        # doesn't necessarily do that, can also be "--xyz foo".
        elems = a.split("=", 1)
        if elems[0] in [short_form, long_form]:
            # At least make sure that an actual name was specified
            if len(elems) == 1:
                if i + 1 < len(args) and not args[i + 1].startswith("-"):
                    val = args[i + 1]
                else:
                    val = ""  # Invalid value was specified
            else:
                val = elems[1]
            break

    return val


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

        mode_name = _param_extract(args, "-m", "--mode")
        if mode_name:
            watcher_plugin_class = load_plugin(mode_name,
                                               "vpcrouter.watcher.plugins")
        else:
            watcher_plugin_class = None

        health_check_name = _param_extract(args, "-H", "--health")
        if health_check_name:
            health_plugin_class = load_plugin(health_check_name,
                                              "vpcrouter.monitor.plugins")
        else:
            health_plugin_class = None

        conf = parse_args(sys.argv[1:],
                          watcher_plugin_class, health_plugin_class)
        setup_logging(conf)

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
            logging.info("*** Starting vpc-router in %s mode ***" %
                         conf['mode'])
            watcher.start_watcher(conf,
                                  watcher_plugin_class, health_plugin_class)
            logging.info("*** Stopping vpc-router ***")
        except Exception as e:
            import traceback
            traceback.print_exc()
            logging.error(e.message)
            logging.error("*** Exiting")
    except Exception as e:
        print "\n*** Error: %s\n" % e.message

    sys.exit(1)
