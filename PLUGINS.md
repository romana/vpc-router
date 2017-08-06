# Plugins for the vpc-router

There are two types of plugins in use:

* Watcher plugins (getting topology information from the environment and
  orchestration system)
* Health monitor plugins (checking the health of routing instances)

# How to write watcher plugins

The 'watcher' is the component of vpc-router that watches for changed routing
configuration. It uses plugins so that it can easily be extended.

Three plugins are included by default:

* configfile: Watches a configuration file for changes.
* http: Starts a small HTTP server, accepts configuration updates via HTTP POST
  requests.
* fixedconf: With this a static config can be provided on the command line. It
  is mostly used as a simple example for plugin developers. It does work
  and might be useful in some cases, but is not commonly going to be used in
  production.

A watcher plugin communicates any routing configuration update to the main
event loop of the vpc-router via a queue. It always sends a full routing
configuration, never a partial update.

It is easy to write your own watcher plugin in order to integrate vpc-router
with whatever orchestration system or application you need.

## Location, naming convention and base class

The vpc-router comes with a number of 'integrated plugins'. These do not add a
lot of additional prerequisites and are relatively simple in their
functionality. However, it is also possible to develop more complex plugins in
their own repository ('external plugins'), which is discussed further below.

The integrated watcher plugins - those that come standard with vpc-router -
are located in the directory `vpcrouter/watcher/plugins/`.

The `-m` option on the vpc-router command line chooses the 'mode': This is
nothing but the name of the watcher plugin. It has to match the Python file
name in which the plugin is implemented. For example, the 'http' mode/plugin is
implemented in the `vpcrouter/watcher/plugins/http.py` file.

Every plugin should provide an implementation of the `WatcherPlugin` base
class, which is found in `vpcrouter/watcher/common.py`. Please make sure you
read the code there, including the docstrings. A plugin needs to implement a
very basic and simple API, which is defined by the `WatcherPlugin` class.

The plugin class' name should be the name of the plugin, capitalized.
Therefore, the 'http' plugin provides the `Http` class. The
'configfile' plugin provides the `Configfile` class, and so on.

## Example of an integrated plugin

Please have a look at `vpcrouter/watcher/plugins/fixedconf.py`. This is a very
simple, but fully functional integrated plugin. It adds a few command line
arguments to the vpc-router's command line parser, provides sanity checking
for those and is well documented.

Key points:

* Filename matches the 'mode' that can be selected via the `-m` argument.
* Classname is the mode name, capitalized.
* All the necessary functions of the `WatcherPlugin` are implemented.

## Example of an external plugin

Some plugins are more complex and add significant dependencies and additional
packages. It is better to develop those as external projects, instead of
bloating the requirements and dependencies of the base vpc-router installation.

As an example, please consider the
[vpc-router Romana plugin](https://github.com/romana/vpcrouter-romana-plugin).
It comes with its own `setup.py`, own test cases and own requirements files.
By perusing this repository you can see how to develop an external plugin for
vpc-router.


# How to write health monitor plugins

The 'monitor' is the component of vpc-router that watches the health of the
cluster nodes. It uses plugins so that it can easily be extended. The
design of health monitor plugins are very similar to the watcher
plugins.

Three health monitor plugin are included by default:

* icmpecho: This uses ICMPecho (ping) requests to check that an EC2 instance is
  responsive.
* tcp: This uses a TCP connection attempt to check that a process on an EC2
  instance is responsive.
* multi: This uses a specified set of simple health monitoring plugins to run
  multiple health-checks at the same time.

A health monitor plugin communicates any detected failed instances to the main
event loop of the vpc-router via a queue. It always sends a full list of the
currently failed instances, never a partial update.

The main event loop also uses a second queue to send full host lists back to
the monitor whenever there has been a change in the overall host list. The
health monitor plugin then starts to monitor all the hosts in that updated
host list.

## Location, naming convention and base class

The 'icmpecho', 'tcp' and 'multi' health monitor plugins are included. They are
"integrated plugins" (included in the vpc-router source) and are located in the
directory `vpcrouter/monitor/plugins/`.

The `-H` / `--health` option in the vpc-router command line chooses the health
monitor plugin. It uses 'icmpecho' as default value. The name of the plugin has
to match the name of the Python file in which the plugin is implemented. For
example, the 'icmpecho' plugin is implemented in the
`vpcrouter/monitor/plugins/icmpecho.py` file.

Every health monitor plugin should provide an implementation of the
`MonitorPlugin` base class, which is found in `vpcrouter/monitor/common.py`.
If you wish to write your own health monitor plugin, please make sure you
read the code there, including the docstrings. A plugin needs to implement
a very basic and simple API, which is defined by the `MonitorPlugin` class.

The plugin class' name should be the name of the plugin, capitalized.
Therefore, the 'icmpecho' plugin provides the `Icmpecho` class, the 'tcp'
plugin provides the `Tcp` class, and so on.

If you wish to study an example in order to start work on your own plugin, we
would recommend you have a look at the 'tcp' plugin, which is the simplest of
the three.
