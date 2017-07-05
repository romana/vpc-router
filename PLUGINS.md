# Developing watcher plugins

The 'watcher' is the component of vpc-router, which watches for changed routing
configuration. It uses plugins so that it can easily be extended.

Two plugins are included by default:

* configfile: Watches a configuration file for changes.
* http: Starts a small HTTP server, accepts configuration updates via HTTP POST
  requests.

A watcher plugin communicates any routing configuration update to the main
event loop of the vpc-router via a queue. It always completes a full routing
configuration, never a partial update.

It is easy to write your own watcher plugin in order to integrate vpc-router
with whatever orchestration system or application you want.

## Location, naming convention and base class

The watcher plugins are located in the directory `vpcrouter/watcher/plugins/`.

The `-m` option on the vpc-router command line chooses the 'mode': This is
nothing but the name of the watcher plugin. It has to match the Python file
name in which the plugin is implemented. For example, the 'http' mode/plugin is
implemented in the `vpcrouter/watcher/plugins/http.py` file.

Every plugin should be an implementation of the `WatcherPlugin` base class,
which is found in `vpcrouter/watcher/common.py`. Please make sure you read the
code there, including the docstrings. A plugin needs to implement a very basic
and simple API, which is defined by the `WatcherPlugin` class.

The plugin class' name should be the name of the plugin, capitalized.
Therefore, the 'http' plugin is implemented in the 'Http' class. The
'configfile' plugin provides a 'Configfile' class, and so on.

## Example

Please have a look at `vpcrouter/watcher/plugins/fixedconf.py`. This is a very
simple, but fully functional plugin. It adds a few command line arguments to
vpc-parser, provides sanity checking for those and is well documented.

Key points:

* Filename matches the 'mode' that can be selected via the `-m` argument.
* Classname is the mode name, capitalized.
* All the necessary functions of the `WatcherPlugin` are implemented.

