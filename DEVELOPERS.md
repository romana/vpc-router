# Contributing and developing

We welcome any contribution or feedback to vpc-router. Please use the [issue
tracker](https://github.com/romana/vpc-router/issues) to file bugs or request
features.


## Installation of required dependencies

When developing or contributing to vpc-router it is helpful to install some
useful packages for running local unit tests. You can do so with this command
(after you have performed the install outlined in the [README](README.md)):

    $ pip install -r requirements/develop.txt


## Running out of the source tree

Use the `vpcrouter-runner.py` script to run the program without having to
actually install (`setup.py`) the application.

    $ ./vpcrouter-runner.py ...


## Testing

To run all unit tests, use the `run_tests.sh` script, like so:

    $ ./run_tests.sh


This also creates code coverage reports in HTML, which are by default stored in
`/tmp/vpc-router-coverage`.


To just run specific tests, use (for example):

    $ python -m unittest vpcrouter.tests.test_utils


Use the `style_test.sh` script to check some common pep8 style guides and
code complexity.

    $ ./style_test.sh


## Architecture

The architecture of vpc-router is simple:

* A health-monitor thread detects if there are any failed hosts
  (`vpcrouter.monitor.plugins.*`).
* A configuration-watcher thread detects if there are any updates to the
  routing configuration (`vpcrouter.watcher.plugins.*`)
* A main loop receives notifications from both those threads via queues
  (`vpcrouter.watcher._event_monitor_loop`).
* If an update is received on either queue (failed hosts or new config) the
  'route-spec' is processed (`vpcrouter.vpc.handle_spec`): Check the current
  routes in VPC against the spec, see if all requested routes are present and
  if the current routers for each route are still healthy. If this is not the
  case the route is updated or removed or a new route is added.
* If a new route configuration is received, the main event loop updates the
  health-monitor thread with the new combined list of all hosts, via a third
  queue.
* The configuration-watcher thread utilizes plugins, which are dynamically
  loaded, and which are used depending on the selected mode (`-m` option on the
  command line).
* The health monitor thread also uses plugins to support different instance
  health monitoring options (`--health` option on the command line). Those
  plugins are conceptually very similar to the watcher plugins.

## Developing plugins

Please read the [plugin developer documentation](PLUGINS.md).

