# VPC-router

## Introduction

### Summary

The vpc-router implements automatic route failover and backup routes for Amazon
VPC environments.

vpc-router lets users avoid route table limitations and build large Kubernetes
clusters with the performance and visibility of native VPC networking.

It can also be used independently of Kubernetes whenever you need to manage
routes, backup routes and route failover in VPC environments.

It provides a plugin architecture for the easy integration with other cloud
orchestration systems.

### Details

vpc-router is a utility for setting and deleting routes in Amazon EC2 VPC route
tables and specifically for automatically managing route failover.

Each route is specified by a destination CIDR as well as a list of IP addresses
of EC2 instances, which are eligible to receive packets for the CIDR. An
instance from the list is chosen and a route is set. vpc-router continuously
monitors instance health and performs an immediate route failover to another
instance in the set in case of a detected instance failure.

Routes can be configured in different ways, but most commonly, vpc-router takes
route configs from storage (a config file, in the future also a KV store) or
via HTTP requests. It will make sure that routes in the VPC route table are
updated as needed with every detected change to the route config.

By default, it applies all route updates to all the route tables it can find
within a specified VPC.

### Project origin

This program was developed for the [Romana project](http://romana.io) to
overcome the limit imposed on VPC route table entries (50 by default), which
constricts the size of clusters. Avoiding this limit typically required running
an overlay network, which does not offer the performance and visibility of
native VPC networking. 

Some users prefer to run CNI network providers that support more advance
network policy APIs. However, most CNI pod networks require an overlay when
clusters are split across Availability Zones (AZs), preventing HA clusters from
delivering native VPC network performance. Romana, using vpc-router can build
CNI pod networks across zones without an overlay.
 
While vpc-router was specifically designed for use with Romana and to take
advantage of its topology aware IPAM in these Kubernetes deployment scenarios,
it does not depend on either project and can also be used stand-alone.

Plugins for integration with different environments are provided. For example,
a [plugin to integrate with Romana](https://github.com/romana/vpcrouter-romana-plugin).

Health-checks are also implemented via plugins. This means that vpc-router may
either directly contact EC2 instances to check their health, or it may instead
connect to AWS status and alert information, or use the node status provided by
orchestration systems, such as Kubernetes.

## Installation and running

You can either run vpc-router out of the source directory, or perform a full
install, it can run outside of the VPC or within, on a cluster node or not.

### Installation via pip

The vpc-router is in the Python Package Index (PyPi). Therefore, the simplest
way to install it is just:

    pip install vpcrouter

### Run vpc-router out of the source directory

If you wish to work with the vpc-router sources, or [contribute](#contributing)
to the project, you might want to run vpc-router directly from the sources.

After downloading the code, create a virtual environment, activate it and
install the required libraries. You can then use the `vpcrouter-runner.py`
helper script to run vpc-router without a full install:

    $ git clone git@github.com:paninetworks/vpc-router.git
    $ virtualenv vpcrouter
    $ source vpcrouter/bin/activate
    $ cd vpc-router
    $ pip install -r requirements/deploy.txt
    $ ./vpcrouter-runner.py .....

### Deploying in production environment

Please see our documentation on how to
[deploy vpc-router in production](DEPLOY.md), which covers issues such as:

* Performing a proper installation
* IaM permissions for running on EC2 instances
* Running vpc-router in a container

## Contributing

### Feedback, bug reports, issue tracker

We welcome any contributions, bug reports or feedback. Please use our
[issue tracker](https://github.com/romana/vpc-router/issues) to file bugs or request
additional features.

### Developing vpc-router

In order to develop or extend vpc-router, please read the [developer
documentation](DEVELOPERS.md) for information that might be useful to get you
started.

## Built-in HTTP server to see internal state and config

vpc-router comes with a built-in HTTP server. By default it listens on
`localhost:33289`. Send a GET request (with a web-browser, curl or wget, or any
client you wish) to `http://localhost:33290/` to receive a JSON formatted
output with the current internal configuration of vpc-router.

The listen address and port can be modified with the `-a` (address) and `-p`
(port) command line options.


## Configuration

### The route spec

vpc-router requires a route spec configuration in JSON format. It looks
something like this:

    {
        "10.55.16.0/24" : [ "10.33.20.142" ],
        "10.66.17.0/24" : [ "10.33.20.93", "10.33.30.22" ]
    }
    
Each entry in the dictionary is keyed on the route's CIDR and then lists a
number of eligible hosts, which can act as the target/router for this route.
vpc-router randomly chooses an instance from a route's set of hosts.

If a route to a specified CIDR does not exist in the VPC's route tables, or if
it does not specify a target that's contained in the specified host list,
vpc-router creates or updates the route.

The health of those hosts is continuously monitored. If a host acting as router
fails, vpc-router immediately switches the route to a different host from the
set, if an alternative is available and healthy.

Note that vpc-router takes control of the routing tables and removes any
entries of this type (interfaces on instances as target) if they are not part
of the route spec.

## Modes of operation

The modes for the detection of configuration updates are implemented via
plugins. It is therefore easy to extend vpc-router to integrate with
various orchestration systems. [How to write plugins](PLUGINS.md) is documented
separately.

A plugin may either accept a route spec in the format described above, or it
may be used to translate other information into the properly formatted
route spec.

### Internal mode plugins

Out of the box, plugins for three different configuration update modes are
included in the vpc-router source:

* configfile: Continuosly monitor a route spec configuration file for any
  changes. The config file should contain the route spec in exactly the format
  described above.
* http: Receive updated route specs via HTTP POSTs. The POSTed data should be
  the route-spec in exactly the format described above.
* fixedconf: With this a static config can be provided on the command line. It
  is mostly used as a simple example for plugin developers. It does work
  and might be useful in some cases, but is not commonly going to be used in
  production. It translates the command line parameters into a route spec of
  the required format.

### External mode plugins

It is also possible to write external plugins, which live in their own
repository. There is currently one example of this:

* romana: The
  [Romana plugin](https://github.com/romana/vpcrouter-romana-plugin) provides
  seamless integration with the [Romana project](http://romana.io/), for the
  creation of Kubernetes and OpenStack clusters without overlays, just
  natively routed network traffic. The vpc-router with the Romana plugin then
  allows those clusters to span multiple VPC Availability Zones, all while
  using native VPC networking and without being hindered by VPC's 50 route
  limit. The Romana plugin watches the network topology knowledge from Romana
  and translates it into the required route spec for vpc-router.

### Mode 'configfile' 

The following command starts vpc-router as a service daemon in 'configfile'
mode:

    $ vpcrouter -m configfile -f route-spec.conf -r us-east-1 -v vpc-350d6a51

The used options are:

* `-m configfile` tells vpc-router to take config changes from a specified
  route spec file.
* `-f` specifies the name of the route spec config file.
* `-r` specifies the AWS region to which vpc-router should connect. Note: This
  can be omitted if vpc-router is run on an instance in the region.
* `-v` specifies the VPC for which vpc-router should perform route updates.
  Note: This can be omitted if vpc-router is run on an instance within the VPC.

In 'configfile' mode the `-f` option must be used to specify the route spec
config file. It must exist when the server is started. The server then
continuously monitors this file for changes.

You can see an example route spec file in `examples/route_spec_1.conf`.

### Mode 'http'

The following command starts vpc-router as a service daemon in the 'http'
mode. It utilizes the built-in HTTP server to listen for new route specs:

    $ vpcrouter -m http -r us-east-1 -v vpc-350d6a51

The used options are:

* `-m http` tells vpc-router to start listening on a certain address and port
for HTTP POST requests containing new route specs.
* `-r` specifies the AWS region to which vpc-router should connect. Note: This
can be omitted if vpc-router is run on an instance in the region.
* `-v` specifies the VPC for which vpc-router should perform route updates.
Note: This can be omitted if vpc-router is run on an instance within the VPC.

A new route spec can be POSTed to the `/route_spec` URL. The current route spec
can be retrieved with a GET to that URL.

For example:

    $ curl -X "POST" -H "Content-type:application/json" "http://localhost:33289/route_spec" -d '{"10.55.0.0/16" : [ "10.33.20.142" ], "10.66.17.0/24" : [ "10.33.20.93", "10.33.30.22" ]}'

### Mode 'romana'

For integration with the [Romana project](http://romana.io/), please see the
[vpc-router Romana plugin](https://github.com/romana/vpcrouter-romana-plugin).

## Continuous monitoring

Continuos monitoring is performed for all hosts listed in the route spec. If an
instance does not appear healthy anymore and it is a current target for a route
then the route will be automatically updated to point to an alternate target,
if a healthy one is available.

The health-check itself is implemented via plugins, which gives vpc-router the
flexibility to use a wide variety of information to determine whether an EC2
routing instance is healthy. By default, it uses the 'icmpecho' plugin, which
utilizes an ICMPecho ('ping') request to actively check the responsiveness of
instances. A 'tcp' plugin, which attempts TCP connection attempts on a
specified port, is also provided.

Use the `--health` option to select the health monitor plugin, for example:

    $ vpcrouter --health tcp --tcp_check_port 22 --tcp_check_interval 5 ...

or:

    $ vpcrouter --health icmpecho --icmp_check_interval 5 ...

### The 'multi' plugin: Combining more than one health monitor plugin

A `multi` plugin is also provided with vpc-router. This plugin allows the
combining of multiple, simpler health-monitoring plugins into complex or
multi-layered instance health monitoring. Use the `--health` option to select
the `multi` plugin. Then use the `--multi_plugins` option to specify the list
of simple health plugins that should be used simultaneously (a list of column
separated health-monitor plugin names). Any additional command line options
added by those plugins can then also be specified.

As an example, let's configure vpc-router to use the `icmpecho` plugin (with a
monitoring interval of 2 seconds) as well as the `tcp` plugin, which should
monitor port 80.

    $ vpcrouter --health multi --multi_plugins icmpecho:tcp \
                        --icmp_check_interval 2 --tcp_check_port 80 ...

An instance is considered 'failed' if ANY of the specified sub-plugins reports
the instance as failed.

### Considering an instance as 'healthy' again

If a health monitoring plugin reports an instance as 'failed', it will be
considered 'failed' for some amount of time (the exact time depends on the
plugin, but usually it's 10 times the selected monitoring interval, when using
the 'multi' plugin, it will be 20 times the largest interval of the specified
sub-plugins).

The health monitoring occasionally attempts to re-check failed instances to see
if they have recovered. If not, it will report them as failed again.

If there has not been a 'failed' report about an instance within that time
window, the instance will automatically be considered as 'healthy' again. This
does not mean that routes are failing back to that instance, it just means that
this instance becomes eligible to be a target for routes again.

## TODO

A 'todo' list is maintained in the
[issue tracker](https://github.com/romana/vpc-router/issues) of the project.

