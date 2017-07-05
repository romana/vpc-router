# vpc-router

The vpc-router implements automatic route failover and backup routes for Amazon
VPC environments.

vpc-router lets users avoid route table limitations and build large Kubernetes
clusters with the performance and visibility of native VPC networking.

It can also be used independently of Kubernetes whenever you need to manage
routes, backup routes and route failover in VPC environments.

## Introduction

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

## Installation

You can either run vpc-router out of the source directory, or perform a full
install.

### Run out of the source directory

After downloading the code, create a virtual environment, activate it and
install the required libraries:

    $ git clone git@github.com:paninetworks/vpc-router.git
    $ virtualenv vpcrouter
    $ source vpcrouter/bin/activate
    $ cd vpc-router
    $ pip install -r requirements/deploy.txt
    $ ./vpcrouter-runner.py .....

### Perform a full install

After downloading the code, run the setup.py script:

    $ git clone git@github.com:paninetworks/vpc-router.git
    $ cd vpc-router
    $ python setup.py install

## Contributing

We welcome any contributions, bug reports or feedback.

Please read the [developer documentation](DEVELOPERS.md) for information that
might be useful if you wish to develop or contribute to vpc-router.

## Configuration: The route spec

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

By default there are two modes in which vpc-router can receive configuration
updates:

* configfile: Continuosly monitor a route spec configuration file for any changes.
* http: Receive updated route specs via HTTP POSTs.

The format of the config data in both cases (config file or POST request) is
the identical.

The modes for the detection of configuration updates are implemented via
plugins. It is therefore easy to directly extend vpc-router to integrate with
various orchestration systems. How to write plugins is documented separately.

### Mode 'configfile' 

The following command starts vpc-router as a service daemon in 'configfile'
mode:

    $ ./vpc-router.py -m configfile -f route-spec.conf -r us-east-1 -v vpc-350d6a51

The used options are:

* `-m configfile` tells vpc-router to take config changes from a specified route
  spec file.
* `-f` specifies the name of the route spec config file.
* `-r` specifies the AWS region to which vpc-router should connect.
* `-v` specifies the VPC for which vpc-router should perform route updates.

In 'configfile' mode the `-f` option must be used to specify the route spec
config file. It must exist when the server is started. The server then
continuously monitors this file for changes.

You can see an example route spec file in `examples/route_spec_1.conf`.

### Mode 'http'

The following command starts vpc-router as a service daemon in the 'http'
mode. In opens a server port on which it listens for new route specs:

    $ ./vpc-router.py -m http -r us-east-1 -v vpc-350d6a51

The used options are:

* `-m http` tells vpc-router to start listening on a certain address and port
for HTTP POST requests containing new route specs.
* `-r` specifies the AWS region to which vpc-router should connect.
* `-v` specifies the VPC for which vpc-router should perform route updates.

In 'http' mode, vpc-router by default uses port 33289 and listens on localhost.
However, you can use the `-p` (port) and `-a` ('address') options to specify a
different listening port or address. Specifically, use `-a 0.0.0.0` to listen
on any interface and address.

There are a two URLs offered in 'http' mode:

* `/route_spec`: POST a new route spec here, or GET the current route spec.
* `/status`: GET a status overview, containing the route spec as well as the
  current list of any failed IP addresses and currently configured routes.

In 'http' mode, new route specs are POSTed to
http://<listen-address>:<port>/route_spec

For example:

    $ curl -X "POST" -H "Content-type:application/json" "http://localhost:33289/route_spec" -d '{"10.55.0.0/16" : [ "10.33.20.142" ], "10.66.17.0/24" : [ "10.33.20.93", "10.33.30.22" ]}'

## Continuous monitoring

Continuos monitoring is performed for all hosts listed in the route spec. If an
instance does not appear healthy anymore and it is a current target for a route
then the route will be automatically updated to point to an alternate target,
if a healthy one is available.

Currently, the health check consists of an ICMP echo request. In the future,
this will be made configurable.

## TODO

* When running on an EC2 instance and no VPC or region is specified,
  auto-detect the VPC and region of that instance.
* Support for BGP listener: Allow vpc-router to act as BGP peer and receive
  route announcements via BGP.
* Access etcd for routing spec.
* Configurable health checks.
* Ability to use CloudWatch alerts, instead of active health checks to detect
  instance failure.


