# vpc-router

## Introduction

vpc-router is a utility for the setting/deleting of routes in a VPC route
table, consisting of a destination CIDR as well as the IP address of an EC2
instance, which should receive packets for any address in that CIDR.

In addition, vpc-router can continuously monitor instance health and perform an
immediate route failover in case of a detected instance failure.

Routes can be configured in different ways, but most commonly, vpc-router will
take route configs from a storage (file or KV store) or via HTTP requests.
It will make sure that routes in the VPC route table are updated as needed.

By default, it applies all route updates to all the route tables it can find
within a specified VPC.

### Project origin

This program was developed for the [Romana project](http://romana.io), in order
to seamlessly deploy large [Kubernetes](https://kubernetes.io) clusters across
multiple availability zones in an Amazon VPC. While specifically designed to
scratch our itch for this usage scenario in the context of Romana and
Kubernetes, the vpc-router does not depend on either project and can also be
used stand-alone.

## Installation

After downloading the code, create a virtual environment, activate it and
install the required libraries:

    $ git clone git@github.com:paninetworks/vpc-router.git
    $ virtualenv vpcrouter
    $ source vpcrouter/bin/activate
    $ cd vpc-router
    $ pip install -r requirements/deploy.txt

## Contributing

We welcome any contributions, bug reports or feedback.

Please read DEVELOPERS.txt for information that might be useful if you wish to
develop or contribute to vpc-router.

## Modes of operation

The vpc-router can be used in various modes:

* CLI mode: a command line utility for a one-off operation
* Watcher mode: as daemon that monitors changes to a config file or takes new
  route configurations in via HTTP requests. It also monitors the health of
  instances and updates routes accordingly (this is the most common mode for
  production deployments)

## CLI mode: Using vpc-router for single commands

When using vpc-router from the command line as an interactive utility, you can
use the '-h' or '--help' options for a brief overview of the available options.

There are three commands, which are understood by vpc-router:

* add: Create a new route for the specified CIDR and target EC2 instance IP
address. This command will add the route to all route tables of the specified
VPC.
* show: Produce output that shows whether the route already exists on any of
the route tables of the VPC.
* del: Delete the specified route from all route tables of the specified VPC.

### Examples for interactive command line mode

**Setting a route ('add' command)**:

The 'ip' option is the IP address of the EC2 instance that should act as
router.

    $ ./vpc-router.py -r us-east-1 -v vpc-350d6a51 -c add --CIDR 10.55.0.0/16 --ip 10.33.20.142

This operation is idempotent.

*Note: An 'add' command for an existing route with the same CIDR, but different
router IP address, will update the route to the new IP address.*

**Checking whether a route exists ('show' command):**

    $ ./vpc-router.py -r us-east-1 -v vpc-350d6a51 -c show --CIDR 10.55.0.0/16

If the specified route doesn't exist, the exit code will be '1'.

**Deleting an existing route ('del' command):**

    $ ./vpc-router.py -r us-east-1 -v vpc-350d6a51 -c del --CIDR 10.55.0.0/16

If the specified route doesn't exist, the exit code will be '1'.


## Watcher mode: Using vpc-router as a configuration and health monitoring server

To use vpc-router as a permanently running daemon, simply specify the region,
VPC ID as well as the '-m / --mode' flag with either 'conffile' or 'http' as
parameter.

    $ ./vpc-router.py -m http -r us-east-1 -v vpc-350d6a51

Or:

    $ ./vpc-router.py -m conffile -f route-spec.conf -r us-east-1 -v vpc-350d6a51

In 'http' mode, vpc-router by default uses port 33289 and listens on localhost.
However, you can use the '-p' (port) and -a ('address') options to specify
different listening port and address. Specifically, use '-a 0.0.0.0' to listen
on any interface and address.

In 'conffile' mode the '-f' option must be used to specify the route spec
config file. It must exist when the server is started. The server will then
continuously monitor this file for changes.

A route spec configuration - either in the config file or via an HTTP request -
has to be provided in JSON format. It looks something like this:

    {
        "10.55.16.0/24" : [ "10.33.20.142" ],
        "10.66.17.0/24" : [ "10.33.20.93", "10.33.30.22" ]
    }
    
Each entry in the dictionary is keyed on the route's CIDR and then lists a
number of eligible hosts, which can act as the target/router for this route.
vpc-router will randomly choose a host from those sets of hosts.

The health of those hosts is monitored (currently by sending ICMP echo
request). If a host acting as router fails, vpc-router immediately switches the
route to an alternative host from the set.


## Watcher mode: Conffile or HTTP

This is the default mode of operation, most suitable for production
deployments. In this mode, the vpc-router continously runs as a daemon. It
retrieves routing specs either from a config file, which it continuously
monitors for any changes, or via HTTP requests:

* Specify 'conffile' as mode and provide a config file via the -f option.
* Specify 'http' as mode and optionally a listen address and port (-a and -p
options, default is 'localhost' and 33289, respectively).

When using the watcher mode, vpc-router will continuously perform health checks on the
instances and update routes to an alternate instance if the current route
target should fail.

    $ ./vpc-router.py -m conffile -f route-spec.conf -r us-east-1 -v vpc-350d6a51

or:

    $ ./vpc-router.py -m http -f route-spec.conf -r us-east-1 -v vpc-350d6a51

The format of the route-spec is simple:

    {
        "10.55.16.0/24" : [ "10.33.20.142" ],
        "10.55.17.0/24" : [ "10.33.20.93", "10.33.20.95" ],
        "10.66.17.0/24" : [ "10.33.20.93" ]
    }

For each CIDR a list of instance IP addresses provided. If a route to the CIDR
doesn't exist then a route to a randomly chosen host in the list is created for
the CIDR. Routes to CIDRs not mentioned in the spec are deleted.

The host list may be changed, but as long as the current route destination is
still in the list the route will not be updated, to avoid unnecessary updates.

This route spec either needs to be present in the config file (with '-m
conffile'), or it needs to be POSTed to
http://<listen-address>:<port>/route_spec

For example:

    $ curl -X "POST" -H "Content-type:application/json" "http://localhost:33289/route_spec" -d '{"10.55.0.0/16" : [ "10.33.20.142" ], "10.66.17.0/24" : [ "10.33.20.93", "10.33.30.22" ]}'


### Continuous monitoring

Continuos monitoring is performed when running in watcher mode. If an instance
does not appear healthy anymore and it is a current target for a route then the
route will be automatically updated to point to an alternate target, if a
healthy one is available.

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


