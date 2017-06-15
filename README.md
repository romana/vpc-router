# vpc-router

## Introduction

vpc-router is a utility for the setting/deleting of routes in a VPC, consisting
of a destination CIDR as well as the IP address of an EC2 instance, which
should receive packets for any address in that CIDR.

This program can be used in various modes:

* CLI mode: a command line utility for a one-off operation
* Server mode: as a daemon listening for REST-like requests on an HTTP port
* Watcher mode: as daemon that monitors changes to a config file and updates
routes accordingly

## Installation

After downloading the code, create a virtual environment, activate it and
install the required libraries:

    $ git clone git@github.com:paninetworks/vpc-router.git
    $ virtualenv vpcrouter
    $ source vpcrouter/bin/activate
    $ cd vpc-router
    $ pip install -r requirements.txt

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


## Server mode: Using vpc-router as a daemon

To use vpc-router as a permanently running daemon, simply specify the region,
VPC ID as well as the '-m / --mode' flag with the 'http' value:

    $ ./vpc-router.py -m http -r us-east-1 -v vpc-350d6a51

You can then perform the 'add', 'show' and 'del' commands by posting requests
with the POST, GET or DELETE message, respectively.

By default, vpc-router uses port 33289. However, a different port number can be
specified with the '-p' option.

By default, vpc-router listens on the loopback address for incoming requests.
To specify other addresses, use the '-a' option. Specifically, use
'-a 0.0.0.0' to listen on any interface and address.

### Examples for API requests in server mode

**Setting a route ('POST')**:

    $ curl -X "POST" -H "Content-type:application/json" "http://localhost:33289/route" -d '{"dst_cidr" : "10.55.0.0/16", "router_ip" : "10.33.20.142"}'

*Note: An 'add' command for an existing route with the same CIDR, but different
router IP address, will update the route to the new IP address.*

**Checking whether a route exists ('GET'):**

    $ curl "http://localhost:33289/route?dst_cidr=10.55.0.0/16"

**Deleting an existing route ('DELETE'):**

    $ curl -X "DELETE" "http://localhost:33289/route?dst_cidr=10.55.0.0/16"

## Watcher mode

The vpc-router may also retrieve routing specs from a config file, which it
continuously monitors for any changes. Specify 'watcher' as mode and provide a
config file via the -f option.

    $ ./vpc-router.py -m watcher -f route-spec.conf -r us-east-1 -v vpc-350d6a51

The format of the route-spec file is simple:

    {
        "10.55.16.0/24" : [ "10.33.20.142" ],
        "10.55.17.0/24" : [ "10.33.20.93", "10.33.20.95" ],
        "10.66.17.0/24" : [ "10.33.20.93" ]
    }

For each CIDR a list of instance IP addresses provided. If a route to the CIDR
doesn't exist then a route to the first host in the list is created for the
CIDR. Routes to CIDRs not mentioned in the spec are deleted.

The host list may be changed, but as long as the current route destination is
still in the list the route will not be updated, to avoid unnecessary updates.

## TODO

* When running on an EC2 instance and no VPC or region is specified,
auto-detect the VPC and region of that instance.
* Support for BGP listener: Allow vpc-router to act as BGP peer and receive
route announcements via BGP.
* Access etcd for routing spec.
* In conjunction with previous point: Detect failure and update route to
backup.
* Fully developed daemon mode.
* Logging.


