# vpc-router

## Introduction

vpc-router is a utility for the setting/deleting of routes in a VPC, consisting
of a destination CIDR as well as the IP address of an EC2 instance, which
should receive packets for any address in that CIDR.

This program can be used either as a command line utility for a one-off
operation, or it can be started in daemon mode. In the latter case, it will
start to listen for REST-like requests on an HTTP port.

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
VPC ID as well as the '-d' flag:

    $ ./vpc-router.py -r us-east-1 -v vpc-350d6a51 -d

You can then perform the 'add', 'show' and 'del' commands by posting requests
with the POST, GET or DELETE message, respectively.

By default, vpc-router uses port 33289. However, a different port number can be
specified with the '-p' option.

By default, vpc-router listens on the loopback address for incoming requests.
To specify other addresses, use the '-a' option. Specifically, use
'-a 0.0.0.0' to listen on any interface and address.

### Examples for API requests in daemon mode

**Setting a route ('POST')**:

    $ curl -X "POST" -H "Content-type:application/json" "http://localhost:33289/route" -d '{"dst_cidr" : "10.55.0.0/16", "router_ip" : "10.33.20.142"}'

*Note: An 'add' command for an existing route with the same CIDR, but different
router IP address, will update the route to the new IP address.*

**Checking whether a route exists ('GET'):**

    $ curl "http://localhost:33289/route?dst_cidr=10.55.0.0/16"

**Deleting an existing route ('DELETE'):**

    $ curl -X "DELETE" "http://localhost:33289/route?dst_cidr=10.55.0.0/16"


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


