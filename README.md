# vpc-router

## Introduction

vpc-router is a utility for the setting/deleting of routes in a VPC, consisting
of a destination CIDR as well as the IP address of an EC2 instance, which
should act as the router for the CIDR.

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

* add: Create a new route to for the specified CIDR and target EC2 instance IP
address. This command will add the route to all route tables of the specified
VPC.
* show: Produce output that shows whether the route already exists on any of
the route tables of the VPC.
* del: Delete the specified route from all route tables of the specified VPC.

### Examples

*Setting a route ('add' command):

The 'ip' option is the IP address of the EC2 instance that should act as
router.

    $ ./vpc-router.py -r us-east-1 -v vpc-350d6a51 -c add --CIDR 10.55.0.0/16 --ip 10.33.20.142

This operation is idempotent.

*Checking whether a route exists ('show' command):*

    $ ./vpc-router.py -r us-east-1 -v vpc-350d6a51 -c show --CIDR 10.55.0.0/16 --ip 10.33.20.142

If the specified route doesn't exist, the exit code will be '1'.

*Deleting an existing route ('del' command):*

    $ ./vpc-router.py -r us-east-1 -v vpc-350d6a51 -c del --CIDR 10.55.0.0/16 --ip 10.33.20.142

If the specified route doesn't exist, the exit code will be '1'.


## Server mode: Using vpc-router as a daemon

To use vpc-router as a permanently running daemon, simply specify the region,
VPC ID as well as the '-d' flag:

    $ ./vpc-router.py -r us-east-1 -v vpc-350d6a51 -d

You can then perform the 'add', 'show' and 'del' commands by posting requests
with the POST, GET or DELETE message, respectively.




