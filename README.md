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

### Examples

*Setting a route*

The 'ip' option is the IP address of the EC2 instance that should act as
router.

    $ ./vpc-router.py -v vpc-350d6a51 -c add --CIDR 10.55.0.0/16 --ip 10.33.20.142

This operation is idempotent.

*Checking whether a route exists*

    $ ./vpc-router.py -v vpc-350d6a51 -c show --CIDR 10.55.0.0/16 --ip 10.33.20.142

If the specified route doesn't exist, the exit code will be '1'.

*Deleting an existing route*

    $ ./vpc-router.py -v vpc-350d6a51 -c del --CIDR 10.55.0.0/16 --ip 10.33.20.142

If the specified route doesn't exist, the exit code will be '1'.






