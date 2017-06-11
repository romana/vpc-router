#!/usr/bin/env python

"""
Copyright 2017 Pani Networks Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

"""

import sys
import netaddr
import boto.vpc

# The AWS connection
CON  = None

# Config as provided by command line arguments or API
CONF = {
    "region_name" : "ap-southeast-2"
}


class VpcRouteSetError(Exception):
    pass


def _usage():
    """
    Print usage information.

    """
    print '''Usage:

    $ ./vr.py <vpc-id> [add|del|show] <dst-cidr> <router-ip>

        vpc-id:       The AWS ID of the VPC.
        add|del|show: Specify whether a route should be added or deleted,
                      or whether it should just show the instance and ENI
                      if the route already exists.
        dst-cidr:     The destination CIDR, for which you want to set a route.
        router-ip:    The IP address of the instance acting as router.
    '''


def _ip_check(ip, netmask_expected=False):
    """
    Sanity check that the specified string is indeed an IP address or mask.

    """
    if netmask_expected:
        netaddr.IPNetwork(ip)
    else:
        netaddr.IPAddress(ip)


def parse_args():
    """
    Parse command line arguments and fill relevant values into CONF dict.

    """
    if len(sys.argv) > 1:
        if "-h" in sys.argv or "--help" in sys.argv:
            _usage()
            sys.exit()
        if len(sys.argv) != 5:
            _usage()
            raise VpcRouteSetError("Need exactly 4 parameters.")
        CONF['vpc_id']    = sys.argv[1]
        CONF['command']   = sys.argv[2]
        CONF['dst_cidr']  = sys.argv[3]
        CONF['router_ip'] = sys.argv[4]
        cidr_check_passed = False
        try:
            _ip_check(CONF['dst_cidr'], netmask_expected=True)
            cidr_check_passed = True
            _ip_check(CONF['router_ip'])
        except netaddr.core.AddrFormatError:
            _usage()
            if cidr_check_passed:
                raise VpcRouteSetError("Format error for router IP address.")
            else:
                raise VpcRouteSetError("Format error for destination CIDR.")
        if CONF['command'] not in [ 'add', 'del', 'show' ]:
            _usage()
            raise VpcRouteSetError("Only commands 'add', 'del' or 'show' are "
                                   "allowed (not '%s')." % CONF['command'])
    else:
        CONF['vpc_id'] = None


def connect_to_region():
    """
    Establish connection to AWS API.

    """
    global CON
    CON = boto.vpc.connect_to_region(CONF['region_name'])


def get_vpc_overview(vpc_id=None):
    """
    Retrieve information for the specified VPC.

    If no VPC ID was specified then just pick the first VPC we find.

    Returns a dict with the VPC's zones, subnets and route tables and
    instances.

    """
    d = {}
    d['zones']  = CON.get_all_zones()

    # Find the specified VPC, or just use the first one
    all_vpcs    = CON.get_all_vpcs()
    if not all_vpcs:
        raise VpcRouteSetError("Cannot find any VPCs.")
    vpc = None
    if not vpc_id:
        # Just grab the first available VPC and use it, if no VPC specified
        vpc = all_vpcs[0]
    else:
        # Search through the list of VPCs for the one with the specified ID
        for v in all_vpcs:
            if v.id == vpc_id:
                vpc = v
                break
        if not vpc:
            raise VpcRouteSetError("Cannot find specified VPC '%s'." % vpc_id)
    d['vpc'] = vpc

    vpc_filter = { "vpc-id" : vpc_id } # Will use this filter expression a lot

    # Now find the subnets, route tables and instances within this VPC
    d['subnets']      = CON.get_all_subnets(filters=vpc_filter)
    d['route_tables'] = CON.get_all_route_tables(filters=vpc_filter)
    reservations      = CON.get_all_instances(filters=vpc_filter)
    d['instances']    = []  # get_all_instances returns reservations...
    for r in reservations:  # ... a reservation may have multiple instances
        d['instances'].extend(r.instances)

    # TODO: Need a way to find which route table we should focus on.

    return d


def find_instance_and_emi_by_ip(ip, vpc_info):
    """
    Given a specific IP address, find the EC2 instance and ENI.

    We need this information for setting the route.

    Returns instance and emi in a tuple.

    """
    for instance in vpc_info['instances']:
        for eni in instance.interfaces:
            if eni.private_ip_address == ip:
                print "Found router instance: (%s, %s)" % \
                    (instance.id, eni.id)
                return instance, eni
    raise VpcRouteSetError("Could not find instance/emi for '%s'." % ip)


def manage_route(vpc_info, instance, eni):
    """
    Set, delete or show the route to the specified instance.

    The specific command, destination CIDR and IP address are contained
    in the config.

    For now, we set the same route in all route tables.

    """
    cmd  = CONF['command']
    ip   = CONF['router_ip']
    cidr = CONF['dst_cidr']

    cmd_str = {
        "show" : "Searching for",
        "add"  : "Adding",
        "del"  : "Deleting"
    }
    print "%s route: %s -> %s (%s, %s)" % \
        (cmd_str[cmd], cidr, ip, instance.id, eni.id)
    for rt in vpc_info['route_tables']:
        found_in_rt = False
        """
        for r in rt.routes:
            print "-"*20
            print r.destination_cidr_block
            print r.gateway_id
            print r.instance_id
            print r.interface_id
            print r.origin
        """
        for r in rt.routes:
            if r.interface_id == eni.id and r.destination_cidr_block == cidr:
                found_in_rt = True
                if cmd == "show":
                    print "--- route exists in RT '%s'" % rt.id
                elif cmd == "del":
                    print "--- deleting route in RT '%s'" % rt.id
                    CON.delete_route(route_table_id         = rt.id,
                                     destination_cidr_block = cidr)
                elif cmd == "add":
                    print "--- route exists already in RT '%s'" % rt.id
        if not found_in_rt:
            if cmd in [ 'show', 'del' ]:
                print "--- did not find route in RT '%s'" % rt.id
            elif cmd == "add":
                print "--- adding route in RT '%s'" % rt.id
                CON.create_route(route_table_id         = rt.id,
                                 destination_cidr_block = cidr,
                                 instance_id            = instance.id,
                                 interface_id           = eni.id)


if __name__ == "__main__":
    try:
        parse_args()
        connect_to_region()
        vpc_info      = get_vpc_overview(CONF['vpc_id'])
        instance, eni = find_instance_and_emi_by_ip(CONF['router_ip'],
                                                    vpc_info)
        manage_route(vpc_info, instance, eni)
        sys.exit(0)
    except VpcRouteSetError as e:
        print "*** Error: %s\n" % e.message
    except boto.exception.EC2ResponseError as e:
        print "*** Error AWS API: %s\n" % e.message
    sys.exit(1)


