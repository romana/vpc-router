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

#
# Functions dealing with VPC.
#

import boto.vpc

from errors import VpcRouteSetError

def connect_to_region(region_name):
    """
    Establish connection to AWS API.

    """
    con = boto.vpc.connect_to_region(region_name)
    if not con:
        raise VpcRouteSetError("Could not establish connection to "
                               "region '%s'." % region_name)
    return con


def get_vpc_overview(con, vpc_id, region_name):
    """
    Retrieve information for the specified VPC.

    If no VPC ID was specified then just pick the first VPC we find.

    Returns a dict with the VPC's zones, subnets and route tables and
    instances.

    """
    d = {}
    d['zones']  = con.get_all_zones()

    # Find the specified VPC, or just use the first one
    all_vpcs    = con.get_all_vpcs()
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
            raise VpcRouteSetError("Cannot find specified VPC '%s' "
                                   "in region '%s'." % (vpc_id, region_name))
    d['vpc'] = vpc

    vpc_filter = { "vpc-id" : vpc_id } # Will use this filter expression a lot

    # Now find the subnets, route tables and instances within this VPC
    d['subnets']      = con.get_all_subnets(filters=vpc_filter)
    d['route_tables'] = con.get_all_route_tables(filters=vpc_filter)
    reservations      = con.get_all_reservations(filters=vpc_filter)
    d['instances']    = []
    for r in reservations:  # a reservation may have multiple instances
        d['instances'].extend(r.instances)

    # TODO: Need a way to find which route table we should focus on.

    return d


def find_instance_and_emi_by_ip(vpc_info, ip, daemon):
    """
    Given a specific IP address, find the EC2 instance and ENI.

    We need this information for setting the route.

    Returns instance and emi in a tuple.

    """
    for instance in vpc_info['instances']:
        for eni in instance.interfaces:
            if eni.private_ip_address == ip:
                if not daemon:
                    print "Found router instance: (%s, %s)" % \
                        (instance.id, eni.id)
                return instance, eni
    raise VpcRouteSetError("Could not find instance/emi for '%s' "
                           "in VPC '%s'." % (ip, vpc_info['vpc'].id))


def manage_route(con, vpc_info, instance, eni, cmd, ip, cidr, daemon):
    """
    Set, delete or show the route to the specified instance.

    For show and delete only the CIDR is needed (instance, eni and ip can
    be None).

    For now, we set the same route in all route tables.

    Returns any accumulated messages in a list of strings, as well as a
    'found' flag. The found flag will be 'false' if a show or delete didn't
    find the specified routes. If the add failes, an exception is thrown.

    """
    msg     = []
    found   = True
    cmd_str = {
        "show" : "Searching for",
        "add"  : "Adding",
        "del"  : "Deleting"
    }
    if not daemon:
        if cmd == "add":
            msg.append("%s route: %s -> %s (%s, %s)" %
                       (cmd_str[cmd], cidr, ip, instance.id, eni.id))
        else:
            msg.append("%s route: %s" % (cmd_str[cmd], cidr))

    for rt in vpc_info['route_tables']:
        found_in_rt = False
        for r in rt.routes:
            if r.destination_cidr_block == cidr:
                found_in_rt = True
                if cmd == "show":
                    msg.append("--- route exists in RT '%s'" % rt.id)
                elif cmd == "del":
                    msg.append("--- deleting route in RT '%s'" % rt.id)
                    con.delete_route(route_table_id         = rt.id,
                                     destination_cidr_block = cidr)
                elif cmd == "add":
                    if r.interface_id == eni.id:
                        msg.append("--- route exists already in RT '%s'" %
                                   rt.id)
                    else:
                        msg.append("--- route exists already in RT '%s', "
                                   "but with different destination. "
                                   "Updating." % rt.id)
                        con.replace_route(route_table_id        = rt.id,
                                         destination_cidr_block = cidr,
                                         instance_id            = instance.id,
                                         interface_id           = eni.id)
                break

        if not found_in_rt:
            if cmd in [ 'show', 'del' ]:
                msg.append("--- did not find route in RT '%s'" % rt.id)
                found = False
            elif cmd == "add":
                msg.append("--- adding route in RT '%s'" % rt.id)
                con.create_route(route_table_id         = rt.id,
                                 destination_cidr_block = cidr,
                                 instance_id            = instance.id,
                                 interface_id           = eni.id)

    return msg, found


def handle_request(region_name, vpc_id, cmd, router_ip, dst_cidr, daemon):
    """
    Connect to region and handle a route add/del/show request.

    Returns accumulated messages in a list, as well as a 'found' flag that
    indicates whether the specified routes for a show or del command were
    found.

    """
    try:
        con           = connect_to_region(region_name)
        vpc_info      = get_vpc_overview(con, vpc_id, region_name)
        if router_ip:
            instance, eni = find_instance_and_emi_by_ip(vpc_info, router_ip,
                                                        daemon)
        else:
            instance = eni = None
        msgs, found   = manage_route(con, vpc_info, instance, eni,
                                     cmd, router_ip, dst_cidr, daemon)
        con.close()

        if not daemon:
            for m in msgs:
                print m

        return msgs, found

    except boto.exception.StandardError as e:
        raise VpcRouteSetError("AWS API: " + e.message)

    except boto.exception.NoAuthHandlerFound:
        raise VpcRouteSetError("AWS API: vpc-router could not authenticate")

