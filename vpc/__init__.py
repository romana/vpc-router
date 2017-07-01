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

import logging
import random

import boto.vpc

from errors  import VpcRouteSetError
from watcher import common


def connect_to_region(region_name):
    """
    Establish connection to AWS API.

    """
    logging.debug("Connecting to AWS region '%s'" % region_name)
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
    logging.debug("Retrieving information for VPC '%s'" % vpc_id)
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

    vpc_filter = { "vpc-id" : vpc_id }  # Will use this filter expression a lot

    # Now find the subnets, route tables and instances within this VPC
    d['subnets']      = con.get_all_subnets(filters=vpc_filter)
    d['route_tables'] = con.get_all_route_tables(filters=vpc_filter)
    reservations      = con.get_all_reservations(filters=vpc_filter)
    d['instances']    = []
    for r in reservations:  # a reservation may have multiple instances
        d['instances'].extend(r.instances)

    # Maintain a quick instance lookup for convenience
    d['instance_by_id'] = {}
    for i in d['instances']:
        d['instance_by_id'][i.id] = i

    # TODO: Need a way to find which route table we should focus on.

    return d


def find_instance_and_emi_by_ip(vpc_info, ip):
    """
    Given a specific IP address, find the EC2 instance and ENI.

    We need this information for setting the route.

    Returns instance and emi in a tuple.

    """
    for instance in vpc_info['instances']:
        for eni in instance.interfaces:
            if eni.private_ip_address == ip:
                return instance, eni
    raise VpcRouteSetError("Could not find instance/emi for '%s' "
                           "in VPC '%s'." % (ip, vpc_info['vpc'].id))


def get_instance_private_ip_from_route(instance, route):
    """
    Find the private IP and ENI of an instance that's pointed to in a route.

    Returns (ipaddr, eni) tuple.

    """
    ipaddr = None
    for eni in instance.interfaces:
        if eni.id == route.interface_id:
            ipaddr = eni.private_ip_address
            break
    return ipaddr, eni if ipaddr else None


def manage_route_for_cli(con, vpc_info, cmd, ip, cidr):
    """
    Set, delete or show the route to the instance, specified by IP address.

    This is used for CLI requests to manage routes. Because CLI requests are
    one offs, the the logic here is different than the route spec processing
    performed in the 'normal' daemon mode.

    For show and delete only the CIDR is needed (the IP address can be left
    as None).

    For now, we set the same route in all route tables.

    Returns 'found' flag. The found flag will be 'false' if a show or delete
    didn't find the specified routes. If the add failes, an exception is
    thrown.

    """
    if ip:
        instance, eni = find_instance_and_emi_by_ip(vpc_info, ip)
    else:
        instance = eni = None

    found   = True
    cmd_str = {
        "show" : "Searching for",
        "add"  : "Adding",
        "del"  : "Deleting"
    }
    logging.debug("%s route: %s" % (cmd_str[cmd], cidr))

    for rt in vpc_info['route_tables']:
        found_in_rt = False
        for r in rt.routes:
            if r.destination_cidr_block == cidr:
                found_in_rt = True
                if not cmd == "add":
                    # For show and del the passed-in instance, ip and eni are
                    # None. Therefore, we find the instance from the route and
                    # the ip and eni from there.
                    instance = vpc_info['instance_by_id'][r.instance_id]
                    ipaddr, eni = get_instance_private_ip_from_route(
                                                                instance, r)

                    ipaddr = ipaddr if ipaddr else "(unknown)"
                    eni_id = eni.id if eni    else "(unknown)"

                    if cmd == "show":
                        logging.info("--- route exists in RT '%s': "
                                     "%s -> %s (%s, %s)" %
                                     (rt.id, cidr, ipaddr, instance.id,
                                      eni_id))

                    elif cmd == "del":
                        logging.info("--- deleting route in RT '%s': "
                                     "%s -> %s (%s, %s)" %
                                     (rt.id, cidr, ipaddr, instance.id,
                                      eni_id))
                        con.delete_route(route_table_id         = rt.id,
                                         destination_cidr_block = cidr)
                else:
                    # For 'add' the eni, instance and ip have been passed in
                    if r.interface_id == eni.id:
                        logging.info("--- route exists already in RT '%s': "
                                     "%s -> %s (%s, %s)" %
                                     (rt.id, cidr, ip, instance.id, eni.id))
                    else:
                        logging.info("--- route exists already in RT '%s', "
                                     "but with different destination: "
                                     "%s -> %s (%s, %s)" %
                                     (rt.id, cidr, ip, instance.id, eni.id))
                        con.replace_route(route_table_id         = rt.id,
                                          destination_cidr_block = cidr,
                                          instance_id            = instance.id,
                                          interface_id           = eni.id)
                break

        if not found_in_rt:
            if cmd in [ 'show', 'del' ]:
                logging.info("--- did not find route in RT '%s'" % rt.id)
                found = False
            elif cmd == "add":
                logging.info("--- adding route in RT '%s' "
                             "%s -> %s (%s, %s)" %
                             (rt.id, cidr, ip, instance.id, eni.id))
                con.create_route(route_table_id         = rt.id,
                                 destination_cidr_block = cidr,
                                 instance_id            = instance.id,
                                 interface_id           = eni.id)

    return found


def _choose_from_hosts(ip_list, failed_ips):
    """
    Randomly choose a host from a list of hosts.

    Check against the list of failed IPs to ensure that none of those is
    returned.

    If no suitable hosts can be found in the list (if it's empty or all hosts
    are in the failed_ips list) it will return None.

    """
    if not ip_list:
        return None

    # First choice is randomly selected, but it may actually be a failed
    # host...
    first_choice = random.randint(0, len(ip_list) - 1)

    # ... so start at the chosen first position and then iterate one by one
    # from there, until we find an IP that's not failed.
    i = first_choice
    while True:
        # Found one that's alive?
        if ip_list[i] not in failed_ips:
            return ip_list[i]
        # Keep going and wrap around...
        i += 1
        if i == len(ip_list):
            i = 0
        # Back at the start? Nothing could be found...
        if i == first_choice:
            break
    return None


def process_route_spec_config(con, vpc_info, route_spec, failed_ips):
    """
    Looks through the route spec and updates routes accordingly.

    Idea: Make sure we have a route for each CIDR.

    If we have a route to any of the IP addresses for a given CIDR then we are
    good. Otherwise, pick one (usually the first) IP and create a route to that
    IP.

    If a route points at a failed IP then a new candidate is chosen.

    """
    if failed_ips:
        logging.debug("Route spec processing. Failed IPs: %s" %
                      ",".join(failed_ips))
    else:
        logging.debug("Route spec processing. No failed IPs.")

    # Iterate over all the routes in the VPC, check they are contained in
    # the spec, update the routes as needed. Note that the status of the routes
    # is checked/updated for every route table, so we may see more than one
    # update for a given route.
    routes_in_rts = {}    # quick lookup of VPC routes by CIDR in 2nd loop
    for rt in vpc_info['route_tables']:
        routes_in_rts[rt.id] = []
        for r in rt.routes:
            dcidr = r.destination_cidr_block
            routes_in_rts[rt.id].append(dcidr)  # remember we've seen the route
            if r.instance_id is None:
                # There are some routes already present in the route table,
                # which we don't need to mess with. Specifically, routes that
                # aren't attached to a particular instance. We skip those.
                continue
            hosts = route_spec.get(dcidr)

            instance    = vpc_info['instance_by_id'][r.instance_id]
            ipaddr, eni = get_instance_private_ip_from_route(instance, r)

            ipaddr_has_failed = ipaddr in failed_ips

            if hosts:
                # This route is in the spec!
                if ipaddr in hosts and not ipaddr_has_failed:
                    # Host in spec and healthy? All good...
                    logging.info("--- route exists already in RT '%s': "
                                 "%s -> %s (%s, %s)" %
                                 (rt.id, dcidr, ipaddr, instance.id, eni.id))
                else:
                    # Select a new host randomly
                    new_addr = _choose_from_hosts(hosts, failed_ips)
                    if not new_addr:
                        # Current route doesn't point to an address in the
                        # spec or that IP has failed. Choose a new router
                        # IP address from the host list.
                        logging.warning("--- cannot find available target "
                                        "for route %s! "
                                        "Nothing I can do..." % dcidr)
                        continue

                    # Host is chosen, time to update the route to point to the
                    # new host.
                    try:
                        new_instance, new_eni = \
                            find_instance_and_emi_by_ip(vpc_info, new_addr)
                        if ipaddr_has_failed:
                            msg_fragment = "but router IP %s has failed: " % \
                                                    ipaddr
                        else:
                            msg_fragment = "but with different destination: "
                        logging.info("--- route exists already in RT '%s', %s"
                                     "updating %s -> %s (%s, %s)" %
                                     (rt.id, msg_fragment, dcidr, new_addr,
                                      new_instance.id, new_eni.id))
                        con.replace_route(
                                    route_table_id         = rt.id,
                                    destination_cidr_block = dcidr,
                                    instance_id            = new_instance.id,
                                    interface_id           = new_eni.id)
                        common.CURRENT_STATE['routes'][dcidr] = \
                                    ( new_addr, str(new_instance.id),
                                      str(new_eni.id) )
                    except VpcRouteSetError as e:
                        logging.error("*** failed to update route in RT '%s' "
                                      "%s -> %s (%s)" %
                                      (rt.id, dcidr, ipaddr, e.message))
            else:
                # The route isn't in the spec anymore and should be deleted.
                logging.info("--- route not in spec, deleting in RT '%s': "
                             "%s -> ... (%s, %s)" %
                             (rt.id, dcidr, instance.id,
                              eni.id if eni else "(unknown)" ))
                con.delete_route(route_table_id         = rt.id,
                                 destination_cidr_block = dcidr)
                if dcidr in common.CURRENT_STATE['routes']:
                    del common.CURRENT_STATE['routes'][dcidr]

    # Now go over all the routes in the spec and add those that aren't in VPC,
    # yet.
    for dcidr, hosts in route_spec.items():
        # Look at the routes we have seen in each of the route tables.
        for rt_id, dcidr_list in routes_in_rts.items():
            if dcidr not in dcidr_list:
                try:
                    # The route does not exist in this route table yet!
                    # Let's choose a host randomly.
                    new_addr = _choose_from_hosts(hosts, failed_ips)
                    instance, eni = find_instance_and_emi_by_ip(
                                                      vpc_info, new_addr)

                    logging.info("--- adding route in RT '%s' "
                                 "%s -> %s (%s, %s)" %
                                 (rt.id, dcidr, new_addr, instance.id,
                                  eni.id))
                    con.create_route(route_table_id         = rt_id,
                                     destination_cidr_block = dcidr,
                                     instance_id            = instance.id,
                                     interface_id           = eni.id)
                    common.CURRENT_STATE['routes'][dcidr] = \
                                ( new_addr, str(instance.id), str(eni.id) )
                except VpcRouteSetError as e:
                    logging.error("*** failed to add route in RT '%s' "
                                  "%s -> %s (%s)" %
                                  (rt_id, dcidr, new_addr, e.message))


def handle_spec(region_name, vpc_id, route_spec, failed_ips):
    """
    Connect to region and update routes according to route spec.

    """
    if not route_spec:
        logging.debug("handle_spec: No route spec provided")
        return

    logging.debug("Handle route spec")

    try:
        con      = connect_to_region(region_name)
        vpc_info = get_vpc_overview(con, vpc_id, region_name)
        process_route_spec_config(con, vpc_info, route_spec, failed_ips)
        con.close()
    except boto.exception.StandardError as e:
        logging.warning("vpc-router could not set route: %s" % e.message)

    except boto.exception.NoAuthHandlerFound:
        logging.error("vpc-router could not authenticate")


def handle_cli_request(region_name, vpc_id, cmd, router_ip, dst_cidr):
    """
    Connect to region and handle a route add/del/show request from the CLI.

    Returns accumulated messages in a list, as well as a 'found' flag that
    indicates whether the specified routes for a show or del command were
    found.

    Currently, we are not cashing the connection to the AWS API, we are opening
    and closing it for every request.

    """
    logging.debug("Handle request: cmd=%s, router_ip=%s, cidr=%s" %
                  (cmd, router_ip, dst_cidr))
    try:
        con      = connect_to_region(region_name)
        vpc_info = get_vpc_overview(con, vpc_id, region_name)
        found    = manage_route_for_cli(con, vpc_info, cmd, router_ip,
                                        dst_cidr)
        con.close()

        return found

    except boto.exception.StandardError as e:
        raise VpcRouteSetError("AWS API: " + e.message)

    except boto.exception.NoAuthHandlerFound:
        raise VpcRouteSetError("AWS API: vpc-router could not authenticate")

