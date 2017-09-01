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

import datetime
import logging
import random

import boto.vpc
import boto.utils

from vpcrouter.errors       import VpcRouteSetError
from vpcrouter.currentstate import CURRENT_STATE


def get_ec2_meta_data():
    """
    Get meta data about ourselves, if we are on an EC2 instance.

    In particular, this returns the VPC ID and region of this instance.

    If we are not on an EC2 instance it returns an empty dict.

    """
    # The timeout is just for the connection attempt, but between retries there
    # is an exponential back off in seconds. So, too many retries and it can
    # possibly block for a very long time here. Main contributor to waiting
    # time here is the number of retries, rather than the timeout time.
    try:
        md     = boto.utils.get_instance_metadata(timeout=2, num_retries=2)
        vpc_id = md['network']['interfaces']['macs'].values()[0]['vpc-id']
        region = md['placement']['availability-zone'][:-1]
        return {"vpc_id" : vpc_id, "region_name" : region}
    except:
        # Any problem while getting the meta data? Assume we are not on an EC2
        # instance.
        return {}


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
    d['zones'] = con.get_all_zones()

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

    vpc_filter = {"vpc-id" : vpc_id}  # Will use this filter expression a lot

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


def find_instance_and_eni_by_ip(vpc_info, ip):
    """
    Given a specific IP address, find the EC2 instance and ENI.

    We need this information for setting the route.

    Returns instance and emi in a tuple.

    """
    for instance in vpc_info['instances']:
        for eni in instance.interfaces:
            if eni.private_ip_address == ip:
                return instance, eni
    raise VpcRouteSetError("Could not find instance/eni for '%s' "
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


def _choose_different_host(old_ip, ip_list, failed_ips, questionable_ips):
    """
    Randomly choose a different host from a list of hosts.

    Pick from fully healthy IPs first (neither failed nor questionable).
    If we don't have any of those, pick from questionable ones next.

    If no suitable hosts can be found in the list (if it's empty or all hosts
    are in the failed_ips list) it will return None.

    The old IP (if any) is passed in. We will try to avoid returning this same
    old IP under the right circumstances. If no old IP is known, None can be
    passed in for it instead.

    """
    if not ip_list:
        # We don't have any hosts to choose from.
        return None

    ip_set           = set(ip_list)
    failed_set       = set(failed_ips)
    # Consider only those questionable IPs that aren't also failed and make
    # sure all of the ones in the questionable list are at least also present
    # in the overall IP list.
    questionable_set = set(questionable_ips).intersection(ip_set). \
                                             difference(failed_set)

    # Get all healthy IPs that are neither failed, nor questionable
    healthy_ips = list(ip_set.difference(failed_set, questionable_set))

    if healthy_ips:
        # Return one of the completely healthy IPs
        return random.choice(healthy_ips)

    if questionable_set:
        # Don't have any completely healthy ones, so return one of the
        # questionable ones. Not perfect, but at least may still provide
        # routing functionality for some time.
        if old_ip not in questionable_set:
            # We may be here because the original address was questionable. If
            # only other questionable ones are available then there's no point
            # changing the address. We only change if the old address wasn't
            # one of the questionable ones already.
            return random.choice(list(questionable_set))

    # We got nothing...
    return None


def _rt_state_update(route_table_id, dcidr, router_ip="(none)",
                     instance_id="(none)", eni_id="(none)",
                     old_router_ip="(none)", msg="(none)"):
    """
    Store a message about a VPC route in the current state.

    """
    buf = "inst: %s, eni: %s, r_ip: %-15s, o_r_ip: %-15s, msg: %s" % \
          (instance_id, eni_id, router_ip, old_router_ip, msg)
    CURRENT_STATE.vpc_state.setdefault('route_tables', {}). \
                            setdefault(route_table_id, {})[dcidr] = buf


def _update_route(dcidr, router_ip, old_router_ip,
                  vpc_info, con, route_table_id, update_reason):
    """
    Update an existing route entry in the route table.

    """
    try:
        instance, eni = find_instance_and_eni_by_ip(vpc_info, router_ip)

        logging.info("--- updating existing route in RT '%s' "
                     "%s -> %s (%s, %s) (old IP: %s, reason: %s)" %
                     (route_table_id, dcidr, router_ip,
                      instance.id, eni.id, old_router_ip, update_reason))

        con.replace_route(
                    route_table_id         = route_table_id,
                    destination_cidr_block = dcidr,
                    instance_id            = instance.id,
                    interface_id           = eni.id)
        CURRENT_STATE.routes[dcidr] = \
                                    (router_ip, str(instance.id), str(eni.id))
    except Exception as e:
        msg = "*** failed to update route in RT '%s' %s -> %s (%s)" % \
              (route_table_id, dcidr, old_router_ip, e.message)
        update_reason += " [ERROR update route: %s]" % e.message
        logging.error(msg)

    _rt_state_update(route_table_id, dcidr, router_ip, instance.id, eni.id,
                     old_router_ip, update_reason)


def _add_new_route(dcidr, router_ip, vpc_info, con, route_table_id):
    """
    Add a new route to the route table.

    """
    try:
        instance, eni = find_instance_and_eni_by_ip(vpc_info, router_ip)

        logging.info("--- adding route in RT '%s' "
                     "%s -> %s (%s, %s)" %
                     (route_table_id, dcidr, router_ip, instance.id, eni.id))
        con.create_route(route_table_id         = route_table_id,
                         destination_cidr_block = dcidr,
                         instance_id            = instance.id,
                         interface_id           = eni.id)
        CURRENT_STATE.routes[dcidr] = \
                                    (router_ip, str(instance.id), str(eni.id))
        msg = "Added route"

    except Exception as e:
        logging.error("*** failed to add route in RT '%s' "
                      "%s -> %s (%s)" %
                      (route_table_id, dcidr, router_ip, e.message))
        msg = "[ERROR add route: %s]" % e.message

    _rt_state_update(route_table_id, dcidr, router_ip, instance.id, eni.id,
                     msg=msg)


def _get_real_instance_if_mismatch(vpc_info, ipaddr, instance, eni):
    """
    Return the real instance for the given IP address, if that instance is
    different than the passed in instance or has a different eni.

    If the ipaddr belongs to the same instance and eni that was passed in then
    this returns None.

    """
    # Careful! A route may be a black-hole route, which still has instance and
    # eni information for an instance that doesn't exist anymore. If a host was
    # terminated and a new host got the same IP then this route won't be
    # updated and will keep pointing to a non-existing node.  So we find the
    # instance by IP and check that the route really points to this instance.
    if ipaddr:
        real_instance, real_eni = \
                        find_instance_and_eni_by_ip(vpc_info, ipaddr)
        if real_instance.id != instance.id  or real_eni.id != eni.id:
            return real_instance
    return None


def _get_host_for_route(vpc_info, route, route_table, dcidr):
    """
    Given a specific route, return information about the instance to which it
    points.

    Need to take care of scenarios where the instance isn't set anymore in the
    route (the instance may have disappeared).

    """
    # The instance_id in the route may be None. We can get this in case of a
    # black-hole route.
    if route.instance_id:
        instance    = vpc_info['instance_by_id'][route.instance_id]
        inst_id     = instance.id if instance else "(unknown)"
        ipaddr, eni = get_instance_private_ip_from_route(instance, route)
        eni_id      = eni.id if eni else "(unknown)"

        # If route points to outdated instance, set ipaddr and eni to
        # None to signal that route needs to be updated
        real_instance = _get_real_instance_if_mismatch(
                                    vpc_info, ipaddr, instance, eni)
        if real_instance:
            logging.info("--- obsoleted route in RT '%s' "
                         "%s -> %s (%s, %s) (new instance with same "
                         "IP address should be used: %s)" %
                         (route_table.id, dcidr, ipaddr, instance.id, eni.id,
                          real_instance.id))
            # Setting the ipaddr and eni to None signals code further
            # down that the route must be updated.
            inst_id = eni_id = "(unknown)"
            ipaddr  = None

    else:
        # This route didn't point to an instance anymore, probably
        # a black hole route
        inst_id = eni_id = "(unknown)"
        ipaddr  = None
        logging.info("--- obsoleted route in RT '%s' "
                     "%s -> ... (doesn't point to instance anymore)" %
                     (route_table.id, dcidr))

    return inst_id, ipaddr, eni_id


def _update_existing_routes(route_spec, failed_ips, questionable_ips,
                            vpc_info, con, routes_in_rts):
    """
    Go over the existing routes and check whether they still match the spec.

    If the chosen router has failed or is questionable or is not in the host
    list anymore, the route needs to be updated. If the CIDR isn't in the spec
    at all anymore then it needs to be deleted.

    Keeps track of the routes we have seen in each RT and populates the
    passed-in routes_in_rts dictionary with that info.

    Returns a dict with the routers chosen for the various routes we
    encountered.

    """
    chosen_routers = {}              # keep track of chosen routers for CIDRs
    NONE_HEALTHY   = "none-healthy"  # used as marker in chosen_routers
    for rt in vpc_info['route_tables']:
        routes_in_rts[rt.id] = []
        # Iterate over all the routes we find in each RT
        for r in rt.routes:
            dcidr = r.destination_cidr_block
            if r.instance_id is None and r.interface_id is None:
                # There are some routes already present in the route table,
                # which we don't need to mess with. Specifically, routes that
                # aren't attached to a particular instance or interface.
                # We skip those.
                _rt_state_update(rt.id, dcidr,
                                 msg="Ignored: Not a route to an instance")
                continue

            routes_in_rts[rt.id].append(dcidr)  # remember we've seen the route

            hosts = route_spec.get(dcidr)       # eligible routers for CIDR

            # Current router host for this CIDR/route.
            inst_id, ipaddr, eni_id = \
                                _get_host_for_route(vpc_info, r, rt, dcidr)

            if not hosts:
                # The route isn't in the spec anymore and should be deleted.
                logging.info("--- route not in spec, deleting in RT '%s': "
                             "%s -> ... (%s, %s)" %
                             (rt.id, dcidr, inst_id, eni_id))
                con.delete_route(route_table_id         = rt.id,
                                 destination_cidr_block = dcidr)
                if dcidr in CURRENT_STATE.routes:
                    del CURRENT_STATE.routes[dcidr]

                continue

            # We have a route and it's still in the spec. Do we need to update
            # the router? Multiple reasons for that:
            # - Router is not in the list of eligible hosts anymore
            # - Router has failed or is questionable
            # - In a different route table we used a different host as the
            #   router.

            # Seen this route in another RT before? This will be None if we'be
            # not seen it before, and will be NONE_HEALTHY, but we couldn't
            # find a single healthy eligible router host for it.
            stored_router_ip = chosen_routers.get(dcidr)

            # Has our current router failed or is questionable?
            ipaddr_should_be_replaced = ipaddr in failed_ips or \
                                        ipaddr in questionable_ips

            # Is the host not eligible anymore?
            ipaddr_not_eligible = ipaddr not in hosts

            shouldnt_use_ipaddr = \
                            ipaddr_should_be_replaced or ipaddr_not_eligible

            if (not stored_router_ip or stored_router_ip == ipaddr) and \
                                                    not shouldnt_use_ipaddr:
                # Haven't seen it before, or points to same router AND
                # router is healthy: All good
                if not stored_router_ip:
                    # Remember this IP as a suitable router for CIDR
                    chosen_routers[dcidr] = ipaddr
                logging.info("--- route exists already in RT '%s': "
                             "%s -> %s (%s, %s)" %
                             (rt.id, dcidr,
                              ipaddr, inst_id, eni_id))
                CURRENT_STATE.routes[dcidr] = (ipaddr, inst_id, eni_id)
                _rt_state_update(rt.id, dcidr, ipaddr, inst_id, eni_id,
                                 msg="Current: Route exist and up to date")
                continue

            if stored_router_ip == NONE_HEALTHY:
                # We've tried to set a route for this before, but
                # couldn't find any health hosts. Can't do anything and
                # need to skip.
                CURRENT_STATE.routes[dcidr] = (ipaddr, inst_id, eni_id)
                _rt_state_update(rt.id, dcidr, ipaddr, inst_id, eni_id,
                                 msg="None healthy, black hole: "
                                     "Determined earlier")
                continue

            if stored_router_ip:
                # Just use the router we've seen before. We know that'll work,
                # because only healthy hosts make it into the chosen_routers
                # dict.
                new_router_ip = stored_router_ip
                update_reason = "other RT used different IP"
            else:
                # Haven't seen this route in another RT, so we'll
                # choose a new router
                new_router_ip = _choose_different_host(ipaddr, hosts,
                                                       failed_ips,
                                                       questionable_ips)
                if new_router_ip is None:
                    # Couldn't find healthy host to be router, forced
                    # to skip this one.
                    CURRENT_STATE.routes[dcidr] = (ipaddr, inst_id, eni_id)
                    chosen_routers[dcidr] = NONE_HEALTHY
                    logging.warning("--- cannot find available target "
                                    "for route update %s! "
                                    "Nothing I can do..." % (dcidr))
                    continue

                chosen_routers[dcidr] = new_router_ip
                update_reason = "old IP failed/questionable or " \
                                "not eligible anymore"

            _update_route(dcidr, new_router_ip, ipaddr,
                          vpc_info, con, rt.id, update_reason)

    return chosen_routers


def _add_missing_routes(route_spec, failed_ips, questionable_ips,
                        chosen_routers, vpc_info, con, routes_in_rts):
    """
    Iterate over route spec and add all the routes we haven't set yet.

    This relies on being told what routes we HAVE already. This is passed
    in via the routes_in_rts dict.

    Furthermore, some routes may be set in some RTs, but not in others. In that
    case, we may already have seen which router was chosen for a certain route.
    This information is passed in via the chosen_routers dict. We should choose
    routers that were used before.

    """
    for dcidr, hosts in route_spec.items():
        new_router_ip = chosen_routers.get(dcidr)
        # Look at the routes we have seen in each of the route tables.
        for rt_id, dcidr_list in routes_in_rts.items():
            if dcidr not in dcidr_list:
                if not new_router_ip:
                    # We haven't chosen a target host for this CIDR.
                    new_router_ip = _choose_different_host(None, hosts,
                                                           failed_ips,
                                                           questionable_ips)
                    if not new_router_ip:
                        logging.warning("--- cannot find available target "
                                        "for route addition %s! "
                                        "Nothing I can do..." % (dcidr))
                        # Skipping the check on any further RT, breaking out to
                        # outer most loop over route spec
                        break
                _add_new_route(dcidr, new_router_ip, vpc_info, con, rt_id)


def process_route_spec_config(con, vpc_info, route_spec,
                              failed_ips, questionable_ips):
    """
    Look through the route spec and update routes accordingly.

    Idea: Make sure we have a route for each CIDR.

    If we have a route to any of the IP addresses for a given CIDR then we are
    good. Otherwise, pick one (usually the first) IP and create a route to that
    IP.

    If a route points at a failed or questionable IP then a new candidate is
    chosen, if possible.

    """
    if CURRENT_STATE._stop_all:
        logging.debug("Routespec processing. Stop requested, abort operation")
        return

    if failed_ips:
        logging.debug("Route spec processing. Failed IPs: %s" %
                      ",".join(failed_ips))
    else:
        logging.debug("Route spec processing. No failed IPs.")

    # Iterate over all the routes in the VPC, check they are contained in
    # the spec, update the routes as needed.

    # Need to remember the routes we saw in different RTs, so that we can later
    # add them, if needed.
    routes_in_rts  = {}

    CURRENT_STATE.vpc_state.setdefault("time",
                                       datetime.datetime.now().isoformat())

    # Passed through the functions and filled in, state accumulates information
    # about all the routes we encounted in the VPC and what we are doing with
    # them. This is then available in the CURRENT_STATE
    chosen_routers = _update_existing_routes(route_spec,
                                             failed_ips, questionable_ips,
                                             vpc_info, con, routes_in_rts)

    # Now go over all the routes in the spec and add those that aren't in VPC,
    # yet.
    _add_missing_routes(route_spec, failed_ips, questionable_ips,
                        chosen_routers,
                        vpc_info, con, routes_in_rts)


def handle_spec(region_name, vpc_id, route_spec, failed_ips, questionable_ips):
    """
    Connect to region and update routes according to route spec.

    """
    if CURRENT_STATE._stop_all:
        logging.debug("handle_spec: Stop requested, abort operation")
        return

    if not route_spec:
        logging.debug("handle_spec: No route spec provided")
        return

    logging.debug("Handle route spec")

    try:
        con      = connect_to_region(region_name)
        vpc_info = get_vpc_overview(con, vpc_id, region_name)
        process_route_spec_config(con, vpc_info, route_spec,
                                  failed_ips, questionable_ips)
        con.close()
    except boto.exception.StandardError as e:
        logging.warning("vpc-router could not set route: %s - %s" %
                        (e.message, e.args))
        raise

    except boto.exception.NoAuthHandlerFound:
        logging.error("vpc-router could not authenticate")
