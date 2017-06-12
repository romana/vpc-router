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
import json
import netaddr
import boto.vpc
import argparse

from bottle import route, run, request, response


# Some parameters needed for daemon mode operation
REGION_NAME = None
VPC_ID      = None
SERVER_PORT = None
SERVER_ADDR = None


class _Exception(Exception):
    """
    Base class for my exceptions, which allows me to use the message attribute.

    """
    def __init__(self, message, *args):
        self.message = message
        super(_Exception, self).__init__(message, *args)


class VpcRouteSetError(_Exception):
    """
    Exception during route setting operations.

    """
    pass


class ArgsError(_Exception):
    """
    Missing or malformed parameters and arguments.

    """
    pass


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
    Parse command line arguments and returns relevant values in a dict.

    Also performs basic sanity checking on some arguments.

    """
    conf = {}
    # Setting up the command line argument parser
    parser = argparse.ArgumentParser(
        description="VPC router: Set routes in VPC route table")
    parser.add_argument('-d', '--daemon', dest='daemon', action='store_true',
                        help="start as daemon, wait for commands via network")
    parser.add_argument('-v', '--vpc', dest="vpc_id", required=True,
                        help="the ID of the VPC in which to operate")
    parser.add_argument('-a', '--address', dest="listen_addr",
                        default="localhost",
                        help="address to listen on for commands "
                             "(only daemon mode)")
    parser.add_argument('-p', '--port', dest="listen_port", default="33289",
                        type=int,
                        help="port to listen on for commands "
                             "(only daemon mode)")
    parser.add_argument('-c', '--cmd', dest="command",
                        help="either 'show', 'add' or 'del' (default: 'show')")
    parser.add_argument('-r', '--region', dest="region",
                        default="ap-southeast-2",
                        help="the AWS region of the VPC")
    parser.add_argument('-C', '--CIDR', dest="dst_cidr",
                        help="the destination CIDR of the route")
    parser.add_argument('-i', '--ip', dest="router_ip",
                        help="the IP address of the routing instance")
    args = parser.parse_args()
    conf['vpc_id']      = args.vpc_id
    conf['region_name'] = args.region
    conf['command']     = args.command
    conf['dst_cidr']    = args.dst_cidr
    conf['router_ip']   = args.router_ip
    conf['daemon']      = args.daemon
    conf['port']        = args.listen_port
    conf['addr']        = args.listen_addr

    # Sanity checking of arguments
    try:
        if conf['daemon']:
            # Sanity checks if started in daemon mode
            if not 0 < conf['port'] < 65535:
                raise ArgsError("Invalid listen port '%d' for daemon mode." %
                                conf['port'])
            if not conf['addr'] == "localhost":
                # maybe a proper address was specified?
                try:
                    _ip_check(conf['addr'])
                except netaddr.core.AddrFormatError:
                    raise ArgsError("Format error for server listen address.")

        else:
            # Sanity check if started with command line arguments
            if conf['command'] not in [ 'add', 'del', 'show' ]:
                raise ArgsError("Only commands 'add', 'del' or 'show' are "
                                "allowed (not '%s')." % conf['command'])
            if not conf['dst_cidr']:
                raise ArgsError("Destination CIDR argument missing.")
            if not conf['router_ip']:
                raise ArgsError("Router IP address argument missing.")

            cidr_check_passed = False
            try:
                _ip_check(conf['dst_cidr'], netmask_expected=True)
                cidr_check_passed = True
                _ip_check(conf['router_ip'])
            except netaddr.core.AddrFormatError:
                if cidr_check_passed:
                    raise ArgsError("Format error for router IP address.")
                else:
                    raise ArgsError("Format error for destination CIDR.")

    except ArgsError as e:
        parser.print_help()
        raise e

    return conf


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

    The specific command, destination CIDR and IP address are contained
    in the config.

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
        msg.append("%s route: %s -> %s (%s, %s)" %
                   (cmd_str[cmd], cidr, ip, instance.id, eni.id))
    for rt in vpc_info['route_tables']:
        found_in_rt = False
        for r in rt.routes:
            if r.interface_id == eni.id and r.destination_cidr_block == cidr:
                found_in_rt = True
                if cmd == "show":
                    msg.append("--- route exists in RT '%s'" % rt.id)
                elif cmd == "del":
                    msg.append("--- deleting route in RT '%s'" % rt.id)
                    con.delete_route(route_table_id         = rt.id,
                                     destination_cidr_block = cidr)
                elif cmd == "add":
                    msg.append("--- route exists already in RT '%s'" % rt.id)
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
    con           = connect_to_region(region_name)
    vpc_info      = get_vpc_overview(con, vpc_id, region_name)
    instance, eni = find_instance_and_emi_by_ip(vpc_info, router_ip, daemon)
    msgs, found   = manage_route(con, vpc_info, instance, eni,
                                 cmd, router_ip, dst_cidr, daemon)
    con.close()

    if not daemon:
        for m in msgs:
            print m

    return msgs, found


#
# Functions for request handling in daemon mode
#

def _get_route_params(req, from_body=False):
    """
    Extracts and checks dst_cidr and router_ip parameters from request URL.

    """
    if from_body:
        try:
            params = json.loads(req.body.read())
        except Exception:
            raise ArgsError("Malformed request body")

    else:
        params = request.query

    dst_cidr  = params['dst_cidr']
    router_ip = params['router_ip']

    _ip_check(dst_cidr, netmask_expected=True)
    _ip_check(router_ip)

    return dst_cidr, router_ip


@route('/route', method='GET')
@route('/route', method='DELETE')
@route('/route', method='POST')
def handle_api_request():
    """
    Show, add or delete specified route.

    For GET and DELETE requests the URL the parameters 'dst_cidr' and
    'router_ip' need to be defined.

    For example:

        ..../route?dst_cidr=10.55.0.0/16&router_ip=10.33.20.142

    For a POST request those parameters need to be contained in the request
    body as JSON.

    For example:

        { "dst_cidr" : "10.55.0.0/16", "router_ip" : "10.33.20.142" }

    """
    cmd = { "GET"    : "show",
            "DELETE" : "del",
            "POST"   : "add"
    }[request.method]

    try:

        from_body = (cmd == "add")  # Flag is True for POST
        dst_cidr, router_ip = _get_route_params(request, from_body)

        msg, found = handle_request(REGION_NAME, VPC_ID,
                                    cmd, router_ip, dst_cidr, True)

        if found:
            response.status   = 200
        else:
            response.status   = 404
        response.content_type = 'application/json'
        return json.dumps(msg)

    except KeyError as e:
        response.status = 400
        return "Missing parameter: '%s'" % e.message

    except netaddr.core.AddrFormatError:
        response.status = 400
        return "Format error for IP address or mask"

    except ArgsError as e:
        response.status = 400
        return e.message

    except VpcRouteSetError as e:
        response.status = 500
        return e.message

    except boto.exception.StandardError as e:
        response.status = 500
        return "*** Error: AWS API: " + e.message

    except boto.exception.NoAuthHandlerFound:
        response.status = 500
        return "*** Error: AWS API: vpc-router could not authenticate"


def start_as_daemon():
    """
    Start the VPC route setter as daemon that listens for commands on port.

    Offers a REST 'inspired' interface.

    """
    run(host=SERVER_ADDR, port=SERVER_PORT, debug=True)


if __name__ == "__main__":
    try:
        conf = parse_args()
        if conf['daemon']:
            REGION_NAME = conf['region_name']
            VPC_ID      = conf['vpc_id']
            SERVER_PORT = conf['port']
            SERVER_ADDR = conf['addr']
            start_as_daemon()
        else:
            # One off run from the command line
            msg, found = handle_request(
                conf['region_name'], conf['vpc_id'], conf['command'],
                conf['router_ip'], conf['dst_cidr'], conf['daemon'])
            if found:
                sys.exit(0)
            else:
                sys.exit(1)
    except ArgsError as e:
        print "\n*** Error: %s\n" % e.message
    except VpcRouteSetError as e:
        print "\n*** Error: %s\n" % e.message
    except boto.exception.EC2ResponseError as e:
        print "\n*** Error AWS API: %s\n" % e.message
    sys.exit(1)


