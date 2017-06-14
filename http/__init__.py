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
# Functions for HTTP request handling in daemon mode
#

import json

from errors import ArgsError, VpcRouteSetError
from utils  import ip_check
from vpc    import handle_request

from bottle import route, run, request, response

_REGION_NAME = None
_VPC_ID      = None
_SERVER_PORT = None
_SERVER_ADDR = None

def _get_route_params(req, from_body=False):
    """
    Extracts and checks dst_cidr and optional router_ip parameters from
    request URL.

    """
    if from_body:
        try:
            params = json.loads(req.body.read())
        except Exception:
            raise ArgsError("Malformed request body")

    else:
        params = request.query

    dst_cidr  = params['dst_cidr']
    ip_check(dst_cidr, netmask_expected=True)

    router_ip = params.get('router_ip')
    if router_ip:
        ip_check(router_ip)

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
    cmd = {
            "GET"    : "show",
            "DELETE" : "del",
            "POST"   : "add"
          }[request.method]

    try:

        from_body = (cmd == "add")  # Flag is True for POST
        dst_cidr, router_ip = _get_route_params(request, from_body)

        if cmd == "add":
            if not router_ip:
                raise KeyError("router_ip")
        else:
            if router_ip:
                raise ArgsError("Illegal parameter 'router_ip' for operation")

        msg, found = handle_request(_REGION_NAME, _VPC_ID,
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

    except ArgsError as e:
        response.status = 400
        return e.message

    except VpcRouteSetError as e:
        response.status = 500
        return e.message


def start_daemon_with_http_api(srv_addr, srv_port, aws_region, vpc_id):
    """
    Start the VPC router as daemon that listens for commands on network port.

    Offers a REST 'inspired' interface.

    """
    global _SERVER_ADDR, _SERVER_PORT, _REGION_NAME, _VPC_ID

    _SERVER_ADDR = srv_addr
    _SERVER_PORT = srv_port
    _REGION_NAME = aws_region
    _VPC_ID      = vpc_id

    run(host=_SERVER_ADDR, port=_SERVER_PORT, debug=True)



