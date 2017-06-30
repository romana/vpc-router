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
# Functions for HTTP request handling
#

import bottle
import json
import logging
import Queue
import threading
import time

from functools import wraps

from . import common


# Need the queue available inside of the request handler functions.
_Q_ROUTE_SPEC = None


# Need to direct Bottle's logs to our standard logger. In the time honoured
# tradition of developers everywhere, Google let to StackOverflow.
# Specifically this here:
#
#     https://stackoverflow.com/a/31093434/7242672
#
# Thank you to StackOverflow user 'ron.rothman'.

logger = logging.getLogger('__root__')

def log_to_logger(fn):
    """
    Wrap a Bottle request so that a log line is emitted after it's handled.

    """
    @wraps(fn)
    def _log_to_logger(*args, **kwargs):
        actual_response = fn(*args, **kwargs)
        # modify this to log exactly what you need:
        logger.info('%s %s %s %s' % (bottle.request.remote_addr,
                                     bottle.request.method,
                                     bottle.request.url,
                                     bottle.response.status))
        return actual_response
    return _log_to_logger

APP = bottle.Bottle()
APP.install(log_to_logger)


# Need to be able to shut down the bottle server thread, but no stop method was
# offered. Found this solution: https://stackoverflow.com/a/16056443/7242672
#
# Thank you to StackOverflow user 'mike'.
class MyWSGIRefServer(bottle.ServerAdapter):
    server = None

    def run(self, handler):
        from wsgiref.simple_server import make_server, WSGIRequestHandler
        if self.quiet:
            class QuietHandler(WSGIRequestHandler):
                def log_request(*args, **kw): pass
            self.options['handler_class'] = QuietHandler
        self.server = make_server(self.host, self.port, handler,
                                  **self.options)
        self.server.serve_forever()

    def stop(self):
        self.server.shutdown()


'''
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
'''

@APP.route('/', method='GET')
def handle_root_request():
    """
    Start page with URLs for further resources.

    """
    bottle.response.status        = 200
    bottle.response.content_type = 'application/json'
    return json.dumps({
        "Posting and retrieving current route spec" : "/route_spec",
        "Current status" : "/status"
    })


@APP.route('/status', method='GET')
def handle_status_request():
    """
    Return the current status.

    """
    bottle.response.status        = 200
    bottle.response.content_type = 'application/json'
    return json.dumps({ "time" : time.time(),
                        "state" : common.CURRENT_STATE })


@APP.route('/route_spec', method='GET')
@APP.route('/route_spec', method='POST')
def handle_route_spec_request():
    """
    Process request for route spec.

    Either a new one is posted or the current one is to be retrieved.

    """
    try:
        if bottle.request.method == 'GET':
            # Just return what we currenty have cached as the route spec
            data = common.CURRENT_STATE['route_spec']
            if not data:
                bottle.response.status = 404
                msg = "Route spec not found!"
            else:
                bottle.response.status = 200
                msg = json.dumps(data)
        else:
            # A new route spec is posted
            raw_data = bottle.request.body.read()
            new_route_spec = json.loads(raw_data)
            logging.info("New route spec posted")
            common.parse_route_spec_config(new_route_spec)
            _Q_ROUTE_SPEC.put(new_route_spec)
            bottle.response.status = 200
            msg = "Ok"

    except ValueError as e:
        logging.error("Config ignored: %s" % str(e))
        bottle.response.status = 400
        msg = "Config ignored: %s" % str(e)

    except Exception as e:
        logging.error("Exception while processing HTTP request: %s" % str(e))
        bottle.response.status = 500
        msg = "Internal server error"

    bottle.response.content_type = 'application/json'
    return msg


def start_config_receiver_thread(srv_addr, srv_port, aws_region, vpc_id):
    """
    Listen on an HTTP server port for new route specs.

    """
    global _Q_ROUTE_SPEC
    _Q_ROUTE_SPEC = Queue.Queue()
    logging.info("Starting to watch for route spec on '%s:%s'..." %
                 (srv_addr, srv_port))

    my_server = MyWSGIRefServer(host=srv_addr, port=srv_port)

    http_thread = threading.Thread(target = APP.run,
                                   name   = "HttpMon",
                                   kwargs = { "quiet"  : True,
                                              "server" : my_server
                                            })

    # Add a stop method to our thread, which then calls our server's stop
    # method.
    def stop_server(*args, **kwargs):
        my_server.stop()
    http_thread.stop = stop_server

    http_thread.daemon = True
    http_thread.start()

    # Return the thread and the two queues to the caller
    return (http_thread, _Q_ROUTE_SPEC)


