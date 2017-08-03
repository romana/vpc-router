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
# HTTP plugin: Get route specs via HTTP interface.
# Starts a small Bottle app for this purpose.
#

import bottle
import json
import logging
import threading
import time

from functools import wraps

from vpcrouter              import utils
from vpcrouter.errors       import ArgsError
from vpcrouter.watcher      import common
from vpcrouter.currentstate import CURRENT_STATE


# Need the queue available inside of the request handler functions. There
# doesn't seem to be a decent way to pass additional parameters to the Bottle
# request handlers, so we made this one global.
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
                def log_request(*args, **kw):
                    pass
            self.options['handler_class'] = QuietHandler
        self.server = make_server(self.host, self.port, handler,
                                  **self.options)
        self.server.serve_forever()

    def stop(self):
        self.server.shutdown()


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
    return json.dumps({"time" : time.time(),
                       "state" : CURRENT_STATE})


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
            data = CURRENT_STATE['route_spec']
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


class Http(common.WatcherPlugin):
    """
    Implements the WatcherPlugin interface for the 'http' plugin.

    Start a Bottle application thread, which serves a minimal HTTP interface
    to set route specs or enquire about the status.

    This plugin adds two command line arguments to vpc-router:

    -a / --address: The listen address for the HTTP server.
    -p / --port:    The listen port for the HTTP server.

    """
    def start(self):
        """
        Start the HTTP change monitoring thread.

        """
        # Store reference to message queue in module global variable, so that
        # our Bottla app handler functions have easy access to it.
        global _Q_ROUTE_SPEC
        _Q_ROUTE_SPEC = self.q_route_spec

        logging.info("Http watcher plugin: "
                     "Starting to watch for route spec on '%s:%s'..." %
                     (self.conf['addr'], self.conf['port']))

        self.my_server = MyWSGIRefServer(host=self.conf['addr'],
                                         port=self.conf['port'])

        self.http_thread = threading.Thread(
                    target = APP.run,
                    name   = "HttpMon",
                    kwargs = {"quiet" : True, "server" : self.my_server})

        self.http_thread.daemon = True
        self.http_thread.start()

    def stop(self):
        """
        Stop the config change monitoring thread.

        """
        self.my_server.stop()
        self.http_thread.join()
        logging.info("Http watcher plugin: Stopped")

    @classmethod
    def add_arguments(cls, parser, sys_arg_list=None):
        """
        Add arguments for the http mode to the argument parser.

        """
        parser.add_argument('-a', '--address', dest="addr",
                            default="localhost",
                            help="address to listen on for commands "
                                 "(only in http mode, default: localhost)")
        parser.add_argument('-p', '--port', dest="port",
                            default="33289", type=int,
                            help="port to listen on for commands "
                                 "(only in http mode, default: 33289)")
        return ["addr", "port"]

    @classmethod
    def check_arguments(cls, conf):
        """
        Sanity check arguments needed for http mode.

        """
        if not 0 < conf['port'] < 65535:
            raise ArgsError("Invalid listen port '%d' for http mode." %
                            conf['port'])
        if not conf['addr'] == "localhost":
            # Check if a proper address was specified
            utils.ip_check(conf['addr'])
