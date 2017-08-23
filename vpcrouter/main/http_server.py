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
# Built-in HTTP server of vpc-router. Gives access to real-time stats
# and information about the state of vpc-router.
#

import bottle
import logging
import socket
import threading
import time

from functools import wraps

from vpcrouter.currentstate import CURRENT_STATE, StateError


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

    def __init__(self, *args, **kwargs):
        if 'romana_http' in kwargs:
            self.romana_http = kwargs['romana_http']
            del kwargs['romana_http']
        super(MyWSGIRefServer, self).__init__(*args, **kwargs)

    def run(self, handler):
        from wsgiref.simple_server import make_server, WSGIRequestHandler
        if self.quiet:
            class QuietHandler(WSGIRequestHandler):
                def log_request(*args, **kw):
                    pass
            self.options['handler_class'] = QuietHandler
        try:
            self.server = make_server(self.host, self.port, handler,
                                      **self.options)
            self.romana_http.wsgi_server_started = True
            logging.info("HTTP server: Started to listen...")
            self.server.serve_forever()
        except socket.error as e:
            logging.fatal("HTTP server: Cannot open socket "
                          "(error %d: %s)... " %
                          (e.errno, e.strerror))

    def stop(self):
        if self.server:
            self.server.shutdown()


def handle_request(path):
    """
    Return the current status.

    """
    accept = bottle.request.get_header("accept", default="text/plain")

    bottle.response.status = 200

    try:
        if "text/html" in accept:
            ret = CURRENT_STATE.as_html(path=path)
            bottle.response.content_type = "text/html"

        elif "application/json" in accept:
            ret = CURRENT_STATE.as_json(path=path)
            bottle.response.content_type = "application/json"

        elif "text/" in accept or "*/*" in accept:
            ret = CURRENT_STATE.as_json(path=path, with_indent=True)
            bottle.response.content_type = "text/plain"

        else:
            bottle.response.status = 407
            ret = "Cannot render data in acceptable content type"
    except StateError:
        bottle.response.status = 404
        ret = "Requested state component not found"

    return ret


@APP.route('/', method='GET')
def handle_root_request():
    return handle_request("")


@APP.route('/ips', method='GET')
def handle_ips_request():
    return handle_request("ips")


@APP.route('/plugins', method='GET')
def handle_plugins_request():
    return handle_request("plugins")


@APP.route('/route_info', method='GET')
def handle_route_info_request():
    return handle_request("route_info")


@APP.route('/vpc', method='GET')
def handle_route_vpc_request():
    return handle_request("vpc")


class VpcRouterHttpServer(object):
    """
    Implements a simple HTTP request handler to get information about current
    state of the VPC router.

    Starts an HTTP handler thread.

    """
    def __init__(self, conf):
        """
        Start the HTTP server thread.

        """
        self.conf                = conf
        self.wsgi_server_started = False
        self.start()

    def start(self):
        """
        Start the HTTP server thread.

        """
        logging.info("HTTP server: "
                     "Starting to listen for requests on '%s:%s'..." %
                     (self.conf['addr'], self.conf['port']))

        self.my_server = MyWSGIRefServer(host=self.conf['addr'],
                                         port=self.conf['port'],
                                         romana_http=self)

        self.http_thread = threading.Thread(
                    target = APP.run,
                    name   = "HTTP",
                    kwargs = {"quiet" : True, "server" : self.my_server})

        self.http_thread.daemon = True
        self.http_thread.start()
        time.sleep(1)
        if not self.wsgi_server_started:
            # Set the global flag indicating that everything should stop
            CURRENT_STATE._stop_all = True

    def stop(self):
        """
        Stop the HTTP server thread.

        """
        self.my_server.stop()
        self.http_thread.join()
        logging.info("HTTP server: Stopped")
