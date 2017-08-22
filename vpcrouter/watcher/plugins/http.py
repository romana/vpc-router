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
# This simply extends the bottle app that we have already created for the http
# interface of the vpc-router.
#

import bottle
import json
import logging

from vpcrouter.watcher          import common
from vpcrouter.currentstate     import CURRENT_STATE
from vpcrouter.main.http_server import APP   # The bottle app of the vpc-router


# Need the queue available inside of the request handler functions. There
# doesn't seem to be a decent way to pass additional parameters to the Bottle
# request handlers, so we made this one global.
_Q_ROUTE_SPEC = None


# The http plugin is only imported on demand. Since there is only one Bottle
# app in the entire system, we can just add to the app when we are imported.

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
            data = CURRENT_STATE.route_spec
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

    Adds a minimal HTTP interface to set route specs.

    """
    def start(self):
        """
        Start the HTTP change monitoring thread.

        """
        # Store reference to message queue in module global variable, so that
        # our Bottle app handler functions have easy access to it.
        global _Q_ROUTE_SPEC
        _Q_ROUTE_SPEC = self.q_route_spec

        logging.info("Http watcher plugin: "
                     "Starting to watch for route spec on "
                     "'%s:%s/route_spec'..." %
                     (self.conf['addr'], self.conf['port']))

    def stop(self):
        """
        Stop the config change monitoring thread.

        """
        logging.info("Http watcher plugin: Stopped")

    def get_info(self):
        """
        Return plugin information.

        """
        return {
            self.get_plugin_name() : {
                "version" : self.get_version(),
                "params" : {
                }
            }
        }
