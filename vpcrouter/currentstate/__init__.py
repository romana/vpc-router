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

# Global data/state shared between modules. This includes some rendering
# options, since we produce output via the http module.

import datetime
import json


class _CurrentState(object):
    """
    Holds the current state of the system.

    We use this for some communication between modules, but mostly to be able
    to render some output of the current system state.

    """
    def __init__(self):
        self.starttime        = datetime.datetime.now()
        self.versions         = ""
        self.plugins          = {}
        self.failed_ips       = []
        self.working_set      = []
        self.route_spec       = {}
        self.routes           = {}
        self.conf             = None
        self.main_param_names = []
        self._vpc_router_http = None

    def add_plugin_info(self, plugin_info):
        """
        Called for every plugin (watcher or health), so we can show information
        about each plugin in the output as well.

        The content of this information is up to the plugin, but by convention
        it's a dictionary with the plugin name as a single key and a further
        dictionary as value, which contains the plugin version and all plugin
        specific parameters.

        """
        self.plugins.update(plugin_info)

    def render_main_params(self):
        """
        Return names and values for the main parameters (not the plugin
        parameters).

        """
        return {n: self.conf[n] for n in self.main_param_names}

    def as_json(self, with_indent=False):
        return json.dumps(
                {
                    "SERVER"             : {
                        "version"        : self.versions,
                        "start_time"     : self.starttime.isoformat(),
                        "current_time"   : datetime.datetime.now().isoformat()
                    },
                    "params" : self.render_main_params(),
                    "plugins"            : self.plugins,
                    "ips"                : {
                        "failed_ips"     : self.failed_ips,
                        "working_set"    : self.working_set,
                    },
                    "route_info"         : {
                        "route_spec"     : self.route_spec,
                        "routes"         : self.routes,
                    }
                }, indent=4 if with_indent else None)


# The module doesn't get reloaded, so no need to check, can just initialize
CURRENT_STATE = _CurrentState()
