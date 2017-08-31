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


class StateError(Exception):
    pass


class _CurrentState(object):
    """
    Holds the current state of the system.

    We use this for some communication between modules, but mostly to be able
    to render some output of the current system state.

    """
    def __init__(self):
        self.starttime        = datetime.datetime.now()
        self.versions         = ""
        self.plugins          = []
        self.failed_ips       = []
        self.questionable_ips = []
        self.working_set      = []
        self.route_spec       = {}
        self.routes           = {}
        self.vpc_state        = {}
        self.conf             = None
        self.main_param_names = []
        self._vpc_router_http = None
        self._stop_all        = False

        # The following top-level items are rendered as links and can be
        # accessed with separate requests.
        self.top_level_links  = ["", "ips", "plugins", "route_info", "vpc"]

    def add_plugin(self, plugin):
        """
        Every plugin (watcher and health) is added so we can later get live
        info from each plugin.

        """
        self.plugins.append(plugin)

    def get_plugins_info(self):
        """
        Collect the current live info from all the registered plugins.

        Return a dictionary, keyed on the plugin name.

        """
        d = {}
        for p in self.plugins:
            d.update(p.get_info())
        return d

    def render_main_params(self):
        """
        Return names and values for the main parameters (not the plugin
        parameters).

        """
        return {n: self.conf[n] for n in self.main_param_names}

    def get_state_repr(self, path):
        """
        Returns the current state, or sub-state, depending on the path.

        """
        if path == "ips":
            return {
                "failed_ips"       : self.failed_ips,
                "questionable_ips" : self.questionable_ips,
                "working_set"      : self.working_set,
            }

        if path == "route_info":
            return {
                "route_spec" : self.route_spec,
                "routes"     : self.routes,
            }

        if path == "plugins":
            return self.get_plugins_info()

        if path == "vpc":
            return self.vpc_state

        if path == "":
            return {
                "SERVER"           : {
                    "version"      : self.versions,
                    "start_time"   : self.starttime.isoformat(),
                    "current_time" : datetime.datetime.now().isoformat()
                },
                "params"     : self.render_main_params(),
                "plugins"    : {"_href" : "/plugins"},
                "ips"        : {"_href" : "/ips"},
                "route_info" : {"_href" : "/route_info"},
                "vpc"        : {"_href" : "/vpc"}
            }

    def as_json(self, path="", with_indent=False):
        """
        Return a rendering of the current state in JSON.

        """
        if path not in self.top_level_links:
            raise StateError("Unknown path")

        return json.dumps(self.get_state_repr(path),
                          indent=4 if with_indent else None)

    def as_html(self, path=""):
        """
        Return a rendering of the current state in HTML.

        """
        if path not in self.top_level_links:
            raise StateError("Unknown path")

        header = """
        <html>
            <head>
                <title>VPC-router state</title>
            </head>
            <body>
                <h3>VPC-router state</h3>
                <hr>
                <font face="courier">
        """

        footer = """
                </font>
            </body>
        </html>
        """

        rep = self.get_state_repr(path)

        def make_links(rep):
            # Recursively create clickable links for _href elements
            for e, v in rep.items():
                if e == "_href":
                    v = '<a href=%s>%s</a>' % (v, v)
                    rep[e] = v
                else:
                    if type(v) == dict:
                        make_links(v)

        make_links(rep)

        rep_str_lines = json.dumps(rep, indent=4).split("\n")
        buf = []
        for l in rep_str_lines:
            # Replace leading spaces with '&nbsp;'
            num_spaces = len(l) - len(l.lstrip())
            l = "&nbsp;" * num_spaces + l[num_spaces:]
            buf.append(l)

        return "%s%s%s" % (header, "<br>\n".join(buf), footer)


# The module doesn't get reloaded, so no need to check, can just initialize
CURRENT_STATE = _CurrentState()
