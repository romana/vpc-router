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
# Functions to load and manage vpcrouter plugins.
#


import importlib


from vpcrouter.errors  import PluginError


def load_plugin(plugin_name, default_plugin_module):
    """
    Load a plugin plugin.

    Supports loading of plugins that are part of the vpcrouter, as well as
    external plugins: If the plugin name has a dotted notation then it
    assumes it's an external plugin and the dotted notation is the complete
    import path. If it's just a single word then it looks for the plugin in
    the specified default module.

    Return the plugin class.

    """
    try:
        if "." in plugin_name:
            # Assume external plugin, full path
            plugin_mod_name   = plugin_name
            plugin_class_name = plugin_name.split(".")[-1].capitalize()
        else:
            # One of the built-in plugins
            plugin_mod_name   = "%s.%s" % (default_plugin_module, plugin_name)
            plugin_class_name = plugin_name.capitalize()

        plugin_mod        = importlib.import_module(plugin_mod_name)
        plugin_class      = getattr(plugin_mod, plugin_class_name)
        return plugin_class
    except ImportError as e:
        raise PluginError("Cannot load '%s'" % plugin_mod_name)
    except AttributeError:
        raise PluginError("Cannot find plugin class '%s' in "
                          "plugin '%s'" %
                          (plugin_class_name, plugin_mod_name))
    except Exception as e:
        raise PluginError("Error while loading plugin '%s': %s" %
                          (plugin_mod_name, str(e)))
