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
# Exceptions for the VPC router.
#


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


class PluginError(_Exception):
    """
    Errors while loading plugins.

    """
    pass
