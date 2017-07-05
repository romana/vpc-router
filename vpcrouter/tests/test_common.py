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
# Code used by different tests
#

from logging import Filter


class MyLogCaptureFilter(Filter):
    """
    Custom capture class for log messages.

    We use log capture in several tests and need a way to get just our messages
    and discard log messages from 3rd party packages.

    """
    def filter(self, record):
        if record.name != "root":
            return 0
        else:
            return 1
