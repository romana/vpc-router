#!/usr/bin/env python

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

import sys

from args    import parse_args
from errors  import ArgsError, VpcRouteSetError
from http    import start_daemon_with_http_api
from vpc     import handle_request
from watcher import start_daemon_as_watcher


if __name__ == "__main__":
    try:
        conf = parse_args()
        if conf['daemon']:
            start_daemon_with_http_api(conf['addr'], conf['port'],
                                       conf['region_name'], conf['vpc_id'])
        elif conf['watcher']:
            start_daemon_as_watcher(conf['vpc_id'], conf['file'])
        else:
            # One off run from the command line
            msg, found = handle_request(
                conf['region_name'], conf['vpc_id'], conf['command'],
                conf['router_ip'], conf['dst_cidr'], conf['daemon'])
            if found:
                sys.exit(0)
            else:
                sys.exit(1)
    except ArgsError as e:
        print "\n*** Error: %s\n" % e.message
    except VpcRouteSetError as e:
        print "\n*** Error: %s\n" % e.message
    sys.exit(1)

