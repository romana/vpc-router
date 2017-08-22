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
# Unit tests for the built-in http server module
#

import json
import requests
import unittest

from vpcrouter.main import http_server


class TestHttpServer(unittest.TestCase):

    def setUp(self):
        self.conf   = {
            "port" : 33445,
            "addr" : "127.0.0.1"
        }
        self.server = http_server.VpcRouterHttpServer(self.conf)

        self.addCleanup(self.cleanup)

    def cleanup(self):
        self.server.stop()

    def test_connec(self):
        r = requests.get("http://localhost:33445")
        d = json.loads(r.content)
        self.assertEqual(d['params'], {})
        self.assertEqual(d['plugins'], {'_href': '/plugins'})
        self.assertEqual(d['route_info'], {'_href': '/route_info'})
        self.assertEqual(d['ips'], {'_href': '/ips'})
