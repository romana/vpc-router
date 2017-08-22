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
# Unit tests for the main module
#

import sys
import unittest

from StringIO import StringIO

import vpcrouter.main as main

from vpcrouter.errors import ArgsError


class TestArgs(unittest.TestCase):
    """
    Tests argument parsing.

    These tests are bit funny, since they capture stdout.

    """
    def setUp(self):
        self.saved_stdout = sys.stdout
        self.saved_stderr = sys.stderr
        self.addCleanup(self.cleanup)

    def cleanup(self):
        sys.stdout = self.saved_stdout
        sys.stderr = self.saved_stderr

    def get_last_line(self, lines):
        return lines.split("\n")[-1]

    def prnt(self, text):
        # Allows me to print something to stdout during development
        self.saved_stdout.write(text + "\n")

    def test_parse_args(self):
        inp = [
            {"args" : ['-h'],
             "exc" : SystemExit, "out" : "0"},
            {"args" : ['-l'],
             "exc" : SystemExit, "out" : "2"},
            {"args" : ['-l', 'foo'],
             "exc" : SystemExit, "out" : "2"},
            {"args" : ['-l', 'foo', '-v', '123'],
             "exc" : SystemExit, "out" : "2"},
            {"args" : ['-l', 'foo', '-v', '123', '-r', 'foo', '-m', 'http'],
             "exc" : None, "watcher_plugin" : "http",
             "conf" : {
                 'verbose': False, 'addr': 'localhost', 'mode': 'http',
                 'vpc_id': '123', 'logfile': 'foo', 'health' : 'icmpecho',
                 'icmp_check_interval' : 2.0, 'port': 33289,
                 'route_recheck_interval' : 30,
                 'region_name': 'foo'}},
            {"args" : ['-l', 'foo', '-v', '123', '-r', 'foo',
                       '-m', 'configfile'],
             "watcher_plugin" : "configfile",
             "exc" : SystemExit, "out" : "2"},
            {"args" : ['-l', 'foo', '-v', '123', '-r', 'foo',
                       '-m', 'configfile',
                       '-f', "/_does_not_exists"],
             "exc" : ArgsError, "watcher_plugin" : "configfile",
             "out" : "Cannot open config file"},
            {"args" : ['-l', 'foo', '-v', '123', '-r', 'foo',
                       '-m', 'configfile', '-p', '99999'],
             "exc" : SystemExit, "watcher_plugin" : "configfile",
             "out" : "2"},
            {"args" : ['-l', 'foo', '-v', '123', '-r', 'foo', '-m', 'http',
                       '-p', '99999'],
             "exc" : ArgsError, "watcher_plugin" : "http",
             "out" : "Invalid listen port"},
            {"args" : ['-l', 'foo', '-v', '123', '-r', 'foo', '-m', 'http',
                       '-a', '999.9'],
             "exc" : ArgsError, "watcher_plugin" : "http",
             "out" : "Not a valid IP address"}
        ]

        for i in inp:
            if 'watcher_plugin' in i:
                wplc = main.load_plugin(i['watcher_plugin'],
                                        "vpcrouter.watcher.plugins")
            else:
                wplc = None

            hplc = main.load_plugin(i.get('health_plugin', 'icmpecho'),
                                    "vpcrouter.monitor.plugins")

            args = i['args']
            exc  = i['exc']
            out  = i.get('out', "")
            conf = i.get('conf', {})
            sys.stdout = StringIO()
            sys.stderr = StringIO()
            if exc:
                with self.assertRaises(exc) as ex:
                    main._parse_args(args, wplc, hplc)
                self.assertTrue(out in str(ex.exception.message))
            else:
                conf_is = main._parse_args(args, wplc, hplc)
                output  = sys.stderr.getvalue().strip()
                ll      = self.get_last_line(output)
                if not out:
                    self.assertFalse(ll)
                else:
                    self.assertTrue(out in ll)
                if conf:
                    self.assertEqual(conf, conf_is)


if __name__ == '__main__':
    unittest.main()
