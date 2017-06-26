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
# Unit tests for the watcher module
#
import ping

import json
import logging
import shutil
import tempfile
import time
import unittest

import watcher
import vpc

from logging import Filter
from testfixtures       import LogCapture
from watchdog.observers import Observer

RES = None

class MyFilter(Filter):
    def filter(self, record):
        if record.name != "root":
            return 0
        else:
            return 1


class TestRouteSpec(unittest.TestCase):

    def setUp(self):
        self.lc = LogCapture()
        self.lc.addFilter(MyFilter())
        self.temp_dir = tempfile.mkdtemp()
        self.addCleanup(self.cleanup)


    def cleanup(self):
        self.lc.uninstall()
        shutil.rmtree(self.temp_dir)


    def test_file_event_watcher(self):
        #
        # Test for the detection of file events.
        #

        # Create a small test file
        global RES
        abs_fname = self.temp_dir + "/r.spec"

        class MyQueue(object):
            def put(self, msg):
                self.msg = msg

        with open(abs_fname, "w+") as f:
            myq = MyQueue()
            handler = watcher.RouteSpecChangeEventHandler(
                                          route_spec_fname   = "r.spec",
                                          route_spec_abspath = abs_fname,
                                          q_route_spec       = myq)
            # Install the file observer on the directory
            observer_thread = Observer()
            observer_thread.schedule(handler, self.temp_dir)
            observer_thread.start()

            # A write event to the file should be detected
            f.write("blah")
            f.flush()
            time.sleep(1) # not instantaneous, so need to wait a little

            # File is malformed, so should not have received a message
            self.assertTrue(myq.msg is None)

            # A new file created in the temp directory should not create an
            # event
            with open(self.temp_dir + "/foo", "w+") as f2:
                f2.write("blah")
                f2.flush()
            time.sleep(1)
            self.assertTrue(myq.msg is None)

            # Check that we received the right log messages about the file
            self.lc.check(
                ('root', 'DEBUG',
                 'Started config file change monitoring thread'),
                ('root', 'INFO',
                 'Detected file change event for %s' % abs_fname),
                ('root', 'ERROR',
                 "Config file ignored: Cannot open file: [Errno 2] "
                 "No such file or directory: 'r.spec'"))


    def test_route_spec_parser(self):
        #
        # Test the spec parsing function with a number of different inputs,
        # valid as well as malformed.
        #
        test_specs = [
            {
                "inp" : {
                            "10.1.0.0/16" : [ "1.1.1.1", "2.2.2.2" ],
                            "10.2.0.0/16" : [ "3.3.3.3" ]
                        },
                "res" : "IDENT"
            },
            {
                # malformed list of IPs
                "inp" : {
                            "10.1.0.0/16" : "Foo",
                        },
                "res" : None
            },
            {
                # malformed IP in list
                "inp" : {
                            "10.1.0.0/16" : [ "1.1.1.", "2.2.2.2" ],
                        },
                "res" : None
            },
            {
                # malformed top level type
                "inp" : "Foo",
                "res" : None
            }
        ]

        for test_data in test_specs:
            abs_fname = self.temp_dir + "/r.spec"
            with open(abs_fname, "w+") as f:
                f.write(json.dumps(test_data['inp']))

            res = watcher.read_route_spec_config(abs_fname)
            if test_data['res'] == "IDENT":
                # Expect same output as input
                out = test_data['inp']
            elif test_data['res'] is None:
                # If input is malformed we expect None as return
                self.assertTrue(res is None)
                continue

            # Compare expected result with real data
            self.assertEqual(out, res)

        self.lc.check(
             ('root', 'ERROR',
              'Config file ignored: Expect list of IPs as values in dict'),
             ('root', 'ERROR',
              'Config file ignored: Not a valid IP address (1.1.1.)'),
             ('root', 'ERROR',
              'Config file ignored: Expected dictionary at top level'))


class TestWatcher(unittest.TestCase):

    def setUp(self):
        self.lc = LogCapture()
        self.lc.setLevel(logging.DEBUG)
        self.lc.addFilter(MyFilter())
        self.temp_dir = tempfile.mkdtemp()
        self.addCleanup(self.cleanup)
        self.abs_fname = self.temp_dir + "/r.spec"

        self.old_handle_spec = vpc.handle_spec
        # Monkey patch the handle_spec function, which is called by the
        # watcher. The handle_spec function is defined in the VPC module.
        # However, it was directly imported by the watcher module, so it's now
        # a copy in the watcher module namespace. Thus, the patch has to be
        # done actually in the watcher module. For safety, we'll do it in both
        # the vpc and watcher module.
        def new_handle_spec(*args, **kwargs):
            pass
        watcher.handle_spec = vpc.handle_spec = new_handle_spec

        # Monkey patch the do_one ping method, since we don't really want to
        # send out ICMP echo requests when we run the tests. Will indicate
        # failure for all IP addresses starting with "3."
        def new_do_one(ip, timeout, size):
            if ip.startswith("3."):
                return None    # indicates failure
            else:
                return 0.5     # indicates success
        ping.do_one = new_do_one


    def cleanup(self):
        self.lc.uninstall()
        watcher.handle_spec = vpc.handle_spec = self.old_handle_spec
        shutil.rmtree(self.temp_dir)


    def test_watcher_thread_no_config(self):
        self.tinfo = watcher._start_working_threads(
                            self.abs_fname, "dummy-region", "dummy-vpc", 2)

        time.sleep(0.5)
        # Config file doesn't exist yet, so we should get an error.
        # Health monitor is started with a second delay, so no messages from
        # there, yet.
        self.lc.check(
            ('root',
             'ERROR',
             "Config file ignored: Cannot open file: [Errno 2] No such file or directory: '%s'" % self.abs_fname),
            ('root', 'DEBUG', 'Started config file change monitoring thread'))

        watcher._stop_working_threads(self.tinfo)


    def test_watcher_thread_wrong_config(self):
        inp = "MALFORMED"
        with open(self.abs_fname, "w+") as f:
            f.write(json.dumps(inp))

        self.tinfo = watcher._start_working_threads(
                            self.abs_fname, "dummy-region", "dummy-vpc", 2)

        time.sleep(0.5)
        # Config file doesn't exist yet, so we should get an error.
        self.lc.check(
            ('root', 'ERROR',
             'Config file ignored: Expected dictionary at top level'),
            ('root', 'DEBUG', 'Started config file change monitoring thread'))

        watcher._stop_working_threads(self.tinfo)


    def test_watcher_thread(self):
        inp = {
                  u"10.1.0.0/16" : [ u"1.1.1.1", u"2.2.2.2" ],
                  u"10.2.0.0/16" : [ u"3.3.3.3" ]
              }
        with open(self.abs_fname, "w+") as f:
            f.write(json.dumps(inp))

        self.tinfo = watcher._start_working_threads(
                            self.abs_fname, "dummy-region", "dummy-vpc", 2)

        time.sleep(1)
        self.lc.check(
             ('root', 'DEBUG', 'Started config file change monitoring thread'),
             ('root', 'DEBUG', 'Started health monitoring thread'),
             ('root', 'DEBUG', 'Checking live IPs: (none alive)'))
        self.lc.clear()

        watcher._event_monitor_loop(
            "dummy-region", "dummy-vpc",
            self.tinfo['q_monitor_ips'], self.tinfo['q_failed_ips'],
            self.tinfo['q_route_spec'],
            iterations=1, sleep_time=0.5)

        time.sleep(2)

        self.lc.check(
            ('root', 'DEBUG',
             'New route spec detected. Updating health-monitor '
             'with: 1.1.1.1,2.2.2.2,3.3.3.3'),
            ('root', 'DEBUG', u'Checking live IPs: 1.1.1.1,2.2.2.2,3.3.3.3'),
            ('root', 'INFO', u'Currently failed IPs: 3.3.3.3'))
        self.lc.clear()

        inp = {
                  u"10.1.0.0/16" : [ u"4.4.4.4", u"2.2.2.2" ],
                  u"10.2.0.0/16" : [ u"3.3.3.3" ]
              }
        with open(self.abs_fname, "w+") as f:
            f.write(json.dumps(inp))

        time.sleep(2)
        self.lc.check(
            ('root', 'INFO',
             'Detected file change event for %s' % self.abs_fname),
            ('root', 'DEBUG', 'Checking live IPs: 1.1.1.1,2.2.2.2'))
        self.lc.clear()

        watcher._event_monitor_loop(
            "dummy-region", "dummy-vpc",
            self.tinfo['q_monitor_ips'], self.tinfo['q_failed_ips'],
            self.tinfo['q_route_spec'],
            iterations=1, sleep_time=0.5)

        time.sleep(2)
        self.lc.check(
            ('root', 'DEBUG',
             'New route spec detected. Updating health-monitor '
             'with: 2.2.2.2,3.3.3.3,4.4.4.4'),
            ('root', 'DEBUG', u'Checking live IPs: 2.2.2.2,4.4.4.4'))

        watcher._stop_working_threads(self.tinfo)


if __name__ == '__main__':
    unittest.main()
