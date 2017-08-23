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

import json
import logging
import os
import requests
import shutil
import tempfile
import time
import unittest

from testfixtures       import LogCapture
from watchdog.observers import Observer

from vpcrouter                 import main
from vpcrouter                 import watcher
from vpcrouter                 import vpc
from vpcrouter.main            import http_server
from vpcrouter.watcher.plugins import configfile

from . import test_common

RES = None


class TestBase(unittest.TestCase):
    def lc_compare(self, should):
        if len(should) > len(self.lc.records):
            print "@@@ should: "
            for l in should:
                print l
            print "@@@ is: "
            for l in self.lc.records:
                print (l.name, l.levelname, l.msg)

        self.assertTrue(len(should) <= len(self.lc.records))
        for i, ll in enumerate(should):
            r = self.lc.records[i]
            self.assertEqual(ll, (r.name, r.levelname, r.msg))


class TestRouteSpec(TestBase):

    def setUp(self):
        self.lc = LogCapture()
        self.lc.addFilter(test_common.MyLogCaptureFilter())
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
            handler = configfile.RouteSpecChangeEventHandler(
                                              route_spec_fname   = "r.spec",
                                              route_spec_abspath = abs_fname,
                                              q_route_spec       = myq,
                                              plugin             = None)
            # Install the file observer on the directory
            observer_thread = Observer()
            observer_thread.schedule(handler, self.temp_dir)
            observer_thread.start()

            # A write event to the file should be detected
            f.write("blah")
            f.flush()
            time.sleep(1)  # not instantaneous, so need to wait a little

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
                ('root', 'INFO',
                 'Detected file change event for %s' % abs_fname),
                ('root', 'ERROR',
                 "Config ignored: Cannot open file: [Errno 2] "
                 "No such file or directory: 'r.spec'"))

    def test_route_spec_parser(self):
        #
        # Test the spec parsing function with a number of different inputs,
        # valid as well as malformed.
        #
        test_specs = [
            {
                "inp" : {
                            "10.1.0.0/16" : ["1.1.1.1", "2.2.2.2"],
                            "10.2.0.0/16" : ["3.3.3.3"]
                        },
                "res" : "IDENT"
            },
            {
                "inp" : {
                            "10.1.0.0/16" : ["1.1.1.1", "2.2.2.2", "2.2.2.2"],
                            "10.2.0.0/16" : ["3.3.3.3"]
                        },
                "res" : {
                            "10.1.0.0/16" : ["1.1.1.1", "2.2.2.2"],
                            "10.2.0.0/16" : ["3.3.3.3"]
                        },
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
                            "10.1.0.0/16" : ["1.1.1.", "2.2.2.2"],
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
            if test_data['res'] is None:
                self.assertRaises(ValueError,
                                  watcher.common.parse_route_spec_config,
                                  test_data['inp'])
            else:
                if test_data['res'] == 'IDENT':
                    expected_out = test_data['inp']
                else:
                    expected_out = test_data['res']

                res = watcher.common.parse_route_spec_config(test_data['inp'])
                self.assertEqual(expected_out, res)


class TestWatcherConfigfile(TestBase):

    def additional_setup(self):
        self.temp_dir = tempfile.mkdtemp()
        self.abs_fname = self.temp_dir + "/r.spec"
        self.conf = {
            "file"                : self.abs_fname,
            "region_name"         : "dummy-region",
            "vpc_id"              : "dummy-vpc",
            "mode"                : "configfile",
            "health"              : "icmpecho",
            "icmp_check_interval" : 2
        }
        self.watcher_plugin_class = \
                main.load_plugin("configfile", DEFAULT_WATCHER_PLUGIN_MOD)
        self.health_plugin_class = \
                main.load_plugin("icmpecho", DEFAULT_HEALTH_PLUGIN_MOD)

        # The watcher thread needs to have a config file available right at the
        # start, even if there's nothing in it
        self.write_config({})

    def setUp(self):
        self.lc = LogCapture()
        self.lc.setLevel(logging.DEBUG)
        self.lc.addFilter(test_common.MyLogCaptureFilter())

        self.additional_setup()

        self.addCleanup(self.cleanup)

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

    def additional_cleanup(self):
        shutil.rmtree(self.temp_dir)

    def cleanup(self):
        self.lc.uninstall()
        watcher.handle_spec = vpc.handle_spec = self.old_handle_spec
        self.additional_cleanup()

    def write_config(self, data):
        with open(self.abs_fname, "w+") as f:
            f.write(json.dumps(data))

    def start_thread_log_tuple(self):
        return [
            ('root', 'INFO',
             "Configfile watcher plugin: Starting to watch route spec file "
             "'%s' for changes..." % self.abs_fname)
        ]

    def change_event_log_tuple(self):
        return ('root', 'INFO',
                "Detected file change event for %s" %
                self.abs_fname)

    def test_watcher_thread_no_config(self):
        os.remove(self.abs_fname)
        watcher_plugin, health_plugin = \
                watcher.start_plugins(
                    self.conf,
                    self.watcher_plugin_class, self.health_plugin_class,
                    2)
        time.sleep(0.5)

        # Config file doesn't exist yet, so we should get an error.
        # Health monitor is started with a second delay, so no messages from
        # there, yet.
        l = self.start_thread_log_tuple()
        l.extend([
            ('root', 'ERROR',
             "Config ignored: Cannot open file: "
             "[Errno 2] No such file or directory: '%s'" % self.abs_fname),
            ('root', 'INFO',
             'ICMPecho health monitor plugin: Starting to watch instances.')
        ])
        self.lc.check(*l)

        watcher.stop_plugins(watcher_plugin, health_plugin)

    def test_watcher_thread_wrong_config(self):
        watcher_plugin, health_plugin = \
                watcher.start_plugins(
                    self.conf,
                    self.watcher_plugin_class, self.health_plugin_class,
                    2)
        time.sleep(1.2)

        self.lc.clear()
        inp = "MALFORMED"
        self.write_config(inp)

        time.sleep(1)
        # Config file malformed
        l = [
            self.change_event_log_tuple(),
            ('root', 'ERROR',
             'Config ignored: Expected dictionary at top level')
        ]
        self.lc_compare(l)

        watcher.stop_plugins(watcher_plugin, health_plugin)

    def test_watcher_thread(self):
        # Monkey patch the healthcheck method of the ICMP health monitor class,
        # since we don't really want to send out ICMP echo requests when we run
        # the tests. Will indicate failure for all IP addresses starting with
        # "3."
        def new_do_health_checks(s, addrs):
            return [a for a in addrs if a.startswith("3.")]

        # We do this in the class, before the plugin is instantiated
        self.health_plugin_class.do_health_checks = new_do_health_checks

        watcher_plugin, health_plugin = \
                watcher.start_plugins(
                    self.conf,
                    self.watcher_plugin_class, self.health_plugin_class,
                    2)

        time.sleep(2)

        l = self.start_thread_log_tuple()
        l.extend([
             ('root', 'INFO',
              'ICMPecho health monitor plugin: Starting to watch instances.'),
             ('root', 'DEBUG', 'Checking live IPs: (none alive)')])
        self.lc.check(*l)
        self.lc.clear()

        inp = {
                  u"10.1.0.0/16" : [u"1.1.1.1", u"2.2.2.2"],
                  u"10.2.0.0/16" : [u"3.3.3.3"]
              }
        self.write_config(inp)

        time.sleep(2)

        watcher._event_monitor_loop(
            "dummy-region", "dummy-vpc",
            watcher_plugin, health_plugin,
            iterations=1, sleep_time=0.5)

        time.sleep(2)

        self.lc.check(
            self.change_event_log_tuple(),
            ('root', 'DEBUG', 'Checking live IPs: (none alive)'),
            ('root', 'DEBUG',
             'New route spec detected. Updating health-monitor '
             'with: 1.1.1.1,2.2.2.2,3.3.3.3'),
            ('root', 'DEBUG', 'event_monitor_loop ended: Global stop'),
            ('root', 'DEBUG', u'Checking live IPs: 1.1.1.1,2.2.2.2,3.3.3.3'),
            ('root', 'INFO', u'Currently failed IPs: 3.3.3.3'))
        self.lc.clear()

        inp = {
                  u"10.1.0.0/16" : [u"4.4.4.4", u"2.2.2.2"],
                  u"10.2.0.0/16" : [u"3.3.3.3"]
              }
        self.write_config(inp)

        time.sleep(1)
        """
        Remove this check: The log messages may come through in a different
        order, which isn't a problem.

        self.lc.check(
            ('root', 'INFO',
             'Detected file change event for %s' % self.abs_fname),
            ('root', 'DEBUG', 'Checking live IPs: 1.1.1.1,2.2.2.2'))
        """
        self.lc.clear()

        watcher._event_monitor_loop(
            "dummy-region", "dummy-vpc",
            watcher_plugin, health_plugin,
            iterations=1, sleep_time=0.5)

        time.sleep(2)
        self.lc.check(
            ('root', 'DEBUG',
             'New route spec detected. Updating health-monitor '
             'with: 2.2.2.2,3.3.3.3,4.4.4.4'),
            ('root', 'DEBUG', 'event_monitor_loop ended: Global stop'),
            ('root', 'DEBUG', u'Checking live IPs: 2.2.2.2,4.4.4.4'))

        self.lc.clear()

        watcher._event_monitor_loop(
            "dummy-region", "dummy-vpc",
            watcher_plugin, health_plugin,
            iterations=2, sleep_time=1, route_check_time_interval=1)

        time.sleep(2)
        self.lc.check(
            ('root', 'DEBUG', u'Checking live IPs: 2.2.2.2,4.4.4.4'),
            ('root', 'DEBUG', 'Time for regular route check'),
            ('root', 'DEBUG', 'event_monitor_loop ended: Global stop'),
            ('root', 'DEBUG', u'Checking live IPs: 2.2.2.2,4.4.4.4'))

        watcher.stop_plugins(watcher_plugin, health_plugin)


PORT = 33289

DEFAULT_WATCHER_PLUGIN_MOD = "vpcrouter.watcher.plugins"
DEFAULT_HEALTH_PLUGIN_MOD  = "vpcrouter.monitor.plugins"


class TestWatcherHttp(TestWatcherConfigfile):
    """
    Same configs and tests as the configfile test case, except that the config
    is written with an HTTP request.

    We just need to overwrite a few hooks.

    """
    def additional_setup(self):
        global PORT
        self.conf = {
            "addr"                : "localhost",
            "port"                : PORT,
            "region_name"         : "dummy-region",
            "vpc_id"              : "dummy-vpc",
            "mode"                : "http",
            "health"              : "icmpecho",
            "icmp_check_interval" : 2
        }
        self.watcher_plugin_class = \
                main.load_plugin("http", DEFAULT_WATCHER_PLUGIN_MOD)
        self.health_plugin_class = \
                main.load_plugin("icmpecho", DEFAULT_HEALTH_PLUGIN_MOD)
        # Changing the listen port number of the server for each test, since we
        # can't reuse the socket addresses in such rapid succession
        PORT += 1
        self.conf['port'] = PORT
        self.http_srv = http_server.VpcRouterHttpServer(self.conf)

    def additional_cleanup(self):
        if self.http_srv:
            self.http_srv.stop()

    def write_config(self, data):
        url = "http://%s:%s/route_spec" % \
                            (self.conf['addr'], self.conf['port'])
        requests.post(url, data=json.dumps(data))

    def start_thread_log_tuple(self):
        return [
            ('root', 'INFO',
             "HTTP server: Starting to listen for requests on "
             "'localhost:%d'..." % self.conf['port']),
            ('root', 'INFO',
             'HTTP server: Started to listen...'),
            ('root', 'INFO',
             "Http watcher plugin: Starting to watch for route spec on "
             "'localhost:%d/route_spec'..." % self.conf['port'])
        ]

    def change_event_log_tuple(self):
        return ('root', 'INFO', "New route spec posted")

    def test_watcher_thread_no_config(self):
        self.watcher_plugin, self.health_plugin = \
                watcher.start_plugins(
                        self.conf,
                        self.watcher_plugin_class, self.health_plugin_class,
                        2)
        time.sleep(1.2)

        # Config file doesn't exist yet, so we should get an error.
        # Health monitor is started with a second delay, so no messages from
        # there, yet.
        l = self.start_thread_log_tuple()
        l.append(
            ('root', 'INFO',
             'ICMPecho health monitor plugin: Starting to watch instances.'))
        self.lc_compare(l)

        watcher.stop_plugins(self.watcher_plugin, self.health_plugin)


if __name__ == '__main__':
    unittest.main()
