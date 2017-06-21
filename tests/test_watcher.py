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
import shutil
import tempfile
import threading
import time
import unittest

import watcher
import vpc

from watchdog.observers import Observer

RES = None


class TestRouteSpec(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.addCleanup(self.cleanup)

        self.old_p_and_p = watcher._parse_and_process
        # Monkey patch the processing function that's called by our file event
        # handler.
        def new_p_and_p(*args, **kwargs):
            # Just store what we received in a variable, so the test code can
            # check whether this was called and with what parameters.
            global RES
            print "@@@ new_p_and_p: args: ", args
            RES = args
        watcher._parse_and_process = new_p_and_p


    def cleanup(self):
        shutil.rmtree(self.temp_dir)
        watcher._parse_and_process = self.old_p_and_p


    def test_file_event_watcher(self):
        #
        # Test for the detection of file events.
        #

        # Create a small test file
        global RES
        abs_fname = self.temp_dir + "/r.spec"
        with open(abs_fname, "w+") as f:
            handler = watcher.RouteSpecChangeEventHandler(
                                              route_spec_fname   = "r.spec",
                                              route_spec_abspath = abs_fname,
                                              region_name        = "foo",
                                              vpc_id             = "bar")
            # Install the file observer on the directory
            observer_thread = Observer()
            observer_thread.schedule(handler, self.temp_dir)
            observer_thread.start()

            # A write event to the file should be detected
            f.write("blah")
            f.flush()
            time.sleep(1) # not instantaneous, so need to wait a little
            self.assertTrue(RES == ('r.spec', 'foo', 'bar'))
            RES = None

            # A new file created in the temp directory should not create an
            # event
            with open(self.temp_dir + "/foo", "w+") as f2:
                f2.write("blah")
                f2.flush()
            time.sleep(1)
            self.assertTrue(RES is None)


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


class TestWatcher(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.addCleanup(self.cleanup)

        self.old_handle_spec = vpc.handle_spec
        # Monkey patch the handle_spec function, which is called by the
        # watcher. The handle_spec function is defined in the VPC module.
        # However, it was directly imported by the watcher module, so it's now
        # a copy in the watcher module namespace. Thus, the patch has to be
        # done actually in the watcher module. For safety, we'll do it in both
        # the vpc and watcher module.
        def new_handle_spec(*args, **kwargs):
            global RES
            RES = args
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
        shutil.rmtree(self.temp_dir)
        watcher.handle_spec = vpc.handle_spec = self.old_handle_spec


    def test_watcher_thread(self):
        #
        # Test the full watcher thread.
        #
        global RES
        test_specs = [
            {
                "inp" :    {
                               u"10.1.0.0/16" : [ u"1.1.1.1", u"2.2.2.2" ],
                               u"10.2.0.0/16" : [ u"3.3.3.3" ]
                           },
                "failed" : [ u"3.3.3.3" ],  # mock ping says this failed
                "valid"  : True
            },
            {
                # This is malformed and should be ignored
                "inp" :    {
                               u"10.1./16" : [ "FOO" ],
                           },
                "failed" : [],
                "valid"  : False
            },
            {
                "inp" :    {
                               u"10.1.0.0/16" : [ u"1.1.1.1", u"3.4.5.6" ],
                           },
                "failed" : [ u"3.4.5.6" ],  # mock ping says this failed
                "valid"  : True
            },
        ]

        abs_fname = self.temp_dir + "/r.spec"
        wt = threading.Thread(target=watcher.start_daemon_as_watcher,
                              args=("foo-region", "vpc-123", abs_fname),
                              kwargs={ 'iterations' : 13, 'sleep_time' : 0.5})
        wt.daemon = True
        wt.start()

        time.sleep(1)   # need to have sleeps here and there to allow the
                        # monitor threads to catch up

        RES = None
        for test_data in test_specs:
            # Write new spec definition to file, should result in file event
            # change being captured and processed, resulting in a call to
            # handle_spec.
            with open(abs_fname, "w+") as f:
                f.write(json.dumps(test_data['inp']))
            time.sleep(2)
            if test_data['valid']:
                # RES should contain the values with which the mock handle_spec
                # function was called
                self.assertEqual(
                    RES, ('foo-region', 'vpc-123', test_data['inp'], True,
                          test_data['failed']))
                RES = None
            else:
                # Nothing should have happened, since the route spec is
                # invalid.
                self.assertTrue(RES is None)

        wt.join()

if __name__ == '__main__':
    unittest.main()
