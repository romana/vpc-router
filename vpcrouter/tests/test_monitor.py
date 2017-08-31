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
# Unit tests for the monitoring module
#

import os
import unittest
import Queue
import time

from vpcrouter                 import utils
from vpcrouter.monitor         import common
from vpcrouter.monitor.plugins import icmpecho, tcp, multi


# This variable determines what IP addresses are considered 'failed' when we
# monkey-patch the health check. Thiis isn't exactly thread-safe, but since
# the tests are normally run in a single thread, this should be ok.
_FAILED_PREFIX = None


class TestPingPlugin(unittest.TestCase):

    def test_sending_receiving_ping(self):
        # Only thing we can really send a ping to that doesn't leak of the host
        # is localhost.
        conf = {
            "icmp_check_interval" : 2
        }
        p = icmpecho.Icmpecho(conf)
        res = p.do_health_checks(["127.0.0.1"])
        if os.geteuid() != 0:
            print "@@@ Not running as root, can't test ping."
            self.assertEqual(res, ["127.0.0.1"])
        else:
            self.assertEqual(len(res), 0)


class TestTcpPlugin(unittest.TestCase):

    def test_tcp_health_check(self):
        # Use localhost for test, so that we don't leak packets out on the
        # network during tests. We also assume that we can use port 22 to try
        # to connect to.
        conf = {
            "tcp_check_interval" : 2,
            "tcp_check_port"     : 22
        }
        p = tcp.Tcp(conf)
        results = []
        p._do_tcp_check("127.0.0.1", results)
        self.assertEqual(len(results), 0)

        # Now check for a port that we assume isn't in use.
        conf = {
            "tcp_check_interval" : 2,
            "tcp_check_port"     : 65533
        }
        p = tcp.Tcp(conf)
        results = []
        p._do_tcp_check("127.0.0.1", results)
        self.assertEqual(results, ["127.0.0.1"])


class TestQueues(unittest.TestCase):

    def setUp(self):
        conf = {
            "icmp_check_interval" : 0.1
        }
        p = icmpecho.Icmpecho(conf)

        # We monkey patch the healthcheck function of the ping module so we can
        # run this without actually pinging servers. Our replacement check
        # function allows us to pre-determine for which IPs it will indicate
        # failure: All IPs starting with _FAILED_PREFIX are added to the output
        # (which is a list of failed IPs).
        def new_do_health_checks(addrs):
            return [a for a in addrs if a.startswith(_FAILED_PREFIX)]

        # Now we install this new healthcheck function in place of the original
        # one. Clearly, this is a white box test: We know about the inner
        # working of the monitoring module in order to perform our monkey
        # patch.
        p.do_health_checks = new_do_health_checks

        # Setup the monitor thread with a small monitoring interval (all
        # local, no real pings). We get back the thread and the two
        # communication queues.
        p.start()
        self.plugin = p
        self.q_monitor_ips, self.q_failed_ips, self.q_questionable_ips = \
                                                    self.plugin.get_queues()

        # Install the cleanup, which will send the stop signal to the monitor
        # thread once we are done with our test
        self.addCleanup(self.cleanup)

    def cleanup(self):
        """
        Send the stop signal to the monitoring thread and end it.

        """
        self.plugin.stop()

    def test_sending_receiving(self):
        #
        # Simple tests to check various inputs against expected outputs.
        #
        global _FAILED_PREFIX
        _FAILED_PREFIX = "11."

        # List of inputs and expected outputs
        input_output = [
            (["10.0.0.0"],                         None),     # No failed IPs
            (["11.1.1.1"],                         ["11.1.1.1"]),
            (["11.1.1.2", "10.0.0.0"],             ["11.1.1.2"]),
            (["11.1.1.3", "11.2.2.3", "10.0.0.3"], ["11.1.1.3", "11.2.2.3"]),
            (["11.1.1.4", "11.2.2.4", "11.3.3.4"], ["11.1.1.4", "11.2.2.4",
                                                    "11.3.3.4"]),
        ]

        for inp, expected_out in input_output:
            self.q_monitor_ips.put(inp)
            if expected_out is None:
                # No message should be received if all hosts in the input
                # list are healthy.
                self.assertRaises(Queue.Empty, self.q_failed_ips.get,
                                  **{"timeout" : 0.2})
            else:
                while True:
                    # Read messages until we are at the last one
                    try:
                        res = self.q_failed_ips.get(timeout=0.5)
                        self.q_failed_ips.task_done()
                        self.assertEqual(sorted(res),
                                         sorted(expected_out))
                    except Queue.Empty:
                        break

    def test_multi_send_single_receive(self):
        #
        # We may send multiple updates through really quickly, within the
        # monitoring interval. In that case, all those should be read at once
        # and then only the last one should be processed by the monitor.
        #
        # We kinda rely on the fact that we can cram those initial messages
        # through within the first monitoring interval (within 0.5 seconds).
        #
        #
        global _FAILED_PREFIX
        _FAILED_PREFIX = "11."

        # List of inputs and expected outputs
        input_output = [
            (["10.0.0.0"],                         None),     # No failed IPs
            (["11.1.1.1"],                         ["11.1.1.1"]),
            (["11.1.1.1", "10.0.0.0"],             ["11.1.1.1"]),
            (["11.1.1.1", "11.2.2.2", "10.0.0.0"], ["11.1.1.1", "11.2.2.2"]),
        ]
        for inp, expected_out in input_output:
            self.q_monitor_ips.put(inp)

        # Only check the last one, since all above messages should be read at
        # once and all but the last one should have been ignored.
        res = self.q_failed_ips.get()
        self.q_failed_ips.task_done()
        self.assertEqual(sorted(res), sorted(expected_out))

        # Since the monitor will keep checking the IPs, we should keep getting
        # results without encountering an empty queue
        res = self.q_failed_ips.get(timeout=1.5)
        res = self.q_failed_ips.get(timeout=1.5)

    def test_monitor_state_change(self):
        #
        # We establish the monitor, then change the result for an IP after a
        # while. We should then receive a message about that IP very soon.
        #
        global _FAILED_PREFIX
        _FAILED_PREFIX = "11."

        # Three IP addresses, none of them should be considered failed
        self.q_monitor_ips.put(["10.0.0.0", "12.0.0.0", "13.0.0.0"])

        # There shouldn't be any messages: No failed IPs
        self.assertRaises(Queue.Empty, self.q_failed_ips.get,
                          **{"timeout" : 0.5})

        # Overwrite the monkey patch for the ping function with something new:
        # Indicate an error for addresses starting with "12."
        _FAILED_PREFIX = "12."

        # Now after a little while we should receive a message for a failed IP.
        res = self.q_failed_ips.get(timeout=2)
        self.assertEqual(["12.0.0.0"], res)

        # We should continue to get notifications about that failed IP...
        res = self.q_failed_ips.get(timeout=2)
        self.assertEqual(["12.0.0.0"], res)
        res = self.q_failed_ips.get(timeout=2)
        self.assertEqual(["12.0.0.0"], res)

        time.sleep(1.5)  # wait and let monitor send a few more messages for 12

        # Now switching again...
        _FAILED_PREFIX = "13."

        # We should have received some more messages for "12.", which were sent
        # before we changed the prefix to 13. However, after a while we
        # definitely only should get messages about 13.
        seen_12 = False
        while True:
            res = self.q_failed_ips.get(timeout=1)
            self.assertTrue(1 <= len(res) <= 2)  # latest and currently failed
            if not seen_12:
                # Make sure we see at least one more message for 12.
                self.assertEqual(res[0], "12.0.0.0")
                seen_12 = True
            else:
                # Now we could get a message for 13. at any moment.
                self.assertTrue(res[0] in ["12.0.0.0", "13.0.0.0"])
                if res[0] == "13.0.0.0":
                    # Finally received a message about 13. Done.
                    break


class TestQueuesTcp(TestQueues):
    # We can run all the same tests as before, but this time with the TCP
    # health monitor plugin.

    def setUp(self):
        # Monkey patch the socket connect test function
        def new_tcp_check(ip, results):
            # There is a more low level test about malformed IP addresses that
            # we use for the ICMP plugin. We don't really need to treat this in
            # some extra way for the TCP plugin, but need to indicate a failure
            # for this malformed IP here as well, so that the test doesn't
            # fail. That's why there is the special case test for a malformed
            # IP (starting with "333.").
            if ip.startswith(_FAILED_PREFIX):
                results.append(ip)

        conf = {
            "tcp_check_interval" : 0.1,
            "tcp_check_port" : 22
        }

        p = tcp.Tcp(conf)
        p._do_tcp_check = new_tcp_check

        p.start()
        self.plugin = p
        self.q_monitor_ips, self.q_failed_ips, self.q_questionable_ips = \
                                                    self.plugin.get_queues()

        self.addCleanup(self.cleanup)


class TestMulti(unittest.TestCase):
    # Test aspects of the multi plugin

    def setUp(self):
        self.mp = None
        self.addCleanup(self.cleanup)

    def cleanup(self):
        if self.mp:
            self.mp.stop()

    def test_expire_set(self):
        exp = multi.ExpireSet(0.2)
        self.assertFalse(exp.get())

        # Watching a set expire after some time
        exp.update([1, 2, 3])
        self.assertEqual(exp.get(), [1, 2, 3])  # still here...
        time.sleep(0.15)
        self.assertEqual(exp.get(), [1, 2, 3])  # still here...
        time.sleep(0.15)
        self.assertFalse(exp.get())             # ... and now it's gone

        exp.update([1, 2, 3])                   # add data...
        time.sleep(0.15)
        exp.update([3, 4, 5])                   # ... update some old and new
        time.sleep(0.15)
        self.assertEqual(exp.get(), [3, 4, 5])  # only recent data shows

        exp.update([4])
        time.sleep(0.05)
        exp.update([3])
        time.sleep(0.05)                        # oldest stuff expires
        self.assertEqual(exp.get(), [3, 4])
        time.sleep(0.11)                        # now a little more expires
        self.assertEqual(exp.get(), [3])

    def test_multi_plugin(self):

        class Testplugin(common.MonitorPlugin):
            # We'll use an easy to control test plugin for our multi-plugin
            # test.
            def __init__(self, conf, thread_name):
                self.thread_name = thread_name
                super(Testplugin, self).__init__(conf, thread_name)

            def get_monitor_interval(self):
                return 0.2

            def start(self):
                pass

            def send_failed(self, items):
                # This allows us to force the plugin to 'report' specified
                # failed IP addresses.
                self.q_failed_ips.put(items)

            def send_questionable(self, items):
                # This allows us to force the plugin to 'report' specified
                # questionable IP addresses.
                self.q_questionable_ips.put(items)

        conf = {}
        t1 = Testplugin(conf, "t1")
        t2 = Testplugin(conf, "t2")
        mp = multi.Multi(conf, TEST_PLUGINS=[
                                  ("t1", t1),
                                  ("t2", t2),
                               ])
        self.mp = mp
        mp.start()

        qm, qf, qq = mp.get_queues()

        # Test that new monitor IPs are passed on.
        time.sleep(1)
        qm.put(["10.1.1.1", "10.1.1.2", "10.1.1.2"])
        self.assertEqual(sorted(t1.q_monitor_ips.get()),
                         ["10.1.1.1", "10.1.1.2", "10.1.1.2"])
        self.assertEqual(sorted(t2.q_monitor_ips.get()),
                         ["10.1.1.1", "10.1.1.2", "10.1.1.2"])

        # Sending various failed IPs through the two plugins. We should get
        # accumulated results...
        self.assertTrue(utils.read_last_msg_from_queue(qf) is None)
        t1.send_failed(["10.1.1.1", "10.1.1.2"])
        time.sleep(0.5)
        self.assertEqual(sorted(utils.read_last_msg_from_queue(qf)),
                         ["10.1.1.1", "10.1.1.2"])
        t2.send_failed(["10.1.1.3"])
        time.sleep(0.5)
        self.assertEqual(sorted(utils.read_last_msg_from_queue(qf)),
                         ["10.1.1.1", "10.1.1.2", "10.1.1.3"])
        t1.send_failed(["10.1.1.1"])
        time.sleep(0.5)
        self.assertEqual(sorted(utils.read_last_msg_from_queue(qf)),
                         ["10.1.1.1", "10.1.1.2", "10.1.1.3"])
        time.sleep(1)
        t1.send_failed(["10.1.1.1"])
        time.sleep(2)
        self.assertEqual(sorted(utils.read_last_msg_from_queue(qf)),
                         ["10.1.1.1", "10.1.1.2", "10.1.1.3"])
        t1.send_failed(["10.1.1.2"])
        time.sleep(1)
        # ... but without refresh, some results should eventually disappear
        self.assertEqual(sorted(utils.read_last_msg_from_queue(qf)),
                         ["10.1.1.1", "10.1.1.2"])

        # Now test questionable IPs
        t1.send_questionable(["10.1.2.3", "10.2.3.4"])
        time.sleep(0.5)
        self.assertEqual(sorted(utils.read_last_msg_from_queue(qq)),
                         ["10.1.2.3", "10.2.3.4"])
        self.assertFalse(utils.read_last_msg_from_queue(qf))

        t1.send_questionable(["10.9.9.9"])
        t2.send_questionable(["10.2.2.2", "10.3.3.3"])
        time.sleep(0.5)
        self.assertEqual(sorted(utils.read_last_msg_from_queue(qq)),
                         ["10.1.2.3", "10.2.2.2", "10.2.3.4",
                          "10.3.3.3", "10.9.9.9"])


if __name__ == '__main__':
    unittest.main()
