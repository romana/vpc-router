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

import unittest
import ping
import socket
import Queue
import time

import monitor


# This variable determines what IP addresses are considered 'failed' when we
# monkey-patch the health check. Thiis isn't exactly thread-safe, but since
# the tests are normally run in a single thread, this should be ok.
_FAILED_PREFIX = None


class TestQueues(unittest.TestCase):

    def setUp(self):
        # We monkey patch the ping function of the ping module (which the
        # monitoring module uses) so we can run this without actually pinging
        # servers. Our replacement ping function allows us to pre-determine for
        # which IPs it will indicate failure: All IPs starting with
        # _FAILED_PREFIX will result in 'None', indicating that those addresses
        # couldn't be pinged.  Addresses starting with "333." will result in
        # the usual socket error, which we would get if the IP address is
        # malformed or the name cannot be resolved. For all other addresses we
        # return a floating point value (the ping time), indicating success.
        def new_do_one(ip, timeout, size):
            if ip.startswith(_FAILED_PREFIX):
                return None
            elif ip.startswith("333."):
                raise socket.gaierror()
            else:
                return 0.5
        # Now we install this new ping function in place of the original one.
        # Clearly, this is a white box test: We know about the inner working of
        # the monitoring module in order to perform our monkey patch.
        ping.do_one = new_do_one

        # Setup the monitor thread with a small monitoring interval (all
        # local, no real pings). We get back the thread and the two
        # communication queues.
        self.monitor_thread, self.q_monitor_ips, self.q_failed_ips = \
                    monitor.start_monitor_in_background(0.1)

        # Install the cleanup, which will send the stop signal to the monitor
        # thread once we are done with our test
        self.addCleanup(self.cleanup)


    def cleanup(self):
        """
        Send the stop signal to the monitoring thread and end it.

        """
        self.q_monitor_ips.put(None)   # send the stop signal
        self.monitor_thread.join()


    def test_sending_receiving(self):
        #
        # Simple tests to check various inputs against expected outputs.
        #
        global _FAILED_PREFIX
        _FAILED_PREFIX = "11."

        # List of inputs and expected outputs
        input_output = [
            ([ "10.0.0.0" ],                        None),     # No failed IPs
            ([ "11.1.1.1" ],                        [ "11.1.1.1" ]),
            ([ "11.1.1.2","10.0.0.0" ],             [ "11.1.1.2" ]),
            ([ "11.1.1.3","11.2.2.3","10.0.0.3" ],  [ "11.1.1.3","11.2.2.3" ]),
            ([ "11.1.1.4","11.2.2.4","11.3.3.4" ],  [ "11.1.1.4","11.2.2.4",
                                                      "11.3.3.4" ]),
            # Now also with some malformed input
            ([ "333.3.3.5","10.2.2.5","11.3.3.5" ], [ "333.3.3.5","11.3.3.5" ])
        ]
        for inp, expected_out in input_output:
            self.q_monitor_ips.put(inp)
            if expected_out is None:
                # No message should be received if all hosts in the input
                # list are healthy.
                self.assertRaises(Queue.Empty, self.q_failed_ips.get,
                                  **{"timeout":0.2})
            else:
                while True:
                    # Read messages until we are at the last one
                    try:
                        res = self.q_failed_ips.get(timeout=1)
                    except Queue.Empty:
                        break
                self.q_failed_ips.task_done()
                self.assertEqual(sorted(res),
                                 sorted(expected_out))


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
            ([ "10.0.0.0" ],                       None),     # No failed IPs
            ([ "11.1.1.1" ],                       [ "11.1.1.1" ]),
            ([ "11.1.1.1","10.0.0.0" ],            [ "11.1.1.1" ]),
            ([ "11.1.1.1","11.2.2.2","10.0.0.0" ], [ "11.1.1.1","11.2.2.2" ]),
        ]
        for inp, expected_out in input_output:
            self.q_monitor_ips.put(inp)

        # Only check the last one, since all above messages should be read at
        # once and all but the last one should have been ignored.
        res = self.q_failed_ips.get()
        self.q_failed_ips.task_done()
        self.assertEqual(sorted(res), sorted(expected_out))

        # Since the monitor will keep checking the IPs, we should keep getting
        # results without en countering an empty queue
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
        self.q_monitor_ips.put([ "10.0.0.0", "12.0.0.0", "13.0.0.0" ])

        # There shouldn't be any messages: No failed IPs
        self.assertRaises(Queue.Empty, self.q_failed_ips.get,
                          **{"timeout":0.5})

        # Overwrite the monkey patch for the ping function with something new:
        # Indicate an error for addresses starting with "12."
        _FAILED_PREFIX = "12."

        # Now after a little while we should receive a message for a failed IP.
        res = self.q_failed_ips.get(timeout=2)
        self.assertEqual([ "12.0.0.0" ], res)

        # We should continue to get notifications about that failed IP...
        res = self.q_failed_ips.get(timeout=2)
        self.assertEqual([ "12.0.0.0" ], res)
        res = self.q_failed_ips.get(timeout=2)
        self.assertEqual([ "12.0.0.0" ], res)

        time.sleep(1.5) # wait and let monitor send a few more messages for 12

        # Now switching again...
        _FAILED_PREFIX = "13."

        # We should have received some more messages for "12.", which were sent
        # before we changed the prefix to 13. However, after a while we
        # definitely only should get messages about 13.
        seen_12 = False
        while True:
            res = self.q_failed_ips.get(timeout=1)
            self.assertEqual(1, len(res))  # only should ever see one result
            if not seen_12:
                # Make sure we see at least one more message for 12.
                self.assertEqual(res[0], "12.0.0.0")
                seen_12 = True
            else:
                # Now we could get a message for 13. at any moment.
                self.assertTrue(res[0] in [ "12.0.0.0", "13.0.0.0" ])
                if res[0] == "13.0.0.0":
                    # Finally received a message about 13. Done.
                    break


if __name__ == '__main__':
    unittest.main()

