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
# Unit tests for the VPC module
#

import boto
import unittest
import random

from moto          import mock_ec2_deprecated
from testfixtures  import LogCapture

from vpcrouter import vpc

from . import test_common


class TestVpcUtil(unittest.TestCase):

    def setUp(self):
        # Hosts are chosen randomly from a prefix group. Therefore, we need to
        # seed the random number generator with a specific value in order to
        # have reproducible tests.
        random.seed(123)

    def test_host_choices(self):
        #
        # Specific test for the _choose_different_host function, verifying that
        # it can find available hosts, or indicate error as needed. Since we
        # fixed the seed, we have predictable 'random' choises for our test.
        #
        in_out = [
            # old_ip  ip_list          failed_ip   quest_ip
            [(None,   [],              [],         []),               None],
            [(None,   ["A"],           [],         []),               "A"],
            [("A",    ["A", "B"],      ["A"],      []),               "B"],
            [("A",    ["A", "B"],      ["C"],      []),               "A"],
            [(None,   ["A", "B"],      ["A", "B"], []),               None],
            [(None,   ["A", "B"],      ["B"],      []),               "A"],
            [(None,   ["A", "B"],      ["A"],      []),               "B"],
            [(None,   ["A", "B"],      ["A", "B"], []),               None],
            [(None,   ["A", "B"],      ["A"],      ["B"]),            "B"],
            [(None,   ["A", "B"],      ["A", "B"], ["B"]),            None],
            [(None,   ["A", "B", "C"], ["A"],      ["B"]),            "C"],
            [(None,   ["A", "B", "C"], [],         ["A", "B", "C"]),  "A"],
            # None is returned, since we won't choose a different host
            [("A",    ["A", "B", "C"], [],         ["A", "B", "C"]),  None],
            [("B",    ["A", "B", "C"], [],         ["A", "B", "C"]),  None],
            [("C",    ["A", "B", "C"], [],         ["A", "B", "C"]),  None],
            [("C",    ["B", "C"],      [],         ["A", "B", "C"]),  None],
            # New host forced, since "C" isn't in ip list
            [("C",    ["A", "B"],      [],         ["A", "B", "C"]),  "B"],
            # No available choice, so nothing to change to
            [("C",    [],              [],         ["A", "B", "C"]),  None],
        ]
        for args, expected_out in in_out:
            self.assertEqual(
                expected_out,
                vpc._choose_different_host(*args))


class TestVpcBotoInteractions(unittest.TestCase):
    """
    We use the moto mock framework for boto in order to test our interactions
    with boto.

    """
    def setUp(self):
        self.lc = LogCapture()
        self.lc.addFilter(test_common.MyLogCaptureFilter())
        self.addCleanup(self.cleanup)
        # Hosts are chosen randomly from a prefix group. Therefore, we need to
        # seed the random number generator with a specific value in order to
        # have reproducible tests.
        random.seed(123)

    def cleanup(self):
        self.lc.uninstall()

    @mock_ec2_deprecated
    def make_mock_vpc(self):
        """
        Use plain (but mocked) boto functions to create a small VPC with two
        subnets and two instances as a basis for our tests.

        (not quite sure why this doesn't run in setUp().

        """
        con = boto.vpc.connect_to_region("ap-southeast-2")

        # Note that moto doesn't seem to honor the subnet and VPC address
        # ranges, it seems all instances always get something random from a
        # 10/8 range.
        self.new_vpc = con.create_vpc('10.0.0.0/16')
        self.new_subnet_a = con.create_subnet(self.new_vpc.id, '10.1.0.0/16')
        self.new_subnet_b = con.create_subnet(self.new_vpc.id, '10.2.0.0/16')

        res1 = con.run_instances('ami-1234abcd',
                                 subnet_id=self.new_subnet_a.id)
        res2 = con.run_instances('ami-1234abcd',
                                 subnet_id=self.new_subnet_b.id)
        self.i1 = res1.instances[0]
        self.i2 = res2.instances[0]
        self.i1ip = self.i1.private_ip_address
        self.i2ip = self.i2.private_ip_address

    @mock_ec2_deprecated
    def test_connect(self):
        self.make_mock_vpc()

        # With a test VPC created, we now test our own functions

        con = vpc.connect_to_region("ap-southeast-2")
        d = vpc.get_vpc_overview(con, self.new_vpc.id, "ap-southeast-2")

        self.assertEqual(
            sorted(['subnets', 'route_tables', 'instance_by_id',
                    'instances', 'zones', 'vpc']),
            sorted(d.keys()))

        self.assertEqual(self.new_vpc.id, d['vpc'].id)
        self.assertTrue(self.new_subnet_a.id in [s.id for s in d['subnets']])
        self.assertTrue(self.new_subnet_b.id in [s.id for s in d['subnets']])
        self.assertTrue(len(d['zones']) == 3)
        self.assertTrue(len(d['route_tables']) == 1)
        self.assertTrue(len(d['instance_by_id'].keys()) == 2)
        self.assertTrue(d['instance_by_id'][self.i1.id].id == self.i1.id)
        self.assertTrue(d['instance_by_id'][self.i2.id].id == self.i2.id)

        self.assertTrue(vpc.find_instance_and_eni_by_ip(d, self.i1ip)[0].id ==
                        self.i1.id)
        self.assertTrue(vpc.find_instance_and_eni_by_ip(d, self.i2ip)[0].id ==
                        self.i2.id)

    @mock_ec2_deprecated
    def test_process_route_spec_config(self):
        self.make_mock_vpc()

        con = vpc.connect_to_region("ap-southeast-2")

        d = vpc.get_vpc_overview(con, self.new_vpc.id, "ap-southeast-2")

        i1, eni1 = vpc.find_instance_and_eni_by_ip(d, self.i1ip)
        i2, eni2 = vpc.find_instance_and_eni_by_ip(d, self.i2ip)

        rt_id = d['route_tables'][0].id

        route_spec = {
                         u"10.1.0.0/16" : [self.i1ip, self.i2ip]
                     }

        # Process a simple route spec, a route should have been added
        self.lc.clear()
        vpc.process_route_spec_config(con, d, route_spec, [], [])
        # One of the hosts is randomly chosen. We seeded the random number
        # generator at in this module, so we know that it will choose the
        # second host in this case.
        self.lc.check(
            ('root', 'DEBUG', 'Route spec processing. No failed IPs.'),
            ('root', 'INFO',
             "--- adding route in RT '%s' "
             "10.1.0.0/16 -> %s (%s, %s)" %
             (rt_id, self.i1ip, i1.id, eni1.id)))

        # One of the two IPs questionable, switch over
        d = vpc.get_vpc_overview(con, self.new_vpc.id, "ap-southeast-2")
        self.lc.clear()
        vpc.process_route_spec_config(con, d, route_spec, [], [self.i1ip])
        self.lc.check(
            ('root', 'DEBUG',
             'Route spec processing. No failed IPs.'),
            ('root',
             'INFO',
             "--- eni in route in RT 'rtb-84dc7f2c' can't be found: "
             "10.1.0.0/16 -> (none) (instance '%s')" % i1.id),
            ('root', 'INFO',
             "--- updating existing route in RT '%s' 10.1.0.0/16 -> "
             "%s (%s, %s) (old IP: None, reason: old IP failed/questionable "
             "or not eligible anymore)" %
             (rt_id, self.i2ip, i2.id, eni2.id)))

        # Now switch back
        d = vpc.get_vpc_overview(con, self.new_vpc.id, "ap-southeast-2")
        self.lc.clear()
        vpc.process_route_spec_config(con, d, route_spec, [], [self.i2ip])
        self.lc.check(
            ('root', 'DEBUG',
             'Route spec processing. No failed IPs.'),
            ('root',
             'INFO',
             "--- eni in route in RT 'rtb-84dc7f2c' can't be found: "
             "10.1.0.0/16 -> (none) (instance '%s')" %
             i2.id),
            ('root', 'INFO',
             "--- updating existing route in RT '%s' 10.1.0.0/16 -> "
             "%s (%s, %s) (old IP: None, reason: old IP failed/questionable "
             "or not eligible anymore)" %
             (rt_id, self.i1ip, i1.id, eni1.id)))

        # One of the two IPs failed, switch over
        d = vpc.get_vpc_overview(con, self.new_vpc.id, "ap-southeast-2")
        self.lc.clear()
        vpc.process_route_spec_config(con, d, route_spec, [self.i1ip], [])
        self.lc.check(
            ('root', 'DEBUG',
             'Route spec processing. Failed IPs: %s' % self.i1ip),
            ('root',
             'INFO',
             "--- eni in route in RT 'rtb-84dc7f2c' can't be found: "
             "10.1.0.0/16 -> (none) (instance '%s')" % i1.id),
            ('root', 'INFO',
             "--- updating existing route in RT '%s' 10.1.0.0/16 -> "
             "%s (%s, %s) (old IP: None, reason: old IP failed/questionable "
             "or not eligible anymore)" %
             (rt_id, self.i2ip, i2.id, eni2.id)))

        # Now all IPs for a route have failed
        d = vpc.get_vpc_overview(con, self.new_vpc.id, "ap-southeast-2")
        self.lc.clear()
        vpc.process_route_spec_config(con, d, route_spec,
                                      [self.i1ip, self.i2ip], [])
        self.lc.check(
            ('root', 'DEBUG',
             'Route spec processing. Failed IPs: %s,%s' %
             (self.i1ip, self.i2ip)),
            ('root',
             'INFO',
             "--- eni in route in RT 'rtb-84dc7f2c' can't be found: "
             "10.1.0.0/16 -> (none) (instance '%s')" % i2.id),
            ('root', 'WARNING',
             '--- cannot find available target for route update 10.1.0.0/16! '
             'Nothing I can do...'))

        # Add new route, remove old one
        route_spec = {
                         u"10.2.0.0/16" : [self.i1ip]
                     }

        d = vpc.get_vpc_overview(con, self.new_vpc.id, "ap-southeast-2")
        self.lc.clear()
        vpc.process_route_spec_config(con, d, route_spec, [], [])
        self.lc.check(
            ('root', 'DEBUG', 'Route spec processing. No failed IPs.'),
            ('root',
             'INFO',
             "--- eni in route in RT 'rtb-84dc7f2c' can't be found: "
             "10.1.0.0/16 -> (none) (instance '%s')" % i2.id),
            ('root', 'INFO',
             "--- route not in spec, deleting in RT '%s': "
             "10.1.0.0/16 -> ... ((unknown), (unknown))" % rt_id),
            ('root', 'INFO',
             "--- adding route in RT '%s' "
             "10.2.0.0/16 -> %s (%s, %s)" %
             (rt_id, self.i1ip, i1.id, eni1.id)))

    @mock_ec2_deprecated
    def test_handle_spec(self):
        self.make_mock_vpc()

        # Need to take a peek inside the VPC so we can properly evaluate the
        # output later on
        con = vpc.connect_to_region("ap-southeast-2")
        d = vpc.get_vpc_overview(con, self.new_vpc.id, "ap-southeast-2")
        i, eni = vpc.find_instance_and_eni_by_ip(d, self.i1ip)
        rt_id = d['route_tables'][0].id

        route_spec = {
                         u"10.2.0.0/16" : [self.i1ip]
                     }

        # Test handle_spec
        vid = self.new_vpc.id
        self.lc.clear()
        vpc.handle_spec("ap-southeast-2", vid, route_spec, [], [])
        self.lc.check(
            ('root', 'DEBUG', 'Handle route spec'),
            ('root', 'DEBUG', "Connecting to AWS region 'ap-southeast-2'"),
            ('root', 'DEBUG', "Retrieving information for VPC '%s'" % vid),
            ('root', 'DEBUG', 'Route spec processing. No failed IPs.'),
            ('root', 'INFO',
             "--- adding route in RT '%s' 10.2.0.0/16 -> %s (%s, %s)" %
             (rt_id, self.i1ip, self.i1.id, eni.id)))

        # mock the get_instance_private_ip_from_route() function in vpc. Reason
        # being: The boto mocking library (moto) doesn't handle ENIs in routes
        # correctly. Therefore, a match against the information we get from the
        # routes will never work. So, we provide a wrapper, which fills the
        # instance's ENI information into the route. This means that this
        # function now will always match. It's good for testing the 'match'
        # part of the code.
        old_func = vpc.get_instance_private_ip_from_route

        def my_get_instance_private_ip_from_route(instance, route):
            route.interface_id = instance.interfaces[0].id
            return old_func(instance, route)

        vpc.get_instance_private_ip_from_route = \
                                my_get_instance_private_ip_from_route
        self.lc.clear()
        vpc.handle_spec("ap-southeast-2", vid, route_spec, [], [])

        vpc.get_instance_private_ip_from_route = old_func

        self.lc.check(
            ('root', 'DEBUG', 'Handle route spec'),
            ('root', 'DEBUG', "Connecting to AWS region 'ap-southeast-2'"),
            ('root', 'DEBUG', "Retrieving information for VPC '%s'" % vid),
            ('root', 'DEBUG', 'Route spec processing. No failed IPs.'),
            ('root', 'INFO',
             "--- route exists already in RT '%s': 10.2.0.0/16 -> "
             "%s (%s, %s)" % (rt_id, self.i1ip, self.i1.id, eni.id)))


if __name__ == '__main__':
    unittest.main()
