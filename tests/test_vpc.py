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

# Hosts are chosen randomly from a prefix group. Therefore, we need to seed
# the random number generator with a specific value in order to have
# reproducible tests.
random.seed(123)

from logging       import Filter
from moto          import mock_ec2_deprecated
from testfixtures  import LogCapture

import errors
import vpc


class MyFilter(Filter):
    def filter(self, record):
        if record.name != "root":
            return 0
        else:
            return 1


class TestVpcUtil(unittest.TestCase):
    def test_host_choices(self):
        #
        # Specific test for the _choose_from_host function, verifying that it
        # can find available hosts, or indicate error as needed.
        #
        in_out = [
            [ ( [], [] ),                     None, 0],
            [ ( [ "A" ], [] ),                "A",  0],
            [ ( [ "A", "B" ], [ "A" ] ),      "B",  0],
            [ ( [ "A", "B" ], [ "C" ] ),      "B",  0],  # known random choice
            [ ( [ "A", "B" ], [ "A", "B" ] ), None, 0],
            [ ( [ "A", "B" ], [ "B" ] ),      "A",  None],
            [ ( [ "A", "B" ], [ "A" ] ),      "B",  None],
            [ ( [ "A", "B" ], [ "A", "B" ] ), None, None],
        ]
        for args, expected_out, first_pos in in_out:
            self.assertEqual(
                expected_out,
                vpc._choose_from_hosts(*args))


class TestVpcBotoInteractions(unittest.TestCase):
    """
    We use the moto mock framework for boto in order to test our interactions
    with boto.

    """
    def setUp(self):
        self.lc = LogCapture()
        self.lc.addFilter(MyFilter())
        self.addCleanup(self.cleanup)


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
            sorted(['subnets','route_tables','instance_by_id',
                    'instances','zones','vpc']),
            sorted(d.keys()))

        self.assertEqual(self.new_vpc.id, d['vpc'].id)
        self.assertTrue(self.new_subnet_a.id in [ s.id for s in d['subnets']])
        self.assertTrue(self.new_subnet_b.id in [ s.id for s in d['subnets']])
        self.assertTrue(len(d['zones']) == 3)
        self.assertTrue(len(d['route_tables']) == 1)
        self.assertTrue(len(d['instance_by_id'].keys()) == 2)
        self.assertTrue(d['instance_by_id'][self.i1.id].id == self.i1.id)
        self.assertTrue(d['instance_by_id'][self.i2.id].id == self.i2.id)

        self.assertTrue(vpc.find_instance_and_emi_by_ip(d, self.i1ip)[0].id ==
                        self.i1.id)
        self.assertTrue(vpc.find_instance_and_emi_by_ip(d, self.i2ip)[0].id ==
                        self.i2.id)

    @mock_ec2_deprecated
    def test_route_add_del_show(self):
        self.make_mock_vpc()

        # With a test VPC created, we now test our own functions

        con = vpc.connect_to_region("ap-southeast-2")
        d = vpc.get_vpc_overview(con, self.new_vpc.id, "ap-southeast-2")

        vpc.manage_route(con, d, "add", self.i1ip, "10.55.0.0/16")
        i, eni = vpc.find_instance_and_emi_by_ip(d, self.i1ip)
        self.lc.check(
            ('root', 'DEBUG', "Connecting to AWS region 'ap-southeast-2'"),
            ('root', 'DEBUG', "Retrieving information for VPC '%s'" %
             d['vpc'].id),
            ('root', 'DEBUG', "Adding route: 10.55.0.0/16"),
            ('root', 'INFO',
             "--- adding route in RT '%s' 10.55.0.0/16 -> %s (%s, %s)" %
             (d['route_tables'][0].id, self.i1ip, self.i1.id, eni.id )))

        # Adding the route again should give us a message that the route exists
        # already. Because moto doesn't seem to store the eni with the route
        # correctly, we can't detect that we have the exact route already, so
        # it shows as 'different destination'.
        d = vpc.get_vpc_overview(con, self.new_vpc.id, "ap-southeast-2")
        self.lc.clear()
        vpc.manage_route(con, d, "add", self.i1ip, "10.55.0.0/16")
        self.lc.check(
            ('root', 'DEBUG', 'Adding route: 10.55.0.0/16'),
            ('root', 'INFO',
             "--- route exists already in RT '%s', but with "
             "different destination: 10.55.0.0/16 -> %s (%s, %s)" %
             (d['route_tables'][0].id, self.i1ip, self.i1.id, eni.id)))

        # Adding with unknown instance IP: Should throw exception
        self.assertRaises(errors.VpcRouteSetError,
                          vpc.manage_route,
                          con, d, "add", "8.8.8.8", "10.55.0.0/16")

        # Listing the route
        d = vpc.get_vpc_overview(con, self.new_vpc.id, "ap-southeast-2")
        self.lc.clear()
        vpc.manage_route(con, d, "show", None, "10.55.0.0/16")
        # See the 'unknowns' in the log messages? This is normally the IP
        # address and eni associated with the route, but it seems as moto
        # doesn't implement storing that.
        self.lc.check(
            ('root', 'DEBUG', 'Searching for route: 10.55.0.0/16'),
            ('root', 'INFO',
             "--- route exists in RT '%s': "
             "10.55.0.0/16 -> (unknown) (%s, (unknown))" %
             (d['route_tables'][0].id, self.i1.id)))

        # Deleting the route
        d = vpc.get_vpc_overview(con, self.new_vpc.id, "ap-southeast-2")
        self.lc.clear()
        vpc.manage_route(con, d, "del", None, "10.55.0.0/16")
        self.lc.check(
            ('root', 'DEBUG', 'Deleting route: 10.55.0.0/16'),
            ('root', 'INFO',
             "--- deleting route in RT '%s': 10.55.0.0/16 -> "
             "(unknown) (%s, (unknown))" %
             (d['route_tables'][0].id, self.i1.id)))

        # Now try to delete the same route again: Error
        d = vpc.get_vpc_overview(con, self.new_vpc.id, "ap-southeast-2")
        self.lc.clear()
        vpc.manage_route(con, d, "del", None, "10.55.0.0/16")
        self.lc.check(
            ('root', 'DEBUG', 'Deleting route: 10.55.0.0/16'),
            ('root', 'INFO',
             "--- did not find route in RT '%s'" %
             (d['route_tables'][0].id)))


    @mock_ec2_deprecated
    def test_process_route_spec_config(self):
        self.make_mock_vpc()

        con = vpc.connect_to_region("ap-southeast-2")

        d = vpc.get_vpc_overview(con, self.new_vpc.id, "ap-southeast-2")

        i1, eni1 = vpc.find_instance_and_emi_by_ip(d, self.i1ip)
        i2, eni2 = vpc.find_instance_and_emi_by_ip(d, self.i2ip)

        rt_id = d['route_tables'][0].id

        route_spec = {
                         u"10.1.0.0/16" : [ self.i1ip, self.i2ip ],
                     }

        # Process a simple route spec, a route should have been added
        self.lc.clear()
        vpc.process_route_spec_config(con, d, route_spec, [])
        # One of the hosts is randomly chosen. We seeded the random number
        # generator at in this module, so we know that it will choose the
        # second host in this case.
        self.lc.check(
            ('root', 'INFO',
             "--- adding route in RT '%s' "
             "10.1.0.0/16 -> %s (%s, %s)" %
             (rt_id, self.i2ip, i2.id, eni2.id)))

        # One of the two IPs failed, switch over
        d = vpc.get_vpc_overview(con, self.new_vpc.id, "ap-southeast-2")
        self.lc.clear()
        vpc.process_route_spec_config(con, d, route_spec, [ self.i1ip ])
        self.lc.check(
            ('root', 'DEBUG',
             'Route spec processing. Failed IPs: %s' % self.i1ip),
            ('root', 'INFO',
             "--- route exists already in RT '%s', "
             "but with different destination: updating "
             "10.1.0.0/16 -> %s (%s, %s)" %
             (rt_id, self.i2ip, i2.id, eni2.id)))

        # Now all IPs for a route have failed
        d = vpc.get_vpc_overview(con, self.new_vpc.id, "ap-southeast-2")
        self.lc.clear()
        vpc.process_route_spec_config(con, d, route_spec,
                                      [ self.i1ip, self.i2ip ])
        self.lc.check(
            ('root', 'DEBUG',
             'Route spec processing. Failed IPs: %s,%s' %
             (self.i1ip, self.i2ip)),
            ('root', 'WARNING',
             '--- cannot find available target for route 10.1.0.0/16! '
             'Nothing I can do...'))

        # Add new route, remove old one
        route_spec = {
                         u"10.2.0.0/16" : [ self.i1ip ]
                     }

        d = vpc.get_vpc_overview(con, self.new_vpc.id, "ap-southeast-2")
        self.lc.clear()
        vpc.process_route_spec_config(con, d, route_spec, [])
        self.lc.check(
            ('root', 'INFO',
             "--- route not in spec, deleting in RT '%s': "
             "10.1.0.0/16 -> ... (%s, (unknown))" %
             (rt_id, i2.id)),
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
        i, eni = vpc.find_instance_and_emi_by_ip(d, self.i1ip)
        rt_id = d['route_tables'][0].id


        route_spec = {
                         u"10.2.0.0/16" : [ self.i1ip ]
                     }

        # Test handle_spec
        vid = self.new_vpc.id
        self.lc.clear()
        vpc.handle_spec("ap-southeast-2", vid, route_spec, [])
        self.lc.check(
            ('root', 'DEBUG', 'Handle route spec'),
            ('root', 'DEBUG', "Connecting to AWS region 'ap-southeast-2'"),
            ('root', 'DEBUG', u"Retrieving information for VPC '%s'" % vid),
            ('root', 'INFO',
             "--- adding route in RT '%s' 10.2.0.0/16 -> %s (%s, %s)" %
             (rt_id, self.i1ip, self.i1.id, eni.id)))


if __name__ == '__main__':
    unittest.main()
