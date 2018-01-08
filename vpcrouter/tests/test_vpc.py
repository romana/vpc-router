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

from vpcrouter              import vpc
from vpcrouter.currentstate import CURRENT_STATE
from vpcrouter.errors       import VpcRouteSetError

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

        # In the mocked test the meta data won't contain the info we need (vpc
        # and region name), because the emulated EC2 instance isn't in any
        # region or vpc.
        meta = vpc.get_ec2_meta_data()
        self.assertTrue(meta == {})

        self.assertRaises(VpcRouteSetError, vpc.connect_to_region, "blah")

        con = vpc.connect_to_region("ap-southeast-2")

        # Error when specifying non-existent VPC
        self.assertRaises(VpcRouteSetError, vpc.get_vpc_overview,
                          con, "non-existent-vpc", "ap-southeast-2")

        # Get the default: First VPC if no VPC is specified
        d = vpc.get_vpc_overview(con, None, "ap-southeast-2")
        self.assertEqual(d['vpc'].id, "vpc-be745e76")

        # Get specified VPC
        d = vpc.get_vpc_overview(con, self.new_vpc.id, "ap-southeast-2")
        self.assertEqual(d['vpc'].id, "vpc-be745e76")

        self.assertEqual(
            sorted(['subnets', 'route_tables', 'instance_by_id',
                    'ip_subnet_lookup', 'instances', 'rt_subnet_lookup',
                    'zones', 'vpc']),
            sorted(d.keys()))

        self.assertEqual(self.new_vpc.id, d['vpc'].id)
        self.assertTrue(self.new_subnet_a.id in [s.id for s in d['subnets']])
        self.assertTrue(self.new_subnet_b.id in [s.id for s in d['subnets']])
        self.assertTrue(len(d['zones']) == 3)
        self.assertTrue(len(d['route_tables']) == 1)
        self.assertTrue(len(d['instance_by_id'].keys()) == 2)
        self.assertTrue(d['instance_by_id'][self.i1.id].id == self.i1.id)
        self.assertTrue(d['instance_by_id'][self.i2.id].id == self.i2.id)

        self.assertRaises(VpcRouteSetError, vpc.find_instance_and_eni_by_ip,
                          d, "9.9.9.9")     # Non existent IP
        self.assertTrue(vpc.find_instance_and_eni_by_ip(d, self.i1ip)[0].id ==
                        self.i1.id)
        self.assertTrue(vpc.find_instance_and_eni_by_ip(d, self.i2ip)[0].id ==
                        self.i2.id)

    def _prepare_mock_env(self):
        self.make_mock_vpc()

        con = vpc.connect_to_region("ap-southeast-2")

        d = vpc.get_vpc_overview(con, self.new_vpc.id, "ap-southeast-2")

        rt_id = d['route_tables'][0].id

        con.associate_route_table(route_table_id=rt_id,
                                  subnet_id=self.new_subnet_a.id)
        con.associate_route_table(route_table_id=rt_id,
                                  subnet_id=self.new_subnet_b.id)

        d = vpc.get_vpc_overview(con, self.new_vpc.id, "ap-southeast-2")

        i1, eni1 = vpc.find_instance_and_eni_by_ip(d, self.i1ip)
        i2, eni2 = vpc.find_instance_and_eni_by_ip(d, self.i2ip)

        return con, d, i1, eni1, i2, eni2, rt_id

    @mock_ec2_deprecated
    def test_process_route_spec_config(self):
        con, d, i1, eni1, i2, eni2, rt_id = self._prepare_mock_env()

        route_spec = {
                         u"10.1.0.0/16" : [self.i1ip, self.i2ip]
                     }

        d['cluster_node_subnets'] = \
                        vpc.make_cluster_node_subnet_list(d, route_spec)
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
        d['cluster_node_subnets'] = \
                        vpc.make_cluster_node_subnet_list(d, route_spec)
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
        d['cluster_node_subnets'] = \
                        vpc.make_cluster_node_subnet_list(d, route_spec)
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
        d['cluster_node_subnets'] = \
                        vpc.make_cluster_node_subnet_list(d, route_spec)
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
        d['cluster_node_subnets'] = \
                        vpc.make_cluster_node_subnet_list(d, route_spec)
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

        # Protect old route (ignore_routes), add new route, watch the old route
        # NOT disappear.
        CURRENT_STATE.ignore_routes.append("10.2.0.0/16")  # protected route
        route_spec = {
                         u"10.3.0.0/16" : [self.i1ip]
                     }

        d = vpc.get_vpc_overview(con, self.new_vpc.id, "ap-southeast-2")
        d['cluster_node_subnets'] = \
                        vpc.make_cluster_node_subnet_list(d, route_spec)
        self.lc.clear()
        vpc.process_route_spec_config(con, d, route_spec, [], [])
        # See in the logs that 10.2.0.0/16 wasn't deleted, even though it's not
        # in the route spec anymore.
        self.lc.check(
            ('root', 'DEBUG', 'Route spec processing. No failed IPs.'),
            ('root', 'INFO',
             "--- adding route in RT '%s' "
             "10.3.0.0/16 -> %s (%s, %s)" %
             (rt_id, self.i1ip, i1.id, eni1.id)))

    @mock_ec2_deprecated
    def test_add_new_route(self):
        con, d, i1, eni1, i2, eni2, rt_id = self._prepare_mock_env()
        route_spec = {
            "10.9.0.0/16" : [self.i1ip]
        }
        d['cluster_node_subnets'] = \
                        vpc.make_cluster_node_subnet_list(d, route_spec)

        self.lc.clear()
        vpc._add_new_route("10.9.0.0/16", self.i1ip, d, con, rt_id)
        self.lc.check(
            ('root', 'INFO',
             "--- adding route in RT '%s' "
             "10.9.0.0/16 -> %s (%s, %s)" %
             (rt_id, self.i1ip, i1.id, eni1.id)))

        self.lc.clear()
        vpc._add_new_route("10.9.0.0/16", "99.99.99.99", d, con, rt_id)
        self.lc.check(
            ('root', 'ERROR',
             "*** failed to add route in RT '%s' "
             "10.9.0.0/16 -> 99.99.99.99 (Could not find instance/eni "
             "for '99.99.99.99' in VPC '%s'.)" %
             (rt_id, self.new_vpc.id)))

    @mock_ec2_deprecated
    def test_update_route(self):
        con, d, i1, eni1, i2, eni2, rt_id = self._prepare_mock_env()

        route_spec = {
            "10.9.0.0/16" : [self.i1ip]
        }
        d['cluster_node_subnets'] = \
                        vpc.make_cluster_node_subnet_list(d, route_spec)

        vpc._add_new_route("10.9.0.0/16", self.i1ip, d, con, rt_id)

        self.lc.clear()
        route_spec = {
            "10.9.0.0/16" : [self.i2ip]
        }
        d['cluster_node_subnets'] = \
                        vpc.make_cluster_node_subnet_list(d, route_spec)
        vpc._update_route("10.9.0.0/16", self.i2ip, self.i1ip, d, con, rt_id,
                          "foobar")
        self.lc.check(
            ('root', 'INFO',
             "--- updating existing route in RT '%s' "
             "10.9.0.0/16 -> %s (%s, %s) "
             "(old IP: %s, reason: foobar)" %
             (rt_id, self.i2ip, i2.id, eni2.id, self.i1ip)))

        self.lc.clear()
        vpc._update_route("10.9.0.0/16", "9.9.9.9", self.i2ip, d, con, rt_id,
                          "foobar")
        self.lc.check(
            ('root', 'ERROR',
             "*** failed to update route in RT '%s' "
             "10.9.0.0/16 -> %s (Could not find instance/eni "
             "for '9.9.9.9' in VPC '%s'.)" %
             (rt_id, self.i2ip, self.new_vpc.id)))

        # Trying to update a non-existent route
        self.lc.clear()
        vpc._update_route("10.9.9.9/16", self.i1ip, self.i2ip, d, con, rt_id,
                          "foobar")
        self.lc.check(
            ('root', 'INFO',
             "--- updating existing route in RT '%s' 10.9.9.9/16 -> %s "
             "(%s, %s) (old IP: %s, reason: foobar)" %
             (rt_id, self.i1ip, i1.id, eni1.id, self.i2ip)),
            ('root', 'ERROR',
             "*** failed to update route in RT '%s' 10.9.9.9/16 -> %s "
             "(replace_route failed: u'%s~10.9.9.9/16')" %
             (rt_id, self.i2ip, rt_id))
        )

    @mock_ec2_deprecated
    def test_get_real_instance_if_mismatched(self):
        con, d, i1, eni1, i2, eni2, rt_id = self._prepare_mock_env()

        self.assertFalse(vpc._get_real_instance_if_mismatch(d, None, i1, eni1))
        ret = vpc._get_real_instance_if_mismatch(d, self.i1ip, i1, eni1)
        self.assertFalse(ret)

        for inst, eni in [(i2, eni2), (i1, eni2), (i2, eni1),
                          (i1, None), (None, eni1),
                          (i2, None), (None, eni2), (None, None)]:
            ret = vpc._get_real_instance_if_mismatch(d, self.i1ip, inst, eni)
            self.assertEqual(ret.id, i1.id)

    @mock_ec2_deprecated
    def test_get_host_for_route(self):
        con, d, i1, eni1, i2, eni2, rt_id = self._prepare_mock_env()

        vpc._add_new_route("10.9.0.0/16", self.i1ip, d, con, rt_id)

        rt = d['route_tables'][0]
        self.assertEqual(rt.id, rt_id)

        route = rt.routes[0]
        # Moto doesn't maintain intance or interface ID in the routes
        # correctly, so need to set this one manually
        route.instance_id  = i1.id
        route.interface_id = eni1.id

        # Find correct host for route (the passed in cidr is only used for
        # logging)
        self.assertEqual((i1.id, self.i1ip, eni1.id),
                         vpc._get_host_for_route(d, route, rt, "cidr-log"))

        # Look for broken route without an instance id
        route.instance_id = None
        self.lc.clear()
        self.assertEqual(('(unknown)', None, '(unknown)'),
                         vpc._get_host_for_route(d, route, rt, "cidr-log"))
        self.lc.check(
            ('root', 'INFO',
              "--- obsoleted route in RT '%s' cidr-log -> "
              "... (doesn't point to instance anymore)" % rt_id)
        )

        # Look for broken route with instance id for non-existent instance
        route.instance_id = "blah"
        self.lc.clear()
        self.assertEqual(('(unknown)', None, '(unknown)'),
                         vpc._get_host_for_route(d, route, rt, "cidr-log"))
        self.lc.check(
            ('root', 'INFO',
             "--- instance in route in RT '%s' can't be found: "
             "cidr-log -> ... (instance 'blah')" % rt_id)
        )

    @mock_ec2_deprecated
    def test_update_existing_routes(self):
        con, d, i1, eni1, i2, eni2, rt_id = self._prepare_mock_env()

        route_spec = {
                         u"10.0.0.0/16" : [self.i1ip]
                     }

        d['cluster_node_subnets'] = \
                        vpc.make_cluster_node_subnet_list(d, route_spec)
        vpc._add_new_route("10.0.0.0/16", self.i1ip, d, con, rt_id)

        routes_in_rts = {}

        # Test that a protected route doesn't get updated
        self.lc.clear()
        CURRENT_STATE.ignore_routes = ["10.0.0.0/8"]
        vpc._update_existing_routes(route_spec, [], [], d, con, routes_in_rts)
        self.assertTrue(rt_id in CURRENT_STATE.vpc_state['route_tables'])
        self.assertTrue("10.0.0.0/16" in
                        CURRENT_STATE.vpc_state['route_tables'][rt_id])
        self.assertTrue("Ignored: Protected CIDR" in
                        CURRENT_STATE.vpc_state['route_tables']
                                               [rt_id]
                                               ["10.0.0.0/16"])
        self.lc.check()

        # Now we un-protect the route and try again. Moto doesn't manage the
        # instance or interface ID in routes, so this will fail, because the
        # route doesn't look like it's pointing to an instance
        CURRENT_STATE.ignore_routes = []
        vpc._update_existing_routes(route_spec, [], [], d, con, routes_in_rts)
        self.assertTrue("Ignored: Not a route to an instance" in
                        CURRENT_STATE.vpc_state['route_tables']
                                               [rt_id]
                                               ["10.0.0.0/16"])
        self.lc.check()

        # Now we manually set the instance and eni id in the route, so that the
        # test can proceed.
        rt = d['route_tables'][0]
        self.assertEqual(rt.id, rt_id)

        route = rt.routes[0]
        # Moto doesn't maintain instance or interface ID in the routes
        # correctly, so need to set this one manually. This time the route spec
        # won't contain eligible hosts.
        route.instance_id  = i1.id
        route.interface_id = eni1.id
        self.lc.clear()
        route_spec = {
                         u"10.0.0.0/16" : []
                     }
        vpc._update_existing_routes(route_spec, [], [], d, con, routes_in_rts)
        self.lc.check(
            ('root', 'INFO',
             "--- route not in spec, deleting in RT '%s': 10.0.0.0/16 -> "
             "... (%s, %s)" %
             (rt_id, i1.id, eni1.id))
        )

        # Get a refresh, since deleting via Boto interface doesn't update the
        # cached vpc-info
        d = vpc.get_vpc_overview(con, self.new_vpc.id, "ap-southeast-2")
        d['cluster_node_subnets'] = \
                        vpc.make_cluster_node_subnet_list(d, route_spec)
        # There shouldn't be any routes left now
        rt = d['route_tables'][0]
        self.assertFalse(rt.routes)

        # Now try again, but with proper route spec. First we need to create
        # the route again and manually...
        route_spec = {
                         u"10.0.0.0/16" : [self.i2ip]
                     }
        d['cluster_node_subnets'] = \
                        vpc.make_cluster_node_subnet_list(d, route_spec)
        vpc._add_new_route("10.0.0.0/16", self.i1ip, d, con, rt_id)
        # ... and update our cached vpc info
        d = vpc.get_vpc_overview(con, self.new_vpc.id, "ap-southeast-2")
        d['cluster_node_subnets'] = \
                        vpc.make_cluster_node_subnet_list(d, route_spec)
        rt = d['route_tables'][0]
        route              = rt.routes[0]
        route.instance_id  = i1.id
        route.interface_id = eni1.id

        # Only IP for spec is in failed IPs, can't do anything
        self.lc.clear()
        vpc._update_existing_routes(route_spec, [self.i2ip], [],
                                    d, con, routes_in_rts)
        self.lc.check(
            ('root', 'WARNING',
             '--- cannot find available target for route update '
             '10.0.0.0/16! Nothing I can do...')
        )

        # Now with available IPs
        self.lc.clear()
        vpc._update_existing_routes(route_spec, [], [], d, con, routes_in_rts)
        self.lc.check(
            ('root', 'INFO',
             "--- updating existing route in RT '%s' 10.0.0.0/16 -> "
             "%s (%s, %s) (old IP: %s, reason: old IP failed/questionable "
             "or not eligible anymore)" %
             (rt_id, self.i2ip, i2.id, eni2.id, self.i1ip))
        )

        # Now with same route spec again
        d = vpc.get_vpc_overview(con, self.new_vpc.id, "ap-southeast-2")
        rt = d['route_tables'][0]
        route              = rt.routes[0]
        route.instance_id  = i2.id
        route.interface_id = eni2.id
        self.lc.clear()
        routes_in_rts = {}
        vpc._update_existing_routes(route_spec, [], [], d, con, routes_in_rts)
        self.lc.check(
            ('root', 'INFO',
             "--- route exists already in RT '%s': 10.0.0.0/16 -> "
             "%s (%s, %s)" %
             (rt_id, self.i2ip, i2.id, eni2.id))
        )

    @mock_ec2_deprecated
    def test_add_missing_routes(self):
        con, d, i1, eni1, i2, eni2, rt_id = self._prepare_mock_env()

        route_spec = {
                         u"10.0.0.0/16" : [self.i1ip]
                     }
        routes_in_rts = {}
        self.lc.clear()
        vpc._update_existing_routes(route_spec, [], [], d, con, routes_in_rts)
        self.lc.check()

        self.lc.clear()
        d['cluster_node_subnets'] = \
                        vpc.make_cluster_node_subnet_list(d, route_spec)
        vpc._add_missing_routes(route_spec, [], [], {}, d, con, routes_in_rts)
        self.lc.check(
            ('root', 'INFO',
             "--- adding route in RT '%s' 10.0.0.0/16 -> "
             "%s (%s, %s)" %
             (rt_id, self.i1ip, i1.id, eni1.id))
        )

        # The route exists already (passed in routes_in_rts), so no new route
        # should be created here.
        self.lc.clear()
        vpc._add_missing_routes(route_spec, [], [],
                                {"10.0.0.0/16" : self.i1ip},
                                d, con, {rt_id : ["10.0.0.0/16"]})
        self.lc.check()

        # Force a route creation by passing nothing for routes_in_rts and
        # passing in a 'previous' choice for the router
        self.lc.clear()
        vpc._add_missing_routes(route_spec, [], [],
                                {"10.0.0.0/16" : self.i1ip},
                                d, con, {rt_id : []})
        self.lc.check(
            ('root', 'INFO',
             "--- adding route in RT '%s' 10.0.0.0/16 -> "
             "%s (%s, %s)" %
             (rt_id, self.i1ip, i1.id, eni1.id))
        )

        # Now try the same with the only possible IP in failed IPs.
        self.lc.clear()
        vpc._add_missing_routes(route_spec, [self.i1ip], [],
                                {},
                                d, con, {rt_id : []})
        self.lc.check(
            ('root', 'WARNING',
             '--- cannot find available target for route addition '
             '10.0.0.0/16! Nothing I can do...')
        )

    @mock_ec2_deprecated
    def test_multi_address(self):
        # Testing that we can find interfaces, which have the specified IP on a
        # second, private IP address
        con, d, i1, eni1, i2, eni2, rt_id = self._prepare_mock_env()

        priv = eni1.private_ip_addresses[0]

        priv = boto.ec2.networkinterface.PrivateIPAddress(
                                                private_ip_address="10.9.9.9",
                                                primary=False)
        eni1.private_ip_addresses.append(priv)
        vpc._make_ip_subnet_lookup(d)

        self.lc.clear()
        route_spec = {
            "10.0.0.0/16" : ["10.9.9.9"]
        }
        d['cluster_node_subnets'] = \
                        vpc.make_cluster_node_subnet_list(d, route_spec)
        vpc._add_missing_routes(route_spec, [], [], {},
                                d, con, {rt_id : []})
        self.lc.check(
            ('root', 'INFO',
             "--- adding route in RT '%s' 10.0.0.0/16 -> 10.9.9.9 "
             "(%s, %s)" % (rt_id, i1.id, eni1.id))
        )

    @mock_ec2_deprecated
    def test_handle_spec(self):
        self.make_mock_vpc()

        # Need to take a peek inside the VPC so we can properly evaluate the
        # output later on
        con = vpc.connect_to_region("ap-southeast-2")
        d = vpc.get_vpc_overview(con, self.new_vpc.id, "ap-southeast-2")
        route_spec = {
                         u"10.2.0.0/16" : [self.i1ip]
                     }
        d['cluster_node_subnets'] = \
                        vpc.make_cluster_node_subnet_list(d, route_spec)
        i, eni = vpc.find_instance_and_eni_by_ip(d, self.i1ip)

        rt_id = d['route_tables'][0].id

        con.associate_route_table(route_table_id=rt_id,
                                  subnet_id=self.new_subnet_a.id)
        con.associate_route_table(route_table_id=rt_id,
                                  subnet_id=self.new_subnet_b.id)

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
