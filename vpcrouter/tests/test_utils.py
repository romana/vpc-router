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
# Unit tests for the utils module
#

import unittest

from vpcrouter.utils  import ip_check, \
                             check_valid_ip_or_cidr, \
                             is_cidr_in_cidr
from vpcrouter.errors import ArgsError


class TestIpCheck(unittest.TestCase):

    def test_correct(self):
        #
        # Specific test for the ip_check function, using correct values.
        #
        ip_check("192.168.1.2")
        ip_check("192.168.0.0/16", netmask_expected=True)
        ip_check("192.168.0.0/1", netmask_expected=True)
        ip_check("192.168.0.0/32", netmask_expected=True)

    def test_incorrect(self):
        #
        # Specific test for the ip_check function, using invalid values.
        #
        for ip, flag in [
                            ("192.168.1.1111", False),
                            ("192.168.1.", False),
                            ("292.168.1.1", False),
                            ("1.1.1.0", True),
                            ("1.1.1.0/", True),
                            ("1.1.1.0/-1", True),
                            ("1.1.1.0/33", True)
                        ]:
            self.assertRaises(ArgsError, ip_check, ip, flag)

    def test_valid_ip_or_cidr(self):
        #
        # Specific tests for the test_valid_ip_or_cidr
        #
        test_data = [
            {
                "inp" : {"val" : "0.0.0.0",     "return_as_cidr" : False},
                "out" : {"val" : "0.0.0.0",     "exc" : None}
            },
            {
                "inp" : {"val" : "0.0.0.0",     "return_as_cidr" : True},
                "out" : {"val" : "0.0.0.0/0",   "exc" : None}
            },
            {
                "inp" : {"val" : "0.0.0.0/10",  "return_as_cidr" : True},
                "out" : {"val" : "0.0.0.0/10",  "exc" : None}
            },
            {
                "inp" : {"val" : "0.0.0.0/10",  "return_as_cidr" : False},
                "out" : {"val" : "0.0.0.0/10",  "exc" : None}
            },
            {
                "inp" : {"val" : "10.1.2.3",    "return_as_cidr" : True},
                "out" : {"val" : "10.1.2.3/32", "exc" : None}
            },
            {
                "inp" : {"val" : "10.1.2.3",    "return_as_cidr" : False},
                "out" : {"val" : "10.1.2.3",    "exc" : None}
            },
            {
                "inp" : {"val" : "101.2.3",     "return_as_cidr" : False},
                "out" : {"val" : None,          "exc" : ArgsError}
            },
            {
                "inp" : {"val" : "301.2.3.0",   "return_as_cidr" : True},
                "out" : {"val" : None,          "exc" : ArgsError}
            },
            {
                "inp" : {"val" : "101.2.3/64",  "return_as_cidr" : True},
                "out" : {"val" : None,          "exc" : ArgsError}
            },
            {
                "inp" : {"val" : "101.2.3/32/2", "return_as_cidr" : True},
                "out" : {"val" : None,          "exc" : ArgsError}
            },
        ]

        for td in test_data:
            val = td["inp"]["val"]
            rac = td["inp"]["return_as_cidr"]
            if td["out"]["exc"]:
                self.assertRaises(ArgsError, check_valid_ip_or_cidr, val, rac)
            else:
                ret = check_valid_ip_or_cidr(val, rac)
                self.assertEqual(ret, td["out"]["val"])

    def test_cidr_in_cidr(self):
        test_data = [
            ({"small_cidr": "10.1.1.0/24", "big_cidr": "10.1.0.0/16"}, True),
            ({"small_cidr": "10.1.1.0/24", "big_cidr": "10.1.1.0/24"}, True),
            ({"small_cidr": "10.1.0.0/16", "big_cidr": "10.1.1.0/24"}, False),
            ({"small_cidr": "10.2.1.0/24", "big_cidr": "10.1.0.0/16"}, False),
            ({"small_cidr": "10.2.1.0/24", "big_cidr": "0.0.0.0/16"},  False),
            ({"small_cidr": "10.2.1.0/24", "big_cidr": "0.0.0.0/0"},   False),
            ({"small_cidr": "0.0.0.0/0",   "big_cidr": "10.0.0.0/8"},  False),
            ({"small_cidr": "0.0.0.0/0",   "big_cidr": "0.0.0.0/0"},   True),
        ]
        for kwargs, res in test_data:
            self.assertEqual(is_cidr_in_cidr(**kwargs), res)


if __name__ == '__main__':
    unittest.main()
