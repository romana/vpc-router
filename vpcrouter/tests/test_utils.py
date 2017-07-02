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

from vpcrouter.utils  import ip_check
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


if __name__ == '__main__':
    unittest.main()
