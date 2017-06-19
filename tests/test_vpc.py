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

import unittest

from vpc  import _choose_from_hosts

class TestVpc(unittest.TestCase):
    def test_host_choices(self):
        in_out = [
            [ ( [], [] ),                     None, 0],
            [ ( [ "A" ], [] ),                "A",  0],
            [ ( [ "A", "B" ], [ "A" ] ),      "B",  0],
            [ ( [ "A", "B" ], [ "C" ] ),      "A",  0],
            [ ( [ "A", "B" ], [ "A", "B" ] ), None, 0],
            [ ( [ "A", "B" ], [ "B" ] ),      "A",  None],
            [ ( [ "A", "B" ], [ "A" ] ),      "B",  None],
            [ ( [ "A", "B" ], [ "A", "B" ] ), None, None],
        ]
        for args, expected_out, first_pos in in_out:
            self.assertEqual(expected_out,
                             _choose_from_hosts(*args, first_choice=first_pos))




if __name__ == '__main__':
    unittest.main()
