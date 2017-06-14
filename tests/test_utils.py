import unittest

from utils  import ip_check
from errors import ArgsError

class TestIpCheck(unittest.TestCase):
    def test_correct(self):
        ip_check("192.168.1.2")
        ip_check("192.168.0.0/16", netmask_expected=True)
        ip_check("192.168.0.0/1", netmask_expected=True)
        ip_check("192.168.0.0/32", netmask_expected=True)

    def test_incorrect(self):
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

