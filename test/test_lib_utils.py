# -*- coding: utf-8 -*-

import unittest
from authappliance.lib.utils import to_unicode


class TestLibUtils(unittest.TestCase):
    def test_01_encoding(self):
        u = u'Hello Wörld'
        b = b'Hello World'

        self.assertEqual(to_unicode(u), u)
        self.assertEqual(to_unicode(b), b.decode('utf8'))
        self.assertEqual(to_unicode(None), None)
        self.assertEqual(to_unicode(10), 10)
