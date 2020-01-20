# -*- coding: utf-8 -*-

import unittest
import os
from shutil import copyfile
from authappliance.lib.appliance import PrivacyIDEAConfig
from .testutil import TEST_CONFIG, TMP_CONFIG


class TestPIConfig(unittest.TestCase):
    def setUp(self):
        copyfile(TEST_CONFIG, TMP_CONFIG)

    def tearDown(self):
        os.unlink(TMP_CONFIG)

    def test_01_init(self):
        # check parser
        pic = PrivacyIDEAConfig(file=TEST_CONFIG)
        self.assertEqual(pic.config.get("PI_AUDIT_SQL_TRUNCATE"), True)
        self.assertEqual(pic.config.get("PI_AUDIT_POOL_SIZE"), 20)

        pic = PrivacyIDEAConfig(file=TMP_CONFIG, init=True)

        self.assertEqual(pic.config.get("PI_PEPPER"),
                         "zzsWra6vnoYFrlVXJM3DlgPO")
        self.assertEqual(pic.config.get("SECRET_KEY"),
                         "sfYF0kW6MsZmmg9dBlf5XMWE")
        self.assertEqual(pic.config.get("SQLALCHEMY_DATABASE_URI"),
                         'mysql+pymysql://pi:P4yvb3d1Thw_@localhost/pi')

        # save the config
        pic.save()

        # read the file again
        pic = PrivacyIDEAConfig(file=TMP_CONFIG)

        self.assertEqual(pic.config.get("PI_PEPPER"),
                         "zzsWra6vnoYFrlVXJM3DlgPO")
        self.assertEqual(pic.config.get("SECRET_KEY"),
                         "sfYF0kW6MsZmmg9dBlf5XMWE")
        self.assertEqual(pic.config.get("SQLALCHEMY_DATABASE_URI"),
                         'mysql+pymysql://pi:P4yvb3d1Thw_@localhost/pi')
        self.assertEqual(pic.config.get("PI_LOGLEVEL"), "logging.DEBUG")
        self.assertEqual(pic.config.get("SUPERUSER_REALM"), ['super'])

        # get keyfile
        r = pic.get_keyfile()
        self.assertEqual(r, '/etc/privacyidea/enckey')

        # get superusers
        r = pic.get_superusers()
        self.assertTrue("super" in r)
        self.assertEqual(len(r), 1)

        # set superusers
        pic.set_superusers(["super", "heros"])
        r = pic.get_superusers()
        self.assertTrue("super" in r)
        self.assertTrue("heros" in r)
        self.assertEqual(len(r), 2)

        # set loglevel
        pic.set_loglevel("logging.WARN")
        with self.assertRaises(Exception):
            pic.set_loglevel("123")

        pic.config["PI_ENCFILE"] = "./test/testdata/enckey"
        pic.config["PI_AUDIT_KEY_PRIVATE"] = "./test/testdata/private.pem"
        pic.config["PI_AUDIT_KEY_PUBLIC"] = "./test/testdata/public.pem"
        pic.config["PI_AUDIT_SQL_TRUNCATE"] = False
        pic.config["PI_AUDIT_POOL_SIZE"] = 21
        pic.config["PI_ENGINE_REGISTRY_CLASS"] = "shared"

        pic.save()
        # Check that values have been written correctly
        with open(TMP_CONFIG, "r") as f:
            contents = f.read()
            self.assertIn("PI_ENCFILE = './test/testdata/enckey'", contents)
            self.assertIn("PI_LOGLEVEL = logging.WARN", contents)
            self.assertIn("SUPERUSER_REALM = ['super', 'heros']", contents)
            self.assertIn("PI_AUDIT_SQL_TRUNCATE = False", contents)
            self.assertIn("PI_AUDIT_POOL_SIZE = 21", contents)
            self.assertIn("PI_ENGINE_REGISTRY_CLASS = 'shared'", contents)

        # Now we can create the files.
        pic.create_audit_keys()
        pic.create_encryption_key()
        # Check if the files exist.
        import os
        for filename in [pic.config["PI_ENCFILE"],
                         pic.config["PI_AUDIT_KEY_PRIVATE"],
                         pic.config["PI_AUDIT_KEY_PUBLIC"]]:
            self.assertTrue(filename)
            self.assertTrue(os.path.exists(filename), filename)
            # Delete the files
            os.unlink(filename)
