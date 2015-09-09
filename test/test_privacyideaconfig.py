# -*- coding: utf-8 -*-
import logging
log = logging.getLogger(__name__)
import unittest
import os
from authappliance.lib.appliance import PrivacyIDEAConfig

class TestPIConfig(unittest.TestCase):

    def test_01_init(self):
        pic = PrivacyIDEAConfig(file="./test/testdata/pi.cfg", init=True)

        self.assertEqual(pic.config.get("PI_PEPPER"),
                         "zzsWra6vnoYFrlVXJM3DlgPO")
        self.assertEqual(pic.config.get("SECRET_KEY"),
                         "sfYF0kW6MsZmmg9dBlf5XMWE")
        self.assertEqual(pic.config.get("SQLALCHEMY_DATABASE_URI"),
                                        'mysql://pi:P4yvb3d1Thw_@localhost/pi')

        # save the config
        pic.save()

        # read the file again
        pic = PrivacyIDEAConfig(file="./test/testdata/pi.cfg")

        self.assertEqual(pic.config.get("PI_PEPPER"),
                         "zzsWra6vnoYFrlVXJM3DlgPO")
        self.assertEqual(pic.config.get("SECRET_KEY"),
                         "sfYF0kW6MsZmmg9dBlf5XMWE")
        self.assertEqual(pic.config.get("SQLALCHEMY_DATABASE_URI"),
                                        'mysql://pi:P4yvb3d1Thw_@localhost/pi')

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

        pic.config["PI_ENCFILE"] = "./test/testdata/enckey"
        pic.config["PI_AUDIT_KEY_PRIVATE"] = "./test/testdata/private.pem"
        pic.config["PI_AUDIT_KEY_PUBLIC"] = "./test/testdata/public.pem"

        pic.save()
        # Now we can create the files.
        pic.create_audit_keys()
        pic.create_encryption_key()
        # Check if the files exist.
        import os.path
        for filename in [pic.config["PI_ENCFILE"],
                     pic.config["PI_AUDIT_KEY_PRIVATE"],
                     pic.config["PI_AUDIT_KEY_PUBLIC"]]:
            self.assertTrue(filename)
            # Delete the files
            os.unlink(filename)



