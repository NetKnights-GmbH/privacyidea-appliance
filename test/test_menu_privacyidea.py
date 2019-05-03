# -*- coding: utf-8 -*-
from __future__ import absolute_import
import authappliance.menu
from authappliance.lib.appliance import PrivacyIDEAConfig
from .mockdialog import preselected, initial
from .testutil import MenuTestCase, ApplianceBehavior, TMP_CONFIG
from mock import patch


class TestMenuPrivacyIDEA(MenuTestCase):
    @patch.object(authappliance.menu.OSConfig, 'restart')
    def test_set_loglevel(self, _mock_method):
        # user1 sets loglevel to ERROR
        user1 = ApplianceBehavior()
        user1.navigate('privacyIDEA', 'loglevel')
        user1.answer_radiolist('ERROR')
        self.simulate_run(user1, config_file=TMP_CONFIG)
        p_config1 = PrivacyIDEAConfig(TMP_CONFIG)
        self.assertEqual(p_config1.get_loglevel(), "logging.ERROR")
        # user2 sets it to DEBUG
        user2 = ApplianceBehavior()
        user2.navigate('privacyIDEA', 'loglevel')
        # check that the radiolist in fact preselects 'ERROR' now
        # (because we have set it above!)
        user2.answer_radiolist('DEBUG')\
             .check(preselected('ERROR'))
        self.simulate_run(user2, config_file=TMP_CONFIG)
        p_config2 = PrivacyIDEAConfig(TMP_CONFIG)
        self.assertEqual(p_config2.get_loglevel(), "logging.DEBUG")

    @patch.object(authappliance.menu.OSConfig, 'restart')
    def test_set_admin_realms(self, _mock_method):
        # user1 sets admin realms
        user1 = ApplianceBehavior()
        user1.navigate('privacyIDEA', 'admin realms')
        user1.answer_inputbox('super1,super2,super3')
        self.simulate_run(user1, config_file=TMP_CONFIG)
        p_config1 = PrivacyIDEAConfig(TMP_CONFIG)
        self.assertEqual(p_config1.get_superusers(), ['super1', 'super2', 'super3'])
        # user2 sets other admin realms
        user2 = ApplianceBehavior()
        user2.navigate('privacyIDEA', 'admin realms')
        user2.answer_inputbox('nix')\
             .check(initial('^super1,super2,super3$'))
        self.simulate_run(user2, config_file=TMP_CONFIG)
        p_config2 = PrivacyIDEAConfig(TMP_CONFIG)
        self.assertEqual(p_config2.get_superusers(), ["nix"])
