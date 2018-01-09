from authappliance.lib.appliance import PrivacyIDEAConfig, DEFAULT_CONFIG
from mockdialog import preselected, initial
from testutil import MenuTestCase, ApplianceBehavior


class TestMenuPrivacyIDEA(MenuTestCase):
    def test_set_loglevel(self):
        # user1 sets loglevel to ERROR
        user1 = ApplianceBehavior()
        user1.navigate('privacyIDEA', 'loglevel')
        user1.answer_radiolist('ERROR')
        self.simulate_run(user1)
        p_config1 = PrivacyIDEAConfig(DEFAULT_CONFIG)
        self.assertEqual(p_config1.get_loglevel(), "logging.ERROR")
        # user2 sets it to DEBUG
        user2 = ApplianceBehavior()
        user2.navigate('privacyIDEA', 'loglevel')
        # check that the radiolist in fact preselects 'ERROR' now
        # (because we have set it above!)
        user2.answer_radiolist('DEBUG')\
             .check(preselected('ERROR'))
        self.simulate_run(user2)
        p_config2 = PrivacyIDEAConfig(DEFAULT_CONFIG)
        self.assertEqual(p_config2.get_loglevel(), "logging.DEBUG")

    def test_set_admin_realms(self):
        # user1 sets admin realms
        user1 = ApplianceBehavior()
        user1.navigate('privacyIDEA', 'admin realms')
        user1.answer_inputbox('super1,super2,super3')
        self.simulate_run(user1)
        p_config1 = PrivacyIDEAConfig(DEFAULT_CONFIG)
        self.assertEqual(p_config1.get_superusers(), ['super1', 'super2', 'super3'])
        # user2 sets other admin realms
        user2 = ApplianceBehavior()
        user2.navigate('privacyIDEA', 'admin realms')
        user2.answer_inputbox('nix')\
             .check(initial('^super1,super2,super3$'))
        self.simulate_run(user2)
        p_config2 = PrivacyIDEAConfig(DEFAULT_CONFIG)
        self.assertEqual(p_config2.get_superusers(), ["nix"])
