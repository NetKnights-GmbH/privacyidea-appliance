import unittest
from dialog import Dialog

import mock

from mockdialog import UserBehavior

class TestMenuPrivacyIDEA(unittest.TestCase):
    def test_invocation(self):
        user = UserBehavior()
        user.expect('yesno', Dialog.CANCEL)
        with user.simulate():
            d = Dialog()
            code = d.yesno('hello!', width=70)
            print 'code is ', code
