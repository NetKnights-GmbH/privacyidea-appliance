# -*- coding: utf-8 -*-
from __future__ import absolute_import
import unittest
import dialog
import os
from shutil import copyfile
from authappliance.menu import MainMenu
from .mockdialog import Handler, UserBehavior

TEST_CONFIG = './test/testdata/pi.cfg'
TMP_CONFIG = './test/testdata/tmp_pi.cfg'


class EscapeHandler(Handler):
    """
    A handler that is used to escape the appliance tool:
    All menus are answered with CANCEL, and the question if the
    services should be restarted is answered with YES.
    """
    def __init__(self, behavior):
        self.behavior = behavior

    def __call__(self, function_name, kwds):
        self.behavior.add_handler(self)
        if function_name == 'menu':
            return dialog.Dialog.CANCEL, ''
        elif function_name == 'yesno':
            assert kwds['text'].startswith('Do you want to restart the services'),\
                    'Unexpected yesno dialog: {!r}'.format(kwds['text'])
            return dialog.Dialog.OK


class ApplianceBehavior(UserBehavior):
    def navigate(self, *choices):
        """
        Helper method to navigate to a menu more swiftly. Works like a sequence of ``answer_menu`` calls::

            behavior.navigate('foo', 'bar', 'baz')
            # is equivalent to
            behavior.answer_menu('foo')
            behavior.answer_menu('bar')
            behavior.answer_menu('baz')
        """
        for choice in choices:
            self.answer_menu(choice)


class MenuTestCase(unittest.TestCase):
    def setUp(self):
        copyfile(TEST_CONFIG, TMP_CONFIG)

    def tearDown(self):
        os.unlink(TMP_CONFIG)

    def simulate_run(self, behavior, config_file=None):
        behavior.add_handler(EscapeHandler(behavior))
        with behavior.simulate():
            menu = MainMenu(config_file)
            menu.main_menu()
