from contextlib import contextmanager
from functools import partial

import mock
import dialog

PATCH_FUNCTIONS = ('yesno',)

class UserBehavior(object):
    def __init__(self):
        self._handlers = []

    def expect(self,
               function_name,
               return_value,
               callback=None):
        def handler(actual_function_name, *args, **kwargs):
            assert actual_function_name == function_name,\
                "Expected call of {}, got {}!".format(function_name, actual_function_name)
            if callback is not None:
                callback(*args, **kwargs)
            return return_value
        self._handlers.append(handler)

    def expect_yesno(self, answer):
        return_value = dialog.Dialog.OK if answer else dialog.Dialog.CANCEL
        self.expect('yesno', return_value)

    def _side_effect_handler(self, function_name, *args, **kwargs):
        assert self._handlers, "Got call of {}, but no handlers are defined!".format(function_name)
        handler = self._handlers.pop()
        return handler(function_name, *args, **kwargs)

    def _start_mock(self, function_name):
        target = 'dialog.Dialog.{}'.format(function_name)
        patcher = mock.patch(target, side_effect=partial(self._side_effect_handler, function_name))
        patcher.start()
        return patcher

    @contextmanager
    def simulate(self):
        patchers = [self._start_mock(function) for function in PATCH_FUNCTIONS]
        try:
            yield
        finally:
            for patcher in patchers:
                patcher.stop()