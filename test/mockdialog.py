import re
from contextlib import contextmanager
from functools import partial

import funcsigs
import mock
import dialog

PATCH_FUNCTIONS = ('yesno', 'menu', 'radiolist', 'inputbox', 'passwordbox')
#: Collect function signatures because we cannot do it once the mocks are activated.
#: They are not going to change anyway.
PATCH_FUNCTION_SIGNATURES = dict((function, funcsigs.signature(getattr(dialog.Dialog, function)))
                                 for function in PATCH_FUNCTIONS)

class Handler(object):
    """
    Callable object that handles the invocation of a mock dialog function.
    """
    def __call__(self, actual_function_name, kwds):
        """
        :param actual_function_name: the dialog function that was called (e.g. "yesno")
        :param kwds: a dictionary of all arguments to the function call
        :return: value that should be returned to the caller
        """
        raise NotImplementedError()

class ActionHandler(Handler):
    """
    A handler that can
     * checks that the invoked function is in fact the expected function
     * check the function arguments against expected arguments
     * call a function to compute a return value
    """
    def __init__(self, function_name):
        Handler.__init__(self)
        self.function_name = function_name
        self._return_value = None
        self._checkers = []

    def __call__(self, actual_function_name, kwds):
        assert actual_function_name == self.function_name, \
            "Expected call of {}, got {}!".format(self.function_name, actual_function_name)
        for checker in self._checkers:
            checker(kwds)
        return_value = self._return_value
        if callable(return_value):
            return_value = self._return_value(kwds)
        return return_value

    def result(self, return_value):
        """
        Use ``return_value`` to compute the function return value.
        :param return_value: the return value or a callable that takes one argument (a dictionary of all
                             arguments to the function call) and returns a value
        :return: self
        """
        self._return_value = return_value
        return self

    def check(self, *checkers):
        """
        Add so-called checkers to the list of checkers. A checker is a function that takes one argument
        (a dictionary of all arguments to the function call) and makes some assertions.
        :return: self
        """
        self._checkers.extend(checkers)
        return self

def text_matches(pattern):
    """
    Check that the displayed dialog text matches the regular expression ``pattern``.
    :param pattern: regular expression that matches anywhere in the string
    """
    def text_matches_checker(kwds):
        match = re.search(pattern, kwds['text'])
        assert match is not None, \
            "Provided text does not match {!r} ({!r})".format(pattern, kwds['text'])
    return text_matches_checker

def preselected(tag_pattern):
    """
    Only applicable for radiolist dialogs:
    Check that
     * there is a preselected item
     * its tag matches the regular expression ``pattern``.
    :param pattern: regular expression that matches anywhere in the string
    """
    def preselected_checker(kwds):
        for choice in kwds['choices']:
            tag = choice[0]
            if choice[-1] in ('on', True, 1):
                assert re.search(tag_pattern, tag) is not None,\
                    "Preselected item does not match {!r} ({!r})".format(tag_pattern, tag)
                # TODO: We just assume that only one item is preselected
                break
        else:
            assert False, "No item was preselected!"
    return preselected_checker

def initial(pattern):
    """
    Only applicable for inputbox dialogs: Check that the initially given text matches the pattern ``text``
    :param text: regular expression that matches anywhere in the string
    """
    def initial_checker(kwds):
        init = kwds.get('init', '')
        assert re.search(pattern, init) is not None,\
            "Initial text does not match {!r} ({!r})".format(pattern, init)
    return initial_checker

def _match_choices(answer, choices):
    matching_tags = []
    for choice in choices:
        tag = choice[0]
        if re.search(answer, tag) is not None:
            matching_tags.append(tag)
    assert matching_tags, "No choice matching {!r} found!".format(answer)
    assert len(matching_tags) == 1, "Ambiguous answer: {!r} (matches {!r})".format(answer, matching_tags)
    return matching_tags[0]

class UserBehavior(object):
    """
    A class that models the user interaction with the dialogs.
    You will probably only need the ``answer_*`` and ``simulate`` methods.
    """
    def __init__(self):
        #: A queue of handlers. Every time a dialog is displayed, the handler at the front of the list is invoked.
        self._handlers = []

    def add_handler(self, handler):
        self._handlers.append(handler)

    def expect(self, function_name):
        """
        Add an ``ActionHandler`` that expects the function name ``function_name`` and return it.
        You should add a return value by invoking ``.result(...)``.
        :param function_name: e.g. "yesno"
        :return: an ``ActionHandler``
        """
        handler = ActionHandler(function_name)
        self.add_handler(handler)
        return handler

    def answer_yesno(self, answer):
        """
        Expect a "yesno" dialog and answer it accordingly.
        :param answer: True if YES should be chosen, False if NO should be chosen
        :return: an ``ActionHandler``
        """
        return_value = dialog.Dialog.OK if answer else dialog.Dialog.CANCEL
        return self.expect('yesno').result(return_value)

    def answer_radiolist(self, answer):
        """
        Expect a "radiolist" dialog and choose an item accordingly.
        :param answer: a regex that matches the item tag that should be selected
                       or None if the dialog should be canceled
        :return: an ``ActionHandler``
        """
        return self._answer_choice('radiolist', answer)

    def answer_menu(self, answer):
        """
        Expect a "menu" dialog and choose an item accordingly.
        :param answer: a regex that matches the item tag that should be selected
                       or None if the dialog should be canceled
        :return: an ``ActionHandler``
        """
        return self._answer_choice('menu', answer)

    def answer_inputbox(self, answer):
        """
        Expect an "inputbox" dialog and give an input accordingly.
        :param answer: Text should be returned
                       or None if the dialog should be canceled
        :return: An ``ActionHandler``
        """
        return_value = (dialog.Dialog.OK, answer) if answer is not None else (dialog.Dialog.CANCEL, '')
        return self.expect('inputbox').result(return_value)

    def answer_passwordbox(self, answer):
        """
        Expect an "passwordbox" dialog and give an input accordingly.
        :param answer: Text should be returned
                       or None if the dialog should be canceled
        :return: An ``ActionHandler``
        """
        return_value = (dialog.Dialog.OK, answer) if answer is not None else (dialog.Dialog.CANCEL, '')
        return self.expect('passwordbox').result(return_value)

    def _side_effect_handler(self, function_name, *args, **kwargs):
        assert self._handlers, "Got call of {}, but ran out of handlers!".format(function_name)
        # Get next handler
        handler = self._handlers.pop(0)
        # From *args and **kwargs, construct one dictionary of all arguments with the help of the ``funcsigs`` module.
        # This comes in handy because we do not have to differentiate between the following two equivalent calls:
        #   yesno("Hello?")
        #   yesno(text="Hello?")
        signature = PATCH_FUNCTION_SIGNATURES[function_name]
        kwds = signature.bind(*args, **kwargs).arguments
        return handler(function_name, kwds)

    def _answer_choice(self, function, answer):
        def _choose_result(kwds):
            if answer is None:
                return dialog.Dialog.CANCEL, ''
            else:
                return dialog.Dialog.OK, _match_choices(answer, kwds['choices'])
        return self.expect(function).result(_choose_result)

    def _start_mock(self, function_name):
        patcher = mock.patch.object(dialog.Dialog, function_name,
                                    autospec=True,
                                    side_effect=partial(self._side_effect_handler, function_name))
        patcher.start()
        return patcher

    @contextmanager
    def simulate(self):
        """
        Context manager that activate all mocks and simulate the user behavior. Example::

            behavior = UserBehavior()
            behavior.answer_yesno(False)
            with behavior.simulate():
                d = Dialog()
                code = d.yesno("Hello?")
                assert code == Dialog.CANCEL

        :return:
        """
        patchers = [self._start_mock(function) for function in PATCH_FUNCTIONS]
        try:
            yield
        finally:
            for patcher in patchers:
                patcher.stop()