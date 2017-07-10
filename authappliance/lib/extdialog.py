import dialog


class ExtDialog(dialog.Dialog):
    def value_menu(self, text, height=15, width=54, menu_height=7,
                   choices=None, **kwargs):
        """
        Extended version of ``menu``. Given a list of value choices, let the user choose a value.
        This function may be handy because it allows to separate tags and return values.

        ``choices`` is a list of tuples like::

            [(return_value1, tag1, item1),
             (return_value2, tag2, item2),
             ...]

        or, in case ``item_help=True`` is passed::

            [(return_value1, tag1, item1, help1),
             ...]

        :param text: see ``menu``
        :param height: see ``menu``
        :param width: see ``menu``
        :param menu_height: see ``menu``
        :param choices: A list of tuples [(return_value1, tag1, ...), ...]
        :return: The value specified in ``choices`` of the chosen item, or None if the user did not choose anything.
        """
        if choices is None:
            choices = []
        return_values = {}
        # preprocess ``choices`` to pass them to ``Dialog.menu``
        processed_choices = []
        for choice in choices:
            return_value, tag = choice[0], choice[1]
            rest = choice[2:]
            # collect return value associated to the tag
            return_values[tag] = return_value
            processed_choices.append((tag,) + rest)
        code, result = self.menu(text, height, width, menu_height, processed_choices, **kwargs)
        if code != self.DIALOG_OK:
            return None
        return return_values[result]

    def value_radiolist(self, text, height=15, width=54, menu_height=7,
                        choices=None, current=None,
                        **kwargs):
        """
        Extended version of ``radiolist``. Given a list of value choices, let the user choose a value.
        This function may be handy because it allows to separate tags and return values.

        ``choices`` is a list of tuples like::

            [(return_value1, tag1, item1),
             (return_value2, tag2, item2),
             ...]

        or, in case ``item_help=True`` is passed::

            [(return_value1, tag1, item1, help1),
             ...]

        In contrast to ``radiolist``, the current value is given in the parameter ``current``.
        If ``current`` is not found in any choice, the first item is preselected.

        :param text: see ``menu``
        :param height: see ``menu``
        :param width: see ``menu``
        :param menu_height: see ``menu``
        :param choices: A list of tuples [(return_value1, tag1, ...), ...]
        :param current: The currently chosen value (the item will be highlighted)
        :return: The value specified in ``choices`` of the chosen item, or None if the user did not choose anything.
        """
        if choices is None:
            choices = []
        assert len(choices) > 0
        return_values = {}
        # find out if we have to preselect the first choice
        if all(choice[0] != current for choice in choices):
            current = choices[0][0]
        # preprocess ``choices`` to pass them to ``Dialog.menu``
        processed_choices = []
        for choice in choices:
            return_value, tag = choice[0], choice[1]
            rest = choice[2:]
            # collect return value associated to the tag
            return_values[tag] = return_value
            # if this happens to be the current choice, preselect it
            preselect = current == return_value
            # the following line is somewhat weird: in case ``item_help=True`` is passed,
            # the choices list needs to look like that:
            # [(tag, desc, status, help), ...]
            processed_choices.append((tag, rest[0], preselect) + rest[1:])
        code, result = self.radiolist(text, height, width, menu_height, processed_choices, **kwargs)
        if code != self.DIALOG_OK:
            return None
        return return_values[result]