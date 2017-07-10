import dialog


class ExtDialog(dialog.Dialog):
    def choice(self, text, height=15, width=54, menu_height=7,
               choices=None, current=None, current_template='{} (current)',
               **kwargs):
        """
        Extended version of ``menu``. Given a list of value choices,
        let the user choose one value. Additionally highlight the currently chosen item.

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
        :param current: The currently chosen value (the item will be highlighted)
        :param current_template: A format string which is used to highlight the current item
        :param kwargs:
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
            # if this happens to be the current choice, add a hint
            if current == return_value:
                tag = current_template.format(tag)
            # collect return value associated to the tag
            return_values[tag] = return_value
            processed_choices.append((tag,) + rest)
        code, result = self.menu(text, height, width, menu_height, processed_choices, **kwargs)
        if code != self.DIALOG_OK:
            return None
        return return_values[result]