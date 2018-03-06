"""
helper script to test the tinc configuration
"""

from authappliance.menu import MainMenu
from testutil import ApplianceBehavior

behavior = ApplianceBehavior()
behavior.navigate('Database', 'setup redundancy')
# remote ip
behavior.answer_inputbox('192.168.33.202')
# remote password
behavior.answer_passwordbox('test')
# local ip
behavior.answer_inputbox('192.168.33.201')
# yes and yes
behavior.answer_yesno(True)
behavior.answer_yesno(True)

with behavior.simulate():
    menu = MainMenu()
    menu.main_menu()
