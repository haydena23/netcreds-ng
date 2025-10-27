import configparser
import os

CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))
CONFIG_FILE = "analytics_configs.ini"
PASSWORDS_SECTION = "passwords"
PASSWORDS_WEAK_SUBSECTION = "weak"
PROTOCOLS_SECTION = "protocols"
PROTOCOLS_CLEARTEXT_SUBSECTION = "cleartext"

config = configparser.ConfigParser()
config.read(os.path.join(CURRENT_DIR, CONFIG_FILE))

def GetWeakPasswords():
    return frozenset(config[PASSWORDS_SECTION][PASSWORDS_WEAK_SUBSECTION].split('\n')[1::])

def GetClearTextProtocols():
    return frozenset(config[PROTOCOLS_SECTION][PROTOCOLS_CLEARTEXT_SUBSECTION].split('\n')[1::])
