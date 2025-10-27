import configparser

CONFIG_FILE = "analytics_configs.ini"
PASSWORDS_SECTION = "passwords"
PASSWORDS_WEAK_SUBSECTION = "weak"
PROTOCOLS_SECTION = "protocols"
PROTOCOLS_CLEARTEXT_SUBSECTION = "cleartext"

config = configparser.ConfigParser()
config.read(CONFIG_FILE)

def GetWeakPasswords():
    return frozenset([config[PASSWORDS_SECTION][PASSWORDS_WEAK_SUBSECTION].split('\n')[1::]])

def GetClearTextProtocols():
    return frozenset([config[PROTOCOLS_SECTION][PROTOCOLS_CLEARTEXT_SUBSECTION].split('\n')[1::]])
