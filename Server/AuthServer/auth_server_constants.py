from os import path as os_path


class Constants:

    # Parsing related constants
    CONSOLE_ACK = "[+]"
    CONSOLE_FAIL = "[-]"
    CONSOLE_ERROR = "[!]"

    # Port related constants
    PORT_FILE_NAME = f"{os_path.join(os_path.dirname(os_path.abspath(__file__)))}\port.info"
    PORT_DEFAULT_NUM = 1256

    # RAM template constants
    FMT_ME = '{}'
    ID = "ID"
    CLIENT_NAME = "Client_Name"
    PUBLIC_KEY = "Public_Key"
    PUBLIC_KEY_LENGTH = "Public_Key_Length"
    LAST_SEEN = "Last_Seen"
    AES_KEY = "AES_Key"
    AES_KEY_LENGTH = "AES_Key_Length"
    ENCRYPTED_AES_KEY = "Encrypted_AES_Key"
    ENCRYPTED_AES_KEY_LENGTH = "Encrypted_AES_Key_Length"

    AUTH_SERVER_LOGO = """
         _         _   _       ____                           
        / \  _   _| |_| |__   / ___|  ___ _ ____   _____ _ __ 
       / _ \| | | | __| '_ \  \___ \ / _ \ '__\ \ / / _ \ '__|
      / ___ \ |_| | |_| | | |  ___) |  __/ |   \ V /  __/ |   
     /_/   \_\__,_|\__|_| |_| |____/ \___|_|    \_/ \___|_|   
    """


"""
Auxiliary data structures templates.
"""

# Dictionary format for saving clients data in RAM memory
ram_clients_template = {
    Constants.ID: Constants.FMT_ME,
    Constants.CLIENT_NAME: Constants.FMT_ME,
    Constants.PUBLIC_KEY: Constants.FMT_ME,
    Constants.PUBLIC_KEY_LENGTH: Constants.FMT_ME,
    Constants.LAST_SEEN: Constants.FMT_ME,
    Constants.AES_KEY: Constants.FMT_ME,
    Constants.AES_KEY_LENGTH: Constants.FMT_ME,
    Constants.ENCRYPTED_AES_KEY: Constants.FMT_ME,
    Constants.ENCRYPTED_AES_KEY_LENGTH: Constants.FMT_ME
}

