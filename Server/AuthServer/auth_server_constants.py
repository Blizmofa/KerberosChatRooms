from os import path as os_path


class Constants:

    # Parsing related constants
    CONSOLE_ACK = "[+]"
    CONSOLE_FAIL = "[-]"
    CONSOLE_ERROR = "[!]"

    # Port related constants
    PORT_FILE_NAME = f"{os_path.join(os_path.dirname(os_path.abspath(__file__)))}\port.info"
    PORT_DEFAULT_NUM = 1256

    # Files related constants
    FILES_DIR_NAME = f"{os_path.join(os_path.dirname(os_path.abspath(__file__)))}\FILES"
    CLIENTS_FILE_NAME = f"{FILES_DIR_NAME}\clients.txt"
    SERVERS_FILE_NAME = f"{FILES_DIR_NAME}\servers.txt"

    # RAM template constants
    FMT_ME = '{}'
    ID = "ID"
    CLIENT_NAME = "Client_Name"
    PASSWORD_HASH = "Password_Hash"
    LAST_SEEN = "Last_Seen"
    AES_KEY = "Aes_Key"


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
    Constants.PASSWORD_HASH: Constants.FMT_ME,
    Constants.LAST_SEEN: Constants.FMT_ME
}

# Dictionary format for saving servers data in RAM memory
ram_servers_template = {
    Constants.ID: Constants.FMT_ME,
    Constants.CLIENT_NAME: Constants.FMT_ME,
    Constants.AES_KEY: Constants.FMT_ME
}

