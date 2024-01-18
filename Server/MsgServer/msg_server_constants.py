from os import path as os_path


class MsgServerConstants:

    # Parsing related constants
    CONSOLE_ACK = "[+]"
    CONSOLE_FAIL = "[-]"
    CONSOLE_ERROR = "[!]"

    # Port related constants
    PORT_FILE_NAME = f"{os_path.join(os_path.dirname(os_path.abspath(__file__)))}\port.info"
    PORT_DEFAULT_NUM = 1234
    
    # Msg data related constants
    MSG_FILE_NAME = "msg.info"
    MSG_FILE_PATH = f"{os_path.join(os_path.dirname(os_path.abspath(__file__)))}\{MSG_FILE_NAME}"

    # RAM template constants
    FMT_ME = '{}'
    ID = "ID"
    CLIENT_NAME = "Client_Name"
    PASSWORD_HASH = "Password_Hash"
    LAST_SEEN = "Last_Seen"
    AES_KEY = "Aes_Key"


    MSG_SERVER_LOGO = """
           \/  |            / ____|                         
        | \  / |___  __ _  | (___   ___ _ ____   _____ _ __ 
        | |\/| / __|/ _` |  \___ \ / _ \ '__\ \ / / _ \ '__|
        | |  | \__ \ (_| |  ____) |  __/ |   \ V /  __/ |   
        |_|  |_|___/\__, | |_____/ \___|_|    \_/ \___|_|   
                    __/ |                                  
                    |___/                                   
    """

    
# Dictionary format for saving clients data in RAM memory
ram_clients_template = {
    MsgServerConstants.ID: MsgServerConstants.FMT_ME,
    MsgServerConstants.CLIENT_NAME: MsgServerConstants.FMT_ME,
    MsgServerConstants.PASSWORD_HASH: MsgServerConstants.FMT_ME,
    MsgServerConstants.LAST_SEEN: MsgServerConstants.FMT_ME
}

# Dictionary format for saving servers data in RAM memory
ram_servers_template = {
    MsgServerConstants.ID: MsgServerConstants.FMT_ME,
    MsgServerConstants.CLIENT_NAME: MsgServerConstants.FMT_ME,
    MsgServerConstants.AES_KEY: MsgServerConstants.FMT_ME
}

