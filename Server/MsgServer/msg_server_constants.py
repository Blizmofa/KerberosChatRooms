from os import path as os_path


class MsgConsts:

    DEF_IP_ADDRESS = '127.0.0.1'
    DEF_PORT_NUM = 1234
    DEF_SERVER_NAME_FMT = "Printer "
    DEF_SERVER_NAME = "Printer 1"
    LINE_IP_PORT = 1
    LINE_NAME = 2
    LINE_ID = 3
    LINE_AES_KEY = 4

    # Files constants
    PORT_FILE_NAME = f"{os_path.join(os_path.dirname(os_path.abspath(__file__)))}\port.info"
    MSG_FILE_NAME = "msg.info"
    MSG_FILE_PATH = f"{os_path.join(os_path.dirname(os_path.abspath(__file__)))}\{MSG_FILE_NAME}"
    SERVICE_POOL_FILE_NAME = "services_pool.json"

    # Service Manager
    CONNECTION_PROTOCOL = "connection_protocol"
    AUTH_PORT = "auth_port"

    # TODO - refactor to protocol constants
    # TODO - create server_constants file instead of msg and auth constants

    # RAM Template constants
    FMT_ME = '{}'
    RAM_SERVICE_NAME = "service_name"
    RAM_SERVICE_ID = "server_id"
    RAM_SERVICE_ID_HEX = "server_id_hex"
    RAM_IS_REGISTERED = "is_registered"
    RAM_TICKET_IV = "ticket_iv"
    RAM_AES_KEY = "aes_key"
    RAM_AES_KEY_HEX = "aes_key_hex"
    RAM_MESSAGE_IV = "message_iv"
    RAM_PORT = "port"
    RAM_IP_ADDRESS = "ip_address"

    MSG_SERVER_LOGO = """
           \/  |            / ____|                         
        | \  / |___  __ _  | (___   ___ _ ____   _____ _ __ 
        | |\/| / __|/ _` |  \___ \ / _ \ '__\ \ / / _ \ '__|
        | |  | \__ \ (_| |  ____) |  __/ |   \ V /  __/ |   
        |_|  |_|___/\__, | |_____/ \___|_|    \_/ \___|_|   
                    __/ |                                  
                    |___/                                   
    """

    WELCOME_MSG = """
    {}
    Welcome to '{}' chat room.
    """


# Dictionary format for saving service data in RAM memory
ram_service_template = {
    MsgConsts.RAM_SERVICE_ID: MsgConsts.FMT_ME,
    MsgConsts.RAM_SERVICE_ID_HEX: MsgConsts.FMT_ME,
    MsgConsts.RAM_SERVICE_NAME: MsgConsts.FMT_ME,
    MsgConsts.RAM_TICKET_IV: MsgConsts.FMT_ME,
    MsgConsts.RAM_AES_KEY: MsgConsts.FMT_ME,
    MsgConsts.RAM_AES_KEY_HEX: MsgConsts.FMT_ME,
    MsgConsts.RAM_MESSAGE_IV: MsgConsts.FMT_ME,
    MsgConsts.RAM_IS_REGISTERED: MsgConsts.FMT_ME
}

# Dictionary format for saving services data in a JSON file
service_manager_template = {
    MsgConsts.CONNECTION_PROTOCOL: MsgConsts.FMT_ME,
    MsgConsts.RAM_IP_ADDRESS: MsgConsts.FMT_ME,
    MsgConsts.AUTH_PORT: MsgConsts.FMT_ME,
    MsgConsts.RAM_PORT: MsgConsts.FMT_ME,
    MsgConsts.RAM_SERVICE_ID_HEX: MsgConsts.FMT_ME,
    MsgConsts.RAM_SERVICE_NAME: MsgConsts.FMT_ME,
    MsgConsts.RAM_TICKET_IV: MsgConsts.FMT_ME,
    MsgConsts.RAM_AES_KEY_HEX: MsgConsts.FMT_ME,
    MsgConsts.RAM_MESSAGE_IV: MsgConsts.FMT_ME,
    MsgConsts.RAM_IS_REGISTERED: MsgConsts.FMT_ME
}
