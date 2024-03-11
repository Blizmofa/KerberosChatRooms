from os import path as os_path


class MsgConsts:

    DEF_IP_ADDRESS = '127.0.0.1'
    DEF_PORT_NUM = 1234
    DEF_SERVER_NAME_PREFIX = "Printer "
    DEF_SERVER_NAME = "Printer 1"
    DEF_SLEEP_TIME = 5
    DEF_INDENT_LVL = 2
    MAX_NUM_OF_SERVICES = 10
    LINE_IP_PORT = 1
    LINE_NAME = 2
    LINE_ID = 3
    LINE_AES_KEY = 4

    # Files constants
    PORT_FILE_NAME = "port.info"
    PORT_FILE_PATH = f"{os_path.join(os_path.dirname(os_path.abspath(__file__)))}\{PORT_FILE_NAME}"
    MSG_FILE_NAME = "msg.info"
    SERVICE_POOL_FILE_NAME = "services_pool.json"
    SERVICE_POOL_FILE_PATH = f"{os_path.join(os_path.dirname(os_path.abspath(__file__)))}\{SERVICE_POOL_FILE_NAME}"

    # Service Manager
    CONNECTION_PROTOCOL = "connection_protocol"
    KDC_PORT = "kdc_port"

    # RAM Template constants
    FMT_ME = '{}'
    RAM_SERVICE_NAME = "service_name"
    RAM_SERVICE_ID = "server_id"
    RAM_SERVICE_ID_HEX = "server_id_hex"
    RAM_IS_REGISTERED = "is_registered"
    RAM_TICKET_IV = "ticket_iv"
    RAM_SERVICE_AES_KEY = "service_aes_key"
    RAM_SERVICE_AES_KEY_ENCODED = "service_aes_key_encoded"
    RAM_KDC_AES_KEY = "kdc_service_aes_key"
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
    MsgConsts.RAM_SERVICE_AES_KEY: MsgConsts.FMT_ME,
    MsgConsts.RAM_SERVICE_AES_KEY_ENCODED: MsgConsts.FMT_ME,
    MsgConsts.RAM_KDC_AES_KEY: MsgConsts.FMT_ME,
    MsgConsts.RAM_MESSAGE_IV: MsgConsts.FMT_ME,
    MsgConsts.RAM_IS_REGISTERED: MsgConsts.FMT_ME
}

# Dictionary format for saving services data in a JSON file
service_manager_template = {
    MsgConsts.CONNECTION_PROTOCOL: MsgConsts.FMT_ME,
    MsgConsts.RAM_IP_ADDRESS: MsgConsts.FMT_ME,
    MsgConsts.KDC_PORT: MsgConsts.FMT_ME,
    MsgConsts.RAM_PORT: MsgConsts.FMT_ME,
    MsgConsts.RAM_SERVICE_ID_HEX: MsgConsts.FMT_ME,
    MsgConsts.RAM_SERVICE_NAME: MsgConsts.FMT_ME,
    MsgConsts.RAM_TICKET_IV: MsgConsts.FMT_ME,
    MsgConsts.RAM_SERVICE_AES_KEY_ENCODED: MsgConsts.FMT_ME,
    MsgConsts.RAM_IS_REGISTERED: MsgConsts.FMT_ME
}
