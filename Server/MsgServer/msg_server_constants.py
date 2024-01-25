from os import path as os_path


class Constants:

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

    # TODO - refactor to protocol constants
    # TODO - create server_constants file instead of msg and auth constants
    # Service Manager
    FMT_ME = '{}'
    SERVICE_POOL_FILE_NAME = "services_pool.json"
    CONNECTION_PROTOCOL = "connection_protocol"
    IP_ADDRESS = "ip_address"
    AUTH_PORT = "auth_port"
    MSG_PORT = "msg_port"
    SERVICE_NAME = "service_name"
    SERVICE_ID = "server_id"
    IS_REGISTERED = "is_registered"
    TICKET_IV = "ticket_iv"
    AES_KEY = "aes_key"
    MSG_IV = "msg_iv"

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
ram_service_template = {
    Constants.SERVICE_ID: Constants.FMT_ME,
    Constants.SERVICE_NAME: Constants.FMT_ME,
    Constants.TICKET_IV: Constants.FMT_ME,
    Constants.AES_KEY: Constants.FMT_ME,
    Constants.MSG_IV: Constants.FMT_ME,
    Constants.IS_REGISTERED: Constants.FMT_ME
}

service_manager_template = {
    Constants.CONNECTION_PROTOCOL: Constants.FMT_ME,
    Constants.IP_ADDRESS: Constants.FMT_ME,
    Constants.AUTH_PORT: Constants.FMT_ME,
    Constants.MSG_PORT: Constants.FMT_ME,
    Constants.SERVICE_ID: Constants.FMT_ME,
    Constants.SERVICE_NAME: Constants.FMT_ME,
    Constants.TICKET_IV: Constants.FMT_ME,
    Constants.AES_KEY: Constants.FMT_ME,
    Constants.MSG_IV: Constants.FMT_ME,
    Constants.IS_REGISTERED: Constants.FMT_ME
}
