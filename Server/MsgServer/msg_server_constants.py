from os import path as os_path


class Constants:


    PORT_FILE_NAME = f"{os_path.join(os_path.dirname(os_path.abspath(__file__)))}\port.info"


    MSG_FILE_NAME = "msg.info"
    MSG_FILE_PATH = f"{os_path.join(os_path.dirname(os_path.abspath(__file__)))}\{MSG_FILE_NAME}"

    SERVICE_POOL_FILE_NAME = "services_pool.json"

    DEF_IP_ADDRESS = '127.0.0.1'
    DEF_PORT_NUM = 1234
    DEF_SERVER_NAM_FMT = "Printer "

    # TODO - refactor to protocol constants
    # TODO - create server_constants file instead of msg and auth constants
    # Service Manager
    FMT_ME = '{}'

    CONNECTION_PROTOCOL = "connection_protocol"
    AUTH_PORT = "auth_port"

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


# Dictionary format for saving clients data in RAM memory
ram_service_template = {
    Constants.RAM_SERVICE_ID: Constants.FMT_ME,
    Constants.RAM_SERVICE_ID_HEX: Constants.FMT_ME,
    Constants.RAM_SERVICE_NAME: Constants.FMT_ME,
    Constants.RAM_TICKET_IV: Constants.FMT_ME,
    Constants.RAM_AES_KEY: Constants.FMT_ME,
    Constants.RAM_AES_KEY_HEX: Constants.FMT_ME,
    Constants.RAM_MESSAGE_IV: Constants.FMT_ME,
    Constants.RAM_IS_REGISTERED: Constants.FMT_ME
}

service_manager_template = {
    Constants.CONNECTION_PROTOCOL: Constants.FMT_ME,
    Constants.RAM_IP_ADDRESS: Constants.FMT_ME,
    Constants.AUTH_PORT: Constants.FMT_ME,
    Constants.RAM_PORT: Constants.FMT_ME,
    Constants.RAM_SERVICE_ID_HEX: Constants.FMT_ME,
    Constants.RAM_SERVICE_NAME: Constants.FMT_ME,
    Constants.RAM_TICKET_IV: Constants.FMT_ME,
    Constants.RAM_AES_KEY_HEX: Constants.FMT_ME,
    Constants.RAM_MESSAGE_IV: Constants.FMT_ME,
    Constants.RAM_IS_REGISTERED: Constants.FMT_ME
}
