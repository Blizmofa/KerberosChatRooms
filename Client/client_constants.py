from os import path as os_path
from Utils.validator import ValConsts as ValConsts


class CConsts:

    SERVER_GENERAL_ERROR = "server responded with an error"

    # Client files constants
    CLIENT_FILE_NAME = "me.info"
    CLIENT_FILE_PATH = f"{os_path.abspath(CLIENT_FILE_NAME)}"
    # TODO - create srv.info with auth server ip:port only
    AUTH_SERVER_FILE_NAME = "srv.info"
    # TODO - move services_file to client directory
    SERVICES_FILE_NAME = "services_info.json"
    CLIENT_IP_PORT_LINE = 1
    CLIENT_NAME_LINE = 1
    CLIENT_ID_LINE = 2
    CLIENT_FILE_MAX_LINES = 2

    # Client input constants
    IN_REQ_REGISTER = 1
    IN_REQ_SERVICES_LIST = 2
    IN_REQ_AES_KEY_CONNECT = 3
    IN_QUIT = 4

    # RAM Template constants
    FMT_ME = '{}'
    RAM_USERNAME = "username"
    RAM_PASSWORD = "password"
    RAM_PASSWORD_HASH = "password_hash"
    RAM_CLIENT_ID = "client_id"
    RAM_CLIENT_ID_HEX = "client_id_hex"
    RAM_IS_REGISTERED = "is_registered"
    RAM_NONCE = "nonce"
    RAM_SERVER_ID = "server_id"
    RAM_SERVER_ID_HEX = "server_id_hex"
    RAM_SERVER_NAME = "server_name"
    RAM_SERVER_IP = "server_ip"
    RAM_SERVER_PORT = "server_port"
    RAM_AUTH_IV = "authenticator_iv"
    RAM_MESSAGE_IV = "message_iv"
    RAM_AES_KEY = "aes_key"
    RAM_ENCRYPTED_KEY_IV = "encrypted_key_iv"
    RAM_TICKET = "ticket"


me_info_default_data = {
    ValConsts.FMT_NAME: 'Michael Jackson'
}

# Dictionary format for saving client data in RAM memory
client_ram_template = {
    CConsts.RAM_USERNAME: CConsts.FMT_ME,
    CConsts.RAM_PASSWORD: CConsts.FMT_ME,
    CConsts.RAM_PASSWORD_HASH: CConsts.FMT_ME,
    CConsts.RAM_CLIENT_ID: CConsts.FMT_ME,
    CConsts.RAM_CLIENT_ID_HEX: CConsts.FMT_ME,
    CConsts.RAM_IS_REGISTERED: CConsts.FMT_ME,
    CConsts.RAM_NONCE: CConsts.FMT_ME,
    CConsts.RAM_AES_KEY: CConsts.FMT_ME,
    CConsts.RAM_ENCRYPTED_KEY_IV: CConsts.FMT_ME,
    CConsts.RAM_AUTH_IV: CConsts.FMT_ME,
    CConsts.RAM_MESSAGE_IV: CConsts.FMT_ME
}

# Dictionary format for saving servers data in file DB
file_db_servers_template = {
    CConsts.RAM_SERVER_ID: CConsts.FMT_ME,
    CConsts.RAM_SERVER_NAME: CConsts.FMT_ME,
    CConsts.RAM_SERVER_IP: CConsts.FMT_ME,
    CConsts.RAM_SERVER_PORT: CConsts.FMT_ME,
    CConsts.RAM_AES_KEY: CConsts.FMT_ME,
    CConsts.RAM_ENCRYPTED_KEY_IV: CConsts.FMT_ME,
    CConsts.RAM_TICKET: CConsts.FMT_ME
}