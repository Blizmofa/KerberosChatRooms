

class ProtoConsts:

    SERVER_VERSION = 24
    DEF_EXPIRATION_TIME_LENGTH = 1
    DEF_SLEEP_TIME = 2
    DEF_PORT_NUM = 8000
    STATUS_ERROR_CODE = 1
    STATUS_NO_ERROR_CODE = 0
    LOCAL_HOST = "127.0.0.1"
    FMT_ME = '{}'

    # Parsing related constants
    CONSOLE_ACK = "[+]"
    CONSOLE_FAIL = "[-]"
    CONSOLE_ERROR = "[!]"

    # Default sizes
    SIZE_CLIENT_ID = 16
    SIZE_ENC_CLIENT_ID = 32
    SIZE_VERSION = 1
    SIZE_ENC_VERSION = 16
    SIZE_CODE = 2
    SIZE_PAYLOAD = 4
    SIZE_CLIENT_NAME = 255
    SIZE_PASSWORD = 255
    SIZE_AES_KEY = 32
    SIZE_ENC_AES_KEY = 48
    SIZE_IV = 16
    SIZE_ENC_IV = 16
    SIZE_AUTH_IV = 16
    SIZE_SERVER_ID = 16
    SIZE_ENC_SERVER_ID = 32
    SIZE_SERVER_IP = 4
    SIZE_SERVER_PORT = 2
    SIZE_NONCE = 8
    SIZE_ENC_NONCE = 16
    SIZE_SERVER_NAME = 255
    SIZE_CREATION_TIME = 8
    SIZE_ENC_CREATION_TIME = 32
    SIZE_ENC_EXPIRATION_TIME = 32
    SIZE_MSG = 4
    SIZE_SERVER_LIST_ENTRY = 277
    SIZE_ENCRYPTED_KEY_PACKET = 80
    SIZE_TICKET_PACKET = 161
    SIZE_AUTHENTICATOR_PACKET = 128

    # Request codes
    REQ_CLIENT_REG = 1024
    REQ_SERVER_REG = 1025
    REQ_MSG_SERVERS_LIST = 1026
    REQ_AES_KEY = 1027
    REQ_MSG_SERVER_AES_KEY = 1028
    REQ_SEND_MSG = 1029

    # Response codes
    RES_REGISTER_SUCCESS = 1600
    RES_REGISTER_FAILED = 1601
    RES_MSG_SERVERS_LIST = 1602
    RES_ENCRYPTED_AES_KEY = 1603
    RES_AES_KEY_ACK = 1604
    RES_MSG_ACK = 1605
    RES_GENERAL_ERROR = 1609

    # Packed packets auxiliary codes
    PKT_SERVERS_LIST = 1700
    PKT_ENCRYPTED_KEY = 1701
    PKT_TICKET = 1702
    PKT_AUTHENTICATOR = 1703
    PKT_NOT_REGISTERED_ERROR = 1704
    PKT_ENC_MSG_WITHOUT_CONTENT = 1705

    # Auxiliary lists
    NO_PAYLOAD_CODE_RESPONSES = [REQ_MSG_SERVERS_LIST, RES_REGISTER_FAILED, RES_AES_KEY_ACK,
                                 RES_MSG_ACK, RES_GENERAL_ERROR, PKT_NOT_REGISTERED_ERROR]
    PACKED_PKT_CODE_RESPONSES = [RES_MSG_SERVERS_LIST, RES_ENCRYPTED_AES_KEY]

    # Protocol naming constants
    CLIENT_ID = "client_id"
    VERSION = "version"
    CODE = "code"
    PAYLOAD_SIZE = "payload_size"
    NAME = "name"
    PASSWORD = "password"
    AES_KEY = "aes_key"
    SERVER_ID = "server_id"
    NONCE = "nonce"
    SERVER_NAME = "server_name"
    SERVER_IP = "server_ip"
    SERVER_PORT = "server_port"
    SERVERS_LIST = "servers_list"
    ENCRYPTED_KEY = "encrypted_key"
    ENCRYPTED_KEY_IV = "encrypted_key_iv"
    CREATION_TIME = "creation_time"
    TICKET = "ticket"
    TICKET_IV = "ticket_iv"
    AUTHENTICATOR = "authenticator"
    AUTHENTICATOR_IV = "authenticator_iv"
    EXPIRATION_TIME = "expiration_time"
    MSG_SIZE = "msg_size"
    MSG_IV = "msg_iv"
    MSG_CONTENT = "msg_content"
    UTF_8 = "utf-8"
    SIZE = "size"
    TYPE = "type"
    CONTENT = "content"
    PROTO_TCP = "tcp"
    PROTO_UDP = "udp"
    IPV4 = "ipv4"
    SERIALIZE = "serialize"
    DESERIALIZE = "deserialize"
    LITTLE_ENDIAN = "little_endian"
