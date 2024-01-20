from Utils import utils
# TODO - refactor according to new protocol


class ProtocolConstants:

    SERVER_VERSION = 24

    # Default sizes
    SIZE_DEFAULT = 0
    SIZE_CLIENT_ID = 16
    SIZE_VERSION = 1
    SIZE_CODE = 2
    SIZE_PAYLOAD = 4
    SIZE_CLIENT_NAME = 255
    SIZE_PASSWORD = 255
    SIZE_AES_KEY = 32
    SIZE_IV = 16
    SIZE_SERVER_ID = 16
    SIZE_NONCE = 8
    SIZE_SERVER_NAME = 255
    SIZE_EXPIRATION_TIME = 4
    SIZE_TIMESTAMP = 4
    SIZE_MSG = 4

    # Request codes
    REQ_CLIENT_REG = 1025
    REQ_MSG_SERVERS_LIST = 1026
    REQ_SERVER_REG = 1027
    REQ_AES_KEY = 1028
    REQ_SEND_MSG = 1029

    # Response codes
    RES_REGISTER_SUCCESS = 1600
    RES_REGISTER_FAILED = 1601
    RES_MSG_SERVERS_LIST = 1602
    RES_ENCRYPTED_AES_KEY = 1603
    RES_AES_KEY_ACK = 1604
    RES_MSG_ACK = 1605
    RES_GENERAL_ERROR = 1609

    # Auxiliary list for no payload responses
    NO_PAYLOAD_CODE_RESPONSES = [RES_REGISTER_FAILED, RES_AES_KEY_ACK, RES_MSG_ACK, RES_GENERAL_ERROR]


# Request default packet structure
server_request = {
    "client_id": {"size": ProtocolConstants.SIZE_CLIENT_ID, "type": str, "content": None},
    "version": {"size": ProtocolConstants.SIZE_VERSION, "type": int, "content": None},
    "code": {"size": ProtocolConstants.SIZE_CODE, "type": int, "content": None},
    "payload_size": {"size": ProtocolConstants.SIZE_PAYLOAD, "type": int, "content": None}
}

server_response = {
    "version": {"size": ProtocolConstants.SIZE_VERSION, "type": int, "content": None},
    "code": {"size": ProtocolConstants.SIZE_CODE, "type": int, "content": None},
    "payload_size": {"size": ProtocolConstants.SIZE_PAYLOAD, "type": int, "content": None}
}

code_to_payload_template = {

    # 1025
    ProtocolConstants.REQ_CLIENT_REG: {
        "name": {"size": ProtocolConstants.SIZE_CLIENT_NAME, "type": str, "content": None},
        "password": {"size": ProtocolConstants.SIZE_PASSWORD, "type": str, "content": None}
    },

    # 1600
    ProtocolConstants.RES_REGISTER_SUCCESS: {
        "client_id": {"size": ProtocolConstants.SIZE_CLIENT_ID, "type": bytes, "content": None}
    }

    # 1601

}

packet_formatter_template = {
    1: 'B',
    2: 'H',
    4: 'I',
    bytes: 's',
    "little_endian": '<'
}