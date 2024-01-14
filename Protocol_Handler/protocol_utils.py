
class ProtocolConstants:

    SERVER_VERSION = 3

    # Default sizes
    DEFAULT_VALUE = 0
    SERVER_RECEIVE_BUFFER_SIZE = 1024
    CLIENT_UUID_SIZE = 16
    CLIENT_PUBKEY_SIZE = 160
    CLIENT_FILE_NAME_SIZE = 255
    SERVER_AES_KEY_SIZE = 16
    SERVER_ENCRYPTED_AES_KEY_SIZE = 128
    FILE_CONTENT_SIZE = 4
    CRC_SIZE = 4
    CRC_RE_RECEIVE_MAX = 3
    CRC_CHUNK_SIZE = 3
    ENCRYPTED_FILE_NAME_SUFFIX = 4

    # Packet indexes
    CLIENT_ID_INDEX = 0
    CLIENT_VERSION_INDEX = 1
    CLIENT_REQUEST_CODE_INDEX = 2
    CLIENT_PAYLOAD_SIZE_INDEX = 3
    CLIENT_USERNAME_INDEX = 4
    CLIENT_PUBKEY_INDEX = 5
    CLIENT_FILE_REQUEST_CONTENT_SIZE_INDEX = 5
    CLIENT_FILE_NAME_INDEX = 6

    # Client request codes
    CLIENT_REG_REQUEST = 1100
    CLIENT_PUBKEY_REQUEST = 1101
    CLIENT_ENCRYPTED_FILE_REQUEST = 1103
    CLIENT_VALID_CRC_REQUEST = 1104
    CLIENT_INVALID_CRC_REQUEST = 1105
    CLIENT_INVALID_CRC_FOURTH_TIME_REQUEST = 1106
    CLIENT_UNPACK_CRC_REQUEST_CODE = 1111

    # Packet unpack/pack formats
    UNPACK_DEFAULT_FORMAT = "<16sBHI"
    PACK_DEFAULT_FORMAT = "BHI"

    # Server response codes and strings
    SERVER_REG_SUCCESS_RESPONSE = 2100
    SERVER_REG_FAILED_RESPONSE = 2101
    SERVER_ENCRYPTED_KEY_RESPONSE = 2102
    SERVER_FILE_CRC_RESPONSE = 2103
    SERVER_ACK_RESPONSE = 2104
    SERVER_RESPONSE_CODE_STR = "response_code"
    SERVER_PAYLOAD_SIZE_STR = "payload_size"


# Auxiliary template for client payload sizes according to the different request codes
client_request_template = {
    ProtocolConstants.CLIENT_REG_REQUEST: '255s',
    ProtocolConstants.CLIENT_PUBKEY_REQUEST: '255s160s',
    ProtocolConstants.CLIENT_ENCRYPTED_FILE_REQUEST: '16sI255s',
    ProtocolConstants.CLIENT_UNPACK_CRC_REQUEST_CODE: '16s255s'
}

# Auxiliary template for server response codes and payload sizes
server_response_template = {

    # For response 2100
    ProtocolConstants.SERVER_REG_SUCCESS_RESPONSE: {
        ProtocolConstants.SERVER_RESPONSE_CODE_STR: ProtocolConstants.SERVER_REG_SUCCESS_RESPONSE,
        ProtocolConstants.SERVER_PAYLOAD_SIZE_STR: ProtocolConstants.CLIENT_UUID_SIZE
    },

    # For response 2101
    ProtocolConstants.SERVER_REG_FAILED_RESPONSE: {
        ProtocolConstants.SERVER_RESPONSE_CODE_STR: ProtocolConstants.SERVER_REG_FAILED_RESPONSE,
        ProtocolConstants.SERVER_PAYLOAD_SIZE_STR: ProtocolConstants.DEFAULT_VALUE
    },

    # For response 2102
    ProtocolConstants.SERVER_ENCRYPTED_KEY_RESPONSE: {
        ProtocolConstants.SERVER_RESPONSE_CODE_STR: ProtocolConstants.SERVER_ENCRYPTED_KEY_RESPONSE,
        ProtocolConstants.SERVER_PAYLOAD_SIZE_STR: ProtocolConstants.CLIENT_UUID_SIZE + ProtocolConstants.SERVER_ENCRYPTED_AES_KEY_SIZE
    },

    # For response 2103
    ProtocolConstants.SERVER_FILE_CRC_RESPONSE: {
        ProtocolConstants.SERVER_RESPONSE_CODE_STR: ProtocolConstants.SERVER_FILE_CRC_RESPONSE,
        ProtocolConstants.SERVER_PAYLOAD_SIZE_STR: ProtocolConstants.CLIENT_UUID_SIZE +
                                                   ProtocolConstants.FILE_CONTENT_SIZE +
                                                   ProtocolConstants.CLIENT_FILE_NAME_SIZE +
                                                   ProtocolConstants.CRC_SIZE
    },

    # For response 2104
    ProtocolConstants.SERVER_ACK_RESPONSE: {
        ProtocolConstants.SERVER_RESPONSE_CODE_STR: ProtocolConstants.SERVER_ACK_RESPONSE,
        ProtocolConstants.SERVER_PAYLOAD_SIZE_STR: ProtocolConstants.DEFAULT_VALUE
    }
}
