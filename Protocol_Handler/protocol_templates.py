from Protocol_Handler.protocol_constants import ProtoConsts


# Request default packet structure
server_request = {
    ProtoConsts.CLIENT_ID: {ProtoConsts.SIZE: ProtoConsts.SIZE_CLIENT_ID, ProtoConsts.TYPE: str, ProtoConsts.CONTENT: None},
    ProtoConsts.VERSION: {ProtoConsts.SIZE: ProtoConsts.SIZE_VERSION, ProtoConsts.TYPE: int, ProtoConsts.CONTENT: None},
    ProtoConsts.CODE: {ProtoConsts.SIZE: ProtoConsts.SIZE_CODE, ProtoConsts.TYPE: int, ProtoConsts.CONTENT: None},
    ProtoConsts.PAYLOAD_SIZE: {ProtoConsts.SIZE: ProtoConsts.SIZE_PAYLOAD, ProtoConsts.TYPE: int, ProtoConsts.CONTENT: None}
}

# Response default packet structure
server_response = {
    ProtoConsts.VERSION: {ProtoConsts.SIZE: ProtoConsts.SIZE_VERSION, ProtoConsts.TYPE: int, ProtoConsts.CONTENT: None},
    ProtoConsts.CODE: {ProtoConsts.SIZE: ProtoConsts.SIZE_CODE, ProtoConsts.TYPE: int, ProtoConsts.CONTENT: None},
    ProtoConsts.PAYLOAD_SIZE: {ProtoConsts.SIZE: ProtoConsts.SIZE_PAYLOAD, ProtoConsts.TYPE: int, ProtoConsts.CONTENT: None}
}

# Generates the packet payload structure according to the code
code_to_payload_template = {

    # 1024
    ProtoConsts.REQ_CLIENT_REG: {
        ProtoConsts.NAME: {ProtoConsts.SIZE: ProtoConsts.SIZE_CLIENT_NAME, ProtoConsts.TYPE: str, ProtoConsts.CONTENT: None},
        ProtoConsts.PASSWORD: {ProtoConsts.SIZE: ProtoConsts.SIZE_PASSWORD, ProtoConsts.TYPE: str, ProtoConsts.CONTENT: None}
    },

    # 1025
    ProtoConsts.REQ_SERVER_REG: {
        ProtoConsts.NAME: {ProtoConsts.SIZE: ProtoConsts.SIZE_CLIENT_NAME, ProtoConsts.TYPE: str, ProtoConsts.CONTENT: None},
        ProtoConsts.AES_KEY: {ProtoConsts.SIZE: ProtoConsts.SIZE_AES_KEY, ProtoConsts.TYPE: bytes, ProtoConsts.CONTENT: None}
    },

    # 1027
    ProtoConsts.REQ_AES_KEY: {
        ProtoConsts.SERVER_ID: {ProtoConsts.SIZE: ProtoConsts.SIZE_SERVER_ID, ProtoConsts.TYPE: bytes, ProtoConsts.CONTENT: None},
        ProtoConsts.NONCE: {ProtoConsts.SIZE: ProtoConsts.SIZE_NONCE, ProtoConsts.TYPE: bytes, ProtoConsts.CONTENT: None}
    },

    # 1028
    ProtoConsts.REQ_MSG_SERVER_AES_KEY: {
        ProtoConsts.AUTHENTICATOR: {ProtoConsts.SIZE: ProtoConsts.FMT_ME, ProtoConsts.TYPE: bytes, ProtoConsts.CONTENT: None},
        ProtoConsts.TICKET: {ProtoConsts.SIZE: ProtoConsts.FMT_ME, ProtoConsts.TYPE: bytes, ProtoConsts.CONTENT: None},
    },

    # 1029
    ProtoConsts.REQ_SEND_MSG: {
        ProtoConsts.MSG_SIZE: {ProtoConsts.SIZE: ProtoConsts.SIZE_MSG, ProtoConsts.TYPE: int, ProtoConsts.CONTENT: None},
        ProtoConsts.MSG_IV: {ProtoConsts.SIZE: ProtoConsts.SIZE_IV, ProtoConsts.TYPE: bytes, ProtoConsts.CONTENT: None},
        ProtoConsts.MSG_CONTENT: {ProtoConsts.SIZE: ProtoConsts.FMT_ME, ProtoConsts.TYPE: bytes, ProtoConsts.CONTENT: None}
    },

    # 1600
    ProtoConsts.RES_REGISTER_SUCCESS: {
        ProtoConsts.CLIENT_ID: {ProtoConsts.SIZE: ProtoConsts.SIZE_CLIENT_ID, ProtoConsts.TYPE: bytes, ProtoConsts.CONTENT: None}
    },

    # 1602
    ProtoConsts.RES_MSG_SERVERS_LIST: {
        ProtoConsts.SERVER_ID: {ProtoConsts.SIZE: ProtoConsts.SIZE_SERVER_ID, ProtoConsts.TYPE: bytes, ProtoConsts.CONTENT: None},
        ProtoConsts.SERVER_NAME: {ProtoConsts.SIZE: ProtoConsts.SIZE_SERVER_NAME, ProtoConsts.TYPE: str, ProtoConsts.CONTENT: None},
        ProtoConsts.SERVER_IP: {ProtoConsts.SIZE: ProtoConsts.SIZE_SERVER_IP, ProtoConsts.TYPE: 'ipv4', ProtoConsts.CONTENT: None},
        ProtoConsts.SERVER_PORT: {ProtoConsts.SIZE: ProtoConsts.SIZE_SERVER_PORT, ProtoConsts.TYPE: int, ProtoConsts.CONTENT: None}
    },

    # 1603
    ProtoConsts.RES_ENCRYPTED_AES_KEY: {
        ProtoConsts.CLIENT_ID: {ProtoConsts.SIZE: ProtoConsts.SIZE_CLIENT_ID, ProtoConsts.TYPE: bytes, ProtoConsts.CONTENT: None},
        ProtoConsts.ENCRYPTED_KEY: {ProtoConsts.SIZE: ProtoConsts.FMT_ME, ProtoConsts.TYPE: bytes, ProtoConsts.CONTENT: None},
        ProtoConsts.TICKET: {ProtoConsts.SIZE: ProtoConsts.FMT_ME, ProtoConsts.TYPE: bytes, ProtoConsts.CONTENT: None},
    },

    # Protocol add-ons for packed payloads responses
    # 1700
    ProtoConsts.PKT_SERVERS_LIST: {
        ProtoConsts.SERVERS_LIST: {ProtoConsts.SIZE: ProtoConsts.FMT_ME, ProtoConsts.TYPE: bytes, ProtoConsts.CONTENT: None}
    },

    # 1701
    ProtoConsts.PKT_ENCRYPTED_KEY: {
        ProtoConsts.ENCRYPTED_KEY_IV: {ProtoConsts.SIZE: ProtoConsts.SIZE_ENC_IV, ProtoConsts.TYPE: bytes, ProtoConsts.CONTENT: None},
        ProtoConsts.NONCE: {ProtoConsts.SIZE: ProtoConsts.SIZE_ENC_NONCE, ProtoConsts.TYPE: bytes, ProtoConsts.CONTENT: None},
        ProtoConsts.AES_KEY: {ProtoConsts.SIZE: ProtoConsts.SIZE_ENC_AES_KEY, ProtoConsts.TYPE: bytes, ProtoConsts.CONTENT: None},
    },

    # 1702
    ProtoConsts.PKT_TICKET: {
        ProtoConsts.VERSION: {ProtoConsts.SIZE: ProtoConsts.SIZE_VERSION, ProtoConsts.TYPE: int, ProtoConsts.CONTENT: None},
        ProtoConsts.CLIENT_ID: {ProtoConsts.SIZE: ProtoConsts.SIZE_CLIENT_ID, ProtoConsts.TYPE: bytes, ProtoConsts.CONTENT: None},
        ProtoConsts.SERVER_ID: {ProtoConsts.SIZE: ProtoConsts.SIZE_SERVER_ID, ProtoConsts.TYPE: bytes, ProtoConsts.CONTENT: None},
        ProtoConsts.CREATION_TIME: {ProtoConsts.SIZE: ProtoConsts.SIZE_ENC_CREATION_TIME, ProtoConsts.TYPE: bytes, ProtoConsts.CONTENT: None},
        ProtoConsts.TICKET_IV: {ProtoConsts.SIZE: ProtoConsts.SIZE_IV, ProtoConsts.TYPE: bytes, ProtoConsts.CONTENT: None},
        ProtoConsts.AES_KEY: {ProtoConsts.SIZE: ProtoConsts.SIZE_ENC_AES_KEY, ProtoConsts.TYPE: bytes, ProtoConsts.CONTENT: None},
        ProtoConsts.EXPIRATION_TIME: {ProtoConsts.SIZE: ProtoConsts.SIZE_ENC_EXPIRATION_TIME, ProtoConsts.TYPE: bytes, ProtoConsts.CONTENT: None}
    },

    # 1703
    ProtoConsts.PKT_AUTHENTICATOR: {
        ProtoConsts.AUTHENTICATOR_IV: {ProtoConsts.SIZE: ProtoConsts.SIZE_AUTH_IV, ProtoConsts.TYPE: bytes, ProtoConsts.CONTENT: None},
        ProtoConsts.VERSION: {ProtoConsts.SIZE: ProtoConsts.SIZE_ENC_VERSION, ProtoConsts.TYPE: bytes, ProtoConsts.CONTENT: None},
        ProtoConsts.CLIENT_ID: {ProtoConsts.SIZE: ProtoConsts.SIZE_ENC_CLIENT_ID, ProtoConsts.TYPE: bytes, ProtoConsts.CONTENT: None},
        ProtoConsts.SERVER_ID: {ProtoConsts.SIZE: ProtoConsts.SIZE_ENC_SERVER_ID, ProtoConsts.TYPE: bytes, ProtoConsts.CONTENT: None},
        ProtoConsts.CREATION_TIME: {ProtoConsts.SIZE: ProtoConsts.SIZE_ENC_CREATION_TIME, ProtoConsts.TYPE: bytes, ProtoConsts.CONTENT: None}
    },

    # 1705
    ProtoConsts.PKT_ENC_MSG_WITHOUT_CONTENT: {
        ProtoConsts.MSG_SIZE: {ProtoConsts.SIZE: ProtoConsts.SIZE_MSG, ProtoConsts.TYPE: int, ProtoConsts.CONTENT: None},
        ProtoConsts.MSG_IV: {ProtoConsts.SIZE: ProtoConsts.SIZE_IV, ProtoConsts.TYPE: bytes, ProtoConsts.CONTENT: None}
    }
}

# Template for converting sizes to struct format
communication_protocol_template = {
    1: 'B',
    2: 'H',
    4: 'I',
    ProtoConsts.IPV4: 's',
    bytes: 's',
    ProtoConsts.LITTLE_ENDIAN: '<'
}

# Template for avoiding deserialize packet content
packet_bytes_index = {
    ProtoConsts.RES_MSG_SERVERS_LIST: 3,
    ProtoConsts.REQ_AES_KEY: (4, 5),
    ProtoConsts.RES_ENCRYPTED_AES_KEY: (4, 5),
    ProtoConsts.REQ_MSG_SERVER_AES_KEY: (4, 5)
}

# Template for adjusting unpack format
payload_buffer_template = {

    # For request 1024
    ProtoConsts.SIZE_CLIENT_NAME + ProtoConsts.SIZE_PASSWORD:
        f"{ProtoConsts.SIZE_CLIENT_NAME}s{ProtoConsts.SIZE_PASSWORD}s",

    # For request 1025
    ProtoConsts.SIZE_SERVER_NAME + ProtoConsts.SIZE_AES_KEY:
        f"{ProtoConsts.SIZE_SERVER_NAME}s{ProtoConsts.SIZE_AES_KEY}s",

    # For request 1027
    ProtoConsts.SIZE_SERVER_ID + ProtoConsts.SIZE_NONCE:
        f"{ProtoConsts.SIZE_SERVER_ID}s{ProtoConsts.SIZE_NONCE}s",

    # For response 1602
    ProtoConsts.SIZE_SERVER_LIST_ENTRY: f"{ProtoConsts.SIZE_SERVER_LIST_ENTRY}s",

    # For response 1603
    ProtoConsts.SIZE_CLIENT_ID + ProtoConsts.SIZE_ENCRYPTED_KEY_PACKET + ProtoConsts.SIZE_TICKET_PACKET:
        f"{ProtoConsts.SIZE_CLIENT_ID}s{ProtoConsts.SIZE_ENCRYPTED_KEY_PACKET}s{ProtoConsts.SIZE_TICKET_PACKET}s",

    # For request 1028
    ProtoConsts.SIZE_AUTHENTICATOR_PACKET + ProtoConsts.SIZE_TICKET_PACKET:
        f"{ProtoConsts.SIZE_AUTHENTICATOR_PACKET}s{ProtoConsts.SIZE_TICKET_PACKET}s"
}

# Template for registration success
packet_register_success = {
    ProtoConsts.VERSION: ProtoConsts.SERVER_VERSION,
    ProtoConsts.CODE: ProtoConsts.RES_REGISTER_SUCCESS,
    ProtoConsts.PAYLOAD_SIZE: ProtoConsts.SIZE_CLIENT_ID,
    ProtoConsts.CLIENT_ID: ProtoConsts.FMT_ME
}

# Template for failure
packet_no_payload = {
    ProtoConsts.VERSION: ProtoConsts.SERVER_VERSION,
    ProtoConsts.CODE: ProtoConsts.FMT_ME,
    ProtoConsts.PAYLOAD_SIZE: 0
}
