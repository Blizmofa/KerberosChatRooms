from Utils.validator import ValidatorConstants


class ClientConstants:

    CLIENT_FILE_NAME = "me.info"

    CLIENT_IP_PORT_LINE = 1
    CLIENT_NAME_LINE = 2
    CLIENT_ID_LINE = 3


me_info_default_data = {
    ValidatorConstants.FMT_IPV4_PORT: '127.0.0.1:8000',
    ValidatorConstants.FMT_NAME: 'Michael Jackson'
}
