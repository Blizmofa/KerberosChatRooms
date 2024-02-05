from ipaddress import IPv4Address, AddressValueError
from typing import Any, Optional, Union, Tuple
from base64 import b64decode, b64encode
from Utils.logger import Logger
from Protocol_Handler.protocol_utils import ProtocolConstants as ProtoConsts


class Constants:

    FMT_IPV4_PORT = "ipv4:port"
    FMT_NAME = "name"
    FMT_ID = "uuid4"
    FMT_AES_KEY = "aes_key"
    FMT_PORT = "port"
    FMT_IPV4 = "ipv4"
    FMT_NONCE = "nonce"
    FMT_IV = "iv"

    TYPE = "type"
    MIN_LENGTH = "min_length"
    MAX_LENGTH = "max_length"

    PORT_LOWER_BOUND = 0
    PORT_UPPER_BOUND = 65535

# TODO - constants from protocol utils, and types after encryption implementation
validator_config_template = {
    Constants.FMT_IPV4_PORT: {Constants.TYPE: str, Constants.MIN_LENGTH: 9, Constants.MAX_LENGTH: 21},
    Constants.FMT_NAME: {Constants.TYPE: str, Constants.MIN_LENGTH: 1, Constants.MAX_LENGTH: 100},
    Constants.FMT_ID: {Constants.TYPE: (str, bytes), Constants.MIN_LENGTH: ProtoConsts.SIZE_CLIENT_ID, Constants.MAX_LENGTH: 32},
    Constants.FMT_AES_KEY: {Constants.TYPE: (bytes, str), Constants.MIN_LENGTH: ProtoConsts.SIZE_AES_KEY, Constants.MAX_LENGTH: ProtoConsts.SIZE_ENC_AES_KEY},
    Constants.FMT_IPV4: {Constants.TYPE: str, Constants.MIN_LENGTH: 7, Constants.MAX_LENGTH: 15},
    Constants.FMT_PORT: {Constants.TYPE: int},
    Constants.FMT_NONCE: {Constants.TYPE: bytes, Constants.MIN_LENGTH: ProtoConsts.SIZE_NONCE, Constants.MAX_LENGTH: ProtoConsts.SIZE_ENC_NONCE},
    Constants.FMT_IV: {Constants.TYPE: bytes, Constants.MIN_LENGTH: ProtoConsts.SIZE_IV, Constants.MAX_LENGTH: ProtoConsts.SIZE_ENC_IV}
}


class Validator:
    def __init__(self, config_data: Optional[dict] = None, debug_mode: Optional[bool] = False) -> None:
        self.config_data = config_data
        # TODO - move logger outside class
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)

    def __validate_type_and_length(self, value: dict, value_to_validate: Any) -> None:

        # Validate type
        data_type = value.get(Constants.TYPE)
        if not isinstance(value_to_validate, data_type):
            raise ValidatorError(f"{value_to_validate} is of type {type(value_to_validate)} and should be of type {data_type}")

        # Validate value length
        value_min_length = value.get(Constants.MIN_LENGTH)
        value_max_length = value.get(Constants.MAX_LENGTH)

        if value_min_length and (len(value_to_validate) < int(value_min_length)):
            raise ValidatorError(f"{value_to_validate} min length should be {value_min_length}")

        if value_max_length and (len(value_to_validate) > int(value_max_length)):
            raise ValidatorError(f"{value_to_validate} max length should be {value_max_length}")

        self.logger.logger.debug(f"Validated {value_to_validate} type {data_type} and max length {value_max_length} successfully.")

    def __validate_port_range(self, port: int) -> bool:
        # port = int(port)
        if port < Constants.PORT_LOWER_BOUND or port > Constants.PORT_UPPER_BOUND:
            return False

        return True

    def __validate_ipv4(self, ip_address: str) -> bool:
        try:
            IPv4Address(ip_address)
            return True

        except AddressValueError:
            return False

    def __validate_ip_and_port(self, ip_and_port: str) -> Tuple[str, int]:
        try:
            ip, port = ip_and_port.split(':')
            ip = str(ip)
            port = int(port)
            if not self.__validate_port_range(port=port):
                raise ValidatorError(f"Port number {port} must be between 1 and 65535.")
            if not self.__validate_ipv4(ip_address=ip):
                raise ValidatorError(f"Invalid IPv4 Address {ip}.")

            self.logger.logger.debug(f"Validated {ip}:{port} successfully.")
            return ip, port

        except Exception as e:
            raise ValidatorError(f"Invalid IP or Port: {str(e)}")

    def __validate_bytes_or_hex(self, value: Union[bytes, str]) -> Union[str, bytes]:

        if isinstance(value, str):
            return bytes.fromhex(value)
        elif isinstance(value, bytes):
            return value.hex()
        else:
            raise ValidatorError(f"Unsupported type '{type(value)}' for {value}, "
                                 f"should be of type {bytes} or {str}.")

    def __validate_bytes_or_base64(self, value: Union[bytes, str]) -> Union[str, bytes]:
        if isinstance(value, str):
            return b64decode(value)
        elif isinstance(value, bytes):
            return b64encode(value).decode('utf-8')
        else:
            raise ValidatorError(f"Unsupported value type '{type(value)}' for {value}, "
                                 f"should be of type {bytes} or {str}.")

    def validate(self, data_type: str, value_to_validate: Any, config_template: Optional[dict] = None) -> Any:
        """
        Factory Pattern to call the appropriate validate method according to the data type.
        :param data_type: For the Validator supported data types.
        :param value_to_validate: For the wanted value to validate.
        :param config_template: For the Validator configurations.
        """
        # For class or passed configurations
        if config_template is None or self.config_data is None:
            config_template = validator_config_template
        else:
            raise ValidatorError(f"Please pass {self.__class__.__name__} configurations.")

        for key, value in config_template.items():

            if not isinstance(value, dict):
                raise ValidatorError(f"Broken or Corrupted configurations. {value} should be of type {dict} and not of type '{type(value)}'")

            if key == data_type:

                try:

                    self.__validate_type_and_length(value=value, value_to_validate=value_to_validate)
                    if data_type == Constants.FMT_IPV4_PORT:
                        return self.__validate_ip_and_port(value_to_validate)
                    if data_type == Constants.FMT_IPV4:
                        return self.__validate_ipv4(ip_address=value_to_validate)
                    if data_type == Constants.FMT_PORT:
                        return self.__validate_port_range(port=value_to_validate)
                    if data_type == Constants.FMT_ID or data_type == Constants.FMT_NONCE:
                        return self.__validate_bytes_or_hex(value=value_to_validate)
                    if data_type == Constants.FMT_AES_KEY:
                        return self.__validate_bytes_or_base64(value=value_to_validate)

                except Exception as e:
                    raise ValidatorError(f"Unable to validate '{data_type}': {value_to_validate}, Error: {str(e)}")

    @classmethod
    def validate_injection(cls, data_type: str, value_to_validate: Any, config_template: Optional[dict] = None) -> Any:
        """For dependency injection."""
        instance = cls()
        return instance.validate(data_type=data_type, value_to_validate=value_to_validate, config_template=config_template)


class ValidatorError(Exception):
    """Auxiliary Exception class to handle validation exceptions more precisely."""
    pass