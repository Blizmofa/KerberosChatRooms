from ipaddress import IPv4Address, AddressValueError
from typing import Any, Optional, Union, Tuple
from base64 import b64decode, b64encode
from Utils.logger import Logger, CustomFilter
from Protocol_Handler.protocol_constants import ProtoConsts
from Utils.custom_exception_handler import get_calling_method_name


class ValConsts:
    TYPE = "type"
    MIN_LENGTH = "min_length"
    MAX_LENGTH = "max_length"

    PORT_LOWER_BOUND = 0
    PORT_UPPER_BOUND = 65535

    # For supported validation formats
    FMT_IPV4_PORT = "ipv4:port"
    FMT_NAME = "name"
    FMT_ID = "uuid4"
    FMT_AES_KEY = "aes_key"
    FMT_PORT = "port"
    FMT_IPV4 = "ipv4"
    FMT_NONCE = "nonce"
    FMT_IV = "iv"
    FMT_PASSWORD = "password"
    FMT_TICKET = "ticket"
    FMT_ENC_VERSION = "enc_version"
    FMT_VERSION = "version"
    FMT_CREATION_TIME = "creation_time"
    FMT_EXPIRATION_TIME = "expiration_time"


# Validator default config template
validator_config_template = {
    ValConsts.FMT_IPV4_PORT: {ValConsts.TYPE: str,
                              ValConsts.MIN_LENGTH: ProtoConsts.SIZE_IPV4_PORT_MIN,
                              ValConsts.MAX_LENGTH: ProtoConsts.SIZE_IPV4_PORT_MAX},
    ValConsts.FMT_NAME: {ValConsts.TYPE: str,
                         ValConsts.MIN_LENGTH: ProtoConsts.SIZE_NAME_MIN,
                         ValConsts.MAX_LENGTH: ProtoConsts.SIZE_NAME_MAX},
    ValConsts.FMT_ID: {ValConsts.TYPE: (str, bytes),
                       ValConsts.MIN_LENGTH: ProtoConsts.SIZE_CLIENT_ID,
                       ValConsts.MAX_LENGTH: ProtoConsts.SIZE_ENC_CLIENT_ID},
    ValConsts.FMT_AES_KEY: {ValConsts.TYPE: (bytes, str),
                            ValConsts.MIN_LENGTH: ProtoConsts.SIZE_AES_KEY,
                            ValConsts.MAX_LENGTH: ProtoConsts.SIZE_ENC_AES_KEY},
    ValConsts.FMT_IPV4: {ValConsts.TYPE: str,
                         ValConsts.MIN_LENGTH: ProtoConsts.SIZE_IPV4_MIN,
                         ValConsts.MAX_LENGTH: ProtoConsts.SIZE_IPV4_MAX},
    ValConsts.FMT_PORT: {ValConsts.TYPE: int},
    ValConsts.FMT_NONCE: {ValConsts.TYPE: (bytes, str),
                          ValConsts.MIN_LENGTH: ProtoConsts.SIZE_NONCE,
                          ValConsts.MAX_LENGTH: ProtoConsts.SIZE_ENC_NONCE},
    ValConsts.FMT_IV: {ValConsts.TYPE: (bytes, str),
                       ValConsts.MIN_LENGTH: ProtoConsts.SIZE_IV,
                       ValConsts.MAX_LENGTH: ProtoConsts.SIZE_ENC_IV},
    ValConsts.FMT_PASSWORD: {ValConsts.TYPE: (str, bytes)},
    ValConsts.FMT_TICKET: {ValConsts.TYPE: (str, bytes)},
    ValConsts.FMT_VERSION: {ValConsts.TYPE: int},
    ValConsts.FMT_CREATION_TIME: {ValConsts.TYPE: str},
    ValConsts.FMT_EXPIRATION_TIME: {ValConsts.TYPE: str}

}


class Validator:
    """Handles all the needed validations, conversions and casting."""

    def __init__(self, config_data: Optional[dict] = None, debug_mode: Optional[bool] = False) -> None:
        self.config_data = config_data
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)

    def __validate_type_and_length(self, value: dict, value_to_validate: Any) -> None:
        """Validates type and length of a given value."""
        # Validate type
        data_type = value.get(ValConsts.TYPE)
        if not isinstance(value_to_validate, data_type):
            raise ValidatorError(f"{value_to_validate} is of type {type(value_to_validate)} and should be of type {data_type}")

        # Validate value length
        value_min_length = value.get(ValConsts.MIN_LENGTH)
        value_max_length = value.get(ValConsts.MAX_LENGTH)

        if value_min_length and (len(value_to_validate) < int(value_min_length)):
            raise ValidatorError(f"{value_to_validate} min length should be {value_min_length}")

        if value_max_length and (len(value_to_validate) > int(value_max_length)):
            raise ValidatorError(f"{value_to_validate} max length should be {value_max_length}")

        self.logger.logger.debug(f"Validated {value_to_validate} type {data_type} and max length {value_max_length} successfully.")

    @staticmethod
    def __validate_port_range(port: int) -> bool:
        """Returns True if the given port is of valid range, False otherwise."""
        if port < ValConsts.PORT_LOWER_BOUND or port > ValConsts.PORT_UPPER_BOUND:
            return False

        return True

    @staticmethod
    def __validate_ipv4(ip_address: str) -> bool:
        """Returns True if the given IP Address is of IPv4 format, False otherwise."""
        try:
            if ip_address == ProtoConsts.LOCAL_HOST:
                ip_address = '127.0.0.1'
            IPv4Address(ip_address)
            return True

        except AddressValueError:
            return False

    @staticmethod
    def __validate_bytes_or_hex(value: Union[bytes, str]) -> Union[str, bytes]:
        """Converts bytes to hex and the opposite."""
        if isinstance(value, str):
            return bytes.fromhex(value)
        elif isinstance(value, bytes):
            return value.hex()
        else:
            raise ValidatorError(f"Unsupported type '{type(value)}' for {value}, "
                                 f"should be of type {bytes} or {str}.")

    @staticmethod
    def __validate_bytes_or_base64(value: Union[bytes, str]) -> Union[str, bytes]:
        """Encodes a given string to base64 and the opposite."""
        if isinstance(value, str):
            return b64decode(value)
        elif isinstance(value, bytes):
            return b64encode(value).decode('utf-8')
        else:
            raise ValidatorError(f"Unsupported value type '{type(value)}' for {value}, "
                                 f"should be of type {bytes} or {str}.")

    def __validate_ip_and_port(self, ip_and_port: str) -> Tuple[str, int]:
        """Returns the validated and parsed IPv4:Port format."""
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

        # Set Logger custom filter
        CustomFilter.filter_name = get_calling_method_name()

        for key, value in config_template.items():

            if not isinstance(value, dict):
                raise ValidatorError(f"Broken or Corrupted configurations. {value} should be of type {dict} and not of type '{type(value)}'")

            if key == data_type:

                try:
                    # First validate type and length
                    self.__validate_type_and_length(value=value, value_to_validate=value_to_validate)

                    # Validate the given value
                    if data_type == ValConsts.FMT_IPV4_PORT:
                        return self.__validate_ip_and_port(value_to_validate)
                    if data_type == ValConsts.FMT_IPV4:
                        return self.__validate_ipv4(ip_address=value_to_validate)
                    if data_type == ValConsts.FMT_PORT:
                        return self.__validate_port_range(port=value_to_validate)
                    if (data_type == ValConsts.FMT_ID or
                            data_type == ValConsts.FMT_NONCE or
                            data_type == ValConsts.FMT_IV or
                            data_type == ValConsts.FMT_PASSWORD):
                        return self.__validate_bytes_or_hex(value=value_to_validate)
                    if data_type == ValConsts.FMT_TICKET or data_type == ValConsts.FMT_AES_KEY:
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