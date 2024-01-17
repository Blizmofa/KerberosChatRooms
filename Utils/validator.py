from Crypto.PublicKey import RSA
from ipaddress import IPv4Address, AddressValueError
from Utils.logger import Logger
from typing import Any, Optional
from Utils.custom_exception_handler import CustomException


class ValidatorConstants:

    FMT_IPV4_PORT = "ipv4:port"
    FMT_NAME = "name"
    FMT_ID = "uuid4"
    FMT_RSA_KEY = "rsa_key"

    PORT_LOWER_BOUND = 0
    PORT_UPPER_BOUND = 65535


# TODO - constants from protocol utils, and types after encryption implementation
info_file_line_index = {
    1: {"value": ValidatorConstants.FMT_IPV4_PORT, "type": str, "max_length": 21},
    2: {"value": ValidatorConstants.FMT_NAME, "type": str, "max_length": 100},
    3: {"value": ValidatorConstants.FMT_ID, "type": bytes, "max_length": 16},
    4: {"value": ValidatorConstants.FMT_RSA_KEY, "type": RSA, "max_length": 2048}
}


class Validator:
    # TODO - refactor as a library, can call as static methods or with the template as a class parameter.
    def __init__(self, index_template: Optional[dict] = None):
        self.index_template = index_template

    def __validate_type_and_length(self, data_type: str, value_to_validate: Any) -> None:
        for value in info_file_line_index.values():

            # Get only the passed value
            if value.get("value") != data_type:
                continue

            # Validate value type
            value_type = value.get("type")
            if not isinstance(value_to_validate, value_type):
                raise ValueError(f"{value_to_validate} is of type {type(value_to_validate)} and should be of type {value_type}")

            # Validate value length
            value_max_length = value.get("max_length")
            if len(value_to_validate) > int(value_max_length):
                raise ValueError(f"{value_to_validate} max length should be {value_max_length}")

    def __validate_port_range(self, port: str) -> bool:
        port = int(port)
        if port < ValidatorConstants.PORT_LOWER_BOUND or port > ValidatorConstants.PORT_UPPER_BOUND:
            return False

        return True

    def __validate_ipv4(self, value: str) -> bool:
        try:
            IPv4Address(value)
            return True

        except AddressValueError:
            return False

    def __validate_ip_and_port(self, ip_and_port: str) -> bool:
        try:
            ip, port = ip_and_port.split(':')
            if not self.__validate_port_range(port=port):
                raise ValueError(f"Port number {port} must be between 1 and 65535.")
            if not self.__validate_ipv4(ip):
                raise ValueError(f"Invalid IPv4 Address {ip}.")

            return True

        except ValueError as e:
            raise ValueError(f"Invalid IP or Port: {str(e)}")

    def validate(self, data_type: str, value_to_validate: Any) -> Any:
        """Factory Pattern to call the appropriate validate method according to the data type."""
        try:
            self.__validate_type_and_length(data_type=data_type, value_to_validate=value_to_validate)
            if data_type == ValidatorConstants.FMT_IPV4_PORT:
                return self.__validate_ip_and_port(value_to_validate)

        except ValueError as e:
            raise CustomException(error_msg=f"Unable to validate '{value_to_validate}'.", exception=e)

    @classmethod
    def validate_injection(cls, data_type: str, value_to_validate: Any) -> Any:
        """For dependency injection."""
        instance = cls()
        return instance.validate(data_type=data_type, value_to_validate=value_to_validate)

