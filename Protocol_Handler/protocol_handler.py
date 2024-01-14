from struct import pack, unpack
from Protocol_Handler.protocol_interface import ProtocolHandlerInterfaces
from Protocol_Handler.protocol_utils import ProtocolConstants, client_request_template
from Utils.logger import Logger
from Utils.custom_exception_handler import CustomException


class ProtocolHandler(ProtocolHandlerInterfaces):

    def __init__(self, debug_mode: bool) -> None:
        self.RESPONSE_CODE = 0
        self.PAYLOAD_SIZE = 0
        self.class_logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)

    def pack_request(self, fmt: str, *args) -> bytes:
        try:
            packed = pack(fmt, *args)
            self.class_logger.logger.debug(f"Packed packet '{self.RESPONSE_CODE}' successfully.")
            return packed

        except Exception as e:
            raise CustomException(error_msg=f"Unable to pack packet '{self.RESPONSE_CODE}'.", exception=e)

    def unpack_request(self, request_code: int, received_packet: bytes) -> tuple:
        try:
            payload_sizes = self.get_client_payload_sizes(client_request_template, request_code)
            unpacked = unpack(f'{ProtocolConstants.UNPACK_DEFAULT_FORMAT}{payload_sizes}', received_packet)
            self.class_logger.logger.debug(f"Unpacked packet '{request_code}' successfully.")
            return unpacked

        except Exception as e:
            raise CustomException(error_msg=f"Unable to unpack '{request_code}'.", exception=e)

    def get_client_payload_sizes(self, template: dict, request_code: int) -> str:
        """
        Auxiliary method to return the needed unpack values according to a given client request code.
        :param template: For the client formats template.
        :param request_code: For the client request code.
        :return: The unpack format value.
        """
        try:
            for key, value in template.items():
                if request_code == key:
                    self.class_logger.logger.debug(f"Parsed request code: {request_code}")
                    return value

        except ValueError as err:
            self.class_logger.logger.error(f"Unable to parse client request code: {request_code}, Error: {err}")

    def get_server_response_code(self, template: dict, response_code: int) -> None:
        """
        Auxiliary method to return the needed pack values according to a given server response code.
        :param template: For the server formats template.
        :param response_code: For the server response code.
        :return: The pack format value.
        """
        try:
            for key, value in template.items():
                if response_code == key:
                    for k, v in value.items():
                        if k == ProtocolConstants.SERVER_RESPONSE_CODE_STR:
                            self.RESPONSE_CODE = v
                        if k == ProtocolConstants.SERVER_PAYLOAD_SIZE_STR:
                            self.PAYLOAD_SIZE = v

        except ValueError as err:
            self.class_logger.logger.error(f"Unable to parse server response code: {response_code}, Error: {err}")