from struct import pack, unpack
from Protocol_Handler.protocol_interface import ProtocolHandlerInterfaces
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
            payload_sizes = self.get_client_payload_sizes(ProtocolHandlersUtils.client_request_template, request_code)
            unpacked = unpack(f'{ProtocolHandlersUtils.UNPACK_DEFAULT_FORMAT}{payload_sizes}', received_packet)
            self.class_logger.logger.debug(f"Unpacked packet '{request_code}' successfully.")
            return unpacked

        except Exception as e:
            raise CustomException(error_msg=f"Unable to unpack '{request_code}'.", exception=e)