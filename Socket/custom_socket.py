from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM, error as socket_error
from threading import Thread
from typing import Optional, Any
from Utils.custom_exception_handler import CustomException


class CustomSocket(Thread):
    """Custom Socket class for..."""

    def __init__(self, connection_protocol: str) -> None:
        super().__init__()
        self.connection_protocol = connection_protocol

    def set_socket_protocol(self, connection_protocol: str):
        if connection_protocol == "tcp":
            return SOCK_STREAM
        elif connection_protocol == "udp":
            return SOCK_DGRAM
        else:
            raise ValueError(f"Unsupported connection protocol '{connection_protocol}'.")

    def create_socket(self) -> socket:
        try:
            protocol = self.set_socket_protocol(self.connection_protocol)
            custom_socket = socket(AF_INET, protocol)

            return custom_socket

        except socket_error as e:
            raise CustomException(error_msg=f"Unable to create socket.", exception=e)


    def custom_send_recv(self, sck: socket, request: str, fmt: Optional[str] = 'utf-8',
                         buffer_size: Optional[int] = 1024, response: Optional[bool] = False) -> Any:
        try:
            sck.send(request.encode(fmt))

            if response:
                return sck.recv(buffer_size).decode(fmt)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to send '{request}' to '{str(socket)}'", exception=e)

