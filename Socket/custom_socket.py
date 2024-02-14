from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM, SocketKind, error as socket_error
from threading import Thread
from typing import Optional
from Protocol_Handler.protocol_utils import ProtocolConstants
from Utils.custom_exception_handler import CustomException
from Utils.logger import Logger
from Utils.utils import write_with_color, Colors


class CustomSocket(Thread):
    """Handles all the required logic and functionality of a multi-threaded Socket."""

    def __init__(self, connection_protocol: str, debug_mode: bool) -> None:
        super().__init__()
        self.connection_protocol = connection_protocol
        self.debug_mode = debug_mode

    def set_socket_protocol(self) -> SocketKind:
        """Sets transport protocol to TCP or UDP."""
        if self.connection_protocol == ProtocolConstants.PROTO_TCP:
            return SOCK_STREAM
        elif self.connection_protocol == ProtocolConstants.PROTO_UDP:
            return SOCK_DGRAM
        else:
            raise ValueError(f"Unsupported connection protocol '{self.connection_protocol}'.")

    def create_socket(self) -> socket:
        """Creates a custom socket object."""
        try:
            protocol = self.set_socket_protocol()
            custom_socket = socket(AF_INET, protocol)

            # For dev mode
            if self.debug_mode:
                print(write_with_color(msg=f"Created custom socket {custom_socket} successfully.",
                                       color=Colors.MAGENTA))

            return custom_socket

        except socket_error as e:
            raise CustomException(error_msg=f"Unable to create socket.", exception=e)

    def receive_packet(self, sck: socket, receive_buffer: Optional[int] = 1024, logger: Optional[Logger] = None) -> bytes:
        """Main receive method, return a raw packet for unpacking purposes."""
        try:
            received_data = b''
            while True:
                chunk = sck.recv(receive_buffer)
                if not chunk:
                    break
                received_data += chunk

                msg = f"Received packet of length {len(received_data)} successfully."
                if logger:
                    logger.logger.debug(msg=msg)

                # For dev mode
                if self.debug_mode:
                    print(write_with_color(msg=msg, color=Colors.MAGENTA))

                return received_data

        except Exception as e:
            raise CustomException(error_msg=f"Unable to receive packet from {sck.getpeername()}.", exception=e)

    def send_packet(self, sck: socket, packet: bytes, logger: Optional[Logger] = None) -> None:
        """Main send method."""
        try:
            sck.send(packet)

            # For fev mode
            msg = f"Sent packet of length {len(packet)} successfully."
            if logger:
                logger.logger.debug(msg=msg)

            if self.debug_mode:
                print(write_with_color(msg=msg, color=Colors.MAGENTA))

        except Exception as e:
            raise CustomException(error_msg=f"Unable to send packet to {sck.getpeername()}.", exception=e)

    def custom_send_recv(self, sck: socket, packet: bytes, buffer_size: Optional[int] = 1024,
                         logger: Optional[Logger] = None, response: Optional[bool] = False) -> bytes:
        """Sends and Receives using class send and receive main methods."""
        try:
            self.send_packet(sck=sck, packet=packet, logger=logger)

            if response:
                return self.receive_packet(sck=sck, receive_buffer=buffer_size, logger=logger)

        except Exception as e:
            raise CustomException(error_msg=f"Send-Recv Error.", exception=e)

