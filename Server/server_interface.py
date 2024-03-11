from abc import ABC, abstractmethod
from Socket.custom_socket import CustomSocket, socket
from Utils.logger import Logger
from Utils.validator import Validator, ValConsts as ValConsts
from Utils.custom_exception_handler import CustomException


class ServerInterface(ABC):
    """Handles servers generic methods and improve servers performances."""

    def __init__(self, connection_protocol: str, ip_address: str, port: int, debug_mode: bool) -> None:
        self.ip_address = ip_address
        self.port = int(port)
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)
        # Access Custom Socket class
        self.custom_socket = CustomSocket(connection_protocol=connection_protocol, debug_mode=debug_mode)

    def setup_server(self, sck: socket) -> None:
        """Binds the server socket and starts server listener."""
        try:
            Validator.validate_injection(data_type=ValConsts.FMT_IPV4, value_to_validate=self.ip_address)
            Validator.validate_injection(data_type=ValConsts.FMT_PORT, value_to_validate=self.port)
            sck.bind((self.ip_address, self.port))
            sck.listen()
            self.logger.logger.info(f"Server is now listening on {self.ip_address}:{self.port}...")

        except Exception as e:
            raise CustomException(error_msg=f"Unable to setup {self.__class__.__name__}.", exception=e)

    def cleanup(self, sck: socket, connections_list: list, active_connections: int) -> None:
        """Remove a connection from the active connections list and closes the passed socket."""
        try:
            connections_list.remove(sck)
            active_connections -= 1
            sck.close()

        except Exception as e:
            raise CustomException(error_msg=f"Unable to cleanup {self.__class__.__name__}.", exception=e)

    def add_new_connection(self, sck: socket, connections_list: list, active_connections: int) -> None:
        """Adds a connection to the active connections lists."""
        # Add client to server list
        try:
            connections_list.append(sck)
            active_connections += 1
            self.logger.logger.debug(f"Added {sck.getpeername()} to list of active connections.")
            self.logger.logger.info(f"Server Active connections are: {active_connections}.")

        except Exception as e:
            raise CustomException(error_msg=f"Unable to add {sck.getpeername()} as new connection.", exception=e)

    @abstractmethod
    def handle_peer(self, sck: socket, ram_template: dict) -> None:
        """Handle new connection main method to be implemented."""
        raise NotImplementedError(f"{self.handle_peer.__name__} must be implemented.")

    @abstractmethod
    def run(self) -> None:
        """Server main run method to be implemented."""
        raise NotImplementedError(f"{self.run.__name__} must be implemented.")