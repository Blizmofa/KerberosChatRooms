from abc import ABC, abstractmethod
from Socket.custom_socket import CustomSocket, socket
from Utils.logger import Logger
from Utils.custom_exception_handler import CustomException


class ServerInterface(ABC):

    def __init__(self, connection_protocol: str, ip_address: str, port: int, debug_mode: bool):
        self.ip_address = ip_address
        self.port = port
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)
        self.socket = CustomSocket(connection_protocol=connection_protocol).create_socket()

    def setup(self) -> None:
        try:
            self.socket.bind((self.ip_address, self.port))
            self.socket.listen()
            self.logger.logger.info(f"Server is now listening on {self.ip_address}:{self.port}...")

        except Exception as e:
            raise CustomException(error_msg=f"Unable to setup {self.__class__.__name__}.", exception=e)

    def cleanup(self, sck: socket, connections_list: list, active_connections: int) -> None:
        try:
            connections_list.remove(sck)
            active_connections -= 1

        except Exception as e:
            raise CustomException(error_msg=f"Unable to cleanup {self.__class__.__name__}.", exception=e)

    def new_connection(self, sck: socket, connections_list: list, active_connections: int) -> None:
        # Add client to server list
        try:
            connections_list.append(sck)
            active_connections += 1
            self.logger.logger.debug(f"Added {sck.getpeername()} to list of active connections.")
            self.logger.logger.info(f"Server Active connections are: {active_connections}.")

        except Exception as e:
            raise CustomException(error_msg=f"Unable to add {sck.getpeername()} as new connection.", exception=e)

    @abstractmethod
    def handle_new_client(self, sck: socket) -> None:
        raise NotImplementedError(f"{self.handle_new_client.__name__} must be implemented.")

    @abstractmethod
    def run(self) -> None:
        raise NotImplementedError(f"{self.run.__name__} must be implemented.")