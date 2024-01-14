from Socket.custom_socket import CustomSocket
from Utils.logger import Logger
from Utils.custom_exception_handler import CustomException


class ClientLogic(CustomSocket):

    def __init__(self, server_ip: str, server_port: int, connection_protocol: str, debug_mode: bool) -> None:
        super().__init__(connection_protocol)
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_socket = super().create_socket()
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)

    def setup(self):
        try:
            self.client_socket.connect((self.server_ip, self.server_port))
            self.logger.logger.info(f"Connected to {self.server_ip}:{self.server_port} successfully.")

        except Exception as e:
            raise CustomException(error_msg=f"Unable to setup client.", exception=e)

    def run(self) -> None:

        try:
            self.setup()

        except Exception as e:
            raise CustomException(error_msg=f"Unable to run {self.__class__.__name__}.", exception=e)