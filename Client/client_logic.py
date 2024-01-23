from Socket.custom_socket import CustomSocket
from Utils.logger import Logger
from Utils import utils
from Utils.custom_exception_handler import CustomException
from Protocol_Handler.protocol_handler import ProtocolHandler
from Protocol_Handler.protocol_utils import ProtocolConstants, server_response, server_request
from Client.client_constants import ClientConstants


class ClientLogic(CustomSocket):

    def __init__(self, server_ip: str, server_port: int, connection_protocol: str, debug_mode: bool) -> None:
        super().__init__(connection_protocol)
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_socket = super().create_socket()
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)
        self.protocol_handler = ProtocolHandler(debug_mode=debug_mode)

    def setup(self):
        try:
            self.client_socket.connect((self.server_ip, self.server_port))
            self.logger.logger.info(f"Connected to {self.server_ip}:{self.server_port} successfully.")

        except Exception as e:
            raise CustomException(error_msg=f"Unable to setup client.", exception=e)

    def handle_registration_request(self) -> None:
        try:
            # Pack registration request packet
            client_id = utils.parse_info_file(file_path=ClientConstants.CLIENT_FILE_NAME, target_line_number=3)
            version = ProtocolConstants.SERVER_VERSION
            code = ProtocolConstants.REQ_CLIENT_REG
            payload_size = ProtocolConstants.SIZE_CLIENT_NAME + ProtocolConstants.SIZE_PASSWORD
            # username = "Alice"
            # username = "Bob"
            # username = "Cooper"
            username = utils.parse_info_file(file_path=ClientConstants.CLIENT_FILE_NAME, target_line_number=2).encode()
            password = "qwer1234"

            data = {"client_id": client_id, "version": version, "code": code,
                    "payload_size": payload_size, "name": username, "password": password}

            packed_register_request = self.protocol_handler.pack_request(code=1025, data=data, formatter=server_request)
            self.send_packet(sck=self.client_socket, packet=packed_register_request)

            # Receive register response
            register_response = self.receive_packet(sck=self.client_socket)
            unpacked_register_response = self.protocol_handler.unpack_request(received_packet=register_response,
                                                                              formatter=server_response, deserialize=True)
            print(unpacked_register_response)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle registration request.", exception=e)

    def handle_msg_servers_request(self):
        pass

    def handle_encrypted_ket_request(self):
        pass

    def run(self) -> None:

        try:
            # Setup client
            self.setup()

            # TODO - enter chat mode

            # Handle registration request from Authentication Server
            self.handle_registration_request()

        except Exception as e:
            raise CustomException(error_msg=f"Unable to run {self.__class__.__name__}.", exception=e)