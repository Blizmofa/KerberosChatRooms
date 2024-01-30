from Socket.custom_socket import socket, Thread
from Server.server_interface import ServerInterface
from Utils.logger import Logger
from Utils import utils
from Utils.custom_exception_handler import CustomException
from Server.AuthServer.auth_server_constants import AuthServerConstants, ram_clients_template, ram_servers_template
from Server.AuthServer.auth_server_logic import AuthServerLogic
from Protocol_Handler.protocol_handler import ProtocolHandler
from Protocol_Handler import protocol_utils


class AuthServer(ServerInterface):

    def __init__(self, connection_protocol: str, ip_address: str, port: int, debug_mode: bool) -> None:
        super().__init__(connection_protocol, ip_address, port, debug_mode)
        # Auth server needs a unique ip and port
        self.ip_address = ip_address
        self.port = port
        self.connections_list = []
        self.threads = []
        self.active_connections = 0
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)
        self.protocol_handler = ProtocolHandler(debug_mode=debug_mode)
        self.auth_server_logic = AuthServerLogic(debug_mode=debug_mode)

    def setup_auth_server_db(self) -> None:
        try:
            # For Files root directory
            utils.create_if_not_exists(path_to_create=AuthServerConstants.FILES_DIR_PATH, is_dir=True)

            # For clients data
            utils.create_if_not_exists(path_to_create=AuthServerConstants.CLIENTS_FILE_PATH, is_file=True)

            # For servers data
            utils.create_if_not_exists(path_to_create=AuthServerConstants.SERVERS_FILE_PATH, is_file=True)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to setup {self.__class__.__name__}.", exception=e)

    def handle_new_client(self, sck: socket) -> None:

        try:
            # Insert new connection
            self.new_connection(sck=sck, connections_list=self.connections_list, active_connections=self.active_connections)

            # Create new client RAM DB
            client_ram_template = ram_clients_template.copy()
            client_ram_template[AuthServerConstants.RAM_LAST_SEEN] = utils.time_now()

            # Create new server RAM DB
            server_ram_template = ram_servers_template

            # Create Request/Response templates
            server_request = protocol_utils.server_request.copy()
            server_response = protocol_utils.server_response.copy()

            # Receive requests
            auth_server_request = self.custom_socket.receive_packet(sck=sck, logger=self.logger)
            request_code, unpacked = self.protocol_handler.unpack_request(received_packet=auth_server_request,
                                                                          formatter=server_request,
                                                                          deserialize=True)

            # Handle Registration requests
            if request_code == protocol_utils.Constants.REQ_CLIENT_REG or request_code == protocol_utils.Constants.REQ_SERVER_REG:

                self.auth_server_logic.handle_registration_request(server_socket=self.custom_socket,
                                                                   client_socket=sck,
                                                                   request_code=request_code,
                                                                   unpacked_packet=unpacked,
                                                                   client_ram_template=client_ram_template,
                                                                   server_ram_template=server_ram_template)

            # Handle AES key request from client
            elif request_code == protocol_utils.Constants.REQ_AES_KEY:
                self.auth_server_logic.handle_aes_key_request(server_socket=self.custom_socket,
                                                              client_socket=sck,
                                                              unpacked_packet=unpacked,
                                                              client_ram_template=client_ram_template,
                                                              server_ram_template=server_ram_template)

            # Handle services list request from client
            elif request_code == protocol_utils.Constants.REQ_MSG_SERVERS_LIST:

                self.auth_server_logic.handle_services_list_request(server_socket=self.custom_socket,
                                                                    client_socket=sck,
                                                                    unpacked_packet=unpacked,
                                                                    client_ram_template=client_ram_template,
                                                                    server_request=server_request,
                                                                    server_response=server_response)

            else:
                # TODO - send general error to client
                raise ValueError(f"Unsupported request code {request_code}.")

            # TODO - create json file for each client according to his uuid json summery of all his and the server session
        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle client {sck.getpeername()}.", exception=e)


    def run(self) -> None:
        try:
            # Initialize Server
            self.setup_server()

            # Setup Server needed files DB
            self.setup_auth_server_db()

            # Print welcome message
            print(AuthServerConstants.KERBEROS_LOGO, end='\n\n')
            print(AuthServerConstants.AUTH_SERVER_LOGO, end='\n\n')
            print(f"{AuthServerConstants.CONSOLE_ACK} Starting Server...")
            print(f"{AuthServerConstants.CONSOLE_ACK} Server is now listening on {self.ip_address}:{self.port}")

            # Wait for clients requests
            while True:
                connection, address = self.server_socket.accept()
                print(f"{AuthServerConstants.CONSOLE_ACK} Connected to peer {connection.getpeername()}")

                # Assign new thread to each connected client
                client_thread = Thread(target=self.handle_new_client, args=(connection, ))
                client_thread.start()
                self.threads.append(client_thread)

        except Exception as e:
            # Cleanup
            self.server_socket.close()
            for thread in self.threads:
                thread.join()

            raise CustomException(error_msg=f"Unable to run {self.__class__.__name__}.", exception=e)


