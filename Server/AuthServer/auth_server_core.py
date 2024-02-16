from Socket.custom_socket import socket, Thread
from Server.server_interface import ServerInterface
from Utils.logger import Logger, CustomFilter
from Utils.utils import create_if_not_exists, time_now, write_with_color, Colors
from Utils.custom_exception_handler import CustomException, get_calling_method_name
from Server.AuthServer.auth_server_constants import Constants, ram_clients_template, ram_servers_template
from Server.AuthServer.auth_server_logic import AuthServerLogic
from Protocol_Handler.protocol_handler import ProtocolHandler
from Protocol_Handler.protocol_utils import server_request, server_response, packet_no_payload, ProtocolConstants as ProtoConsts


class AuthServerCore(ServerInterface):
    """Handles the Authentication Server core functionalities."""

    def __init__(self, connection_protocol: str, ip_address: str, port: int, debug_mode: bool) -> None:
        super().__init__(connection_protocol, ip_address, port, debug_mode)
        # Auth server needs a unique ip and port
        self.ip_address = ip_address
        self.port = port
        self.debug_mode = debug_mode
        self.connections_list = []
        self.threads = []
        self.active_connections = 0
        self.server_socket = self.custom_socket.create_socket()
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)
        self.protocol_handler = ProtocolHandler(debug_mode=debug_mode)
        self.auth_server_logic = AuthServerLogic(debug_mode=debug_mode)

    def setup_auth_server_db(self) -> None:
        """Setups Auth Server files databases."""
        try:
            # For Files root directory
            create_if_not_exists(path_to_create=Constants.FILES_DIR_PATH, is_dir=True)

            # For clients data
            create_if_not_exists(path_to_create=Constants.CLIENTS_FILE_PATH, is_file=True)

            # For servers data
            create_if_not_exists(path_to_create=Constants.SERVERS_FILE_PATH, is_file=True)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to setup {self.__class__.__name__}.", exception=e)

    def handle_new_connection(self, sck: socket) -> None:
        """Handles a new connection according to the communication protocol."""
        try:
            # Insert new connection
            self.new_connection(sck=sck, connections_list=self.connections_list, active_connections=self.active_connections)

            # TODO - load data from clients.txt and validate with new_connection. auth server protocol instructions #3
            # TODO - load it to ram template, its enough

            # Create new client RAM DB
            client_ram_template = ram_clients_template.copy()
            client_ram_template[Constants.RAM_LAST_SEEN] = time_now()

            # Create new server RAM DB
            server_ram_template = ram_servers_template

            # Receive requests from clients/services
            while True:
                auth_server_request = self.custom_socket.receive_packet(sck=sck, logger=self.logger)
                request_code, unpacked = self.protocol_handler.unpack_request(received_packet=auth_server_request,
                                                                              formatter=server_request.copy(),
                                                                              deserialize=True)

                # For dev mode:
                if self.debug_mode:
                    print(write_with_color(msg=f"Received Request --> Code: {request_code}, Data: {unpacked}",
                                           color=Colors.MAGENTA))

                # Handle register requests from Clients and Services
                if request_code == ProtoConsts.REQ_CLIENT_REG or request_code == ProtoConsts.REQ_SERVER_REG:

                    self.auth_server_logic.handle_registration_request(server_socket=self.custom_socket,
                                                                       client_socket=sck,
                                                                       request_code=request_code,
                                                                       unpacked_packet=unpacked,
                                                                       client_ram_template=client_ram_template,
                                                                       server_ram_template=server_ram_template,
                                                                       server_response=server_response.copy())
                    # For dev mode
                    if self.debug_mode:
                        print(write_with_color(msg=f"Registered client template --> {client_ram_template}", color=Colors.CYAN))
                        print(write_with_color(msg=f"Registered server template --> {server_ram_template}", color=Colors.CYAN))

                # Handle AES key request from client
                elif request_code == ProtoConsts.REQ_AES_KEY:
                    self.auth_server_logic.handle_aes_key_request(server_socket=self.custom_socket,
                                                                  client_socket=sck,
                                                                  unpacked_packet=unpacked,
                                                                  client_ram_template=client_ram_template,
                                                                  server_response=server_response.copy())

                    # For dev mode
                    if self.debug_mode:
                        print(write_with_color(msg=f"AES key client template --> {client_ram_template}",
                                               color=Colors.CYAN))

                # Handle services list request from client
                elif request_code == ProtoConsts.REQ_MSG_SERVERS_LIST:

                    self.auth_server_logic.handle_services_list_request(server_socket=self.custom_socket,
                                                                        client_socket=sck,
                                                                        server_response=server_response.copy())
                # Send general server error in any other case
                else:
                    self.auth_server_logic.send_server_general_error(server_socket=self.custom_socket,
                                                                     client_socket=sck,
                                                                     server_response=server_response.copy())
                    raise ValueError(f"Unsupported request code {request_code}.")

            # TODO - create json file for each client according to his uuid json summery of all his and the server session
        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle client {sck.getpeername()}.", exception=e)

    # TODO - move server run method to interface for all servers
    def run(self) -> None:
        try:
            # Initialize Server
            self.setup_server(sck=self.server_socket)

            # Setup Server needed files DB
            self.setup_auth_server_db()

            # Set Logger custom filter
            CustomFilter.filter_name = get_calling_method_name()

            # Print welcome message
            print(Constants.KERBEROS_LOGO, end='\n\n')
            print(Constants.AUTH_SERVER_LOGO, end='\n\n')
            print(f"{ProtoConsts.CONSOLE_ACK} Starting Server...")
            print(f"{ProtoConsts.CONSOLE_ACK} Server is now listening on {self.ip_address}:{self.port}")

            # Wait for clients requests
            while True:
                connection, address = self.server_socket.accept()
                print(f"{ProtoConsts.CONSOLE_ACK} Connected to peer {connection.getpeername()}")

                # Assign new thread to each connected client
                client_thread = Thread(target=self.handle_new_connection, args=(connection,))
                client_thread.start()
                self.threads.append(client_thread)

        except Exception as e:
            self.logger.logger.error(msg=str(e))

            # Cleanup
            self.server_socket.close()
            for thread in self.threads:
                thread.join()

            raise CustomException(error_msg=f"Unable to run {self.__class__.__name__}.", exception=e)


