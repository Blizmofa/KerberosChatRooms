from Socket.custom_socket import socket, Thread
from Utils import utils
from Utils.logger import Logger, CustomFilter
from Utils.custom_exception_handler import CustomException, get_calling_method_name
from Utils.validator import Validator, ValConsts
from Protocol_Handler.protocol_handler import ProtocolHandler
from Protocol_Handler.protocol_constants import ProtoConsts
from Protocol_Handler.protocol_templates import server_request
from Server.server_interface import ServerInterface
from Server.AuthServer.auth_server_constants import ram_clients_template, ram_servers_template, AuthConsts
from Server.AuthServer.auth_server_logic import AuthServerLogic


class AuthServerCore(ServerInterface):
    """Handles the Auth Server core functionalities."""

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
            utils.create_if_not_exists(path_to_create=AuthConsts.FILES_DIR_PATH, is_dir=True)

            # For clients data
            utils.create_if_not_exists(path_to_create=AuthConsts.CLIENTS_FILE_PATH, is_file=True)

            # For servers data
            utils.create_if_not_exists(path_to_create=AuthConsts.SERVICES_FILE_PATH, is_file=True)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to setup {self.__class__.__name__}.", exception=e)

    def __load_client_data_into_ram_db(self, client_id: bytes, ram_template: dict) -> dict:
        """Private method to fetch Client entry from file DB and load it into RAM DB."""
        try:
            client_id_hex = client_id.hex()
            if not utils.search_value_in_txt_file(value=client_id_hex, file_path=AuthConsts.CLIENTS_FILE_PATH):
                return ram_template

            # Fetch client entry
            client_entry = utils.fetch_value_from_txt_db(file_path=AuthConsts.CLIENTS_FILE_PATH,
                                                         target_value=client_id_hex).split(': ')
            # Load entry into RAM template
            ram_template[AuthConsts.RAM_CLIENT_ID] = client_id
            ram_template[AuthConsts.RAM_CLIENT_ID_HEX] = client_id_hex
            ram_template[AuthConsts.RAM_CLIENT_NAME] = client_entry[AuthConsts.INDEX_CLIENT_NAME]
            password_hash = client_entry[AuthConsts.INDEX_CLIENT_PASSWORD_HASH]
            if isinstance(password_hash, str):
                ram_template[AuthConsts.RAM_PASSWORD_HASH_HEX] = password_hash
                password_hash = Validator.validate_injection(data_type=ValConsts.FMT_PASSWORD,
                                                             value_to_validate=password_hash)
                ram_template[AuthConsts.RAM_PASSWORD_HASH] = password_hash
            ram_template[AuthConsts.RAM_IS_REGISTERED] = True

            # For dev mode
            if self.debug_mode:
                print(utils.write_with_color(msg=f"Client RAM Template --> {ram_template}", color=utils.Colors.CYAN))

        except Exception as e:
            raise CustomException(error_msg=f"Unable to load client data into RAM DB.", exception=e)

    def handle_peer(self, sck: socket, ram_template: dict) -> None:
        """Handles a new connection according to the communication protocol."""
        try:
            # Insert new connection
            self.add_new_connection(sck=sck, connections_list=self.connections_list, active_connections=self.active_connections)

            # Update RAM DB
            ram_template[AuthConsts.RAM_LAST_SEEN] = utils.time_now()
            ram_template[AuthConsts.RAM_IS_REGISTERED] = False

            # Create new server RAM DB
            server_ram_template = ram_servers_template.copy()
            server_ram_template[AuthConsts.RAM_IS_REGISTERED] = False

            # Receive requests from clients/services
            while True:

                # Monitor peers connections
                if not self.custom_socket.monitor_connection(sck=sck):
                    self.cleanup(sck=sck, connections_list=self.connections_list, active_connections=self.active_connections)

                # Received request
                auth_server_request = self.custom_socket.receive_packet(sck=sck, logger=self.logger)

                # Peer has disconnected
                if not auth_server_request:
                    break

                # Unpack request
                request_code, unpacked = self.protocol_handler.unpack_request(received_packet=auth_server_request,
                                                                              formatter=server_request.copy(),
                                                                              deserialize=True)
                # For dev mode:
                if self.debug_mode:
                    print(utils.write_with_color(msg=f"Received Request --> Code: {request_code}, Data: {unpacked}",
                                                 color=utils.Colors.MAGENTA))

                # Check if client already registered
                client_id = unpacked[ProtoConsts.CLIENT_ID]
                if client_id:
                    self.__load_client_data_into_ram_db(client_id=client_id, ram_template=ram_template)

                # Handle register requests from Clients and Services
                if request_code == ProtoConsts.REQ_CLIENT_REG or request_code == ProtoConsts.REQ_SERVER_REG:

                    self.auth_server_logic.handle_registration_request(server_socket=self.custom_socket,
                                                                       client_socket=sck,
                                                                       request_code=request_code,
                                                                       unpacked_packet=unpacked,
                                                                       client_ram_template=ram_template,
                                                                       server_ram_template=server_ram_template)
                    # For dev mode
                    if self.debug_mode:
                        print(utils.write_with_color(msg=f"Registered client template --> {ram_template}",
                                                     color=utils.Colors.CYAN))
                        print(utils.write_with_color(msg=f"Registered server template --> {server_ram_template}",
                                                     color=utils.Colors.CYAN))

                # Handle AES key request from client
                elif request_code == ProtoConsts.REQ_AES_KEY:
                    self.auth_server_logic.handle_aes_key_request(server_socket=self.custom_socket,
                                                                  client_socket=sck,
                                                                  unpacked_packet=unpacked,
                                                                  client_ram_template=ram_template)

                    # For dev mode
                    if self.debug_mode:
                        print(utils.write_with_color(msg=f"AES key client template --> {ram_template}",
                                                     color=utils.Colors.CYAN))

                # Handle services list request from client
                elif request_code == ProtoConsts.REQ_MSG_SERVERS_LIST:

                    self.auth_server_logic.handle_services_list_request(server_socket=self.custom_socket,
                                                                        client_socket=sck,
                                                                        client_ram_template=ram_template)
                # Send general server error in any other case
                else:
                    self.auth_server_logic.send_server_general_error(server_socket=self.custom_socket,
                                                                     client_socket=sck)
                    self.cleanup(sck=sck, connections_list=self.connections_list, active_connections=self.active_connections)
                    raise ValueError(f"Unsupported request code {request_code}.")

        except Exception as e:
            self.logger.logger.error(msg=str(e))
            raise CustomException(error_msg=f"Unable to handle client {sck.getpeername()}.", exception=e)

    def run(self) -> None:
        """Auth Server main run method."""
        try:
            # Initialize Server
            self.setup_server(sck=self.server_socket)

            # Setup Server needed files DB
            self.setup_auth_server_db()

            # Set Logger custom filter
            CustomFilter.filter_name = get_calling_method_name()

            # Create new client RAM DB
            client_ram_template = ram_clients_template.copy()

            # Print welcome message
            print(AuthConsts.KERBEROS_LOGO, end='\n\n')
            print(AuthConsts.AUTH_SERVER_LOGO, end='\n\n')
            print(f"{ProtoConsts.CONSOLE_ACK} Starting Server...")
            print(f"{ProtoConsts.CONSOLE_ACK} Server is now listening on {self.ip_address}:{self.port}")

            # Wait for clients requests
            while True:
                connection, address = self.server_socket.accept()
                print(f"{ProtoConsts.CONSOLE_ACK} Connected to peer {connection.getpeername()}")

                # Assign new thread to each connected client
                client_thread = Thread(target=self.handle_peer, args=(connection, client_ram_template))
                client_thread.start()
                self.threads.append(client_thread)

        except Exception as e:
            self.logger.logger.error(msg=str(e))

            # Cleanup
            self.server_socket.close()
            for thread in self.threads:
                thread.join()

            raise CustomException(error_msg=f"Unable to run {self.__class__.__name__}.", exception=e)


