from sys import exit as sys_exit
from struct import unpack, calcsize
from Utils.utils import write_with_color, Colors, fetch_entry_from_json_db
from Utils.custom_exception_handler import CustomException, get_calling_method_name
from Utils.logger import Logger, CustomFilter
from Utils.validator import Validator, ValConsts
from Utils.encryptor import Encryptor
from Socket.custom_socket import socket, Thread
from Server.server_interface import ServerInterface
from Server.MsgServer.msg_server_constants import ram_service_template, MsgConsts
from Server.MsgServer.service_registration_handler import RegistrationHandler
from Server.MsgServer.symmetric_key_handler import SymmetricKeyHandler
from Protocol_Handler.protocol_handler import ProtocolHandler
from Protocol_Handler.protocol_utils import server_request, server_response, packet_no_payload, ProtoConsts


class MsgServerCore(ServerInterface):
    """Handles the Msg Server core functionalities."""

    def __init__(self, connection_protocol: str, ip_address: str, port: int, service_name: str, debug_mode: bool) -> None:
        super().__init__(connection_protocol, ip_address, port, debug_mode)
        self.ip_address = ip_address
        self.port = port
        self.service_name = service_name
        self.debug_mode = debug_mode
        self.connections_list = []
        self.threads = []
        self.active_connections = 0
        self.client_socket = self.custom_socket.create_socket()
        self.service_socket = self.custom_socket.create_socket()
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)
        self.protocol_handler = ProtocolHandler(debug_mode=debug_mode)
        self.encryptor = Encryptor(debug_mode=debug_mode)
        self.registration_handler = RegistrationHandler(debug_mode=debug_mode)
        self.symmetric_key_handler = SymmetricKeyHandler(debug_mode=debug_mode)

    def setup_as_client(self) -> None:
        """Setups the Msg Server as a client in order to register to AS."""
        try:
            self.custom_socket.connect(sck=self.client_socket, ip_address=self.ip_address, port=self.port)
            self.logger.logger.info(f"Connected to {self.ip_address}:{self.port} successfully.")

        except Exception as e:
            raise CustomException(error_msg=f"Unable to setup {self.__class__.__name__} as client", exception=e)

    def handle_peer(self, sck: socket, ram_template: dict) -> None:
        """Starts the Chat Room."""
        try:
            # Insert new connection
            self.add_new_connection(sck=sck,
                                    connections_list=self.connections_list,
                                    active_connections=self.active_connections)

            # Log
            CustomFilter.filter_name = get_calling_method_name()
            msg = f"{sck.getpeername()} has entered the chat."
            self.logger.logger.info(msg=msg)

            # For dev mode
            if self.debug_mode:
                print(write_with_color(msg=f"{ProtoConsts.CONSOLE_ACK} {msg}", color=Colors.GREEN))

            # Start chat
            while True:

                # Monitor peers connections
                if not self.custom_socket.monitor_connection(sck=sck):
                    self.cleanup(sck=sck,
                                 connections_list=self.connections_list,
                                 active_connections=self.active_connections)

                # Receive encrypted message request
                msg_request = self.custom_socket.receive_packet(sck=sck, logger=self.logger)

                # Peer has disconnected
                if not msg_request:
                    break

                # Adjust sizes to get encrypted message content
                msg_formatter = self.protocol_handler.build_packet_format(code=ProtoConsts.PKT_ENC_MSG_WITHOUT_CONTENT,
                                                                          formatter=server_request.copy())
                msg_fmt = self.protocol_handler.generate_packet_fmt(raw_packet=msg_formatter)
                msg_content_size = len(msg_request[calcsize(msg_fmt):])

                # Unpack encrypted message packet
                unpacked_msg_request = unpack(f"{msg_fmt}{msg_content_size}s", msg_request)
                client_id, version, code, payload_size, msg_size, msg_iv, msg_content = unpacked_msg_request

                # Fetch and validate service AES key
                aes_key = ram_template[MsgConsts.RAM_AES_KEY]
                Validator.validate_injection(data_type=ValConsts.FMT_AES_KEY, value_to_validate=aes_key)

                # Decrypt message and print to screen
                decrypted_msg = self.encryptor.decrypt(encrypted_value=msg_content,
                                                       decryption_key=aes_key,
                                                       iv=msg_iv).decode()
                print(decrypted_msg)

                packet_no_payload[ProtoConsts.CODE] = ProtoConsts.RES_MSG_ACK
                packed_msg_ack = self.protocol_handler.pack_request(code=ProtoConsts.RES_AES_KEY_ACK,
                                                                    data=packet_no_payload,
                                                                    formatter=server_response.copy())
                self.custom_socket.send_packet(sck=sck, packet=packed_msg_ack, logger=self.logger)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle client {sck.getpeername()}.", exception=e)    

    def setup_as_chat_room(self, service_ram_template: dict) -> None:
        try:
            # Get DNS mapping from RAM
            self.ip_address = service_ram_template[MsgConsts.RAM_IP_ADDRESS]
            self.port = service_ram_template[MsgConsts.RAM_PORT]

            # Initialize Server
            self.setup_server(sck=self.service_socket)

            # Print welcome message
            print(MsgConsts.MSG_SERVER_LOGO, end='\n\n')
            print(f"{ProtoConsts.CONSOLE_ACK} Starting Server...")
            print(f"{ProtoConsts.CONSOLE_ACK} Server is now listening on {self.ip_address}:{self.port}")

            # Wait for clients requests
            while True:
                connection, address = self.service_socket.accept()
                print(f"{ProtoConsts.CONSOLE_ACK} Connected to peer {connection.getpeername()}")

                # Handle Symmetric Key requests from clients
                if self.symmetric_key_handler.handle_symmetric_key_request(sck=self.custom_socket,
                                                                           client_socket=connection,
                                                                           ram_template=service_ram_template,
                                                                           encryptor=self.encryptor,
                                                                           protocol_handler=self.protocol_handler):

                    # Assign new thread to each connected client and enter chat mode
                    client_thread = Thread(target=self.handle_peer, args=(connection, service_ram_template))
                    client_thread.start()
                    self.threads.append(client_thread)
                else:
                    # TODO - return server error
                    pass

        except Exception as e:
            self.logger.logger.error(str(e))

            # Cleanup
            self.service_socket.close()
            for thread in self.threads:
                thread.join()

            raise CustomException(error_msg=f"Unable to run {self.__class__.__name__}.", exception=e)

    def run(self) -> None:

        # TODO - update services_pool DB with message and ticket iv. check that aes key is the same as the ticket key
        # TODO - if service id in services pool, already registered, fetch id like in client case
        # TODO - if already registered and in services_pool start service

        # Create service RAM template and update its values
        service_ram_template = ram_service_template.copy()
        service_ram_template[MsgConsts.RAM_SERVICE_NAME] = self.service_name
        Validator.validate_injection(data_type=ValConsts.FMT_NAME, value_to_validate=self.service_name)

        # Default service
        if self.service_name == MsgConsts.DEF_SERVER_NAME:

            # Fetch data from file DB and update RAM DB
            default_service_entry = fetch_entry_from_json_db(file_path=MsgConsts.SERVICE_POOL_FILE_NAME,
                                                             pivot_key=MsgConsts.RAM_SERVICE_NAME,
                                                             pivot_value=self.service_name)

            default_aes_key = default_service_entry[MsgConsts.RAM_AES_KEY_HEX]
            default_server_id = default_service_entry[MsgConsts.RAM_SERVICE_ID_HEX]
            if isinstance(default_aes_key, str):
                default_service_entry[MsgConsts.RAM_AES_KEY] = Validator.validate_injection(data_type=ValConsts.FMT_AES_KEY,
                                                                                            value_to_validate=default_aes_key)
            if isinstance(default_server_id, str):
                default_service_entry[MsgConsts.RAM_SERVICE_ID] = Validator.validate_injection(data_type=ValConsts.FMT_ID,
                                                                                               value_to_validate=default_server_id)
            service_ram_template.update(default_service_entry)

            # For dev mode
            if self.debug_mode:
                print(write_with_color(msg=f"Parsed service template --> {service_ram_template}",
                                       color=Colors.CYAN))

            # Start default service
            self.setup_as_chat_room(service_ram_template=service_ram_template)

        # Service Manager services
        else:
            # Setup first as a client
            self.setup_as_client()

            # Register
            if not self.registration_handler.handle_registration_request(sck=self.custom_socket,
                                                                         client_socket=self.client_socket,
                                                                         ram_template=service_ram_template,
                                                                         service_name=self.service_name,
                                                                         encryptor=self.encryptor,
                                                                         protocol_handler=self.protocol_handler):

                print(write_with_color(msg=f"{ProtoConsts.CONSOLE_FAIL} Register to Auth server has failed, "
                                           f"shutting down", color=Colors.RED))
                self.client_socket.close()
                sys_exit(ProtoConsts.STATUS_ERROR_CODE)

            # For dev mode
            if self.debug_mode:
                print(write_with_color(msg=f"Registered service template --> {service_ram_template}",
                                       color=Colors.CYAN))

            # Initialize Server as a service only on registration success
            self.setup_as_chat_room(service_ram_template=service_ram_template)








