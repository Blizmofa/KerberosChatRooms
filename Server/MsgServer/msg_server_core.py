from Socket.custom_socket import socket, Thread
from Server.server_interface import ServerInterface
from Utils.custom_exception_handler import CustomException
from Utils.logger import Logger
from Server.MsgServer.msg_server_logic import MsgServerLogic
from Server.MsgServer.msg_server_constants import ram_service_template, Constants as MsgConsts
from Utils import utils
from Utils.validator import Validator, Constants as ValConsts
import os
from Utils.encryptor import Encryptor
from Protocol_Handler.protocol_handler import ProtocolHandler
from Protocol_Handler.protocol_utils import server_request, server_response, ProtocolConstants as ProtoConsts


class MsgServer(ServerInterface):
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
        self.msg_server_logic = MsgServerLogic(debug_mode=debug_mode)

    def setup_as_client(self):
        """Setups the Msg Server as a client in order to register to Authentication server."""
        try:

            self.client_socket.connect((self.ip_address, self.port))
            self.logger.logger.info(f"Connected to {self.ip_address}:{self.port} successfully.")

        except Exception as e:
            raise CustomException(error_msg=f"Unable to setup {self.__class__.__name__} as client", exception=e)

    def create_default_msg_server(self) -> None:
        """Creates a registered default Msg server in case of system failure."""
        try:
            # Create default server data
            default_server_id = utils.generate_uuid()
            default_aes_key = self.encryptor.generate_bytes_stream(size=ProtoConsts.SIZE_AES_KEY)

            msg_info_data = {
                ValConsts.FMT_IPV4_PORT: f"{MsgConsts.DEF_IP_ADDRESS}:{MsgConsts.DEF_PORT_NUM}",
                ValConsts.FMT_NAME: f"{MsgConsts.DEF_SERVER_NAM_FMT}{utils.generate_random_num(lower_bound=11, upper_bound=19)}",
                ValConsts.FMT_ID: default_server_id.hex(),
                ValConsts.FMT_AES_KEY: self.encryptor.encode_decode_base64(value=default_aes_key,
                                                                           mode=ProtoConsts.ENCODE)
            }

            # Register default server
            utils.create_info_file(file_name=f"{MsgConsts.MSG_FILE_NAME}", file_data=msg_info_data)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to create default {self.__class__.__name__}.", exception=e)

    def handle_new_client(self, sck: socket) -> None:
        try:
            # Insert new connection
            self.new_connection(sck=sck, connections_list=self.connections_list, active_connections=self.active_connections)

            # TODO - close socket to auth server
            # TODO - Unpack packet
            # TODO - handle encrypted key request from client 1028, unpack authenticator and ticket
            # TODO - handle client msg request --> chat mode

            # # Create new client RAM DB
            # client_ram_template = ram_service_template.copy()
            
            # Handle Symmetric Key 1028 request
            symmetric_key_request = self.custom_socket.receive_packet(sck=sck, logger=self.logger)

            # Enter chat mode

            # self.msg_server_logic.handle_registration_request(sck=sck, client_ram_template=client_ram_template, register_request=symmetric_key_request)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle client {sck.getpeername()}.", exception=e)    

    def handle_registration_request(self, service_ram_template: dict, server_request_formatter: dict, server_response_formatter: dict) -> bool:
        try:
            # Create service AES key and update RAM DB
            msg_server_aes_key = self.encryptor.generate_bytes_stream(size=ProtoConsts.SIZE_AES_KEY)
            service_ram_template[MsgConsts.RAM_AES_KEY] = msg_server_aes_key
            service_ram_template[MsgConsts.RAM_AES_KEY_HEX] = msg_server_aes_key.hex()

            # Create packet data frame
            data = {
                ProtoConsts.CLIENT_ID: None,
                ProtoConsts.VERSION: ProtoConsts.SERVER_VERSION,
                ProtoConsts.CODE: ProtoConsts.REQ_SERVER_REG,
                ProtoConsts.PAYLOAD_SIZE: ProtoConsts.SIZE_SERVER_NAME + ProtoConsts.SIZE_AES_KEY,
                ProtoConsts.NAME: self.service_name,
                ProtoConsts.AES_KEY: msg_server_aes_key
            }

            # Pack and send register request
            packed_register_request = self.protocol_handler.pack_request(code=ProtoConsts.REQ_SERVER_REG,
                                                                         data=data,
                                                                         formatter=server_request_formatter)
            self.custom_socket.send_packet(sck=self.client_socket, packet=packed_register_request, logger=self.logger)

            # Receive register response, unpack and deserialize packet data
            register_response = self.custom_socket.receive_packet(sck=self.client_socket)
            response_code, unpacked_register_response = self.protocol_handler.unpack_request(received_packet=register_response,
                                                                                             formatter=server_response_formatter,
                                                                                             deserialize=True)
            # For dev mode
            if self.debug_mode:
                print(utils.write_with_color(
                    msg=f"Received Response --> Code: {response_code}, Data: {unpacked_register_response}",
                    color=utils.Colors.MAGENTA))

            # Register success
            if response_code == ProtoConsts.RES_REGISTER_SUCCESS:

                service_id = unpacked_register_response[ProtoConsts.CLIENT_ID]
                service_ram_template[MsgConsts.RAM_SERVICE_ID] = service_id
                service_ram_template[MsgConsts.RAM_SERVICE_ID_HEX] = service_id.hex()

                # Update the new DNS mapping ip and port
                self.ip_address, self.port = self.client_socket.getsockname()

                service_ram_template[MsgConsts.RAM_IP_ADDRESS] = self.ip_address
                service_ram_template[MsgConsts.RAM_PORT] = self.port
                service_ram_template[MsgConsts.RAM_IS_REGISTERED] = True
                print(utils.write_with_color(msg=f"{ProtoConsts.CONSOLE_ACK} Registration successful.",
                                             color=utils.Colors.GREEN))

                # Update services JSON db
                utils.insert_data_to_json_db(file_path=MsgConsts.SERVICE_POOL_FILE_NAME,
                                             data=service_ram_template,
                                             pivot_key=MsgConsts.RAM_SERVICE_NAME,
                                             pivot_value=self.service_name)
                return True

            elif response_code == ProtoConsts.RES_REGISTER_FAILED:
                print(utils.write_with_color(msg=f"{ProtoConsts.CONSOLE_FAIL} Registration failure.",
                                             color=utils.Colors.RED))
                return False

        except Exception as e:
            # Register default server
            self.create_default_msg_server()
            raise CustomException(error_msg=f"Unable to handle registration request.", exception=e)

        finally:
            # Close socket to Auth Server
            self.client_socket.close()

    def setup_as_msg_server(self):
        try:
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

                # Assign new thread to each connected client
                client_thread = Thread(target=self.handle_new_client, args=(connection, ))
                client_thread.start()
                self.threads.append(client_thread)

        except Exception as e:
            # Cleanup
            self.service_socket.close()
            for thread in self.threads:
                thread.join()

            raise CustomException(error_msg=f"Unable to run {self.__class__.__name__}.", exception=e)

    def run(self) -> None:

        # Setup first as a client
        self.setup_as_client()

        # Create service RAM template and update its values
        service_ram_template = ram_service_template.copy()
        service_ram_template[MsgConsts.RAM_SERVICE_NAME] = self.service_name
        Validator.validate_injection(data_type=ValConsts.FMT_NAME, value_to_validate=self.service_name)

        # For dev mode
        if self.debug_mode:
            print(utils.write_with_color(msg=f"Parsed service template --> {service_ram_template}", color=utils.Colors.CYAN))

        # Create formatters templates
        server_request_formatter = server_request.copy()
        server_response_formatter = server_response.copy()

        # Register
        if self.handle_registration_request(service_ram_template=service_ram_template,
                                            server_request_formatter=server_request_formatter,
                                            server_response_formatter=server_response_formatter):
            # For dev mode
            if self.debug_mode:
                print(utils.write_with_color(msg=f"Registered service template --> {service_ram_template}",
                                             color=utils.Colors.CYAN))

            # Initialize Server as a service only on registration success
            self.setup_as_msg_server()








