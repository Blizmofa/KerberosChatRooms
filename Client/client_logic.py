import base64
import json
import struct
import socket
from copy import deepcopy
import pickle
from Socket.custom_socket import CustomSocket
from Utils.logger import Logger
from Utils import utils
from Utils.custom_exception_handler import CustomException
from Protocol_Handler.protocol_handler import ProtocolHandler
from Protocol_Handler import protocol_utils
from Client import client_constants
from Utils.encryptor import Encryptor


class ClientLogic(CustomSocket):

    def __init__(self, server_ip: str, server_port: int, connection_protocol: str, debug_mode: bool) -> None:
        super().__init__(connection_protocol)
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_socket = super().create_socket()
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)
        self.protocol_handler = ProtocolHandler(debug_mode=debug_mode)
        self.encryptor = Encryptor(debug_mode=debug_mode)

    def setup(self):
        try:
            self.client_socket.connect((self.server_ip, self.server_port))
            self.logger.logger.info(f"Connected to {self.server_ip}:{self.server_port} successfully.")

        except Exception as e:
            raise CustomException(error_msg=f"Unable to setup client.", exception=e)

    def handle_registration_request(self, client_ram_template: dict, server_request: dict, server_response: dict) -> bool:
        try:
            # Pack and send register request
            client_id = client_ram_template[client_constants.Constants.RAM_ID]
            # TODO - refactor
            if isinstance(client_id, str):
                client_id = utils.convert_bytes_or_hex(data=client_id, mode=protocol_utils.Constants.BYTES)
            data = {
                protocol_utils.Constants.CLIENT_ID: client_id,
                protocol_utils.Constants.VERSION: protocol_utils.Constants.SERVER_VERSION,
                protocol_utils.Constants.CODE: protocol_utils.Constants.REQ_CLIENT_REG,
                protocol_utils.Constants.PAYLOAD_SIZE: protocol_utils.Constants.SIZE_CLIENT_NAME + protocol_utils.Constants.SIZE_PASSWORD,
                protocol_utils.Constants.NAME: utils.parse_info_file(file_path=client_constants.Constants.CLIENT_FILE_NAME, target_line_number=2).encode(),
                protocol_utils.Constants.PASSWORD: client_ram_template[client_constants.Constants.RAM_PASSWORD]
            }

            packed_register_request = self.protocol_handler.pack_request(code=protocol_utils.Constants.REQ_CLIENT_REG,
                                                                         data=data,
                                                                         formatter=server_request)
            self.send_packet(sck=self.client_socket, packet=packed_register_request)

            # Receive register response
            register_response = self.receive_packet(sck=self.client_socket)
            response_code, unpacked_register_response = self.protocol_handler.unpack_request(
                received_packet=register_response,
                formatter=server_response,
                deserialize=True)

            # Register success
            if response_code == protocol_utils.Constants.RES_REGISTER_SUCCESS:
                hexed_client_id = utils.convert_bytes_or_hex(
                    data=unpacked_register_response[protocol_utils.Constants.CLIENT_ID],
                    mode=protocol_utils.Constants.HEX)
                utils.insert_value_into_file(value=hexed_client_id,
                                             target_line=3,
                                             file_path=client_constants.Constants.CLIENT_FILE_NAME,
                                             max_lines=3)
                print("Registration successful.")
                client_ram_template[client_constants.Constants.RAM_IS_REGISTERED] = True
                return True
                # TODO - cleanup, close socket to auth server

            elif response_code == protocol_utils.Constants.RES_REGISTER_FAILED:
                print("Registration failure")
                return False

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle registration request.", exception=e)

    def handle_aes_key_request(self, client_ram_template: dict, server_request: dict, server_response: dict):
        try:
            # Generate random nonce value
            client_nonce = utils.generate_nonce()
            client_ram_template[client_constants.Constants.RAM_NONCE] = utils.convert_bytes_or_hex(data=client_nonce,
                                                                                                   mode=protocol_utils.Constants.HEX)

            # Pack and send request
            # TODO - server id is the wanted msg server
            data = {
                protocol_utils.Constants.CLIENT_ID: utils.convert_bytes_or_hex(
                    data=client_ram_template[client_constants.Constants.RAM_ID],
                    mode=protocol_utils.Constants.BYTES),
                protocol_utils.Constants.VERSION: protocol_utils.Constants.SERVER_VERSION,
                protocol_utils.Constants.CODE: protocol_utils.Constants.REQ_AES_KEY,
                protocol_utils.Constants.PAYLOAD_SIZE: protocol_utils.Constants.SIZE_CLIENT_ID + protocol_utils.Constants.SIZE_NONCE,
                protocol_utils.Constants.SERVER_ID: None,
                protocol_utils.Constants.NONCE: client_nonce
            }

            packed_aes_request = self.protocol_handler.pack_request(code=protocol_utils.Constants.REQ_AES_KEY,
                                                                    data=data,
                                                                    formatter=server_request)

            self.send_packet(sck=self.client_socket, packet=packed_aes_request, logger=self.logger)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle encrypted key request.", exception=e)

    def handle_services_list_request(self, client_ram_template: dict, server_request: dict, server_response: dict):
        try:

            # TODO - refactor
            client_id = client_ram_template[client_constants.Constants.RAM_ID]
            if isinstance(client_id, str):
                client_id = utils.convert_bytes_or_hex(data=client_id, mode=protocol_utils.Constants.BYTES)
            data = {
                protocol_utils.Constants.CLIENT_ID: client_id,
                protocol_utils.Constants.VERSION: protocol_utils.Constants.SERVER_VERSION,
                protocol_utils.Constants.CODE: protocol_utils.Constants.REQ_MSG_SERVERS_LIST,
                protocol_utils.Constants.PAYLOAD_SIZE: 0
            }
            packed_services_list_request = self.protocol_handler.pack_request(
                code=protocol_utils.Constants.REQ_MSG_SERVERS_LIST,
                data=data,
                formatter=server_request)

            self.send_packet(sck=self.client_socket, packet=packed_services_list_request)

            # Receive response
            # TODO - receive with chunks, not with buffer, recv when server is still sending
            servers_list_response = self.receive_packet(sck=self.client_socket, receive_buffer=4096,
                                                        logger=self.logger)

            response_code, unpacked = self.protocol_handler.unpack_request(received_packet=servers_list_response,
                                                                           formatter=server_response,
                                                                           deserialize=True)

            server_data_formatter = protocol_utils.code_to_payload_template[protocol_utils.Constants.RES_MSG_SERVERS_LIST].copy()
            server_list = []
            fmt_str = self.protocol_handler.generate_packet_fmt(raw_packet=server_data_formatter)

            packet_size = struct.calcsize(fmt_str)

            for i in range(0, unpacked[protocol_utils.Constants.PAYLOAD_SIZE], packet_size):
                server = unpacked[protocol_utils.Constants.SERVERS_LIST][i:i + packet_size]
                unpacked_server = struct.unpack(fmt_str, server)

                raw_data = self.protocol_handler.deserialize_packet(packet=unpacked_server, index_to_pass=2)
                server_data = self.protocol_handler.build_packet_format(code=protocol_utils.Constants.RES_MSG_SERVERS_LIST,
                                                                        formatter=server_data_formatter.copy())

                server_data.update(self.protocol_handler.insert_unpacked_packet_content(data_format=server_data,
                                                                                        unpacked_packet=raw_data))

                server_data.update(self.protocol_handler.serialize_packet_value(formatter=server_data_formatter,
                                                                                data=server_data,
                                                                                mode=protocol_utils.Constants.DESERIALIZE))
                server_list.append(server_data)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle services list request.", exception=e)

    def run(self) -> None:

        try:
            # Setup client
            self.setup()

            # TODO - enter chat mode
            # Create client RAM template and parse needed data from file DB
            client_ram_template = client_constants.client_ram_template.copy()
            client_ram_template[client_constants.Constants.RAM_USERNAME] = utils.parse_info_file(
                file_path=client_constants.Constants.CLIENT_FILE_NAME, target_line_number=2)
            client_ram_template[client_constants.Constants.RAM_PASSWORD] = "qwer1234"
            client_ram_template[client_constants.Constants.RAM_ID] = utils.parse_info_file(
                file_path=client_constants.Constants.CLIENT_FILE_NAME, target_line_number=3)
            client_ram_template[client_constants.Constants.RAM_IS_REGISTERED] = False

            # Create formatters templates
            server_request = protocol_utils.server_request.copy()
            server_response = protocol_utils.server_response.copy()

            # Handle registration request from Authentication Server
            # self.handle_registration_request(client_ram_template=client_ram_template,
            #                                  server_request=server_request,
            #                                  server_response=server_response)

            # TODO - temp protocol:
            # TODO - close socket to auth server
            #  1. connect to a msg server
            #  2. send request 1028
            #  3. receive response 1604
            #  4. send request 1029 --> handle method that takes input. first print welcome to msg server message.
            #  5. receive response 1605

            # TODO - connect to Msg Server, hardcoded

            # TODO - send packed data packet, according to communication protocol

            # Handle AES key request from Authentication Server
            self.handle_aes_key_request(client_ram_template=client_ram_template,
                                        server_request=server_request,
                                        server_response=server_response)

            # Handle services list request
            # self.handle_services_list_request(client_ram_template=client_ram_template,
            #                                   server_request=server_request,
            #                                   server_response=server_response)


        except Exception as e:
            raise CustomException(error_msg=f"Unable to run {self.__class__.__name__}.", exception=e)

# TODO - for the all project, if debug mode print_with_color for dev informative outputs
# TODO - formatter should be a copy, dont pass the original one
