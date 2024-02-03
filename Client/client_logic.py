import struct
from typing import Union
from Socket.custom_socket import CustomSocket
from Utils.logger import Logger
from Utils import utils
from Utils.validator import Validator, Constants as ValConsts
from Utils.custom_exception_handler import CustomException
from Protocol_Handler.protocol_handler import ProtocolHandler
from Protocol_Handler.protocol_utils import ProtocolConstants as ProtoConsts, code_to_payload_template, server_request, server_response
from Client.client_constants import Constants as CConsts, client_ram_template, me_info_default_data, file_db_servers_template
from Utils.encryptor import Encryptor


class ClientLogic(CustomSocket):

    def __init__(self, server_ip: str, server_port: int, connection_protocol: str, debug_mode: bool) -> None:
        super().__init__(connection_protocol)
        self.server_ip = server_ip
        self.server_port = server_port
        self.debug_mode = debug_mode
        self.msg_servers_list = []
        self.client_socket = super().create_socket()
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)
        self.protocol_handler = ProtocolHandler(debug_mode=debug_mode)
        self.encryptor = Encryptor(debug_mode=debug_mode)

    def connect(self):
        """Setups the Msg Server as a client in order to register to Authentication server."""
        try:
            # TODO - ip and port should be paramters, change between servers
            self.client_socket.connect((self.server_ip, self.server_port))
            self.logger.logger.info(f"Connected to {self.server_ip}:{self.server_port} successfully.")

        except Exception as e:
            raise CustomException(error_msg=f"Unable to connect to {self.server_ip}:{self.server_port}", exception=e)

    def handle_registration_request(self, ram_template: dict, server_request_formatter: dict, server_response_formatter: dict) -> bool:
        """Handles client registration request logic."""
        try:
            # Validate data
            client_id = ram_template[CConsts.RAM_ID]
            if client_id and not isinstance(client_id, bytes):
                client_id = Validator.validate_injection(data_type=ValConsts.FMT_ID,
                                                         value_to_validate=client_id)
            client_username = ram_template[CConsts.RAM_USERNAME]
            Validator.validate_injection(data_type=ValConsts.FMT_NAME, value_to_validate=client_username)

            # Create packet data frame
            data = {
                ProtoConsts.CLIENT_ID: client_id,
                ProtoConsts.VERSION: ProtoConsts.SERVER_VERSION,
                ProtoConsts.CODE: ProtoConsts.REQ_CLIENT_REG,
                ProtoConsts.PAYLOAD_SIZE: ProtoConsts.SIZE_CLIENT_NAME + ProtoConsts.SIZE_PASSWORD,
                ProtoConsts.NAME: client_username,
                ProtoConsts.PASSWORD: ram_template[CConsts.RAM_PASSWORD]
            }

            # Pack and send register request
            packed_register_request = self.protocol_handler.pack_request(code=ProtoConsts.REQ_CLIENT_REG,
                                                                         data=data,
                                                                         formatter=server_request_formatter)
            self.send_packet(sck=self.client_socket, packet=packed_register_request)

            # Receive register response, unpack and deserialize packet data
            register_response = self.receive_packet(sck=self.client_socket)
            response_code, unpacked_register_response = self.protocol_handler.unpack_request(received_packet=register_response,
                                                                                             formatter=server_response_formatter,
                                                                                             deserialize=True)
            # For dev mode
            if self.debug_mode:
                print(utils.write_with_color(msg=f"Received Response --> Code: {response_code}, Data: {unpacked_register_response}", color=utils.Colors.MAGENTA))

            # Register success
            if response_code == ProtoConsts.RES_REGISTER_SUCCESS:

                client_id = unpacked_register_response[ProtoConsts.CLIENT_ID]
                # TODO - add client id gex to ram and work with it
                utils.insert_value_into_info_file(value=client_id.hex(),
                                                  target_line=2,
                                                  file_path=CConsts.CLIENT_FILE_NAME,
                                                  max_lines=2)
                print(utils.write_with_color(msg=f"{ProtoConsts.CONSOLE_ACK} Registration successful.",
                                             color=utils.Colors.GREEN))
                ram_template[CConsts.RAM_IS_REGISTERED] = True
                return True

            elif response_code == ProtoConsts.RES_REGISTER_FAILED:
                print(utils.write_with_color(msg=f"{ProtoConsts.CONSOLE_FAIL} Registration failure.",
                                             color=utils.Colors.RED))
                return False

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle registration request for client "
                                            f"'{ram_template[CConsts.RAM_USERNAME]}'.", exception=e)

    def __get_client_wanted_service(self) -> dict:
        """Private method that return the wanted service entry from Client DB."""
        try:
            # msg_servers_list = {'server_id': b'2\xb0\x07o\xa4ODx\x90\xd6f\xa6\xa8\xf5\x94z', 'server_name': 'Printer 10', 'server_ip': '127.0.0.1', 'server_port': 56841}
            # self.msg_servers_list = [{'server_id': b'2\xb0\x07o\xa4ODx\x90\xd6f\xa6\xa8\xf5\x94z', 'server_name': 'Printer 10', 'server_ip': '127.0.0.1', 'server_port': 56841}, {'server_id': b'j;\xd46)\x16O\xdd\x963a\x18t\xa5\x90z', 'server_name': 'Printer 20', 'server_ip': '127.0.0.1', 'server_port': 56846}, {'server_id': b'\xe9\xa8\x0c\xcf\t\x06O\x94\xb8d\xddP\x87\xc1\xd5\x9b', 'server_name': 'Printer 30', 'server_ip': '127.0.0.1', 'server_port': 56851}]
            # if msg_servers_list:
            server_name = "Printer 20"
            if self.msg_servers_list:
                # TODO - get wanted server name from client
                msg_server = utils.fetch_value_from_ram_db(data=self.msg_servers_list,
                                                          pivot_key=CConsts.RAM_SERVER_NAME,
                                                          pivot_value=server_name)

                self.logger.logger.debug(f"Fetched server id {msg_server} from servers list successfully.")
                return msg_server

            elif utils.check_if_exists(path_to_check=CConsts.SERVERS_FILE_NAME):
                msg_server = utils.fetch_value_from_json_db(file_path=CConsts.SERVERS_FILE_NAME,
                                                           pivot_key=CConsts.RAM_SERVER_NAME,
                                                           pivot_value=server_name)
                return msg_server

        except Exception as e:
            raise CustomException(error_msg=f"Unable to get client wanted service.", exception=e)

    def handle_aes_key_request(self, ram_template: dict, server_request_formatter: dict, server_response_formatter: dict) -> None:
        # TODO - continue from here, refactor
        try:
            # Generate random nonce value and validate it
            client_nonce = utils.generate_nonce()
            ram_template[CConsts.RAM_NONCE] = client_nonce
            Validator.validate_injection(data_type=ValConsts.FMT_NONCE, value_to_validate=client_nonce)

            # Validate client id
            client_id = ram_template[CConsts.RAM_ID]
            if client_id and not isinstance(client_id, bytes):
                client_id = Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=client_id)

            # Get client wanted service and validate data
            msg_server = self.__get_client_wanted_service()
            server_id = msg_server[CConsts.RAM_SERVER_ID]
            if not isinstance(server_id, bytes):
                server_id = Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=server_id)

            # Create packet data frame
            # TODO - server id is the wanted msg server
            data = {
                ProtoConsts.CLIENT_ID: client_id,
                ProtoConsts.VERSION: ProtoConsts.SERVER_VERSION,
                ProtoConsts.CODE: ProtoConsts.REQ_AES_KEY,
                ProtoConsts.PAYLOAD_SIZE: ProtoConsts.SIZE_CLIENT_ID + ProtoConsts.SIZE_NONCE,
                ProtoConsts.SERVER_ID: server_id,
                ProtoConsts.NONCE: client_nonce
            }

            packed_aes_request = self.protocol_handler.pack_request(code=ProtoConsts.REQ_AES_KEY,
                                                                    data=data,
                                                                    formatter=server_request_formatter)

            self.send_packet(sck=self.client_socket, packet=packed_aes_request, logger=self.logger)

            # Receive response
            encrypted_key_response = self.receive_packet(sck=self.client_socket, receive_buffer=4096,
                                                         logger=self.logger)

            response_code, unpacked_aes_key_response = self.protocol_handler.unpack_request(received_packet=encrypted_key_response,
                                                                           formatter=server_response_formatter,
                                                                           code=1603,
                                                                           deserialize=True)
            # For dev mode
            if self.debug_mode:
                print(utils.write_with_color(
                    msg=f"Received Response --> Code: {response_code}, Data: {unpacked_aes_key_response}",
                    color=utils.Colors.MAGENTA))


            # # TODO - add to client ram template
            # print(unpacked['ticket'])

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle encrypted key request.", exception=e)

    def __parse_servers_list_data(self, unpacked_data: bytes) -> None:
        """Private method to extract all the servers from the returned packed list."""
        try:
            # Create server list formatter template and calculate sizes
            server_data_formatter = code_to_payload_template[ProtoConsts.RES_MSG_SERVERS_LIST].copy()
            packed_server_fmt = self.protocol_handler.generate_packet_fmt(raw_packet=server_data_formatter)
            packed_server_size = struct.calcsize(packed_server_fmt)

            # Loop over the packed packet and handle each server separately
            for i in range(0, unpacked_data[ProtoConsts.PAYLOAD_SIZE], packed_server_size):
                server = unpacked_data[ProtoConsts.SERVERS_LIST][i:i + packed_server_size]
                unpacked_server = struct.unpack(packed_server_fmt, server)

                # Deserialize server raw data
                raw_data = self.protocol_handler.deserialize_packet(packet=unpacked_server, index_to_pass=2)
                server_data = self.protocol_handler.build_packet_format(code=ProtoConsts.RES_MSG_SERVERS_LIST,
                                                                        formatter=server_data_formatter.copy())

                server_data.update(self.protocol_handler.insert_unpacked_packet_content(data_format=server_data,
                                                                                        unpacked_packet=raw_data))

                server_data.update(self.protocol_handler.serialize_packet_value(formatter=server_data_formatter,
                                                                                data=server_data,
                                                                                mode=ProtoConsts.DESERIALIZE))
                self.msg_servers_list.append(server_data)

            # For dev mode:
            if self.debug_mode:
                print(utils.write_with_color(msg=f"Parsed services list: {self.msg_servers_list}", color=utils.Colors.CYAN))

            # Insert servers to file DB
            # TODO - refactor into validator, maybe all of the handler serialize method with ipv4
            # print(self.msg_servers_list)
            for server in self.msg_servers_list:
                if isinstance(server[ProtoConsts.SERVER_ID], bytes):
                    server[ProtoConsts.SERVER_ID] = Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=server[ProtoConsts.SERVER_ID])
            utils.create_json_file(file_path=CConsts.SERVERS_FILE_NAME, data=self.msg_servers_list)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to parse servers list.", exception=e)

    def handle_services_list_request(self, ram_template: dict, server_request_formatter: dict, server_response_formatter: dict) -> None:
        try:
            # Validate data
            client_id = ram_template[CConsts.RAM_ID]
            if client_id and not isinstance(client_id, bytes):
                client_id = Validator.validate_injection(data_type=ValConsts.FMT_ID,
                                                         value_to_validate=client_id)
            # Create packet data frame
            data = {
                ProtoConsts.CLIENT_ID: client_id,
                ProtoConsts.VERSION: ProtoConsts.SERVER_VERSION,
                ProtoConsts.CODE: ProtoConsts.REQ_MSG_SERVERS_LIST,
                ProtoConsts.PAYLOAD_SIZE: 0
            }

            # Pack and send register request
            packed_services_list_request = self.protocol_handler.pack_request(code=ProtoConsts.REQ_MSG_SERVERS_LIST,
                                                                              data=data,
                                                                              formatter=server_request_formatter)
            self.send_packet(sck=self.client_socket, packet=packed_services_list_request)

            # Receive servers list response, unpack and deserialize packet data
            # TODO - receive with chunks, not with buffer, recv when server is still sending
            servers_list_response = self.receive_packet(sck=self.client_socket, receive_buffer=4096,
                                                        logger=self.logger)

            response_code, unpacked_servers_list_response = self.protocol_handler.unpack_request(received_packet=servers_list_response,
                                                                                                 formatter=server_response_formatter,
                                                                                                 deserialize=True)
            # In case there aren't any msg servers registered, also not the default one
            if response_code == ProtoConsts.RES_GENERAL_ERROR:
                print(utils.write_with_color(msg=f"{ProtoConsts.CONSOLE_ERROR} {CConsts.SERVER_GENERAL_ERROR}",
                                             color=utils.Colors.RED))

            # For dev mode
            if self.debug_mode:
                print(utils.write_with_color(
                    msg=f"Received Response --> Code: {response_code}, Data: {unpacked_servers_list_response}",
                    color=utils.Colors.MAGENTA))

            # Parse servers list data
            self.__parse_servers_list_data(unpacked_data=unpacked_servers_list_response)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle services list request.", exception=e)

    def run(self) -> None:

        try:
            # Connect to Auth server
            self.connect()

            # Validate me.info file
            if not utils.check_if_exists(CConsts.CLIENT_FILE_PATH):
                utils.create_info_file(CConsts.CLIENT_FILE_PATH, file_data=me_info_default_data)

            # Create client RAM template, parse data from file DB or get it from user
            ram_template = client_ram_template.copy()

            if utils.check_if_exists(CConsts.CLIENT_FILE_PATH):
                username = utils.parse_info_file(file_path=CConsts.CLIENT_FILE_PATH, target_line_number=1)
                client_id = utils.parse_info_file(file_path=CConsts.CLIENT_FILE_PATH, target_line_number=2)

            else:
                username = input("Please enter your username: ")
                client_id = None

            ram_template[CConsts.RAM_USERNAME] = username
            ram_template[CConsts.RAM_ID] = client_id
            ram_template[CConsts.RAM_PASSWORD] = "qwer1234"
            # ram_template[CConsts.RAM_PASSWORD] = input("Please enter your password: ")
            ram_template[CConsts.RAM_IS_REGISTERED] = False

            # For dev mode
            if self.debug_mode:
                print(utils.write_with_color(msg=f"Parsed client template --> {ram_template}", color=utils.Colors.CYAN))

            # Create formatters templates
            server_request_formatter = server_request.copy()
            server_response_formatter = server_response.copy()

            # Handle registration request from Authentication Server
            # self.handle_registration_request(ram_template=ram_template,
            #                                  server_request_formatter=server_request_formatter,
            #                                  server_response_formatter=server_response_formatter)

            # TODO - if already registered do something, maybe if server responded with an error

            # For dev mode
            if self.debug_mode:
                print(utils.write_with_color(msg=f"Registered client template --> {ram_template}", color=utils.Colors.CYAN))

            # Handle AES key request from Authentication Server
            self.handle_aes_key_request(ram_template=ram_template,
                                        server_request_formatter=server_request_formatter,
                                        server_response_formatter=server_response_formatter)
            # For dev mode
            if self.debug_mode:
                print(utils.write_with_color(msg=f"AES Key client template --> {ram_template}",
                                             color=utils.Colors.CYAN))

            # # Handle services list request
            # self.handle_services_list_request(ram_template=ram_template,
            #                                   server_request_formatter=server_request_formatter,
            #                                   server_response_formatter=server_response_formatter)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to run {self.__class__.__name__}.", exception=e)

# TODO - for the all project, if debug mode print_with_color for dev informative outputs
# TODO - formatter should be a copy, dont pass the original one
# TODO - cleanup, close socket to auth server and open to msg server