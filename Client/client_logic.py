from struct import calcsize, unpack
from Socket.custom_socket import CustomSocket, socket
from Client.client_constants import file_db_servers_template, Constants as CConsts
from Client.client_input import ClientInput
from Server.MsgServer.msg_server_constants import Constants as MsgConsts
from Utils.validator import Validator, Constants as ValConsts
from Protocol_Handler.protocol_utils import code_to_payload_template, ProtocolConstants as ProtoConsts
from Protocol_Handler.protocol_handler import ProtocolHandler
from Utils.logger import Logger, CustomFilter
from Utils.custom_exception_handler import CustomException
from Utils.encryptor import Encryptor
from Utils import utils


class ClientLogic:
    """Handles all the Client protocol requirements."""

    def __init__(self, debug_mode: bool) -> None:
        self.debug_mode = debug_mode
        self.msg_servers_list = []
        self.protocol_handler = ProtocolHandler(debug_mode=debug_mode)
        self.encryptor = Encryptor(debug_mode=debug_mode)
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)

    def handle_registration_request(self, sck: CustomSocket, client_socket: socket, ram_template: dict,
                                    server_request_formatter: dict, server_response_formatter: dict) -> bool:
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
            # Send register request and receive response
            register_response = sck.custom_send_recv(sck=client_socket, packet=packed_register_request,
                                                     logger=self.logger, response=True)

            # Unpack and deserialize packet data
            response_code, unpacked_register_response = self.protocol_handler.unpack_request(received_packet=register_response,
                                                                                             formatter=server_response_formatter,
                                                                                             deserialize=True)
            # For dev mode
            if self.debug_mode:
                print(utils.write_with_color(
                    msg=f"Sent Request --> Code: {ProtoConsts.REQ_CLIENT_REG}, Data: {data}",
                    color=utils.Colors.MAGENTA))
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

    def __parse_servers_list_data(self, unpacked_data: bytes) -> None:
        """Private method to extract all the servers from the returned packed list."""
        try:
            # Create server list formatter template and calculate sizes
            server_data_formatter = code_to_payload_template[ProtoConsts.RES_MSG_SERVERS_LIST].copy()
            packed_server_fmt = self.protocol_handler.generate_packet_fmt(raw_packet=server_data_formatter)
            packed_server_size = calcsize(packed_server_fmt)

            # Loop over the packed packet and handle each server separately
            for i in range(0, unpacked_data[ProtoConsts.PAYLOAD_SIZE], packed_server_size):
                server = unpacked_data[ProtoConsts.SERVERS_LIST][i:i + packed_server_size]
                unpacked_server = unpack(packed_server_fmt, server)

                # Deserialize server raw data
                raw_data = self.protocol_handler.deserialize_packet(packet=unpacked_server, index_to_pass=2)
                server_data = self.protocol_handler.build_packet_format(code=ProtoConsts.RES_MSG_SERVERS_LIST,
                                                                        formatter=server_data_formatter.copy())

                server_data.update(self.protocol_handler.insert_unpacked_packet_content(data_format=server_data,
                                                                                        unpacked_packet=raw_data))

                server_data.update(self.protocol_handler.serialize_packet_value(formatter=server_data_formatter,
                                                                                data=server_data,
                                                                                mode=ProtoConsts.DESERIALIZE))
                # TODO - add to list file the server aes key, iv and all other needed fields, so in case of disconnection the data will be in DB and not only in RAM
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

    def handle_services_list_request(self, sck: CustomSocket, client_socket: socket, ram_template: dict,
                                     server_request_formatter: dict, server_response_formatter: dict) -> None:
        try:
            # Validate data
            client_id = utils.parse_info_file(file_path=CConsts.CLIENT_FILE_NAME, target_line_number=CConsts.CLIENT_ID_LINE)
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

            sck.send_packet(sck=client_socket, packet=packed_services_list_request, logger=self.logger)

            # Receive servers list response, unpack and deserialize packet data
            # TODO - receive with chunks, not with buffer, recv when server is still sending
            servers_list_response = sck.receive_packet(sck=client_socket, receive_buffer=4096,
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

    def __parse_msg_info_file_to_json(self, file_path: str, formatter: dict) -> dict:
        # TODO - refactor, same method in auth server
        if not utils.check_if_exists(path_to_check=file_path):
            raise OSError(f"File '{file_path}' does not exists.")
        default_service = utils.parse_info_file(file_path=file_path)
        ip_and_port = default_service[MsgConsts.LINE_IP_PORT]
        server_name = default_service[MsgConsts.LINE_NAME]
        server_id = default_service[MsgConsts.LINE_ID]
        server_ip, server_port = Validator.validate_injection(data_type=ValConsts.FMT_IPV4_PORT,
                                                              value_to_validate=ip_and_port)
        Validator.validate_injection(data_type=ValConsts.FMT_NAME, value_to_validate=server_name)
        if not isinstance(server_id, bytes):
            server_id = Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=server_id)

        formatter[CConsts.RAM_SERVER_ID] = server_id
        formatter[CConsts.RAM_SERVER_NAME] = server_name
        formatter[CConsts.RAM_SERVER_IP] = server_ip
        formatter[CConsts.RAM_SERVER_PORT] = server_port
        return formatter

    def __get_client_wanted_service(self):
        """Private method that return the wanted service entry from Client DB."""
        try:
            # Services list is empty
            if not self.msg_servers_list:
                # TODO - maybe it should be srv_info.json.
                self.msg_servers_list.append(self.__parse_msg_info_file_to_json(file_path=MsgConsts.MSG_FILE_NAME,
                                                                                formatter=file_db_servers_template.copy()))

            # Services file is empty
            if not self.msg_servers_list:
                print(utils.write_with_color(msg=f"{ProtoConsts.CONSOLE_ERROR} There aren't any registered services, "
                                                 f"please call support.", color=utils.Colors.RED))

            # get and return the wanted service object
            server_object = ClientInput.get_service_name(services_list=self.msg_servers_list)

            # For dev mode:
            if self.debug_mode:
                print(utils.write_with_color(msg=f"Selected service object --> {server_object}", color=utils.Colors.CYAN))

            return server_object

        except Exception as e:
            raise CustomException(error_msg=f"Unable to get client wanted service.", exception=e)

    def handle_aes_key_request(self, sck: CustomSocket, client_socket: socket, ram_template: dict,
                               server_request_formatter: dict, server_response_formatter: dict) -> None:
        # TODO - continue from here, refactor
        try:
            # Generate random nonce value and validate it
            client_nonce = utils.generate_nonce()
            ram_template[CConsts.RAM_NONCE] = client_nonce
            Validator.validate_injection(data_type=ValConsts.FMT_NONCE, value_to_validate=client_nonce)

            # Validate client id
            client_id = utils.parse_info_file(file_path=CConsts.CLIENT_FILE_NAME, target_line_number=CConsts.CLIENT_ID_LINE)
            # client_id = ram_template[CConsts.RAM_ID]
            if client_id and not isinstance(client_id, bytes):
                client_id = Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=client_id)

            # Get client wanted service and validate data
            msg_server = self.__get_client_wanted_service()
            server_id = msg_server[CConsts.RAM_SERVER_ID]

            if not isinstance(server_id, bytes):
                server_id = Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=server_id)
            ram_template[CConsts.RAM_SERVER_ID] = server_id

            # Create packet data frame
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

            sck.send_packet(sck=client_socket, packet=packed_aes_request, logger=self.logger)

            # Receive response
            encrypted_key_response = sck.receive_packet(sck=client_socket, receive_buffer=4096,
                                                        logger=self.logger)

            response_code, unpacked_aes_key_response = self.protocol_handler.unpack_request(received_packet=encrypted_key_response,
                                                                                            formatter=server_response_formatter,
                                                                                            deserialize=True)
            # For dev mode
            if self.debug_mode:
                print(utils.write_with_color(
                    msg=f"Received Response --> Code: {response_code}, Data: {unpacked_aes_key_response}",
                    color=utils.Colors.MAGENTA))

            if response_code == ProtoConsts.RES_GENERAL_ERROR:
                print(utils.write_with_color(msg=f"{ProtoConsts.CONSOLE_FAIL} {CConsts.SERVER_GENERAL_ERROR}", color=utils.Colors.RED))
                return

            unpacked_encrypted_key = self.protocol_handler.unpack_request(received_packet=unpacked_aes_key_response[ProtoConsts.ENCRYPTED_KEY],
                                                                          formatter=code_to_payload_template[ProtoConsts.PKT_ENCRYPTED_KEY])

            # TODO - refactor into a method
            encrypted_key_iv, encrypted_nonce, encrypted_aes_key = unpacked_encrypted_key
            password_hash = ram_template[CConsts.RAM_PASSWORD_HASH]
            decrypted_key = self.encryptor.decrypt(encrypted_value=encrypted_aes_key, decryption_key=password_hash, iv=encrypted_key_iv)
            decrypted_nonce = self.encryptor.decrypt(encrypted_value=encrypted_nonce, decryption_key=password_hash, iv=encrypted_key_iv)
            ram_template[CConsts.RAM_AES_KEY] = decrypted_key
            ram_template[CConsts.RAM_ENCRYPTED_KEY_IV] = encrypted_key_iv

            # Validate nonce and return ticket
            if client_nonce == decrypted_nonce:
                ram_template[CConsts.RAM_TICKET] = unpacked_aes_key_response[ProtoConsts.TICKET]

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle encrypted key request.", exception=e)

    def __pack_authenticator_packet(self, ram_template: dict) -> bytes:
        try:
            # Create Authenticator
            authenticator_iv = self.encryptor.generate_bytes_stream()
            ram_template[CConsts.RAM_AUTH_IV] = authenticator_iv
            client_id = ram_template[CConsts.RAM_ID]
            if not isinstance(client_id, bytes):
                client_id = Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=client_id)
            server_id = utils.generate_uuid()
            # server_id = ram_template[CConsts.RAM_SERVER_ID]
            if not isinstance(client_id, bytes):
                server_id = Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=server_id)

            aes_key = self.encryptor.generate_bytes_stream(size=32)
            # aes_key = ram_template[CConsts.RAM_AES_KEY]
            encrypted_client_id = self.encryptor.encrypt(value=client_id, encryption_key=aes_key, iv=authenticator_iv)
            encrypted_server_id = self.encryptor.encrypt(value=server_id, encryption_key=aes_key, iv=authenticator_iv)
            creation_time = utils.time_now()
            encrypted_creation_time = self.encryptor.encrypt(value=creation_time, encryption_key=aes_key, iv=authenticator_iv)

            # Create packet data frame
            authenticator_data = {
                ProtoConsts.AUTHENTICATOR_IV: authenticator_iv,
                ProtoConsts.VERSION: ProtoConsts.SERVER_VERSION,
                ProtoConsts.CLIENT_ID: encrypted_client_id,
                ProtoConsts.SERVER_ID: encrypted_server_id,
                ProtoConsts.CREATION_TIME: encrypted_creation_time
            }

            # Pack authenticator packet
            return self.protocol_handler.pack_request(code=ProtoConsts.PKT_AUTHENTICATOR,
                                                      data=authenticator_data,
                                                      formatter=code_to_payload_template[ProtoConsts.PKT_AUTHENTICATOR].copy())

        except Exception as e:
            raise CustomException(error_msg=f"Unable to pack authenticator packet.", exception=e)

    def connect_to_service(self,sck: CustomSocket, client_socket: socket, ram_template: dict,
                           server_request_formatter: dict, server_response_formatter: dict) -> None:
        try:
            authenticator = self.__pack_authenticator_packet(ram_template=ram_template)
            ticket = b'\x18cL\xb5\x942\xb1J\xe2\xa3\x02\xe4q\x89\xd8h\xa5\xb1\xbb\x7f\xb2Y\xfeKp\xb5\x86\xb8\xdc\x1e\xf7\xc4b06/02/24]=\xcf\xe0\xa4\x9c,\xa3\xceZ\x1d\xf5\xb0\xda\x1c\xfbh4\xae\xc0\x90\xde|\xa9Q_\\\x1e\xff\x89\xec\xa2\x93\xab\xc8\x98\x98s\t\x13v.{-<R\xf6&y\twDH$\xad\xb4\x92\xe0\xbc&\xd8q>\x98\xbf\xb6\xc3N\x8a\xbf"\xe5Y\xb9\xd9\x0f\x88\x1fi\x95\xc2\xb8\xdb\x06\xc6\x89\xa6\xe7\xbd\x91\x05$\xfa\x8a\xda"'
            # ticket = ram_template[CConsts.RAM_TICKET]
            client_id = ram_template[CConsts.RAM_ID]
            if not isinstance(client_id, bytes):
                client_id = Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=client_id)

            # Create packet data frame
            data = {
                ProtoConsts.CLIENT_ID: client_id,
                ProtoConsts.VERSION: ProtoConsts.SERVER_VERSION,
                ProtoConsts.CODE: ProtoConsts.REQ_MSG_SERVERS_LIST,
                ProtoConsts.PAYLOAD_SIZE: len(authenticator) + len(ticket),
                ProtoConsts.AUTHENTICATOR: authenticator,
                ProtoConsts.TICKET: ticket
            }

            # Adjust sizes
            server_data_formatter = code_to_payload_template[ProtoConsts.REQ_MSG_SERVER_AES_KEY].copy()
            server_data_formatter.update(self.protocol_handler.update_formatter_value(formatter=server_data_formatter,
                                                                                      pivot_key=ProtoConsts.AUTHENTICATOR,
                                                                                      pivot_value=ProtoConsts.SIZE,
                                                                                      new_value=len(authenticator)))
            server_data_formatter.update(self.protocol_handler.update_formatter_value(formatter=server_data_formatter,
                                                                                      pivot_key=ProtoConsts.TICKET,
                                                                                      pivot_value=ProtoConsts.SIZE,
                                                                                      new_value=len(ticket)))
            packed_service_aes_request = self.protocol_handler.pack_request(code=ProtoConsts.REQ_MSG_SERVER_AES_KEY,
                                                                            data=data,
                                                                            formatter=server_request_formatter)

            # TODO - connect to msg server then send
            # Send

        except Exception as e:
            raise CustomException(error_msg=f"Unable to connect to service.", exception=e)