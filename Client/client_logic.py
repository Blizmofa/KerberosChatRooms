from struct import calcsize, unpack
from typing import Union
from Utils import utils
from Utils.validator import Validator, Constants as ValConsts
from Utils.logger import Logger
from Utils.custom_exception_handler import CustomException
from Utils.encryptor import Encryptor
from Socket.custom_socket import CustomSocket, socket
from Protocol_Handler.protocol_handler import ProtocolHandler
from Protocol_Handler.protocol_utils import code_to_payload_template, ProtocolConstants as ProtoConsts
from Client.client_constants import file_db_servers_template, Constants as CConsts
from Client.client_input import ClientInput
from Server.MsgServer.msg_server_constants import Constants as MsgConsts


class ClientLogic:
    """Handles all the Client protocol requirements."""

    def __init__(self, debug_mode: bool) -> None:
        self.debug_mode = debug_mode
        self.msg_servers_list = []
        self.protocol_handler = ProtocolHandler(debug_mode=debug_mode)
        self.encryptor = Encryptor(debug_mode=debug_mode)
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)

    def __process_register_response(self, response_code: int, data: dict, ram_template: dict) -> bool:
        """Private method to process register response, returns True for success, False otherwise."""
        try:
            # Register success
            if response_code == ProtoConsts.RES_REGISTER_SUCCESS:

                client_id = data[ProtoConsts.CLIENT_ID]
                if not isinstance(client_id, bytes):
                    client_id = Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=client_id)

                # Insert received client id into me.info file
                utils.insert_value_into_info_file(value=client_id.hex(),
                                                  target_line=CConsts.CLIENT_ID_LINE,
                                                  file_path=CConsts.CLIENT_FILE_NAME,
                                                  max_lines=CConsts.CLIENT_FILE_MAX_LINES)

                msg = "Registration successful."
                self.logger.logger.info(msg=msg)
                print(utils.write_with_color(msg=f"{ProtoConsts.CONSOLE_ACK} {msg}",
                                             color=utils.Colors.GREEN))
                ram_template[CConsts.RAM_IS_REGISTERED] = True
                return True

            # Register failure
            elif response_code == ProtoConsts.RES_REGISTER_FAILED:
                msg = "Registration failure."
                self.logger.logger.info(msg=msg)
                print(utils.write_with_color(msg=f"{ProtoConsts.CONSOLE_FAIL} {msg}",
                                             color=utils.Colors.RED))
                return False

        except Exception as e:
            raise CustomException(error_msg=f"Unable to process register response.", exception=e)

    def handle_registration_request(self, sck: CustomSocket, client_socket: socket, ram_template: dict,
                                    server_request_formatter: dict, server_response_formatter: dict) -> bool:
        """Sends registration request to Authentication Server."""
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

            # Pack request
            packed_register_request = self.protocol_handler.pack_request(code=ProtoConsts.REQ_CLIENT_REG,
                                                                         data=data,
                                                                         formatter=server_request_formatter)
            # Send request and receive response
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
                print(utils.write_with_color(msg=f"Received Response --> Code: {response_code}, Data: {unpacked_register_response}",
                                             color=utils.Colors.MAGENTA))
            # Process response
            return self.__process_register_response(response_code=response_code,
                                                    data=unpacked_register_response,
                                                    ram_template=ram_template)

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
                self.msg_servers_list.append(server_data)

            # For dev mode:
            if self.debug_mode:
                print(utils.write_with_color(msg=f"Parsed services list: {self.msg_servers_list}", color=utils.Colors.CYAN))

            # Insert servers to file DB
            for server in self.msg_servers_list:
                server[CConsts.RAM_TICKET] = CConsts.FMT_ME
                if isinstance(server[ProtoConsts.SERVER_ID], bytes):
                    server[ProtoConsts.SERVER_ID] = Validator.validate_injection(data_type=ValConsts.FMT_ID,
                                                                                 value_to_validate=server[ProtoConsts.SERVER_ID])
            utils.create_json_file(file_path=CConsts.SERVERS_FILE_NAME, data=self.msg_servers_list)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to parse servers list.", exception=e)

    def handle_services_list_request(self, sck: CustomSocket, client_socket: socket, ram_template: dict,
                                     server_request_formatter: dict, server_response_formatter: dict) -> None:
        """Sends services list request to Authentication Server."""
        try:
            # Fetch and validate data
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
            # Pack request
            packed_services_list_request = self.protocol_handler.pack_request(code=ProtoConsts.REQ_MSG_SERVERS_LIST,
                                                                              data=data,
                                                                              formatter=server_request_formatter)
            # Send request and receive response
            servers_list_response = sck.custom_send_recv(sck=client_socket, packet=packed_services_list_request,
                                                         buffer_size=4096, logger=self.logger, response=True)
            # Unpack and deserialize packet data
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

    def __get_client_wanted_service(self) -> Union[dict, None]:
        """Return the wanted service entry from Client DB."""
        try:
            # Services file is empty
            if not self.msg_servers_list:
                return None

            # get and return the wanted service object
            server_object = ClientInput.get_service_name(services_list=self.msg_servers_list)

            # For dev mode:
            if self.debug_mode:
                print(utils.write_with_color(msg=f"Selected service object --> {server_object}", color=utils.Colors.CYAN))

            return server_object

        except Exception as e:
            raise CustomException(error_msg=f"Unable to get client wanted service.", exception=e)

    def __process_encrypted_aes_key_response(self, unpacked_data: dict, ram_template: dict, server_id: bytes) -> dict:
        """Unpacks encrypted AES packet, inserts data into RAM DB
        and appends Ticket packet to the appropriate service."""
        try:
            # Unpack encrypted AES key packet
            unpacked_encrypted_key = self.protocol_handler.unpack_request(received_packet=unpacked_data[ProtoConsts.ENCRYPTED_KEY],
                                                                          formatter=code_to_payload_template[ProtoConsts.PKT_ENCRYPTED_KEY])
            # Parse data
            encrypted_key_iv, encrypted_nonce, encrypted_aes_key = unpacked_encrypted_key

            # Decrypt AES key and nonce
            password_hash = ram_template[CConsts.RAM_PASSWORD_HASH]
            decrypted_key = self.encryptor.decrypt(encrypted_value=encrypted_aes_key, decryption_key=password_hash,
                                                   iv=encrypted_key_iv)
            decrypted_nonce = self.encryptor.decrypt(encrypted_value=encrypted_nonce, decryption_key=password_hash,
                                                     iv=encrypted_key_iv)
            # Insert data into RAM DB
            ram_template[CConsts.RAM_AES_KEY] = decrypted_key
            ram_template[CConsts.RAM_ENCRYPTED_KEY_IV] = encrypted_key_iv

            # Validate nonce and update ticket in services JSON DB
            if ram_template[CConsts.RAM_NONCE] == decrypted_nonce:
                if isinstance(server_id, bytes):
                    server_id = Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=server_id)
                service_object = utils.fetch_entry_from_json_db(file_path=CConsts.SERVERS_FILE_NAME,
                                                                pivot_key=CConsts.RAM_SERVER_ID,
                                                                pivot_value=server_id)
                # Serialize Ticket packet
                ticket = unpacked_data[ProtoConsts.TICKET]
                serialized_ticket = Validator.validate_injection(data_type=ValConsts.FMT_TICKET,
                                                                 value_to_validate=ticket)
                service_object[CConsts.RAM_TICKET] = serialized_ticket
                utils.insert_data_to_json_db(file_path=CConsts.SERVERS_FILE_NAME, data=service_object,
                                             pivot_key=CConsts.RAM_SERVER_ID, pivot_value=server_id)

                # Return the updated service object
                return service_object

        except Exception as e:
            raise CustomException(error_msg=f"Unable to unpack encrypted AES key packet.", exception=e)

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
            encrypted_creation_time = self.encryptor.encrypt(value=creation_time, encryption_key=aes_key,
                                                             iv=authenticator_iv)

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
                                                      formatter=code_to_payload_template[
                                                          ProtoConsts.PKT_AUTHENTICATOR].copy())

        except Exception as e:
            raise CustomException(error_msg=f"Unable to pack authenticator packet.", exception=e)

    def __chat_mode(self):
        try:
            # TODO - pack msg request, send, get input from user, etc
            pass

        except Exception as e:
            raise CustomException(error_msg=f"Unable to chat.", exception=e)


    def __connect_to_service(self, service_object: dict, sck: CustomSocket, client_socket: socket, ram_template: dict,
                             server_request_formatter: dict, server_response_formatter: dict) -> None:
        try:
            # Pack Authenticator packet
            authenticator = self.__pack_authenticator_packet(ram_template=ram_template)

            # Fetch Ticket
            ticket = service_object[CConsts.RAM_TICKET]

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

            # TODO - check if client has service aes key, else return error

            # TODO - connect to msg server then send
            # TODO - disconnect from auth server
            service_ip_address = service_object[CConsts.RAM_SERVER_IP]
            service_port = service_object[CConsts.RAM_SERVER_PORT]
            # TODO - validate ip and port
            client_socket.close()
            service_socket = sck.create_socket()
            service_socket.connect((service_ip_address, service_port))
            # TODO - while true chat mode send messages

        except Exception as e:
            raise CustomException(error_msg=f"Unable to connect to service.", exception=e)

    def handle_aes_key_request(self, sck: CustomSocket, client_socket: socket, ram_template: dict,
                               server_request_formatter: dict, server_response_formatter: dict) -> None:
        """Sends AES key request to Authentication Server."""
        try:
            # Generate random nonce value and validate it
            client_nonce = utils.generate_nonce()
            Validator.validate_injection(data_type=ValConsts.FMT_NONCE, value_to_validate=client_nonce)
            ram_template[CConsts.RAM_NONCE] = client_nonce

            # Validate client id
            client_id = ram_template[CConsts.RAM_ID]
            if client_id and not isinstance(client_id, bytes):
                client_id = Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=client_id)

            # Get client wanted service
            msg_server = self.__get_client_wanted_service()
            if not msg_server:
                print(utils.write_with_color(msg=f"{ProtoConsts.CONSOLE_ERROR} There aren't any registered services, "
                                                 f"please get available services.", color=utils.Colors.RED))
                return

            # Validate return service id
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
            # Pack request
            packed_aes_request = self.protocol_handler.pack_request(code=ProtoConsts.REQ_AES_KEY,
                                                                    data=data,
                                                                    formatter=server_request_formatter)
            # Send request and receive response
            encrypted_key_response = sck.custom_send_recv(sck=client_socket, packet=packed_aes_request,
                                                          logger=self.logger, response=True)
            # Unpack and deserialize packet data
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

            # Process encrypted AES key packet and fetch Ticket
            service_object = self.__process_encrypted_aes_key_response(unpacked_data=unpacked_aes_key_response,
                                                                       ram_template=ram_template,
                                                                       server_id=server_id)

            # Connect to Service
            self.__connect_to_service(service_object=service_object,
                                      sck=sck,
                                      client_socket=client_socket,
                                      ram_template=ram_template,
                                      server_request_formatter=server_request_formatter,
                                      server_response_formatter=server_response_formatter)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle encrypted key request.", exception=e)

