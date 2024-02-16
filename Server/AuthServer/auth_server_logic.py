from typing import Union
from Utils.logger import Logger, CustomFilter
from Utils import utils
from Socket.custom_socket import CustomSocket, socket
from Utils.custom_exception_handler import CustomException
from Protocol_Handler.protocol_handler import ProtocolHandler
from Server.MsgServer.msg_server_constants import Constants as MsgConsts
from Utils.validator import Validator, Constants as ValConsts
from Utils.encryptor import Encryptor
from Server.AuthServer.auth_server_constants import file_db_clients_template, file_db_servers_template, Constants as AuthConsts
from Protocol_Handler.protocol_utils import (packet_register_success, packet_no_payload, code_to_payload_template,
                                             ProtocolConstants as ProtoConsts)


class AuthServerLogic:
    """Handles all the authentication server protocol requirements."""

    def __init__(self, debug_mode: bool) -> None:
        self.debug_mode = debug_mode
        self.msg_server_list = []
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)
        self.protocol_handler = ProtocolHandler(debug_mode=debug_mode)
        self.encryptor = Encryptor(debug_mode=debug_mode)

    def __register_client(self, data: dict, client_ram_template: dict, server_response: dict) -> bytes:
        """Private method to registers new clients if not already registered according to the server DB."""
        try:
            # Not registered client case
            if "name" in data:
            # if not utils.search_value_in_file(value=data[AuthConsts.RAM_CLIENT_NAME], file_path=AuthConsts.CLIENTS_FILE_PATH):

                # Set Logger custom filter
                CustomFilter.filter_name = data[ProtoConsts.NAME]

                # Insert client data into RAM DB
                client_id = utils.generate_uuid()
                Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=client_id)
                client_password_hash = self.encryptor.hash_password(password=data[ProtoConsts.PASSWORD])
                data[AuthConsts.RAM_CLIENT_ID_HEX] = client_id.hex()
                data[AuthConsts.RAM_PASSWORD_HASH] = client_password_hash
                data[AuthConsts.RAM_PASSWORD_HASH_HEX] = client_password_hash.hex()
                client_ram_template.update(utils.insert_data_to_ram_db(ram_template=client_ram_template, data=data))

                # Insert client data into file DB
                utils.insert_data_to_file_db(file_path=AuthConsts.CLIENTS_FILE_PATH,
                                             data=client_ram_template,
                                             formatter=file_db_clients_template.copy())
                # Return success
                return self.__handle_register_success_response(data=data, uuid=client_id, server_response=server_response)

            # Already Registered case
            else:
                return self.__handle_register_failed_response(data=data, server_response=server_response)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to register client '{data[ProtoConsts.NAME]}'.", exception=e)

    def __register_server(self, data: dict, server_ram_template: dict, sck: socket, server_response: dict) -> bytes:
        """Private method to registers new services if not already registered according to the server DB."""
        try:
            # Not registered server case
            if "name" in data:
            # if not utils.search_value_in_file(value=data[ProtoConsts.NAME], file_path=AuthConsts.SERVERS_FILE_PATH):

                # Set Logger custom filter
                CustomFilter.filter_name = data[ProtoConsts.NAME]

                # Insert server data into RAM DB
                server_id = utils.generate_uuid()
                Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=server_id)
                server_ram_template[AuthConsts.RAM_SERVER_ID] = server_id
                server_ram_template[AuthConsts.RAM_SERVER_ID_HEX] = server_id.hex()
                server_aes_key = data[ProtoConsts.AES_KEY]
                Validator.validate_injection(data_type=ValConsts.FMT_AES_KEY, value_to_validate=server_aes_key)
                server_ram_template[AuthConsts.RAM_AES_KEY_HEX] = server_aes_key.hex()

                # Create a DNS mapping of the registered servers
                server_ip, server_port = sck.getpeername()
                server_ram_template[AuthConsts.RAM_SERVER_IP] = server_ip
                server_ram_template[AuthConsts.RAM_SERVER_PORT] = server_port

                # Insert Server data into DBs and list
                utils.insert_data_to_ram_db(ram_template=server_ram_template, data=data)
                self.msg_server_list.append({
                    ProtoConsts.SERVER_ID: server_id,
                    ProtoConsts.SERVER_NAME: data[ProtoConsts.NAME],
                    ProtoConsts.AES_KEY: data[ProtoConsts.AES_KEY],
                    ProtoConsts.SERVER_IP: server_ip,
                    ProtoConsts.SERVER_PORT: server_port
                })
                # Insert new server to file DB
                file_data = utils.insert_data_to_template(data=server_ram_template, formatter=file_db_servers_template.copy())
                utils.append_data_to_json(file_path=AuthConsts.SERVERS_FILE_PATH, data=file_data)

                # Return success
                return self.__handle_register_success_response(data=data, uuid=server_id, server_response=server_response)

            # Already Registered case
            else:
                return self.__handle_register_failed_response(data=data, server_response=server_response)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to register server.", exception=e)

    def __handle_register_success_response(self, data: dict, uuid: bytes, server_response: dict) -> bytes:
        """Private method to packs response in case of registration success."""
        try:
            # Log output
            msg = f"'{data[ProtoConsts.NAME]}' has been registered successfully."
            self.logger.logger.info(msg=msg)

            # For dev mode
            if self.debug_mode:
                print(utils.write_with_color(msg=f"{ProtoConsts.CONSOLE_ACK} {msg}", color=utils.Colors.GREEN))

            # Pack response
            packet_register_success[ProtoConsts.CLIENT_ID] = uuid
            return self.protocol_handler.pack_request(code=ProtoConsts.RES_REGISTER_SUCCESS,
                                                      data=packet_register_success,
                                                      formatter=server_response.copy())
        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle register success response.", exception=e)

    def __handle_register_failed_response(self, data: dict, server_response: dict) -> bytes:
        """Private method to packs response in case of registration failure."""
        try:
            msg = f"'{data[ProtoConsts.NAME]}' is already registered."
            self.logger.logger.info(msg=f"{ProtoConsts.CONSOLE_FAIL} {msg}")

            # For dev mode
            if self.debug_mode:
                print(utils.write_with_color(msg=msg, color=utils.Colors.RED))

            # Pack response
            packet_no_payload[ProtoConsts.CODE] = ProtoConsts.RES_REGISTER_FAILED
            return self.protocol_handler.pack_request(code=ProtoConsts.RES_REGISTER_FAILED,
                                                      data=packet_no_payload,
                                                      formatter=server_response.copy())
        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle register failed response.", exception=e)

    def handle_registration_request(self, server_socket: CustomSocket, client_socket: socket, request_code: int,
                                    unpacked_packet: dict, client_ram_template: dict, server_ram_template: dict,
                                    server_response: dict) -> None:
        """Sends response with the packed register request back to the requesting peer."""
        try:
            # TODO - if server has shut down unexpectedly, load client.txt if exists, and check if registered there
            # Handle clients requests
            if request_code == ProtoConsts.REQ_CLIENT_REG:
                register_response = self.__register_client(data=unpacked_packet,
                                                           client_ram_template=client_ram_template,
                                                           server_response=server_response)

            # Handle servers requests
            elif request_code == ProtoConsts.REQ_SERVER_REG:
                register_response = self.__register_server(data=unpacked_packet, server_ram_template=server_ram_template,
                                                           sck=client_socket, server_response=server_response)

            else:
                raise ValueError(f"Unsupported registration request code '{request_code}'.")

            # Send response back to client/server
            server_socket.send_packet(sck=client_socket, packet=register_response, logger=self.logger)

            # For dev mode
            if self.debug_mode:
                print(utils.write_with_color(msg=f"Sent Response --> {register_response}", color=utils.Colors.MAGENTA))

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle registration request from {client_socket.getpeername()}.",
                                  exception=e)

    def send_server_general_error(self, server_socket: CustomSocket, client_socket: socket, server_response: dict) -> None:
        """Sends server general error response."""
        try:
            packet_no_payload[ProtoConsts.CODE] = ProtoConsts.RES_GENERAL_ERROR
            packed_general_error = self.protocol_handler.pack_request(code=ProtoConsts.RES_GENERAL_ERROR,
                                                                      data=packet_no_payload,
                                                                      formatter=server_response.copy())
            server_socket.send_packet(sck=client_socket, packet=packed_general_error, logger=self.logger)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to send {self.__class__.__name__} general error.", exception=e)

    def __parse_msg_info_file(self) -> tuple:
        """Private method that Parses the default service data from msg.info file."""
        try:
            # Parse default service data
            ip_and_port = utils.parse_info_file(file_path=MsgConsts.MSG_FILE_NAME,
                                                target_line_number=MsgConsts.LINE_IP_PORT)
            server_id = utils.parse_info_file(file_path=MsgConsts.MSG_FILE_NAME, target_line_number=MsgConsts.LINE_ID)
            server_name = utils.parse_info_file(file_path=MsgConsts.MSG_FILE_NAME, target_line_number=MsgConsts.LINE_NAME)
            server_aes_key = utils.parse_info_file(file_path=MsgConsts.MSG_FILE_NAME, target_line_number=MsgConsts.LINE_AES_KEY)

            self.logger.logger.debug(f"Parsed {MsgConsts.MSG_FILE_NAME} successfully.")

            # Return as a Tuple
            return ip_and_port, server_name, server_id, server_aes_key

        except Exception as e:
            raise CustomException(error_msg=f"Unable to parse {MsgConsts.MSG_FILE_NAME}.", exception=e)

    def __get_service_object(self, service_id: Union[str, bytes], server_socket: CustomSocket,
                             client_socket: socket, server_response: dict) -> dict:
        """Private method that return the wanted service entry from Client DB."""
        try:
            # Get from JSON DB
            if not self.msg_server_list and utils.check_if_exists(path_to_check=AuthConsts.SERVERS_FILE_PATH):
                service_id = Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=service_id)
                service_object = utils.fetch_value_from_json_db(file_path=AuthConsts.SERVERS_FILE_PATH,
                                                                pivot_key=AuthConsts.RAM_SERVER_ID_HEX,
                                                                pivot_value=service_id)
                if service_object:
                    self.msg_server_list.append(service_object)

            # Get default service
            if not self.msg_server_list and utils.check_if_exists(path_to_check=MsgConsts.MSG_FILE_NAME):
                self.__get_default_service_data(server_socket=server_socket,
                                                client_socket=client_socket,
                                                server_response=server_response)

            # Get and return the wanted service object
            service_object = utils.fetch_value_from_ram_db(data=self.msg_server_list,
                                                           pivot_key=AuthConsts.RAM_SERVER_ID,
                                                           pivot_value=service_id)
            # For dev mode:
            if self.debug_mode:
                print(utils.write_with_color(msg=f"Selected service object --> {service_object}", color=utils.Colors.CYAN))

            return service_object

        except Exception as e:
            raise CustomException(error_msg=f"Unable to get client wanted service.", exception=e)

    def __pack_encrypted_key_packet(self, client_ram_template: dict, client_nonce: bytes) -> bytes:
        """Private method that returns the packed encrypted AES key packet."""
        try:
            # Get client password hash
            password_hash = client_ram_template[AuthConsts.RAM_PASSWORD_HASH]

            # Generate AES key for the client
            client_aes_key = self.encryptor.generate_bytes_stream(size=ProtoConsts.SIZE_AES_KEY)

            # Encrypt packet content
            encrypted_key_iv = self.encryptor.generate_bytes_stream(size=ProtoConsts.SIZE_IV)
            encrypted_aes_key = self.encryptor.encrypt(value=client_aes_key,
                                                       encryption_key=password_hash,
                                                       iv=encrypted_key_iv)
            encrypted_nonce = self.encryptor.encrypt(value=client_nonce,
                                                     encryption_key=password_hash,
                                                     iv=encrypted_key_iv)
            # Create packet data frame
            encrypted_key_data = {
                ProtoConsts.ENCRYPTED_KEY_IV: encrypted_key_iv,
                ProtoConsts.NONCE: encrypted_nonce,
                ProtoConsts.AES_KEY: encrypted_aes_key
            }
            # Pack Encrypted key packet
            return self.protocol_handler.pack_request(code=ProtoConsts.PKT_ENCRYPTED_KEY,
                                                      data=encrypted_key_data,
                                                      formatter=code_to_payload_template[ProtoConsts.PKT_ENCRYPTED_KEY])
        except Exception as e:
            raise CustomException(error_msg=f"Unable to pack encrypted key packet.", exception=e)

    def __pack_ticket_packet(self, client_id: bytes, server_id: bytes, service_aes_key: bytes) -> bytes:
        """Private method that returns the packed ticket key packet."""
        try:
            # Generate packet data
            ticket_iv = self.encryptor.generate_bytes_stream()
            creation_time = utils.time_now()
            expiration_time = utils.expiration_time(days_buffer=ProtoConsts.DEF_EXPIRATION_TIME_LENGTH)

            # Encrypt packet content
            encrypted_ticket_aes_key = self.encryptor.encrypt(value=service_aes_key,
                                                              encryption_key=service_aes_key,
                                                              iv=ticket_iv)
            encrypted_ticket_expiration_time = self.encryptor.encrypt(value=expiration_time,
                                                                      encryption_key=service_aes_key,
                                                                      iv=ticket_iv)
            # Create packet data frame
            ticket_data = {
                ProtoConsts.VERSION: ProtoConsts.SERVER_VERSION,
                ProtoConsts.CLIENT_ID: client_id,
                ProtoConsts.SERVER_ID: server_id,
                ProtoConsts.CREATION_TIME: creation_time,
                ProtoConsts.TICKET_IV: ticket_iv,
                ProtoConsts.AES_KEY: encrypted_ticket_aes_key,
                ProtoConsts.EXPIRATION_TIME: encrypted_ticket_expiration_time
            }
            # Pack Ticket packet
            return self.protocol_handler.pack_request(code=ProtoConsts.PKT_TICKET,
                                                      data=ticket_data,
                                                      formatter=code_to_payload_template[ProtoConsts.PKT_TICKET])

        except Exception as e:
            raise CustomException(error_msg=f"Unable to pack ticket packet.", exception=e)

    def handle_aes_key_request(self, server_socket: CustomSocket, client_socket: socket, unpacked_packet: dict,
                               client_ram_template: dict, server_response: dict) -> None:
        """Sends response with the packed AES key request back to the requesting peer."""
        try:
            # Validate received data
            client_nonce = unpacked_packet[ProtoConsts.NONCE]
            Validator.validate_injection(data_type=ValConsts.FMT_NONCE, value_to_validate=client_nonce)
            client_id = unpacked_packet[ProtoConsts.CLIENT_ID]
            Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=client_id)
            server_id = unpacked_packet[ProtoConsts.SERVER_ID]
            Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=server_id)

            # Insert client nonce to RAM DB
            client_ram_template[ProtoConsts.NONCE] = client_nonce

            # Get the client wanted service object from DB
            service_object = self.__get_service_object(service_id=server_id, server_socket=server_socket,
                                                       client_socket=client_socket, server_response=server_response)

            # Pack encrypted key packet
            packed_encrypted_key_packet = self.__pack_encrypted_key_packet(client_ram_template=client_ram_template,
                                                                           client_nonce=client_nonce)

            # Pack Ticket packet
            server_aes_key = service_object[AuthConsts.RAM_AES_KEY]
            packed_ticket_packet = self.__pack_ticket_packet(client_id=client_id,
                                                             server_id=server_id,
                                                             service_aes_key=server_aes_key)

            # Adjust sized and pack response
            server_data_formatter = code_to_payload_template[ProtoConsts.RES_ENCRYPTED_AES_KEY].copy()
            server_data_formatter.update(self.protocol_handler.update_formatter_value(formatter=server_data_formatter,
                                                                                      pivot_key=ProtoConsts.ENCRYPTED_KEY,
                                                                                      pivot_value=ProtoConsts.SIZE,
                                                                                      new_value=len(packed_encrypted_key_packet)))
            server_data_formatter.update(self.protocol_handler.update_formatter_value(formatter=server_data_formatter,
                                                                                      pivot_key=ProtoConsts.TICKET,
                                                                                      pivot_value=ProtoConsts.SIZE,
                                                                                      new_value=len(packed_ticket_packet)))
            # Create packet data frame
            response_data = {
                ProtoConsts.VERSION: ProtoConsts.SERVER_VERSION,
                ProtoConsts.CODE: ProtoConsts.RES_ENCRYPTED_AES_KEY,
                ProtoConsts.PAYLOAD_SIZE: ProtoConsts.SIZE_CLIENT_ID + len(packed_encrypted_key_packet) + len(packed_ticket_packet),
                ProtoConsts.CLIENT_ID: client_id,
                ProtoConsts.ENCRYPTED_KEY: packed_encrypted_key_packet,
                ProtoConsts.TICKET: packed_ticket_packet
            }
            # Pack and send AES key response
            packed_encrypted_key_response = self.protocol_handler.pack_request(code=ProtoConsts.RES_ENCRYPTED_AES_KEY,
                                                                               data=response_data,
                                                                               formatter=server_response)
            server_socket.send_packet(sck=client_socket, packet=packed_encrypted_key_response, logger=self.logger)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle encrypted key request from {client_socket.getpeername()}.",
                                  exception=e)

    def __get_default_service_data(self, server_socket: CustomSocket, client_socket: socket, server_response: dict) -> None:
        """Private method to get a default registered service data."""
        try:
            # Parse and validate default registered service file
            default_service_data = self.__parse_msg_info_file()
            if default_service_data:
                ip_and_port, server_name, server_id, server_aes_key = default_service_data
                server_ip, server_port = Validator.validate_injection(data_type=ValConsts.FMT_IPV4_PORT,
                                                                      value_to_validate=ip_and_port)
                if not isinstance(server_id, bytes):
                    server_id = Validator.validate_injection(data_type=ValConsts.FMT_ID,
                                                             value_to_validate=server_id)
                if not isinstance(server_aes_key, bytes):
                    server_aes_key = Validator.validate_injection(data_type=ValConsts.FMT_AES_KEY,
                                                                  value_to_validate=server_aes_key)

                # Add default service data to the list
                self.msg_server_list.append({
                    ProtoConsts.SERVER_ID: server_id,
                    ProtoConsts.SERVER_NAME: server_name,
                    ProtoConsts.AES_KEY: server_aes_key,
                    ProtoConsts.SERVER_IP: server_ip,
                    ProtoConsts.SERVER_PORT: server_port
                })

            # Default service data file doesn't exists
            else:
                self.send_server_general_error(server_socket=server_socket,
                                               client_socket=client_socket,
                                               server_response=server_response)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to get default service data.", exception=e)

    def __get_services_packed_list_data(self) -> bytes:
        """Private method to pack the services list packet."""
        try:
            # Serialize services list
            for server in self.msg_server_list:
                server.update(self.protocol_handler.serialize_packet_value(
                    formatter=code_to_payload_template[ProtoConsts.RES_MSG_SERVERS_LIST],
                    data=server,
                    mode=ProtoConsts.SERIALIZE))

            # Pack servers list
            service_list_formatter = code_to_payload_template[ProtoConsts.RES_MSG_SERVERS_LIST].copy()
            packed = b''
            for service in self.msg_server_list:
                packed += self.protocol_handler.pack_request(code=ProtoConsts.RES_MSG_SERVERS_LIST, data=service,
                                                             formatter=service_list_formatter)
            return packed

        except Exception as e:
            raise CustomException(error_msg=f"Unable to get services list packed data.", exception=e)

    def handle_services_list_request(self, server_socket: CustomSocket, client_socket: socket, server_response: dict) -> None:
        """Sends response with the packed services list back to the requesting peer."""
        try:
            # In case of services registration process failure
            if not self.msg_server_list:
                self.__get_default_service_data(server_socket=server_socket,
                                                client_socket=client_socket,
                                                server_response=server_response)

            # Get services list packed data
            packed_services_list = self.__get_services_packed_list_data()

            # Create packet data frame
            data = {
                ProtoConsts.VERSION: ProtoConsts.SERVER_VERSION,
                ProtoConsts.CODE: ProtoConsts.RES_MSG_SERVERS_LIST,
                ProtoConsts.PAYLOAD_SIZE: len(packed_services_list),
                ProtoConsts.SERVERS_LIST: packed_services_list
            }

            # Create server list formatter template
            servers_list_formatter = code_to_payload_template[ProtoConsts.PKT_SERVERS_LIST].copy()
            servers_list_formatter.update(self.protocol_handler.update_formatter_value(formatter=servers_list_formatter,
                                                                                       pivot_key=ProtoConsts.SERVERS_LIST,
                                                                                       pivot_value=ProtoConsts.SIZE,
                                                                                       new_value=len(packed_services_list)))
            # Pack and send service list response
            packed_servers_list_response = self.protocol_handler.pack_request(code=ProtoConsts.PKT_SERVERS_LIST,
                                                                              data=data,
                                                                              formatter=server_response)
            server_socket.send_packet(sck=client_socket, packet=packed_servers_list_response, logger=self.logger)

            # For dev mode
            if self.debug_mode:
                print(utils.write_with_color(msg=f"Sent Response --> {packed_servers_list_response}",
                                             color=utils.Colors.MAGENTA))

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle services list request.", exception=e)