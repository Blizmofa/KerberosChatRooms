import json
import struct

from Utils.logger import Logger
from Utils import utils
import base64
from Socket.custom_socket import CustomSocket, socket
from Utils.custom_exception_handler import CustomException
from Protocol_Handler.protocol_handler import ProtocolHandler
from Protocol_Handler.protocol_utils import (packet_register_success, packet_no_payload,
                                             code_to_payload_template, ProtocolConstants as ProtoConsts)
from Server.AuthServer.auth_server_constants import (file_db_clients_template, file_db_servers_template,
                                                     Constants as AuthConsts)
from Server.MsgServer.msg_server_constants import Constants as MsgConsts
from Utils.validator import Validator, Constants as ValConsts
from Utils.encryptor import Encryptor


class AuthServerLogic:
    """AuthServerLogic is an auxiliary class to handle all Auth Server protocol requirements."""

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
            # if not utils.search_value_in_file(value=data[AuthConsts.RAM_CLIENT_NAME],
            #                                   file_path=AuthConsts.CLIENTS_FILE_PATH):

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

                # Log output
                msg = (f"{ProtoConsts.CONSOLE_ACK} '{data[ProtoConsts.NAME]}' "
                       f"has been registered successfully.")
                self.logger.logger.info(msg=msg)

                # For dev mode
                if self.debug_mode:
                    print(utils.write_with_color(msg=msg, color=utils.Colors.GREEN))

                # Pack response
                packet_register_success[ProtoConsts.CLIENT_ID] = client_id
                return self.protocol_handler.pack_request(code=ProtoConsts.RES_REGISTER_SUCCESS,
                                                          data=packet_register_success,
                                                          formatter=server_response.copy())
            # Already Registered case
            else:
                msg = (f"{ProtoConsts.CONSOLE_FAIL} '{data[ProtoConsts.NAME]}' "
                       f"is already registered.")
                self.logger.logger.info(msg=msg)

                # For dev mode
                if self.debug_mode:
                    print(utils.write_with_color(msg=msg, color=utils.Colors.RED))

                # Pack response
                packet_no_payload[ProtoConsts.CODE] = ProtoConsts.RES_REGISTER_FAILED
                return self.protocol_handler.pack_request(code=ProtoConsts.RES_REGISTER_FAILED,
                                                          data=packet_no_payload,
                                                          formatter=server_response.copy())

        except Exception as e:
            raise CustomException(error_msg=f"Unable to register client '{data[ProtoConsts.NAME]}'.", exception=e)

    def __register_server(self, data: dict, server_ram_template: dict, sck: socket, server_response: dict) -> bytes:
        """Private method to registers new services if not already registered according to the server DB."""
        try:
            # Not registered server case
            if "name" in data:
            # if not utils.search_value_in_file(value=data[protocol_utils.Constants.NAME],
            #                                   file_path=AuthServerConstants.SERVERS_FILE_PATH):
                # Generate server id
                server_id = utils.generate_uuid()
                Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=server_id)
                server_ram_template[AuthConsts.RAM_SERVER_ID] = server_id
                server_ram_template[AuthConsts.RAM_SERVER_ID_HEX] = server_id.hex()
                server_aes_key = data[ProtoConsts.AES_KEY]
                # TODO - create validator method for aes key, consider str, bytes, lengths, encrypted etc.
                if isinstance(server_aes_key, bytes):
                    server_ram_template[AuthConsts.RAM_AES_KEY_HEX] = server_aes_key.hex()

                # Insert Server data into DBs and list
                utils.insert_data_to_ram_db(ram_template=server_ram_template, data=data)

                # Create a DNS mapping of the registered servers
                server_ip, server_port = sck.getpeername()
                self.msg_server_list.append({
                    ProtoConsts.SERVER_ID: server_id,
                    ProtoConsts.SERVER_NAME: data[ProtoConsts.NAME],
                    ProtoConsts.SERVER_IP: server_ip,
                    ProtoConsts.SERVER_PORT: server_port
                })
                utils.insert_data_to_file_db(file_path=AuthConsts.SERVERS_FILE_PATH,
                                             data=server_ram_template,
                                             formatter=file_db_servers_template.copy())

                # Log output
                msg = (f"{ProtoConsts.CONSOLE_ACK} '{data[ProtoConsts.NAME]}' "
                       f"has been registered successfully.")
                self.logger.logger.info(msg=msg)

                # For dev mode
                if self.debug_mode:
                    print(utils.write_with_color(msg=msg, color=utils.Colors.GREEN))

                # Pack response
                packet_register_success[ProtoConsts.CLIENT_ID] = server_id
                return self.protocol_handler.pack_request(code=ProtoConsts.RES_REGISTER_SUCCESS,
                                                          data=packet_register_success,
                                                          formatter=server_response.copy())
            # Already Registered case
            else:
                msg = (
                    f"{ProtoConsts.CONSOLE_FAIL} '{data[ProtoConsts.NAME]}' "
                    f"is already registered.")
                self.logger.logger.info(msg=msg)

                # For dev mode
                if self.debug_mode:
                    print(utils.write_with_color(msg=msg, color=utils.Colors.RED))

                # Pack response
                packet_no_payload[ProtoConsts.CODE] = ProtoConsts.RES_REGISTER_FAILED
                return self.protocol_handler.pack_request(code=ProtoConsts.RES_REGISTER_FAILED,
                                                          data=packet_no_payload,
                                                          formatter=server_response.copy())

        except Exception as e:
            raise CustomException(error_msg=f"Unable to register server.", exception=e)

    def handle_registration_request(self, server_socket: CustomSocket, client_socket: socket, request_code: int,
                                    unpacked_packet: dict, client_ram_template: dict, server_ram_template: dict,
                                    server_response: dict) -> None:
        """Sends response with the packed register request back to client or server."""
        try:
            # Handle clients requests
            if request_code == ProtoConsts.REQ_CLIENT_REG:
                register_response = self.__register_client(data=unpacked_packet, client_ram_template=client_ram_template, server_response=server_response)

            # Handle servers requests
            elif request_code == ProtoConsts.REQ_SERVER_REG:
                register_response = self.__register_server(data=unpacked_packet, server_ram_template=server_ram_template, sck=client_socket, server_response=server_response)

            else:
                raise ValueError(f"Unsupported registration request code '{request_code}'.")

            # Send response back to client/server
            server_socket.send_packet(sck=client_socket, packet=register_response)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle registration request from {client_socket.getpeername()}.", exception=e)

    def create_ticket(self):
        try:
            pass

        except Exception as e:
            raise CustomException(error_msg=f"Unable to create ticket for.", exception=e)

    def handle_aes_key_request(self, server_socket: CustomSocket, client_socket: socket, unpacked_packet: dict,
                               client_ram_template: dict, server_ram_template: dict, server_response: dict) -> None:
        try:
            # Fetch and validate needed data
            client_nonce = unpacked_packet[ProtoConsts.NONCE]
            client_ram_template[ProtoConsts.NONCE] = client_nonce
            client_id = client_ram_template[ProtoConsts.CLIENT_ID]
            server_id = unpacked_packet[ProtoConsts.SERVER_ID]
            # TODO - continue from here, get client wanted server id the get its data and continue
            # TODO - check if server id is in msg servers list and file
            # TODO - insert values to RAM and file DB
            password_hash = self.encryptor.hash_password(password='qwer1234')

            # Generate AES key, encrypt nonce, and pack encrypted key packet
            aes_key = self.encryptor.generate_bytes_stream(size=ProtoConsts.SIZE_AES_KEY)
            encrypted_key_iv = self.encryptor.generate_bytes_stream(size=ProtoConsts.SIZE_IV)
            encrypted_aes_key = self.encryptor.encrypt(value=aes_key, encryption_key=password_hash, iv=encrypted_key_iv)
            encrypted_nonce = self.encryptor.encrypt(value=client_nonce, encryption_key=password_hash, iv=encrypted_key_iv)

            # Pack Encrypted key packet
            encrypted_key_data = {
                ProtoConsts.ENCRYPTED_KEY_IV: encrypted_key_iv,
                ProtoConsts.NONCE: encrypted_nonce,
                ProtoConsts.AES_KEY: encrypted_aes_key
            }

            packed_encrypted_key_packet = self.protocol_handler.pack_request(code=ProtoConsts.PKT_ENCRYPTED_KEY,
                                                                             data=encrypted_key_data,
                                                                             formatter=code_to_payload_template[1701])

            # Pack Ticket packet
            # TODO - insert to DBs
            # TODO - how does the msg server gets his key??
            ticket_iv = self.encryptor.generate_bytes_stream()
            ticket_aes_key = self.encryptor.generate_bytes_stream(size=ProtoConsts.SIZE_AES_KEY)
            expiration_time = utils.expiration_time(days_buffer=1)
            encrypted_ticket_aes_key = self.encryptor.encrypt(value=ticket_aes_key, encryption_key=ticket_aes_key, iv=ticket_iv)
            encrypted_ticket_expiration_time = self.encryptor.encrypt(value=expiration_time,
                                                                      encryption_key=ticket_aes_key,
                                                                      iv=ticket_iv)

            ticket_data = {
                ProtoConsts.VERSION: ProtoConsts.SERVER_VERSION,
                ProtoConsts.CLIENT_ID: client_id,
                ProtoConsts.SERVER_ID: server_id,
                ProtoConsts.CREATION_TIME: utils.time_now(),
                ProtoConsts.TICKET_IV: ticket_iv,
                ProtoConsts.AES_KEY: encrypted_ticket_aes_key,
                ProtoConsts.EXPIRATION_TIME: encrypted_ticket_expiration_time
            }

            packed_ticket_packet = self.protocol_handler.pack_request(code=ProtoConsts.PKT_TICKET,
                                                                      data=ticket_data,
                                                                      formatter=code_to_payload_template[1702])

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
            response_data = {
                ProtoConsts.VERSION: ProtoConsts.SERVER_VERSION,
                ProtoConsts.CODE: ProtoConsts.RES_ENCRYPTED_AES_KEY,
                ProtoConsts.PAYLOAD_SIZE: ProtoConsts.SIZE_CLIENT_ID + len(packed_encrypted_key_packet) + len(packed_ticket_packet),
                ProtoConsts.CLIENT_ID: client_id,
                ProtoConsts.ENCRYPTED_KEY: packed_encrypted_key_packet,
                ProtoConsts.TICKET: packed_ticket_packet
            }
            packed_encrypted_key_response = self.protocol_handler.pack_request(code=ProtoConsts.RES_ENCRYPTED_AES_KEY,
                                                                               data=response_data,
                                                                               formatter=server_response)
            # print(len(packed_encrypted_key_packet))
            # print(len(packed_ticket_packet))

            server_socket.send_packet(sck=client_socket, packet=packed_encrypted_key_response, logger=self.logger)
            # code, unpacked_encrypted_key_response = self.protocol_handler.unpack_request(received_packet=packed_encrypted_key_response,
            #                                                                        formatter=server_response,
            #                                                                        deserialize=True)
            # #
            # print(unpacked_encrypted_key_response['encrypted_key'])
            # print(unpacked_encrypted_key_response['ticket'])

            # TODO - get server details from DB

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle encrypted key request from {client_socket.getpeername()}.", exception=e)

    def __get_default_service_data(self, file_db: str, server_socket: CustomSocket,
                                   client_socket: socket, server_response: dict) -> None:
        """Private method to get a default registered service data."""
        try:
            # Validate default registered service file
            if utils.check_if_exists(file_db):

                # Parse and validate default service data
                ip_and_port = utils.parse_info_file(file_path=file_db,
                                                    target_line_number=MsgConsts.LINE_IP_PORT)
                server_ip, server_port = Validator.validate_injection(data_type=ValConsts.FMT_IPV4_PORT, value_to_validate=ip_and_port)
                server_id = utils.parse_info_file(file_path=file_db, target_line_number=MsgConsts.LINE_ID)
                if not isinstance(server_id, bytes):
                    server_id = Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=server_id)

                server_name = utils.parse_info_file(file_path=file_db, target_line_number=MsgConsts.LINE_NAME)
                Validator.validate_injection(data_type=ValConsts.FMT_NAME, value_to_validate=server_name)

                # Add default service data to the list
                self.msg_server_list.append({
                    ProtoConsts.SERVER_ID: server_id,
                    ProtoConsts.SERVER_NAME: server_name,
                    ProtoConsts.SERVER_IP: server_ip,
                    ProtoConsts.SERVER_PORT: server_port
                })
                print(self.msg_server_list)
            # Default service data file doesn't exists
            else:
                packet_no_payload[ProtoConsts.CODE] = ProtoConsts.RES_GENERAL_ERROR
                packed_general_error = self.protocol_handler.pack_request(code=ProtoConsts.RES_GENERAL_ERROR,
                                                                          data=packet_no_payload,
                                                                          formatter=server_response.copy())
                server_socket.send_packet(sck=client_socket, packet=packed_general_error)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to get default service data.", exception=e)

    def __get_services_packed_list_data(self) -> bytes:
        """Private method to get the services list packed packet."""
        try:
            # Serialize services list
            for server in self.msg_server_list:
                server.update(self.protocol_handler.serialize_packet_value(
                    formatter=code_to_payload_template[ProtoConsts.RES_MSG_SERVERS_LIST],
                    data=server,
                    mode=ProtoConsts.SERIALIZE))

            # Pack servers list
            formatter_copy = code_to_payload_template[ProtoConsts.RES_MSG_SERVERS_LIST].copy()
            packed = b''
            for service in self.msg_server_list:
                packed += self.protocol_handler.pack_request(code=ProtoConsts.RES_MSG_SERVERS_LIST, data=service,
                                                             formatter=formatter_copy)
            return packed

        except Exception as e:
            raise CustomException(error_msg=f"Unable to get services list packed data.", exception=e)

    def handle_services_list_request(self, server_socket: CustomSocket, client_socket: socket, server_response: dict) -> None:
        """Sends response with the packed services list back to client."""
        try:
            # In case of services registration process failure
            if not self.msg_server_list:
                self.__get_default_service_data(file_db=MsgConsts.MSG_FILE_NAME, server_socket=server_socket,
                                                client_socket=client_socket, server_response=server_response)

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

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle services list request.", exception=e)