import struct

from Utils.logger import Logger
from Utils import utils
import base64
from Socket.custom_socket import CustomSocket, socket
from Utils.custom_exception_handler import CustomException
from Protocol_Handler.protocol_handler import ProtocolHandler
from Protocol_Handler import protocol_utils
from Server.AuthServer.auth_server_constants import AuthServerConstants
from Utils.encryptor import Encryptor


class AuthServerLogic:
    """AuthServerLogic is an auxiliary class to handle all Auth Server protocol requirements."""

    def __init__(self, debug_mode: bool) -> None:
        self.msg_server_list = []
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)
        self.protocol_handler = ProtocolHandler(debug_mode=debug_mode)
        self.encryptor = Encryptor(debug_mode=debug_mode)

    def __register_client(self, data: dict, client_ram_template: dict) -> bytes:
        try:
            # Not registered client case
            if not utils.search_value_in_file(value=data[AuthServerConstants.RAM_CLIENT_NAME],
                                              file_path=AuthServerConstants.CLIENTS_FILE_PATH):
                client_id = utils.generate_uuid()
                client_ram_template[AuthServerConstants.RAM_ID] = utils.convert_bytes_or_hex(data=client_id,
                                                                                             mode=protocol_utils.Constants.HEX)
                client_ram_template[AuthServerConstants.RAM_PASSWORD_HASH] = self.encryptor.hash_password(
                    data[protocol_utils.Constants.PASSWORD])

                # Insert Client data into DBs
                utils.insert_data_to_ram_db(ram_template=client_ram_template, data=data)
                # utils.insert_data_to_file_db(file_path=AuthServerConstants.CLIENTS_FILE_PATH, data=client_ram_template)

                # Pack response
                protocol_utils.packet_register_success[protocol_utils.Constants.CLIENT_ID] = client_id
                return self.protocol_handler.pack_request(code=protocol_utils.Constants.RES_REGISTER_SUCCESS,
                                                          data=protocol_utils.packet_register_success,
                                                          formatter=protocol_utils.server_response.copy())
            # Already Registered case
            else:
                # Pack response
                return self.protocol_handler.pack_request(code=protocol_utils.Constants.RES_REGISTER_FAILED,
                                                          data=protocol_utils.packet_register_failure,
                                                          formatter=protocol_utils.server_response.copy())

        except Exception as e:
            raise CustomException(error_msg=f"Unable to register client.", exception=e)

    def __register_server(self, data: dict, server_ram_template: dict, sck: socket) -> bytes:
        try:
            # Not registered server case
            if not utils.search_value_in_file(value=data[protocol_utils.Constants.NAME],
                                              file_path=AuthServerConstants.SERVERS_FILE_PATH):
                # Generate server id
                server_id = utils.generate_uuid()
                server_ram_template[AuthServerConstants.RAM_ID] = utils.convert_bytes_or_hex(data=server_id,
                                                                                             mode=protocol_utils.Constants.HEX)
                # Insert Server data into DBs and list
                utils.insert_data_to_ram_db(ram_template=server_ram_template, data=data)
                # utils.insert_data_to_file_db(file_path=AuthServerConstants.SERVERS_FILE_PATH, data=server_ram_template)

                # Create a DNS mapping of the registered servers
                server_ip, server_port = sck.getpeername()
                self.msg_server_list.append({
                    protocol_utils.Constants.SERVER_ID: server_id,
                    protocol_utils.Constants.SERVER_NAME: data[protocol_utils.Constants.NAME],
                    protocol_utils.Constants.SERVER_IP: server_ip,
                    protocol_utils.Constants.SERVER_PORT: server_port
                })
                # print(self.msg_server_list)
                # Pack response
                protocol_utils.packet_register_success[protocol_utils.Constants.CLIENT_ID] = server_id
                return self.protocol_handler.pack_request(code=protocol_utils.Constants.RES_REGISTER_SUCCESS,
                                                          data=protocol_utils.packet_register_success,
                                                          formatter=protocol_utils.server_response.copy())

            # Already Registered case
            else:
                # Pack response
                return self.protocol_handler.pack_request(code=protocol_utils.Constants.RES_REGISTER_FAILED,
                                                          data=protocol_utils.packet_register_failure,
                                                          formatter=protocol_utils.server_response.copy())

        except Exception as e:
            raise CustomException(error_msg=f"Unable to register server.", exception=e)

    def handle_registration_request(self, server_socket: CustomSocket, client_socket: socket, request_code: int,
                                    unpacked_packet: dict, client_ram_template: dict, server_ram_template: dict) -> None:
        try:
            # Handle clients requests
            if request_code == protocol_utils.Constants.REQ_CLIENT_REG:
                register_response = self.__register_client(data=unpacked_packet, client_ram_template=client_ram_template)

            # Handle servers requests
            elif request_code == protocol_utils.Constants.REQ_SERVER_REG:
                register_response = self.__register_server(data=unpacked_packet, server_ram_template=server_ram_template, sck=client_socket)

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
                               client_ram_template: dict, server_ram_template: dict) -> None:
        try:
            nonce = unpacked_packet['nonce']
            client_id = client_ram_template[protocol_utils.Constants.CLIENT_ID]
            # TODO - fetch the wanted server if from DBs
            server_id = None
            # print(client_id)
            # print(unpacked_packet)
            # print("NONCE: ", nonce)
            # TODO - check if server id is in msg servers list and file
            # TODO - insert values to RAM and file DB
            password_hash = self.encryptor.hash_password(password='qwer1234')
            # print("HASH: ", password_hash)
            # Generate AES key, encrypt nonce, and pack encrypted key packet
            aes_key = self.encryptor.generate_bytes_stream(size=32)
            # print("AES_KEY: ", aes_key)
            encrypted_key_iv = self.encryptor.generate_bytes_stream(size=16)
            encrypted_aes_key = self.encryptor.encrypt(value=aes_key, encryption_key=password_hash, iv=encrypted_key_iv)
            encrypted_nonce = self.encryptor.encrypt(value=nonce, encryption_key=password_hash, iv=encrypted_key_iv)
            # print("IV: ", iv)
            # print("ENCRYPTED_KEY", encrypted_aes_key)
            # print("ENCRYPTED_NONCE", encrypted_nonce)

            # decrypted_aes_key = self.encryptor.decrypt(encrypted_value=encrypted_aes_key, password_hash=password_hash, iv=iv)
            # decrypted_nonce = self.encryptor.decrypt(encrypted_value=encrypted_nonce, password_hash=password_hash, iv=iv)
            # print("DECRYPTED_KEY", decrypted_aes_key)
            # print("DECRYPTED_NONCE", decrypted_nonce)
            # print(decrypted_aes_key == aes_key)
            # print(decrypted_nonce == nonce)

            # Pack Encrypted key packet
            encrypted_key_data = {
                protocol_utils.Constants.ENCRYPTED_KEY_IV: encrypted_key_iv,
                protocol_utils.Constants.NONCE: encrypted_nonce,
                protocol_utils.Constants.AES_KEY: encrypted_aes_key
            }

            packed_encrypted_key_packet = self.protocol_handler.pack_request(code=protocol_utils.Constants.PKT_ENCRYPTED_KEY,
                                                                             data=encrypted_key_data,
                                                                             formatter=protocol_utils.code_to_payload_template[1701])

            # Pack Ticket packet
            # TODO - insert to DBs
            # TODO - how does the msg server gets his key??
            ticket_iv = self.encryptor.generate_bytes_stream()
            ticket_aes_key = self.encryptor.generate_bytes_stream(size=32)
            encrypted_ticket_aes_key = self.encryptor.encrypt(value=ticket_aes_key, encryption_key=ticket_aes_key, iv=ticket_iv)
            # print(ticket_aes_key)
            # print(encrypted_ticket_aes_key)
            # decrypted_ticket_aes_key = self.encryptor.decrypt(encrypted_value=encrypted_ticket_aes_key, decryption_key=ticket_aes_key, iv=ticket_iv)
            # print(decrypted_ticket_aes_key)
            # print(ticket_aes_key == decrypted_ticket_aes_key)
            encrypted_ticket_expiration_time = self.encryptor.encrypt(value=utils.expiration_time(days_buffer=1),
                                                                      encryption_key=ticket_aes_key,
                                                                      iv=ticket_iv)
            print(encrypted_ticket_expiration_time)

            ticket_data = {
                protocol_utils.Constants.VERSION: protocol_utils.Constants.SERVER_VERSION,
                protocol_utils.Constants.CLIENT_ID: client_id,
                protocol_utils.Constants.SERVER_ID: server_id,
                protocol_utils.Constants.CREATION_TIME: utils.time_now(),
                protocol_utils.Constants.TICKET_IV: ticket_iv,
                protocol_utils.Constants.AES_KEY: encrypted_ticket_aes_key,
                protocol_utils.Constants.EXPIRATION_TIME: encrypted_ticket_expiration_time
            }

            packed_ticket_response = self.protocol_handler.pack_request(code=protocol_utils.Constants.PKT_TICKET,
                                                                        data=ticket_data,
                                                                        formatter=protocol_utils.code_to_payload_template[1702])
            # print(packed_ticket_response)
            # TODO - continue from herre, adjust sizes after encryption, padding, etc and check pack unpack and decryption
            unpacked = struct.unpack(f'<B16s16s8s16s32s8s', packed_ticket_response)
            expiration_time = unpacked[6]
            unpacked_ticket_iv = unpacked[4]
            print(unpacked_ticket_iv)
            print(unpacked_ticket_iv == ticket_iv)
            print(expiration_time)
            print(encrypted_ticket_expiration_time == expiration_time)
            # print(self.encryptor.decrypt(encrypted_value=unpacked[6], decryption_key=aes_key, iv=ticket_iv))

            # TODO - get server details from DB

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle encrypted key request from {client_socket.getpeername()}.", exception=e)

    def handle_services_list_request(self, server_socket: CustomSocket, client_socket: socket, unpacked_packet: dict,
                                     client_ram_template: dict,
                                     server_request: dict, server_response: dict) -> None:
        try:
            # TODO - more scalable and robust server, pass the receive request to core, then according to the request code call the logic method.
            # TODO - add case for empty servers list

            # Serialize list
            for server in self.msg_server_list:

            # for server in servers_list:
                server.update(self.protocol_handler.serialize_packet_value(
                    formatter=protocol_utils.code_to_payload_template[1602],
                    data=server,
                    mode=protocol_utils.Constants.SERIALIZE))

            formatter_copy = protocol_utils.code_to_payload_template[1602].copy()
            packed = b''
            for service in self.msg_server_list:
            # for service in servers_list:
                packed += self.protocol_handler.pack_request(code=1602, data=service, formatter=formatter_copy)

            data = {
                protocol_utils.Constants.VERSION: protocol_utils.Constants.SERVER_VERSION,
                protocol_utils.Constants.CODE: protocol_utils.Constants.RES_MSG_SERVERS_LIST,
                protocol_utils.Constants.PAYLOAD_SIZE: len(packed),
                protocol_utils.Constants.SERVERS_LIST: packed
            }

            servers_list_formatter = protocol_utils.code_to_payload_template[1700].copy()
            servers_list_formatter.update(self.protocol_handler.update_formatter_value(formatter=servers_list_formatter,
                                                                                       pivot_key="size",
                                                                                       new_value=len(packed)))
            packed_servers_list_response = self.protocol_handler.pack_request(code=protocol_utils.Constants.PKT_SERVERS_LIST,
                                                                              data=data,
                                                                              formatter=server_response)

            server_socket.send_packet(sck=client_socket, packet=packed_servers_list_response, logger=self.logger)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle services list request.", exception=e)