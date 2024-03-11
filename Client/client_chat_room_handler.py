from sys import exit as sys_exit
from Utils import utils
from Utils.logger import Logger, CustomFilter
from Utils.validator import Validator, ValConsts
from Utils.encryptor import Encryptor
from Utils.custom_exception_handler import CustomException, get_calling_method_name
from Socket.custom_socket import CustomSocket, socket
from Protocol_Handler.protocol_constants import ProtoConsts
from Protocol_Handler.protocol_templates import  server_request, server_response, code_to_payload_template
from Protocol_Handler.protocol_handler import ProtocolHandler
from Client.client_constants import CConsts
from Client.client_input import ClientInput
from Server.MsgServer.msg_server_constants import MsgConsts


class IncompatibleNonce(Exception):
    """Custom Exception in case client nonce and decrypted auth server nonce is not the same."""
    pass


class ChatRoomHandler:
    """Handles all the Client to Service logic."""

    def __init__(self, debug_mode: bool) -> None:
        self.debug_mode = debug_mode
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)

    def __process_service_object(self, unpacked_data: dict, service_id: bytes,
                                 aes_key: bytes, encrypted_key_iv: bytes) -> dict:
        """Returns an updated service object with the TGS generated Ticket."""
        try:
            # Fetch service object
            if not isinstance(service_id, str):
                service_id = Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=service_id)
            service_object = utils.fetch_entry_from_json_db(file_path=CConsts.SERVICES_FILE_PATH,
                                                            pivot_key=CConsts.RAM_SERVER_ID,
                                                            pivot_value=service_id)
            # Serialize packet data and insert into file DBs
            ticket = unpacked_data[ProtoConsts.TICKET]
            serialized_ticket = Validator.validate_injection(data_type=ValConsts.FMT_TICKET,
                                                             value_to_validate=ticket)
            service_object[CConsts.RAM_TICKET] = serialized_ticket
            service_object[CConsts.RAM_AES_KEY] = Validator.validate_injection(data_type=ValConsts.FMT_AES_KEY,
                                                                               value_to_validate=aes_key)
            service_object[CConsts.RAM_ENCRYPTED_KEY_IV] = Validator.validate_injection(data_type=ValConsts.FMT_IV,
                                                                                        value_to_validate=encrypted_key_iv)

            utils.insert_data_to_json_db(file_path=CConsts.SERVICES_FILE_PATH, data=service_object,
                                         pivot_key=CConsts.RAM_SERVER_ID, pivot_value=service_id)

            # Log
            CustomFilter.filter_name = get_calling_method_name()
            self.logger.logger.debug(f"Updated service object successfully.")

            # Return the updated service object
            return service_object

        except Exception as e:
            raise CustomException(error_msg=f"Unable to process service object.", exception=e)

    def __process_encrypted_aes_key_response(self, unpacked_data: dict, ram_template: dict, service_id: bytes,
                                             encryptor: Encryptor, protocol_handler: ProtocolHandler) -> dict:
        """Unpacks and decrypt the encrypted AES packet and return the updated service object."""
        try:
            # Unpack encrypted AES key packet
            unpacked_encrypted_key = protocol_handler.unpack_request(received_packet=unpacked_data[ProtoConsts.ENCRYPTED_KEY],
                                                                     formatter=code_to_payload_template[ProtoConsts.PKT_ENCRYPTED_KEY])
            encrypted_key_iv, encrypted_nonce, encrypted_aes_key = unpacked_encrypted_key

            # Validate data
            Validator.validate_injection(data_type=ValConsts.FMT_IV, value_to_validate=encrypted_key_iv)
            Validator.validate_injection(data_type=ValConsts.FMT_NONCE, value_to_validate=encrypted_nonce)
            Validator.validate_injection(data_type=ValConsts.FMT_AES_KEY, value_to_validate=encrypted_aes_key)

            # Decrypt AES key and nonce
            password_hash = ram_template[CConsts.RAM_PASSWORD_HASH]
            decrypted_kdc_key = encryptor.decrypt(encrypted_value=encrypted_aes_key,
                                                  decryption_key=password_hash,
                                                  iv=encrypted_key_iv)
            decrypted_nonce = encryptor.decrypt(encrypted_value=encrypted_nonce,
                                                decryption_key=password_hash,
                                                iv=encrypted_key_iv)
            # Insert data into RAM DB
            ram_template[CConsts.RAM_AES_KEY] = decrypted_kdc_key
            ram_template[CConsts.RAM_ENCRYPTED_KEY_IV] = encrypted_key_iv

            # Validate nonce and update ticket in services JSON DB
            if ram_template[CConsts.RAM_NONCE] != decrypted_nonce:
                raise IncompatibleNonce(f"Security alert! Incompatible returned nonce, shutting down.")

            # Log
            CustomFilter.filter_name = get_calling_method_name()
            self.logger.logger.debug(f"Processed encrypted key response successfully.")

            # Return the updated service object
            return self.__process_service_object(unpacked_data=unpacked_data, service_id=service_id,
                                                 aes_key=decrypted_kdc_key, encrypted_key_iv=encrypted_key_iv)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to unpack encrypted AES key packet.", exception=e)

    def __process_authenticator_packet(self, ram_template: dict, service_object: dict,
                                       encryptor: Encryptor, protocol_handler: ProtocolHandler) -> bytes:
        """Returns the packed encrypted Authenticator packet."""
        try:
            # Generate Authenticator IV
            authenticator_iv = encryptor.generate_bytes_stream()
            ram_template[CConsts.RAM_AUTH_IV] = authenticator_iv

            # Fetch and validate data
            client_id = ram_template[CConsts.RAM_CLIENT_ID]
            Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=client_id)
            server_id = service_object[CConsts.RAM_SERVER_ID]
            if not isinstance(server_id, bytes):
                server_id = Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=server_id)
            aes_key = service_object[CConsts.RAM_AES_KEY]
            if not isinstance(aes_key, bytes):
                aes_key = Validator.validate_injection(data_type=ValConsts.FMT_AES_KEY, value_to_validate=aes_key)

            # Encrypt data with service AES key
            encrypted_version = encryptor.encrypt(value=str(ProtoConsts.SERVER_VERSION),
                                                  encryption_key=aes_key,
                                                  iv=authenticator_iv)
            encrypted_client_id = encryptor.encrypt(value=client_id, encryption_key=aes_key, iv=authenticator_iv)
            encrypted_server_id = encryptor.encrypt(value=server_id, encryption_key=aes_key, iv=authenticator_iv)
            creation_time = utils.time_now()
            encrypted_creation_time = encryptor.encrypt(value=creation_time, encryption_key=aes_key, iv=authenticator_iv)

            # Create packet data frame
            authenticator_data = {
                ProtoConsts.AUTHENTICATOR_IV: authenticator_iv,
                ProtoConsts.VERSION: encrypted_version,
                ProtoConsts.CLIENT_ID: encrypted_client_id,
                ProtoConsts.SERVER_ID: encrypted_server_id,
                ProtoConsts.CREATION_TIME: encrypted_creation_time
            }
            # Log
            CustomFilter.filter_name = get_calling_method_name()
            self.logger.logger.debug(f"Generated Authenticator packet data successfully.")

            # Pack authenticator packet
            return protocol_handler.pack_request(code=ProtoConsts.PKT_AUTHENTICATOR,
                                                 data=authenticator_data,
                                                 formatter=code_to_payload_template[
                                                          ProtoConsts.PKT_AUTHENTICATOR].copy())

        except Exception as e:
            raise CustomException(error_msg=f"Unable to pack authenticator packet.", exception=e)

    def __process_service_symmetric_key_request(self, ram_template: dict, service_object: dict,
                                                encryptor: Encryptor, protocol_handler: ProtocolHandler) -> bytes:
        """Returns the packed symmetric key packet."""
        try:
            # Pack Authenticator packet
            authenticator = self.__process_authenticator_packet(ram_template=ram_template,
                                                                service_object=service_object,
                                                                encryptor=encryptor,
                                                                protocol_handler=protocol_handler)
            # Fetch and validate Ticket
            ticket = service_object[CConsts.RAM_TICKET]
            if not isinstance(ticket, bytes):
                ticket = Validator.validate_injection(data_type=ValConsts.FMT_TICKET, value_to_validate=ticket)

            # Validate client id
            client_id = ram_template[CConsts.RAM_CLIENT_ID]
            Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=client_id)

            # Create packet data frame
            data = {
                ProtoConsts.CLIENT_ID: client_id,
                ProtoConsts.VERSION: ProtoConsts.SERVER_VERSION,
                ProtoConsts.CODE: ProtoConsts.REQ_MSG_SERVER_AES_KEY,
                ProtoConsts.PAYLOAD_SIZE: len(authenticator) + len(ticket),
                ProtoConsts.AUTHENTICATOR: authenticator,
                ProtoConsts.TICKET: ticket
            }

            # Log
            CustomFilter.filter_name = get_calling_method_name()
            self.logger.logger.debug(f"Created symmetric key packet data successfully.")

            # Return the packed request
            return protocol_handler.pack_request(code=ProtoConsts.REQ_MSG_SERVER_AES_KEY,
                                                 data=data,
                                                 formatter=server_request.copy())

        except Exception as e:
            raise CustomException(error_msg=f"Unable to pack symmetric key request.", exception=e)

    def __enter_chat_room(self, sck: CustomSocket, service_socket: socket, ram_template: dict,
                          encryptor: Encryptor, protocol_handler: ProtocolHandler) -> None:
        """Start chatting with encrypted messages."""
        try:
            # Log
            client_name = ram_template[CConsts.RAM_USERNAME]
            CustomFilter.filter_name = get_calling_method_name()
            self.logger.logger.debug(f"{client_name} has entered the chat.")

            # Start chat
            while True:
                # Monitor connection to chat room
                if not sck.monitor_connection(sck=service_socket):
                    service_socket.close()

                # Get and validate data
                msg_iv = encryptor.generate_bytes_stream()
                ram_template[CConsts.RAM_MESSAGE_IV] = msg_iv
                aes_key = ram_template[CConsts.RAM_AES_KEY]
                client_id = ram_template[CConsts.RAM_CLIENT_ID]
                Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=client_id)

                # Get and encrypt message
                msg_content = f"{ram_template[CConsts.RAM_USERNAME]}: {ClientInput.get_client_input(suffix='message')}"
                encrypted_message = encryptor.encrypt(value=msg_content, encryption_key=aes_key, iv=msg_iv)

                msg_data = {
                    ProtoConsts.CLIENT_ID: client_id,
                    ProtoConsts.VERSION: ProtoConsts.SERVER_VERSION,
                    ProtoConsts.CODE: ProtoConsts.REQ_SEND_MSG,
                    ProtoConsts.PAYLOAD_SIZE: ProtoConsts.SIZE_MSG + ProtoConsts.SIZE_IV + len(encrypted_message),
                    ProtoConsts.MSG_SIZE: len(encrypted_message),
                    ProtoConsts.MSG_IV: msg_iv,
                    ProtoConsts.MSG_CONTENT: encrypted_message
                }
                # Adjust sizes and pack request
                code_to_payload_template[ProtoConsts.REQ_SEND_MSG][ProtoConsts.MSG_CONTENT][ProtoConsts.SIZE] = len(encrypted_message)
                packed_msg_request = protocol_handler.pack_request(code=ProtoConsts.REQ_SEND_MSG,
                                                                   data=msg_data,
                                                                   formatter=server_request.copy())
                msg_response = sck.send_recv_packet(sck=service_socket, packet=packed_msg_request,
                                                    logger=self.logger, response=True)
                code, unpacked_msg_response = protocol_handler.unpack_request(received_packet=msg_response,
                                                                              formatter=server_response.copy(),
                                                                              deserialize=True)
                # Corrupted message
                if code != ProtoConsts.RES_MSG_ACK:
                    print(utils.write_with_color(msg=f"{ProtoConsts.CONSOLE_ERROR} {CConsts.SERVER_GENERAL_ERROR}",
                                                 color=utils.Colors.RED))
                    pass

        except Exception as e:
            raise CustomException(error_msg=f"Unable to use chat room.", exception=e)

    def __handle_symmetric_key_request(self, service_object: dict, sck: CustomSocket, service_socket: socket,
                                       ram_template: dict, encryptor: Encryptor, protocol_handler: ProtocolHandler) -> bytes:
        """Sends symmetric key request to the service."""
        try:
            # Fetch and validate connection data
            service_ip_address = service_object[CConsts.RAM_SERVER_IP]
            Validator.validate_injection(data_type=ValConsts.FMT_IPV4, value_to_validate=service_ip_address)
            service_port = service_object[CConsts.RAM_SERVER_PORT]
            Validator.validate_injection(data_type=ValConsts.FMT_PORT, value_to_validate=service_port)

            # Connect to the service server
            sck.connect(sck=service_socket, ip_address=service_ip_address, port=service_port)

            # Pack request
            packed_service_aes_request = self.__process_service_symmetric_key_request(ram_template=ram_template,
                                                                                      service_object=service_object,
                                                                                      encryptor=encryptor,
                                                                                      protocol_handler=protocol_handler)

            # Send request and receive response
            return sck.send_recv_packet(sck=service_socket, packet=packed_service_aes_request,
                                        logger=self.logger, response=True)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle symmetric key request from service.", exception=e)

    def connect_to_service(self, sck: CustomSocket, client_socket: socket, ram_template: dict, server_id: bytes,
                           unpacked_aes_key_response: dict, encryptor: Encryptor, protocol_handler: ProtocolHandler) -> None:
        """Sends symmetric key request to the service and enter the chat room."""
        try:
            # Close connection to auth server
            client_socket.close()

            # Create a new socket to connect to service
            service_socket = sck.create_socket()

            # Process encrypted AES key packet and fetch Ticket
            try:
                service_object = self.__process_encrypted_aes_key_response(unpacked_data=unpacked_aes_key_response,
                                                                           ram_template=ram_template,
                                                                           service_id=server_id,
                                                                           encryptor=encryptor,
                                                                           protocol_handler=protocol_handler)
                # For dev mode
                if self.debug_mode:
                    print(utils.write_with_color(msg=f"Parsed encrypted key response template --> {ram_template}",
                                                 color=utils.Colors.CYAN))

                # Handle symmetric key request
                symmetric_key_response = self.__handle_symmetric_key_request(service_object=service_object,
                                                                             sck=sck,
                                                                             service_socket=service_socket,
                                                                             ram_template=ram_template,
                                                                             encryptor=encryptor,
                                                                             protocol_handler=protocol_handler)
                code, unpacked_symmetric_key_response = protocol_handler.unpack_request(received_packet=symmetric_key_response,
                                                                                        formatter=server_response.copy(),
                                                                                        deserialize=True)
                # Enter chat room
                if code == ProtoConsts.RES_AES_KEY_ACK:
                    service_name = service_object[CConsts.RAM_SERVER_NAME]
                    print(MsgConsts.WELCOME_MSG.format(MsgConsts.MSG_SERVER_LOGO, service_name))
                    self.__enter_chat_room(sck=sck,
                                           service_socket=service_socket,
                                           ram_template=ram_template,
                                           encryptor=encryptor,
                                           protocol_handler=protocol_handler)
                else:
                    print(utils.write_with_color(msg=f"{ProtoConsts.CONSOLE_ERROR} {CConsts.SERVER_GENERAL_ERROR}",
                                                 color=utils.Colors.RED))

            except IncompatibleNonce as e:
                self.logger.logger.error(str(e))
                print(utils.write_with_color(msg=f"{ProtoConsts.CONSOLE_ERROR} {str(e)}", color=utils.Colors.RED))
                client_socket.close()
                sys_exit(ProtoConsts.STATUS_ERROR_CODE)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to connect to service.", exception=e)