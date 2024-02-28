from Utils.utils import is_expired, write_with_color, Colors
from Utils.logger import Logger, CustomFilter
from Utils.validator import Validator, ValConsts
from Utils.encryptor import Encryptor
from Utils.custom_exception_handler import CustomException, get_calling_method_name
from Socket.custom_socket import CustomSocket, socket
from Protocol_Handler.protocol_utils import (ProtoConsts, server_request, server_response,
                                             packet_no_payload, code_to_payload_template)
from Protocol_Handler.protocol_handler import ProtocolHandler
from Server.MsgServer.msg_server_constants import MsgConsts


class SymmetricKeyHandler:
    """Handles Msg Server Symmetric Key request logic."""

    def __init__(self, debug_mode: bool) -> None:
        self.debug_mode = debug_mode
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)

    def __process_authenticator_packet(self, authenticator: bytes, service_aes_key: bytes,
                                       encryptor: Encryptor, protocol_handler: ProtocolHandler) -> dict:
        """Returns the decrypted unpacked Authenticator data."""
        try:
            # Unpack Authenticator packet
            authenticator_data = protocol_handler.unpack_request(received_packet=authenticator,
                                                                 formatter=code_to_payload_template[
                                                                                ProtoConsts.PKT_AUTHENTICATOR].copy())
            # Unpack Authenticator data
            authenticator_iv, version, client_id, server_id, creation_time = authenticator_data

            # Decrypt and validate data
            decrypted_version = int(encryptor.decrypt(encrypted_value=version,
                                                      decryption_key=service_aes_key,
                                                      iv=authenticator_iv).decode())
            Validator.validate_injection(data_type=ValConsts.FMT_VERSION, value_to_validate=decrypted_version)
            decrypted_client_id = encryptor.decrypt(encrypted_value=client_id,
                                                    decryption_key=service_aes_key,
                                                    iv=authenticator_iv)
            Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=client_id)
            decrypted_server_id = encryptor.decrypt(encrypted_value=server_id,
                                                    decryption_key=service_aes_key,
                                                    iv=authenticator_iv)
            Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=server_id)
            decrypted_creation_time = encryptor.decrypt(encrypted_value=creation_time,
                                                        decryption_key=service_aes_key,
                                                        iv=authenticator_iv).decode()
            Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=server_id)

            # Create data frame
            processes_authenticator_data = {
                ProtoConsts.VERSION: decrypted_version,
                ProtoConsts.CLIENT_ID: decrypted_client_id,
                ProtoConsts.SERVER_ID: decrypted_server_id,
                ProtoConsts.CREATION_TIME: decrypted_creation_time
            }
            # Log
            CustomFilter.filter_name = get_calling_method_name()
            msg = f"Decrypted authenticator packet --> {processes_authenticator_data}"
            self.logger.logger.debug(msg=msg)

            # For dev mode
            if self.debug_mode:
                print(write_with_color(msg=msg, color=Colors.CYAN))

            # Return the processed data
            return processes_authenticator_data

        except Exception as e:
            raise CustomException(error_msg=f"Unable to process authenticator packet.", exception=e)

    def __process_ticket_packet(self, ticket: bytes, service_aes_key: bytes,
                                encryptor: Encryptor, protocol_handler: ProtocolHandler) -> dict:
        """Returns the decrypted unpacked Ticket data."""
        try:
            # Unpack Ticket packet
            ticket_data = protocol_handler.unpack_request(received_packet=ticket,
                                                          formatter=code_to_payload_template[
                                                                                ProtoConsts.PKT_TICKET].copy())
            # Unpack Ticket data
            version, client_id, server_id, creation_time, ticket_iv, ticket_aes_key, expiration_time = ticket_data

            # Decrypt and validate data
            decrypted_creation_time = encryptor.decrypt(encrypted_value=creation_time,
                                                        decryption_key=service_aes_key,
                                                        iv=ticket_iv).decode()
            Validator.validate_injection(data_type=ValConsts.FMT_CREATION_TIME, value_to_validate=decrypted_creation_time)
            decrypted_aes_key = encryptor.decrypt(encrypted_value=ticket_aes_key,
                                                  decryption_key=service_aes_key,
                                                  iv=ticket_iv)
            Validator.validate_injection(data_type=ValConsts.FMT_AES_KEY, value_to_validate=decrypted_aes_key)
            decrypted_expiration_time = encryptor.decrypt(encrypted_value=expiration_time,
                                                          decryption_key=service_aes_key,
                                                          iv=ticket_iv).decode()
            Validator.validate_injection(data_type=ValConsts.FMT_CREATION_TIME, value_to_validate=decrypted_creation_time)

            # Create data frame
            processes_ticket_data = {
                ProtoConsts.VERSION: version,
                ProtoConsts.CLIENT_ID: client_id,
                ProtoConsts.SERVER_ID: server_id,
                ProtoConsts.CREATION_TIME: decrypted_creation_time,
                ProtoConsts.AES_KEY: decrypted_aes_key,
                ProtoConsts.EXPIRATION_TIME: decrypted_expiration_time
            }
            # Log
            CustomFilter.filter_name = get_calling_method_name()
            msg = f"Decrypted ticket packet --> {processes_ticket_data}"
            self.logger.logger.debug(msg=msg)

            # For dev mode
            if self.debug_mode:
                print(write_with_color(msg=msg, color=Colors.CYAN))

            # Return the processed data
            return processes_ticket_data

        except Exception as e:
            raise CustomException(error_msg=f"Unable to process ticket packet.", exception=e)

    def __validate_symmetric_key_data(self, authenticator_data: dict, ticket_data: dict) -> bool:
        """Validates Client received unpacked and decrypted Symmetric Key data."""
        try:
            if ticket_data[ProtoConsts.SERVER_ID] != authenticator_data[ProtoConsts.SERVER_ID]:
                # TODO - verify with msg server id from ram
                # TODO - do something, maybe custom exception
                pass
            if ticket_data[ProtoConsts.CLIENT_ID] != authenticator_data[ProtoConsts.CLIENT_ID]:
                # TODO - do something, maybe custom exception
                pass
            # TODO - create custom error for expired ticket
            if is_expired(ticket_data[ProtoConsts.EXPIRATION_TIME]):
                # TODO - do something, maybe custom exception
                pass

            return True

        except Exception as e:
            raise CustomException(error_msg=f"Unable to validate symmetric key request data.", exception=e)

    def handle_symmetric_key_request(self, sck: CustomSocket, client_socket: socket, ram_template: dict,
                                     encryptor: Encryptor, protocol_handler: ProtocolHandler) -> bool:
        try:
            # Receive request
            symmetric_key_request = sck.receive_packet(sck=client_socket, logger=self.logger)
            request_code, unpacked_symmetric_key_request = protocol_handler.unpack_request(received_packet=symmetric_key_request,
                                                                                           formatter=server_request.copy(),
                                                                                           code=ProtoConsts.REQ_MSG_SERVER_AES_KEY,
                                                                                           deserialize=True)
            # Fetch and validate service AES key
            aes_key = ram_template[MsgConsts.RAM_AES_KEY]
            Validator.validate_injection(data_type=ValConsts.FMT_AES_KEY, value_to_validate=aes_key)

            # Process Authenticator packet
            authenticator = unpacked_symmetric_key_request[ProtoConsts.AUTHENTICATOR]
            authenticator_data = self.__process_authenticator_packet(authenticator=authenticator,
                                                                     service_aes_key=aes_key,
                                                                     encryptor=encryptor,
                                                                     protocol_handler=protocol_handler)
            # Process Ticket packet
            ticket = unpacked_symmetric_key_request[ProtoConsts.TICKET]
            ticket_data = self.__process_ticket_packet(ticket=ticket,
                                                       service_aes_key=aes_key,
                                                       encryptor=encryptor,
                                                       protocol_handler=protocol_handler)

            # Verify data
            if self.__validate_symmetric_key_data(authenticator_data=authenticator_data, ticket_data=ticket_data):

                # Return success
                # TODO - if success, insert needed data into services_pool.json
                packet_no_payload[ProtoConsts.CODE] = ProtoConsts.RES_AES_KEY_ACK
                packed_symmetric_key_ack = protocol_handler.pack_request(code=ProtoConsts.RES_AES_KEY_ACK,
                                                                         data=packet_no_payload,
                                                                         formatter=server_response.copy())
                sck.send_packet(sck=client_socket, packet=packed_symmetric_key_ack, logger=self.logger)
                return True
            else:
                # TODO - return some error
                pass

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle symmetric key request.", exception=e)