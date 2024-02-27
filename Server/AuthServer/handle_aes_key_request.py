from typing import Union
from Utils import utils
from Utils.validator import Validator, ValConsts
from Utils.logger import Logger, CustomFilter
from Utils.custom_exception_handler import CustomException, get_calling_method_name
from Utils.encryptor import Encryptor
from Protocol_Handler.protocol_utils import ProtoConsts, code_to_payload_template
from Protocol_Handler.protocol_handler import ProtocolHandler
from Server.AuthServer.auth_server_constants import AuthConsts
from Server.AuthServer.handle_services_list_request import ServicesHandler
from Server.MsgServer.msg_server_constants import MsgConsts


class KeyTicketHandler:
    """Handles all the TGS Encrypted Key and Ticket request logic."""

    def __init__(self, debug_mode: bool) -> None:
        self.debug_mode = debug_mode
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)

    def get_service_object(self, service_id: Union[str, bytes], msg_server_list: list,
                           services_handler: ServicesHandler) -> dict:
        """Returns the wanted service entry from the Client DB."""
        try:
            # Get from JSON DB
            if not msg_server_list and utils.is_exists(path_to_check=AuthConsts.SERVICES_FILE_PATH):
                service_id = Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=service_id)
                service_object = utils.fetch_entry_from_json_db(file_path=AuthConsts.SERVICES_FILE_PATH,
                                                                pivot_key=AuthConsts.RAM_SERVER_ID_HEX,
                                                                pivot_value=service_id)
                if service_object:
                    msg_server_list.append(service_object)

            # Get default service
            if not msg_server_list and utils.is_exists(path_to_check=MsgConsts.MSG_FILE_NAME):
                services_handler.get_default_service_data(msg_server_list=msg_server_list)

            # Get and return the wanted service object
            service_object = utils.fetch_value_from_ram_db(data=msg_server_list,
                                                           pivot_key=AuthConsts.RAM_SERVER_ID,
                                                           pivot_value=service_id)
            # Log
            CustomFilter.filter_name = get_calling_method_name()
            msg = f"Selected service object --> {service_object}"
            self.logger.logger.debug(msg=msg)

            # For dev mode:
            if self.debug_mode:
                print(utils.write_with_color(msg=msg, color=utils.Colors.CYAN))

            return service_object

        except Exception as e:
            raise CustomException(error_msg=f"Unable to get client wanted service.", exception=e)

    def pack_encrypted_key_packet(self, client_ram_template: dict, client_nonce: bytes, service_object: dict,
                                  encryptor: Encryptor, protocol_handler: ProtocolHandler) -> bytes:
        """Returns the packed Encrypted Key packet."""
        try:
            # Get client password hash
            password_hash = client_ram_template[AuthConsts.RAM_PASSWORD_HASH]

            # Fetch the selected service AES key
            client_aes_key = service_object[AuthConsts.RAM_AES_KEY]

            # Encrypt packet content
            encrypted_key_iv = encryptor.generate_bytes_stream(size=ProtoConsts.SIZE_IV)
            encrypted_aes_key = encryptor.encrypt(value=client_aes_key,
                                                  encryption_key=password_hash,
                                                  iv=encrypted_key_iv)
            encrypted_nonce = encryptor.encrypt(value=client_nonce,
                                                encryption_key=password_hash,
                                                iv=encrypted_key_iv)
            # Create packet data frame
            encrypted_key_data = {
                ProtoConsts.ENCRYPTED_KEY_IV: encrypted_key_iv,
                ProtoConsts.NONCE: encrypted_nonce,
                ProtoConsts.AES_KEY: encrypted_aes_key
            }

            CustomFilter.filter_name = get_calling_method_name()
            self.logger.logger.debug(f"Packed Encrypted Key packet successfully.")

            # Pack Encrypted key packet
            return protocol_handler.pack_request(code=ProtoConsts.PKT_ENCRYPTED_KEY,
                                                 data=encrypted_key_data,
                                                 formatter=code_to_payload_template[ProtoConsts.PKT_ENCRYPTED_KEY])
        except Exception as e:
            raise CustomException(error_msg=f"Unable to pack encrypted key packet.", exception=e)

    def pack_ticket_packet(self, client_id: bytes, server_id: bytes, service_aes_key: bytes,
                           encryptor: Encryptor, protocol_handler: ProtocolHandler) -> bytes:
        """Returns the packed Ticket packet."""
        try:
            # Generate packet data
            ticket_iv = encryptor.generate_bytes_stream()
            creation_time = utils.time_now()
            expiration_time = utils.expiration_time(days_buffer=ProtoConsts.DEF_EXPIRATION_TIME_LENGTH)

            # Encrypt packet content
            encrypted_creation_time = encryptor.encrypt(value=creation_time,
                                                        encryption_key=service_aes_key,
                                                        iv=ticket_iv)
            encrypted_ticket_aes_key = encryptor.encrypt(value=service_aes_key,
                                                         encryption_key=service_aes_key,
                                                         iv=ticket_iv)
            encrypted_ticket_expiration_time = encryptor.encrypt(value=expiration_time,
                                                                 encryption_key=service_aes_key,
                                                                 iv=ticket_iv)
            # Create packet data frame
            ticket_data = {
                ProtoConsts.VERSION: ProtoConsts.SERVER_VERSION,
                ProtoConsts.CLIENT_ID: client_id,
                ProtoConsts.SERVER_ID: server_id,
                ProtoConsts.CREATION_TIME: encrypted_creation_time,
                ProtoConsts.TICKET_IV: ticket_iv,
                ProtoConsts.AES_KEY: encrypted_ticket_aes_key,
                ProtoConsts.EXPIRATION_TIME: encrypted_ticket_expiration_time
            }

            CustomFilter.filter_name = get_calling_method_name()
            self.logger.logger.debug(f"Packed Ticket packet successfully.")

            # Pack Ticket packet
            return protocol_handler.pack_request(code=ProtoConsts.PKT_TICKET,
                                                 data=ticket_data,
                                                 formatter=code_to_payload_template[ProtoConsts.PKT_TICKET])

        except Exception as e:
            raise CustomException(error_msg=f"Unable to pack ticket packet.", exception=e)