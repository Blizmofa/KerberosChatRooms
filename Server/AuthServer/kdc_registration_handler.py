from Utils import utils
from Utils.logger import Logger, CustomFilter
from Utils.custom_exception_handler import CustomException, get_calling_method_name
from Utils.validator import Validator, ValConsts
from Utils.encryptor import Encryptor
from Socket.custom_socket import socket
from Protocol_Handler.protocol_handler import ProtocolHandler
from Protocol_Handler.protocol_utils import packet_no_payload, packet_register_success, ProtoConsts as ProtoConsts
from Server.AuthServer.auth_server_constants import file_db_clients_template, file_db_servers_template, AuthConsts


class RegistrationHandler:
    """Handles all the AS registration requests logic."""

    def __init__(self, debug_mode: bool) -> None:
        self.debug_mode = debug_mode
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)

    def register_client(self, data: dict, client_ram_template: dict, server_response: dict,
                        encryptor: Encryptor, protocol_handler: ProtocolHandler) -> bytes:
        """Registers new clients if not already registered according to the server DB."""
        try:
            # Not registered client case
            if not client_ram_template[AuthConsts.RAM_IS_REGISTERED]:

                # Set Logger custom filter
                CustomFilter.filter_name = data[ProtoConsts.NAME]

                # Insert client data into RAM DB
                client_id = utils.generate_uuid()
                Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=client_id)
                client_password_hash = encryptor.hash_password(password=data[ProtoConsts.PASSWORD])
                data[AuthConsts.RAM_CLIENT_ID_HEX] = client_id.hex()
                data[AuthConsts.RAM_PASSWORD_HASH] = client_password_hash
                data[AuthConsts.RAM_PASSWORD_HASH_HEX] = client_password_hash.hex()
                client_ram_template.update(utils.insert_data_to_ram_db(ram_template=client_ram_template, data=data))

                # Insert client data into file DB
                utils.insert_data_to_file_db(file_path=AuthConsts.CLIENTS_FILE_PATH,
                                             data=client_ram_template,
                                             formatter=file_db_clients_template.copy())
                # Return success
                return self.__handle_register_success(data=data,
                                                      uuid=client_id,
                                                      ram_template=client_ram_template,
                                                      server_response=server_response,
                                                      protocol_handler=protocol_handler)

            # Already Registered case
            else:
                return self.__handle_register_failed(data=data,
                                                     server_response=server_response,
                                                     protocol_handler=protocol_handler)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to register client '{data[ProtoConsts.NAME]}'.", exception=e)

    def register_service(self, data: dict, server_ram_template: dict, sck: socket, server_response: dict,
                         msg_server_list: list, protocol_handler: ProtocolHandler) -> bytes:
        """Registers new services if not already registered according to the server DB."""
        try:
            # Not registered server case
            if "name" in data:
                # if not utils.search_value_in_txt_file(value=data[ProtoConsts.NAME],
                #                                       file_path=AuthConsts.SERVICES_FILE_PATH):

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
                msg_server_list.append({
                    ProtoConsts.SERVER_ID: server_id,
                    ProtoConsts.SERVER_NAME: data[ProtoConsts.NAME],
                    ProtoConsts.AES_KEY: data[ProtoConsts.AES_KEY],
                    ProtoConsts.SERVER_IP: server_ip,
                    ProtoConsts.SERVER_PORT: server_port
                })

                # Insert new server to file DB
                file_data = utils.insert_data_to_template(data=server_ram_template,
                                                          formatter=file_db_servers_template.copy())
                utils.append_data_to_json(file_path=AuthConsts.SERVICES_FILE_PATH, data=file_data)

                # Return success
                return self.__handle_register_success(data=data,
                                                      uuid=server_id,
                                                      ram_template=server_ram_template,
                                                      server_response=server_response,
                                                      protocol_handler=protocol_handler)
            # Already Registered case
            else:
                return self.__handle_register_failed(data=data,
                                                     server_response=server_response,
                                                     protocol_handler=protocol_handler)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to register server.", exception=e)

    def __handle_register_success(self, data: dict, uuid: bytes, ram_template: dict,
                                  server_response: dict, protocol_handler: ProtocolHandler) -> bytes:
        """Private method to packs response in case of registration success."""
        try:
            ram_template[AuthConsts.RAM_IS_REGISTERED] = True
            # Log output
            CustomFilter.filter_name = get_calling_method_name()
            msg = f"'{data[ProtoConsts.NAME]}' has been registered successfully."
            self.logger.logger.info(msg=msg)

            # For dev mode
            if self.debug_mode:
                print(utils.write_with_color(msg=f"{ProtoConsts.CONSOLE_ACK} {msg}", color=utils.Colors.GREEN))

            # Pack response
            packet_register_success[ProtoConsts.CLIENT_ID] = uuid
            return protocol_handler.pack_request(code=ProtoConsts.RES_REGISTER_SUCCESS,
                                                 data=packet_register_success,
                                                 formatter=server_response.copy())
        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle register success response.", exception=e)

    def __handle_register_failed(self, data: dict, server_response: dict, protocol_handler: ProtocolHandler) -> bytes:
        """Private method to packs response in case of registration failure."""
        try:
            CustomFilter.filter_name = get_calling_method_name()
            msg = f"'{data[ProtoConsts.NAME]}' is already registered."
            self.logger.logger.info(msg=f"{ProtoConsts.CONSOLE_FAIL} {msg}")

            # For dev mode
            if self.debug_mode:
                print(utils.write_with_color(msg=msg, color=utils.Colors.RED))

            # Pack response
            packet_no_payload[ProtoConsts.CODE] = ProtoConsts.RES_REGISTER_FAILED
            return protocol_handler.pack_request(code=ProtoConsts.RES_REGISTER_FAILED,
                                                 data=packet_no_payload,
                                                 formatter=server_response.copy())
        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle register failed response.", exception=e)