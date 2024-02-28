from Utils.utils import write_with_color, Colors, insert_data_to_json_db
from Utils.logger import Logger, CustomFilter
from Utils.validator import Validator, ValConsts
from Utils.encryptor import Encryptor
from Utils.custom_exception_handler import CustomException, get_calling_method_name
from Socket.custom_socket import CustomSocket, socket
from Protocol_Handler.protocol_utils import ProtoConsts, server_request, server_response
from Protocol_Handler.protocol_handler import ProtocolHandler
from Server.MsgServer.msg_server_constants import MsgConsts


class RegistrationHandler:
    """Handles Msg Server registration request logic."""

    def __init__(self, debug_mode: bool) -> None:
        self.debug_mode = debug_mode
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)

    def __process_registration_response(self, client_socket: socket, response_code: int, service_name: str,
                                        ram_template: dict, unpacked_register_response: dict) -> bool:
        """Processes the AS registration response, returns True for success, False otherwise."""
        try:
            CustomFilter.filter_name = get_calling_method_name()

            # Register success
            if response_code == ProtoConsts.RES_REGISTER_SUCCESS:

                service_id = unpacked_register_response[ProtoConsts.CLIENT_ID]
                ram_template[MsgConsts.RAM_SERVICE_ID] = service_id
                if isinstance(service_id, bytes):
                    ram_template[MsgConsts.RAM_SERVICE_ID_HEX] = Validator.validate_injection(data_type=ValConsts.FMT_ID,
                                                                                              value_to_validate=service_id)
                # Update the new DNS mapping ip and port
                ip_address, port = client_socket.getsockname()

                ram_template[MsgConsts.RAM_IP_ADDRESS] = ip_address
                ram_template[MsgConsts.RAM_PORT] = port
                ram_template[MsgConsts.RAM_IS_REGISTERED] = True

                # Log
                msg = "Registration successful."
                self.logger.logger.info(msg=msg)
                print(write_with_color(msg=f"{ProtoConsts.CONSOLE_ACK} {msg}",
                                       color=Colors.GREEN))

                # Update services JSON db
                insert_data_to_json_db(file_path=MsgConsts.SERVICE_POOL_FILE_NAME,
                                       data=ram_template,
                                       pivot_key=MsgConsts.RAM_SERVICE_NAME,
                                       pivot_value=service_name)
                return True

            # Register failure
            elif response_code == ProtoConsts.RES_REGISTER_FAILED:
                msg = "Registration failure."
                self.logger.logger.info(msg=msg)
                print(write_with_color(msg=f"{ProtoConsts.CONSOLE_FAIL} {msg}",
                                       color=Colors.RED))
                ram_template[MsgConsts.RAM_IS_REGISTERED] = False
                return False

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle registration success.", exception=e)

    def handle_registration_request(self, sck: CustomSocket, client_socket: socket, ram_template: dict,
                                    service_name: str, encryptor: Encryptor, protocol_handler: ProtocolHandler) -> bool:
        """Sends registration request to the AS."""
        try:
            # Create service AES key and update RAM DB
            msg_server_aes_key = encryptor.generate_bytes_stream(size=ProtoConsts.SIZE_AES_KEY)
            Validator.validate_injection(data_type=ValConsts.FMT_AES_KEY, value_to_validate=msg_server_aes_key)
            # TODO - if aes key validate error, raise exception or something, catch validator exception and exit
            ram_template[MsgConsts.RAM_AES_KEY] = msg_server_aes_key
            ram_template[MsgConsts.RAM_AES_KEY_HEX] = msg_server_aes_key.hex()

            # Create packet data frame
            data = {
                ProtoConsts.CLIENT_ID: None,
                ProtoConsts.VERSION: ProtoConsts.SERVER_VERSION,
                ProtoConsts.CODE: ProtoConsts.REQ_SERVER_REG,
                ProtoConsts.PAYLOAD_SIZE: ProtoConsts.SIZE_SERVER_NAME + ProtoConsts.SIZE_AES_KEY,
                ProtoConsts.NAME: service_name,
                ProtoConsts.AES_KEY: msg_server_aes_key
            }

            # Pack and send register request
            packed_register_request = protocol_handler.pack_request(code=ProtoConsts.REQ_SERVER_REG,
                                                                    data=data,
                                                                    formatter=server_request.copy())
            sck.send_packet(sck=client_socket, packet=packed_register_request, logger=self.logger)

            # Receive register response, unpack and deserialize packet data
            register_response = sck.receive_packet(sck=client_socket, logger=self.logger)
            response_code, unpacked_register_response = protocol_handler.unpack_request(received_packet=register_response,
                                                                                        formatter=server_response.copy(),
                                                                                        deserialize=True)
            # Log
            CustomFilter.filter_name = get_calling_method_name()
            msg = f"Received Response --> Code: {response_code}, Data: {unpacked_register_response}"
            self.logger.logger.debug(msg=msg)

            # For dev mode
            if self.debug_mode:
                print(write_with_color(msg=msg, color=Colors.MAGENTA))

            # Process registration response
            return self.__process_registration_response(client_socket=client_socket,
                                                        response_code=response_code,
                                                        service_name=service_name,
                                                        ram_template=ram_template,
                                                        unpacked_register_response=unpacked_register_response)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle registration request.", exception=e)

        finally:
            # Close socket to AS
            client_socket.close()