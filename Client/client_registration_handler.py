from Utils.utils import insert_value_into_info_file, write_with_color, Colors
from Utils.logger import Logger, CustomFilter
from Utils.custom_exception_handler import CustomException, get_calling_method_name
from Utils.validator import Validator, ValConsts
from Socket.custom_socket import CustomSocket, socket
from Protocol_Handler.protocol_constants import ProtoConsts
from Protocol_Handler.protocol_templates import server_request, server_response
from Protocol_Handler.protocol_handler import ProtocolHandler
from Client.client_constants import CConsts


class RegistrationHandler:
    """Handles Client registration request logic."""

    def __init__(self, debug_mode: bool) -> None:
        self.debug_mode = debug_mode
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)

    def __process_register_response(self, response_code: int, data: dict, ram_template: dict) -> None:
        """Processes the AS registration response and update RAM template accordingly."""
        try:
            CustomFilter.filter_name = get_calling_method_name()

            # Register success
            if response_code == ProtoConsts.RES_REGISTER_SUCCESS:

                # Validate received id
                client_id = data[ProtoConsts.CLIENT_ID]
                Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=client_id)

                # Insert received client id into me.info file and RAM DB
                ram_template[CConsts.RAM_CLIENT_ID] = client_id
                ram_template[CConsts.RAM_CLIENT_ID_HEX] = client_id.hex()
                insert_value_into_info_file(value=client_id.hex(),
                                            target_line=CConsts.CLIENT_ID_LINE,
                                            file_path=CConsts.CLIENT_FILE_NAME,
                                            max_lines=CConsts.CLIENT_FILE_MAX_LINES)
                # Log
                msg = "Registration successful."
                self.logger.logger.info(msg=msg)
                print(write_with_color(msg=f"{ProtoConsts.CONSOLE_ACK} {msg}",
                                       color=Colors.GREEN))
                ram_template[CConsts.RAM_IS_REGISTERED] = True

            # Register failure
            elif response_code == ProtoConsts.RES_REGISTER_FAILED:
                msg = "Registration failure."
                self.logger.logger.info(msg=msg)
                print(write_with_color(msg=f"{ProtoConsts.CONSOLE_FAIL} {msg}",
                                       color=Colors.RED))
                ram_template[CConsts.RAM_IS_REGISTERED] = False

        except Exception as e:
            raise CustomException(error_msg=f"Unable to process register response.", exception=e)

    def handle_registration_request(self, sck: CustomSocket, client_socket: socket, ram_template: dict,
                                    protocol_handler: ProtocolHandler) -> None:
        """Sends registration request to the AS."""
        try:
            # Validate data
            client_id = ram_template[CConsts.RAM_CLIENT_ID]

            # If not registered client id is None
            if client_id:
                Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=client_id)

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
            packed_register_request = protocol_handler.pack_request(code=ProtoConsts.REQ_CLIENT_REG,
                                                                    data=data,
                                                                    formatter=server_request.copy())
            # Send request and receive response
            register_response = sck.send_recv_packet(sck=client_socket, packet=packed_register_request,
                                                     logger=self.logger, response=True)
            # Unpack and deserialize packet data
            response_code, unpacked_register_response = protocol_handler.unpack_request(received_packet=register_response,
                                                                                        formatter=server_response.copy(),
                                                                                        deserialize=True)
            # For dev mode
            if self.debug_mode:
                print(write_with_color(msg=f"Sent Request --> Code: {ProtoConsts.REQ_CLIENT_REG}, Data: {data}",
                                       color=Colors.MAGENTA))
                print(write_with_color(msg=f"Received Response --> Code: {response_code}, "
                                           f"Data: {unpacked_register_response}",
                                       color=Colors.MAGENTA))
            # Process response
            self.__process_register_response(response_code=response_code,
                                             data=unpacked_register_response,
                                             ram_template=ram_template)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle registration request for client "
                                            f"'{ram_template[CConsts.RAM_USERNAME]}'.", exception=e)