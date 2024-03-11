from typing import Union
from Utils import utils
from Utils.logger import Logger, CustomFilter
from Utils.validator import Validator, ValConsts
from Utils.encryptor import Encryptor
from Utils.custom_exception_handler import CustomException, get_calling_method_name
from Socket.custom_socket import CustomSocket, socket
from Protocol_Handler.protocol_constants import ProtoConsts
from Protocol_Handler.protocol_templates import server_request, server_response
from Protocol_Handler.protocol_handler import ProtocolHandler
from Client.client_input import ClientInput
from Client.client_constants import CConsts
from Client.client_chat_room_handler import ChatRoomHandler


class KeyTicketHandler:
    """Handles all the TGS Encrypted Key and Ticket request logic."""

    def __init__(self, debug_mode: bool) -> None:
        self.debug_mode = debug_mode
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)
        self.chat_room_handler = ChatRoomHandler(debug_mode=debug_mode)

    def __get_service_object(self, msg_servers_list: list) -> Union[dict, None]:
        """Returns the wanted service entry from the Client DB."""
        try:
            # Services file is empty
            if not msg_servers_list:
                return None

            # get and return the wanted service object
            server_object = ClientInput.get_service_name(services_list=msg_servers_list)

            # Log
            CustomFilter.filter_name = get_calling_method_name()
            msg = f"Selected service object --> {server_object}"
            self.logger.logger.debug(msg=msg)

            # For dev mode:
            if self.debug_mode:
                print(utils.write_with_color(msg=msg, color=utils.Colors.CYAN))

            return server_object

        except Exception as e:
            raise CustomException(error_msg=f"Unable to get client wanted service.", exception=e)

    def handle_aes_key_request(self, sck: CustomSocket, client_socket: socket, ram_template: dict,
                               msg_servers_list: list, encryptor: Encryptor, protocol_handler: ProtocolHandler) -> None:
        """Sends AES key request to the TGS."""
        try:
            # Generate random nonce value and validate it
            client_nonce = utils.generate_nonce()
            Validator.validate_injection(data_type=ValConsts.FMT_NONCE, value_to_validate=client_nonce)
            ram_template[CConsts.RAM_NONCE] = client_nonce

            # Validate client id
            client_id = ram_template[CConsts.RAM_CLIENT_ID]
            Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=client_id)

            # Get client wanted service
            service_object = self.__get_service_object(msg_servers_list=msg_servers_list)
            if not service_object:
                print(utils.write_with_color(msg=f"{ProtoConsts.CONSOLE_ERROR} There aren't any registered services, "
                                                 f"please get available services.", color=utils.Colors.RED))
                return

            # Validate return service id
            server_id = service_object[CConsts.RAM_SERVER_ID]
            if not isinstance(server_id, bytes):
                server_id = Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=server_id)

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
            packed_aes_request = protocol_handler.pack_request(code=ProtoConsts.REQ_AES_KEY,
                                                               data=data,
                                                               formatter=server_request.copy())
            # Send request and receive response
            encrypted_key_response = sck.send_recv_packet(sck=client_socket, packet=packed_aes_request,
                                                          logger=self.logger, response=True)
            # Unpack and deserialize packet data
            response_code, unpacked_aes_key_response = protocol_handler.unpack_request(received_packet=encrypted_key_response,
                                                                                       formatter=server_response.copy(),
                                                                                       code=ProtoConsts.RES_ENCRYPTED_AES_KEY,
                                                                                       deserialize=True)
            # For dev mode
            if self.debug_mode:
                print(utils.write_with_color(
                    msg=f"Received Response --> Code: {response_code}, Data: {unpacked_aes_key_response}",
                    color=utils.Colors.MAGENTA))

            if response_code == ProtoConsts.RES_GENERAL_ERROR:
                print(utils.write_with_color(msg=f"{ProtoConsts.CONSOLE_FAIL} {CConsts.SERVER_GENERAL_ERROR}",
                                             color=utils.Colors.RED))
                return

            # Connect to the requested service
            self.chat_room_handler.connect_to_service(sck=sck, client_socket=client_socket,
                                                      ram_template=ram_template,
                                                      server_id=server_id,
                                                      unpacked_aes_key_response=unpacked_aes_key_response,
                                                      encryptor=encryptor,
                                                      protocol_handler=protocol_handler)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle encrypted key request.", exception=e)