from Utils.utils import write_with_color, Colors, parse_info_file
from Utils.validator import Validator, ValConsts
from Utils.custom_exception_handler import CustomException, get_calling_method_name
from Utils.logger import Logger, CustomFilter
from Server.MsgServer.msg_server_constants import MsgConsts
from Protocol_Handler.protocol_utils import ProtoConsts, code_to_payload_template
from Protocol_Handler.protocol_handler import ProtocolHandler


class ServicesHandler:
    """Handles all the KDC Services List request logic."""

    def __init__(self, debug_mode: bool) -> None:
        self.debug_mode = debug_mode
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)

    def __parse_msg_info_file(self) -> tuple:
        """Private method that Parses the default service data from msg.info file."""
        try:
            # Parse default service data
            ip_and_port = parse_info_file(file_path=MsgConsts.MSG_FILE_NAME,
                                          target_line_number=MsgConsts.LINE_IP_PORT)
            server_id = parse_info_file(file_path=MsgConsts.MSG_FILE_NAME, target_line_number=MsgConsts.LINE_ID)
            server_name = parse_info_file(file_path=MsgConsts.MSG_FILE_NAME, target_line_number=MsgConsts.LINE_NAME)
            server_aes_key = parse_info_file(file_path=MsgConsts.MSG_FILE_NAME, target_line_number=MsgConsts.LINE_AES_KEY)

            CustomFilter.filter_name = get_calling_method_name()
            self.logger.logger.debug(f"Parsed {MsgConsts.MSG_FILE_NAME} successfully.")

            # Return as a Tuple
            return ip_and_port, server_name, server_id, server_aes_key

        except Exception as e:
            raise CustomException(error_msg=f"Unable to parse {MsgConsts.MSG_FILE_NAME}.", exception=e)

    def get_default_service_data(self, msg_server_list: list) -> None:
        """Inserts the default registered service data to the services list."""
        try:
            # Parse and validate default registered service file
            default_service_data = self.__parse_msg_info_file()

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
            msg_server_list.append({
                ProtoConsts.SERVER_ID: server_id,
                ProtoConsts.SERVER_NAME: server_name,
                ProtoConsts.AES_KEY: server_aes_key,
                ProtoConsts.SERVER_IP: server_ip,
                ProtoConsts.SERVER_PORT: server_port
            })

            CustomFilter.filter_name = get_calling_method_name()
            self.logger.logger.debug(f"Retrieved default service data successfully.")

        except Exception as e:
            raise CustomException(error_msg=f"Unable to get default service data.", exception=e)

    def get_services_packed_list_data(self, msg_server_list: list, protocol_handler: ProtocolHandler) -> bytes:
        """Returns the services list packed packet."""
        try:
            # Serialize services list
            for server in msg_server_list:
                server.update(protocol_handler.serialize_packet_value(
                    formatter=code_to_payload_template[ProtoConsts.RES_MSG_SERVERS_LIST],
                    data=server,
                    mode=ProtoConsts.SERIALIZE))

            # Log
            CustomFilter.filter_name = get_calling_method_name()
            msg = f"Parsed services list --> {msg_server_list}"
            self.logger.logger.debug(msg=msg)

            # For dev mode
            if self.debug_mode:
                print(write_with_color(msg=msg,
                                       color=Colors.CYAN))

            # Pack servers list
            service_list_formatter = code_to_payload_template[ProtoConsts.RES_MSG_SERVERS_LIST].copy()
            packed = b''
            for service in msg_server_list:
                packed += protocol_handler.pack_request(code=ProtoConsts.RES_MSG_SERVERS_LIST,
                                                        data=service,
                                                        formatter=service_list_formatter)
            return packed

        except Exception as e:
            raise CustomException(error_msg=f"Unable to get services list packed data.", exception=e)