import sys
from struct import calcsize, unpack
from Utils.logger import Logger, CustomFilter
from Utils.utils import insert_data_to_template, create_json_file, write_with_color, Colors
from Utils.custom_exception_handler import CustomException, get_calling_method_name
from Utils.validator import Validator, ValConsts
from Socket.custom_socket import CustomSocket, socket
from Protocol_Handler.protocol_constants import ProtoConsts
from Protocol_Handler.protocol_templates import code_to_payload_template, server_request, server_response
from Protocol_Handler.protocol_handler import ProtocolHandler
from Protocol_Handler.protocol_utils import insert_unpacked_packet_content, deserialize_packet, get_bytes_value_index
from Client.client_constants import file_db_servers_template, CConsts


class ServicesHandler:
    """Handles all the Client Services List request logic."""

    def __init__(self, debug_mode: bool) -> None:
        self.debug_mode = debug_mode
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)

    def __insert_services_list_to_file_db(self, msg_servers_list: list) -> None:
        """Inserts the parsed services list into the Client file DB."""
        try:
            for index, server in enumerate(msg_servers_list):

                # Create services formatter for each service
                file_db = file_db_servers_template.copy()

                if isinstance(server[ProtoConsts.SERVER_ID], bytes):
                    server[ProtoConsts.SERVER_ID] = Validator.validate_injection(data_type=ValConsts.FMT_ID,
                                                                                 value_to_validate=server[ProtoConsts.SERVER_ID])
                # Insert parsed service into new formatter template and override list object
                file_db.update(insert_data_to_template(data=server, formatter=file_db))
                msg_servers_list[index] = file_db

            # Insert updated services to file DB
            create_json_file(file_path=CConsts.SERVICES_FILE_PATH, data=msg_servers_list)

            # Log
            CustomFilter.filter_name = get_calling_method_name()
            self.logger.logger.debug(f"Inserted parsed services list to '{CConsts.SERVICES_FILE_PATH}' successfully.")

        except Exception as e:
            raise CustomException(error_msg=f"Unable to insert services list into file DB {CConsts.SERVICES_FILE_PATH}.",
                                  exception=e)

    def __parse_services_list_data(self, unpacked_data: bytes, msg_servers_list: list, protocol_handler: ProtocolHandler) -> None:
        """Extracts all the services from the unpacked services packet."""
        try:
            # Create server list formatter template and calculate sizes
            server_data_formatter = code_to_payload_template[ProtoConsts.RES_MSG_SERVERS_LIST].copy()
            packed_server_fmt = protocol_handler.generate_packet_fmt(raw_packet=server_data_formatter)
            packed_server_size = calcsize(packed_server_fmt)

            # Loop over the packed packet and handle each server separately
            for i in range(0, unpacked_data[ProtoConsts.PAYLOAD_SIZE], packed_server_size):
                server = unpacked_data[ProtoConsts.SERVERS_LIST][i:i + packed_server_size]
                unpacked_server = unpack(packed_server_fmt, server)

                # Deserialize server raw data
                raw_data = deserialize_packet(packet=unpacked_server,
                                              index_to_pass=get_bytes_value_index(code=ProtoConsts.PKT_UNPACKED_SERVER))
                server_data = protocol_handler.build_packet_format(code=ProtoConsts.RES_MSG_SERVERS_LIST,
                                                                   formatter=server_data_formatter.copy())

                server_data.update(insert_unpacked_packet_content(data_format=server_data,
                                                                  unpacked_packet=raw_data))

                server_data.update(protocol_handler.deserialize_serialize_ipv4(formatter=server_data_formatter,
                                                                               data=server_data,
                                                                               mode=ProtoConsts.DESERIALIZE))
                msg_servers_list.append(server_data)

            # Insert servers to file DB
            self.__insert_services_list_to_file_db(msg_servers_list=msg_servers_list)

            # Log
            CustomFilter.filter_name = get_calling_method_name()
            msg = f"Parsed services list: {msg_servers_list}"
            self.logger.logger.debug(msg=msg)

            # For dev mode:
            if self.debug_mode:
                print(write_with_color(msg=msg, color=Colors.CYAN))

        except Exception as e:
            raise CustomException(error_msg=f"Unable to parse servers list.", exception=e)

    def handle_services_list_request(self, sck: CustomSocket, client_socket: socket, ram_template: dict,
                                     msg_servers_list: list, protocol_handler: ProtocolHandler) -> None:
        """Sends the services list request to the AS."""
        try:
            # Fetch and validate data
            client_id = ram_template[CConsts.RAM_CLIENT_ID]
            Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=client_id)

            # Create packet data frame
            data = {
                ProtoConsts.CLIENT_ID: client_id,
                ProtoConsts.VERSION: ProtoConsts.SERVER_VERSION,
                ProtoConsts.CODE: ProtoConsts.REQ_MSG_SERVERS_LIST,
                ProtoConsts.PAYLOAD_SIZE: 0
            }
            # Pack request
            packed_services_list_request = protocol_handler.pack_request(code=ProtoConsts.REQ_MSG_SERVERS_LIST,
                                                                         data=data,
                                                                         formatter=server_request.copy())
            # Send request and receive response
            servers_list_response = sck.send_recv_packet(sck=client_socket, packet=packed_services_list_request,
                                                         buffer_size=ProtoConsts.SERVER_LIST_BUFFER_SIZE,
                                                         logger=self.logger,
                                                         response=True)
            # Unpack and deserialize packet data
            response_code, unpacked_servers_list_response = protocol_handler.unpack_request(received_packet=servers_list_response,
                                                                                            formatter=server_response.copy(),
                                                                                            deserialize=True)
            # In case there aren't any services registered, also not the default one
            if response_code == ProtoConsts.RES_GENERAL_ERROR:
                print(write_with_color(msg=f"{ProtoConsts.CONSOLE_ERROR} Chat rooms is not available at this time.",
                                       color=Colors.RED))
                client_socket.close()
                sys.exit(ProtoConsts.STATUS_ERROR_CODE)

            # Log
            CustomFilter.filter_name = get_calling_method_name()
            msg = f"Received Response --> Code: {response_code}, Data: {unpacked_servers_list_response}"
            self.logger.logger.debug(msg=msg)

            # For dev mode
            if self.debug_mode:
                print(write_with_color(msg=msg, color=Colors.MAGENTA))

            # Parse servers list data
            self.__parse_services_list_data(unpacked_data=unpacked_servers_list_response,
                                            msg_servers_list=msg_servers_list,
                                            protocol_handler=protocol_handler)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle services list request.", exception=e)