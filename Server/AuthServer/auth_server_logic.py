from Utils.logger import Logger
from Utils import utils
from Socket.custom_socket import CustomSocket, socket
from Utils.custom_exception_handler import CustomException
from Protocol_Handler.protocol_handler import ProtocolHandler
from Protocol_Handler.protocol_utils import ProtocolConstants, server_request, server_response
from Server.AuthServer.auth_server_constants import AuthServerConstants
from Utils.encryptor import Encryptor


class AuthServerLogic:
    """AuthServerLogic is an auxiliary class to handle all Auth Server protocol requirements."""

    def __init__(self, debug_mode: bool) -> None:
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)

        self.protocol_handler = ProtocolHandler(debug_mode=debug_mode)
        self.encryptor = Encryptor(debug_mode=debug_mode)

    def __register_client(self, data: dict, client_ram_template: dict) -> bytes:
        try:
            # Not registered client case
            if not utils.search_value_in_file(value=data[AuthServerConstants.CLIENT_NAME],
                                              file_path=AuthServerConstants.CLIENTS_FILE_PATH):
                client_id = utils.generate_uuid()
                client_ram_template[AuthServerConstants.ID] = utils.convert_bytes_or_hex(data=client_id, mode="hex")
                client_ram_template[AuthServerConstants.PASSWORD_HASH] = self.encryptor.hash_password(
                    data["password"])

                # Insert Client data into DBs
                utils.insert_data_to_ram_db(ram_template=client_ram_template, data=data)
                utils.insert_data_to_file(file_path=AuthServerConstants.CLIENTS_FILE_PATH, data=client_ram_template)

                # Pack response
                data = {"version": 24, "code": 1600, "payload_size": ProtocolConstants.SIZE_CLIENT_ID,
                        "client_id": client_id}
                return self.protocol_handler.pack_request(code=1600, data=data, formatter=server_response)

            # Already Registered case
            else:
                # Pack response
                data = {"version": 24, "code": 1601, "payload_size": 0}
                return self.protocol_handler.pack_request(code=1601, data=data, formatter=server_response)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to register client.", exception=e)

    def __register_server(self, data: dict, server_ram_template: dict) -> bytes:
        try:
            # Not registered server case
            if not utils.search_value_in_file(value=data[AuthServerConstants.CLIENT_NAME],
                                              file_path=AuthServerConstants.SERVERS_FILE_PATH):
                # Generate server id
                server_id = utils.generate_uuid()
                server_ram_template[AuthServerConstants.ID] = utils.convert_bytes_or_hex(data=server_id, mode="hex")

                # TODO - insert to servers list

                # Insert Server data into DBs
                utils.insert_data_to_ram_db(ram_template=server_ram_template, data=data)
                utils.insert_data_to_file(file_path=AuthServerConstants.SERVERS_FILE_PATH, data=server_ram_template)

                # Pack response
                data = {"version": 24, "code": 1600, "payload_size": ProtocolConstants.SIZE_CLIENT_ID,
                        "server_id": server_id}
                return self.protocol_handler.pack_request(code=1600, data=data, formatter=server_response)

            # Already Registered case
            else:
                # Pack response
                data = {"version": 24, "code": 1601, "payload_size": 0}
                return self.protocol_handler.pack_request(code=1601, data=data, formatter=server_response)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to register server.", exception=e)

    def handle_registration_request(self, server_socket: CustomSocket, client_socket: socket,
                                    client_ram_template: dict, server_ram_template: dict) -> None:
        try:

            # Receive registration requests from client and msg servers
            register_request = server_socket.receive_packet(sck=client_socket, logger=self.logger)
            request_code, unpacked = self.protocol_handler.unpack_request(received_packet=register_request,
                                                                          formatter=server_request,
                                                                          deserialize=True)
            # TODO - refactor into one method
            # Handle clients requests
            if request_code == ProtocolConstants.REQ_CLIENT_REG:
                register_response = self.__register_client(unpacked, client_ram_template)

            # Handle servers requests
            elif request_code == ProtocolConstants.REQ_SERVER_REG:
                register_response = self.__register_server(unpacked, server_ram_template)

            else:
                raise ValueError(f"Unsupported registration request code '{request_code}'.")

            # Send response back to client/server
            server_socket.send_packet(sck=client_socket, packet=register_response)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle registration request from {client_socket.getpeername()}.", exception=e)