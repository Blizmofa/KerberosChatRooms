from Socket.custom_socket import socket, Thread
from Server.server_interface import ServerInterface
from Utils.custom_exception_handler import CustomException
from Utils.logger import Logger
from Server.MsgServer.msg_server_logic import MsgServerLogic
from Server.MsgServer import msg_server_constants
from Utils import utils
import os
from Utils.encryptor import Encryptor
from Protocol_Handler.protocol_handler import ProtocolHandler
from Protocol_Handler import protocol_utils


class MsgServer(ServerInterface):
    def __init__(self, connection_protocol: str, ip_address: str, port: int, service_name: str, debug_mode: bool) -> None:
        super().__init__(connection_protocol, ip_address, port, debug_mode)
        self.ip_address = ip_address
        self.port = port
        self.service_name = service_name
        self.connections_list = []
        self.threads = []
        self.active_connections = 0
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)
        self.protocol_handler = ProtocolHandler(debug_mode=debug_mode)
        self.encryptor = Encryptor(debug_mode=debug_mode)
        self.msg_server_logic = MsgServerLogic(debug_mode=debug_mode)

    def get_service_name(self):
        return

    def handle_new_client(self, sck: socket) -> None:
        try:
            # Insert new connection
            self.new_connection(sck=sck, connections_list=self.connections_list, active_connections=self.active_connections)

            # # Create new client RAM DB
            # client_ram_template = ram_service_template.copy()
            
            # Handle Symmetric Key 1028 request
            symmetric_key_request = self.custom_socket.receive_packet(sck=sck, logger=self.logger)

            # self.msg_server_logic.handle_registration_request(sck=sck, client_ram_template=client_ram_template, register_request=symmetric_key_request)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle client {sck.getpeername()}.", exception=e)    

    def handle_registration_request(self, service_ram_template: dict) -> bool:
        try:
            result = None
            # Connect to auth server
            # TODO - refactor into validator
            if not isinstance(self.ip_address, str):
                self.ip_address = str(self.ip_address)
            if not isinstance(self.port, int):
                self.port = int(self.port)
            self.server_socket.connect((self.ip_address, self.port))

            # Create Msg Server AES key
            aes_key = self.encryptor.generate_bytes_stream(size=32)
            service_ram_template[msg_server_constants.Constants.AES_KEY] = utils.convert_bytes_or_hex(data=aes_key,
                                                                                                      mode=protocol_utils.Constants.HEX)
            service_ram_template[msg_server_constants.Constants.SERVICE_NAME] = self.service_name
            # utils.insert_value_into_file(value=self.encryptor.encode_decode_base64(value=aes_key, mode="encode"), target_line=4,
            #                              file_path=msg_server_constants.Constants.MSG_FILE_NAME, max_lines=4)

            # Pack and send register request
            data = {protocol_utils.Constants.CLIENT_ID: utils.parse_info_file(os.path.abspath(msg_server_constants.Constants.MSG_FILE_NAME), 3),
                    protocol_utils.Constants.VERSION: protocol_utils.Constants.SERVER_VERSION,
                    protocol_utils.Constants.CODE: protocol_utils.Constants.REQ_SERVER_REG,
                    protocol_utils.Constants.PAYLOAD_SIZE: protocol_utils.Constants.SIZE_SERVER_NAME + protocol_utils.Constants.SIZE_AES_KEY,
                    protocol_utils.Constants.NAME: self.service_name,
                    # protocol_utils.Constants.NAME: utils.parse_info_file(os.path.abspath(MsgServerConstants.MSG_FILE_NAME), 2),
                    protocol_utils.Constants.AES_KEY: aes_key}

            packed_register_request = self.protocol_handler.pack_request(code=protocol_utils.Constants.REQ_SERVER_REG,
                                                                         data=data,
                                                                         formatter=protocol_utils.server_request)

            self.custom_socket.send_packet(sck=self.server_socket, packet=packed_register_request, logger=self.logger)

            # Receive register response
            register_response = self.custom_socket.receive_packet(sck=self.server_socket)
            response_code, unpacked_register_response = self.protocol_handler.unpack_request(received_packet=register_response,
                                                                                             formatter=protocol_utils.server_response,
                                                                                             deserialize=True)
            # Register success
            if response_code == protocol_utils.Constants.RES_REGISTER_SUCCESS:
                # utils.insert_value_into_file(value=utils.convert_bytes_or_hex(data=unpacked_register_response["client_id"], mode="hex"),
                #                              target_line=3, file_path=msg_server_constants.Constants.MSG_FILE_NAME, max_lines=3)
                service_id = unpacked_register_response[protocol_utils.Constants.CLIENT_ID]
                service_ram_template[msg_server_constants.Constants.SERVICE_ID] = utils.convert_bytes_or_hex(data=service_id,
                                                                                                             mode=protocol_utils.Constants.HEX)
                # Update the new DNS mapping ip and port
                self.ip_address, self.port = self.server_socket.getsockname()
                service_ram_template[msg_server_constants.Constants.IP_ADDRESS] = self.ip_address
                service_ram_template[msg_server_constants.Constants.MSG_PORT] = self.port
                service_ram_template[msg_server_constants.Constants.IS_REGISTERED] = True
                print(f"{self.service_name} Registration successful.")

                result = True

            elif response_code == protocol_utils.Constants.RES_REGISTER_FAILED:
                print(f"{self.service_name} Registration failure")
                result = False

            # Update services JSON db
            utils.insert_data_to_json_db(file_path=msg_server_constants.Constants.SERVICE_POOL_FILE_NAME,
                                         data=service_ram_template,
                                         pivot_key=msg_server_constants.Constants.SERVICE_NAME,
                                         pivot_value=self.service_name)
            return result

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle registration request.", exception=e)

    def setup_as_msg_server(self):
        try:

            # Initialize Server as a service only on registration success
            self.setup_server()

            # Print welcome message
            print(msg_server_constants.Constants.MSG_SERVER_LOGO, end='\n\n')
            print(f"{msg_server_constants.Constants.CONSOLE_ACK} Starting Server...")
            print(f"{msg_server_constants.Constants.CONSOLE_ACK} Server is now listening on {self.ip_address}:{self.port}")

            # Wait for clients requests
            while True:
                connection, address = self.server_socket.accept()
                print(f"{msg_server_constants.Constants.CONSOLE_ACK} Connected to peer {connection.getpeername()}")

                # Assign new thread to each connected client
                client_thread = Thread(target=self.handle_new_client, args=(connection, ))
                client_thread.start()
                self.threads.append(client_thread)

        except Exception as e:
            # Cleanup
            self.server_socket.close()
            for thread in self.threads:
                thread.join()

            raise CustomException(error_msg=f"Unable to run {self.__class__.__name__}.", exception=e)

    def run(self) -> None:
        # Create service RAM template and update its values
        service_ram_template = msg_server_constants.ram_service_template.copy()
        service_ram_template.update(utils.update_template_values(template=service_ram_template,
                                                                 current_value=msg_server_constants.Constants.FMT_ME,
                                                                 new_value=None))
        # Register
        if self.handle_registration_request(service_ram_template=service_ram_template):
            pass
            # self.chat_mode()






