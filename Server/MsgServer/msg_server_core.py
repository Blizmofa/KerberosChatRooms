import struct

from Socket.custom_socket import socket, Thread
from Server.server_interface import ServerInterface
from Utils.custom_exception_handler import CustomException
from Utils.logger import Logger
from Server.MsgServer.msg_server_logic import MsgServerLogic
from Server.MsgServer.msg_server_constants import MsgServerConstants, ram_clients_template
from Utils import utils
import os
from Protocol_Handler.protocol_handler import ProtocolHandler
from Protocol_Handler.protocol_utils import ProtocolConstants, server_request, server_response

class MsgServer(ServerInterface):
    def __init__(self, connection_protocol: str, ip_address: str, port: int, debug_mode: bool) -> None:
        super().__init__(connection_protocol, ip_address, port, debug_mode)
        self.ip_address = ip_address
        self.port = port
        self.connections_list = []
        self.threads = []
        self.active_connections = 0
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)
        self.protocol_handler = ProtocolHandler(debug_mode=debug_mode)
        self.msg_server_logic = MsgServerLogic(debug_mode=debug_mode)
        
    def handle_new_client(self, sck: socket) -> None:
        try:
            # Insert new connection
            self.new_connection(sck=sck, connections_list=self.connections_list, active_connections=self.active_connections)

            # TODO - Use Encryptor class to decrypt client requests and parse them.

            # Create new client RAM DB
            client_ram_template = ram_clients_template.copy()
            print(client_ram_template)
            
            # Handle Symmetric Key 1028 request
            symmetric_key_request = self.custom_socket.receive_packet(sck=sck, logger=self.logger)
            print(symmetric_key_request)
            # self.msg_server_logic.handle_registration_request(sck=sck, client_ram_template=client_ram_template, register_request=symmetric_key_request)
            # TODO - unpack request

            # TODO - Use Encryptor only when given to you class to decrypt client requests and parse them.

            # TODO - parse unpacked packet after decryption the Authenticator and Ticket:
            #  1. validate server id from packet with server id from msg.info, if not raise MsgServerError, and send error code to client
            #  2. validate Authenticator and Ticket ID's
            #  3. insert needed data to ram template

            # TODO - for Msg Server responses use Auth server template from page 7.

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle client {sck.getpeername()}.", exception=e)    

    def handle_registration_request(self) -> bool:
        try:
            # Connect to auth server
            self.server_socket.connect((self.ip_address, self.port))

            # Pack register request
            server_id = utils.parse_info_file(os.path.abspath(MsgServerConstants.MSG_FILE_NAME), 3)
            version = ProtocolConstants.SERVER_VERSION
            code = ProtocolConstants.REQ_SERVER_REG
            payload_size = ProtocolConstants.SIZE_SERVER_NAME + ProtocolConstants.SIZE_AES_KEY
            server_name = utils.parse_info_file(os.path.abspath(MsgServerConstants.MSG_FILE_NAME), 2)
            aes_key = utils.parse_info_file(os.path.abspath(MsgServerConstants.MSG_FILE_NAME), 4)

            data = {"client_id": server_id, "version": version, "code": code,
                    "payload_size": payload_size, "name": server_name, "aes_key": aes_key}

            packed_register_request = self.protocol_handler.pack_request(code=code, data=data, formatter=server_request)

            self.custom_socket.send_packet(sck=self.server_socket, packet=packed_register_request, logger=self.logger)

            # Receive register response
            register_response = self.custom_socket.receive_packet(sck=self.server_socket)
            unpacked_register_response = self.protocol_handler.unpack_request(received_packet=register_response,
                                                                              formatter=server_response,
                                                                              deserialize=True)
            print(unpacked_register_response)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle registration request.", exception=e)

    def chat_mode(self):
        try:

            # Initialize Server as a service only on registration success
            self.setup_server()

            # Print welcome message
            print(MsgServerConstants.MSG_SERVER_LOGO, end='\n\n')
            print(f"{MsgServerConstants.CONSOLE_ACK} Starting Server...")
            print(f"{MsgServerConstants.CONSOLE_ACK} Server is now listening on {self.ip_address}:{self.port}")

            # Wait for clients requests
            while True:
                connection, address = self.server_socket.accept()
                print(f"{MsgServerConstants.CONSOLE_ACK} Connected to peer {connection.getpeername()}")

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

        # Register
        if self.handle_registration_request():

            self.chat_mode()






