from Socket.custom_socket import socket
from Utils.custom_exception_handler import CustomException
from Utils.logger import Logger
from Server.MsgServer.msg_server_constants import MsgServerConstants

class MsgServerLogic:
    def __init__(self, debug_mode: bool) -> None:
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)

    def handle_registration_request(self, sck: socket, client_ram_template: dict, register_request: bytes) -> None:
        try:
            print(client_ram_template)
            print(register_request)
            
            server_config = self.read_msg_server_config()
            
            # TODO - implement getting key and printing message

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle registration request from {sck.getpeername()}.", exception=e)
        
    def read_msg_server_config(self):
        try:
            with open(MsgServerConstants.MSG_FILE_NAME, 'r') as file:
                port = int(file.readline().strip())
                server_name = file.readline().strip()
                shared_key_ascii = file.readline().strip()
                
                # Convert ASCII representation to bytes
                shared_key = bytes.fromhex(shared_key_ascii)
                
                return port, server_name, shared_key
                        
        except Exception as e:
            raise CustomException(error_msg=f"Unable to read config {self.__class__.__name__}.", exception=e)