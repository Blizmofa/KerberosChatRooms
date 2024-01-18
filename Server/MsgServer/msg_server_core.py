from Socket.custom_socket import socket, Thread
from Server.server_interface import ServerInterface
from Utils.custom_exception_handler import CustomException
from Utils.logger import Logger
from Server.MsgServer.msg_server_logic import MsgServerLogic
from Server.MsgServer.msg_server_constants import MsgServerConstants, ram_clients_template
from Utils.utils import create_if_not_exists, last_seen, generate_client_uuid


class MsgServer(ServerInterface):
    def __init__(self, connection_protocol: str, ip_address: str, port: int, debug_mode: bool) -> None:
        super().__init__(connection_protocol, ip_address, port, debug_mode)
        self.ip_address = ip_address
        self.port = port
        self.connections_list = []
        self.threads = []
        self.active_connections = 0
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)
        self.msg_server_logic = MsgServerLogic(debug_mode=debug_mode)
        
    def handle_new_client(self, sck: socket) -> None:
        try:
            # Insert new connection
            self.new_connection(sck=sck, connections_list=self.connections_list, active_connections=self.active_connections)
            
            # Create new client RAM DB
            client_ram_template = ram_clients_template.copy()
            client_ram_template[MsgServerConstants.ID] = generate_client_uuid()
            client_ram_template[MsgServerConstants.LAST_SEEN] = last_seen()
            
            # Handle Registration request
            register_request = self.custom_socket.receive_packet(sck=sck, logger=self.logger)
            self.msg_server_logic.handle_registration_request(sck=sck, client_ram_template=client_ram_template, register_request=register_request)
            
            
        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle client {sck.getpeername()}.", exception=e)    
            
            
    def run(self) -> None:
        try:
            # Initialize Server
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


