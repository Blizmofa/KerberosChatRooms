from Socket.custom_socket import CustomSocket, socket, Thread
from Server.server_interfcae import ServerInterface
from Utils.logger import Logger
from Utils.custom_exception_handler import CustomException
from Server.AuthServer.auth_server_constants import Constants, ram_clients_template

# TODO - create server interface for the two servers, the interface should inherit socket


# class AuthServerCore(CustomSocket):
class AuthServer(ServerInterface):

    def __init__(self, connection_protocol: str, ip_address: str, port: int, debug_mode: bool):
        super().__init__(connection_protocol, ip_address, port, debug_mode)
        self.ip_address = ip_address
        self.port = port
        self.connections_list = []
        self.threads = []
        self.active_connections = 0
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)

    def handle_new_client(self, sck: socket) -> None:
        try:
            # Insert new connection
            self.new_connection(sck=sck, connections_list=self.connections_list, active_connections=self.active_connections)

            # Create new client RAM DB
            client_ram_template = ram_clients_template.copy()
            print(client_ram_template)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle client {sck.getpeername()}.", exception=e)

    def run(self) -> None:
        try:
            # Initialize Server
            self.setup()

            # Print welcome message
            print(Constants.AUTH_SERVER_LOGO, end='\n\n')
            print(f"{Constants.CONSOLE_ACK} Starting Server...")
            print(f"{Constants.CONSOLE_ACK} Server is now listening on {self.ip_address}:{self.port}")

            # Wait for clients requests
            while True:
                connection, address = self.socket.accept()
                print(f"{Constants.CONSOLE_ACK} Connected to peer {connection.getpeername()}")

                # Assign new thread to each connected client
                client_thread = Thread(target=self.handle_new_client, args=(connection, ))
                client_thread.start()
                self.threads.append(client_thread)

        except Exception as e:
            # Cleanup
            self.socket.close()
            for thread in self.threads:
                thread.join()

            raise CustomException(error_msg=f"Unable to run {self.__class__.__name__}.", exception=e)


