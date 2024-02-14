from sys import exit
from Socket.custom_socket import CustomSocket, Thread
from Utils.logger import Logger, CustomFilter
from Utils import utils
from Utils.custom_exception_handler import CustomException, get_calling_method_name
from Protocol_Handler.protocol_utils import ProtocolConstants as ProtoConsts, server_request, server_response
from Client.client_constants import Constants as CConsts, client_ram_template, me_info_default_data
from Client.client_input import ClientInput
from Client.client_logic import ClientLogic
from Utils.encryptor import Encryptor


class ClientCore(CustomSocket):
    """Handles the Client core functionalities."""

    def __init__(self, server_ip: str, server_port: int, connection_protocol: str, debug_mode: bool) -> None:
        super().__init__(connection_protocol=connection_protocol, debug_mode=debug_mode)
        self.server_ip = server_ip
        self.server_port = server_port
        self.debug_mode = debug_mode
        self.client_socket = self.create_socket()
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)
        self.encryptor = Encryptor(debug_mode=debug_mode)
        self.client_logic = ClientLogic(debug_mode=debug_mode)

    def connect(self):
        """Setups the Msg Server as a client in order to register to Authentication server."""
        try:
            # TODO - ip and port should be paramters, change between servers
            self.client_socket.connect((self.server_ip, self.server_port))
            self.logger.logger.info(f"Connected to {self.server_ip}:{self.server_port} successfully.")

        except Exception as e:
            raise CustomException(error_msg=f"Unable to connect to {self.server_ip}:{self.server_port}", exception=e)

    def start_client(self, ram_template: dict) -> None:
        try:
            # Run client logic
            while True:
                # Prompt client menu
                client_input = ClientInput.show_client_menu()

                # Check if already registered
                is_registered = ram_template[CConsts.RAM_IS_REGISTERED]

                # Handle registration request to Authentication Server
                if client_input == 1:
                    if not is_registered:
                        self.client_logic.handle_registration_request(sck=self,
                                                                      client_socket=self.client_socket,
                                                                      ram_template=ram_template,
                                                                      server_request_formatter=server_request.copy(),
                                                                      server_response_formatter=server_response.copy())
                        # For dev mode
                        if self.debug_mode:
                            print(utils.write_with_color(msg=f"Registered client template --> {ram_template}", color=utils.Colors.CYAN))
                    else:
                        print(utils.write_with_color(msg=f"{ProtoConsts.CONSOLE_ERROR} You are already registered.",
                                                     color=utils.Colors.GREEN))

                # Handle services list request
                elif client_input == 2:
                    if is_registered:
                        self.client_logic.handle_services_list_request(sck=self,
                                                                       client_socket=self.client_socket,
                                                                       ram_template=ram_template,
                                                                       server_request_formatter=server_request.copy(),
                                                                       server_response_formatter=server_response.copy())

                        print(utils.write_with_color(msg=f"{ProtoConsts.CONSOLE_ACK} Services list has received successfully, "
                                                         f"and been parse to '{CConsts.SERVERS_FILE_NAME}'", color=utils.Colors.GREEN))
                    else:
                        print(utils.write_with_color(msg=f"{ProtoConsts.CONSOLE_ERROR} Please register first.", color=utils.Colors.RED))

                # Handle AES Key request
                elif client_input == 3:
                    if is_registered:
                        self.client_logic.handle_aes_key_request(sck=self,
                                                                 client_socket=self.client_socket,
                                                                 ram_template=ram_template,
                                                                 server_request_formatter=server_request.copy(),
                                                                 server_response_formatter=server_response.copy())
                        # For dev mode
                        if self.debug_mode:
                            print(utils.write_with_color(msg=f"AES Key client template --> {ram_template}",
                                                         color=utils.Colors.CYAN))
                    else:
                        print(utils.write_with_color(msg=f"{ProtoConsts.CONSOLE_ERROR} Please register first.",
                                                     color=utils.Colors.RED))

                # Connect to MSG server
                elif client_input == 4:
                    if is_registered:
                        self.client_logic.connect_to_service(sck=self,
                                                             client_socket=self.client_socket,
                                                             ram_template=ram_template,
                                                             server_request_formatter=server_request.copy(),
                                                             server_response_formatter=server_response.copy())
                    else:
                        print(utils.write_with_color(msg=f"{ProtoConsts.CONSOLE_ERROR} Please register first.",
                                                     color=utils.Colors.RED))
                # Shut down client
                elif client_input == 5:
                    # TODO - call cleanup
                    print(utils.write_with_color(msg=f"Shutting down client.", color=utils.Colors.RED))
                    exit(0)

                else:
                    print(f"{ProtoConsts.CONSOLE_FAIL} Invalid option, please choose another: ")

                # print("[+] Processing request...")
                # time.sleep(2)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to start {self.__class__.__name__}.", exception=e)

    def run(self) -> None:
        try:
            # Connect to Auth server
            self.connect()

            # Set Logger custom filter
            CustomFilter.filter_name = get_calling_method_name()

            # Validate me.info file
            if not utils.check_if_exists(CConsts.CLIENT_FILE_PATH):
                utils.create_info_file(CConsts.CLIENT_FILE_PATH, file_data=me_info_default_data)

            # Create client RAM template, parse data from file DB or get it from user
            ram_template = client_ram_template.copy()

            if utils.check_if_exists(CConsts.CLIENT_FILE_PATH):
                username = utils.parse_info_file(file_path=CConsts.CLIENT_FILE_PATH, target_line_number=CConsts.CLIENT_NAME_LINE)
                client_id = utils.parse_info_file(file_path=CConsts.CLIENT_FILE_PATH, target_line_number=CConsts.CLIENT_ID_LINE)

            else:
                username = input("Please enter your username: ")
                client_id = None

            ram_template[CConsts.RAM_USERNAME] = username
            ram_template[CConsts.RAM_ID] = client_id
            password = "qwer1234"
            # password = input("Please enter your password: ")
            ram_template[CConsts.RAM_PASSWORD] = password
            ram_template[CConsts.RAM_PASSWORD_HASH] = self.encryptor.hash_password(password=password)
            ram_template[CConsts.RAM_IS_REGISTERED] = False

            # For dev mode
            if self.debug_mode:
                print(utils.write_with_color(msg=f"Parsed client template --> {ram_template}", color=utils.Colors.CYAN))

            # Start client
            client_thread = Thread(target=self.start_client, args=(ram_template, ))
            client_thread.start()

        except Exception as e:
            raise CustomException(error_msg=f"Unable to run {self.__class__.__name__}.", exception=e)


# TODO - cleanup, close socket to auth server and open to msg server