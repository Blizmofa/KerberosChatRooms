from sys import exit as sys_exit
from time import sleep
from Utils import utils
from Utils.logger import Logger, CustomFilter
from Utils.encryptor import Encryptor
from Utils.custom_exception_handler import CustomException, get_calling_method_name
from Socket.custom_socket import CustomSocket, Thread
from Protocol_Handler.protocol_utils import ProtoConsts as ProtoConsts, server_request, server_response
from Protocol_Handler.protocol_handler import ProtocolHandler
from Client.client_input import ClientInput
from Client.client_constants import CConsts as CConsts, client_ram_template, me_info_default_data
from Client.client_registration_handler import RegistrationHandler
from Client.client_services_handler import ServicesHandler
from Client.client_key_ticket_handler import KeyTicketHandler


class ClientCore(CustomSocket):
    """Handles the Client core functionalities."""

    def __init__(self, connection_protocol: str, server_ip: str, server_port: int, debug_mode: bool) -> None:
        super().__init__(connection_protocol=connection_protocol, debug_mode=debug_mode)
        self.server_ip = server_ip
        self.server_port = server_port
        self.debug_mode = debug_mode
        self.msg_servers_list = []
        self.client_socket = self.create_socket()
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)
        self.encryptor = Encryptor(debug_mode=debug_mode)
        self.protocol_handler = ProtocolHandler(debug_mode=debug_mode)
        self.registration_handler = RegistrationHandler(debug_mode=debug_mode)
        self.services_handler = ServicesHandler(debug_mode=debug_mode)
        self.key_ticket_handler = KeyTicketHandler(debug_mode=debug_mode)

    def __register(self, is_registered: bool, ram_template: dict) -> None:
        """Private method to wrap registration request logic."""
        try:
            if not is_registered:
                self.registration_handler.handle_registration_request(sck=self,
                                                                      client_socket=self.client_socket,
                                                                      ram_template=ram_template,
                                                                      server_request_formatter=server_request.copy(),
                                                                      server_response_formatter=server_response.copy(),
                                                                      protocol_handler=self.protocol_handler)
                # For dev mode
                if self.debug_mode:
                    print(utils.write_with_color(msg=f"Registered client template --> {ram_template}",
                                                 color=utils.Colors.CYAN))
            else:
                print(utils.write_with_color(msg=f"{ProtoConsts.CONSOLE_ERROR} You are already registered.",
                                             color=utils.Colors.GREEN))
        except Exception as e:
            raise CustomException(error_msg=f"Unable to register.", exception=e)

    def __get_services_list(self, is_registered: bool, ram_template: dict) -> None:
        """Private method to wrap services list request logic."""
        try:
            if is_registered:
                self.services_handler.handle_services_list_request(sck=self,
                                                                   client_socket=self.client_socket,
                                                                   ram_template=ram_template,
                                                                   server_request_formatter=server_request.copy(),
                                                                   server_response_formatter=server_response.copy(),
                                                                   msg_servers_list=self.msg_servers_list,
                                                                   protocol_handler=self.protocol_handler)

                print(utils.write_with_color(msg=f"{ProtoConsts.CONSOLE_ACK} Services list has received successfully, "
                                                 f"and been parse to '{CConsts.SERVICES_FILE_NAME}'",
                                             color=utils.Colors.GREEN))
            else:
                print(utils.write_with_color(msg=f"{ProtoConsts.CONSOLE_ERROR} Please register first.",
                                             color=utils.Colors.RED))

        except Exception as e:
            raise CustomException(error_msg=f"Unable to get services lists.", exception=e)

    def __get_service_aes_key(self, is_registered: bool, ram_template: dict) -> None:
        """Private method to wrap service AES key request logic."""
        try:
            if is_registered:
                self.key_ticket_handler.handle_aes_key_request(sck=self,
                                                               client_socket=self.client_socket,
                                                               ram_template=ram_template,
                                                               server_request_formatter=server_request.copy(),
                                                               server_response_formatter=server_response.copy(),
                                                               msg_servers_list=self.msg_servers_list,
                                                               encryptor=self.encryptor,
                                                               protocol_handler=self.protocol_handler)
                # For dev mode
                if self.debug_mode:
                    print(utils.write_with_color(msg=f"AES Key client template --> {ram_template}",
                                                 color=utils.Colors.CYAN))
            else:
                print(utils.write_with_color(msg=f"{ProtoConsts.CONSOLE_ERROR} Please register first.",
                                             color=utils.Colors.RED))

        except Exception as e:
            raise CustomException(error_msg=f"Unable to get service aes key.", exception=e)

    def handle_client_logic(self, ram_template: dict) -> None:
        """Runs client logic according to the user input."""
        try:
            # Run client logic
            while True:

                # Prompt client menu
                client_input = ClientInput.show_client_menu()

                print("[+] Processing request...")
                sleep(ProtoConsts.DEF_SLEEP_TIME)

                # Check if already registered
                is_registered = ram_template[CConsts.RAM_IS_REGISTERED]

                # Handle registration request to Authentication Server
                if client_input == CConsts.IN_REQ_REGISTER:
                    self.__register(is_registered=is_registered, ram_template=ram_template)

                # Handle services list request
                elif client_input == CConsts.IN_REQ_SERVICES_LIST:
                    self.__get_services_list(is_registered=is_registered, ram_template=ram_template)

                # Handle AES Key request and connect to Service
                elif client_input == CConsts.IN_REQ_AES_KEY_CONNECT:
                    self.__get_service_aes_key(is_registered=is_registered, ram_template=ram_template)
                    # TODO - cleanup socket to auth server
                    # TODO - break only if connected successfully
                    # break

                # Shut down client
                elif client_input == CConsts.IN_QUIT:
                    # TODO - call cleanup
                    print(utils.write_with_color(msg=f"Shutting down client.", color=utils.Colors.RED))
                    sys_exit(ProtoConsts.STATUS_NO_ERROR_CODE)

                else:
                    print(f"{ProtoConsts.CONSOLE_FAIL} Invalid option, please choose another: ")

        except Exception as e:
            raise CustomException(error_msg=f"Unable to start {self.__class__.__name__}.", exception=e)

    def run(self) -> None:
        """Client main run method."""
        try:
            # Connect to Auth server
            self.connect(sck=self.client_socket, ip_address=self.server_ip, port=self.server_port)

            # Set Logger custom filter
            CustomFilter.filter_name = get_calling_method_name()

            # Validate me.info file
            if not utils.is_exists(CConsts.CLIENT_FILE_PATH):
                utils.create_info_file(CConsts.CLIENT_FILE_PATH, file_data=me_info_default_data)

            # Create client RAM template, parse data from file DB or get it from user
            ram_template = client_ram_template.copy()

            if utils.is_exists(CConsts.CLIENT_FILE_PATH):
                username = utils.parse_info_file(file_path=CConsts.CLIENT_FILE_PATH, target_line_number=CConsts.CLIENT_NAME_LINE)
                client_id = utils.parse_info_file(file_path=CConsts.CLIENT_FILE_PATH, target_line_number=CConsts.CLIENT_ID_LINE)

            else:
                username = input("Please enter your username: ")
                client_id = None

            ram_template[CConsts.RAM_USERNAME] = username
            ram_template[CConsts.RAM_CLIENT_ID] = client_id
            password = "qwer1234"
            # password = input("Please enter your password: ")
            ram_template[CConsts.RAM_PASSWORD] = password
            ram_template[CConsts.RAM_PASSWORD_HASH] = self.encryptor.hash_password(password=password)

            # Already registered
            # TODO - fix bug when in server not registered but in client registered
            # if client_id:
            #     ram_template[CConsts.RAM_IS_REGISTERED] = True
            # else:
            #     ram_template[CConsts.RAM_IS_REGISTERED] = False
            ram_template[CConsts.RAM_IS_REGISTERED] = False

            # For dev mode
            if self.debug_mode:
                print(utils.write_with_color(msg=f"Parsed client template --> {ram_template}", color=utils.Colors.CYAN))

            # Start client
            client_thread = Thread(target=self.handle_client_logic, args=(ram_template,))
            client_thread.start()

        except Exception as e:
            raise CustomException(error_msg=f"Unable to run {self.__class__.__name__}.", exception=e)


# TODO - cleanup, close socket to auth server and open to msg server