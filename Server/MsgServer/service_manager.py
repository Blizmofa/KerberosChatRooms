from time import sleep
from json import dump, load
from typing import Optional
from Utils.logger import Logger
from Utils.custom_exception_handler import CustomException
from Utils.validator import Validator, ValConsts as ValConsts
from Utils.encryptor import Encryptor
from Utils.utils import generate_uuid, create_info_file, is_exists, update_template_values, parse_msg_info_file
from Socket.custom_socket import Thread
from Protocol_Handler.protocol_constants import ProtoConsts as ProtoConsts
from Server.MsgServer.msg_server_core import MsgServerCore
from Server.MsgServer.msg_server_constants import service_manager_template, MsgConsts as MsgConsts


class ServiceManager:
    """A Wrapper Class that uses the Msg Server service.
    provides methods to create, run, start stop, and clean services for the KDC."""

    def __init__(self, connection_protocol: str, kdc_ip_address: str,
                 kdc_port: int, service_name_prefix: str, debug_mode: bool) -> None:
        self.connection_protocol = connection_protocol
        self.kdc_ip_address = kdc_ip_address
        self.kdc_port = int(kdc_port)
        self.service_name_prefix = service_name_prefix
        self.debug_mode = debug_mode
        self.active_services = []
        self.services_pool = []
        self.encryptor = Encryptor(debug_mode=debug_mode)
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)

    def __create_default_service(self) -> dict:
        """Creates a registered default Msg server in case of a system failure."""
        try:
            # Create Service template
            service_template = self.__create_service_template()

            # Create the default Service data
            default_server_id = generate_uuid()
            default_server_id_hex = Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=default_server_id)
            default_aes_key = self.encryptor.generate_bytes_stream(size=ProtoConsts.SIZE_AES_KEY)
            default_aes_key_encoded = Validator.validate_injection(data_type=ValConsts.FMT_AES_KEY, value_to_validate=default_aes_key)

            # Create msg.info data frame
            msg_info_data = {
                ValConsts.FMT_IPV4_PORT: f"{MsgConsts.DEF_IP_ADDRESS}:{MsgConsts.DEF_PORT_NUM}",
                ValConsts.FMT_NAME: service_template[MsgConsts.RAM_SERVICE_NAME],
                ValConsts.FMT_ID: default_server_id_hex,
                ValConsts.FMT_AES_KEY: default_aes_key_encoded
            }

            # Create default Service object and register it
            create_info_file(file_name=MsgConsts.MSG_FILE_NAME, file_data=msg_info_data)
            service_template[MsgConsts.CONNECTION_PROTOCOL] = self.connection_protocol
            service_template[MsgConsts.RAM_IP_ADDRESS] = self.kdc_ip_address
            service_template[MsgConsts.KDC_PORT] = self.kdc_port
            service_template[MsgConsts.RAM_PORT] = MsgConsts.DEF_PORT_NUM
            service_template[MsgConsts.RAM_SERVICE_ID_HEX] = default_server_id_hex
            service_template[MsgConsts.RAM_SERVICE_AES_KEY_ENCODED] = default_aes_key_encoded
            service_template[MsgConsts.RAM_IS_REGISTERED] = True
            service_template.update(update_template_values(template=service_template,
                                                           current_value=MsgConsts.FMT_ME,
                                                           new_value=None))
            return service_template

        except Exception as e:
            raise CustomException(error_msg=f"Unable to create default {self.__class__.__name__}.", exception=e)

    def __parse_default_service_data(self) -> dict:
        """Returns the default Service parsed object."""
        # Parse msg.info file
        ip_and_port, service_name, service_id, service_aes_key = parse_msg_info_file()
        ip_address, port = Validator.validate_injection(data_type=ValConsts.FMT_IPV4_PORT, value_to_validate=ip_and_port)

        # Update default Service object
        service_template = self.__create_service_template()
        service_template[MsgConsts.RAM_IP_ADDRESS] = ip_address
        service_template[MsgConsts.KDC_PORT] = self.kdc_port
        service_template[MsgConsts.RAM_PORT] = int(port)
        service_template[MsgConsts.RAM_SERVICE_NAME] = service_name
        service_template[MsgConsts.RAM_SERVICE_ID_HEX] = service_id
        service_template[MsgConsts.RAM_SERVICE_AES_KEY] = service_aes_key
        service_template[MsgConsts.RAM_IS_REGISTERED] = True

        self.logger.logger.debug(msg=f"Parsed default Service data successfully.")
        return service_template

    def __create_service(self, connection_protocol: str, ip_address: str, port: int,
                         service_name: str, is_registered: bool, debug_mode: Optional[bool] = False) -> None:
        """Creates a Service."""
        try:
            service = MsgServerCore(connection_protocol=connection_protocol,
                                    ip_address=ip_address,
                                    port=port,
                                    service_name=service_name,
                                    is_registered=is_registered,
                                    debug_mode=debug_mode)
            service_thread = Thread(target=self.run_service, args=(service, ))
            self.logger.logger.info(msg=f"Created service {service.service_name} successfully.")
            self.active_services.append(service_thread)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to create service {service_name}.", exception=e)

    def __parse_services_configs(self, service: dict) -> tuple:
        """Returns a tuple of the needed configurations for the service creation."""
        # Get and validate service connection protocol
        connection_protocol = service.get(MsgConsts.CONNECTION_PROTOCOL)
        Validator.validate_injection(data_type=ValConsts.FMT_CONNECTION_PROTOCOL, value_to_validate=connection_protocol)

        # Get and validate service IP Address
        ip_address = service.get(MsgConsts.RAM_IP_ADDRESS)
        Validator.validate_injection(data_type=ValConsts.FMT_IPV4, value_to_validate=ip_address)

        # Get and validate service Port
        port = service.get(MsgConsts.KDC_PORT)
        Validator.validate_injection(data_type=ValConsts.FMT_PORT, value_to_validate=port)

        # Get and validate service name
        service_name = service.get(MsgConsts.RAM_SERVICE_NAME)
        Validator.validate_injection(data_type=ValConsts.FMT_NAME, value_to_validate=service_name)

        is_registered = service.get(MsgConsts.RAM_IS_REGISTERED)

        self.logger.logger.debug(msg=f"Parsed service configs successfully.")
        return connection_protocol, ip_address, port, service_name, is_registered

    def __create_service_template(self, service: Optional[int] = None) -> dict:
        """Returns an updated dict template with the Service needed configurations."""
        service_template = service_manager_template.copy()
        service_template[MsgConsts.CONNECTION_PROTOCOL] = self.connection_protocol
        service_template[MsgConsts.RAM_IP_ADDRESS] = self.kdc_ip_address
        service_template[MsgConsts.KDC_PORT] = int(self.kdc_port)
        service_template[MsgConsts.RAM_SERVICE_NAME] = \
            f"{self.service_name_prefix}{service + 1}0" if service is not None else MsgConsts.DEF_SERVER_NAME
        service_template[MsgConsts.RAM_IS_REGISTERED] = False
        service_template.update(update_template_values(template=service_template,
                                                       current_value=MsgConsts.FMT_ME,
                                                       new_value=None))
        return service_template

    def __add_unique_service(self, service_object: dict) -> bool:
        """Adds to services pool list only a unique Service."""
        service_name = service_object.get(MsgConsts.RAM_SERVICE_NAME)

        # Check if service already in services pool list
        for existing_service in self.services_pool:
            if service_name == existing_service.get(MsgConsts.RAM_SERVICE_NAME):
                return False

        # Add service
        self.services_pool.append(service_object)
        return True

    def __create_services_pool(self, num_of_services: int) -> None:
        """Creates a pool of services according to the given number of services."""
        # Limit the amount of services
        if num_of_services > MsgConsts.MAX_NUM_OF_SERVICES:
            raise ServiceManagerError(f"The number of requested services exceeds the "
                                      f"maximum allowed {MsgConsts.MAX_NUM_OF_SERVICES} services.")
        # Create/Start the default service
        elif num_of_services == 0:
            if not is_exists(path_to_check=MsgConsts.MSG_FILE_NAME):
                self.__add_unique_service(self.__create_default_service())
            else:
                self.__add_unique_service(self.__parse_default_service_data())

        # Create the requested amount of services without duplications
        else:
            for service in range(num_of_services):
                service_object = self.__create_service_template(service=service)
                self.__add_unique_service(service_object=service_object)

        # Dumpo services into JSON database
        with open(MsgConsts.SERVICE_POOL_FILE_PATH, 'w') as sp:
            dump(self.services_pool, sp, indent=MsgConsts.DEF_INDENT_LVL)

    def run_service(self, service: MsgServerCore) -> None:
        """Run a give Service."""
        service.run()
        self.logger.logger.info(msg=f"Started service {service.service_name} successfully.")

    def start_services(self):
        """Starts all the Services."""
        for service_thread in self.active_services:
            sleep(MsgConsts.DEF_SLEEP_TIME)
            service_thread.start()

    def stop_services(self) -> None:
        """Stops all the Services."""
        for service_thread in self.active_services:
            service_thread.join()

    def run(self, num_of_services: int) -> None:
        """Service Manager main run method."""
        try:
            # Load JSON database
            if is_exists(path_to_check=MsgConsts.SERVICE_POOL_FILE_PATH):
                with open(MsgConsts.SERVICE_POOL_FILE_PATH, 'r') as f:
                    self.services_pool = load(f)

            # Create services pool as a JSON database
            self.__create_services_pool(num_of_services=num_of_services)

            if not self.services_pool:
                raise ValueError(f"Services pool is empty.")

            # Create and start services
            for service in self.services_pool:
                connection_protocol, ip_address, port, service_name, is_registered = self.__parse_services_configs(service=service)
                self.__create_service(connection_protocol=connection_protocol,
                                      ip_address=ip_address,
                                      port=port,
                                      service_name=service_name,
                                      is_registered=is_registered,
                                      debug_mode=self.debug_mode)

            self.start_services()

        except Exception as e:
            raise CustomException(error_msg=f"Unable to run {self.__class__.__name__}.", exception=e)


class ServiceManagerError(Exception):
    """Auxiliary Exception class to handle Service Manager exceptions more precisely."""
    pass

