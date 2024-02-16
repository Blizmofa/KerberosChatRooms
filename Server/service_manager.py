from time import sleep
import json
from typing import Optional
from Utils import utils
from Utils.logger import Logger
from Utils.utils import check_if_exists, update_template_values
from Utils.custom_exception_handler import CustomException
from Utils.validator import Constants as ValConsts
from Utils.encryptor import Encryptor
from Socket.custom_socket import Thread
from Protocol_Handler.protocol_utils import ProtocolConstants as ProtoConsts
from Server.MsgServer.msg_server_core import MsgServer
from Server.MsgServer.msg_server_constants import service_manager_template, Constants as MsgConsts


class ServiceManager:
    def __init__(self, debug_mode: bool) -> None:
        self.debug_mode = debug_mode
        self.active_services = []
        self.encryptor = Encryptor(debug_mode=debug_mode)
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)

    def create_default_msg_server(self, connection_protocol: str) -> dict:
        """Creates a registered default Msg server in case of system failure."""
        try:
            # Create service formatter
            service_template = service_manager_template.copy()

            # Create default server data
            default_server_id = utils.generate_uuid()
            default_aes_key = self.encryptor.generate_bytes_stream(size=ProtoConsts.SIZE_AES_KEY)
            default_server_name = MsgConsts.DEF_SERVER_NAME

            msg_info_data = {
                ValConsts.FMT_IPV4_PORT: f"{MsgConsts.DEF_IP_ADDRESS}:{MsgConsts.DEF_PORT_NUM}",
                ValConsts.FMT_NAME: default_server_name,
                ValConsts.FMT_ID: default_server_id.hex(),
                ValConsts.FMT_AES_KEY: self.encryptor.encode_decode_base64(value=default_aes_key,
                                                                           mode=ProtoConsts.ENCODE)
            }

            # Create default service object and register it
            utils.create_info_file(file_name=f"{MsgConsts.MSG_FILE_NAME}", file_data=msg_info_data)
            service_template[MsgConsts.CONNECTION_PROTOCOL] = connection_protocol
            service_template[MsgConsts.RAM_IP_ADDRESS] = str(MsgConsts.DEF_IP_ADDRESS)
            service_template[MsgConsts.AUTH_PORT] = MsgConsts.DEF_PORT_NUM
            service_template[MsgConsts.RAM_SERVICE_NAME] = default_server_name
            service_template[MsgConsts.RAM_IS_REGISTERED] = True
            # TODO - in auth server, if is registered dont enter registration method
            service_template.update(update_template_values(template=service_template,
                                                           current_value=MsgConsts.FMT_ME,
                                                           new_value=None))
            return service_template

        except Exception as e:
            raise CustomException(error_msg=f"Unable to create default {self.__class__.__name__}.", exception=e)

    def create_service(self, connection_protocol: str, ip_address: str, port: int, service_name: str, debug_mode: Optional[bool] = False):
        try:
            service = MsgServer(connection_protocol=connection_protocol,
                                ip_address=ip_address,
                                port=port,
                                service_name=service_name,
                                debug_mode=debug_mode)
            service_thread = Thread(target=self.run_service, args=(service, ))
            self.logger.logger.info(f"Created service {service.service_name} successfully.")
            self.active_services.append(service_thread)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to create service {service_name}.", exception=e)

    def run_service(self, service: MsgServer) -> None:
        service.run()
        self.logger.logger.info(f"Started service {service.service_name} successfully.")

    def start_services(self):
        for service_thread in self.active_services:
            sleep(5)
            service_thread.start()

    def stop_services(self):
        for service_thread in self.active_services:
            service_thread.join()

    def create_service_pool(self, num_of_services: int, connection_protocol: str,
                            auth_server_ip_address: str,
                            auth_server_port: int, service_name_prefix: str):
        # Create default server
        services_pool = [self.create_default_msg_server(connection_protocol=connection_protocol)]

        # TODO - add max services, lets say 10, validate with validator
        for service in range(num_of_services):
            # TODO - Refactor to a method, also id default server
            service_template = service_manager_template.copy()
            service_template[MsgConsts.CONNECTION_PROTOCOL] = connection_protocol
            service_template[MsgConsts.RAM_IP_ADDRESS] = auth_server_ip_address
            service_template[MsgConsts.AUTH_PORT] = int(auth_server_port)
            service_template[MsgConsts.RAM_SERVICE_NAME] = f"{service_name_prefix}{service + 1}0"
            service_template[MsgConsts.RAM_IS_REGISTERED] = False
            service_template.update(update_template_values(template=service_template,
                                                           current_value=MsgConsts.FMT_ME,
                                                           new_value=None))
            services_pool.append(service_template)

        with open(MsgConsts.SERVICE_POOL_FILE_NAME, 'w') as sp:
            json.dump(services_pool, sp, indent=2)

    def parse_services_configs(self, service: dict) -> tuple:
        connection_protocol = service.get(MsgConsts.CONNECTION_PROTOCOL)
        ip_address = service.get(MsgConsts.RAM_IP_ADDRESS)
        port = service.get(MsgConsts.AUTH_PORT)
        service_name = service.get(MsgConsts.RAM_SERVICE_NAME)
        return connection_protocol, ip_address, port, service_name

    def run(self) -> None:

        if not check_if_exists(path_to_check=MsgConsts.SERVICE_POOL_FILE_NAME):
            raise OSError(f"{MsgConsts.SERVICE_POOL_FILE_NAME} does not exists, "
                          f"please run again {self.__class__.__name__} to create it.")

        with open(MsgConsts.SERVICE_POOL_FILE_NAME, 'r') as f:
            services = json.load(f)

        if not services:
            raise ValueError(f"Services pool is empty.")

        for service in services:
            connection_protocol, ip_address, port, service_name = self.parse_services_configs(service=service)
            self.create_service(connection_protocol=connection_protocol,
                                ip_address=ip_address,
                                port=port,
                                service_name=service_name,
                                debug_mode=self.debug_mode)

        self.start_services()


