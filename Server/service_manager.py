from time import sleep
import json
from typing import Optional
from Socket.custom_socket import Thread
from Server.MsgServer.msg_server_core import MsgServer
from Server.MsgServer import msg_server_constants
from Utils.logger import Logger
from Utils.utils import create_if_not_exists, check_if_exists
from Utils.custom_exception_handler import CustomException

# TODO - services_pool.json is a DB, insert server id, aes key, etc.


class ServiceManager:
    def __init__(self, debug_mode: bool) -> None:
        self.active_services = []
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)

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

    def create_service_pool(self, num_of_services: int, auth_server_ip_address: str,
                            auth_server_port: int, service_name_prefix: str):
        pool = []
        for service in range(num_of_services):
            service_template = msg_server_constants.service_manager_template.copy()
            service_template[msg_server_constants.Constants.CONNECTION_PROTOCOL] = "tcp"
            service_template[msg_server_constants.Constants.IP_ADDRESS] = auth_server_ip_address
            service_template[msg_server_constants.Constants.PORT] = auth_server_port
            service_template[msg_server_constants.Constants.SERVICE_NAME] = f"{service_name_prefix} {service+1}0"
            service_template[msg_server_constants.Constants.SERVICE_ID] = None
            service_template[msg_server_constants.Constants.IS_REGISTERED] = False
            service_template[msg_server_constants.Constants.AES_KEY] = None
            pool.append(service_template)

        with open(msg_server_constants.Constants.SERVICE_POOL_FILE_NAME, 'w') as sp:
            json.dump(pool, sp, indent=2)

    def parse_services_configs(self, service: dict) -> tuple:
        connection_protocol = service.get(msg_server_constants.Constants.CONNECTION_PROTOCOL)
        ip_address = service.get(msg_server_constants.Constants.IP_ADDRESS)
        port = service.get(msg_server_constants.Constants.PORT)
        service_name = service.get(msg_server_constants.Constants.SERVICE_NAME)
        return connection_protocol, ip_address, port, service_name

    def run(self, mode: str) -> None:
        if not check_if_exists(path_to_check=msg_server_constants.Constants.SERVICE_POOL_FILE_NAME):
            raise OSError(f"{msg_server_constants.Constants.SERVICE_POOL_FILE_NAME} does not exists, "
                          f"please run again {self.__class__.__name__} to create it.")

        with open(msg_server_constants.Constants.SERVICE_POOL_FILE_NAME, 'r') as f:
            services = json.load(f)

        if not services:
            raise ValueError(f"Services pool is empty.")

        if mode == "all":
            for service in services:
                connection_protocol, ip_address, port, service_name = self.parse_services_configs(service=service)
                self.create_service(connection_protocol=connection_protocol,
                                    ip_address=ip_address,
                                    port=port,
                                    service_name=service_name)
        elif mode == "one":
            connection_protocol, ip_address, port, service_name = self.parse_services_configs(service=services[0])
            self.create_service(connection_protocol=connection_protocol,
                                ip_address=ip_address,
                                port=port,
                                service_name=service_name)
        self.start_services()


