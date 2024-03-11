from Client.client_constants import CConsts


class ClientInput:
    """Auxiliary Class that Handles all client input logic."""

    @staticmethod
    def show_client_menu():
        # with self.lock:
        print(f"{'#'}" * 40)
        print(f"# Available client options: ")
        # print(f"# __________________________")
        print(f"# {CConsts.IN_REQ_REGISTER}. Register to Authentication Server.")
        print(f"# {CConsts.IN_REQ_SERVICES_LIST}. Get available Services.")
        print(f"# {CConsts.IN_REQ_AES_KEY_CONNECT}. Request Service AES key and connect to Service.")
        print(f"# {CConsts.IN_QUIT}. Quit.")
        print(f"{'#'}" * 40)

        # Get client input
        client_input = input(f"Please enter your choice: ")
        if not client_input:
            return None
        return int(client_input)

    @staticmethod
    def get_service_name(services_list: list) -> dict:
        # Validate service list
        if not services_list:
            raise ValueError(f"Services list {services_list} is empty.")

        # Print the available services
        for index, service in enumerate(services_list, start=1):
            if CConsts.RAM_SERVER_NAME in service:
                print(f"{index}. {service[CConsts.RAM_SERVER_NAME]}")

        # Get user choice
        selected_server = int(input("Please select the wanted service: "))

        # # Validate and return the service object
        if 1 <= selected_server <= len(services_list):
            selected_name = services_list[selected_server - 1].get(CConsts.RAM_SERVER_NAME)

            return next(obj for obj in services_list if obj.get(CConsts.RAM_SERVER_NAME) == selected_name)

    @staticmethod
    def get_client_input(suffix: str) -> str:
        return input(f"Enter your {suffix}: ")

