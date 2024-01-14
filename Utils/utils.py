from os import path as os_path
from Utils.custom_exception_handler import CustomException

PORT_UPPER_BOUND = 65535
PORT_LOWER_BOUND = 0
DEFAULT_NUM_OF_LINES = 1


def check_if_exists(path_to_check: str) -> bool:
    return os_path.exists(path_to_check)


def create_port_file(file_name: str, port_num: str) -> None:
    try:
        with open(file_name, 'w') as f:
            f.write(port_num)

    except Exception as e:
        raise CustomException(error_msg=f"Unable to create port file '{file_name}'", exception=e)


def validate_port_range(port: str) -> bool:
    port = int(port)
    if port < PORT_LOWER_BOUND or port > PORT_UPPER_BOUND:
        return False

    return True


def get_port_num(port_file: str) -> int:
    try:
        with open(port_file, 'r') as pf:
            lines = pf.readlines()

        # Port file can have only one line
        if len(lines) is not DEFAULT_NUM_OF_LINES:
            raise ValueError(f"'{port_file}' can contain only one line.")

        # Parse port from file
        port = lines[0]
        if not validate_port_range(port):
            raise ValueError(f"Invalid port number! {port} should be an integer value between "
                             f"{PORT_LOWER_BOUND} and {PORT_UPPER_BOUND}.")

        return int(port)

    except Exception as e:
        raise CustomException(error_msg=f"Unable to get port number from '{port_file}'.", exception=e)

