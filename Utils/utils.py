from os import path as os_path, makedirs
from typing import Optional
from uuid import uuid4
from datetime import datetime
from Utils.custom_exception_handler import CustomException

PORT_UPPER_BOUND = 65535
PORT_LOWER_BOUND = 0
DEFAULT_NUM_OF_LINES = 1
DATE_TIME_FMT = "%d/%m/%y %H:%M:%S"


def check_if_exists(path_to_check: str) -> bool:
    return os_path.exists(path_to_check)


def create_if_not_exists(path_to_create: str, is_file: Optional[bool] = False, is_dir: Optional[bool] = False) -> None:
    # Path exists
    if check_if_exists(path_to_check=path_to_create):
        return

    # Create empty file
    elif is_file:
        with open(path_to_create, 'w'):
            pass

    # Create empty directory
    elif is_dir:
        makedirs(path_to_create, exist_ok=True)

    else:
        raise ValueError(f"You must indicate if '{path_to_create}' is a directory or a file.")


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


def generate_client_uuid() -> bytes:
    return uuid4().bytes


def last_seen() -> str:
    return datetime.now().strftime(DATE_TIME_FMT)


def process_bytes(input_data: bytes) -> str:
    if not isinstance(input_data, bytes):
        raise ValueError(f"{input_data} must be of type bytes, not of type {type(input_data)}.")
    # Convert bytes to string and remove null bytes
    return input_data.decode('utf-8', 'ignore').rstrip('\x00')


def process_bytes_tuple(tuple_data: tuple) -> tuple:
    """Process each element in the tuple and decode bytes to string, remove null bytes."""
    return tuple(
        element.decode('utf-8', 'ignore').rstrip('\x00')
        if isinstance(element, bytes) else element
        for element in tuple_data
    )
