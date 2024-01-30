import json
from os import path as os_path, makedirs
from typing import Optional, Tuple, Union, Any
from secrets import token_bytes
from uuid import uuid4
from binascii import hexlify, unhexlify
from datetime import datetime, timedelta
from Utils.custom_exception_handler import CustomException
from Utils.validator import Validator, ValidatorConstants, validator_config_template
from Protocol_Handler.protocol_utils import Constants

DEFAULT_NUM_OF_LINES = 1
DATE_TIME_FMT = "%d/%m/%y_%H:%M:%S"


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


def get_port_num(port_file: str) -> int:
    try:
        with open(port_file, 'r') as pf:
            lines = pf.readlines()

        # Port file can have only one line
        if len(lines) is not DEFAULT_NUM_OF_LINES:
            raise ValueError(f"'{port_file}' can contain only one line.")

        # Parse port from file
        port = int(lines[0])
        if not Validator.validate_injection(data_type=ValidatorConstants.FMT_PORT, value_to_validate=port,
                                            config_template=validator_config_template):
            raise ValueError(f"Invalid port number! {port} should be an integer value between "
                             f"{ValidatorConstants.PORT_LOWER_BOUND} and {ValidatorConstants.PORT_UPPER_BOUND}.")

        return port

    except Exception as e:
        raise CustomException(error_msg=f"Unable to get port number from '{port_file}'.", exception=e)


def generate_uuid() -> bytes:
    return uuid4().bytes


def generate_nonce(size: Optional[int] = 8):
    return token_bytes(size)


def convert_bytes_or_hex(data: Union[bytes, str], mode: str, decode_fmt: Optional[str] = 'utf-8'):
    if mode == Constants.HEX and isinstance(data, bytes):
        return hexlify(data).decode(decode_fmt)
    elif mode == Constants.BYTES and isinstance(data, str):
        return unhexlify(data)
    else:
        raise ValueError(f"Unable to convert {data} to {mode}.")


def time_now() -> str:
    return datetime.now().strftime(DATE_TIME_FMT)


def expiration_time(days_buffer: int) -> str:
    exp_time = datetime.now() + timedelta(days=days_buffer)
    return exp_time.strftime(DATE_TIME_FMT)


def is_expired(time: str) -> bool:
    return datetime.strptime(time, DATE_TIME_FMT) <= datetime.now()


def parse_ip_and_port(ip_and_port: str) -> Tuple[str, int]:
    ip, port = ip_and_port.split(':')
    return ip, port


def reset_template_values(template: dict, value_to_update: Any, reset_as_type: Optional[bool] = False):
    for value in template.values():
        if reset_as_type:
            wanted_type = value['type']
        else:
            wanted_type = value_to_update
        value['content'] = wanted_type
    return template


def update_template_values(template: dict, current_value: Any, new_value: Any) -> dict:
    # TODO - same method in protocol handler
    updated_template = {}
    for key, value in template.items():

        if value is not current_value:
            updated_template[key] = value
        else:
            updated_template[key] = new_value

    return updated_template


def create_info_file(file_name: str, file_data: dict) -> None:
    try:
        with open(file_name, 'w') as info_file:
            for key, value in file_data.items():
                Validator.validate_injection(data_type=key, value_to_validate=value)
                info_file.write(f"{value}\n")
    except Exception as e:
        raise CustomException(error_msg=f"Unable to create '{file_name}'.", exception=e)


# TODO - refactor
def parse_info_file(file_path: str, target_line_number: Optional[int] = None) -> Union[dict, str, None]:
    file_data = {}
    try:
        with open(file_path, 'r') as info_file:
            lines = info_file.readlines()

            for line_number, line in enumerate(lines, start=1):
                file_data[line_number] = line.strip()

                if target_line_number is not None and line_number == target_line_number:
                    return line.strip()

                if target_line_number is not None and target_line_number > len(lines):
                    return None

        return file_data

    except Exception as e:
        raise CustomException(error_msg=f"Unable to parse file {file_path}.", exception=e)


def search_value_in_file(value: str, file_path: str) -> bool:
    if check_if_exists(file_path):
        with open(file_path, 'r') as f:
            lines = f.readlines()
        for line in lines:
            if value in line:
                return True

    return False


def insert_value_into_file(value: str, target_line: int, file_path: str, max_lines: int) -> None:
    if check_if_exists(file_path):
        with open(file_path, 'r') as file:
            lines = file.readlines()

        if 1 <= target_line <= len(lines) + 1:
            lines.insert(target_line - 1, f"{value}\n")

            # Truncate the lines list if max_lines is specified
            if max_lines is not None and len(lines) > max_lines:
                lines = lines[:max_lines]

            with open(file_path, 'w') as file:
                file.writelines(lines)

        else:
            print(f"Error: Line number {target_line} is out of range.")


def insert_data_to_ram_db(ram_template: dict, data: dict) -> None:
    if not isinstance(data, dict):
        raise ValueError(
            f"Unable to insert data into RAM db, data should be of type dict and not of type {type(data)}.")
    for key, value in data.items():
        if key in ram_template and value is not None:
            ram_template[key] = value


def insert_data_to_file_db(file_path: str, data: dict) -> None:
    if not isinstance(data, dict):
        raise ValueError(
            f"Unable to insert data into file {file_path}, data should be of type dict and not of type {type(data)}.")
    if not check_if_exists(path_to_check=file_path):
        create_if_not_exists(path_to_create=file_path, is_file=True)
    with open(file_path, 'a') as f:
        for index, value in enumerate(data.values()):
            f.write(f"{value}")
            if index < len(data) - 1:
                f.write(': ')
        f.write('\n')


def insert_data_to_json_db(file_path: str, data: dict, pivot_key: str, pivot_value: Any) -> None:
    if not isinstance(data, dict):
        raise ValueError(
            f"Unable to insert data into file {file_path}, data should be of type dict and not of type {type(data)}.")
    if not check_if_exists(path_to_check=file_path):
        raise FileNotFoundError(f"Unable to find file '{file_path}'.")

    with open(file_path, 'r') as input_file:
        file_data = json.load(input_file)

    for item in file_data:
        if item[pivot_key] == pivot_value:
            for key, value in data.items():
                if key in item and value is not None:
                    item[key] = value

    with open(file_path, 'w') as output_file:
        json.dump(file_data, output_file, indent=2)

def get_list_index(data_list: list, value: Any) -> int:
    if data_list:
        if value not in data_list:
            raise ValueError(f"{value} is not in {data_list}.")
        return data_list.index(value)
    else:
        raise ValueError(f"List {data_list} is empty.")