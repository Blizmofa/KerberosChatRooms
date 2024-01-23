import struct
from struct import pack, unpack
from typing import Optional, Tuple, Union
from Protocol_Handler.protocol_interface import ProtocolHandlerInterfaces
from Protocol_Handler.protocol_utils import ProtocolConstants, server_request, \
    packet_formatter_template, code_to_payload_template
from Utils.logger import Logger
from Utils.custom_exception_handler import CustomException
from Utils.utils import get_list_index


class ProtocolHandler(ProtocolHandlerInterfaces):

    def __init__(self, debug_mode: bool) -> None:
        self.class_logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)

    def pack_request(self, code: int, data: dict, formatter: dict) -> bytes:
        try:
            fmt, values = self.serialize_packet(code=code, data=data, formatter=formatter)
            packed_data = pack(fmt, *values)
            self.class_logger.logger.debug(f"Packed packet '{code}' successfully.")
            return packed_data

        except Exception as e:
            raise CustomException(error_msg=f"Unable to pack packet '{code}'.", exception=e)

    def unpack_request(self, received_packet: bytes, formatter: dict, code: Optional[int] = None,
                       deserialize: Optional[bool] = False) -> Union[dict, tuple]:
        try:

            fmt = self.generate_packet_fmt(raw_packet=self.build_packet_format(code=code, formatter=formatter))

            # Adjust unpack format sizes
            # TODO - at the end, refactor into validate method
            if len(received_packet) != struct.calcsize(fmt):
                temp = len(received_packet) - struct.calcsize(fmt)
                if temp > 255:
                    remainder = temp % 255
                    fmt += f"{temp-remainder}s{remainder}s"
                else:
                    fmt += f"{temp}s"

            unpacked = unpack(fmt, received_packet)
            self.class_logger.logger.debug(f"Unpacked packet '{code}' successfully.")

            # Return as formatted dictionary
            if deserialize:
                return self.clean_unpacked_data(unpacked_data=unpacked, formatter=formatter)

            # Return as raw tuple
            else:
                return unpacked

        except Exception as e:
            raise CustomException(error_msg=f"Unable to unpack '{code}'.", exception=e)

    def clean_unpacked_data(self, unpacked_data: tuple, formatter: dict) -> Tuple[int, dict]:
        # Deserialize the data
        deserialized = self.deserialize_packet(packet=unpacked_data)

        # Extract the code and format the packet structure
        code_index = get_list_index(data_list=list(formatter.keys()), value='code')
        code = deserialized[code_index]
        data = self.build_packet_format(code=code, formatter=formatter)

        # Insert and clean deserialized data into the formatted packet
        formatted_data = self.insert_unpacked_packet_content(data, deserialized)
        cleaned_data = self.remove_empty_data(data=formatted_data)
        return code, cleaned_data

    def deserialize_packet(self, packet: tuple) -> tuple:
        """
        Process each element in the tuple and decode bytes to a string
        only if null bytes are present.
        """
        deserialized_data = []

        for element in packet:
            if isinstance(element, bytes) and b'\x00' in element:
                deserialized_data.append(element.decode('utf-8', 'ignore').rstrip('\x00'))
            else:
                deserialized_data.append(element)

        return tuple(deserialized_data)

    def build_packet_format(self, code: int, formatter: dict) -> dict:
        # Create a copy of the packet
        packet = formatter.copy()

        # For no payload response
        if code is None or code in ProtocolConstants.NO_PAYLOAD_CODE_RESPONSES:
            return packet

        # Insert the payload according to the code
        else:
            packet.update(self.get_code_payload(code=code))
            return packet

    def serialize_packet(self, code: int, data: dict, formatter: dict) -> Tuple[str, list]:
        # Build packet format according to the code
        packet = self.build_packet_format(code=code, formatter=formatter)
        # Insert the data content
        packet.update(self.insert_packet_content(request_template=packet, data=data))

        # Serialize packet content
        packet.update(self.serialize_content(packet=packet))

        # Get packet fmt and content
        packet_fmt = self.generate_packet_fmt(raw_packet=packet)
        packet_content = self.get_packet_content(raw_packet=packet)

        # Return the pack format and content
        return packet_fmt, packet_content

    def get_code_payload(self, code: int, payloads_template: Optional[dict] = code_to_payload_template) -> dict:
        if not isinstance(payloads_template, dict):
            raise ValueError(f"{payloads_template} should be of type dict, not of type {type(payloads_template)}")

        if code in payloads_template:
            return payloads_template[code]
        else:
            raise ValueError(f"Unknown protocol code {code}.")

    def insert_packet_content(self, request_template: dict, data: dict) -> dict:
        for key, value in data.items():
            if key in request_template:
                request_template[key]["content"] = value
        return request_template

    def insert_unpacked_packet_content(self, data_format: dict, unpacked_packet: tuple):
        print(unpacked_packet)
        for index, key in enumerate(data_format.keys()):
            data_format[key] = unpacked_packet[index]
        return data_format

    def encode_value(self, value) -> Union[bytes, int]:
        if isinstance(value, str):
            return value.encode('utf-8')
        elif value is None:
            return b''
        else:
            return value
    def serialize_content(self, packet: dict):
        for key, value in packet.items():
            if "content" in value:
                new_value = self.encode_value(value["content"])
                packet[key]["content"] = new_value

        return packet

    def get_packet_content(self, raw_packet: dict) -> list:
        content_values = []
        for value in raw_packet.values():
            content_values.append(value["content"])
        return content_values

    def generate_packet_fmt(self, raw_packet: dict, formatter_template: Optional[dict] = packet_formatter_template,
                            network_type: Optional[str] = "little_endian") -> str:
        fmt = ""
        for key, value in raw_packet.items():
            size = value["size"]
            content_type = value["type"]
            if content_type == bytes or content_type == str:
                fmt += f"{size}{formatter_template[bytes]}"
            if size in formatter_template:
                fmt += formatter_template[size]

        return f"{formatter_template[network_type]}{fmt}"

    def remove_empty_data(self, data: dict) -> dict:
        for key, value in data.items():
            if value == b'' or value == '':
                data[key] = None
        return data