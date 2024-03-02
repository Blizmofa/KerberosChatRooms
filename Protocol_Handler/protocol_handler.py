from struct import pack, unpack, calcsize
from typing import Optional, Tuple, Union, Any
from Utils.utils import write_with_color, Colors
from Utils.logger import Logger, CustomFilter
from Utils.custom_exception_handler import CustomException, get_calling_method_name
from Protocol_Handler import protocol_utils
from Protocol_Handler.protocol_interface import ProtocolHandlerInterfaces
from Protocol_Handler.protocol_constants import ProtoConsts
from Protocol_Handler.protocol_templates import communication_protocol_template, code_to_payload_template, payload_buffer_template


class ProtocolHandler(ProtocolHandlerInterfaces):
    """Handles all the packets packing and unpacking logic and requirements according to the communication protocol."""

    def __init__(self, debug_mode: bool) -> None:
        self.debug_mode = debug_mode
        self.class_logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)

    def pack_request(self, code: int, data: dict, formatter: dict) -> bytes:
        """Main pack method, serializes and returned the packed packet according to a given formatter."""
        try:
            fmt, values = self.__serialize_packet(code=code, data=data, formatter=formatter)
            packed_data = pack(fmt, *values)

            # Set Logger custom filter
            CustomFilter.filter_name = get_calling_method_name()

            # For dev mode:
            if self.debug_mode:
                print(write_with_color(msg=f"Pack formatter --> {formatter}", color=Colors.BLUE))
                print(write_with_color(msg=f"Packed packet --> Code: {code}, Format: {fmt}, Data: {packed_data}",
                                       color=Colors.BLUE))

            self.class_logger.logger.debug(f"Packed packet '{code}' successfully.")
            return packed_data

        except Exception as e:
            raise CustomException(error_msg=f"Unable to pack packet '{code}'.", exception=e)

    def unpack_request(self, received_packet: bytes, formatter: dict, code: Optional[int] = None,
                       deserialize: Optional[bool] = False) -> Union[dict, tuple]:
        """Main unpack method, builds the unpack format from a given formatter
        and return the unpacked deserialized or raw data."""
        try:
            request_fmt = self.generate_packet_fmt(raw_packet=self.build_packet_format(code=code, formatter=formatter))
            fmt = self.__adjust_fmt(request_fmt, received_packet)
            unpacked = unpack(fmt, received_packet)

            # Set Logger custom filter
            CustomFilter.filter_name = get_calling_method_name()

            # For dev mode:
            if self.debug_mode:
                print(write_with_color(msg=f"Unpack formatter --> {formatter}", color=Colors.YELLOW))
                print(write_with_color(msg=f"Unpacked packet --> Code: {code}, Format: {fmt}, Data: {unpacked}",
                                       color=Colors.YELLOW))

            self.class_logger.logger.debug(f"Unpacked packet '{code}' successfully.")

            # Return as formatted dictionary
            if deserialize:
                return self.__clean_unpacked_data(unpacked_data=unpacked, formatter=formatter, code=code)

            # Return as raw tuple
            else:
                return unpacked

        except Exception as e:
            raise CustomException(error_msg=f"Unable to unpack '{code}'.", exception=e)

    def __adjust_fmt(self, fmt: str, packet: bytes, template: Optional[dict] = payload_buffer_template) -> str:
        """Returns the adjusted unpack format according to the payload size."""
        original_size = calcsize(fmt)
        if len(packet) != original_size:
            payload_buffer = len(packet) - original_size

            # For payload larger than 255 or with at least two entries
            if payload_buffer in template:
                fmt += template[payload_buffer]

            # For all other cases
            else:
                fmt += f"{payload_buffer}s"

        if self.debug_mode:
            print(write_with_color(msg=f"Adjusted format --> Packet Length: {len(packet)}, "
                                       f"Original Size: {original_size}, Format: {fmt}", color=Colors.GREEN))

        return fmt

    def __clean_unpacked_data(self, unpacked_data: tuple, formatter: dict, code: Optional[int] = None) -> Tuple[int, dict]:
        """Returns a tuple of the response code and the deserialized cleaned unpacked data as a JSON object."""
        # Extract the packet response code
        if code is None:
            code_index = protocol_utils.get_list_index(data_list=list(formatter.keys()), value=ProtoConsts.CODE)
            code = unpacked_data[code_index]
        else:
            code = code

        # Extract the packet header payload size
        payload_size_index = protocol_utils.get_list_index(data_list=list(formatter.keys()), value=ProtoConsts.PAYLOAD_SIZE)
        if payload_size_index:
            payload_size = unpacked_data[payload_size_index]
        else:
            payload_size = None

        # Extract indexes for bytes values
        bytes_index = protocol_utils.get_bytes_value_index(code=code)

        # Deserialize the rest  of the data
        deserialized = protocol_utils.deserialize_packet(packet=unpacked_data, index_to_pass=bytes_index)

        # format the packet structure
        formatted_data = self.build_packet_format(code=code, formatter=formatter, payload_size=payload_size)

        # Insert and clean deserialized data into the formatted packet
        formatted_data.update(protocol_utils.insert_unpacked_packet_content(formatted_data, deserialized))

        # Clean the formatted packet
        formatted_data.update(protocol_utils.remove_empty_data(data=formatted_data))

        # For dev mode:
        if self.debug_mode:
            print(write_with_color(msg=f"Deserialized Packet --> Code: {code}, Data: {formatted_data}",
                                   color=Colors.YELLOW))

        return code, formatted_data

    def build_packet_format(self, code: int, formatter: dict, payload_size: Optional[int] = None) -> dict:
        """Returns the adjusted packet formatter."""
        # For no payload response
        if code is None or code in ProtoConsts.NO_PAYLOAD_CODE_RESPONSES:
            return formatter

        # For response 1602
        if code == ProtoConsts.RES_MSG_SERVERS_LIST and payload_size:
            temp_formatter = code_to_payload_template[ProtoConsts.PKT_SERVERS_LIST].copy()
            temp_formatter.update(self.update_formatter_value(formatter=temp_formatter,
                                                              pivot_key=ProtoConsts.SERVERS_LIST,
                                                              pivot_value=ProtoConsts.SIZE,
                                                              new_value=payload_size))
            formatter.update(temp_formatter)
            return formatter

        # For response 1603
        if code == ProtoConsts.RES_ENCRYPTED_AES_KEY:
            temp_formatter = code_to_payload_template[code].copy()
            temp_formatter.update(self.update_formatter_value(formatter=temp_formatter,
                                                              pivot_key=ProtoConsts.ENCRYPTED_KEY,
                                                              pivot_value=ProtoConsts.SIZE,
                                                              new_value=ProtoConsts.SIZE_ENCRYPTED_KEY_PACKET))
            temp_formatter.update(self.update_formatter_value(formatter=temp_formatter,
                                                              pivot_key=ProtoConsts.TICKET,
                                                              pivot_value=ProtoConsts.SIZE,
                                                              new_value=ProtoConsts.SIZE_TICKET_PACKET))
            formatter.update(temp_formatter)
            return formatter

        # For request 1027
        if code == ProtoConsts.REQ_MSG_SERVER_AES_KEY:
            temp_formatter = code_to_payload_template[code].copy()
            temp_formatter.update(self.update_formatter_value(formatter=temp_formatter,
                                                              pivot_key=ProtoConsts.AUTHENTICATOR,
                                                              pivot_value=ProtoConsts.SIZE,
                                                              new_value=ProtoConsts.SIZE_AUTHENTICATOR_PACKET))
            temp_formatter.update(self.update_formatter_value(formatter=temp_formatter,
                                                              pivot_key=ProtoConsts.TICKET,
                                                              pivot_value=ProtoConsts.SIZE,
                                                              new_value=ProtoConsts.SIZE_TICKET_PACKET))
            formatter.update(temp_formatter)
            return formatter

        # For request 1029 without message content
        if code == ProtoConsts.PKT_ENC_MSG_WITHOUT_CONTENT:
            temp_formatter = code_to_payload_template[code].copy()
            formatter.update(temp_formatter)
            return formatter

        # Insert the payload according to the code
        else:
            formatter.update(protocol_utils.get_code_payload(code=code))
            return formatter

    def __serialize_packet(self, code: int, data: dict, formatter: dict) -> Tuple[str, list]:
        """Returns the packet needed pack format and data according to a given formatter."""

        # Build packet format according to the code
        packet = self.build_packet_format(code=code, formatter=formatter)

        # Insert the data content
        packet.update(protocol_utils.insert_packet_content(request_template=packet, raw_data=data))

        # Serialize packet content
        packet.update(protocol_utils.serialize_content(packet=packet))

        # Get packet fmt and content
        packet_fmt = self.generate_packet_fmt(raw_packet=packet)
        packet_content = protocol_utils.get_packet_content(raw_packet=packet)

        # For dev mode
        if self.debug_mode:
            print(write_with_color(msg=f"Serialized packet --> Code: {code}, Format: {packet_fmt}, data: {packet_content}",
                                   color=Colors.BLUE))

        # Return the pack format and content
        return packet_fmt, packet_content

    def deserialize_serialize_ipv4(self, formatter: dict, data: dict, mode: str,
                                   network_type: Optional[str] = ProtoConsts.LITTLE_ENDIAN) -> dict:
        """Deserializes or Serializes IPv4 value between str to bytes according to the passed mode."""

        for key, value in formatter.items():
            if key not in data:
                continue

            # Get IPv4 value from formatter, extract its content and adjust sizes
            if value.get(ProtoConsts.TYPE) == ProtoConsts.IPV4:
                fmt_network_type = communication_protocol_template[network_type]
                fmt_type = communication_protocol_template[value.get(ProtoConsts.TYPE)]
                size = formatter[key][ProtoConsts.SIZE]
                fmt_size = f"{size}{fmt_type}"

                # Serialize
                if mode == ProtoConsts.SERIALIZE and isinstance(data[key], str):
                    data[key] = protocol_utils.pack_unpack_ipv4(ip_address=data[key], network_type=fmt_network_type,
                                                                size=fmt_size, mode=mode)
                    # For dev mode
                    if self.debug_mode:
                        print(write_with_color(msg=f"Serialized --> {data[key]}", color=Colors.BLUE))

                # Deserialize
                elif mode == ProtoConsts.DESERIALIZE and isinstance(data[key], bytes):
                    data[key] = protocol_utils.pack_unpack_ipv4(ip_address=data[key], network_type=fmt_network_type,
                                                                size=fmt_size, mode=mode)
                    # For dev mode
                    if self.debug_mode:
                        print(write_with_color(msg=f"Deserialized --> {data[key]}", color=Colors.YELLOW))

                else:
                    raise ValueError(f"Unsupported mode '{mode}'.")

        return data

    def generate_packet_fmt(self, raw_packet: dict, protocol_template: Optional[dict] = communication_protocol_template,
                            network_type: Optional[str] = ProtoConsts.LITTLE_ENDIAN) -> str:
        """Generates the needed to unpack format according to the raw packet,
        a given formatter template and network type. for unpacking purposes."""
        fmt = ""
        # Get raw packet values
        for key, value in raw_packet.items():
            size = value[ProtoConsts.SIZE]
            content_type = value[ProtoConsts.TYPE]

            # Adjust sizes according to the protocol template.
            if content_type == bytes or content_type == str or content_type == ProtoConsts.IPV4:
                fmt += f"{size}{protocol_template[bytes]}"

            elif size in protocol_template:
                fmt += protocol_template[size]

        # For dev mode
        if self.debug_mode:
            print(write_with_color(msg=f"Generated packet format --> {protocol_template[network_type]}{fmt}",
                                   color=Colors.GREEN))

        return f"{protocol_template[network_type]}{fmt}"

    def update_formatter_value(self, formatter: dict, pivot_key: str, pivot_value: str, new_value: Any) -> dict:
        """Updated the formatter given value."""
        for key, value in formatter.items():
            if key == pivot_key and pivot_value in value:
                formatter[pivot_key][pivot_value] = new_value

                # For dev mode
                if self.debug_mode:
                    print(write_with_color(msg=f"Updated {formatter[pivot_key][pivot_value]} with {new_value}",
                                           color=Colors.GREEN))
        return formatter