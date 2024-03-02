from typing import Union, Optional, Any
from socket import inet_ntoa, inet_aton
from struct import pack, unpack
from Protocol_Handler.protocol_constants import ProtoConsts
from Protocol_Handler.protocol_templates import code_to_payload_template, packet_bytes_index


def get_list_index(data_list: list, value: Any) -> Union[int, None]:
    """Returns the index of a given value in a given list."""
    if data_list:
        if value not in data_list:
            return None

        return data_list.index(value)
    else:
        raise ValueError(f"List {data_list} is empty.")


def get_bytes_value_index(code: int, bytes_indexes_template: Optional[dict] = packet_bytes_index) -> Union[int, None, tuple]:
    """Return the indexes of the bytes values in a packet according to the given code."""
    if code in bytes_indexes_template:
        return bytes_indexes_template[code]


def deserialize_packet(packet: tuple, index_to_pass: Optional[Union[int, tuple]] = None) -> tuple:
    """Return a tuple with the deserialized packet content."""
    deserialized_data = []

    for index, element in enumerate(packet):

        # For packed packets case
        if isinstance(element, bytes) and b'\x00' in element and isinstance(index_to_pass, tuple) and index in index_to_pass:
            deserialized_data.append(element)

        # For standalone value case
        elif isinstance(element, bytes) and b'\x00' in element and index != index_to_pass:
            deserialized_data.append(element.decode(ProtoConsts.UTF_8, 'ignore').rstrip('\x00'))

        else:
            deserialized_data.append(element)

    return tuple(deserialized_data)


def pack_unpack_ipv4(ip_address: Union[str, bytes], network_type: str, size: str, mode: str) -> Union[bytes, str]:
    """Serialize/Deserialize IPv4 from a str to bytes to fit size 4."""

    if mode == ProtoConsts.SERIALIZE and isinstance(ip_address, str):
        packed_ip = inet_aton(ip_address)
        return pack(f'{network_type}{size}', unpack(f'!{size}', packed_ip)[0])

    elif mode == ProtoConsts.DESERIALIZE and isinstance(ip_address, bytes):
        unpacked = unpack(f'{network_type}{size}', ip_address)
        return inet_ntoa(pack(f'!{size}', *unpacked))

    else:
        raise ValueError(f"Unsupported mode '{mode}' or type '{type(ip_address)}'.")


def get_code_payload(code: int, payloads_template: Optional[dict] = code_to_payload_template) -> Union[dict, None]:
    """Returns the protocol request/response code."""
    if not isinstance(payloads_template, dict):
        raise ValueError(f"{payloads_template} should be of type dict, not of type {type(payloads_template)}")

    if code in payloads_template:
        return payloads_template[code]

    if code in ProtoConsts.NO_PAYLOAD_CODE_RESPONSES:
        return

    else:
        raise ValueError(f"Unknown protocol code {code}.")


def insert_packet_content(request_template: dict, raw_data: dict) -> dict:
    """Inserts the given raw data into the packet request template. for packing purposes."""
    for key, value in raw_data.items():
        if key in request_template:
            request_template[key][ProtoConsts.CONTENT] = value
    return request_template


def insert_unpacked_packet_content(data_format: dict, unpacked_packet: tuple) -> dict:
    """Inserts the unpacked packet data into a dict template. for unpacking purposes."""
    for index, key in enumerate(data_format.keys()):
        data_format[key] = unpacked_packet[index]
    return data_format


def serialize_content(packet: dict) -> dict:
    """Serializes the packet content. for packing purposes."""
    for key, value in packet.items():
        if ProtoConsts.CONTENT in value:
            new_value = encode_value(value[ProtoConsts.CONTENT])
            packet[key][ProtoConsts.CONTENT] = new_value
    return packet


def encode_value(value: Union[str, int]) -> Union[bytes, int]:
    """Returns an encoded value according to its type."""
    if isinstance(value, str):
        return value.encode(ProtoConsts.UTF_8)
    elif value is None:
        return b''
    else:
        return value


def get_packet_content(raw_packet: dict) -> list:
    """Returns the raw packet content data. for packing purposes."""
    content_values = []
    for value in raw_packet.values():
        content_values.append(value[ProtoConsts.CONTENT])
    return content_values


def remove_empty_data(data: dict) -> dict:
    """Removes empty bytes or str data from deserialized packet. for unpacking purposes."""
    for key, value in data.items():
        if value == b'' or value == '':
            data[key] = None
    return data


