from unittest import TestCase, main as unittest_main
from sys import path
path.append('..')
from Protocol_Handler.protocol_constants import ProtoConsts
from Socket.custom_socket import CustomSocket, SOCK_STREAM, SOCK_DGRAM, socket


class TestCustomSocket(TestCase):

    def test_set_socket_protocol_tcp(self) -> None:
        custom_socket = CustomSocket(connection_protocol=ProtoConsts.PROTO_TCP, debug_mode=False)
        self.assertEqual(custom_socket.set_socket_protocol(), SOCK_STREAM)

    def test_set_socket_protocol_udp(self) -> None:
        custom_socket = CustomSocket(connection_protocol=ProtoConsts.PROTO_UDP, debug_mode=False)
        self.assertEqual(custom_socket.set_socket_protocol(), SOCK_DGRAM)

    def test_set_socket_protocol_invalid(self) -> None:
        custom_socket = CustomSocket(connection_protocol="invalid_protocol", debug_mode=False)
        with self.assertRaises(ValueError) as context:
            custom_socket.set_socket_protocol()

        self.assertEqual(str(context.exception), "Unsupported connection protocol 'invalid_protocol'.")

    def test_create_socket(self) -> None:
        custom_socket = CustomSocket(connection_protocol=ProtoConsts.PROTO_TCP, debug_mode=False)
        self.assertIsInstance(custom_socket.create_socket(), socket)


if __name__ == "__main__":
    unittest_main(verbosity=2)