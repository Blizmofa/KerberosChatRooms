from unittest import TestCase, main as unittest_main
from sys import path
path.append('..')
from Socket.custom_socket import CustomSocket, PROTO_TCP, PROTO_UDP, SOCK_STREAM, SOCK_DGRAM


class TestCustomSocket(TestCase):

    def test_set_socket_protocol_tcp(self) -> None:
        custom_socket = CustomSocket(connection_protocol=PROTO_TCP)
        self.assertEqual(custom_socket.set_socket_protocol(), SOCK_STREAM)

    def test_set_socket_protocol_udp(self) -> None:
        custom_socket = CustomSocket(connection_protocol=PROTO_UDP)
        self.assertEqual(custom_socket.set_socket_protocol(), SOCK_DGRAM)

    def test_set_socket_protocol_invalid(self) -> None:
        custom_socket = CustomSocket(connection_protocol="invalid_protocol")
        with self.assertRaises(ValueError) as context:
            custom_socket.set_socket_protocol()

        self.assertEqual(str(context.exception), "Unsupported connection protocol 'invalid_protocol'.")


if __name__ == "__main__":
    unittest_main(verbosity=2)