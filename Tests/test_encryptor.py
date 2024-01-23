from unittest import TestCase, main as unittest_main
from sys import path
path.append('..')
from Utils.encryptor import Encryptor, get_random_bytes


class TestEncryptor(TestCase):

    def test_generate_bytes_stream(self) -> None:
        bytes_stream_default = Encryptor.generate_bytes_stream()
        self.assertEqual(len(bytes_stream_default), 16)
        self.assertEqual(type(bytes_stream_default), bytes)
        bytes_stream = Encryptor.generate_bytes_stream(32)
        self.assertEqual(len(bytes_stream), 32)

    def test_hash_password(self) -> None:
        str_hashed_password = Encryptor.hash_password(password="qwer1234")
        self.assertEqual(type(str_hashed_password), bytes)
        self.assertEqual(len(str_hashed_password), 32)
        bytes_hashed_password = Encryptor.hash_password(password=b'qwer1234')
        self.assertEqual(type(bytes_hashed_password), bytes)


if __name__ == '__main__':
    unittest_main(verbosity=2)