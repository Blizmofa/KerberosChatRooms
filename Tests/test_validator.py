from unittest import TestCase, main as unittest_main
from sys import path
path.append('..')
from Utils.validator import Validator, ValidatorConstants, validator_config_template, ValidatorError


class TestValidator(TestCase):

    def setUp(self) -> None:
        self.validator_object = Validator(config_data=validator_config_template)
        self.validator_injection = Validator()

    def test_validator_exception(self) -> None:
        with self.assertRaises(ValidatorError) as context:
            self.validator_object.validate(data_type=ValidatorConstants.FMT_IPV4_PORT,
                                           value_to_validate='127.0.0.1:80000')
        self.assertEqual(str(context.exception), "Unable to validate '127.0.0.1:80000', "
                                                 "Error: Invalid IP or Port: Port number 80000 must be between 1 and "
                                                 "65535.")

    def test_validate_ip_and_port(self) -> None:
        self.assertTrue(self.validator_object.validate(data_type=ValidatorConstants.FMT_IPV4_PORT,
                                                       value_to_validate='127.0.0.1:8000'))
        self.assertTrue(self.validator_injection.validate(data_type=ValidatorConstants.FMT_IPV4_PORT,
                                                          value_to_validate='127.0.0.1:8000',
                                                          config_template={
                                                              1: {"value": ValidatorConstants.FMT_IPV4_PORT,
                                                                  "type": str, "max_length": 21}}))

    def test_validate_port_range(self) -> None:
        self.assertTrue(self.validator_object.validate(data_type=ValidatorConstants.FMT_PORT, value_to_validate=8000))
        self.assertTrue(
            self.validator_injection.validate(data_type=ValidatorConstants.FMT_PORT, value_to_validate=65535,
                                              config_template={1: {"value": ValidatorConstants.FMT_PORT, "type": int}}))
        self.assertTrue(self.validator_object.validate(data_type=ValidatorConstants.FMT_PORT, value_to_validate=1))
        self.assertFalse(self.validator_object.validate(data_type=ValidatorConstants.FMT_PORT, value_to_validate=80000))
        self.assertFalse(self.validator_object.validate(data_type=ValidatorConstants.FMT_PORT, value_to_validate=-1))


if __name__ == '__main__':
    unittest_main(verbosity=2)
