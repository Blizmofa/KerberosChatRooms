from sys import path
path.append('..')
from Utils.custom_exception_handler import CustomException


def divide_by_zero():
    try:
        return 2 / 0

    except Exception as e:
        raise CustomException(error_msg=f"Unable to divide by zero.", exception=e)


class TestClass:

    def test_method(self):
        try:
            return 2 / 0

        except Exception as e:
            raise CustomException(error_msg="Test Custom Exception Output.", exception=ZeroDivisionError(e))


if __name__ == "__main__":

    test_class = TestClass()
    test_class.test_method()

    try:
        divide_by_zero()
    except Exception as e:
        print(e)




