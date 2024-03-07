from sys import exc_info
from typing import Optional, Any, Union
from inspect import currentframe, getframeinfo, FrameInfo
from traceback import extract_tb

FMT_INDENTATION = ' '*2


class CustomException(Exception):
    """Raises high level and vey informative exceptions."""

    def __init__(self, error_msg: str, exception: Optional[Any] = None) -> None:
        self.caller_frame = currentframe().f_back
        method_info = self.get_method_info(self.caller_frame)
        full_error_msg = f"Error: {error_msg}\nInfo: {method_info}\nException: {str(exception)}\n"
        super().__init__(full_error_msg)

    def get_method_info(self, frame: FrameInfo.frame) -> str:
        """Return a formatted exception message."""
        # Get calling method info
        caller_info = getframeinfo(frame)

        # Get calling method name
        method_name = frame.f_code.co_name

        # Get calling class name
        class_name = frame.f_locals.get('self', None).__class__.__name__

        # Format and return
        function_info = f"Function: '{class_name}.{method_name}" if class_name else f"Function: '{method_name}'"
        error_line_content, error_line_number = self.get_error_line_content_and_number(caller_info.filename)
        return (f"\n{FMT_INDENTATION}- File: {caller_info.filename}\n{FMT_INDENTATION}- Info: {function_info}\n"
                f"{FMT_INDENTATION}- Line Number: {error_line_number}\n{FMT_INDENTATION}- Code Line: {error_line_content}")

    def get_error_line_content_and_number(self, source_file_name: str) -> Union[list, str]:
        """Returns the code line content and number that triggered the exception."""
        # Get current exception traceback
        exc_type, exc_value, exc_traceback = exc_info()
        tb = extract_tb(exc_traceback)

        # Get last frame content
        if tb:
            error_frame = tb[-1]
            error_line_number = error_frame.lineno
            error_line_content = self.get_exception_source_line(source_file_name, error_line_number)
            return [error_line_content, error_line_number]

        return "Error line content is not available."

    @staticmethod
    def get_exception_source_line(source_file_name: str, source_line_number: int) -> str:
        """Returns the error code source line."""
        with open(source_file_name, 'r') as sf:
            lines = sf.readlines()

        if 1 <= source_line_number <= len(lines):
            return lines[source_line_number-1].strip()
        return ""


def get_calling_method_name():
    """Return the calling method name."""
    return currentframe().f_back.f_code.co_name