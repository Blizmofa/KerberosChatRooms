from inspect import getframeinfo, currentframe


class CustomException(Exception):

    def __init__(self, error_msg: str, exception: Exception) -> None:
        self.error_msg = error_msg
        self.exception = exception
        super().__init__(error_msg)

    def __str__(self):
        frame_info = getframeinfo(currentframe().f_back)
        return f"{'#'*40}\nException was Raised:\n - File: {frame_info.filename}\n - Line: {frame_info.lineno}\n " \
               f"- Error: {self.error_msg}\n - Exception: {str(self.exception)}\n{'#'*40}"
