from logging import getLogger, basicConfig, INFO, DEBUG, Filter
from os import path


LOG_FILE_FMT = "[%(asctime)s] - [%(name)s] - [%(levelname)s] --- [%(custom_attribute)s]: %(message)s"
LOG_DATE_FMT = "%d/%m/%y %H:%M:%S"
LOG_FILE = "kerberos.log"


class Logger:
    """Handles logging for the entire project, based on python logging library."""

    def __init__(self, logger_name: str, debug_mode: bool) -> None:
        # Create logger
        self.logger = getLogger(logger_name)
        self.log_file_mode = self.set_log_file_mode(LOG_FILE)
        # Set level and format
        self.log_level = self.set_log_level(debug_mode)
        self.log_format = LOG_FILE_FMT
        self.date_format = LOG_DATE_FMT
        self.logger.addFilter(CustomFilter())
        basicConfig(filename=LOG_FILE, filemode=self.log_file_mode, level=self.log_level,
                    format=self.log_format, datefmt=self.date_format)

    @staticmethod
    def set_log_file_mode(log_file: str) -> str:
        """Sets the log file mode."""
        if path.exists(log_file):
            return 'a'
        else:
            return 'w'

    @staticmethod
    def set_log_level(debug_mode: bool) -> int:
        """Sets the log level according to the config file."""
        if debug_mode:
            return DEBUG
        return INFO


class CustomFilter(Filter):
    """Adds a custom attribute log entry to associate log message to a specific component."""

    # Server will format this name according to the new connected client
    filter_name = None

    def filter(self, record) -> bool:
        record.custom_attribute = self.filter_name
        return True
