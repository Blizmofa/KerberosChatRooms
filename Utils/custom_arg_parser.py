from typing import Optional
from argparse import ArgumentParser, RawTextHelpFormatter, SUPPRESS, Namespace


class CustomArgParser(ArgumentParser):
    """Custom helper Class to parse CLI arguments."""
    def __init__(self, description: str, wrapper: Optional[str] = '#', supress_usage: Optional[bool] = False) -> None:
        self.description = self.__format_description(description, wrapper_fmt=wrapper)
        usage = SUPPRESS if supress_usage else None
        super().__init__(description=self.description, usage=usage, formatter_class=RawTextHelpFormatter)

    def add_arg(self, *args, **kwargs) -> None:
        """Add arguments dynamically."""
        self.add_argument(*args, **kwargs)

    def parse_args(self, args=None, namespace=None):
        """Returns the parsed args as a Namespace."""
        parsed_args = super().parse_args(args, namespace)
        return parsed_args

    @staticmethod
    def format_arg_help(general_description: str, usage_example: str, default_value: Optional[str] = None) -> str:
        """Format help for arguments."""
        default_value_str = f"Default Value: {default_value if default_value is not None else '%(default)s'}"
        return f"{general_description}\nUsage Example: {usage_example}\n{default_value_str}"

    @staticmethod
    def __format_description(description: str, wrapper_fmt: str) -> str:
        """Returns a formatted description."""
        # Split the description into lines
        lines = description.splitlines()

        # Find the maximum length among all the lines
        max_length = max(len(line) for line in lines)

        # Create a wrapper
        wrapper = wrapper_fmt * (max_length + 4)

        # Format the parser description
        formatted_description = wrapper + '\n'
        for line in lines:
            formatted_description += f"# {line}\n"
        formatted_description += wrapper
        return formatted_description
