from sys import exit as sys_exit
from Utils.utils import is_exists, create_info_file, parse_info_file
from Utils.validator import Validator, ValConsts
from Utils.custom_arg_parser import CustomArgParser, Namespace
from Protocol_Handler.protocol_constants import ProtoConsts
from Client.client_core import ClientCore
from Client.client_constants import CConsts


def get_client_args() -> Namespace:
    """Returns a Namespace with the Client parsed CLI arguments."""
    client_parser = CustomArgParser(description="Client argument parser.\n"
                                                f"Example Usage: python3 [path_to_client] -d -pr "
                                                f"{ProtoConsts.PROTO_TCP} -ip {ProtoConsts.LOCAL_HOST} -p {ProtoConsts.DEF_PORT_NUM}",
                                    supress_usage=True)
    client_parser.add_arg('-d', '--debug-mode', action='store_true',
                          help=client_parser.format_arg_help(general_description="For more informative logs and print statements.",
                                                             usage_example=f"python3 [path_to_client] -d/--debug_mode",
                                                             default_value="False"))
    client_parser.add_arg('-pr', '--protocol', type=str, nargs='?', default=ProtoConsts.PROTO_TCP,
                          help=client_parser.format_arg_help(general_description="For the KDC connection protocol.",
                                                             usage_example="python3 [path_to_client] -pr/--protocol [udp | tcp]"))
    client_parser.add_arg('-ip', '--ip-address', type=str, nargs='?', default=ProtoConsts.LOCAL_HOST,
                          help=client_parser.format_arg_help(general_description="For the KDC IP Address.",
                                                             usage_example="python3 [path_to_client] -ip/--ip-address [ip_address]"))
    client_parser.add_arg('-p', '--port', type=int, nargs='?', default=ProtoConsts.DEF_PORT_NUM,
                          help=client_parser.format_arg_help(general_description="For the KDC Port number.",
                                                             usage_example="python3 [path_to_client] -p/--port [port_number]"))
    client_parser.add_arg('-un', '--username', type=str, nargs='?', default=None,
                          help=client_parser.format_arg_help(general_description="For the Client username.",
                                                             usage_example="python3 [path_to_client] -un/--username [username]"))
    client_parser.add_arg('-pass', '--password', type=str, nargs='?', default=None,
                          help=client_parser.format_arg_help(general_description="For the Client password.",
                                                             usage_example="python3 [path_to_client] -pass/--password [password]"))
    return client_parser.parse_args()


def main():

    # Validate srv.info file
    if not is_exists(path_to_check=CConsts.AUTH_SERVER_FILE_NAME):
        create_info_file(file_name=CConsts.AUTH_SERVER_FILE_NAME,
                         file_data={ValConsts.FMT_IPV4_PORT: f"{ProtoConsts.LOCAL_HOST}:{ProtoConsts.DEF_PORT_NUM}"})

    try:
        # Fetch and validate KDC ip and port
        ip_port = parse_info_file(file_path=CConsts.AUTH_SERVER_FILE_NAME, target_line_number=1)
        ip_address, port = Validator.validate_injection(data_type=ValConsts.FMT_IPV4_PORT, value_to_validate=ip_port)

        # Get CLI args and set default values
        client_args = get_client_args()
        if client_args.ip_address and client_args.port:
            ip_address, port = client_args.ip_address, client_args.port

        # Create Client and connect to KDC
        client = ClientCore(connection_protocol=client_args.protocol,
                            server_ip=ip_address,
                            server_port=int(port),
                            debug_mode=client_args.debug_mode,
                            username=client_args.username,
                            password=client_args.password)
        client.run()

    except Exception as e:
        print(e)
        sys_exit(ProtoConsts.STATUS_ERROR_CODE)


if __name__ == "__main__":
    main()