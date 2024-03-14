from sys import exit as sys_exit
from Utils.utils import is_exists, create_info_file, parse_info_file
from Utils.validator import Validator, ValConsts
from Utils.custom_arg_parser import CustomArgParser, Namespace
from Protocol_Handler.protocol_constants import ProtoConsts as ProtoConsts
from Server.AuthServer.auth_server_constants import AuthConsts
from Server.AuthServer.auth_server_core import AuthServerCore


def get_kdc_args() -> Namespace:
    """Returns a Namespace with the KDC parsed CLI arguments."""
    kdc_parser = CustomArgParser(description="KDC argument parser.\n"
                                             f"Example Usage: python3 [path_to_kdc] -d -pr "
                                             f"{ProtoConsts.PROTO_TCP} -ip {ProtoConsts.LOCAL_HOST} -p {ProtoConsts.DEF_PORT_NUM}",
                                 supress_usage=True)
    kdc_parser.add_arg('-d', '--debug-mode', action='store_true',
                       help=kdc_parser.format_arg_help(general_description="For more informative logs and print statements.",
                                                       usage_example=f"python3 [path_to_kdc] -d/--debug_mode",
                                                       default_value="False"))
    kdc_parser.add_arg('-pr', '--protocol', type=str, nargs='?', default=ProtoConsts.PROTO_TCP,
                       help=kdc_parser.format_arg_help(general_description="For the KDC connection protocol.",
                                                       usage_example="python3 [path_to_kdc] -pr/--protocol [udp | tcp]"))
    kdc_parser.add_arg('-ip', '--ip-address', type=str, nargs='?', default=ProtoConsts.LOCAL_HOST,
                       help=kdc_parser.format_arg_help(general_description="For the KDC IP Address.",
                                                       usage_example="python3 [path_to_kdc] -ip/--ip-address [ip_address]"))
    kdc_parser.add_arg('-p', '--port', type=int, nargs='?', default=ProtoConsts.DEF_PORT_NUM,
                       help=kdc_parser.format_arg_help(general_description="For the KDC Port number.",
                                                       usage_example="python3 [path_to_client] -p/--port [port_number]"))
    return kdc_parser.parse_args()


def main():

    # Validate port.info file
    if not is_exists(AuthConsts.PORT_FILE_PATH):
        create_info_file(file_name=AuthConsts.PORT_FILE_PATH,
                         file_data={ValConsts.FMT_PORT: ProtoConsts.DEF_PORT_NUM})

    try:
        # Get port number from file
        port_num = parse_info_file(file_path=AuthConsts.PORT_FILE_PATH, target_line_number=1)

    except ValueError:
        # Get default port number
        port_num = AuthConsts.PORT_DEFAULT_NUM

    # Validate port number
    Validator.validate_injection(data_type=ValConsts.FMT_PORT, value_to_validate=int(port_num))

    try:
        # Get CLI args
        kdc_args = get_kdc_args()

        # Create and run the KDC
        auth_server = AuthServerCore(connection_protocol=kdc_args.protocol,
                                     ip_address=kdc_args.ip_address,
                                     port=int(port_num),
                                     debug_mode=kdc_args.debug_mode)
        auth_server.run()

    except Exception as e:
        print(e)
        sys_exit(ProtoConsts.STATUS_ERROR_CODE)


if __name__ == "__main__":
    main()