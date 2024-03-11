from sys import exit as sys_exit
from Utils.utils import is_exists, create_info_file, parse_info_file
from Utils.validator import Validator, ValConsts
from Utils.custom_arg_parser import CustomArgParser, Namespace
from Protocol_Handler.protocol_constants import ProtoConsts as ProtoConsts
from Server.MsgServer.service_manager import ServiceManager
from Server.MsgServer.msg_server_constants import MsgConsts


def get_msg_server_args() -> Namespace:
    """Returns a Namespace with the Msg Server parsed CLI arguments."""
    msg_server_parser = CustomArgParser(description="Msg Server argument parser.\n"
                                        f"Example Usage: python3 [path_to_msg_server] -d -pr "
                                        f"{ProtoConsts.PROTO_TCP} -ip {ProtoConsts.LOCAL_HOST} -p {ProtoConsts.DEF_PORT_NUM}"
                                        f" -nos 1 -snp {MsgConsts.DEF_SERVER_NAME_PREFIX}",
                                        supress_usage=True)
    msg_server_parser.add_arg('-d', '--debug-mode', action='store_true',
                              help=msg_server_parser.format_arg_help(general_description="For more informative logs and print statements.",
                                                                     usage_example=f"python3 [path_to_msg_server] -d/--debug_mode",
                                                                     default_value="False"))
    msg_server_parser.add_arg('-pr', '--protocol', type=str, nargs='?', default=ProtoConsts.PROTO_TCP,
                              help=msg_server_parser.format_arg_help(general_description="For the KDC connection protocol.",
                                                                     usage_example="python3 [path_to_msg_server] -pr/--protocol [udp | tcp]"))
    msg_server_parser.add_arg('-ip', '--ip-address', type=str, nargs='?', default=ProtoConsts.LOCAL_HOST,
                              help=msg_server_parser.format_arg_help(general_description="For the KDC IP Address.",
                                                                     usage_example="python3 [path_to_msg_server] -ip/--ip-address [ip_address]"))
    msg_server_parser.add_arg('-p', '--port', type=int, nargs='?', default=ProtoConsts.DEF_PORT_NUM,
                              help=msg_server_parser.format_arg_help(general_description="For the KDC Port number.",
                                                                     usage_example="python3 [path_to_msg_server] -p/--port [port_number]"))
    msg_server_parser.add_arg('-nos', '--number-of-services', type=int, nargs='?', default=1,
                              help=msg_server_parser.format_arg_help(general_description="For the number of msg services to create and register.",
                                                                     usage_example="python3 [path_to_msg_server] -nos/--number-of-services [num]"))
    msg_server_parser.add_arg('-snp', '--service-name-prefix', type=str, nargs='?', default=MsgConsts.DEF_SERVER_NAME_PREFIX,
                              help=msg_server_parser.format_arg_help(general_description="For msg services name prefix.",
                                                                     usage_example="python3 [path_to_msg_server] -snp/----service-name-prefix [prefix]"))

    return msg_server_parser.parse_args()


def main():

    # Validate port.info file
    if not is_exists(MsgConsts.PORT_FILE_PATH):
        create_info_file(file_name=MsgConsts.PORT_FILE_PATH,
                         file_data={ValConsts.FMT_PORT: ProtoConsts.DEF_PORT_NUM})

    try:
        # Fetch and Validate KDC port number
        port = parse_info_file(file_path=MsgConsts.PORT_FILE_PATH, target_line_number=1)
        Validator.validate_injection(data_type=ValConsts.FMT_PORT, value_to_validate=int(port))

        # Get CLI args and set default values
        msg_server_args = get_msg_server_args()
        if msg_server_args.port:
            port = msg_server_args.port

        # Create and run the Service Manager
        manager = ServiceManager(connection_protocol=msg_server_args.protocol,
                                 kdc_ip_address=msg_server_args.ip_address,
                                 kdc_port=int(port),
                                 service_name_prefix=msg_server_args.service_name_prefix,
                                 debug_mode=msg_server_args.debug_mode)
        manager.run(num_of_services=msg_server_args.number_of_services)

    except Exception as e:
        print(str(e))
        sys_exit(ProtoConsts.STATUS_ERROR_CODE)


if __name__ == "__main__":
    main()