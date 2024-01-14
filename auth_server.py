from sys import exit as sys_exit
from Utils import utils
from Server.AuthServer.auth_server_constants import Constants
from Server.AuthServer.auth_server_core import AuthServer


def main():

    # Validate port.info file
    if not utils.check_if_exists(Constants.PORT_FILE_NAME):
        utils.create_port_file(file_name=Constants.PORT_FILE_NAME, port_num=str(Constants.PORT_DEFAULT_NUM))

    # TODO - refactor into utils method
    port_num = None
    try:
        port_num = utils.get_port_num(Constants.PORT_FILE_NAME)

    except Exception as e:
        print(e)
        port_num = Constants.PORT_DEFAULT_NUM

    try:
        auth_server = AuthServer(connection_protocol="tcp", ip_address="127.0.0.1",
                                 port=8000, debug_mode=False)
        auth_server.run()
    except Exception as e:
        print(e)
        sys_exit(1)


if __name__ == "__main__":
    main()