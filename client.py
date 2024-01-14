from sys import exit as sys_exit
from Client.client_logic import ClientLogic


def main():

    try:

        client = ClientLogic(server_ip='127.0.0.1', server_port=8000, connection_protocol="tcp", debug_mode=False)
        client.run()

    except Exception as e:
        print(e)
        sys_exit(1)


if __name__ == "__main__":
    main()