from os import path as os_path


class AuthConsts:

    # Port related constants
    PORT_FILE_NAME = "port.info"
    PORT_FILE_PATH = f"{os_path.join(os_path.dirname(os_path.abspath(__file__)))}\{PORT_FILE_NAME}"
    PORT_DEFAULT_NUM = 1256

    # Files related constants
    FILES_DIR_NAME = "FILES"
    FILES_DIR_PATH = f"{os_path.join(os_path.dirname(os_path.abspath(__file__)))}\{FILES_DIR_NAME}"
    CLIENTS_FILE_NAME = "clients.txt"
    CLIENTS_FILE_PATH = f"{FILES_DIR_PATH}\{CLIENTS_FILE_NAME}"
    SERVICES_FILE_NAME = "services.json"
    SERVICES_FILE_PATH = f"{FILES_DIR_PATH}\{SERVICES_FILE_NAME}"
    INDEX_CLIENT_HEX_ID = 0
    INDEX_CLIENT_NAME = 1
    INDEX_CLIENT_PASSWORD_HASH = 2

    # RAM template constants
    FMT_ME = '{}'
    RAM_CLIENT_ID = "client_id"
    RAM_CLIENT_ID_HEX = "client_id_hex"
    RAM_SERVER_ID = "server_id"
    RAM_SERVER_ID_HEX = "server_id_hex"
    RAM_CLIENT_NAME = "name"
    RAM_PASSWORD_HASH = "password_hash"
    RAM_PASSWORD_HASH_HEX = "password_hash_hex"
    RAM_LAST_SEEN = "last_seen"
    RAM_IS_REGISTERED = "is_registered"
    RAM_AES_KEY = "aes_key"
    RAM_AES_KEY_HEX = "aes_key_hex"
    RAM_SERVER_IP = "server_ip"
    RAM_SERVER_PORT = "server_port"

    AUTH_SERVER_LOGO = """
         _         _   _       ____                           
        / \  _   _| |_| |__   / ___|  ___ _ ____   _____ _ __ 
       / _ \| | | | __| '_ \  \___ \ / _ \ '__\ \ / / _ \ '__|
      / ___ \ |_| | |_| | | |  ___) |  __/ |   \ V /  __/ |   
     /_/   \_\__,_|\__|_| |_| |____/ \___|_|    \_/ \___|_|   
    """

    KERBEROS_LOGO = """
                                                                                                                                                                                    
                                                                                                                                                                                                                                                                                                                                                
                                                                                 %                    #,                                                                            
                                                                                &&&,                 &&&/                                                                           
                                                                               &&&#&(              .&#&&&#                                                                          
                                                                              %&&&/%&&            #&&.&&&&%                                                                         
                                                                             %&&&&(*&&&/        .&&&%.&&&&&#                                                                        
                                                                            #&&&&&(*&&&&&*     #&&&&%.&&&&&&,                                                                       
                                                                            %&&&&&,%&&&&&&&&&&&&&&&&& &&&&&&#                                                                       
                                                                            %&&&&%#&&&&&&&&&&&&&&&&&&#/&&&&&(                                                                       
                                                                            /&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&.                                                                       
                                                                           .&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&                                                                       
                                                                            &&&&&&&&&&& #&&&&&&&* &&&&&&&&&&%                                                                       
                                                                           *,&&&&&#/&&&&..&&&&& .&&&&/#&&&&%*.                                                                      
                                                     %&.                    /&&&&&&&% .%&&&&&&&&&#..&&&&&&&&,                    #%                                                 
                                                  (&&&&#                      %&&&&&&&%  &&&&&&#  %&&&&&&&(                     *&&&&/                                              
                                              #&&&&&&&&#                      ..&&&&&&&&.&&&&&&(/&&&&&&&&/                      *&&&&&&&&#                                          
                                       .%&&&&&&&&&&&&&&,,*/(#&&&&%            #&,&&&&&&&&&&&&&&&&&&&&&&&/&*           #&&&#*,..  &&&&&&&&&&&&&&(.                                   
                                    //&&&&&&&&&&&&&&&&/*&&&&&&&&&&&#*        ,&&&*&&&&&&&&&&&&&&&&&&&&&*&&&.       .#&&&&&&&&&&&/,&&&&&&&&&&&&&&&&(.                                
                                 (&&&&&&&&&&&&&&&&&&&&.&&&&&&&&&&&&&&&*     .&&&&&*&&&&&&&&&&&&&&&&&&&*&&&&&      (&&&&&&&&&&&&&&.&&&&&&&&&&&&&&&&&&&&/                             
                              ,&&&&&&&&&&&&&&&&&&&&&/*&&&&&&&&&&&&&&&&%&%( ,&&&&&&&*&&&&&&&&&&&&&&&&&,&&&&&&% .%&&&&&&&&&&&&&&&&&&*#&&&&&&&&&&&&&&&&&&&&&,                          
                             &&, %&&/%&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&, #&&&&&&&&&*&&&&&&&&&&&&&&&,&&&&&&&&&  (&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&%/&&&.,&&                         
                            *%  #&# (&&&&&&&&&&&&#%%&%%&&&&&&&&&&&&&&&&(.&&&&&&&&&&&&*&&&&&&&&&&&&&*%&&&&&&&&&& *&&&&&&&&&&&&&&&&&&&&&%%&&&&&&&&&&&# #&%  ##                        
                            %&&&/  *&&&&&&&&&&&&&&&&&&(&&&&&&&&&&&&&&% (&&&&&&&&&&&&&&*&&&&&&&&&&&(%&&&&&&&&&&%/# #&&&&&&&&&&&&&&#&&&&&&&&&&&&&&&&&&/  (&&&&                        
                           .&&&&&&&&&&&&&&&&&&&&&&&&&#(&&&&&&&&&&&&&&&&,*&&&&&&&&&&&&&&(........,#&&&&&&&&&&&&&%.&&&&&&&&&&&&&&&&%(&&&&&&&&&&&&&&&&&&&&&&&&&*                       
                          *&&&&&&&&&&&&&&&&&&&&&&&&&&(%&&&&&&&&&&&&&&&%.&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&#/&&&&&&&&&&&&&&&&/&&&&&&&&&&&&&&&&&&&&&&&&&&/                      
                        %&&&&&&&&&&&&&&&&&&&&&&&&&%*%&&&&&&&&&&&&&&&&&,*&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&%.&&&&&&&&&&&&&&&&&%*%&&&&&&&&&&&&&&&&&&&&&&&&&&                    
                      &&&&&&&&&&&&&&&&&&&&&&&&&&%*(*%&&&&&&&&&&&&&&&&&.,&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&% %&&&&&&&&&&&&&&&&&/(##&&&&&&&&&&&&&&&&&&&&&&&&&&.                 
                   .%%&&&&&&&&&&%&#%&&&&&&&&&&&&&&&/%&&&&&&&&&&&&&&&&&# %%&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&%&,,&&&&&&&&&&&&&&&&&&/%&&&&&&&&&&&&&&%/&&&&&&&&&&&&&(.               
                  #&&&&&&&&&#(%(&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&(..&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&% .&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&/#%%&&&&&&&&&#              
                 &&&&&&&&#(&%%&&&&%#,               .#&&&&&&&&&&&&&&&&&&&*#&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&,&&&&&&&&&&&&&&&&&&&&#.             ,(%&&&&&&/%(%&&&&&&&&,            
                  .%&%&(&&&&&(.                        .%&&&&&&&&&&&&&&&&&*%&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&*%&&&&&&&&&&&&&&&&&(                        ,%&&&%&/%&&&#              
                       ,/.                               #&&&&&&&&&&&&&&&&&,%&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&.%&&&&&&&&&&&&&&&&&.                              *%#,                  
                                                         *&&&&&&&&&&&&&&&&&&//&&&&&&&&&&&&&&&&&&&&&&&&&&&&% &&&&&&&&&&&&&&&&&&(                                                     
                                                        %%#%&&&&&&&&&&&&&&&&&% %%&&&&&&&&&&&&&&&&&&&&&&&* *&&&&&&&&&&&&&&&&&&%&%                                                    
                                                          , *&&&&&&&&&&&&&&&&&&. #&&&&&&&&&&&&&&&&&&&&%  #&&&&&&&&&&&&&&&&&% *                                                      
                                                              %&&&&&&&&&&&&&&&&&% .&&&&&&&&&&&&&&&&&&( *&&&&&&&&&&&&&&&&&&(                                                         
                                                                # ,&&&&&&&&&&&&&&&# *&&&&&&&&&&&&&&& .&&&&&&&&&&&&&&&% .(                                                           
                                                                      , (%&&&&&&&&&&# /&&&&&&&&&&% .&&&&&&&&&&&%*(,                                                                 
                                                                            .(%&&&&&&&% .&&&&&&/ *&&&&&&&&%(.                                                                       
                                                                                   ,(%&&&* #&, #&&&&#*.                                                                             
    
    """


"""
Auxiliary data structures templates.
"""

# Dictionary format for saving clients data in RAM memory
ram_clients_template = {
    AuthConsts.RAM_CLIENT_ID: AuthConsts.FMT_ME,
    AuthConsts.RAM_CLIENT_ID_HEX: AuthConsts.FMT_ME,
    AuthConsts.RAM_CLIENT_NAME: AuthConsts.FMT_ME,
    AuthConsts.RAM_PASSWORD_HASH: AuthConsts.FMT_ME,
    AuthConsts.RAM_PASSWORD_HASH_HEX: AuthConsts.FMT_ME,
    AuthConsts.RAM_LAST_SEEN: AuthConsts.FMT_ME,
    AuthConsts.RAM_IS_REGISTERED: AuthConsts.FMT_ME,
}

# Dictionary format for saving servers data in RAM memory
ram_servers_template = {
    AuthConsts.RAM_SERVER_ID: AuthConsts.FMT_ME,
    AuthConsts.RAM_SERVER_ID_HEX: AuthConsts.FMT_ME,
    AuthConsts.RAM_CLIENT_NAME: AuthConsts.FMT_ME,
    AuthConsts.RAM_AES_KEY: AuthConsts.FMT_ME,
    AuthConsts.RAM_AES_KEY_HEX: AuthConsts.FMT_ME,
    AuthConsts.RAM_SERVER_IP: AuthConsts.FMT_ME,
    AuthConsts.RAM_SERVER_PORT: AuthConsts.FMT_ME,
    AuthConsts.RAM_IS_REGISTERED: AuthConsts.FMT_ME
}

# Dictionary format for saving clients data in file DB
file_db_clients_template = {
    AuthConsts.RAM_CLIENT_ID_HEX: AuthConsts.FMT_ME,
    AuthConsts.RAM_CLIENT_NAME: AuthConsts.FMT_ME,
    AuthConsts.RAM_PASSWORD_HASH_HEX: AuthConsts.FMT_ME,
    AuthConsts.RAM_LAST_SEEN: AuthConsts.FMT_ME
}

# Dictionary format for saving servers data in file DB
file_db_servers_template = {
    AuthConsts.RAM_SERVER_ID_HEX: AuthConsts.FMT_ME,
    AuthConsts.RAM_CLIENT_NAME: AuthConsts.FMT_ME,
    AuthConsts.RAM_AES_KEY_HEX: AuthConsts.FMT_ME,
    AuthConsts.RAM_SERVER_IP: AuthConsts.FMT_ME,
    AuthConsts.RAM_SERVER_PORT: AuthConsts.FMT_ME
}